#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#ifndef IMONITOR_PACKET_TEST
#include <bpf/bpf_helpers.h>
#endif

struct rule_key {
    __u32 ifindex;
    __be32 source_ip;
    __be32 destination_ip;
    __u8 protocol;
    __u8 protocol_any;
    __u16 port;
};
struct rule_value { __be32 rewrite_ip; };
struct fragment_key {
    __u32 ifindex;
    __be32 source_ip;
    __be32 destination_ip;
    __be16 identification;
    __u8 protocol;
    __u8 pad;
};
struct fragment_value { __be32 rewrite_ip; __u32 pad; __u64 observed_ns; };
#ifndef IMONITOR_PACKET_TEST
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
} ingress_rules SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct fragment_key);
    __type(value, struct fragment_value);
} fragment_rules SEC(".maps");
#define lookup_rule(key) bpf_map_lookup_elem(&ingress_rules, key)
#define lookup_fragment(key) bpf_map_lookup_elem(&fragment_rules, key)
#define remember_fragment(key, value) bpf_map_update_elem(&fragment_rules, key, value, BPF_ANY)
#define current_ns() bpf_ktime_get_ns()
#else
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
extern struct rule_value *test_lookup_rule(const struct rule_key *key);
extern struct fragment_value *test_lookup_fragment(const struct fragment_key *key);
extern void test_remember_fragment(const struct fragment_key *key, const struct fragment_value *value);
extern __u64 test_current_ns(void);
#define lookup_rule(key) test_lookup_rule(key)
#define lookup_fragment(key) test_lookup_fragment(key)
#define remember_fragment(key, value) test_remember_fragment(key, value)
#define current_ns() test_current_ns()
#endif

/* RFC 1624: HC' = ~(~HC + ~m + m'). Work in host-order 16-bit
 * words and convert back, avoiding helper/endian ambiguity. */
static __always_inline __be16 replace_checksum32(__be16 check, __be32 old_ip, __be32 new_ip) {
    __u32 old = bpf_ntohl(old_ip), new = bpf_ntohl(new_ip);
    __u32 sum = (~bpf_ntohs(check)) & 0xffff;
    sum += (~(old >> 16)) & 0xffff;
    sum += (~old) & 0xffff;
    sum += new >> 16;
    sum += new & 0xffff;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return bpf_htons((__u16)~sum);
}

static __always_inline struct rule_value *find_rule(struct rule_key *key, __u16 source_port, __u16 dest_port, int ports_available) {
    struct rule_value *value;
    if (ports_available) {
        key->port = source_port; value = lookup_rule(key); if (value) return value;
        key->port = dest_port; value = lookup_rule(key); if (value) return value;
    }
    key->port = 0; value = lookup_rule(key); if (value) return value;
    key->protocol_any = 1; key->protocol = 0;
    return lookup_rule(key);
}

static __always_inline int rewrite_ipv4(void *data, void *data_end, __u32 ifindex) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    __be16 type = eth->h_proto;
    __u32 offset = sizeof(*eth);
#pragma unroll
    for (int tag = 0; tag < 2; tag++) {
        if (type == bpf_htons(ETH_P_8021Q) || type == bpf_htons(ETH_P_8021AD)) {
            struct vlan_header { __be16 tci; __be16 proto; } *vlan = data + offset;
            if ((void *)(vlan + 1) > data_end) return XDP_PASS;
            type = vlan->proto; offset += sizeof(*vlan);
        }
    }
    if (type != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *iph = data + offset;
    if ((void *)(iph + 1) > data_end || iph->version != 4 || iph->ihl < 5) return XDP_PASS;
    __u32 header_len = iph->ihl * 4;
    __u32 total_len = bpf_ntohs(iph->tot_len);
    // Older verifiers can lose the scalar bounds after the 16-bit endian
    // conversion. Compare the declared length with the available bytes,
    // rather than adding that scalar to a packet pointer. The bounded IHL
    // check still proves the transport-header pointer is inside the packet.
    __u64 available = (__u64)data_end - (__u64)iph;
    if (total_len < header_len || (void *)iph + header_len > data_end || total_len > available) return XDP_PASS;
    void *transport = (void *)iph + header_len;
    __u32 payload_len = total_len - header_len;
    __u16 fragment = bpf_ntohs(iph->frag_off);
    __u32 fragment_offset = (fragment & 0x1fff) * 8;
    int more = fragment & 0x2000;
    if (more && (payload_len & 7)) return XDP_PASS;
    __u16 source_port = 0, dest_port = 0;
    int port_protocol = iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP;
    int ports_available = port_protocol && !fragment_offset && payload_len >= 4;
    if (ports_available) {
        __be16 *ports = transport;
        if ((void *)(ports + 2) > data_end) return XDP_PASS;
        source_port = bpf_ntohs(ports[0]); dest_port = bpf_ntohs(ports[1]);
    }
    // Complete datagrams must contain complete, internally valid headers.
    if (!fragment_offset && !more && port_protocol) {
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = transport;
            if ((void *)(tcp + 1) > data_end || payload_len < sizeof(*tcp) || tcp->doff < 5 || tcp->doff * 4 > payload_len) return XDP_PASS;
        } else {
            struct udphdr *udp = transport;
            if ((void *)(udp + 1) > data_end || payload_len < sizeof(*udp) || bpf_ntohs(udp->len) < sizeof(*udp) || bpf_ntohs(udp->len) > payload_len) return XDP_PASS;
        }
    }
    struct fragment_key frag_key = { .ifindex = ifindex, .source_ip = iph->saddr, .destination_ip = iph->daddr, .identification = iph->id, .protocol = iph->protocol };
    struct rule_key key = { .ifindex = ifindex, .source_ip = iph->saddr, .destination_ip = iph->daddr, .protocol = iph->protocol };
    __be32 new_ip = 0;
    // Remember the first fragment's port decision for subsequent fragments.
    // Portless rules also work when fragments arrive before their first part.
    if (fragment_offset) {
        struct fragment_value *saved = lookup_fragment(&frag_key);
        __u64 now = current_ns();
        if (saved && now >= saved->observed_ns && now - saved->observed_ns < 30000000000ULL) new_ip = saved->rewrite_ip;
    }
    if (!new_ip) {
        struct rule_value *value = find_rule(&key, source_port, dest_port, ports_available);
        if (!value) return XDP_PASS;
        new_ip = value->rewrite_ip;
    }
    __be32 old_ip = iph->saddr;
    if (old_ip == new_ip) return XDP_PASS;
    if (!fragment_offset && more) {
        struct fragment_value saved = { .rewrite_ip = new_ip, .observed_ns = current_ns() };
        remember_fragment(&frag_key, &saved);
    }
    // A TCP checksum can sit in a later fragment when the first fragment
    // contains only eight bytes of the header. Adjust the fragment containing
    // that field exactly once, without interpreting other payload as ports.
    if (port_protocol) {
        __u32 checksum_offset = iph->protocol == IPPROTO_TCP ? 16 : 6;
        if (fragment_offset <= checksum_offset && checksum_offset + 2 <= fragment_offset + payload_len) {
            __u32 relative = checksum_offset - fragment_offset;
            __be16 *check = transport + relative;
            if ((void *)(check + 1) > data_end) return XDP_PASS;
            if (iph->protocol == IPPROTO_TCP || *check != 0) {
                __be16 next = replace_checksum32(*check, old_ip, new_ip);
                // RFC 768 represents a computed zero as all ones. An input
                // zero remains zero because it means UDP checksum disabled.
                if (iph->protocol == IPPROTO_UDP && next == 0) next = bpf_htons(0xffff);
                *check = next;
            }
        }
    }
    iph->check = replace_checksum32(iph->check, old_ip, new_ip);
    iph->saddr = new_ip;
    return XDP_PASS;
}
#ifndef IMONITOR_PACKET_TEST
SEC("xdp")
int xdp_translate_ingress(struct xdp_md *ctx) {
    return rewrite_ipv4((void *)(long)ctx->data, (void *)(long)ctx->data_end, ctx->ingress_ifindex);
}
char LICENSE[] SEC("license") = "GPL";
#endif
