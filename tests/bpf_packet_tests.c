#define IMONITOR_PACKET_TEST 1
#include "../src/bpf/xdp_ingress.c"
extern int puts(const char *);
static struct rule_key wanted;
static struct rule_value replacement;
static struct fragment_key saved_key;
static struct fragment_value saved_value;
static int saved_valid;
static int equal_bytes(const void *left, const void *right, int length) { const unsigned char *a=left,*b=right; for(int i=0;i<length;i++)if(a[i]!=b[i])return 0;return 1; }
static void copy_bytes(void *destination,const void *source,int length){unsigned char *a=destination;const unsigned char *b=source;for(int i=0;i<length;i++)a[i]=b[i];}
static void zero_bytes(void *destination,int length){unsigned char *a=destination;for(int i=0;i<length;i++)a[i]=0;}
struct rule_value *test_lookup_rule(const struct rule_key *key){return equal_bytes(key,&wanted,sizeof(wanted))?&replacement:0;}
struct fragment_value *test_lookup_fragment(const struct fragment_key *key){return saved_valid&&equal_bytes(key,&saved_key,sizeof(saved_key))?&saved_value:0;}
void test_remember_fragment(const struct fragment_key *key,const struct fragment_value *value){saved_key=*key;saved_value=*value;saved_valid=1;}
__u64 test_current_ns(void){return 1000000000ULL;}
static unsigned sum_bytes(const unsigned char *data,int length,unsigned sum){for(int i=0;i+1<length;i+=2)sum+=((unsigned)data[i]<<8)|data[i+1];if(length&1)sum+=(unsigned)data[length-1]<<8;return sum;}
static unsigned short finish(unsigned sum){while(sum>>16)sum=(sum&65535)+(sum>>16);return (unsigned short)~sum;}
static __be16 checksum(const void *data,int length){return bpf_htons(finish(sum_bytes(data,length,0)));}
static __be16 transport_checksum(struct iphdr *ip,const unsigned char *transport,int length){unsigned sum=sum_bytes((void *)&ip->saddr,8,0)+ip->protocol+length;return bpf_htons(finish(sum_bytes(transport,length,sum)));}
static int checks;
#define ASSERT(test,message) do{checks++;if(!(test)){puts(message);return 1;}}while(0)
static int packet(unsigned char *buffer,int protocol,int options,int payload){
    zero_bytes(buffer,256);struct ethhdr *eth=(void*)buffer;eth->h_proto=bpf_htons(ETH_P_IP);
    struct iphdr *ip=(void*)(eth+1);ip->version=4;ip->ihl=5+options;ip->ttl=64;ip->protocol=protocol;ip->saddr=bpf_htonl(0xcb007109);ip->daddr=bpf_htonl(0xc0000201);ip->id=bpf_htons(1234);
    unsigned char *transport=(void*)ip+ip->ihl*4;int length=(protocol==6?20:8)+payload;
    if(protocol==6){struct tcphdr *tcp=(void*)transport;tcp->source=bpf_htons(12345);tcp->dest=bpf_htons(443);tcp->doff=5;tcp->window=bpf_htons(4096);}
    if(protocol==17){struct udphdr *udp=(void*)transport;udp->source=bpf_htons(12345);udp->dest=bpf_htons(443);udp->len=bpf_htons(length);}
    for(int i=(protocol==6?20:8);i<length;i++)transport[i]=(unsigned char)(i*7);
    ip->tot_len=bpf_htons(ip->ihl*4+length);ip->check=checksum(ip,ip->ihl*4);
    if(protocol==6)((struct tcphdr*)transport)->check=transport_checksum(ip,transport,length);
    if(protocol==17)((struct udphdr*)transport)->check=transport_checksum(ip,transport,length);
    zero_bytes(&wanted,sizeof(wanted));wanted.ifindex=2;wanted.source_ip=ip->saddr;wanted.destination_ip=ip->daddr;wanted.protocol=protocol;wanted.port=443;replacement.rewrite_ip=bpf_htonl(0xc6336402);saved_valid=0;
    return 14+ip->ihl*4+length;
}
int main(void){
    unsigned char buffer[256],before[256],second[256];
    for(int protocol=6;protocol<=17;protocol+=11){
        for(int options=0;options<2;options++){
            int size=packet(buffer,protocol,options,12);struct iphdr *ip=(void*)(buffer+14);int hlen=ip->ihl*4;unsigned char *transport=(void*)ip+hlen;int tlen=size-14-hlen;
            rewrite_ipv4(buffer,buffer+size,2);
            ASSERT(ip->saddr==replacement.rewrite_ip,"source address was not rewritten");ASSERT(checksum(ip,hlen)==0,"IPv4 checksum invalid after rewrite");ASSERT(transport_checksum(ip,transport,tlen)==0,"TCP/UDP pseudo-header checksum invalid after rewrite");
        }
    }
    int size=packet(buffer,17,0,8);struct iphdr *ip=(void*)(buffer+14);struct udphdr *udp=(void*)ip+20;udp->check=0;rewrite_ipv4(buffer,buffer+size,2);ASSERT(udp->check==0,"disabled UDP checksum changed");
    size=packet(buffer,17,0,8);ip=(void*)(buffer+14);udp=(void*)ip+20;__be16 old=udp->check;int found=0;
    // Find the rare RFC 768 computed-zero case without relying on the
    // production algorithm to calculate the initial full checksum.
    for(unsigned value=1;value<=65535;value++){replacement.rewrite_ip=bpf_htonl(0xc6330000|value);struct iphdr fake=*ip;fake.saddr=replacement.rewrite_ip;udp->check=0;if(transport_checksum(&fake,(void*)udp,16)==0){found=1;break;}}
    ASSERT(found,"failed to construct UDP computed-zero fixture");udp->check=old;rewrite_ipv4(buffer,buffer+size,2);ASSERT(udp->check==bpf_htons(65535),"computed zero UDP checksum was not encoded as 0xffff");
    for(int mismatch=0;mismatch<4;mismatch++){
        size=packet(buffer,6,0,8);copy_bytes(before,buffer,size);
        if(mismatch==0)wanted.source_ip^=1;if(mismatch==1)wanted.destination_ip^=1;if(mismatch==2)wanted.ifindex=3;if(mismatch==3)wanted.protocol=17;
        rewrite_ipv4(buffer,buffer+size,2);ASSERT(equal_bytes(buffer,before,size),"unrelated source/destination/interface/protocol packet changed");
    }
    size=packet(buffer,50,0,16);wanted.port=0;copy_bytes(before,buffer,size);rewrite_ipv4(buffer,buffer+size,2);ip=(void*)(buffer+14);ASSERT(ip->saddr==replacement.rewrite_ip,"ESP protocol 50 was not matched");ASSERT(equal_bytes(buffer+34,before+34,size-34),"ESP payload was modified");ASSERT(checksum(ip,20)==0,"ESP IPv4 checksum invalid");
    size=packet(buffer,0,0,16);wanted.port=0;rewrite_ipv4(buffer,buffer+size,2);ASSERT(((struct iphdr*)(buffer+14))->saddr==replacement.rewrite_ip,"exact protocol zero did not match");
    for(int malformed=0;malformed<6;malformed++){
        size=packet(buffer,6,0,8);ip=(void*)(buffer+14);
        if(malformed==0)ip->version=6;if(malformed==1)ip->ihl=4;if(malformed==2)ip->tot_len=bpf_htons(10);if(malformed==3)((struct tcphdr*)((void*)ip+20))->doff=4;if(malformed==5)ip->tot_len=bpf_htons(65535);
        int visible=size-(malformed==4?1:0);copy_bytes(before,buffer,size);rewrite_ipv4(buffer,buffer+visible,2);ASSERT(equal_bytes(buffer,before,size),"malformed/truncated packet was partially changed");
    }
    // Split TCP header after eight bytes: checksum belongs to fragment two.
    size=packet(buffer,6,0,12);ip=(void*)(buffer+14);int tlen=size-34;copy_bytes(before,buffer,size);copy_bytes(second,buffer,34);copy_bytes(second+34,buffer+42,tlen-8);
    struct iphdr *tail=(void*)(second+14);tail->frag_off=bpf_htons(1);tail->tot_len=bpf_htons(20+tlen-8);tail->check=0;tail->check=checksum(tail,20);
    ip->frag_off=bpf_htons(0x2000);ip->tot_len=bpf_htons(28);ip->check=0;ip->check=checksum(ip,20);
    rewrite_ipv4(buffer,buffer+42,2);rewrite_ipv4(second,second+34+tlen-8,2);
    ASSERT(ip->saddr==replacement.rewrite_ip && tail->saddr==replacement.rewrite_ip,"fragment port decision was not retained");ASSERT(checksum(ip,20)==0 && checksum(tail,20)==0,"fragment IPv4 checksum invalid");
    copy_bytes(before+34,buffer+34,8);copy_bytes(before+42,second+34,tlen-8);struct iphdr *whole=(void*)(before+14);whole->saddr=replacement.rewrite_ip;
    ASSERT(transport_checksum(whole,before+34,tlen)==0,"checksum field in later TCP fragment was not adjusted");
    puts("PASS: packet assertions (TCP/UDP, options, exact matching, ESP, zero, fragments and malformed inputs)");return 0;
}
