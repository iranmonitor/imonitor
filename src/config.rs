use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpVersion {
    Ipv4,
    Ipv6,
    Any,
}

impl Default for IpVersion {
    fn default() -> Self {
        Self::Any
    }
}

impl IpVersion {
    pub fn from_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "ipv4" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            _ => Self::Any,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Txt,
}

impl Default for DnsRecordType {
    fn default() -> Self {
        Self::A
    }
}

impl DnsRecordType {
    pub fn from_str(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "AAAA" => Self::Aaaa,
            "CNAME" => Self::Cname,
            "MX" => Self::Mx,
            "NS" => Self::Ns,
            "TXT" => Self::Txt,
            _ => Self::A,
        }
    }

    pub fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Txt => "TXT",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelProtocol {
    Gre,
    Gretap,
    Vxlan,
    Geneve,
    Ipv4IpInIp,
    Ipip,
    Ipv6Encapsulation,
    Etherip,
    Encap,
    L2tp,
    Esp,
    Wireguard,
    Tun,
    Ssh,
    ReverseSsh,
}

impl TunnelProtocol {
    pub fn from_str(value: &str) -> Result<Self, String> {
        Ok(match value.trim().to_ascii_lowercase().as_str() {
            "gre" => Self::Gre,
            "gretap" | "gre_tap" => Self::Gretap,
            "vxlan" => Self::Vxlan,
            "geneve" => Self::Geneve,
            "ipv4_ip_in_ip" | "ip-in-ip" | "ipinip4" => Self::Ipv4IpInIp,
            "ipip" => Self::Ipip,
            "ipv6_encapsulation" | "ipv6" | "sit" => Self::Ipv6Encapsulation,
            "etherip" => Self::Etherip,
            "encap" => Self::Encap,
            "l2tp" => Self::L2tp,
            "esp" => Self::Esp,
            "wireguard" | "wire_guard" | "wg" => Self::Wireguard,
            "tun" | "icmp" => Self::Tun,
            "ssh" => Self::Ssh,
            "reverse_ssh" | "reverse-ssh" | "reverse ssh" => Self::ReverseSsh,
            _ => return Err("Unknown tunnel protocol. Choose a supported tunnel mode.".to_string()),
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gre => "gre",
            Self::Gretap => "gretap",
            Self::Vxlan => "vxlan",
            Self::Geneve => "geneve",
            Self::Ipv4IpInIp => "ipv4_ip_in_ip",
            Self::Ipip => "ipip",
            Self::Ipv6Encapsulation => "ipv6_encapsulation",
            Self::Etherip => "etherip",
            Self::Encap => "encap",
            Self::L2tp => "l2tp",
            Self::Esp => "esp",
            Self::Wireguard => "wireguard",
            Self::Tun => "tun",
            Self::Ssh => "ssh",
            Self::ReverseSsh => "reverse_ssh",
        }
    }

    pub fn protocol_number(self) -> u16 {
        match self {
            Self::Gre | Self::Gretap => 47,
            Self::Vxlan | Self::Geneve => 17,
            Self::Ipv4IpInIp => 4,
            // Linux's `ip tunnel ... mode ipip` uses RFC 2003 protocol 4.
            Self::Ipip => 4,
            Self::Ipv6Encapsulation => 41,
            Self::Etherip => 97,
            // Managed ENCAP is IPIP encapsulated in GUE over UDP.
            Self::Encap => 17,
            Self::L2tp => 115,
            Self::Esp => 50,
            Self::Wireguard => 17,
            Self::Tun => 0,
            Self::Ssh => 6,
            Self::ReverseSsh => 6,
        }
    }

    pub fn is_interface_based(self) -> bool {
        matches!(
            self,
            Self::Gre
                | Self::Gretap
                | Self::Vxlan
                | Self::Geneve
                | Self::Ipv4IpInIp
                | Self::Ipip
                | Self::Ipv6Encapsulation
                | Self::Etherip
                | Self::Encap
                | Self::L2tp
                | Self::Tun
                | Self::Ssh
                | Self::ReverseSsh
                | Self::Wireguard
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EspKeyDerivation {
    /// Retained only so existing peer configurations continue to interoperate.
    #[default]
    Legacy,
    HkdfSha256,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EspCipher {
    /// Preserve saved configurations and active SAs, never recreate static GCM.
    #[default]
    LegacyAesGcm,
    AesCbcHmacSha256,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyType {
    Socks5,
    Http,
    Https,
    Vmess,
    Vless,
    Trojan,
    Wireguard,
    Shadowsocks,
    OtherV2ray,
}

impl ProxyType {
    pub fn from_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "http" => Self::Http,
            "https" => Self::Https,
            "vmess" => Self::Vmess,
            "vless" => Self::Vless,
            "trojan" => Self::Trojan,
            "wireguard" | "wire_guard" | "wg" => Self::Wireguard,
            "shadowsocks" | "ss" => Self::Shadowsocks,
            "other_v2ray" | "other" | "custom" | "xray" | "v2ray" => Self::OtherV2ray,
            _ => Self::Socks5,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Http => "http",
            Self::Https => "https",
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Wireguard => "wireguard",
            Self::Shadowsocks => "shadowsocks",
            Self::OtherV2ray => "other_v2ray",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalEntryType {
    Socks5,
    Http,
    Https,
    Direct,
}

impl Default for LocalEntryType {
    fn default() -> Self {
        Self::Direct
    }
}

impl LocalEntryType {
    pub fn from_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "socks" | "socks5" => Self::Socks5,
            "http" => Self::Http,
            "https" => Self::Https,
            "direct" => Self::Direct,
            _ => Self::Direct,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Http => "http",
            Self::Https => "https",
            Self::Direct => "direct",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    #[serde(default)]
    pub output_file: Option<String>,
    #[serde(default)]
    pub history_file: Option<String>,
    #[serde(default)]
    pub state_file: Option<String>,
    #[serde(default)]
    pub checks: Vec<CheckDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CheckDefinition {
    Icmp(IcmpCheck),
    Tcp(SocketCheck),
    Udp(UdpCheck),
    Ssh(SshCheck),
    Sftp(SshCheck),
    Http(WebCheck),
    Https(WebCheck),
    Dns(DnsCheck),
    Rdp(RdpCheck),
    Ftp(FtpCheck),
    Tunnel(TunnelCheck),
    #[serde(rename = "v2ray", alias = "v2ray_simulation")]
    V2raySimulation(V2raySimulationCheck),
}

impl CheckDefinition {
    pub fn id(&self) -> &str {
        match self {
            Self::Icmp(check) => &check.id,
            Self::Tcp(check) => &check.id,
            Self::Udp(check) => &check.id,
            Self::Ssh(check) => &check.id,
            Self::Sftp(check) => &check.id,
            Self::Http(check) => &check.id,
            Self::Https(check) => &check.id,
            Self::Dns(check) => &check.id,
            Self::Rdp(check) => &check.id,
            Self::Ftp(check) => &check.id,
            Self::Tunnel(check) => &check.id,
            Self::V2raySimulation(check) => &check.id,
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Icmp(_) => "icmp",
            Self::Tcp(_) => "tcp",
            Self::Udp(_) => "udp",
            Self::Ssh(_) => "ssh",
            Self::Sftp(_) => "sftp",
            Self::Http(_) => "http",
            Self::Https(_) => "https",
            Self::Dns(_) => "dns",
            Self::Rdp(_) => "rdp",
            Self::Ftp(_) => "ftp",
            Self::Tunnel(_) => "tunnel",
            Self::V2raySimulation(_) => "v2ray",
        }
    }

    pub fn interval_secs(&self) -> u64 {
        match self {
            Self::Icmp(check) => check.interval_secs,
            Self::Tcp(check) => check.interval_secs,
            Self::Udp(check) => check.interval_secs,
            Self::Ssh(check) => check.interval_secs,
            Self::Sftp(check) => check.interval_secs,
            Self::Http(check) => check.interval_secs,
            Self::Https(check) => check.interval_secs,
            Self::Dns(check) => check.interval_secs,
            Self::Rdp(check) => check.interval_secs,
            Self::Ftp(check) => check.interval_secs,
            Self::Tunnel(check) => check.interval_secs,
            Self::V2raySimulation(check) => check.interval_secs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpCheck {
    pub id: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    pub target: String,
    #[serde(default)]
    pub ip_version: IpVersion,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketCheck {
    pub id: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    pub target: String,
    pub port: u16,
    #[serde(default)]
    pub ip_version: IpVersion,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpCheck {
    pub id: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    pub target: String,
    pub port: u16,
    #[serde(default)]
    pub ip_version: IpVersion,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub expect_response: bool,
    #[serde(default)]
    pub response_contains: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCheck {
    pub id: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    pub target: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(default)]
    pub ip_version: IpVersion,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub expect_banner_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebCheck {
    pub id: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    pub host: String,
    #[serde(default)]
    pub connect_host: Option<String>,
    #[serde(default)]
    pub host_header: Option<String>,
    #[serde(default)]
    pub tls_server_name: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default = "default_http_method")]
    pub method: String,
    #[serde(default = "default_http_path")]
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub expected_status: Vec<u16>,
    #[serde(default)]
    pub body_contains: Option<String>,
    #[serde(default)]
    pub ip_version: IpVersion,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCheck {
    pub id: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    pub server: String,
    #[serde(default = "default_dns_port")]
    pub port: u16,
    pub record_name: String,
    #[serde(default)]
    pub record_type: DnsRecordType,
    #[serde(default = "default_expected_answers_min")]
    pub expect_answers_min: u16,
    #[serde(default)]
    pub ip_version: IpVersion,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdpCheck {
    pub id: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    pub target: String,
    #[serde(default = "default_rdp_port")]
    pub port: u16,
    #[serde(default)]
    pub ip_version: IpVersion,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpCheck {
    pub id: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    pub target: String,
    #[serde(default = "default_ftp_port")]
    pub port: u16,
    #[serde(default)]
    pub ip_version: IpVersion,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelCheck {
    pub id: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    pub protocol: TunnelProtocol,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default = "default_auto_create_tunnel_interface")]
    pub auto_create_interface: bool,
    #[serde(default)]
    pub outer_remote: Option<String>,
    #[serde(default)]
    pub local_outer: Option<String>,
    #[serde(default)]
    pub inner_probe: Option<String>,
    #[serde(default)]
    pub source_interface: Option<String>,
    #[serde(default)]
    pub inner_local_cidr: Option<String>,
    /// Maximum inner IP packet size. None preserves the existing device default.
    #[serde(default)]
    pub mtu: Option<u16>,
    /// Outer IPv4 TTL / IPv6 hop limit, for kernel modes that expose it.
    #[serde(default)]
    pub ttl: Option<u8>,
    /// Outer TOS / traffic class, including DSCP and ECN bits.
    #[serde(default)]
    pub traffic_class: Option<u8>,
    /// Shared 24-bit network identifier for VXLAN and GENEVE.
    #[serde(default)]
    pub vni: Option<u32>,
    /// Native TCP or ICMP forwarding lanes; None preserves one lane.
    #[serde(default)]
    pub tun_lanes: Option<u8>,
    /// Shared secret used only for authenticated native tunnel throughput tests.
    /// It is never copied into public check-result details.
    #[serde(default)]
    pub speedtest_token: Option<String>,
    #[serde(default = "default_speedtest_port", alias = "iperf_port")]
    pub speedtest_port: u16,
    #[serde(default)]
    pub tunnel_key: Option<String>,
    #[serde(default)]
    pub esp_key_derivation: EspKeyDerivation,
    #[serde(default)]
    pub esp_cipher: EspCipher,
    #[serde(default)]
    pub tun_transport: Option<String>,
    #[serde(default)]
    pub transport_port: Option<u16>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub l2tp_tunnel_id: Option<u32>,
    #[serde(default)]
    pub l2tp_peer_tunnel_id: Option<u32>,
    #[serde(default)]
    pub l2tp_session_id: Option<u32>,
    #[serde(default)]
    pub l2tp_peer_session_id: Option<u32>,
    #[serde(default)]
    pub l2tp_encapsulation: Option<String>,
    #[serde(default)]
    pub wireguard_private_key: Option<String>,
    #[serde(default)]
    pub wireguard_peer_public_key: Option<String>,
    #[serde(default)]
    pub wireguard_preshared_key: Option<String>,
    #[serde(default)]
    pub wireguard_allowed_ips: Option<String>,
    #[serde(default)]
    pub ssh_username: Option<String>,
    #[serde(default)]
    pub ssh_password: Option<String>,
    #[serde(default)]
    pub ssh_private_key: Option<String>,
    #[serde(default)]
    pub ip_version: IpVersion,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_operstate")]
    pub expected_operstate: String,
    #[serde(default)]
    pub require_bidirectional_traffic: bool,
    #[serde(default = "default_min_packet_delta")]
    pub min_rx_packets_delta: u64,
    #[serde(default = "default_min_packet_delta")]
    pub min_tx_packets_delta: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V2raySimulationCheck {
    pub id: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    pub proxy_type: ProxyType,
    #[serde(default = "default_local_entry_type")]
    pub local_entry_type: LocalEntryType,
    #[serde(default)]
    pub profile_import: Option<String>,
    #[serde(default)]
    pub proxy_host: Option<String>,
    #[serde(default)]
    pub proxy_port: Option<u16>,
    #[serde(default)]
    pub test_url: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub expected_status: Vec<u16>,
    #[serde(default)]
    pub body_contains: Option<String>,
    #[serde(default)]
    pub server_host: Option<String>,
    #[serde(default)]
    pub server_port: Option<u16>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub wireguard_interface: Option<String>,
    #[serde(default)]
    pub wireguard_peer: Option<String>,
    #[serde(default)]
    pub inner_probe: Option<String>,
    #[serde(default)]
    pub source_interface: Option<String>,
    #[serde(default)]
    pub max_handshake_age_secs: Option<u64>,
    #[serde(default)]
    pub ip_version: IpVersion,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_agent_id() -> String {
    "iranmonitor-solo".to_string()
}

fn default_speedtest_port() -> u16 {
    5201
}

fn default_interval_secs() -> u64 {
    60
}

fn default_timeout_ms() -> u64 {
    3_000
}

fn default_http_method() -> String {
    "GET".to_string()
}

fn default_http_path() -> String {
    "/".to_string()
}

fn default_expected_answers_min() -> u16 {
    1
}

fn default_ssh_port() -> u16 {
    22
}

fn default_dns_port() -> u16 {
    53
}

fn default_rdp_port() -> u16 {
    3389
}

fn default_ftp_port() -> u16 {
    21
}

fn default_operstate() -> String {
    "up".to_string()
}

fn default_auto_create_tunnel_interface() -> bool {
    true
}

fn default_min_packet_delta() -> u64 {
    1
}

fn default_local_entry_type() -> LocalEntryType {
    LocalEntryType::Direct
}
