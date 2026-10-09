use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpProtocol {
    pub number: u8,
    pub any: bool,
}

impl IpProtocol {
    pub fn has_ports(self) -> bool { matches!(self.number, 6 | 17) && !self.any }
    pub fn tc_flower_token(self) -> String {
        // tc flower parses numeric IP protocols in base 16, unlike iptables.
        match self.number { 6 => "tcp".into(), 17 => "udp".into(), number => format!("0x{number:02x}") }
    }
}

pub fn parse_ip_protocol(raw: &str, ipv6: bool) -> Result<IpProtocol, String> {
    let raw = raw.trim().to_ascii_lowercase();
    let number = match raw.as_str() {
        "" | "all" | "any" => return Ok(IpProtocol { number: 0, any: true }),
        "tcp" => 6, "udp" => 17,
        "icmp" => if ipv6 { 58 } else { 1 },
        "icmpv6" | "ipv6-icmp" => { if !ipv6 { return Err("ICMPv6 requires IPv6".into()); } 58 },
        "ipip" | "ipv4" => 4,
        "ipv6" | "sit" => 41,
        "gre" => 47, "esp" => 50, "ah" => 51,
        "etherip" => 97, "l2tp" | "l2tpv3" => 115,
        value => value.parse::<u8>().map_err(|_| "protocol must be a known name or IP protocol number 0–255".to_string())?,
    };
    Ok(IpProtocol { number, any: false })
}

pub fn validate_interface(raw: &str) -> Result<(), String> {
    if raw.is_empty() { return Ok(()); }
    if raw.len() > 15 || !raw.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')) {
        return Err("interface must be a Linux device name of at most 15 characters".into());
    }
    Ok(())
}

pub fn family_is_ipv6(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "ipv4" => Ok(false), "ipv6" => Ok(true),
        _ => Err("select IPv4 or IPv6".into()),
    }
}

pub fn validate_ip(raw: &str, ipv6: bool) -> Result<IpAddr, String> {
    let address = raw.parse::<IpAddr>().map_err(|_| "enter a literal IP address".to_string())?;
    if address.is_ipv6() != ipv6 { return Err("IP address does not match the selected family".into()); }
    if address.is_unspecified() || address.is_multicast() { return Err("use a unicast IP address".into()); }
    Ok(address)
}

pub fn validate_network(raw: &str, ipv6: bool) -> Result<(), String> {
    let (address, prefix) = raw.split_once('/').map_or((raw, None), |(address, prefix)| (address, Some(prefix)));
    let parsed = address.parse::<IpAddr>().map_err(|_| "destination must be a literal IP or CIDR network".to_string())?;
    if parsed.is_ipv6() != ipv6 { return Err("destination does not match the selected family".into()); }
    if let Some(prefix) = prefix {
        let prefix = prefix.parse::<u8>().map_err(|_| "invalid CIDR prefix".to_string())?;
        if prefix > if ipv6 { 128 } else { 32 } { return Err("CIDR prefix is outside the address family range".into()); }
    }
    Ok(())
}

pub fn default_source_ip_mode() -> String { "paired".into() }

pub fn validate_source_ip(
    mode: &str, family: &str, protocol: &str, port: u16, interface: &str,
    destination: &str, source: &str, translate: &str,
) -> Result<(), String> {
    let ipv6 = family_is_ipv6(family)?;
    let protocol = parse_ip_protocol(protocol, ipv6)?;
    if port != 0 && !protocol.has_ports() && !protocol.any {
        return Err("only TCP/UDP packets have ports; use port 0 for this IP protocol".into());
    }
    if !protocol.any && protocol.number == 51 {
        return Err("AH authenticates IP addresses and is unsupported for source-IP rewriting".into());
    }
    validate_interface(interface)?;
    validate_ip(source, ipv6)?;
    match mode {
        "paired" => {
            if ipv6 { return Err("paired stateless rewriting supports IPv4; choose SNAT for IPv6".into()); }
            validate_ip(destination, false)?;
            if !translate.is_empty() { validate_ip(translate, false)?; }
        }
        "snat" => {
            validate_network(destination, ipv6)?;
            if !translate.is_empty() { return Err("SNAT handles replies through conntrack; leave incoming translation empty".into()); }
        }
        _ => return Err("source IP mode must be paired or snat".into()),
    }
    Ok(())
}

pub fn runtime_namespace(raw: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in raw.bytes() { hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3); }
    format!("{:016x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_ip_protocols_and_zero_are_distinct_from_any() {
        for (name, value) in [("ipip",4),("ipv6",41),("gre",47),("esp",50),("ah",51),("etherip",97),("l2tp",115)] {
            assert_eq!(parse_ip_protocol(name, false).unwrap(), parse_ip_protocol(&value.to_string(), false).unwrap());
        }
        assert_eq!(parse_ip_protocol("0", false).unwrap(), IpProtocol { number: 0, any: false });
        assert!(parse_ip_protocol("all", false).unwrap().any);
        for value in ["256", "-1", "tcp --jump", "not-a-protocol"] { assert!(parse_ip_protocol(value, false).is_err()); }
    }

    #[test]
    fn source_ip_modes_validate_real_family_and_port_requirements() {
        assert!(validate_source_ip("snat","ipv6","esp",0,"eth0","2001:db8:2::/64","2001:db8:1::5","").is_ok());
        assert!(validate_source_ip("paired","ipv4","50",0,"eth0","198.51.100.2","203.0.113.9","").is_ok());
        assert!(validate_source_ip("paired","ipv4","esp",443,"eth0","198.51.100.2","203.0.113.9","").is_err());
        assert!(validate_source_ip("paired","ipv6","all",0,"eth0","2001:db8::2","2001:db8::3","").is_err());
        assert!(validate_source_ip("snat","ipv4","ah",0,"eth0","198.51.100.2","203.0.113.9","").is_err());
        assert!(validate_network("198.51.100.2/33", false).is_err());
        assert!(validate_interface("../eth0").is_err());
    }
    #[test]
    fn tc_flower_tokens_keep_decimal_form_inputs_at_the_intended_ip_protocol(){
        assert_eq!(parse_ip_protocol("17",false).unwrap().tc_flower_token(),"udp");
        assert_eq!(parse_ip_protocol("6",false).unwrap().tc_flower_token(),"tcp");
        for number in [0,4,41,47,50,51,97,115,255] {
            let token=parse_ip_protocol(&number.to_string(),false).unwrap().tc_flower_token();
            assert_eq!(u8::from_str_radix(token.strip_prefix("0x").unwrap(),16).unwrap(),number);
        }
        assert_eq!(parse_ip_protocol("50",false).unwrap().tc_flower_token(),"0x32");
    }

}
