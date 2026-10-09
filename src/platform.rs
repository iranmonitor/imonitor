use crate::app_types::{
    AppSettings, AppSocketRecord, HostIpInventoryEntry, PortForwardRule, SourceIpRule, SpeedLimitRule,
    SystemSample, TcpConnLimitPolicy, TrafficWatcher,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::{Command, Stdio};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
pub struct CpuTimes {
    pub idle: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkTotals {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub observed_at_unix: u64,
}

pub fn collect_system_sample(
    previous_cpu: Option<CpuTimes>,
    previous_net: Option<NetworkTotals>,
) -> Result<(SystemSample, CpuTimes, NetworkTotals), String> {
    let now = unix_now();
    let cpu = read_cpu_times()?;
    let (total_ram_bytes, used_ram_bytes, total_swap_bytes, used_swap_bytes) = read_meminfo()?;
    let (total_disk_bytes, used_disk_bytes) = read_disk_usage("/")?;
    let (load1, load5, load15) = read_loadavg()?;
    let current_net = read_network_totals(now)?;

    let cpu_percent = if let Some(previous_cpu) = previous_cpu {
        let total_delta = cpu.total.saturating_sub(previous_cpu.total);
        let idle_delta = cpu.idle.saturating_sub(previous_cpu.idle);
        if total_delta == 0 {
            0.0
        } else {
            ((total_delta.saturating_sub(idle_delta)) as f64 / total_delta as f64) * 100.0
        }
    } else {
        0.0
    };

    let (rx_bps, tx_bps) = if let Some(previous_net) = previous_net {
        let elapsed = current_net
            .observed_at_unix
            .saturating_sub(previous_net.observed_at_unix)
            .max(1);
        (
            current_net.rx_bytes.saturating_sub(previous_net.rx_bytes) / elapsed,
            current_net.tx_bytes.saturating_sub(previous_net.tx_bytes) / elapsed,
        )
    } else {
        (0, 0)
    };

    let ram_percent = percent(used_ram_bytes, total_ram_bytes);
    let swap_percent = percent(used_swap_bytes, total_swap_bytes);
    let disk_percent = percent(used_disk_bytes, total_disk_bytes);

    Ok((
        SystemSample {
            observed_at_unix: now,
            cpu_percent,
            ram_percent,
            swap_percent,
            disk_percent,
            rx_bps,
            tx_bps,
            load1,
            load5,
            load15,
            total_ram_bytes,
            used_ram_bytes,
            total_swap_bytes,
            used_swap_bytes,
            total_disk_bytes,
            used_disk_bytes,
        },
        cpu,
        current_net,
    ))
}

pub fn collect_socket_inventory(limit: usize) -> Result<Vec<AppSocketRecord>, String> {
    let output = run_command_capture("ss", &["-tunapH"])?;
    let mut rows = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let proto = parts[0].to_string();
        let state = parts[1].to_string();
        let local = parts[4].to_string();
        let remote = parts[5].to_string();
        let process_chunk = parts.iter().find(|part| part.starts_with("users:")).copied().unwrap_or("");
        let (process, pid) = parse_process_descriptor(process_chunk);
        let service_unit = service_unit_for_pid(&pid).unwrap_or_default();
        let is_protected = is_protected_socket_process(&process, &service_unit);
        let has_unit = !service_unit.is_empty();
        let has_pid = !pid.is_empty();
        rows.push(AppSocketRecord {
            proto,
            state,
            local_port: parse_socket_port(&local),
            local_address: local,
            remote_address: remote,
            process,
            pid,
            service_unit,
            can_start: has_unit && !is_protected,
            can_stop: (has_pid || has_unit) && !is_protected,
            can_restart: has_unit && !is_protected,
            is_protected,
        });
        if rows.len() >= limit {
            break;
        }
    }
    Ok(rows)
}

pub fn control_socket_app(
    action: &str,
    service_unit: Option<&str>,
    pid: Option<&str>,
    is_protected: bool,
) -> Result<String, String> {
    if is_protected {
        return Err("iranmonitor is protected in the web panel and cannot be controlled here".to_string());
    }

    let action = action.trim().to_ascii_lowercase();
    match (
        service_unit.filter(|value| !value.trim().is_empty()),
        pid.filter(|value| !value.trim().is_empty()),
    ) {
        (Some(unit), _) => {
            let action_name = match action.as_str() {
                "start" => "start",
                "stop" => "stop",
                "restart" => "restart",
                _ => return Err(format!("unsupported socket action: {action}")),
            };
            run_command("systemctl", &[action_name, unit])?;
            Ok(format!("{action_name} requested for {unit}"))
        }
        (None, Some(pid_value)) => {
            if action != "stop" {
                return Err(
                    "this process is not mapped to a systemd service, so only stop is available"
                        .to_string(),
                );
            }
            run_command("kill", &["-TERM", pid_value])?;
            Ok(format!("stop requested for pid {pid_value}"))
        }
        (None, None) => Err("no controllable target was found for this app".to_string()),
    }
}

pub fn collect_host_ip_inventory() -> Vec<String> {
    let detailed = collect_host_ip_inventory_detailed();
    if !detailed.is_empty() {
        return detailed.into_iter().map(|entry| entry.address).collect();
    }

    collect_host_ip_inventory_legacy()
}

fn collect_host_ip_inventory_legacy() -> Vec<String> {
    let mut seen = BTreeSet::new();
    if let Ok(output) = run_command_capture("hostname", &["-I"]) {
        for token in output.split_whitespace() {
            let value = token.trim();
            if !value.is_empty() {
                seen.insert(value.to_string());
            }
        }
    }
    seen.into_iter().collect()
}

pub fn collect_host_ip_inventory_detailed() -> Vec<HostIpInventoryEntry> {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();

    if let Ok(output) = run_command_capture("ip", &["-o", "addr", "show", "up", "scope", "global"]) {
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let interface = parts[1].trim_end_matches(':').trim();
            let family = parts[2].trim();
            let address = parts[3]
                .split('/')
                .next()
                .unwrap_or("")
                .trim();
            if interface.is_empty() || address.is_empty() {
                continue;
            }

            let key = format!("{interface}|{address}");
            if !seen.insert(key) {
                continue;
            }

            entries.push(HostIpInventoryEntry {
                interface: interface.to_string(),
                address: address.to_string(),
                family: family.to_string(),
                is_public: ip_address_is_public(address),
            });
        }
    }

    if entries.is_empty() {
        for address in collect_host_ip_inventory_legacy() {
            let key = format!("auto|{address}");
            if !seen.insert(key) {
                continue;
            }
            entries.push(HostIpInventoryEntry {
                interface: "auto".to_string(),
                address: address.clone(),
                family: if address.contains(':') {
                    "inet6".to_string()
                } else {
                    "inet".to_string()
                },
                is_public: ip_address_is_public(&address),
            });
        }
    }

    entries.sort_by(|left, right| {
        (!left.is_public)
            .cmp(&(!right.is_public))
            .then_with(|| left.interface.cmp(&right.interface))
            .then_with(|| left.family.cmp(&right.family))
            .then_with(|| left.address.cmp(&right.address))
    });
    entries
}

fn ip_address_is_public(address: &str) -> bool {
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ipv4_is_public(ip),
        Ok(IpAddr::V6(ip)) => ipv6_is_public(ip),
        Err(_) => false,
    }
}

fn ipv4_is_public(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
    {
        return false;
    }
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return false;
    }
    if octets[0] == 198 && octets[1] == 18 {
        return false;
    }
    if octets[0] == 198 && octets[1] == 19 {
        return false;
    }
    true
}

fn ipv6_is_public(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }

    let segments = ip.segments();
    if (segments[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    if (segments[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    true
}

pub fn generate_reverse_proxy_snippet(settings: &AppSettings) -> String {
    let server_name = if settings.reverse_proxy_server_name.trim().is_empty() {
        "status.example.com"
    } else {
        settings.reverse_proxy_server_name.trim()
    };
    let cert_path = if settings.ssl_cert_path.trim().is_empty() {
        "/etc/letsencrypt/live/status.example.com/fullchain.pem"
    } else {
        settings.ssl_cert_path.trim()
    };
    let key_path = if settings.ssl_key_path.trim().is_empty() {
        "/etc/letsencrypt/live/status.example.com/privkey.pem"
    } else {
        settings.ssl_key_path.trim()
    };

    format!(
        "\
server {{
    listen 443 ssl http2;
    server_name {server_name};

    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};

    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }}
}}

server {{
    listen 80;
    server_name {server_name};
    return 301 https://$host$request_uri;
}}
",
        port = extract_port(&settings.bind_addr).unwrap_or(6060)
    )
}

static WATCHER_COUNTERS: std::sync::Mutex<BTreeMap<i64, (u64, u64)>> = std::sync::Mutex::new(BTreeMap::new());

pub fn sync_traffic_watchers(watchers: &[TrafficWatcher]) -> Result<(), String> {
    // Validate both families before committing either table.
    build_stats_restore(watchers, false)?;
    build_stats_restore(watchers, true)?;
    rebuild_stats_chain("iptables", watchers, false)?;
    rebuild_stats_chain("ip6tables", watchers, true)?;
    WATCHER_COUNTERS.lock().map_err(|_| "traffic counter lock failed")?.clear();
    Ok(())
}

pub fn read_traffic_watcher_counters(
    watchers: &[TrafficWatcher], interval_secs: u64,
) -> Result<BTreeMap<i64, (u64, u64, u64)>, String> {
    let ipv4 = if watchers.iter().any(|watcher| watcher.enabled && watcher.family != "ipv6") {
        parse_iptables_save_counters("iptables-save", false)?
    } else { BTreeMap::new() };
    let ipv6 = if watchers.iter().any(|watcher| watcher.enabled && watcher.family != "ipv4") {
        parse_iptables_save_counters("ip6tables-save", true)?
    } else { BTreeMap::new() };
    let mut previous = WATCHER_COUNTERS.lock().map_err(|_| "traffic counter lock failed")?;
    Ok(accumulate_watcher_counters(watchers, interval_secs, &ipv4, &ipv6, &mut previous))
}

fn accumulate_watcher_counters(watchers: &[TrafficWatcher], interval_secs: u64,
    ipv4: &BTreeMap<String,(u64,u64)>, ipv6: &BTreeMap<String,(u64,u64)>,
    previous: &mut BTreeMap<i64,(u64,u64)>,
) -> BTreeMap<i64,(u64,u64,u64)> {
    let mut counters = BTreeMap::new();
    for watcher in watchers.iter().filter(|watcher| watcher.enabled) {
        let tag = format!("imwatch-{}", watcher.id);
        let left = if watcher.family == "ipv6" { (0,0) } else { ipv4.get(&tag).copied().unwrap_or((0,0)) };
        let right = if watcher.family == "ipv4" { (0,0) } else { ipv6.get(&tag).copied().unwrap_or((0,0)) };
        let raw = (left.0.saturating_add(right.0), left.1.saturating_add(right.1));
        let prior = previous.insert(watcher.id, raw).unwrap_or((0,0));
        let packets = if raw.0 < prior.0 { raw.0 } else { raw.0-prior.0 };
        let bytes = if raw.1 < prior.1 { raw.1 } else { raw.1-prior.1 };
        counters.insert(watcher.id, (watcher.total_packets.saturating_add(packets),
            watcher.total_bytes.saturating_add(bytes), bytes/interval_secs.max(1)));
    }
    counters
}

pub fn apply_tcp_conn_limit(policy: &TcpConnLimitPolicy) -> Result<String,String> {
    for (command,ipv6) in [("iptables",false),("ip6tables",true)] {
        if !policy.enabled {
            match run_command_capture(command,&["-w","5","-S","IRANMONITOR_GUARD"]) {
                Err(error) if firewall_chain_missing(&error)=>continue, Err(error)=>return Err(error),Ok(_)=>{},
            }
        }
        let body=build_connlimit_restore(policy,ipv6)?;
        run_command_with_input(&format!("{command}-restore"),&["-w","5","--noflush"],&body)?;
        if policy.enabled {ensure_custom_chain(command,"IRANMONITOR_GUARD","INPUT")?;}
    }
    Ok(if policy.enabled {format!("applied TCP connection limit of {} per source IP on port {}",policy.limit_per_ip,policy.target_port)} else {"TCP connection limit disabled".into()})
}
fn build_connlimit_restore(policy:&TcpConnLimitPolicy,ipv6:bool)->Result<String,String>{
    let mut body="*filter\n:IRANMONITOR_GUARD - [0:0]\n-F IRANMONITOR_GUARD\n".to_string();
    if policy.enabled {
        if policy.limit_per_ip==0 || policy.target_port==0 {return Err("TCP connection limits require a positive port and limit".into());}
        body.push_str(&format!("-A IRANMONITOR_GUARD -p tcp --dport {} --syn -m connlimit --connlimit-above {} --connlimit-mask {} -j REJECT --reject-with tcp-reset\n",policy.target_port,policy.limit_per_ip,if ipv6 {128}else{32}));
    }
    body.push_str("COMMIT\n");Ok(body)
}
fn firewall_chain_missing(error:&str)->bool{
    let error=error.to_ascii_lowercase();error.contains("no chain/target/match")||error.contains("does not exist")||error.contains("no such file")||error.contains("os error 2")
}

static SPEED_LIMIT_SYNC: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn sync_speed_limits(rules: &[SpeedLimitRule],runtime:&Path) -> Result<Vec<(i64, bool, String)>, String> {
    let _guard=SPEED_LIMIT_SYNC.lock().map_err(|_|"speed-limit synchronization lock failed")?;
    let path=runtime.join("speed_limit_owned_roots.json");
    let mut owned:BTreeSet<String>=match fs::read(&path){
        Ok(body)=>serde_json::from_slice(&body).map_err(|error|format!("invalid shaping ownership state: {error}"))?,
        Err(error) if error.kind()==std::io::ErrorKind::NotFound=>BTreeSet::new(),Err(error)=>return Err(error.to_string()),
    };
    let statuses=sync_speed_limits_with_owned_backend(rules,&mut owned,|args|{
        let borrowed=args.iter().map(String::as_str).collect::<Vec<_>>();run_command_capture("tc",&borrowed)
    });
    fs::create_dir_all(runtime).map_err(|error|error.to_string())?;
    let next=path.with_extension("json.next");fs::write(&next,serde_json::to_vec(&owned).map_err(|error|error.to_string())?).map_err(|error|error.to_string())?;
    fs::rename(next,path).map_err(|error|format!("shaping ownership state commit: {error}"))?;
    Ok(statuses)
}
#[cfg(test)]
fn sync_speed_limits_with_backend(rules:&[SpeedLimitRule],backend:impl FnMut(&[String])->Result<String,String>)->Vec<(i64,bool,String)>{
    sync_speed_limits_with_owned_backend(rules,&mut BTreeSet::new(),backend)
}

fn sync_speed_limits_with_owned_backend(
    rules: &[SpeedLimitRule],
    owned: &mut BTreeSet<String>,
    mut backend: impl FnMut(&[String]) -> Result<String, String>,
) -> Vec<(i64, bool, String)> {
    rules.iter().map(|rule| {
        if !rule.enabled {
            // An unapplied disabled rule requires no network commands. A rule
            // disabled after installation removes only its own class/filter.
            let removed = if rule.applied {
                speed_limit_root_for_cleanup(rule, owned, &mut backend).and_then(|present| {
                    if present { remove_speed_limit_with_backend(rule, &mut backend, true) } else { Ok(()) }
                })
            } else { Ok(()) };
            return match removed {
                Ok(()) => (rule.id, false, "disabled".to_string()),
                Err(error) => (rule.id, rule.applied, format!("failed to remove disabled speed limit: {error}")),
            };
        }
        let mut attempted_rule_mutation = false;
        let applied = speed_limit_apply_commands(rule).and_then(|commands| {
            ensure_speed_limit_root(rule, owned, &mut backend)?;
            remove_speed_limit_with_backend(rule, &mut backend, false)?;
            for (index, command) in commands.into_iter().enumerate() {
                // The first two commands maintain the shared root/default
                // classes. Only the remaining commands can leave this rule
                // partially installed if a later family fails.
                if index >= 2 { attempted_rule_mutation = true; }
                backend(&command)?;
            }
            Ok(())
        });
        match applied {
            Ok(()) => (rule.id, true, format!("applied egress speed limit of {}{} on {} port {}",
                rule.rate_value, normalize_rate_unit(&rule.rate_unit), rule.interface_name.trim(), rule.port)),
            Err(error) if attempted_rule_mutation && !rule.applied => {
                match remove_speed_limit_with_backend(rule, &mut backend, true) {
                    Ok(()) => (rule.id, false, format!("failed to apply speed limit: {error}; partial rule rolled back")),
                    // Keep ownership visible in the database so disable/delete
                    // retries cleanup instead of forgetting a live filter.
                    Err(cleanup) => (rule.id, true, format!("failed to apply speed limit: {error}; cleanup failed: {cleanup}")),
                }
            }
            Err(error) => (rule.id, rule.applied, format!("failed to apply speed limit: {error}")),
        }
    }).collect()
}

fn ensure_speed_limit_root(rule: &SpeedLimitRule, owned:&mut BTreeSet<String>, backend: &mut impl FnMut(&[String])->Result<String,String>) -> Result<(),String> {
    let interface = rule.interface_name.trim();
    crate::network_rules::validate_interface(interface)?;
    let query = ["-j","qdisc","show","dev",interface].map(str::to_string);
    let raw = backend(&query)?;
    let qdiscs: serde_json::Value = serde_json::from_str(&raw).map_err(|_|"tc qdisc metadata is invalid")?;
    let qdiscs = qdiscs.as_array().ok_or("tc qdisc metadata is not an array")?;
    let root = qdiscs.iter().find(|value|value["root"].as_bool()==Some(true));
    if let Some(root) = root {
        let kind=root["kind"].as_str().unwrap_or(""); let handle=root["handle"].as_str().unwrap_or("");
        if kind=="htb" && handle=="1:" && owned.contains(interface) { return Ok(()); }
        if handle != "0:" || !matches!(kind,"noqueue"|"pfifo_fast"|"fq_codel"|"fq"|"mq") {
            return Err(format!("{interface} has an unrelated root qdisc ({kind} {handle}); it was preserved"));
        }
    }
    let command = ["qdisc","replace","dev",interface,"root","handle","1:","htb","default","999"].map(str::to_string);
    backend(&command)?; owned.insert(interface.into()); Ok(())
}

fn speed_limit_root_for_cleanup(rule: &SpeedLimitRule, owned: &BTreeSet<String>, backend: &mut impl FnMut(&[String])->Result<String,String>) -> Result<bool,String> {
    let interface = rule.interface_name.trim();
    if interface.is_empty() { return Err("speed limit rule needs an interface name".into()); }
    crate::network_rules::validate_interface(interface)?;
    let query = ["-j","qdisc","show","dev",interface].map(str::to_string);
    let raw = match backend(&query) {
        Ok(raw) => raw,
        Err(error) if tc_object_missing(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    let qdiscs: serde_json::Value = serde_json::from_str(&raw).map_err(|_| "tc qdisc metadata is invalid")?;
    let qdiscs = qdiscs.as_array().ok_or("tc qdisc metadata is not an array")?;
    let Some(root) = qdiscs.iter().find(|value| value["root"].as_bool() == Some(true)) else { return Ok(false); };
    let kind = root["kind"].as_str().unwrap_or("");
    let handle = root["handle"].as_str().unwrap_or("");
    if kind == "htb" && handle == "1:" && owned.contains(interface) { return Ok(true); }
    if handle == "0:" && matches!(kind,"noqueue"|"pfifo_fast"|"fq_codel"|"fq"|"mq") { return Ok(false); }
    Err(format!("{interface} root qdisc ({kind} {handle}) is not confirmed as owned by iMonitor; it was preserved. Restore the original shaping ownership state, or verify and remove this rule manually before deleting it"))
}

fn speed_limit_class_id(rule: &SpeedLimitRule) -> Result<String, String> {
    // Keep the legacy class numbering so previously installed rules can be
    // removed. tc interprets class IDs as hexadecimal even for decimal digits.
    let minor = rule.id.checked_add(100).filter(|id| *id > 0)
        .ok_or_else(|| "invalid speed-limit rule id".to_string())?;
    let minor_text = minor.to_string();
    let parsed = u16::from_str_radix(&minor_text, 16).map_err(|_| "speed-limit class id is outside the tc range")?;
    if matches!(parsed, 1 | 0x999) { return Err("speed-limit class id conflicts with the root/default class".to_string()); }
    Ok(format!("1:{minor_text}"))
}

fn speed_limit_apply_commands(rule: &SpeedLimitRule) -> Result<Vec<Vec<String>>, String> {
    if !rule.enabled { return Ok(Vec::new()); }
    let interface = rule.interface_name.trim();
    if interface.is_empty() { return Err("speed limit rule needs an interface name".to_string()); }
    if rule.port == 0 || rule.rate_value == 0 { return Err("speed limits require a positive port and rate".to_string()); }
    let protocol=crate::network_rules::parse_ip_protocol(&rule.protocol,false)?;
    if !protocol.has_ports(){return Err("speed limits support tcp or udp".into());}
    let protocol_token=protocol.tc_flower_token();
    let protocol=protocol_token.as_str();
    let unit = normalize_rate_unit(&rule.rate_unit);
    if !matches!(unit.as_str(), "kbit" | "mbit" | "gbit") { return Err("unsupported speed-limit rate unit".to_string()); }
    let class = speed_limit_class_id(rule)?;
    let rate = format!("{}{unit}", rule.rate_value);
    let port = rule.port.to_string();
    let handle = format!("0x{:x}", 0x20000000u32 | u32::try_from(rule.id).map_err(|_| "invalid speed limit ID")?);
    Ok(vec![
        vec!["class", "replace", "dev", interface, "parent", "1:", "classid", "1:1", "htb", "rate", "1000gbit", "ceil", "1000gbit"],
        vec!["class", "replace", "dev", interface, "parent", "1:1", "classid", "1:999", "htb", "rate", "1000gbit", "ceil", "1000gbit"],
        vec!["class", "replace", "dev", interface, "parent", "1:1", "classid", &class, "htb", "rate", &rate, "ceil", &rate],
        vec!["filter", "replace", "dev", interface, "protocol", "ip", "parent", "1:", "pref", "2", "handle", &handle, "flower", "ip_proto", protocol, "src_port", &port, "classid", &class],
        vec!["filter", "replace", "dev", interface, "protocol", "ipv6", "parent", "1:", "pref", "3", "handle", &handle, "flower", "ip_proto", protocol, "src_port", &port, "classid", &class],
    ].into_iter().map(|args| args.into_iter().map(str::to_string).collect()).collect())
}

fn remove_speed_limit_with_backend(
    rule: &SpeedLimitRule,
    backend: &mut impl FnMut(&[String]) -> Result<String, String>,
    remove_class: bool,
) -> Result<(), String> {
    let interface = rule.interface_name.trim();
    if interface.is_empty() { return Err("speed limit rule needs an interface name".to_string()); }
    let class = speed_limit_class_id(rule)?;
    let query = ["-j", "filter", "show", "dev", interface, "parent", "1:"].map(str::to_string);
    let output = match backend(&query) {
        Ok(output) => output,
        Err(error) if tc_object_missing(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let filters: serde_json::Value = serde_json::from_str(&output)
        .map_err(|_| "tc did not return valid filter metadata")?;
    let filters = filters.as_array().ok_or_else(|| "tc filter metadata is not an array".to_string())?;
    for filter in filters {
        let Some(options) = filter.get("options") else { continue; };
        let kind=filter.get("kind").and_then(serde_json::Value::as_str).unwrap_or("");
        if (!remove_class && kind=="flower") || !matches!(kind,"u32"|"flower") || options.get("flowid").or_else(||options.get("classid")).and_then(serde_json::Value::as_str) != Some(class.as_str()) { continue; }
        let handle_value = options.get("fh").or_else(||options.get("handle")).or_else(||filter.get("handle")).ok_or("tc filter handle is missing")?;
        let handle = handle_value.as_str().map(str::to_string).or_else(||handle_value.as_u64().map(|value|format!("0x{value:x}"))).ok_or("tc filter handle is invalid")?;
        let protocol = filter.get("protocol").and_then(serde_json::Value::as_str).unwrap_or("ip");
        let preference = filter.get("pref").and_then(serde_json::Value::as_u64).unwrap_or(1).to_string();
        let command = ["filter", "del", "dev", interface, "protocol", protocol, "parent", "1:", "pref", &preference, "handle", &handle, kind].map(str::to_string);
        if let Err(error) = backend(&command) { if !tc_object_missing(&error) { return Err(error); } }
    }
    if !remove_class {return Ok(());}
    let command = ["class", "del", "dev", interface, "classid", class.as_str()].map(str::to_string);
    if let Err(error) = backend(&command) { if !tc_object_missing(&error) { return Err(error); } }
    // Keep the shared root qdisc and all other classes: deleting one rule must
    // never remove or briefly bypass enabled shaping on the same interface.
    Ok(())
}

fn tc_object_missing(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("no such file") || error.contains("no such device")
        || error.contains("cannot find device") || error.contains("parent qdisc doesn't exist")
        || error.contains("cannot find qdisc")
}


pub fn sync_port_forward_rules(
    rules: &[PortForwardRule],
) -> Result<Vec<(i64, bool, String)>, String> {
    let mut ipv4_rules = Vec::new();
    let mut ipv6_rules = Vec::new();
    let mut statuses = Vec::new();

    for rule in rules {
        let enabled = rule.enabled;
        let protocol = rule.protocol.trim().to_ascii_lowercase();
        let family = rule.family.trim().to_ascii_lowercase();
        let target_host = rule.target_host.trim();
        let interface_name = rule.interface_name.trim();
        let source_ip = rule.source_ip.trim();

        if !enabled {
            statuses.push((rule.id, false, "disabled".to_string()));
            continue;
        }
        crate::network_rules::validate_interface(interface_name)?;
        if target_host.is_empty() {
            return Err(format!("forward rule '{}' needs a target IP", rule.label));
        }
        if !source_ip.is_empty() && source_ip != "*" {
            let parsed_source_ip = source_ip.parse::<IpAddr>().map_err(|_| {
                format!("forward rule '{}' has an invalid source IP filter", rule.label)
            })?;
            if (family == "ipv4" && !parsed_source_ip.is_ipv4())
                || (family == "ipv6" && !parsed_source_ip.is_ipv6())
            {
                return Err(format!(
                    "forward rule '{}' source IP filter does not match the selected family",
                    rule.label
                ));
            }
        }
        if !matches!(protocol.as_str(), "tcp" | "udp" | "icmp") {
            return Err(format!(
                "forward rule '{}' uses unsupported protocol '{}'",
                rule.label, rule.protocol
            ));
        }
        if !matches!(family.as_str(), "ipv4" | "ipv6") {
            return Err(format!(
                "forward rule '{}' needs family ipv4 or ipv6",
                rule.label
            ));
        }
        let parsed_ip = target_host
            .parse::<IpAddr>()
            .map_err(|_| format!("forward rule '{}' needs a literal target IP address", rule.label))?;
        if (family == "ipv4" && !parsed_ip.is_ipv4()) || (family == "ipv6" && !parsed_ip.is_ipv6()) {
            return Err(format!(
                "forward rule '{}' target IP does not match the selected family",
                rule.label
            ));
        }
        if protocol != "icmp" && rule.listen_port == 0 {
            return Err(format!(
                "forward rule '{}' needs a listen port for {} forwarding",
                rule.label, protocol
            ));
        }
        if protocol != "icmp" && rule.target_port == 0 {
            return Err(format!(
                "forward rule '{}' needs a target port for {} forwarding",
                rule.label, protocol
            ));
        }

        if family == "ipv6" {
            ipv6_rules.push(rule);
        } else {
            ipv4_rules.push(rule);
        }

        let status = if protocol == "icmp" {
            format!("applied {} host forward to {}", family, target_host)
        } else {
            format!(
                "applied {} {}:{} -> {}:{}",
                family, protocol, rule.listen_port, target_host, rule.target_port
            )
        };
        let filter_suffix = {
            let mut fragments = Vec::new();
            if !interface_name.is_empty() {
                fragments.push(format!("iface {}", interface_name));
            }
            if !source_ip.is_empty() && source_ip != "*" {
                fragments.push(format!("source {}", source_ip));
            }
            if fragments.is_empty() {
                String::new()
            } else {
                format!(" [{}]", fragments.join(", "))
            }
        };
        statuses.push((rule.id, true, format!("{status}{filter_suffix}")));
    }

    rebuild_forward_chain("iptables", false, &ipv4_rules)?;
    rebuild_forward_chain("ip6tables", true, &ipv6_rules)?;

    if !ipv4_rules.is_empty() {
        run_command("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
    }
    if !ipv6_rules.is_empty() {
        run_command("sysctl", &["-w", "net.ipv6.conf.all.forwarding=1"])?;
    }

    Ok(statuses)
}

pub fn sync_source_ip_rules(rules: &[SourceIpRule], runtime: &Path) -> Result<Vec<(i64, bool, String)>, String> {
    crate::source_ip::sync(rules, runtime)
}

pub fn send_free_report(endpoint: &str, token: &str, payload_json: &str) -> Result<String, String> {
    let mut command = Command::new("curl");
    command
        .arg("--silent")
        .arg("--show-error")
        .arg("--max-time")
        .arg("20")
        .arg("--request")
        .arg("POST")
        .arg("--header")
        .arg("Content-Type: application/json");

    if !token.trim().is_empty() {
        command
            .arg("--header")
            .arg(format!("Authorization: Bearer {}", token.trim()));
    }

    let output = command
        .arg("--data")
        .arg(payload_json)
        .arg(endpoint)
        .output()
        .map_err(|error| format!("failed to execute curl for free report: {error}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn build_stats_restore(watchers: &[TrafficWatcher], ipv6: bool) -> Result<String,String> {
    let mut body = "*filter\n:IRANMONITOR_STATS_IN - [0:0]\n:IRANMONITOR_STATS_OUT - [0:0]\n-F IRANMONITOR_STATS_IN\n-F IRANMONITOR_STATS_OUT\n".to_string();
    for watcher in watchers.iter().filter(|watcher| watcher.enabled && (watcher.family == "both" || watcher.family == if ipv6 { "ipv6" } else { "ipv4" })) {
        if !matches!(watcher.direction.as_str(), "input" | "output") { return Err("traffic direction must be input or output".into()); }
        let protocol = crate::network_rules::parse_ip_protocol(&watcher.protocol,ipv6)?;
        if watcher.target_port != 0 && !protocol.any && !protocol.has_ports() { return Err("ports apply only to TCP/UDP traffic watchers".into()); }
        let source = watcher.source_ip.trim();
        if !source.is_empty() && source != "*" { crate::network_rules::validate_network(source,ipv6)?; }
        let protocols = if protocol.any && watcher.target_port != 0 { vec![Some(6),Some(17)] } else if protocol.any { vec![None] } else { vec![Some(protocol.number)] };
        for protocol in protocols {
            let mut line = format!("-A {}", if watcher.direction == "output" {"IRANMONITOR_STATS_OUT"} else {"IRANMONITOR_STATS_IN"});
            if !source.is_empty() && source != "*" { line.push_str(&format!(" -s {source}")); }
            if let Some(protocol) = protocol {
                // iptables reserves -p 0 for all protocols. Match the actual
                // header byte when the user selected numeric protocol zero.
                if protocol == 0 {
                    line.push_str(if ipv6 { " -m u32 --u32 \"4>>8&0xff=0\"" } else { " -m u32 --u32 \"6&0xff=0\"" });
                } else { line.push_str(&format!(" -p {protocol}")); }
            }
            if watcher.target_port != 0 { line.push_str(&format!(" {} {}", if watcher.direction == "output" {"--sport"} else {"--dport"},watcher.target_port)); }
            // A targetless rule counts then continues, so overlapping watchers
            // each see a packet instead of the first RETURN hiding it.
            line.push_str(&format!(" -m comment --comment imwatch-{}\n",watcher.id)); body.push_str(&line);
        }
    }
    body.push_str("COMMIT\n"); Ok(body)
}

fn rebuild_stats_chain(command: &str, watchers: &[TrafficWatcher], ipv6: bool) -> Result<(), String> {
    let body = build_stats_restore(watchers,ipv6)?;
    // With no selected watchers, clear existing owned chains but avoid
    // requiring IPv6 firewall tools on IPv4-only installations.
    let active = watchers.iter().any(|watcher|watcher.enabled && (watcher.family == "both" || watcher.family == if ipv6 {"ipv6"} else {"ipv4"}));
    if !active {match run_command_capture(command,&["-w","5","-S","IRANMONITOR_STATS_IN"]) {
        Err(error) if firewall_chain_missing(&error)=>return Ok(()),Err(error)=>return Err(error),Ok(_)=>{},
    }}
    run_command_with_input(&format!("{command}-restore"), &["-w","5","--noflush"], &body)?;
    ensure_custom_chain(command,"IRANMONITOR_STATS_IN","INPUT")?;
    ensure_custom_chain(command,"IRANMONITOR_STATS_OUT","OUTPUT")?;
    Ok(())
}

fn rebuild_forward_chain(command: &str, ipv6: bool, rules: &[&PortForwardRule]) -> Result<(), String> {
    let pre="IRANMONITOR_FWD_PRE";let out="IRANMONITOR_FWD_OUT";let post="IRANMONITOR_FWD_POST";let allow="IRANMONITOR_FWD_ALLOW";
    if rules.is_empty() {match run_command_capture(command,&["-w","5","-t","nat","-S",pre]) {
        Err(error) if firewall_chain_missing(&error)=>return Ok(()),Err(error)=>return Err(error),Ok(_)=>{},
    }}
    let body=build_forward_restore(ipv6,rules);
    // Both NAT and filter chains are committed by their table, preserving
    // unrelated chains and avoiding a flush/add gap inside each table.
    run_command_with_input(&format!("{command}-restore"), &["-w","5","--noflush"],&body)?;
    ensure_table_chain(command,"nat",pre,"PREROUTING")?;ensure_table_chain(command,"nat",out,"OUTPUT")?;
    ensure_table_chain(command,"nat",post,"POSTROUTING")?;ensure_table_chain(command,"filter",allow,"FORWARD")?;
    Ok(())
}
fn build_forward_restore(ipv6:bool,rules:&[&PortForwardRule])->String{
    let chains=["IRANMONITOR_FWD_PRE","IRANMONITOR_FWD_OUT","IRANMONITOR_FWD_POST","IRANMONITOR_FWD_ALLOW"];
    let specs=rules.iter().flat_map(|rule|build_forward_rule_specs(ipv6,chains[0],chains[1],chains[2],chains[3],rule)).collect::<Vec<_>>();
    let mut body=String::new();
    for table in ["nat","filter"]{
        body.push_str(&format!("*{table}\n"));
        for chain in &chains { if (table=="filter")==chain.ends_with("ALLOW") {body.push_str(&format!(":{chain} - [0:0]\n-F {chain}\n"));} }
        for spec in &specs {if spec[1]==table {body.push_str(&spec[2..].join(" "));body.push('\n');}}
        body.push_str("COMMIT\n");
    }
    body
}

fn build_forward_rule_specs(
    ipv6: bool,
    prerouting_chain: &str,
    output_chain: &str,
    postrouting_chain: &str,
    filter_chain: &str,
    rule: &PortForwardRule,
) -> Vec<Vec<String>> {
    let protocol = rule.protocol.trim().to_ascii_lowercase();
    let proto_token = if ipv6 && protocol == "icmp" {
        "ipv6-icmp"
    } else {
        protocol.as_str()
    };
    let destination = build_dnat_destination(ipv6, &protocol, rule.target_host.trim(), rule.target_port);
    let comment = format!("imfwd-{}", rule.id);
    let mut pre_args = vec![
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        prerouting_chain.to_string(),
        "-p".to_string(),
        proto_token.to_string(),
    ];
    pre_args.extend(["-m".into(),"addrtype".into(),"--dst-type".into(),"LOCAL".into()]);
    if protocol != "icmp" {
        pre_args.push("--dport".to_string());
        pre_args.push(rule.listen_port.to_string());
    }
    if !rule.interface_name.trim().is_empty() {
        pre_args.push("-i".to_string());
        pre_args.push(rule.interface_name.trim().to_string());
    }
    if !rule.source_ip.trim().is_empty() && rule.source_ip.trim() != "*" {
        pre_args.push("-s".to_string());
        pre_args.push(rule.source_ip.trim().to_string());
    }
    pre_args.extend(vec![
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        comment.clone(),
        "-j".to_string(),
        "DNAT".to_string(),
        "--to-destination".to_string(),
        destination.clone(),
    ]);

    let mut out_args = vec![
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        output_chain.to_string(),
        "-p".to_string(),
        proto_token.to_string(),
    ];
    out_args.extend(["-m".into(),"addrtype".into(),"--dst-type".into(),"LOCAL".into()]);
    if protocol != "icmp" {
        out_args.push("--dport".to_string());
        out_args.push(rule.listen_port.to_string());
    }
    if !rule.source_ip.trim().is_empty() && rule.source_ip.trim() != "*" {
        out_args.push("-s".to_string());
        out_args.push(rule.source_ip.trim().to_string());
    }
    out_args.extend(vec![
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        comment.clone(),
        "-j".to_string(),
        "DNAT".to_string(),
        "--to-destination".to_string(),
        destination.clone(),
    ]);

    let mut post_args = vec![
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        postrouting_chain.to_string(),
        "-p".to_string(),
        proto_token.to_string(),
        "-d".to_string(),
        rule.target_host.trim().to_string(),
    ];
    if protocol != "icmp" {
        post_args.push("--dport".to_string());
        post_args.push(rule.target_port.to_string());
    }
    if !rule.source_ip.trim().is_empty() && rule.source_ip.trim() != "*" {
        post_args.push("-s".to_string());
        post_args.push(rule.source_ip.trim().to_string());
    }
    post_args.extend(["-m".into(),"conntrack".into(),"--ctstate".into(),"DNAT".into()]);
    if protocol != "icmp" {post_args.extend(["--ctorigdstport".into(),rule.listen_port.to_string()]);}
    post_args.extend(vec![
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        comment.clone(),
        "-j".to_string(),
        "MASQUERADE".to_string(),
    ]);

    let mut forward_out = vec![
        "-t".to_string(),
        "filter".to_string(),
        "-A".to_string(),
        filter_chain.to_string(),
        "-m".to_string(),
        "conntrack".to_string(),
        "--ctstate".to_string(),
        "NEW,ESTABLISHED,RELATED".to_string(),
        "-p".to_string(),
        proto_token.to_string(),
        "-d".to_string(),
        rule.target_host.trim().to_string(),
    ];
    if protocol != "icmp" {
        forward_out.push("--dport".to_string());
        forward_out.push(rule.target_port.to_string());
    }
    if !rule.interface_name.trim().is_empty() {
        forward_out.push("-i".to_string());
        forward_out.push(rule.interface_name.trim().to_string());
    }
    if !rule.source_ip.trim().is_empty() && rule.source_ip.trim() != "*" {
        forward_out.push("-s".to_string());
        forward_out.push(rule.source_ip.trim().to_string());
    }
    // DNAT is a virtual conntrack state, not a status. Use a second match
    // instance so it is ANDed with the allowed connection states above.
    forward_out.extend(["-m".into(),"conntrack".into(),"--ctstate".into(),"DNAT".into()]);
    if protocol != "icmp" {forward_out.extend(["--ctorigdstport".into(),rule.listen_port.to_string()]);}
    forward_out.extend(vec![
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        comment.clone(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]);

    let mut forward_back = vec![
        "-t".to_string(),
        "filter".to_string(),
        "-A".to_string(),
        filter_chain.to_string(),
        "-m".to_string(),
        "conntrack".to_string(),
        "--ctstate".to_string(),
        "ESTABLISHED,RELATED".to_string(),
        "-p".to_string(),
        proto_token.to_string(),
        "-s".to_string(),
        rule.target_host.trim().to_string(),
    ];
    if protocol != "icmp" {
        forward_back.push("--sport".to_string());
        forward_back.push(rule.target_port.to_string());
    }
    forward_back.extend(["-m".into(),"conntrack".into(),"--ctstate".into(),"DNAT".into()]);
    if protocol != "icmp" {forward_back.extend(["--ctorigdstport".into(),rule.listen_port.to_string()]);}
    forward_back.extend(vec![
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        comment,
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]);
    vec![pre_args, out_args, post_args, forward_out, forward_back]
}

fn build_dnat_destination(ipv6: bool, protocol: &str, target_host: &str, target_port: u16) -> String {
    if protocol == "icmp" {
        target_host.to_string()
    } else if ipv6 {
        format!("[{target_host}]:{target_port}")
    } else {
        format!("{target_host}:{target_port}")
    }
}

fn ensure_custom_chain(command: &str, chain: &str, parent_chain: &str) -> Result<(), String> {
    let _ = run_command(command, &["-N", chain]);
    let check = run_command(command, &["-C", parent_chain, "-j", chain]);
    if check.is_err() {
        run_command(command, &["-I", parent_chain, "1", "-j", chain])?;
    }
    Ok(())
}

fn ensure_table_chain(command: &str, table: &str, chain: &str, parent_chain: &str) -> Result<(), String> {
    let _ = run_command(command, &["-t", table, "-N", chain]);
    let check = run_command(command, &["-t", table, "-C", parent_chain, "-j", chain]);
    if check.is_err() {
        run_command(command, &["-t", table, "-I", parent_chain, "1", "-j", chain])?;
    }
    Ok(())
}

fn parse_iptables_save_counters(command: &str, _ipv6: bool) -> Result<BTreeMap<String,(u64,u64)>,String> {
    Ok(parse_counter_dump(&run_command_capture(command,&["-c"])?))
}

fn parse_counter_dump(output: &str) -> BTreeMap<String,(u64,u64)> {
    let mut counters = BTreeMap::<String,(u64,u64)>::new();
    for line in output.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        let Some(index) = parts.iter().position(|part| *part == "--comment") else {continue};
        let Some(tag) = parts.get(index+1).map(|value| value.trim_matches('"')) else {continue};
        if !tag.starts_with("imwatch-") {continue;}
        let raw = parts.first().and_then(|part|part.strip_prefix('[')).and_then(|part|part.strip_suffix(']')).and_then(|part|part.split_once(':'));
        let mut packets = raw.and_then(|(packets,_)|packets.parse::<u64>().ok()).unwrap_or(0);
        let mut bytes = raw.and_then(|(_,bytes)|bytes.parse::<u64>().ok()).unwrap_or(0);
        if let Some(index) = parts.iter().position(|part|*part == "-c") {
            packets = parts.get(index+1).and_then(|value|value.parse().ok()).unwrap_or(0);
            bytes = parts.get(index+2).and_then(|value|value.parse().ok()).unwrap_or(0);
        }
        let entry = counters.entry(tag.into()).or_default(); entry.0 = entry.0.saturating_add(packets); entry.1 = entry.1.saturating_add(bytes);
    }
    counters
}

fn parse_process_descriptor(chunk: &str) -> (String, String) {
    let process_name = chunk
        .split('"')
        .nth(1)
        .unwrap_or("")
        .to_string();
    let pid = chunk
        .split("pid=")
        .nth(1)
        .and_then(|tail| tail.split([',', ')']).next())
        .unwrap_or("")
        .to_string();
    (process_name, pid)
}

fn service_unit_for_pid(pid: &str) -> Option<String> {
    let pid = pid.trim();
    if pid.is_empty() || !pid.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    for line in content.lines() {
        let cgroup_path = line.rsplit(':').next()?.trim();
        for segment in cgroup_path.split('/').rev() {
            let trimmed = segment.trim();
            if trimmed.ends_with(".service") {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn is_protected_socket_process(process: &str, service_unit: &str) -> bool {
    process.eq_ignore_ascii_case("iranmonitor_node")
        || process.eq_ignore_ascii_case("iranmonitor")
        || service_unit.eq_ignore_ascii_case("iranmonitor-node.service")
}

fn parse_socket_port(address: &str) -> u16 {
    address
        .rsplit(':')
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0)
}

fn read_cpu_times() -> Result<CpuTimes, String> {
    let stat = fs::read_to_string("/proc/stat")
        .map_err(|error| format!("failed to read /proc/stat: {error}"))?;
    let first = stat.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let _cpu = parts.next();
    let values: Vec<u64> = parts.filter_map(|part| part.parse::<u64>().ok()).collect();
    if values.len() < 4 {
        return Err("unexpected /proc/stat format".to_string());
    }
    let idle = values.get(3).copied().unwrap_or(0) + values.get(4).copied().unwrap_or(0);
    let total = values.iter().sum();
    Ok(CpuTimes { idle, total })
}

fn read_meminfo() -> Result<(u64, u64, u64, u64), String> {
    let content = fs::read_to_string("/proc/meminfo")
        .map_err(|error| format!("failed to read /proc/meminfo: {error}"))?;
    let mut map = BTreeMap::new();
    for line in content.lines() {
        if let Some((key, rest)) = line.split_once(':') {
            let value = rest
                .split_whitespace()
                .next()
                .and_then(|text| text.parse::<u64>().ok())
                .unwrap_or(0);
            map.insert(key.to_string(), value * 1024);
        }
    }
    let total_ram = map.get("MemTotal").copied().unwrap_or(0);
    let available_ram = map.get("MemAvailable").copied().unwrap_or(0);
    let total_swap = map.get("SwapTotal").copied().unwrap_or(0);
    let free_swap = map.get("SwapFree").copied().unwrap_or(0);
    Ok((
        total_ram,
        total_ram.saturating_sub(available_ram),
        total_swap,
        total_swap.saturating_sub(free_swap),
    ))
}

fn read_disk_usage(path: &str) -> Result<(u64, u64), String> {
    let output = run_command_capture("df", &["-B1", path])?;
    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let total = parts[1].parse::<u64>().unwrap_or(0);
            let used = parts[2].parse::<u64>().unwrap_or(0);
            return Ok((total, used));
        }
    }
    Err("failed to parse df output".to_string())
}

fn read_loadavg() -> Result<(f64, f64, f64), String> {
    let content = fs::read_to_string("/proc/loadavg")
        .map_err(|error| format!("failed to read /proc/loadavg: {error}"))?;
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("unexpected /proc/loadavg format".to_string());
    }
    Ok((
        parts[0].parse::<f64>().unwrap_or(0.0),
        parts[1].parse::<f64>().unwrap_or(0.0),
        parts[2].parse::<f64>().unwrap_or(0.0),
    ))
}

fn read_network_totals(observed_at_unix: u64) -> Result<NetworkTotals, String> {
    let content = fs::read_to_string("/proc/net/dev")
        .map_err(|error| format!("failed to read /proc/net/dev: {error}"))?;
    let mut rx_bytes = 0_u64;
    let mut tx_bytes = 0_u64;
    for line in content.lines().skip(2) {
        let Some((interface, rest)) = line.split_once(':') else {
            continue;
        };
        let iface = interface.trim();
        if iface == "lo" || iface.starts_with("ifb") {
            continue;
        }
        let values: Vec<&str> = rest.split_whitespace().collect();
        if values.len() >= 16 {
            rx_bytes = rx_bytes.saturating_add(values[0].parse::<u64>().unwrap_or(0));
            tx_bytes = tx_bytes.saturating_add(values[8].parse::<u64>().unwrap_or(0));
        }
    }
    Ok(NetworkTotals {
        rx_bytes,
        tx_bytes,
        observed_at_unix,
    })
}

fn percent(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (used as f64 / total as f64) * 100.0
    }
}

fn normalize_rate_unit(value: &str) -> String {
    let lower = value.trim().to_ascii_lowercase();
    match lower.as_str() {
        "kbps" | "kbit" | "kbit/s" => "kbit".to_string(),
        "mbps" | "mbit" | "mbit/s" => "mbit".to_string(),
        "gbps" | "gbit" | "gbit/s" => "gbit".to_string(),
        _ => lower,
    }
}

fn run_command(command: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|error| format!("failed to execute {command}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("{command}: {}", stderr.trim()))
    }
}

fn run_command_with_input(command: &str, args: &[&str], input: &str) -> Result<(), String> {
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to execute {command}: {error}"))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|error| format!("failed to write to {command}: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for {command}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("{command}: {}", stderr.trim()))
    }
}

pub fn run_command_capture(command: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("failed to execute {command}: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn extract_port(bind_addr: &str) -> Option<u16> {
    bind_addr
        .rsplit(':')
        .next()
        .and_then(|value| value.parse::<u16>().ok())
}

pub fn read_file_bytes(path: &str) -> Result<Vec<u8>, String> {
    fs::read(Path::new(path)).map_err(|error| format!("failed to read file {path}: {error}"))
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_types::{PortForwardRule, SpeedLimitRule};

    fn speed_rule(id: i64, enabled: bool, applied: bool) -> SpeedLimitRule {
        SpeedLimitRule {
            id, interface_name: "eth0".into(), protocol: "tcp".into(), port: 443,
            rate_value: 500, rate_unit: "mbps".into(), enabled, applied,
            last_status: String::new(), created_at_unix: 0, updated_at_unix: 0,
        }
    }

    #[test]
    fn disabled_unapplied_speed_limits_emit_no_network_commands() {
        let rule = speed_rule(1, false, false);
        assert!(speed_limit_apply_commands(&rule).unwrap().is_empty());
        let statuses = sync_speed_limits_with_backend(&[rule], |_| panic!("disabled rule must not run tc"));
        assert_eq!(statuses, vec![(1, false, "disabled".into())]);
    }

    #[test]
    fn mixed_rules_remove_only_disabled_class_and_preserve_enabled_rates() {
        let filters = r#"[
            {"protocol":"ip","pref":1,"kind":"u32","options":{"fh":"800::800","flowid":"1:101"}},
            {"protocol":"ip","pref":1,"kind":"u32","options":{"fh":"800::801","flowid":"1:102"}}
        ]"#;
        let rules = [speed_rule(1, false, true), speed_rule(2, true, false)];
        let mut commands = Vec::new();
        let statuses = sync_speed_limits_with_owned_backend(&rules, &mut BTreeSet::from(["eth0".into()]), |command| {
            commands.push(command.join(" "));
            Ok(if command.get(1).is_some_and(|value| value == "qdisc") {
                r#"[{"kind":"htb","handle":"1:","root":true}]"#.into()
            } else if command.first().is_some_and(|value| value == "-j") { filters.to_string() } else { String::new() })
        });
        assert_eq!(statuses[0], (1, false, "disabled".into()));
        assert!(statuses[1].1);
        let commands = commands.join("\n");
        assert!(commands.contains("handle 800::800 u32"));
        assert!(commands.contains("handle 800::801 u32"));
        assert!(!commands.contains("class del dev eth0 classid 1:102"));
        assert!(commands.contains("class del dev eth0 classid 1:101"));
        assert!(!commands.contains("qdisc del"));
        assert!(!commands.contains("qdisc del"));
        assert!(commands.contains("classid 1:102 htb rate 500mbit ceil 500mbit"));
        assert!(!commands.contains("classid 1:101 htb rate"));
    }

    #[test]
    fn a_failed_disabled_cleanup_remains_marked_applied() {
        let statuses = sync_speed_limits_with_backend(&[speed_rule(1, false, true)], |_| Err("permission denied".into()));
        assert!(statuses[0].1);
        assert!(statuses[0].2.contains("failed to remove disabled speed limit"));
    }

    fn partial_shaping_filters() -> &'static str {
        r#"[
            {"protocol":"ip","pref":2,"kind":"flower","handle":"0x20000001","options":{"classid":"1:101"}},
            {"protocol":"ip","pref":2,"kind":"flower","handle":"0x20000002","options":{"classid":"1:102"}}
        ]"#
    }

    #[test]
    fn new_partial_shaping_failure_rolls_back_only_its_class_and_filter() {
        let mut commands = Vec::new();
        let mut installed_ipv4 = false;
        let statuses = sync_speed_limits_with_owned_backend(
            &[speed_rule(1, true, false)], &mut BTreeSet::from(["eth0".into()]), |command| {
                let text = command.join(" ");
                commands.push(text.clone());
                if text == "-j qdisc show dev eth0" {
                    return Ok(r#"[{"kind":"htb","handle":"1:","root":true}]"#.into());
                }
                if text == "-j filter show dev eth0 parent 1:" {
                    return Ok(if installed_ipv4 { partial_shaping_filters() } else { "[]" }.into());
                }
                if text.starts_with("filter replace") && text.contains("protocol ip ") { installed_ipv4 = true; }
                if text.starts_with("filter replace") && text.contains("protocol ipv6 ") { return Err("IPv6 flower rejected".into()); }
                Ok(String::new())
            });
        assert!(!statuses[0].1);
        assert!(statuses[0].2.contains("partial rule rolled back"));
        assert!(commands.iter().any(|command| command == "filter del dev eth0 protocol ip parent 1: pref 2 handle 0x20000001 flower"));
        assert!(commands.iter().any(|command| command == "class del dev eth0 classid 1:101"));
        assert!(!commands.iter().any(|command| command.contains("qdisc del") || command.contains("handle 0x20000002") || command == "class del dev eth0 classid 1:102" || command == "class del dev eth0 classid 1:1" || command == "class del dev eth0 classid 1:999"));
    }

    #[test]
    fn failed_partial_shaping_rollback_stays_applied_and_delete_retries() {
        let mut row = speed_rule(1, true, false);
        let statuses = sync_speed_limits_with_owned_backend(
            &[row.clone()], &mut BTreeSet::from(["eth0".into()]), |command| {
                let text = command.join(" ");
                if text == "-j qdisc show dev eth0" { return Ok(r#"[{"kind":"htb","handle":"1:","root":true}]"#.into()); }
                if text == "-j filter show dev eth0 parent 1:" { return Ok(partial_shaping_filters().into()); }
                if text.starts_with("filter replace") && text.contains("protocol ipv6 ") { return Err("IPv6 flower rejected".into()); }
                if text.starts_with("filter del") { return Err("cleanup permission denied".into()); }
                Ok(String::new())
            });
        assert!(statuses[0].1);
        assert!(statuses[0].2.contains("cleanup failed: cleanup permission denied"));
        row.applied = statuses[0].1;
        row.enabled = false;
        let mut commands = Vec::new();
        let disabled = sync_speed_limits_with_owned_backend(&[row], &mut BTreeSet::from(["eth0".into()]), |command| {
            commands.push(command.join(" "));
            Ok(if command.get(1).is_some_and(|value| value == "qdisc") {
                r#"[{"kind":"htb","handle":"1:","root":true}]"#.into()
            } else if command.first().is_some_and(|value| value == "-j") { partial_shaping_filters().into() } else { String::new() })
        });
        assert_eq!(disabled, vec![(1, false, "disabled".into())]);
        assert!(commands.iter().any(|command| command.contains("handle 0x20000001 flower")));
        assert!(commands.iter().any(|command| command == "class del dev eth0 classid 1:101"));
        assert!(!commands.iter().any(|command| command.contains("handle 0x20000002") || command.contains("qdisc del")));
    }

    #[test]
    fn applied_shaping_reapply_failure_keeps_the_existing_class() {
        let mut commands = Vec::new();
        let statuses = sync_speed_limits_with_owned_backend(
            &[speed_rule(1, true, true)], &mut BTreeSet::from(["eth0".into()]), |command| {
                let text = command.join(" ");
                commands.push(text.clone());
                if text == "-j qdisc show dev eth0" { return Ok(r#"[{"kind":"htb","handle":"1:","root":true}]"#.into()); }
                if text == "-j filter show dev eth0 parent 1:" { return Ok(partial_shaping_filters().into()); }
                if text.starts_with("filter replace") && text.contains("protocol ipv6 ") { return Err("IPv6 flower rejected".into()); }
                Ok(String::new())
            });
        assert!(statuses[0].1);
        assert!(statuses[0].2.contains("failed to apply speed limit"));
        assert!(!commands.iter().any(|command| command.starts_with("filter del") || command.starts_with("class del")));
    }

    #[test]
    fn legacy_applied_shaping_cannot_delete_a_foreign_matching_root() {
        let mut commands = Vec::new();
        let statuses = sync_speed_limits_with_backend(&[speed_rule(1, false, true)], |command| {
            commands.push(command.join(" "));
            Ok(r#"[{"kind":"htb","handle":"1:","root":true}]"#.into())
        });
        assert!(statuses[0].1);
        assert!(statuses[0].2.contains("not confirmed as owned"));
        assert_eq!(commands, vec!["-j qdisc show dev eth0"]);
    }

    #[test]
    fn disappeared_shaping_root_is_already_clean_without_mutation() {
        for absent in [Ok(r#"[{"kind":"noqueue","handle":"0:","root":true}]"#.to_string()), Err("Cannot find device eth0".to_string())] {
            let mut commands = Vec::new();
            let statuses = sync_speed_limits_with_backend(&[speed_rule(1, false, true)], |command| {
                commands.push(command.join(" "));
                absent.clone()
            });
            assert_eq!(statuses, vec![(1, false, "disabled".into())]);
            assert_eq!(commands, vec!["-j qdisc show dev eth0"]);
        }
    }

    fn sample_rule(protocol: &str, family: &str, target_host: &str, target_port: u16) -> PortForwardRule {
        PortForwardRule {
            id: 42,
            label: "rule".to_string(),
            protocol: protocol.to_string(),
            family: family.to_string(),
            interface_name: "eth0".to_string(),
            source_ip: "198.51.100.10".to_string(),
            listen_port: 443,
            target_host: target_host.to_string(),
            target_port,
            enabled: true,
            last_status: String::new(),
            created_at_unix: 0,
            updated_at_unix: 0,
        }
    }

    #[test]
    fn ipv6_dnat_destination_wraps_host_in_brackets() {
        assert_eq!(
            build_dnat_destination(true, "tcp", "2001:db8::10", 8443),
            "[2001:db8::10]:8443"
        );
    }

    #[test]
    fn ipv4_dnat_destination_keeps_classic_host_port_format() {
        assert_eq!(
            build_dnat_destination(false, "udp", "10.0.0.2", 5353),
            "10.0.0.2:5353"
        );
    }

    #[test]
    fn icmp_destination_has_no_port_suffix() {
        assert_eq!(
            build_dnat_destination(false, "icmp", "10.0.0.9", 0),
            "10.0.0.9"
        );
    }

    #[test]
    fn forward_specs_include_conntrack_and_ipv6_safe_dnat() {
        let rule = sample_rule("tcp", "ipv6", "2001:db8::20", 8443);
        let specs = build_forward_rule_specs(
            true,
            "IRANMONITOR_FWD_PRE",
            "IRANMONITOR_FWD_OUT",
            "IRANMONITOR_FWD_POST",
            "IRANMONITOR_FWD_ALLOW",
            &rule,
        );
        let flattened = specs
            .iter()
            .map(|spec| spec.join(" "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(flattened.contains("--to-destination [2001:db8::20]:8443"));
        assert!(flattened.contains("-m conntrack --ctstate NEW,ESTABLISHED,RELATED"));
        assert!(flattened.contains("-m conntrack --ctstate ESTABLISHED,RELATED"));
    }
    fn watcher(id:i64)->TrafficWatcher {TrafficWatcher{id,label:"watch".into(),family:"ipv4".into(),direction:"input".into(),protocol:"any".into(),source_ip:"*".into(),target_port:443,enabled:true,last_packets:0,last_bytes:0,total_packets:100,total_bytes:1000,current_bps:0,created_at_unix:0,updated_at_unix:0}}
    #[test]
    fn watcher_any_port_counts_tcp_udp_and_overlaps_without_return(){
        let body=build_stats_restore(&[watcher(1),watcher(2)],false).unwrap();assert_eq!(body.matches("--dport 443").count(),4);assert!(!body.contains("RETURN"));assert!(body.contains(" -p 6 ") && body.contains(" -p 17 "));
        let mut raw=watcher(1);raw.protocol="esp".into();raw.target_port=0;assert!(!build_stats_restore(&[raw.clone()],false).unwrap().contains("--dport"));raw.target_port=443;assert!(build_stats_restore(&[raw],false).is_err());
    }
    #[test]
    fn watcher_numeric_protocol_zero_is_exact_for_both_families() {
        let mut row = watcher(1);
        row.family = "both".into(); row.target_port = 0; row.protocol = "0".into();
        let ipv4 = build_stats_restore(&[row.clone()], false).unwrap();
        let ipv6 = build_stats_restore(&[row.clone()], true).unwrap();
        assert!(ipv4.contains("-m u32 --u32 \"6&0xff=0\""));
        assert!(ipv6.contains("-m u32 --u32 \"4>>8&0xff=0\""));
        assert!(!ipv4.contains(" -p 0 ") && !ipv6.contains(" -p 0 "));
        row.protocol = "any".into();
        for ipv6 in [false, true] {
            let wildcard = build_stats_restore(&[row.clone()], ipv6).unwrap();
            assert!(!wildcard.contains("--u32") && !wildcard.contains(" -p "));
        }
    }
    #[test]
    fn ah_remains_a_valid_watcher_but_is_rejected_for_source_rewriting() {
        for protocol in ["ah","51"] {
            let mut row=watcher(1);row.family="both".into();row.protocol=protocol.into();row.target_port=0;
            for ipv6 in [false,true] {
                assert!(build_stats_restore(&[row.clone()],ipv6).unwrap().contains(" -p 51 "));
            }
            for mode in ["paired","snat"] {
                let error=crate::network_rules::validate_source_ip(mode,"ipv4",protocol,0,"eth0","198.51.100.2","203.0.113.9","").unwrap_err();
                assert!(error.contains("AH authenticates"));
            }
        }
        // Preserve legacy wildcard selector compatibility.
        assert!(crate::network_rules::validate_source_ip("paired","ipv4","any",0,"eth0","198.51.100.2","203.0.113.9","").is_ok());
    }
    #[test]
    fn counter_dump_parses_native_and_legacy_formats_and_sums_expanded_matches(){
        let counters=parse_counter_dump("[12:1200] -A IRANMONITOR_STATS_IN -p tcp -m comment --comment \"imwatch-1\"\n[3:300] -A IRANMONITOR_STATS_IN -p udp -m comment --comment imwatch-1\n-A IRANMONITOR_STATS_IN -c 4 400 -m comment --comment imwatch-2 -j RETURN\n");
        assert_eq!(counters["imwatch-1"],(15,1500));assert_eq!(counters["imwatch-2"],(4,400));
    }
    #[test]
    fn watcher_totals_survive_restarts_and_kernel_counter_resets(){
        let mut baseline=BTreeMap::new();let mut row=watcher(1);
        let first=accumulate_watcher_counters(&[row.clone()],10,&BTreeMap::from([("imwatch-1".into(),(10,500))]),&BTreeMap::new(),&mut baseline);
        assert_eq!(first[&1],(110,1500,50));row.total_packets=110;row.total_bytes=1500;
        let second=accumulate_watcher_counters(&[row.clone()],10,&BTreeMap::from([("imwatch-1".into(),(14,700))]),&BTreeMap::new(),&mut baseline);
        assert_eq!(second[&1],(114,1700,20));row.total_packets=114;row.total_bytes=1700;
        let reset=accumulate_watcher_counters(&[row],10,&BTreeMap::from([("imwatch-1".into(),(2,80))]),&BTreeMap::new(),&mut baseline);assert_eq!(reset[&1],(116,1780,8));
    }
    #[test]
    fn speed_apply_reuses_root_and_keeps_stable_filter_handle(){
        let row=speed_rule(1,true,true);let mut calls=Vec::new();let statuses=sync_speed_limits_with_owned_backend(&[row.clone()],&mut BTreeSet::from(["eth0".into()]),|values|{calls.push(values.to_vec());Ok(if values.get(1).is_some_and(|value|value=="qdisc"){r#"[{"kind":"htb","handle":"1:","root":true}]"#.into()}else if values.first().is_some_and(|value|value=="-j"){"[]".into()}else{String::new()})});
        assert!(statuses[0].1);assert!(!calls.iter().any(|values|values.first().is_some_and(|value|value=="qdisc")));assert!(!calls.iter().any(|values|values.starts_with(&["class".into(),"del".into()])));
        let commands=speed_limit_apply_commands(&row).unwrap();let filter=&commands[3];assert!(filter.join(" ").contains("pref 2 handle 0x20000001 flower ip_proto tcp src_port 443 classid 1:101"));
    }
    #[test]
    fn foreign_root_shaping_is_not_replaced(){
        let mut calls=Vec::new();let statuses=sync_speed_limits_with_backend(&[speed_rule(1,true,false)],|values|{calls.push(values.to_vec());Ok(r#"[{"kind":"htb","handle":"1:","root":true}]"#.into())});assert!(!statuses[0].1);assert!(statuses[0].2.contains("unrelated root qdisc"));assert_eq!(calls.len(),1);
    }
    fn flower_filter_details(filters:&serde_json::Value)->Vec<&serde_json::Value>{
        // tc dumps a header record and then detailed filter records for each
        // preference. Headers have no options/handle and are not filters.
        filters.as_array().expect("tc filter inventory must be an array").iter()
            .filter(|row|row["kind"]=="flower" && row.get("options").is_some_and(serde_json::Value::is_object)).collect()
    }
    #[test]
    fn shaping_inventory_ignores_headers_but_keeps_actual_duplicate_details(){
        let mut inventory:serde_json::Value=serde_json::from_str(r#"[
            {"protocol":"ip","pref":2,"kind":"flower","chain":0},
            {"protocol":"ip","pref":2,"kind":"flower","chain":0,"options":{"handle":536870913,"classid":"1:101"}},
            {"protocol":"ipv6","pref":3,"kind":"flower","chain":0},
            {"protocol":"ipv6","pref":3,"kind":"flower","chain":0,"options":{"handle":536870913,"classid":"1:101"}}
        ]"#).unwrap();
        assert_eq!(inventory.as_array().unwrap().len(),4);
        assert_eq!(flower_filter_details(&inventory).len(),2);
        let duplicate=inventory[1].clone();
        inventory.as_array_mut().unwrap().push(duplicate);
        assert_eq!(flower_filter_details(&inventory).len(),3,"actual duplicates must not be hidden by deduplicating handles");
    }
    #[test]
    fn connection_limits_use_correct_family_masks_and_reject_zero(){
        let policy=TcpConnLimitPolicy{id:1,enabled:true,target_port:443,limit_per_ip:50,last_status:String::new(),updated_at_unix:0};assert!(build_connlimit_restore(&policy,false).unwrap().contains("--connlimit-mask 32"));assert!(build_connlimit_restore(&policy,true).unwrap().contains("--connlimit-mask 128"));let mut zero=policy;zero.limit_per_ip=0;assert!(build_connlimit_restore(&zero,false).is_err());zero.enabled=false;assert!(!build_connlimit_restore(&zero,false).unwrap().contains("REJECT"));
    }
    #[test]
    fn forwarding_matches_local_destinations_and_only_dnat_connections(){
        for ipv6 in [false,true] {
            let row=sample_rule("udp",if ipv6{"ipv6"}else{"ipv4"},if ipv6{"fd00:1::2"}else{"192.0.2.2"},8443);
            let body=build_forward_restore(ipv6,&[&row]);
            assert_eq!(body.matches("--dst-type LOCAL").count(),2);
            assert_eq!(body.matches("--ctstate DNAT").count(),3);
            assert!(!body.contains("--ctstatus"));
            assert_eq!(body.matches("--ctorigdstport 443").count(),3);
            for line in body.lines().filter(|line|line.starts_with("-A IRANMONITOR_FWD_ALLOW ")) {
                assert_eq!(line.matches("-m conntrack").count(),2);
                assert_eq!(line.matches("--ctstate").count(),2);
                assert!(line.contains("--ctstate NEW,ESTABLISHED,RELATED") || line.contains("--ctstate ESTABLISHED,RELATED"));
                assert!(line.contains("-m conntrack --ctstate DNAT"));
                // A comma-joined state list would OR DNAT with NEW/ESTABLISHED
                // and accidentally admit unrelated forwarded connections.
                assert!(!line.contains("RELATED,DNAT"));
            }
            assert!(!body.contains("-F PREROUTING"));assert!(!body.contains("-F FORWARD"));assert!(body.ends_with("COMMIT\n"));
        }
    }

    #[cfg(target_os="linux")]
    #[test]
    #[ignore="requires disposable namespace setup in source-ip-acceptance.sh"]
    fn linux_network_acceptance_controls(){
        use std::net::UdpSocket;use std::time::{Duration,Instant};
        assert_eq!(std::env::var("IMONITOR_ACCEPT_DISPOSABLE").as_deref(),Ok("1"));
        let ready=Path::new("/tmp/imonitor-controls-ready");
        if std::env::var("IMONITOR_ACCEPT_ROLE").as_deref()==Ok("server"){
            let ipv4=UdpSocket::bind("192.0.2.2:44002").unwrap();let ipv6=UdpSocket::bind("[fd00:1::2]:44002").unwrap();
            fs::write(ready,"ready").unwrap();
            for socket in [ipv4,ipv6]{socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();for _ in 0..2{let mut buffer=[0u8;64];let(size,source)=socket.recv_from(&mut buffer).unwrap();socket.send_to(&buffer[..size],source).unwrap();}}
            return;
        }
        let _=fs::remove_file(ready);
        let server=std::env::var("IMONITOR_ACCEPT_SERVER").unwrap();let mut child=Command::new("ip").args(["netns","exec",&server]).arg(std::env::current_exe().unwrap())
            .args(["--ignored","--exact","platform::tests::linux_network_acceptance_controls","--nocapture"]).env("IMONITOR_ACCEPT_ROLE","server").spawn().unwrap();
        let start=Instant::now();while !ready.is_file(){assert!(start.elapsed()<Duration::from_secs(5));std::thread::sleep(Duration::from_millis(25));}
        let mut watchers=[watcher(10),watcher(11)];for row in &mut watchers{row.family="both".into();row.direction="output".into();row.protocol="udp".into();row.target_port=44003;row.total_packets=0;row.total_bytes=0;}
        sync_traffic_watchers(&watchers).unwrap();
        let mut forward4=sample_rule("udp","ipv4","192.0.2.2",44002);forward4.listen_port=54000;forward4.source_ip=String::new();forward4.interface_name=String::new();
        let mut forward6=forward4.clone();forward6.id=43;forward6.family="ipv6".into();forward6.target_host="fd00:1::2".into();
        let statuses=sync_port_forward_rules(&[forward4,forward6]).unwrap();assert!(statuses.iter().all(|row|row.1));
        let policy=TcpConnLimitPolicy{id:1,enabled:true,target_port:44002,limit_per_ip:12,last_status:String::new(),updated_at_unix:0};apply_tcp_conn_limit(&policy).unwrap();
        for command in ["iptables-save","ip6tables-save"]{assert!(run_command_capture(command,&[]).unwrap().contains("--connlimit-above 12"));}
        let runtime=Path::new("/tmp/imonitor-shaping-acceptance");let mut shaping=speed_rule(1,true,false);shaping.protocol="udp".into();shaping.port=44003;shaping.rate_value=100;shaping.interface_name="vethc".into();
        let statuses=sync_speed_limits(&[shaping.clone()],runtime).unwrap();assert!(statuses[0].1,"{:?}",statuses);shaping.applied=true;
        let statuses=sync_speed_limits(&[shaping.clone()],runtime).unwrap();assert!(statuses[0].1);
        let filters:serde_json::Value=serde_json::from_str(&run_command_capture("tc",&["-j","filter","show","dev","vethc","parent","1:"]).unwrap()).unwrap();
        let details=flower_filter_details(&filters);
        assert_eq!(details.len(),2,"reapply created duplicate shaping filters: {filters}");
        let protocols=details.iter().map(|row|row["protocol"].as_str().unwrap_or("")).collect::<BTreeSet<_>>();
        assert_eq!(protocols,BTreeSet::from(["ip","ipv6"]),"wrong shaping filter families: {filters}");
        for row in details {
            let options=&row["options"];
            let class=options.get("classid").or_else(||options.get("flowid")).and_then(serde_json::Value::as_str);
            assert_eq!(class,Some("1:101"),"wrong shaping class: {filters}");
            let handle=options.get("handle").or_else(||row.get("handle")).unwrap();
            assert!(handle.as_u64()==Some(0x20000001) || handle.as_str()==Some("0x20000001"),"wrong stable shaping handle: {filters}");
        }
        for (bind,local,direct) in [("192.0.2.1:44003","192.0.2.1:54000","192.0.2.2:44002"),("[fd00:1::1]:44003","[fd00:1::1]:54000","[fd00:1::2]:44002")]{
            let socket=UdpSocket::bind(bind).unwrap();socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            for destination in [local,direct]{socket.send_to(b"network control probe",destination).unwrap();let mut buffer=[0u8;64];let(size,_)=socket.recv_from(&mut buffer).unwrap();assert_eq!(&buffer[..size],b"network control probe");}
        }
        assert!(child.wait().unwrap().success());
        let counters=read_traffic_watcher_counters(&watchers,1).unwrap();assert!(counters[&10].0>=4 && counters[&10].1>0,"watcher did not count packets: {:?}",counters);assert_eq!(counters[&10],counters[&11],"overlapping watcher did not see the same packets");
        shaping.enabled=false;let statuses=sync_speed_limits(&[shaping],runtime).unwrap();assert_eq!(statuses[0].1,false);assert_eq!(statuses[0].2,"disabled");
        let classes=run_command_capture("tc",&["class","show","dev","vethc"]).unwrap();assert!(!classes.contains("1:101 "));
        sync_port_forward_rules(&[]).unwrap();sync_traffic_watchers(&[]).unwrap();let mut disabled=policy;disabled.enabled=false;apply_tcp_conn_limit(&disabled).unwrap();
        for command in ["iptables-save","ip6tables-save"]{let body=run_command_capture(command,&[]).unwrap();assert!(!body.contains("--connlimit-above"));assert!(!body.contains("-j DNAT"));assert!(body.contains("-A POSTROUTING -j SENTINEL_ACCEPT"));}
    }

}
