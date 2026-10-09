use crate::app_types::SourceIpRule;
use crate::network_rules::{parse_ip_protocol, runtime_namespace, validate_source_ip};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

static SOURCE_IP_SYNC: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Clone)]
struct NetworkCommand {
    program: String,
    args: Vec<String>,
    input: Option<String>,
}

fn execute(command: &NetworkCommand) -> Result<String, String> {
    let mut child = Command::new(&command.program).args(&command.args)
        .stdin(if command.input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
        .map_err(|error| format!("{}: {error}", command.program))?;
    if let Some(input) = &command.input {
        child.stdin.take().ok_or_else(|| "network command stdin is missing".to_string())?
            .write_all(input.as_bytes()).map_err(|error| format!("network command input: {error}"))?;
    }
    let output = child.wait_with_output().map_err(|error| format!("network command wait: {error}"))?;
    if !output.status.success() {
        return Err(format!("{}: {}", command.program, String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn sync(rules: &[SourceIpRule], runtime: &Path) -> Result<Vec<(i64, bool, String)>, String> {
    let _guard = SOURCE_IP_SYNC.lock().map_err(|_| "source IP synchronization lock failed")?;
    let mut results = BTreeMap::new();
    let mut valid = Vec::new();
    for rule in rules {
        if !rule.enabled {
            results.insert(rule.id, (false, "disabled".to_string()));
            valid.push(rule.clone());
            continue;
        }
        match validate_source_ip(&rule.mode, &rule.family, &rule.protocol, rule.match_port, rule.interface_name.trim(),
            rule.destination_ip.trim(), rule.source_ip.trim(), rule.translate_ip.trim()) {
            Ok(()) => valid.push(rule.clone()),
            Err(error) => { results.insert(rule.id, (false, format!("failed to apply '{}': {error}", rule.label))); }
        }
    }
    let prior_owned=read_paired_ownership(&runtime.join("source_ip_engine_state.json"))?;
    let state_path = runtime.join("source_ip_snat_state.json");
    let previous: BTreeSet<String> = match fs::read(&state_path) {
        Ok(body)=>serde_json::from_slice(&body).map_err(|error|format!("invalid SNAT ownership state: {error}"))?,
        Err(error) if error.kind()==std::io::ErrorKind::NotFound=>BTreeSet::new(),Err(error)=>return Err(format!("SNAT ownership state: {error}")),
    };
    let chain = format!("IM_SNAT_{}", runtime_namespace(&runtime.to_string_lossy()));
    let mut installed = previous.clone();
    for family in ["ipv4", "ipv6"] {
        let active = valid.iter().filter(|rule| rule.mode == "snat" && rule.enabled && rule.family.eq_ignore_ascii_case(family)).collect::<Vec<_>>();
        if active.is_empty() && !previous.contains(family) { continue; }
        let outcome = sync_snat_family(&chain, family == "ipv6", &active, &mut execute);
        if outcome.is_ok() {
            if active.is_empty() { installed.remove(family); } else { installed.insert(family.into()); }
        }
        for rule in valid.iter().filter(|rule| rule.mode == "snat" && rule.family.eq_ignore_ascii_case(family)) {
            let value = match &outcome {
                Ok(()) if rule.enabled => (true, format!("active SNAT: {} → {} ({})", rule.destination_ip, rule.source_ip, family)),
                Ok(()) => (false, "disabled".into()),
                Err(error) => (false, format!("failed to synchronize SNAT: {error}")),
            };
            results.insert(rule.id, value);
        }
        if let Err(error) = &outcome {
            // Keep cleanup metadata for a failed removal, even when the deleted
            // rule is not in this payload. The next apply can retry safely.
            if !valid.iter().any(|rule| rule.mode == "snat" && rule.family.eq_ignore_ascii_case(family)) {
                return Err(format!("failed to remove prior {family} SNAT rules: {error}"));
            }
        }
    }
    fs::create_dir_all(runtime).map_err(|error| format!("source IP runtime: {error}"))?;
    let next=state_path.with_extension("json.next");
    fs::write(&next,serde_json::to_vec(&installed).map_err(|error|error.to_string())?).map_err(|error|format!("source IP SNAT state: {error}"))?;
    fs::rename(&next,&state_path).map_err(|error|format!("source IP SNAT state commit: {error}"))?;

    let paired = valid.iter().filter(|rule| rule.mode == "paired").collect::<Vec<_>>();
    if paired.iter().any(|rule| rule.enabled) || prior_owned {
        match sync_paired(&paired, runtime) {
            Ok(statuses) => { for (id, applied, message) in statuses { results.insert(id, (applied, message)); } }
            Err(error) => {
                if paired.is_empty() { return Err(error); }
                for rule in &paired { results.insert(rule.id, (false, format!("failed to synchronize paired rewriting: {error}"))); }
            }
        }
    }
    Ok(rules.iter().map(|rule| {
        let (applied, message) = results.remove(&rule.id).unwrap_or((false, "disabled".into()));
        (rule.id, applied, message)
    }).collect())
}

fn read_paired_ownership(path:&Path)->Result<bool,String>{
    let body=match fs::read(path){Ok(body)=>body,Err(error) if error.kind()==std::io::ErrorKind::NotFound=>return Ok(false),Err(error)=>return Err(format!("paired ownership state: {error}"))};
    let value:Value=serde_json::from_slice(&body).map_err(|error|format!("invalid paired ownership state: {error}"))?;
    let object=value.as_object().ok_or("paired ownership state is not an object")?;
    let mut owned=false;
    for key in ["applied","filters","xdp"]{
        if let Some(value)=object.get(key){let items=value.as_array().ok_or_else(||format!("paired ownership field {key} is not an array"))?;owned|=!items.is_empty();}
    }
    Ok(owned)
}

fn sync_snat_family(
    chain: &str, ipv6: bool, rules: &[&SourceIpRule],
    backend: &mut impl FnMut(&NetworkCommand) -> Result<String, String>,
) -> Result<(), String> {
    let program = if ipv6 { "ip6tables" } else { "iptables" };
    let command = |args: &[&str]| NetworkCommand { program: program.into(), args: args.iter().map(|arg| arg.to_string()).collect(), input: None };
    if rules.is_empty() {
        match backend(&command(&["-w","5","-t","nat","-S",chain])) {
            Err(error) if chain_missing(&error) => return Ok(()),
            Err(error) => return Err(error), Ok(_) => {},
        }
        backend(&command(&["-w","5","-t","nat","-F",chain]))?;
        // Remove only this runtime's jump and chain; never flush POSTROUTING.
        if backend(&command(&["-w","5","-t","nat","-C","POSTROUTING","-j",chain])).is_ok() {
            backend(&command(&["-w","5","-t","nat","-D","POSTROUTING","-j",chain]))?;
        }
        backend(&command(&["-w","5","-t","nat","-X",chain]))?;
        return Ok(());
    }
    let inventory = backend(&NetworkCommand { program: "ip".into(), args: vec!["-j".into(), if ipv6 { "-6".into() } else { "-4".into() }, "address".into(), "show".into()], input: None })?;
    let addresses = assigned_addresses(&inventory)?;
    for rule in rules {
        if !addresses.contains(&rule.source_ip.trim().parse::<std::net::IpAddr>().map_err(|_| "invalid SNAT source IP")?.to_string()) {
            return Err(format!("SNAT source {} must be assigned to this server", rule.source_ip));
        }
    }
    let body = build_snat_restore(chain, ipv6, rules)?;
    backend(&NetworkCommand { program: format!("{program}-restore"), args: vec!["-w".into(),"5".into(),"--noflush".into()], input: Some(body) })?;
    if backend(&command(&["-w","5","-t","nat","-C","POSTROUTING","-j",chain])).is_err() {
        backend(&command(&["-w","5","-t","nat","-I","POSTROUTING","1","-j",chain]))?;
    }
    Ok(())
}

fn assigned_addresses(raw: &str) -> Result<BTreeSet<String>, String> {
    let data: Value = serde_json::from_str(raw).map_err(|_| "ip returned invalid address metadata".to_string())?;
    let interfaces = data.as_array().ok_or_else(|| "ip address metadata is not an array".to_string())?;
    Ok(interfaces.iter().flat_map(|item| item.get("addr_info").and_then(Value::as_array).into_iter().flatten())
        .filter_map(|address| address.get("local").and_then(Value::as_str)).filter_map(|address| address.parse::<std::net::IpAddr>().ok()).map(|address| address.to_string()).collect())
}

fn chain_missing(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("no chain/target/match") || error.contains("does not exist") || error.contains("no such file or directory")
}

fn build_snat_restore(chain: &str, ipv6: bool, rules: &[&SourceIpRule]) -> Result<String, String> {
    let mut body = format!("*nat\n:{chain} - [0:0]\n-F {chain}\n");
    for rule in rules {
        validate_source_ip("snat", &rule.family, &rule.protocol, rule.match_port, rule.interface_name.trim(), rule.destination_ip.trim(), rule.source_ip.trim(), rule.translate_ip.trim())?;
        let protocol = parse_ip_protocol(&rule.protocol, ipv6)?;
        let numbers = if protocol.any && rule.match_port != 0 { vec![Some(6),Some(17)] }
            else if protocol.any { vec![None] } else { vec![Some(protocol.number)] };
        for number in numbers {
            // Conventional SNAT chooses outgoing destination port, and conntrack
            // performs the reverse mapping for replies without another rule.
            let mut line = format!("-A {chain} -d {}", rule.destination_ip.trim());
            if !rule.interface_name.trim().is_empty() { line.push_str(&format!(" -o {}", rule.interface_name.trim())); }
            if let Some(number) = number {
                if number == 0 {
                    // iptables interprets -p 0 as all; u32 keeps custom protocol
                    // zero distinct from the wildcard selection.
                    line.push_str(if ipv6 { " -m u32 --u32 \"4>>8&0xff=0\"" } else { " -m u32 --u32 \"6&0xff=0\"" });
                } else { line.push_str(&format!(" -p {number}")); }
            }
            if rule.match_port != 0 { line.push_str(&format!(" --dport {}", rule.match_port)); }
            line.push_str(&format!(" -m comment --comment imsrc-{} -j SNAT --to-source {}\n", rule.id, rule.source_ip.trim()));
            body.push_str(&line);
        }
    }
    body.push_str("COMMIT\n");
    Ok(body)
}

fn sync_paired(rules: &[&SourceIpRule], runtime: &Path) -> Result<Vec<(i64, bool, String)>, String> {
    let helper = resolve_helper().ok_or_else(|| "paired source IP rewriting needs the installed imonitor-bpf helper".to_string())?;
    let key_file = runtime.join(".engine.key");
    let token = fs::read_to_string(&key_file).map_err(|_| "source IP engine key is missing".to_string())?;
    let payload = json!({"version":2,"rules":rules});
    let mut child = Command::new(helper).arg("apply")
        .env("IMONITOR_INTERNAL_CALL","1").env("IMONITOR_ENGINE_TOKEN",token.trim())
        .env("IMONITOR_ENGINE_KEY_FILE",&key_file).env("IMONITOR_ENGINE_STATE_FILE",runtime.join("source_ip_engine_state.json"))
        .env("IMONITOR_ENGINE_PIN_ROOT",format!("/sys/fs/bpf/imonitor-{}",runtime_namespace(&runtime.to_string_lossy())))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
        .map_err(|error| format!("failed to launch source IP helper: {error}"))?;
    child.stdin.take().ok_or_else(|| "source IP helper stdin is missing".to_string())?
        .write_all(serde_json::to_string(&payload).map_err(|error| error.to_string())?.as_bytes()).map_err(|error| error.to_string())?;
    let output = child.wait_with_output().map_err(|error| error.to_string())?;
    if !output.status.success() { return Err(String::from_utf8_lossy(&output.stderr).trim().to_string()); }
    parse_helper_response(&String::from_utf8_lossy(&output.stdout), &rules.iter().map(|rule| rule.id).collect::<BTreeSet<_>>())
}

fn parse_helper_response(raw: &str, expected: &BTreeSet<i64>) -> Result<Vec<(i64, bool, String)>, String> {
    let data: Value = serde_json::from_str(raw).map_err(|_| "source IP helper returned invalid JSON".to_string())?;
    let items = data.as_array().ok_or_else(|| "source IP helper response is not an array".to_string())?;
    let mut seen = BTreeSet::new();
    let mut statuses = Vec::new();
    for item in items {
        let id = item.get("id").and_then(Value::as_i64).ok_or_else(|| "source IP helper response has no rule id".to_string())?;
        if !expected.contains(&id) || !seen.insert(id) { return Err("source IP helper response contains an unexpected or duplicate rule".into()); }
        let ok = item.get("ok").and_then(Value::as_bool).ok_or_else(|| "source IP helper response has no apply status".to_string())?;
        let message = item.get("message").and_then(Value::as_str).filter(|value| !value.trim().is_empty()).ok_or_else(|| "source IP helper response has no details".to_string())?;
        statuses.push((id,ok,message.into()));
    }
    if &seen != expected { return Err("source IP helper response is missing a rule result".into()); }
    Ok(statuses)
}

fn resolve_helper() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("IMONITOR_BPF_HELPER") { let path = PathBuf::from(path); if path.is_file() { return Some(path); } }
    std::env::current_exe().ok().and_then(|path| path.parent().map(|parent| parent.join("imonitor-bpf")))
        .filter(|path| path.is_file()).or_else(|| { let path = PathBuf::from("/opt/imonitor/bin/imonitor-bpf"); path.is_file().then_some(path) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(family: &str, protocol: &str, port: u16) -> SourceIpRule {
        SourceIpRule { id:1,label:"Test".into(),mode:"snat".into(),family:family.into(),protocol:protocol.into(),match_port:port,
            interface_name:"eth0".into(),destination_ip:if family == "ipv6" { "2001:db8:2::/64".into() } else { "198.51.100.0/24".into() },
            source_ip:if family == "ipv6" { "2001:db8:1::5".into() } else { "192.0.2.5".into() },translate_ip:String::new(),enabled:true,last_status:String::new(),created_at_unix:0,updated_at_unix:0 }
    }

    #[test]
    fn snat_ipv4_ipv6_and_raw_protocol_restore_specs_are_real() {
        let esp = rule("ipv4","50",0);
        let raw = build_snat_restore("IM_TEST",false,&[&esp]).unwrap();
        assert!(raw.contains("-d 198.51.100.0/24 -o eth0 -p 50"));
        assert!(raw.contains("-j SNAT --to-source 192.0.2.5"));
        assert!(!raw.contains("--dport"));
        let ipv6 = rule("ipv6","udp",443);
        let raw = build_snat_restore("IM_TEST",true,&[&ipv6]).unwrap();
        assert!(raw.contains("-p 17 --dport 443"));
        assert!(raw.contains("--to-source 2001:db8:1::5"));
    }

    #[test]
    fn all_with_port_matches_tcp_and_udp_without_fake_esp_ports() {
        let all = rule("ipv4","all",443);
        let raw = build_snat_restore("IM_TEST",false,&[&all]).unwrap();
        assert_eq!(raw.matches("--dport 443").count(),2);
        assert!(raw.contains("-p 6 --dport 443") && raw.contains("-p 17 --dport 443"));
        assert!(build_snat_restore("IM_TEST",false,&[&rule("ipv4","esp",443)]).is_err());
    }

    #[test]
    fn snat_apply_is_atomic_and_removal_only_touches_its_owned_chain() {
        let test_rule = rule("ipv6","esp",0);
        let mut calls = Vec::new();
        sync_snat_family("IM_TEST",true,&[&test_rule],&mut |cmd: &NetworkCommand| {
            calls.push(cmd.clone());
            if cmd.program == "ip" { Ok(r#"[{"addr_info":[{"local":"2001:db8:1::5"}]}]"#.into()) }
            else { Ok(String::new()) }
        }).unwrap();
        let restore = calls.iter().find(|cmd| cmd.program == "ip6tables-restore").unwrap();
        assert!(restore.args.contains(&"--noflush".into()));
        assert!(restore.input.as_ref().unwrap().ends_with("COMMIT\n"));
        calls.clear();
        sync_snat_family("IM_TEST",false,&[],&mut |cmd: &NetworkCommand| { calls.push(cmd.clone()); Ok(String::new()) }).unwrap();
        assert!(calls.iter().any(|cmd| cmd.args.ends_with(&["-X".into(),"IM_TEST".into()])));
        assert!(!calls.iter().any(|cmd| cmd.args.windows(2).any(|args| args == ["-F","POSTROUTING"])));
    }

    #[test]
    fn apply_errors_and_incomplete_helper_results_are_never_reported_as_success() {
        let test_rule = rule("ipv4","tcp",443);
        assert!(sync_snat_family("IM_TEST",false,&[&test_rule],&mut |_| Err("permission denied".into())).is_err());
        let expected = BTreeSet::from([1,2]);
        assert!(parse_helper_response(r#"[{"id":1,"ok":true,"message":"active"}]"#,&expected).is_err());
        let result = parse_helper_response(r#"[{"id":1,"ok":false,"message":"tc failed"},{"id":2,"ok":true,"message":"active"}]"#,&expected).unwrap();
        assert_eq!(result[0],(1,false,"tc failed".into()));
    }
}
#[cfg(all(test, target_os = "linux"))]
mod linux_acceptance {
    use super::*;
    use std::net::UdpSocket;
    use std::time::Duration;

    #[test]
    #[ignore = "requires the disposable namespace setup in work/source-ip-acceptance.sh"]
    fn linux_network_acceptance_snat() {
        assert_eq!(std::env::var("IMONITOR_ACCEPT_DISPOSABLE").as_deref(), Ok("1"));
        let family = std::env::var("IMONITOR_ACCEPT_FAMILY").unwrap_or("ipv4".into());
        let ipv6 = family == "ipv6";
        let peer = if ipv6 { "fd00:1::2" } else { "192.0.2.2" };
        let original = if ipv6 { "fd00:1::1" } else { "192.0.2.1" };
        let translated = if ipv6 { "fd00:1::9" } else { "198.51.100.9" };
        let destination = if ipv6 { "[fd00:1::2]:44000" } else { "192.0.2.2:44000" };
        if std::env::var("IMONITOR_ACCEPT_ROLE").as_deref() == Ok("server") {
            let socket = UdpSocket::bind(destination).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            for expected in [translated, original] {
                let mut buffer = [0u8; 128];
                let (size, source) = socket.recv_from(&mut buffer).unwrap();
                assert_eq!(source.ip().to_string(), expected);
                assert_eq!(&buffer[..size], b"imonitor checksum and conntrack probe");
                socket.send_to(source.ip().to_string().as_bytes(), source).unwrap();
            }
            return;
        }
        let server = std::env::var("IMONITOR_ACCEPT_SERVER").expect("server namespace missing");
        let binary = std::env::current_exe().unwrap();
        let mut child = Command::new("ip").args(["netns", "exec", &server]).arg(binary)
            .args(["--ignored", "--exact", "source_ip::linux_acceptance::linux_network_acceptance_snat", "--nocapture"])
            .env("IMONITOR_ACCEPT_ROLE", "server").spawn().unwrap();
        std::thread::sleep(Duration::from_millis(250));
        let test_rule = SourceIpRule { id: 1, label: "live SNAT".into(), mode: "snat".into(), family: family.clone(),
            protocol: "udp".into(), match_port: 44000, interface_name: "vethc".into(), destination_ip: peer.into(), source_ip: translated.into(),
            translate_ip: String::new(), enabled: true, last_status: String::new(), created_at_unix: 0, updated_at_unix: 0 };
        let chain = "IM_SNAT_ACCEPTANCE";
        sync_snat_family(chain, ipv6, &[&test_rule], &mut execute).unwrap();
        for expected in [translated, original] {
            let socket = UdpSocket::bind(if ipv6 { format!("[{original}]:0") } else { format!("{original}:0") }).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.connect(destination).unwrap();
            socket.send(b"imonitor checksum and conntrack probe").unwrap();
            let mut buffer = [0u8; 128]; let size = socket.recv(&mut buffer).unwrap();
            assert_eq!(std::str::from_utf8(&buffer[..size]).unwrap(), expected);
            if expected == translated { sync_snat_family(chain, ipv6, &[], &mut execute).unwrap(); }
        }
        assert!(child.wait().unwrap().success());
        let program = if ipv6 { "ip6tables" } else { "iptables" };
        let command = |program: &str, values: &[&str], input: Option<String>| NetworkCommand { program: program.into(), args: values.iter().map(|value| (*value).into()).collect(), input };
        assert!(execute(&command(program, &["-w", "5", "-t", "nat", "-S", chain], None)).is_err());
        assert!(execute(&command(program, &["-w", "5", "-t", "nat", "-C", "POSTROUTING", "-j", "SENTINEL_ACCEPT"], None)).is_ok());
    }
    #[test]
    fn corrupt_or_unreadable_paired_state_never_skips_cleanup(){
        let path=std::env::temp_dir().join(format!("imonitor-owned-state-{}-{}.json",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        assert!(!read_paired_ownership(&path).unwrap());
        for body in ["broken JSON","null",r#"{"filters":false}"#,r#"{"xdp":"lost"}"#]{fs::write(&path,body).unwrap();assert!(read_paired_ownership(&path).is_err());}
        fs::write(&path,r#"{"applied":[],"filters":[{"rule_id":1}],"xdp":[]}"#).unwrap();assert!(read_paired_ownership(&path).unwrap());fs::remove_file(&path).unwrap();
        assert!(read_paired_ownership(&std::env::temp_dir()).is_err());
    }

}

#[cfg(all(test, target_os = "linux"))]
mod paired_acceptance {
    use super::*;
    use std::net::UdpSocket;
    use std::time::{Duration,Instant};
    #[test]
    #[ignore = "requires the disposable Linux VM and paired helper"]
    fn linux_network_acceptance_paired() {
        assert_eq!(std::env::var("IMONITOR_ACCEPT_DISPOSABLE").as_deref(),Ok("1"));
        let server_role=std::env::var("IMONITOR_ACCEPT_ROLE").as_deref()==Ok("server");
        let root=std::env::var("IMONITOR_ACCEPT_RUNTIME").expect("acceptance runtime missing");
        let runtime=PathBuf::from(&root).join(if server_role {"server"} else {"client"});
        fs::create_dir_all(&runtime).unwrap();fs::write(runtime.join(".engine.key"),"disposable-network-test-key\n").unwrap();
        let mut rule=SourceIpRule{id:1,label:"live paired".into(),mode:"paired".into(),family:"ipv4".into(),protocol:"udp".into(),match_port:44001,
            interface_name:if server_role {"veths".into()} else {"vethc".into()},destination_ip:if server_role {"192.0.2.1".into()} else {"192.0.2.2".into()},
            source_ip:"203.0.113.77".into(),translate_ip:String::new(),enabled:true,last_status:String::new(),created_at_unix:0,updated_at_unix:0};
        let statuses=sync_paired(&[&rule],&runtime).unwrap();assert!(statuses[0].1,"{:?}",statuses);
        if server_role {
            let socket=UdpSocket::bind("192.0.2.2:44001").unwrap();socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            fs::write(Path::new(&root).join("ready"),"ready").unwrap();
            let mut buffer=[0u8;128];let(size,source)=socket.recv_from(&mut buffer).unwrap();assert_eq!(source.ip().to_string(),"192.0.2.1");
            assert_eq!(&buffer[..size],b"paired checksum probe");socket.send_to(b"paired reply",source).unwrap();
        } else {
            let server=std::env::var("IMONITOR_ACCEPT_SERVER").unwrap();let mut child=Command::new("ip").args(["netns","exec",&server]).arg(std::env::current_exe().unwrap())
                .args(["--ignored","--exact","source_ip::paired_acceptance::linux_network_acceptance_paired","--nocapture"]).env("IMONITOR_ACCEPT_ROLE","server").spawn().unwrap();
            let start=Instant::now();while !Path::new(&root).join("ready").is_file(){assert!(start.elapsed()<Duration::from_secs(8),"paired server did not become ready");std::thread::sleep(Duration::from_millis(50));}
            let socket=UdpSocket::bind("192.0.2.1:0").unwrap();socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();socket.connect("192.0.2.2:44001").unwrap();
            socket.send(b"paired checksum probe").unwrap();let mut buffer=[0u8;128];let size=socket.recv(&mut buffer).unwrap();assert_eq!(&buffer[..size],b"paired reply");assert!(child.wait().unwrap().success());
        }
        let output=Command::new("tc").args(["-s","-j","filter","show","dev",&rule.interface_name,"egress"]).output().unwrap();assert!(output.status.success());
        let value:Value=serde_json::from_slice(&output.stdout).unwrap();
        fn has_bytes(value:&Value)->bool {match value{Value::Object(values)=>values.get("bytes").and_then(Value::as_u64).is_some_and(|bytes|bytes>0)||values.values().any(has_bytes),Value::Array(values)=>values.iter().any(has_bytes),_=>false}}
        assert!(has_bytes(&value),"paired egress NAT did not count any actual packets: {value}");
        rule.enabled=false;let statuses=sync_paired(&[&rule],&runtime).unwrap();assert_eq!(statuses[0],(1,false,"disabled".into()));
        let ownership:Value=serde_json::from_slice(&fs::read(runtime.join("source_ip_engine_state.json")).unwrap()).unwrap();
        assert!(ownership["filters"].as_array().unwrap().is_empty());assert!(ownership["xdp"].as_array().unwrap().is_empty());
    }
}
