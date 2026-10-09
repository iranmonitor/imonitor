use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../network_rules.rs"]
mod network_rules;

#[derive(Debug, Deserialize)]
struct ApplyPayload { version: u8, rules: Vec<RuleInput> }

#[derive(Debug, Deserialize, Clone)]
struct RuleInput {
    id: i64,
    #[serde(default)] label: String,
    #[serde(default = "network_rules::default_source_ip_mode")] mode: String,
    family: String, protocol: String, match_port: u16,
    #[serde(alias = "interface_name")] interface: String,
    destination_ip: String, source_ip: String, translate_ip: String, enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct LegacyRef { rule_id: i64, interface: String }
#[derive(Debug, Deserialize, Serialize, Clone)]
struct FilterRef { rule_id: i64, interface: String, handle: u32 }
#[derive(Debug, Deserialize, Serialize, Clone)]
struct XdpRef { interface: String, program_id: u32, mode: String }
#[derive(Debug, Default, Deserialize, Serialize)]
struct EngineState {
    #[serde(default)] applied: Vec<LegacyRef>,
    #[serde(default)] filters: Vec<FilterRef>,
    #[serde(default)] xdp: Vec<XdpRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
struct XdpEntry { ifindex: u32, source: [u8;4], destination: [u8;4], protocol: u8, any: bool, port: u16, rewrite: [u8;4] }
#[derive(Debug, Clone)]
struct Device { name: String, index: u32, addresses: Vec<Ipv4Addr> }

const FILTER_PREF: &str = "49152";
type Backend<'a> = dyn FnMut(&str, &[String]) -> Result<String, String> + 'a;
fn args(values: &[&str]) -> Vec<String> { values.iter().map(|value| (*value).into()).collect() }
fn execute(program: &str, arguments: &[String]) -> Result<String, String> {
    let output = Command::new(program).args(arguments).output().map_err(|error| format!("{program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program}: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
fn main() { if let Err(error) = run() { eprintln!("{error}"); std::process::exit(1); } }
fn run() -> Result<(), String> {
    require_internal_call()?;
    if execute("id", &args(&["-u"]))?.trim() != "0" { return Err("imonitor-bpf must run as root".into()); }
    if env::args().nth(1).as_deref() != Some("apply") { return Err("unsupported action".into()); }
    let mut input = String::new(); io::stdin().read_to_string(&mut input).map_err(|error| error.to_string())?;
    let payload: ApplyPayload = serde_json::from_str(&input).map_err(|error| format!("invalid payload: {error}"))?;
    if !matches!(payload.version, 1 | 2) { return Err("unsupported payload version".into()); }
    // Reject explicit AH requests before even retiring the previous rules.
    // The normal rule validator below also rejects AH before any tc install.
    validate_ah_rewrite_rules(&payload.rules)?;
    let state_path = env::var_os("IMONITOR_ENGINE_STATE_FILE").map(PathBuf::from)
        .unwrap_or_else(|| runtime_root().join("source_ip_engine_state.json"));
    let pin_root = pin_root()?;
    let mut state = load_state(&state_path)?;
    // Cleanup must succeed before rebuilding, so failures retain the ownership
    // record and can be retried without forgetting installed rules.
    cleanup_owned(&mut state, &payload.rules, &pin_root, &mut execute)?;
    save_state(&state_path, &state)?;
    let devices = if payload.rules.iter().any(|rule| rule.enabled) { read_devices(&mut execute)? } else { Vec::new() };
    let desired_interfaces=devices.iter().filter(|device|payload.rules.iter().any(|rule|rule.enabled && rule.mode=="paired" && (rule.interface.is_empty() || rule.interface==device.name)))
        .map(|device|device.name.clone()).collect::<BTreeSet<_>>();
    if payload.rules.iter().any(|rule|rule.enabled) {preflight_xdp(&desired_interfaces,object_path().as_deref(),&mut execute)?;}
    let mut results = BTreeMap::new();
    let mut entries = BTreeMap::<Vec<u8>, (i64, XdpEntry)>::new();
    let mut xdp_interfaces = BTreeSet::new();
    for rule in &payload.rules {
        if !rule.enabled { results.insert(rule.id, (false, "disabled".to_string())); continue; }
        let result = prepare_rule(rule, &devices, &mut state, &mut entries, &mut xdp_interfaces, &state_path, &mut execute);
        let outcome=match result {
            Ok(())=>(true,"active paired IPv4".into()),
            Err(error)=>{
                entries.retain(|_,(id,_)|*id!=rule.id);
                xdp_interfaces.retain(|interface|devices.iter().find(|device|device.name==*interface).is_some_and(|device|entries.values().any(|(_,entry)|entry.ifindex==device.index)));
                let rollback=rollback_filters(&mut state,Some(rule.id),&mut execute);
                (false,format!("{}: {error}{}",rule.label,rollback.err().map(|error|format!("; cleanup failed: {error}")).unwrap_or_default()))
            }
        };
        results.insert(rule.id,outcome);
        // Record every successful tc add immediately, even if a later add fails.
        save_state(&state_path, &state)?;
    }
    if !entries.is_empty() {
        let values = entries.values().map(|(_, entry)| entry.clone()).collect::<Vec<_>>();
        if let Err(error) = apply_xdp(&values, &xdp_interfaces, &pin_root, &mut state, &state_path, &mut execute) {
            let rollback=rollback_attempt(&mut state,&mut execute);
            let detail=format!("XDP ingress: {error}{}",rollback.err().map(|error|format!("; cleanup failed: {error}")).unwrap_or_default());
            for (_,value) in results.iter_mut().filter(|(_,value)|value.0){*value=(false,detail.clone());}
            if state.xdp.is_empty() && pin_root.exists(){let _=fs::remove_dir_all(&pin_root);}
        }
    }
    save_state(&state_path, &state)?;
    let response = payload.rules.iter().map(|rule| {
        let (ok,message) = results.get(&rule.id).cloned().unwrap_or((false,"disabled".into()));
        json!({"id":rule.id,"ok":ok,"message":message})
    }).collect::<Vec<_>>();
    println!("{}", serde_json::to_string(&response).map_err(|error| error.to_string())?);
    Ok(())
}
fn runtime_root() -> PathBuf {
    env::current_exe().ok().and_then(|path| path.parent().and_then(Path::parent).map(|root| root.join("runtime")))
        .unwrap_or_else(|| PathBuf::from("/opt/imonitor/runtime"))
}
fn validate_ah_rewrite_rules(rules:&[RuleInput])->Result<(),String>{
    for rule in rules.iter().filter(|rule|rule.enabled) {
        let protocol=network_rules::parse_ip_protocol(&rule.protocol,rule.family.eq_ignore_ascii_case("ipv6"))?;
        if !protocol.any && protocol.number==51 {
            network_rules::validate_source_ip(&rule.mode,&rule.family,&rule.protocol,rule.match_port,&rule.interface,&rule.destination_ip,&rule.source_ip,&rule.translate_ip)?;
        }
    }
    Ok(())
}
fn require_internal_call() -> Result<(), String> {
    if env::var("IMONITOR_INTERNAL_CALL").ok().as_deref() != Some("1") { return Err("manual launch is not allowed".into()); }
    let token = env::var("IMONITOR_ENGINE_TOKEN").unwrap_or_default();
    let key = env::var_os("IMONITOR_ENGINE_KEY_FILE").map(PathBuf::from).unwrap_or_else(|| runtime_root().join(".engine.key"));
    let expected = fs::read_to_string(key).map_err(|_| "engine key file is missing")?;
    if token.trim().is_empty() || token.trim() != expected.trim() { return Err("engine token mismatch".into()); }
    Ok(())
}
fn pin_root() -> Result<PathBuf,String> {
    let root = env::var_os("IMONITOR_ENGINE_PIN_ROOT").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(format!("/sys/fs/bpf/imonitor-{}",network_rules::runtime_namespace(&runtime_root().to_string_lossy()))));
    if root.parent() != Some(Path::new("/sys/fs/bpf")) || !root.file_name().is_some_and(|name| {
        let name = name.to_string_lossy(); name.starts_with("imonitor-") && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) { return Err("invalid private BPF pin directory".into()); }
    Ok(root)
}
fn load_state(path: &Path) -> Result<EngineState,String> {
    match fs::read(path) { Ok(body) => serde_json::from_slice(&body).map_err(|error| format!("invalid engine ownership state: {error}")),
        Err(error) if error.kind()==io::ErrorKind::NotFound => Ok(EngineState::default()), Err(error) => Err(format!("engine state: {error}")) }
}
fn save_state(path: &Path, state: &EngineState) -> Result<(), String> {
    if let Some(parent)=path.parent() { fs::create_dir_all(parent).map_err(|error| error.to_string())?; }
    let body=serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?;
    let temp=path.with_extension("json.next"); fs::write(&temp,body).map_err(|error| error.to_string())?;
    fs::rename(temp,path).map_err(|error| format!("engine state commit: {error}"))
}
fn read_devices(backend: &mut Backend<'_>) -> Result<Vec<Device>,String> {
    let body=backend("ip",&args(&["-j","-4","address","show"]))?;
    let value:Value=serde_json::from_str(&body).map_err(|error| format!("IP inventory: {error}"))?;
    value.as_array().ok_or("IP inventory is not an array")?.iter().map(|value| {
        let name=value["ifname"].as_str().ok_or("missing device name")?.to_string();
        network_rules::validate_interface(&name)?;
        let index=value["ifindex"].as_u64().ok_or("missing device index")? as u32;
        let addresses=value["addr_info"].as_array().into_iter().flatten().filter_map(|value| value["local"].as_str()?.parse::<Ipv4Addr>().ok()).collect();
        Ok(Device{name,index,addresses})
    }).collect()
}
fn protocol_specs(rule: &RuleInput) -> Result<Vec<(network_rules::IpProtocol,Option<&'static str>)>,String> {
    let protocol=network_rules::parse_ip_protocol(&rule.protocol,false)?;
    let protocols=if protocol.any && rule.match_port!=0 { vec![network_rules::IpProtocol{number:6,any:false},network_rules::IpProtocol{number:17,any:false}] } else { vec![protocol] };
    Ok(protocols.into_iter().flat_map(|protocol| if rule.match_port!=0 { vec![(protocol,Some("dst_port")),(protocol,Some("src_port"))] } else { vec![(protocol,None)] }).collect())
}
fn selectors_overlap(left:&XdpEntry,right:&XdpEntry)->bool{
    left.ifindex==right.ifindex && left.source==right.source && left.destination==right.destination
        && (left.any || right.any || left.protocol==right.protocol)
        // Either source or destination port can match, so different nonzero
        // TCP/UDP ports also overlap on a packet connecting those two ports.
        && (left.port==0 || right.port==0 || left.port==right.port || matches!(left.protocol,6|17) || matches!(right.protocol,6|17))
}
fn preflight_xdp(interfaces:&BTreeSet<String>,object:Option<&Path>,backend:&mut Backend<'_>)->Result<(),String>{
    object.ok_or("xdp_ingress.o is missing; no egress rewrite was installed")?;
    for interface in interfaces{if !net_programs(interface,backend)?.is_empty(){return Err(format!("{interface} has an unrelated XDP program; no egress rewrite was installed"));}}
    Ok(())
}
fn rollback_filters(state:&mut EngineState,only_rule:Option<i64>,backend:&mut Backend<'_>)->Result<(),String>{
    let mut retained=Vec::new();let mut errors=Vec::new();
    for reference in state.filters.drain(..){
        if only_rule.is_some_and(|id|reference.rule_id!=id){retained.push(reference);continue;}
        if let Err(error)=delete_filter(&reference,backend){retained.push(reference);errors.push(error);}
    }
    state.filters=retained;
    if errors.is_empty(){Ok(())}else{Err(errors.join(" | "))}
}
fn rollback_attempt(state:&mut EngineState,backend:&mut Backend<'_>)->Result<(),String>{
    let mut errors=Vec::new();if let Err(error)=rollback_filters(state,None,backend){errors.push(error);}
    let mut retained=Vec::new();
    for reference in state.xdp.drain(..){if let Err(error)=detach_owned(&reference,backend){retained.push(reference);errors.push(error);}}
    state.xdp=retained;
    if errors.is_empty(){Ok(())}else{Err(errors.join(" | "))}
}

fn prepare_rule(rule:&RuleInput, devices:&[Device], state:&mut EngineState, entries:&mut BTreeMap<Vec<u8>,(i64,XdpEntry)>, interfaces:&mut BTreeSet<String>, state_path:&Path, backend:&mut Backend<'_>) -> Result<(),String> {
    network_rules::validate_source_ip(&rule.mode,&rule.family,&rule.protocol,rule.match_port,&rule.interface,&rule.destination_ip,&rule.source_ip,&rule.translate_ip)?;
    if rule.mode!="paired" { return Err("SNAT must be applied by the main application".into()); }
    if !(1..=0x000f_ffff).contains(&rule.id) { return Err("paired rule ID exceeds the supported filter handle range".into()); }
    let selected=devices.iter().filter(|device| if rule.interface.is_empty() { device.name!="lo" && !device.name.starts_with("ifb") } else { device.name==rule.interface }).collect::<Vec<_>>();
    if selected.is_empty() { return Err("interface was not found".into()); }
    let addresses=devices.iter().flat_map(|device|device.addresses.iter().copied()).collect::<BTreeSet<_>>();
    if addresses.is_empty() { return Err("no local IPv4 address is assigned".into()); }
    let source=rule.source_ip.parse::<Ipv4Addr>().map_err(|error|error.to_string())?.octets();
    let rewrite=if rule.translate_ip.is_empty(){&rule.destination_ip}else{&rule.translate_ip}.parse::<Ipv4Addr>().map_err(|error|error.to_string())?.octets();
    let specs=protocol_specs(rule)?;
    if addresses.len()*specs.len()>255 { return Err("too many source addresses for one paired rule".into()); }
    // Preflight every return key before installing any egress filter.
    for device in &selected { for address in &addresses { for (protocol,_) in &specs {
        let entry=XdpEntry{ifindex:device.index,source,destination:address.octets(),protocol:protocol.number,any:protocol.any,port:rule.match_port,rewrite};
        for (id,previous) in entries.values(){
            if selectors_overlap(previous,&entry) && previous.rewrite!=rewrite {return Err(format!("return traffic overlaps rule {id}; use a different fake IPv4 address for each peer"));}
        }
    } } }
    for device in selected {
        ensure_clsact(&device.name,backend)?;
        let mut slot=0u32;
        for address in &addresses { for (protocol,port_flag) in &specs {
            slot+=1; let handle=0x1000_0000 | ((rule.id as u32)<<8) | slot;
            let reference=FilterRef{rule_id:rule.id,interface:device.name.clone(),handle};
            backend("tc",&egress_args(rule,&reference,*address,*protocol,*port_flag))?;
            state.filters.push(reference);
            save_state(state_path,state)?;
            let entry=XdpEntry{ifindex:device.index,source,destination:address.octets(),protocol:protocol.number,any:protocol.any,port:rule.match_port,rewrite};
            entries.insert(encode_key(&entry),(rule.id,entry));
        } }
        interfaces.insert(device.name.clone());
    }
    Ok(())
}
fn ensure_clsact(interface:&str,backend:&mut Backend<'_>)->Result<(),String>{
    let body=backend("tc",&args(&["-j","qdisc","show","dev",interface]))?;
    let value:Value=serde_json::from_str(&body).map_err(|error|format!("qdisc inventory: {error}"))?;
    if value.as_array().is_some_and(|items|items.iter().any(|item|item["kind"]=="clsact")) {return Ok(());}
    backend("tc",&args(&["qdisc","add","dev",interface,"clsact"]))?; Ok(())
}
fn egress_args(rule:&RuleInput,reference:&FilterRef,address:Ipv4Addr,protocol:network_rules::IpProtocol,port_flag:Option<&str>)->Vec<String>{
    let mut values=args(&["filter","add","dev",&reference.interface,"egress","protocol","ip","pref",FILTER_PREF,"handle",&format!("0x{:x}",reference.handle),"flower","dst_ip",&rule.destination_ip,"src_ip",&address.to_string()]);
    if !protocol.any {values.extend(args(&["ip_proto",&protocol.tc_flower_token()]));}
    if let Some(flag)=port_flag {values.extend(args(&[flag,&rule.match_port.to_string()]));}
    // Kernel tc NAT updates IPv4 and TCP/UDP pseudo-header checksums,
    // including checksum offload. Matching /32 preserves the entire new IP.
    values.extend(args(&["action","nat","egress",&format!("{address}/32"),&rule.source_ip])); values
}
fn delete_filter(reference:&FilterRef,backend:&mut Backend<'_>)->Result<(),String>{
    match backend("tc",&args(&["filter","del","dev",&reference.interface,"egress","protocol","ip","pref",FILTER_PREF,"handle",&format!("0x{:x}",reference.handle),"flower"])) {
        Ok(_)=>Ok(()), Err(error) if missing(&error)=>Ok(()),Err(error)=>Err(error)
    }
}
fn missing(error:&str)->bool { let error=error.to_ascii_lowercase(); error.contains("no such file")||error.contains("no such device")||error.contains("cannot find device")||error.contains("does not exist")||error.contains("not found") }
fn net_programs(interface:&str,backend:&mut Backend<'_>)->Result<Vec<XdpRef>,String>{
    let body=backend("bpftool",&args(&["-j","net","show","dev",interface]))?;
    let value:Value=serde_json::from_str(&body).map_err(|error|format!("XDP inventory: {error}"))?;
    let mut refs=Vec::new();
    fn visit(value:&Value,interface:&str,refs:&mut Vec<XdpRef>){
        match value {
            Value::Array(values)=>for value in values{visit(value,interface,refs)},
            Value::Object(values)=>{
                if let Some(mode)=values.get("mode").and_then(Value::as_str) {
                    if let Some(id)=values.get("id").or_else(||values.get("prog_id")).and_then(Value::as_u64) {
                        let mode=match mode {"driver"|"drv"|"xdpdrv"=>"xdpdrv","generic"|"skb"|"xdpgeneric"=>"xdpgeneric","offload"|"hw"|"xdpoffload"=>"xdpoffload",_=>""};
                        if !mode.is_empty(){refs.push(XdpRef{interface:interface.into(),program_id:id as u32,mode:mode.into()});}
                    }
                }
                for value in values.values(){visit(value,interface,refs)}
            },_=>{}
        }
    }
    visit(&value,interface,&mut refs); Ok(refs)
}
fn detach_owned(reference:&XdpRef,backend:&mut Backend<'_>)->Result<(),String>{
    let current=match net_programs(&reference.interface,backend){
        Ok(current)=>current,Err(error) if missing(&error)=>return Ok(()),Err(error)=>return Err(error),
    };
    if current.iter().any(|current|current.program_id==reference.program_id && current.mode==reference.mode){
        backend("bpftool",&args(&["net","detach",&reference.mode,"dev",&reference.interface]))?;
    }
    Ok(())
}
fn cleanup_owned(state:&mut EngineState,rules:&[RuleInput],pin:&Path,backend:&mut Backend<'_>)->Result<(),String>{
    for reference in &state.filters {delete_filter(reference,backend)?;}
    for reference in &state.xdp {detach_owned(reference,backend)?;}
    // A v1 state proves the rule ID, but contains no filter handles or XDP ID.
    // Migrate only matching pedit filters and the program proven by its old pin.
    if !state.applied.is_empty(){
        let old_pin=Path::new("/sys/fs/bpf/imonitor/xdp_ingress_prog");
        let old_id=program_id(old_pin,backend).ok();
        for reference in &state.applied {
            for direction in ["egress","ingress"] {
                let base=if direction=="egress"{20000}else{30000};
                for offset in 0..if direction=="egress"{2}else{4} {
                    let pref=base+reference.rule_id*10+offset;
                    let body=backend("tc",&args(&["-j","filter","show","dev",&reference.interface,direction,"pref",&pref.to_string()]))?;
                    let value:Value=serde_json::from_str(&body).map_err(|error|format!("legacy filter inventory: {error}"))?;
                    for filter in value.as_array().into_iter().flatten() {
                        if filter["kind"]!="flower" {continue;}
                        let options=&filter["options"];
                        let has_pedit=options["actions"].as_array().is_some_and(|actions|actions.iter().any(|action|action["kind"]=="pedit"));
                        if !has_pedit {continue;}
                        let rule=rules.iter().find(|rule|rule.id==reference.rule_id).ok_or("legacy paired rule cannot be removed without its saved configuration")?;
                        let key=if direction=="egress"{"dst_ip"}else{"src_ip"};
                        let expected=if direction=="egress"{&rule.destination_ip}else{&rule.source_ip};
                        if !options["keys"][key].as_str().is_some_and(|value|value.split('/').next()==Some(expected.as_str())){return Err("legacy filter ownership could not be confirmed".into());}
                        let handle=options["handle"].as_str().or_else(||filter["handle"].as_str()).map(str::to_string)
                            .or_else(||options["handle"].as_u64().map(|id|format!("0x{id:x}"))).ok_or("legacy flower handle is missing")?;
                        backend("tc",&args(&["filter","del","dev",&reference.interface,direction,"protocol","ip","pref",&pref.to_string(),"handle",&handle,"flower"]))?;
                    }
                }
            }
            if let Some(id)=old_id {for current in net_programs(&reference.interface,backend)?{if current.program_id==id{detach_owned(&current,backend)?;}}}
        }
    }
    state.filters.clear();state.xdp.clear();state.applied.clear();
    if pin.exists(){fs::remove_dir_all(pin).map_err(|error|format!("private XDP pins: {error}"))?;}
    Ok(())
}
fn program_id(pin:&Path,backend:&mut Backend<'_>)->Result<u32,String>{
    let body=backend("bpftool",&args(&["-j","prog","show","pinned",&pin.to_string_lossy()]))?;
    let value:Value=serde_json::from_str(&body).map_err(|error|error.to_string())?;
    value.get("id").or_else(||value.as_array().and_then(|values|values.first()).and_then(|value|value.get("id"))).and_then(Value::as_u64).map(|id|id as u32).ok_or("loaded XDP program ID is missing".into())
}
fn apply_xdp(entries:&[XdpEntry],interfaces:&BTreeSet<String>,pin:&Path,state:&mut EngineState,state_path:&Path,backend:&mut Backend<'_>)->Result<(),String>{
    for interface in interfaces{if !net_programs(interface,backend)?.is_empty(){return Err(format!("{interface} already has an unrelated XDP program; it was left attached"));}}
    if backend("mountpoint",&args(&["-q","/sys/fs/bpf"])).is_err(){backend("mount",&args(&["-t","bpf","bpf","/sys/fs/bpf"]))?;}
    let maps=pin.join("maps");fs::create_dir_all(&maps).map_err(|error|error.to_string())?;
    let object=object_path().ok_or("xdp_ingress.o is missing")?;let prog=pin.join("xdp_ingress_prog");
    backend("bpftool",&args(&["prog","load",&object.to_string_lossy(),&prog.to_string_lossy(),"type","xdp","pinmaps",&maps.to_string_lossy()]))?;
    let id=program_id(&prog,backend)?;
    for entry in entries {
        let mut values=args(&["map","update","pinned",&maps.join("ingress_rules").to_string_lossy(),"key","hex"]);
        values.extend(encode_key(entry).iter().map(|byte|format!("{byte:02x}")));
        values.extend(args(&["value","hex"]));values.extend(entry.rewrite.iter().map(|byte|format!("{byte:02x}")));values.push("any".into());backend("bpftool",&values)?;
    }
    for interface in interfaces{
        // No overwrite: a concurrent foreign attachment also remains safe.
        let mut last=String::new();let mut attached=false;
        for mode in ["xdpdrv","xdpgeneric"]{
            match backend("bpftool",&args(&["net","attach",mode,"pinned",&prog.to_string_lossy(),"dev",interface])) {
                Ok(_)=>{state.xdp.push(XdpRef{interface:interface.clone(),program_id:id,mode:mode.into()});save_state(state_path,state)?;attached=true;break;},
                Err(error)=>last=error,
            }
        }
        if !attached{return Err(format!("{interface}: {last}"));}
    }
    Ok(())
}
fn object_path()->Option<PathBuf>{
    let mut paths=Vec::new();if let Ok(exe)=env::current_exe(){if let Some(root)=exe.parent().and_then(Path::parent){paths.push(root.join("bpf/xdp_ingress.o"));paths.push(root.join("bin/xdp_ingress.o"));}}
    paths.push(PathBuf::from("/opt/imonitor/bpf/xdp_ingress.o"));paths.into_iter().find(|path|path.is_file())
}
fn encode_key(entry:&XdpEntry)->Vec<u8>{
    let mut bytes=Vec::with_capacity(16);bytes.extend_from_slice(&entry.ifindex.to_ne_bytes());bytes.extend_from_slice(&entry.source);bytes.extend_from_slice(&entry.destination);bytes.push(entry.protocol);bytes.push(u8::from(entry.any));bytes.extend_from_slice(&entry.port.to_ne_bytes());bytes
}
#[cfg(test)]
mod tests {
    use super::*;
    fn rule()->RuleInput {RuleInput{id:3,label:"pair".into(),mode:"paired".into(),family:"ipv4".into(),protocol:"tcp".into(),match_port:443,interface:"eth0".into(),destination_ip:"198.51.100.2".into(),source_ip:"203.0.113.9".into(),translate_ip:String::new(),enabled:true}}
    #[test]
    fn egress_nat_uses_exact_old_source_and_real_protocol_with_checksum_action(){
        let rule=rule();let reference=FilterRef{rule_id:3,interface:"eth0".into(),handle:0x10000301};
        let values=egress_args(&rule,&reference,"192.0.2.1".parse().unwrap(),network_rules::parse_ip_protocol("tcp",false).unwrap(),Some("dst_port"));
        let joined=values.join(" ");assert!(joined.contains("dst_ip 198.51.100.2 src_ip 192.0.2.1 ip_proto tcp dst_port 443 action nat egress 192.0.2.1/32 203.0.113.9"));assert!(!joined.contains("pedit"));
        let mut raw=rule.clone();raw.protocol="50".into();raw.match_port=0;let specs=protocol_specs(&raw).unwrap();assert_eq!(specs.len(),1);assert!(specs[0].1.is_none());
    }
    #[test]
    fn explicit_ah_payload_is_rejected_before_network_mutation(){
        for protocol in ["ah","51"] {
            let mut row=rule();row.protocol=protocol.into();row.match_port=0;
            assert!(validate_ah_rewrite_rules(&[row.clone()]).unwrap_err().contains("AH authenticates"));
            let error=prepare_rule(&row,&[],&mut EngineState::default(),&mut BTreeMap::new(),&mut BTreeSet::new(),Path::new("unused-state"),&mut|_,_|panic!("AH must be rejected before network commands")).unwrap_err();
            assert!(error.contains("AH authenticates"));
        }
        let mut legacy=rule();legacy.protocol="any".into();legacy.match_port=0;
        validate_ah_rewrite_rules(&[legacy]).unwrap();
    }
    #[test]
    fn unrelated_xdp_is_never_detached(){
        let reference=XdpRef{interface:"eth0".into(),program_id:100,mode:"xdpdrv".into()};let mut calls=Vec::new();
        detach_owned(&reference,&mut |program,arguments|{calls.push((program.to_string(),arguments.to_vec()));Ok(r#"[{"xdp":[{"devname":"eth0","mode":"driver","id":200}]}]"#.into())}).unwrap();
        assert_eq!(calls.len(),1);assert!(!calls[0].1.contains(&"detach".into()));
    }
    #[test]
    fn owned_detach_and_filter_delete_keep_shared_qdisc_and_other_filters(){
        let mut calls=Vec::new();let reference=XdpRef{interface:"eth0".into(),program_id:100,mode:"xdpdrv".into()};
        detach_owned(&reference,&mut |program,arguments|{calls.push((program.to_string(),arguments.to_vec()));Ok(r#"[{"xdp":[{"mode":"driver","id":100}]}]"#.into())}).unwrap();assert_eq!(calls.len(),2);
        let filter=FilterRef{rule_id:3,interface:"eth0".into(),handle:0x10000301};delete_filter(&filter,&mut|program,arguments|{calls.push((program.to_string(),arguments.to_vec()));Ok(String::new())}).unwrap();
        assert!(calls[2].1.contains(&"handle".into()));assert!(calls[2].1.contains(&"0x10000301".into()));assert!(!calls.iter().any(|(_,values)|values.contains(&"qdisc".into())));
    }
    #[test]
    fn existing_clsact_is_preserved_and_zero_protocol_is_exact(){
        let mut calls=0;ensure_clsact("eth0",&mut|_,_|{calls+=1;Ok(r#"[{"kind":"clsact"}]"#.into())}).unwrap();assert_eq!(calls,1);
        let mut entry=XdpEntry{ifindex:2,source:[1,2,3,4],destination:[5,6,7,8],protocol:0,any:false,port:0,rewrite:[9,10,11,12]};let exact=encode_key(&entry);entry.any=true;assert_ne!(exact,encode_key(&entry));assert_eq!(exact.len(),16);
    }
    #[test]
    fn missing_or_foreign_xdp_preflight_never_adds_tc_egress(){
        let interfaces=BTreeSet::from(["eth0".into()]);let mut calls=Vec::new();
        assert!(preflight_xdp(&interfaces,None,&mut|program,values|{calls.push((program.to_string(),values.to_vec()));Ok(String::new())}).is_err());assert!(calls.is_empty());
        assert!(preflight_xdp(&interfaces,Some(Path::new("object.o")),&mut|program,values|{calls.push((program.to_string(),values.to_vec()));Ok(r#"[{"xdp":[{"mode":"driver","id":200}]}]"#.into())}).is_err());assert_eq!(calls.len(),1);assert_eq!(calls[0].0,"bpftool");
    }
    #[test]
    fn failed_attempt_rolls_back_owned_egress_and_xdp_and_retains_cleanup_errors(){
        let mut state=EngineState{filters:vec![FilterRef{rule_id:1,interface:"eth0".into(),handle:0x10000101}],xdp:vec![XdpRef{interface:"eth0".into(),program_id:100,mode:"xdpdrv".into()}],..Default::default()};let mut calls=Vec::new();
        rollback_attempt(&mut state,&mut|program,values|{calls.push((program.to_string(),values.to_vec()));Ok(if program=="bpftool" && values.first().is_some_and(|value|value=="-j"){r#"[{"xdp":[{"mode":"driver","id":100}]}]"#.into()}else{String::new()})}).unwrap();assert!(state.filters.is_empty()&&state.xdp.is_empty());assert_eq!(calls[0].0,"tc");assert!(calls[0].1.contains(&"del".into()));assert!(calls.iter().any(|(_,values)|values.contains(&"detach".into())));
        state.filters.push(FilterRef{rule_id:1,interface:"eth0".into(),handle:0x10000101});assert!(rollback_attempt(&mut state,&mut|_,_|Err("permission denied".into())).is_err());assert_eq!(state.filters.len(),1);
    }
    #[test]
    fn deleted_interface_is_already_detached_but_permission_failures_are_kept(){
        let reference=XdpRef{interface:"deleted0".into(),program_id:1,mode:"xdpdrv".into()};assert!(detach_owned(&reference,&mut|_,_|Err("ifindex: No such device".into())).is_ok());assert!(detach_owned(&reference,&mut|_,_|Err("permission denied".into())).is_err());
    }
    #[test]
    fn wildcard_or_bidirectional_ports_cannot_rewrite_a_peer_as_another_peer(){
        let a=XdpEntry{ifindex:2,source:[203,0,113,9],destination:[192,0,2,1],protocol:0,any:true,port:0,rewrite:[198,51,100,2]};let mut b=a.clone();b.protocol=6;b.any=false;b.port=80;b.rewrite=[198,51,100,3];assert!(selectors_overlap(&a,&b));let mut specific=a.clone();specific.protocol=6;specific.any=false;specific.port=443;assert!(selectors_overlap(&specific,&b));b.protocol=17;assert!(!selectors_overlap(&specific,&b));b.destination=[192,0,2,2];assert!(!selectors_overlap(&a,&b));
    }

    #[test]
    fn conflicting_wildcard_rule_is_rejected_before_any_filter_add(){
        let previous=XdpEntry{ifindex:2,source:[203,0,113,9],destination:[192,0,2,1],protocol:0,any:true,port:0,rewrite:[198,51,100,2]};
        let mut entries=BTreeMap::from([(encode_key(&previous),(1,previous))]);let device=Device{name:"eth0".into(),index:2,addresses:vec!["192.0.2.1".parse().unwrap()]};let mut incoming=rule();incoming.protocol="tcp".into();incoming.match_port=80;incoming.destination_ip="198.51.100.3".into();
        let result=prepare_rule(&incoming,&[device],&mut EngineState::default(),&mut entries,&mut BTreeSet::new(),Path::new("unused.json"),&mut|_,_|panic!("a conflicting rule must not run tc"));assert!(result.unwrap_err().contains("overlaps rule 1"));
    }

    #[cfg(target_os="linux")]
    #[test]
    #[ignore="requires disposable network namespace and real tc"]
    fn linux_tc_flower_protocol_numbers_round_trip(){
        assert_eq!(std::env::var("IMONITOR_ACCEPT_DISPOSABLE").as_deref(),Ok("1"));
        let interface=std::env::var("IMONITOR_ACCEPT_INTERFACE").unwrap_or("vethc".into());
        ensure_clsact(&interface,&mut execute).unwrap();
        let reference=FilterRef{rule_id:120,interface:interface.clone(),handle:0x10007801};
        for number in [0,4,6,17,41,47,50,51,97,115,255] {
            let mut row=rule();row.protocol=number.to_string();row.match_port=if matches!(number,6|17){443}else{0};
            let protocol=network_rules::parse_ip_protocol(&row.protocol,false).unwrap();
            execute("tc",&egress_args(&row,&reference,"192.0.2.1".parse().unwrap(),protocol,if row.match_port==0{None}else{Some("dst_port")})).unwrap();
            let raw=execute("tc",&args(&["-j","filter","show","dev",&interface,"egress","pref",FILTER_PREF])).unwrap();let value:Value=serde_json::from_str(&raw).unwrap();
            let observed=value.as_array().unwrap().iter().find_map(|value|value["options"]["keys"]["ip_proto"].as_str()).expect("real flower protocol missing");
            let actual=match observed {"tcp"=>6,"udp"=>17,"icmp"=>1,"icmpv6"=>58,"sctp"=>132,"esp"=>50,"ah"=>51,"l2tp"=>115,raw=>u8::from_str_radix(raw.trim_start_matches("0x"),16).unwrap()};
            assert_eq!(actual,number,"tc round trip changed protocol {number} into {observed}");
            delete_filter(&reference,&mut execute).unwrap();
        }
    }

}
