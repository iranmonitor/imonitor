use crate::config::{
    AgentConfig, CheckDefinition, DnsCheck, DnsRecordType, EspCipher, EspKeyDerivation, FtpCheck, IcmpCheck, IpVersion,
    LocalEntryType, ProxyType, RdpCheck, SocketCheck, SshCheck, TunnelCheck, TunnelProtocol,
    UdpCheck,
    V2raySimulationCheck, WebCheck,
};
use crate::http;
use crate::types::{AgentSnapshot, CheckResult, CheckStatus, PersistedState, TunnelCounterState};
use crate::util::decode_base64_lenient;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
#[cfg(target_os = "linux")]
use std::os::raw::{c_char, c_int, c_short, c_ulong};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
    mpsc, Arc, Mutex, MutexGuard, OnceLock,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn run_cycle(config: &AgentConfig, state: &mut PersistedState) -> AgentSnapshot {
    sync_tunnel_runtimes(&config.checks);
    let shared_state = Arc::new(Mutex::new(std::mem::take(state)));
    let mut indexed_results = Vec::with_capacity(config.checks.len());
    let next_check = AtomicUsize::new(0);

    thread::scope(|scope| {
        // Bound monitor probes now that installations have no monitor limit.
        // Existing tunnel runtime children and forwarding lanes are unaffected.
        let workers = config.checks.len().min(64);
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let state_handle = Arc::clone(&shared_state);
            let next_check = &next_check;
            handles.push(scope.spawn(move || {
                let mut results = Vec::new();
                loop {
                    let index = next_check.fetch_add(1, AtomicOrdering::Relaxed);
                    let Some(check) = config.checks.get(index) else { break; };
                    results.push((index, run_check(check, &state_handle)));
                }
                results
            }));
        }

        for handle in handles {
            if let Ok(results) = handle.join() {
                indexed_results.extend(results);
            }
        }
    });

    if let Ok(mut guard) = shared_state.lock() {
        let active_ids = config
            .checks
            .iter()
            .map(|check| check.id().to_string())
            .collect::<BTreeSet<_>>();
        guard
            .last_check_run_unix
            .retain(|check_id, _| active_ids.contains(check_id));
        guard
            .last_results
            .retain(|check_id, _| active_ids.contains(check_id));
    }

    indexed_results.sort_by_key(|(index, _)| *index);
    let results = indexed_results
        .into_iter()
        .map(|(_, result)| result)
        .collect::<Vec<_>>();

    let restored_state = match Arc::try_unwrap(shared_state) {
        Ok(mutex) => mutex.into_inner().unwrap_or_default(),
        Err(shared) => shared.lock().map(|guard| guard.clone()).unwrap_or_default(),
    };
    *state = restored_state;

    AgentSnapshot {
        agent_id: config.agent_id.clone(),
        hostname: current_hostname(),
        generated_at_unix: unix_now(),
        results,
    }
}

pub fn run_tun_helper(arguments: Vec<String>) -> Result<(), String> {
    let args = TunHelperArgs::parse(arguments)?;
    let tun = open_named_tun(&args.interface)?;
    bring_interface_up(&args.interface)?;

    match args.mode {
        TunHelperMode::Listen(address) => {
            run_tun_listener(&args.interface, tun, address, args.lanes, args.profile, args.packet_limit, args.allowed_peer)
        }
        TunHelperMode::Connect(addresses) => {
            run_tun_connector(&args.interface, tun, addresses, args.profile, args.packet_limit, args.source_ip)
        }
    }
}

#[derive(Clone, Copy)]
enum TunHelperStreamProfile {
    Interactive,
    Bulk,
}

impl TunHelperStreamProfile {
    fn from_cli(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "interactive" => Ok(Self::Interactive),
            "bulk" => Ok(Self::Bulk),
            other => Err(format!(
                "invalid value for --stream-profile: {other} (expected interactive or bulk)"
            )),
        }
    }

    fn enables_nodelay(self) -> bool {
        matches!(self, Self::Interactive)
    }
}

enum TunHelperMode {
    Listen(SocketAddr),
    Connect(Vec<SocketAddr>),
}

struct TunHelperArgs {
    interface: String,
    lanes: usize,
    mode: TunHelperMode,
    profile: TunHelperStreamProfile,
    packet_limit: usize,
    source_ip: Option<IpAddr>,
    allowed_peer: Option<IpAddr>,
}

impl TunHelperArgs {
    fn parse(arguments: Vec<String>) -> Result<Self, String> {
        let mut interface = None;
        let mut lanes = 1_usize;
        let mut listen_addr = None;
        let mut connect_addrs = Vec::new();
        let mut profile = TunHelperStreamProfile::Interactive;
        let mut packet_limit = u16::MAX as usize;
        let mut source_ip = None;
        let mut allowed_peer = None;
        let mut index = 0_usize;

        while index < arguments.len() {
            match arguments[index].as_str() {
                "--interface" => {
                    index += 1;
                    interface = Some(
                        arguments
                            .get(index)
                            .cloned()
                            .ok_or_else(|| "missing value for --interface".to_string())?,
                    );
                }
                "--listen-addr" => {
                    index += 1;
                    listen_addr = Some(
                        arguments
                            .get(index)
                            .cloned()
                            .ok_or_else(|| "missing value for --listen-addr".to_string())?,
                    );
                }
                "--connect-addr" => {
                    index += 1;
                    connect_addrs.push(
                        arguments
                            .get(index)
                            .cloned()
                            .ok_or_else(|| "missing value for --connect-addr".to_string())?,
                    );
                }
                "--lanes" => {
                    index += 1;
                    lanes = arguments
                        .get(index)
                        .ok_or_else(|| "missing value for --lanes".to_string())?
                        .parse::<usize>()
                        .map_err(|_| "invalid value for --lanes".to_string())?;
                }
                "--stream-profile" => {
                    index += 1;
                    let value = arguments
                        .get(index)
                        .ok_or_else(|| "missing value for --stream-profile".to_string())?;
                    profile = TunHelperStreamProfile::from_cli(value)?;
                }
                "--packet-limit" => {
                    index += 1;
                    packet_limit = arguments.get(index).ok_or_else(|| "missing value for --packet-limit".to_string())?
                        .parse::<usize>().map_err(|_| "invalid value for --packet-limit".to_string())?;
                }
                "--source-ip" => {
                    index += 1;
                    source_ip = Some(arguments.get(index).ok_or_else(|| "missing value for --source-ip".to_string())?
                        .parse::<IpAddr>().map_err(|_| "--source-ip must be an IP literal".to_string())?);
                }
                "--allowed-peer" => {
                    index += 1;
                    allowed_peer = Some(arguments.get(index).ok_or_else(|| "missing value for --allowed-peer".to_string())?
                        .parse::<IpAddr>().map_err(|_| "--allowed-peer must be an IP literal".to_string())?);
                }
                other => return Err(format!("unknown tun-helper argument: {other}")),
            }
            index += 1;
        }

        let interface = interface
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "tun-helper needs --interface".to_string())?;
        if !(1..=8).contains(&lanes) || connect_addrs.len() > 8 {
            return Err("tun-helper accepts 1–8 lanes / connection addresses".to_string());
        }
        if !(576..=u16::MAX as usize).contains(&packet_limit) {
            return Err("tun-helper --packet-limit must be between 576 and 65535 bytes".to_string());
        }
        if source_ip.is_some_and(|ip| ip.is_unspecified() || ip.is_multicast()) { return Err("--source-ip requires a specific unicast address".to_string()); }
        if allowed_peer.is_some_and(|ip| ip.is_unspecified() || ip.is_multicast()) { return Err("--allowed-peer requires a specific unicast address".to_string()); }

        let mode = match (listen_addr, connect_addrs.is_empty()) {
            (Some(listen_addr), true) => {
                if source_ip.is_some() { return Err("--source-ip is for a connector; set the listener IP directly in --listen-addr".to_string()); }
                TunHelperMode::Listen(resolve_tun_helper_socket_addr(&listen_addr, None)?)
            }
            (None, false) => {
                if allowed_peer.is_some() { return Err("--allowed-peer is for a listener, not a connector".to_string()); }
                let addresses = connect_addrs
                    .iter()
                    .map(|value| resolve_tun_helper_socket_addr(value, source_ip))
                    .collect::<Result<Vec<_>, _>>()?;
                TunHelperMode::Connect(addresses)
            }
            (Some(_), false) => {
                return Err(
                    "tun-helper accepts either --listen-addr or one or more --connect-addr values, not both"
                        .to_string(),
                )
            }
            (None, true) => {
                return Err(
                    "tun-helper needs either --listen-addr or at least one --connect-addr".to_string(),
                )
            }
        };

        Ok(Self {
            interface,
            lanes,
            mode,
            profile,
            packet_limit,
            source_ip,
            allowed_peer,
        })
    }
}

fn resolve_tun_helper_socket_addr(value: &str, source: Option<IpAddr>) -> Result<SocketAddr, String> {
    let mut addresses = value
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve tunnel helper socket address {value}: {error}"))?;
    addresses
        .find(|address| source.map_or(true, |source| source.is_ipv4() == address.is_ipv4()))
        .ok_or_else(|| format!("no socket addresses in the source IP family resolved for {value}"))
}

fn run_tun_listener(
    _interface: &str,
    tun: fs::File,
    address: SocketAddr,
    lanes: usize,
    profile: TunHelperStreamProfile,
    packet_limit: usize,
    allowed_peer: Option<IpAddr>,
) -> Result<(), String> {
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("failed to bind tunnel helper listener on {address}: {error}"))?;
    loop {
        let mut streams = Vec::with_capacity(lanes);
        while streams.len() < lanes {
            let stream = accept_tun_peer(&listener, allowed_peer)
                .map_err(|error| format!("failed to accept tunnel helper connection on {address}: {error}"))?;
            if let Err(error) = configure_tunnel_stream(&stream, profile) {
                return Err(format!("failed to configure tunnel helper stream: {error}"));
            }
            streams.push(stream);
        }
        if let Err(error) = bridge_tun_and_streams(&tun, streams, packet_limit) {
            if is_transient_tunnel_stream_error(&error) {
                thread::sleep(Duration::from_millis(150));
                continue;
            }
            return Err(error);
        }
    }
}

fn accept_tun_peer(listener: &TcpListener, allowed_peer: Option<IpAddr>) -> io::Result<TcpStream> {
    loop {
        let (stream, remote) = listener.accept()?;
        if allowed_peer.map_or(true, |allowed| allowed == remote.ip()) { return Ok(stream); }
        // Reject before counting a lane or touching the TUN packet bridge.
        let _ = stream.shutdown(Shutdown::Both);
    }
}

fn run_tun_connector(
    _interface: &str,
    tun: fs::File,
    addresses: Vec<SocketAddr>,
    profile: TunHelperStreamProfile,
    packet_limit: usize,
    source_ip: Option<IpAddr>,
) -> Result<(), String> {
    loop {
        let mut streams = Vec::with_capacity(addresses.len());
        let mut connect_failed = false;
        for address in &addresses {
            match connect_tun_stream(*address, source_ip) {
                Ok(stream) => {
                    if let Err(error) = configure_tunnel_stream(&stream, profile) {
                        return Err(format!("failed to configure tunnel helper stream: {error}"));
                    }
                    streams.push(stream);
                }
                Err(_) => {
                    connect_failed = true;
                    break;
                }
            }
        }
        if connect_failed {
            thread::sleep(Duration::from_millis(250));
            continue;
        }

        if let Err(error) = bridge_tun_and_streams(&tun, streams, packet_limit) {
            if is_transient_tunnel_stream_error(&error) {
                thread::sleep(Duration::from_millis(200));
                continue;
            }
            return Err(error);
        }
    }
}

fn connect_tun_stream(address: SocketAddr, source_ip: Option<IpAddr>) -> io::Result<TcpStream> {
    let socket = socket2::Socket::new(if address.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 }, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if let Some(source) = source_ip {
        if source.is_ipv4() != address.is_ipv4() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN TCP source and peer address families differ")); }
        socket.bind(&SocketAddr::new(source, 0).into())?;
    }
    socket.connect_timeout(&address.into(), Duration::from_secs(5))?;
    Ok(socket.into())
}

fn configure_tunnel_stream(stream: &TcpStream, profile: TunHelperStreamProfile) -> io::Result<()> {
    stream.set_nodelay(profile.enables_nodelay())?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(())
}

fn bridge_tun_and_streams(tun: &fs::File, streams: Vec<TcpStream>, packet_limit: usize) -> Result<(), String> {
    let running = Arc::new(AtomicBool::new(true));
    let tun_writer = tun
        .try_clone()
        .map_err(|error| format!("failed to clone TUN writer: {error}"))?;
    let mut tun_reader = tun
        .try_clone()
        .map_err(|error| format!("failed to clone TUN reader: {error}"))?;
    let tun_writer = Arc::new(Mutex::new(tun_writer));
    let shutdown_streams = streams
        .iter()
        .map(|stream| {
            stream
                .try_clone()
                .map_err(|error| format!("failed to clone tunnel stream shutdown handle: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut writer_streams = streams
        .iter()
        .map(|stream| {
            stream
                .try_clone()
                .map_err(|error| format!("failed to clone tunnel stream writer: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (result_tx, result_rx) = mpsc::channel::<io::Result<()>>();
    let mut handles = Vec::new();

    for stream in streams {
        let mut stream_reader = stream
            .try_clone()
            .map_err(|error| format!("failed to clone tunnel stream reader: {error}"))?;
        let reader_running = Arc::clone(&running);
        let tun_writer = Arc::clone(&tun_writer);
        let tx = result_tx.clone();
        handles.push(thread::spawn(move || {
            let result = bridge_single_inbound_stream(&mut stream_reader, tun_writer, &reader_running, packet_limit);
            let _ = tx.send(result);
        }));
    }

    let writer_running = Arc::clone(&running);
    let tx = result_tx.clone();
    handles.push(thread::spawn(move || {
        let result = bridge_tun_outbound_streams(&mut tun_reader, &mut writer_streams, &writer_running, packet_limit);
        let _ = tx.send(result);
    }));
    drop(result_tx);

    let first_result = result_rx
        .recv()
        .map_err(|_| "tunnel helper workers stopped unexpectedly".to_string())?;
    running.store(false, AtomicOrdering::Relaxed);
    for stream in shutdown_streams {
        let _ = stream.shutdown(Shutdown::Both);
    }
    for handle in handles {
        let _ = handle.join();
    }

    match first_result {
        Ok(()) => Ok(()),
        Err(error) if is_stream_disconnect_error(&error) => Ok(()),
        Err(error) => Err(format!("tunnel helper stream failed: {error}")),
    }
}

fn bridge_single_inbound_stream(
    stream_reader: &mut TcpStream,
    tun_writer: Arc<Mutex<fs::File>>,
    running: &AtomicBool,
    packet_limit: usize,
) -> io::Result<()> {
    let mut size_buffer = [0_u8; 2];
    let mut packet = vec![0_u8; u16::MAX as usize];
    loop {
        if !running.load(AtomicOrdering::Relaxed) {
            return Ok(());
        }
        if !read_exact_interruptible(stream_reader, &mut size_buffer, running)? {
            return Ok(());
        }
        let packet_len = u16::from_be_bytes(size_buffer) as usize;
        if packet_len == 0 {
            continue;
        }
        validate_tun_packet_size(packet_len, packet_limit)?;
        if !read_exact_interruptible(stream_reader, &mut packet[..packet_len], running)? {
            return Ok(());
        }
        let mut tun_writer = tun_writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        write_tun_packet(&mut tun_writer, &packet[..packet_len], running)?;
    }
}

fn bridge_tun_outbound_streams(
    tun_reader: &mut fs::File,
    stream_writers: &mut [TcpStream],
    running: &AtomicBool,
    packet_limit: usize,
) -> io::Result<()> {
    let mut packet = vec![0_u8; 65_536];
    let mut frame = Vec::with_capacity(65_538);
    let mut lane_index = 0_usize;
    loop {
        if !running.load(AtomicOrdering::Relaxed) {
            return Ok(());
        }
        match tun_reader.read(&mut packet) {
            Ok(0) => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(packet_len) => {
                validate_tun_packet_size(packet_len, packet_limit)?;
                let packet_len = u16::try_from(packet_len).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "tunnel packet exceeded 65535 bytes")
                })?;
                let writer = &mut stream_writers[lane_index % stream_writers.len()];
                lane_index = lane_index.wrapping_add(1);
                frame.clear();
                frame.extend_from_slice(&packet_len.to_be_bytes());
                frame.extend_from_slice(&packet[..packet_len as usize]);
                writer.write_all(&frame)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn validate_tun_packet_size(size: usize, limit: usize) -> io::Result<()> {
    if size > limit || size > u16::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("tunnel packet size {size} exceeds the configured {limit}-byte ceiling")));
    }
    Ok(())
}

fn read_exact_interruptible(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    running: &AtomicBool,
) -> io::Result<bool> {
    let mut offset = 0_usize;
    while offset < buffer.len() {
        if !running.load(AtomicOrdering::Relaxed) {
            return Ok(false);
        }
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => return Ok(false),
            Ok(read_len) => offset += read_len,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

fn write_tun_packet(
    tun: &mut fs::File,
    packet: &[u8],
    running: &AtomicBool,
) -> io::Result<()> {
    while running.load(AtomicOrdering::Relaxed) {
        match tun.write(packet) {
            Ok(written) if written == packet.len() => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short write while injecting tunnel packet",
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn is_stream_disconnect_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

fn is_transient_tunnel_stream_error(message: &str) -> bool {
    message.contains("Broken pipe")
        || message.contains("Connection reset by peer")
        || message.contains("UnexpectedEof")
        || message.contains("Connection aborted")
}

#[cfg(target_os = "linux")]
const TUN_HELPER_IFNAMSIZ: usize = 16;
#[cfg(target_os = "linux")]
const TUN_HELPER_IFF_TUN: c_short = 0x0001;
#[cfg(target_os = "linux")]
const TUN_HELPER_IFF_NO_PI: c_short = 0x1000;
#[cfg(target_os = "linux")]
const TUN_HELPER_SETIFF: c_ulong = 0x4004_54ca;
#[cfg(target_os = "linux")]
const TUN_HELPER_NONBLOCK: i32 = 0o4000;

#[cfg(target_os = "linux")]
#[repr(C)]
union TunIfReqData {
    flags: c_short,
    raw: [u8; 24],
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct TunIfReq {
    name: [c_char; TUN_HELPER_IFNAMSIZ],
    data: TunIfReqData,
}

#[cfg(target_os = "linux")]
extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

#[cfg(target_os = "linux")]
fn open_named_tun(interface: &str) -> Result<fs::File, String> {
    if interface.is_empty() {
        return Err("tunnel helper needs a non-empty interface name".to_string());
    }
    if interface.len() >= TUN_HELPER_IFNAMSIZ {
        return Err(format!(
            "tunnel helper interface name {interface} is too long for Linux TUN"
        ));
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(TUN_HELPER_NONBLOCK)
        .open("/dev/net/tun")
        .map_err(|error| format!("failed to open /dev/net/tun: {error}"))?;

    let mut request = TunIfReq {
        name: [0; TUN_HELPER_IFNAMSIZ],
        data: TunIfReqData {
            raw: [0; 24],
        },
    };
    for (index, byte) in interface.as_bytes().iter().enumerate() {
        request.name[index] = *byte as c_char;
    }
    request.data = TunIfReqData {
        flags: TUN_HELPER_IFF_TUN | TUN_HELPER_IFF_NO_PI,
    };

    let result = unsafe { ioctl(file.as_raw_fd(), TUN_HELPER_SETIFF, &mut request as *mut TunIfReq) };
    if result < 0 {
        return Err(format!(
            "failed to attach tunnel helper to interface {interface}: {}",
            io::Error::last_os_error()
        ));
    }

    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn open_named_tun(_interface: &str) -> Result<fs::File, String> {
    Err("the built-in TUN helper currently supports Linux only".to_string())
}

fn run_check(
    check: &CheckDefinition,
    state: &Arc<Mutex<PersistedState>>,
) -> CheckResult {
    let check_id = check.id().to_string();
    let interval_secs = check.interval_secs().max(10);
    let now = unix_now();

    if let Ok(guard) = state.lock() {
        if let Some(last_run_unix) = guard.last_check_run_unix.get(&check_id).copied() {
            if now.saturating_sub(last_run_unix) < interval_secs {
                if let Some(cached_result) = guard.last_results.get(&check_id).cloned() {
                    return cached_result;
                }
            }
        }
    }

    let result = match check {
        CheckDefinition::Icmp(check) => run_icmp(check),
        CheckDefinition::Tcp(check) => run_tcp(check),
        CheckDefinition::Udp(check) => run_udp(check),
        CheckDefinition::Ssh(check) => run_ssh_like(check, "ssh"),
        CheckDefinition::Sftp(check) => run_ssh_like(check, "sftp"),
        CheckDefinition::Http(check) => run_http(check, false),
        CheckDefinition::Https(check) => run_http(check, true),
        CheckDefinition::Dns(check) => run_dns(check),
        CheckDefinition::Rdp(check) => run_rdp(check),
        CheckDefinition::Ftp(check) => run_ftp(check),
        CheckDefinition::Tunnel(check) => run_tunnel(check, state, interval_secs),
        CheckDefinition::V2raySimulation(check) => run_v2ray_simulation(check),
    };

    if let Ok(mut guard) = state.lock() {
        guard
            .last_check_run_unix
            .insert(check_id.clone(), result.observed_at_unix);
        guard.last_results.insert(check_id, result.clone());
    }

    result
}

fn run_icmp(check: &IcmpCheck) -> CheckResult {
    let observed_at = unix_now();
    let started = Instant::now();
    let mut details = BTreeMap::new();
    details.insert("target".to_string(), json!(check.target));

    match run_ping(&check.target, check.ip_version, check.timeout_ms, None) {
        Ok(outcome) => {
            if let Some(latency_ms) = outcome.latency_ms {
                details.insert("rtt_ms".to_string(), json!(latency_ms));
            }
            details.insert("probe_output".to_string(), json!(outcome.summary));
            make_result(
                &check.id,
                "icmp",
                CheckStatus::Up,
                "icmp echo succeeded",
                observed_at,
                started,
                outcome.latency_ms,
                Some(check.ip_version),
                Some(check.target.clone()),
                details,
            )
        }
        Err(error) => make_result(
            &check.id,
            "icmp",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            Some(check.target.clone()),
            details,
        ),
    }
}

fn run_tcp(check: &SocketCheck) -> CheckResult {
    let observed_at = unix_now();
    let started = Instant::now();
    let mut details = BTreeMap::new();

    match resolve_socket_addresses(&check.target, check.port, check.ip_version)
        .and_then(|addresses| connect_tcp_candidates(&addresses, check.timeout_ms)) {
        Ok((_stream, address)) => {
            details.insert("resolved_address".to_string(), json!(address.to_string()));
            make_result(
                    &check.id,
                    "tcp",
                    CheckStatus::Up,
                    "tcp connect succeeded",
                    observed_at,
                    started,
                    Some(elapsed_ms(started)),
                    Some(ip_version_from_addr(address)),
                    Some(address.to_string()),
                    details,
                )
        }
        Err(error) => make_result(
            &check.id,
            "tcp",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            None,
            details,
        ),
    }
}

fn run_udp(check: &UdpCheck) -> CheckResult {
    let observed_at = unix_now();
    let started = Instant::now();
    let mut details = BTreeMap::new();

    match resolve_socket_addr(&check.target, check.port, check.ip_version) {
        Ok(address) => {
            details.insert("resolved_address".to_string(), json!(address.to_string()));
            let bind_address = match address {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            };

            match UdpSocket::bind(bind_address) {
                Ok(socket) => {
                    if let Err(error) = socket.set_read_timeout(Some(timeout_duration(check.timeout_ms)))
                    {
                        return make_result(
                            &check.id,
                            "udp",
                            CheckStatus::Down,
                            format!("failed to set udp read timeout: {error}"),
                            observed_at,
                            started,
                            None,
                            Some(ip_version_from_addr(address)),
                            Some(address.to_string()),
                            details,
                        );
                    }
                    if let Err(error) = socket.set_write_timeout(Some(timeout_duration(check.timeout_ms)))
                    {
                        return make_result(
                            &check.id,
                            "udp",
                            CheckStatus::Down,
                            format!("failed to set udp write timeout: {error}"),
                            observed_at,
                            started,
                            None,
                            Some(ip_version_from_addr(address)),
                            Some(address.to_string()),
                            details,
                        );
                    }
                    if let Err(error) = socket.connect(address) {
                        return make_result(
                            &check.id,
                            "udp",
                            CheckStatus::Down,
                            format!("udp connect failed: {error}"),
                            observed_at,
                            started,
                            None,
                            Some(ip_version_from_addr(address)),
                            Some(address.to_string()),
                            details,
                        );
                    }

                    let payload = check.payload.clone().unwrap_or_default().into_bytes();
                    match socket.send(&payload) {
                        Ok(bytes_sent) => {
                            details.insert("bytes_sent".to_string(), json!(bytes_sent));
                            if !check.expect_response {
                                details.insert("peer_response_verified".to_string(), json!(false));
                                return make_result(
                                    &check.id,
                                    "udp",
                                    CheckStatus::Degraded,
                                    "udp datagram sent; peer availability is unverified. Enable an expected response to verify the service",
                                    observed_at,
                                    started,
                                    Some(elapsed_ms(started)),
                                    Some(ip_version_from_addr(address)),
                                    Some(address.to_string()),
                                    details,
                                );
                            }

                            let mut buffer = [0_u8; 2048];
                            match socket.recv(&mut buffer) {
                                Ok(received) => {
                                    let response = String::from_utf8_lossy(&buffer[..received]).to_string();
                                    details.insert("bytes_received".to_string(), json!(received));
                                    details.insert("peer_response_verified".to_string(), json!(true));
                                    details.insert("response_preview".to_string(), json!(truncate(&response, 180)));
                                    if let Some(expected) = &check.response_contains {
                                        if !response.contains(expected) {
                                            return make_result(
                                                &check.id,
                                                "udp",
                                                CheckStatus::Down,
                                                format!(
                                                    "udp response arrived but did not contain expected text: {expected}"
                                                ),
                                                observed_at,
                                                started,
                                                None,
                                                Some(ip_version_from_addr(address)),
                                                Some(address.to_string()),
                                                details,
                                            );
                                        }
                                    }

                                    make_result(
                                        &check.id,
                                        "udp",
                                        CheckStatus::Up,
                                        "udp response received",
                                        observed_at,
                                        started,
                                        Some(elapsed_ms(started)),
                                        Some(ip_version_from_addr(address)),
                                        Some(address.to_string()),
                                        details,
                                    )
                                }
                                Err(error) => make_result(
                                    &check.id,
                                    "udp",
                                    CheckStatus::Down,
                                    format!("udp response wait failed: {error}"),
                                    observed_at,
                                    started,
                                    None,
                                    Some(ip_version_from_addr(address)),
                                    Some(address.to_string()),
                                    details,
                                ),
                            }
                        }
                        Err(error) => make_result(
                            &check.id,
                            "udp",
                            CheckStatus::Down,
                            format!("udp send failed: {error}"),
                            observed_at,
                            started,
                            None,
                            Some(ip_version_from_addr(address)),
                            Some(address.to_string()),
                            details,
                        ),
                    }
                }
                Err(error) => make_result(
                    &check.id,
                    "udp",
                    CheckStatus::Down,
                    format!("failed to bind udp socket: {error}"),
                    observed_at,
                    started,
                    None,
                    Some(ip_version_from_addr(address)),
                    Some(address.to_string()),
                    details,
                ),
            }
        }
        Err(error) => make_result(
            &check.id,
            "udp",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            None,
            details,
        ),
    }
}

fn run_ssh_like(check: &SshCheck, kind: &str) -> CheckResult {
    let observed_at = unix_now();
    let started = Instant::now();
    let mut details = BTreeMap::new();
    let expected_prefix = check
        .expect_banner_prefix
        .as_deref()
        .unwrap_or("SSH-");

    match resolve_socket_addr(&check.target, check.port, check.ip_version) {
        Ok(address) => match connect_with_timeouts(address, check.timeout_ms) {
            Ok(stream) => {
                let mut reader = BufReader::new(stream);
                match read_ssh_banner(&mut reader) {
                    Ok(banner) => {
                        details.insert("banner".to_string(), json!(banner.clone()));
                        let message = if kind == "sftp" {
                            "ssh transport is reachable for sftp"
                        } else {
                            "ssh banner received"
                        };
                        if banner.starts_with(expected_prefix) {
                            make_result(
                                &check.id,
                                kind,
                                CheckStatus::Up,
                                message,
                                observed_at,
                                started,
                                Some(elapsed_ms(started)),
                                Some(ip_version_from_addr(address)),
                                Some(address.to_string()),
                                details,
                            )
                        } else {
                            make_result(
                                &check.id,
                                kind,
                                CheckStatus::Down,
                                format!("received unexpected ssh banner: {banner}"),
                                observed_at,
                                started,
                                None,
                                Some(ip_version_from_addr(address)),
                                Some(address.to_string()),
                                details,
                            )
                        }
                    }
                    Err(error) => make_result(
                        &check.id,
                        kind,
                        CheckStatus::Down,
                        error,
                        observed_at,
                        started,
                        None,
                        Some(ip_version_from_addr(address)),
                        Some(address.to_string()),
                        details,
                    ),
                }
            }
            Err(error) => make_result(
                &check.id,
                kind,
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(ip_version_from_addr(address)),
                Some(address.to_string()),
                details,
            ),
        },
        Err(error) => make_result(
            &check.id,
            kind,
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            None,
            details,
        ),
    }
}

fn run_http(check: &WebCheck, use_tls: bool) -> CheckResult {
    let observed_at = unix_now();
    let started = Instant::now();
    let kind = if use_tls { "https" } else { "http" };
    let port = check.port.unwrap_or(if use_tls { 443 } else { 80 });
    let connect_host = check.connect_host.as_deref().unwrap_or(&check.host);
    let host_header = check.host_header.as_deref().unwrap_or(&check.host);
    let path = normalized_path(&check.path);
    let mut details = BTreeMap::new();
    details.insert("host".to_string(), json!(host_header));
    details.insert("path".to_string(), json!(path.clone()));

    // Curl owns name resolution for web monitors. A separate DNS preflight made
    // otherwise healthy domains fail before their actual HTTP request was tried.
    let resolved_address = connect_host.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, port));
    if let Some(address) = resolved_address {
        details.insert("resolved_endpoint".to_string(), json!(address.to_string()));
    }
    let result_ip_version = resolved_address
        .map(ip_version_from_addr)
        .unwrap_or(check.ip_version);
    let result_target = resolved_address
        .map(|address| address.to_string())
        .unwrap_or_else(|| connect_host.to_string());

    match perform_curl_exchange(check, use_tls, port) {
            Ok(summary) => {
                let result_ip_version = summary.remote_ip.map(|ip| ip_version_from_addr(SocketAddr::new(ip, port))).unwrap_or(result_ip_version);
                let result_target = summary.remote_ip.map(|ip| SocketAddr::new(ip, port).to_string()).unwrap_or_else(|| result_target.clone());
                if let Some(remote_ip) = summary.remote_ip { details.insert("resolved_endpoint".to_string(), json!(SocketAddr::new(remote_ip, port).to_string())); }
                details.insert("status_line".to_string(), json!(summary.status_line.clone()));
                details.insert("status_code".to_string(), json!(summary.status_code));
                details.insert(
                    "body_preview".to_string(),
                    json!(truncate(&summary.body_preview, 240)),
                );
                let expected_match = if check.expected_status.is_empty() {
                    (200..=399).contains(&summary.status_code)
                } else {
                    check.expected_status.contains(&summary.status_code)
                };
                if !expected_match {
                    return make_result(
                        &check.id,
                        kind,
                        CheckStatus::Down,
                        format!("unexpected http status: {}", summary.status_code),
                        observed_at,
                        started,
                        None,
                        Some(result_ip_version),
                        Some(result_target.clone()),
                        details,
                    );
                }
                if let Some(needle) = &check.body_contains {
                    if !summary.body_preview.contains(needle) {
                        return make_result(
                            &check.id,
                            kind,
                            CheckStatus::Down,
                            format!("response body did not contain expected text: {needle}"),
                            observed_at,
                            started,
                            None,
                            Some(result_ip_version),
                            Some(result_target.clone()),
                            details,
                        );
                    }
                }
                make_result(
                    &check.id,
                    kind,
                    CheckStatus::Up,
                    "http request succeeded",
                    observed_at,
                    started,
                    Some(elapsed_ms(started)),
                    Some(result_ip_version),
                    Some(result_target),
                    details,
                )
            }
            Err(error) => make_result(
                &check.id,
                kind,
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(result_ip_version),
                Some(result_target),
                details,
            ),
    }
}

fn run_dns(check: &DnsCheck) -> CheckResult {
    let observed_at = unix_now();
    let started = Instant::now();
    let mut details = BTreeMap::new();
    details.insert("record_name".to_string(), json!(check.record_name));
    details.insert("record_type".to_string(), json!(check.record_type.as_str()));
    let mut endpoint = None;
    let mut family = check.ip_version;
    let result = resolve_socket_addr(&check.server, check.port, check.ip_version).and_then(|server| {
        endpoint = Some(server.to_string());
        family = ip_version_from_addr(server);
        let (packet, query_id, used_tcp) = exchange_dns_packet(check, server)?;
        details.insert("dns_transport".to_string(), json!(if used_tcp { "tcp" } else { "udp" }));
        parse_dns_response(&packet, query_id, &check.record_name, check.record_type)
    });
    match result {
        Ok(summary) => {
            details.insert("rcode".to_string(), json!(summary.rcode));
            details.insert("answer_count".to_string(), json!(summary.answer_count));
            details.insert("answers".to_string(), json!(summary.answers));
            let enough = summary.answer_count >= check.expect_answers_min;
            make_result(&check.id, "dns", if enough { CheckStatus::Up } else { CheckStatus::Down },
                if enough { format!("dns query succeeded with {} {} answers", summary.answer_count, check.record_type.as_str()) }
                else { format!("dns query returned too few {} answers: expected at least {}, got {}", check.record_type.as_str(), check.expect_answers_min, summary.answer_count) },
                observed_at, started, Some(elapsed_ms(started)), Some(family), endpoint, details)
        }
        Err(error) => make_result(&check.id, "dns", CheckStatus::Down, error,
            observed_at, started, None, Some(family), endpoint, details),
    }
}

fn exchange_dns_packet(check: &DnsCheck, server: SocketAddr) -> Result<(Vec<u8>, u16, bool), String> {
    let deadline = Instant::now() + timeout_duration(check.timeout_ms);
    let bind_address = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind_address).map_err(|error| format!("Cannot bind DNS UDP socket: {error}"))?;
    socket.set_write_timeout(Some(timeout_duration(check.timeout_ms))).map_err(|error| error.to_string())?;
    socket.connect(server).map_err(|error| error.to_string())?;
    let query_id = dns_query_id();
    let query = build_dns_query(query_id, &check.record_name, check.record_type)?;
    socket.send(&query).map_err(|error| format!("Cannot send DNS query: {error}"))?;
    let mut response = [0_u8; 4096];
    loop {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or_else(|| "DNS query timed out.".to_string())?;
        socket.set_read_timeout(Some(remaining)).map_err(|error| error.to_string())?;
        let received = socket.recv(&mut response).map_err(|error| format!("Cannot receive DNS response: {error}"))?;
        if received < 2 || read_u16(&response[..received], 0)? != query_id { continue; }
        let packet = &response[..received];
        if packet.len() >= 4 && read_u16(packet, 2)? & 0x0200 != 0 {
            // RFC 1035 truncated UDP responses must be retried over TCP.
            let remaining = deadline.checked_duration_since(Instant::now()).ok_or_else(|| "DNS TCP retry timed out.".to_string())?;
            let mut stream = TcpStream::connect_timeout(&server, remaining).map_err(|error| format!("DNS response was truncated and TCP retry failed: {error}"))?;
            stream.set_write_timeout(Some(remaining)).map_err(|error| error.to_string())?;
            let mut framed = (query.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&query);
            stream.write_all(&framed).map_err(|error| format!("Cannot send DNS TCP query: {error}"))?;
            let mut length = [0_u8; 2];
            read_exact_until(&mut stream, &mut length, deadline)?;
            let length = u16::from_be_bytes(length) as usize;
            if length < 12 { return Err("DNS TCP response was shorter than its header.".to_string()); }
            let mut packet = vec![0_u8; length];
            read_exact_until(&mut stream, &mut packet, deadline)?;
            return Ok((packet, query_id, true));
        }
        return Ok((packet.to_vec(), query_id, false));
    }
}

fn read_exact_until(stream: &mut TcpStream, mut buffer: &mut [u8], deadline: Instant) -> Result<(), String> {
    while !buffer.is_empty() {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or_else(|| "Response deadline exceeded.".to_string())?;
        stream.set_read_timeout(Some(remaining)).map_err(|error| error.to_string())?;
        let received = stream.read(buffer).map_err(|error| format!("Cannot read response: {error}"))?;
        if received == 0 { return Err("Peer closed before sending the complete response.".to_string()); }
        buffer = &mut buffer[received..];
    }
    Ok(())
}

fn run_rdp(check: &RdpCheck) -> CheckResult {
    let observed_at = unix_now();
    let started = Instant::now();
    let mut details = BTreeMap::new();

    match resolve_socket_addr(&check.target, check.port, check.ip_version) {
        Ok(address) => match connect_with_timeouts(address, check.timeout_ms) {
            Ok(mut stream) => {
                const RDP_NEGOTIATION_REQUEST: [u8; 19] = [
                    0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                    0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
                ];
                if let Err(error) = stream.write_all(&RDP_NEGOTIATION_REQUEST) {
                    return make_result(
                        &check.id,
                        "rdp",
                        CheckStatus::Down,
                        format!("failed to write rdp negotiation packet: {error}"),
                        observed_at,
                        started,
                        None,
                        Some(ip_version_from_addr(address)),
                        Some(address.to_string()),
                        details,
                    );
                }
                let mut buffer = [0_u8; 64];
                match stream.read(&mut buffer) {
                    Ok(received) => {
                        details.insert("bytes_received".to_string(), json!(received));
                        if received >= 6 && buffer[0] == 0x03 && buffer[1] == 0x00 {
                            make_result(
                                &check.id,
                                "rdp",
                                CheckStatus::Up,
                                "rdp negotiation response received",
                                observed_at,
                                started,
                                Some(elapsed_ms(started)),
                                Some(ip_version_from_addr(address)),
                                Some(address.to_string()),
                                details,
                            )
                        } else {
                            make_result(
                                &check.id,
                                "rdp",
                                CheckStatus::Down,
                                "received data but not a valid rdp negotiation response",
                                observed_at,
                                started,
                                None,
                                Some(ip_version_from_addr(address)),
                                Some(address.to_string()),
                                details,
                            )
                        }
                    }
                    Err(error) => make_result(
                        &check.id,
                        "rdp",
                        CheckStatus::Down,
                        format!("failed to read rdp response: {error}"),
                        observed_at,
                        started,
                        None,
                        Some(ip_version_from_addr(address)),
                        Some(address.to_string()),
                        details,
                    ),
                }
            }
            Err(error) => make_result(
                &check.id,
                "rdp",
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(ip_version_from_addr(address)),
                Some(address.to_string()),
                details,
            ),
        },
        Err(error) => make_result(
            &check.id,
            "rdp",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            None,
            details,
        ),
    }
}

fn run_ftp(check: &FtpCheck) -> CheckResult {
    let observed_at = unix_now();
    let started = Instant::now();
    let mut details = BTreeMap::new();

    match resolve_socket_addr(&check.target, check.port, check.ip_version) {
        Ok(address) => match connect_with_timeouts(address, check.timeout_ms) {
            Ok(mut stream) => {
                let read_handle = match stream.try_clone() {
                    Ok(clone) => clone,
                    Err(error) => {
                        return make_result(
                            &check.id,
                            "ftp",
                            CheckStatus::Down,
                            format!("failed to clone ftp stream: {error}"),
                            observed_at,
                            started,
                            None,
                            Some(ip_version_from_addr(address)),
                            Some(address.to_string()),
                            details,
                        )
                    }
                };

                let mut reader = BufReader::new(read_handle);
                match read_ftp_response(&mut reader) {
                    Ok(banner) => {
                        details.insert("banner".to_string(), json!(banner.clone()));
                        if !banner.starts_with("220") {
                            return make_result(
                                &check.id,
                                "ftp",
                                CheckStatus::Down,
                                format!("unexpected ftp banner: {banner}"),
                                observed_at,
                                started,
                                None,
                                Some(ip_version_from_addr(address)),
                                Some(address.to_string()),
                                details,
                            );
                        }

                        if let Some(username) = &check.username {
                            if let Err(error) = write_ftp_command(&mut stream, &format!("USER {username}")) {
                                return make_result(
                                    &check.id,
                                    "ftp",
                                    CheckStatus::Down,
                                    format!("failed to send ftp USER command: {error}"),
                                    observed_at,
                                    started,
                                    None,
                                    Some(ip_version_from_addr(address)),
                                    Some(address.to_string()),
                                    details,
                                );
                            }

                            let user_response = match read_ftp_response(&mut reader) {
                                Ok(response) => response,
                                Err(error) => {
                                    return make_result(
                                        &check.id,
                                        "ftp",
                                        CheckStatus::Down,
                                        format!("failed to read ftp USER response: {error}"),
                                        observed_at,
                                        started,
                                        None,
                                        Some(ip_version_from_addr(address)),
                                        Some(address.to_string()),
                                        details,
                                    )
                                }
                            };
                            details.insert("user_response".to_string(), json!(user_response.clone()));

                            if user_response.starts_with("230") {
                                return make_result(
                                    &check.id,
                                    "ftp",
                                    CheckStatus::Up,
                                    "ftp login succeeded without password",
                                    observed_at,
                                    started,
                                    Some(elapsed_ms(started)),
                                    Some(ip_version_from_addr(address)),
                                    Some(address.to_string()),
                                    details,
                                );
                            }

                            if !user_response.starts_with("331") {
                                return make_result(
                                    &check.id,
                                    "ftp",
                                    CheckStatus::Down,
                                    format!("ftp server rejected USER command: {user_response}"),
                                    observed_at,
                                    started,
                                    None,
                                    Some(ip_version_from_addr(address)),
                                    Some(address.to_string()),
                                    details,
                                );
                            }

                            let password = check.password.as_deref().unwrap_or("");
                            if let Err(error) = write_ftp_command(&mut stream, &format!("PASS {password}")) {
                                return make_result(
                                    &check.id,
                                    "ftp",
                                    CheckStatus::Down,
                                    format!("failed to send ftp PASS command: {error}"),
                                    observed_at,
                                    started,
                                    None,
                                    Some(ip_version_from_addr(address)),
                                    Some(address.to_string()),
                                    details,
                                );
                            }

                            match read_ftp_response(&mut reader) {
                                Ok(response) => {
                                    details.insert("pass_response".to_string(), json!(response.clone()));
                                    if response.starts_with("230") {
                                        make_result(
                                            &check.id,
                                            "ftp",
                                            CheckStatus::Up,
                                            "ftp login succeeded",
                                            observed_at,
                                            started,
                                            Some(elapsed_ms(started)),
                                            Some(ip_version_from_addr(address)),
                                            Some(address.to_string()),
                                            details,
                                        )
                                    } else {
                                        make_result(
                                            &check.id,
                                            "ftp",
                                            CheckStatus::Down,
                                            format!("ftp login failed: {response}"),
                                            observed_at,
                                            started,
                                            None,
                                            Some(ip_version_from_addr(address)),
                                            Some(address.to_string()),
                                            details,
                                        )
                                    }
                                }
                                Err(error) => make_result(
                                    &check.id,
                                    "ftp",
                                    CheckStatus::Down,
                                    format!("failed to read ftp PASS response: {error}"),
                                    observed_at,
                                    started,
                                    None,
                                    Some(ip_version_from_addr(address)),
                                    Some(address.to_string()),
                                    details,
                                ),
                            }
                        } else {
                            make_result(
                                &check.id,
                                "ftp",
                                CheckStatus::Up,
                                "ftp banner received",
                                observed_at,
                                started,
                                Some(elapsed_ms(started)),
                                Some(ip_version_from_addr(address)),
                                Some(address.to_string()),
                                details,
                            )
                        }
                    }
                    Err(error) => make_result(
                        &check.id,
                        "ftp",
                        CheckStatus::Down,
                        error,
                        observed_at,
                        started,
                        None,
                        Some(ip_version_from_addr(address)),
                        Some(address.to_string()),
                        details,
                    ),
                }
            }
            Err(error) => make_result(
                &check.id,
                "ftp",
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(ip_version_from_addr(address)),
                Some(address.to_string()),
                details,
            ),
        },
        Err(error) => make_result(
            &check.id,
            "ftp",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            None,
            details,
        ),
    }
}

fn run_tunnel(
    check: &TunnelCheck,
    state: &Arc<Mutex<PersistedState>>,
    interval_secs: u64,
) -> CheckResult {
    let observed_at = unix_now();
    let started = Instant::now();
    let mut details = BTreeMap::new();
    details.insert("protocol".to_string(), json!(check.protocol.as_str()));
    details.insert("protocol_number".to_string(), json!(check.protocol.protocol_number()));
    if let Err(error) = validate_tunnel_configuration(check) {
        return make_result(&check.id, "tunnel", CheckStatus::Down, error, observed_at, started,
            None, Some(check.ip_version), check.interface.clone(), details);
    }
    if matches!(check.protocol, TunnelProtocol::L2tp)
        && check.l2tp_encapsulation.as_deref().unwrap_or("udp").eq_ignore_ascii_case("udp") {
        details.insert("protocol_number".to_string(), json!(17));
    }

    if matches!(check.protocol, TunnelProtocol::Tun) {
        return run_tun_tunnel(check, state, interval_secs, observed_at, started, details);
    }

    if matches!(check.protocol, TunnelProtocol::Ssh) {
        return run_ssh_tunnel(check, state, interval_secs, observed_at, started, details);
    }

    if matches!(check.protocol, TunnelProtocol::ReverseSsh) {
        return run_reverse_ssh_tunnel(check, state, interval_secs, observed_at, started, details);
    }

    if matches!(check.protocol, TunnelProtocol::Esp) {
        return run_esp_tunnel(check, state, observed_at, started, details);
    }

    if check.protocol.is_interface_based() {
        return run_interface_tunnel(check, state, observed_at, started, details);
    }

    make_result(
        &check.id,
        "tunnel",
        CheckStatus::Down,
        "unsupported tunnel protocol configuration",
        observed_at,
        started,
        None,
        Some(check.ip_version),
        None,
        details,
    )
}

pub fn validate_tunnel_configuration(check: &TunnelCheck) -> Result<(), String> {
    for interface in [check.interface.as_deref(), check.source_interface.as_deref()].into_iter().flatten() {
        if interface.is_empty() || interface.len() > 15 || !interface.bytes().all(|byte|
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')) || interface == "." || interface == ".." {
            return Err("Tunnel interface names must use 1–15 letters, numbers, dots, underscores, or dashes.".to_string());
        }
    }
    if let Some(cidr) = check.inner_local_cidr.as_deref() {
        let mut parts = cidr.trim().split('/');
        let address = parts.next().unwrap_or("").parse::<IpAddr>().map_err(|_| "Invalid inner tunnel address.".to_string())?;
        if let Some(prefix) = parts.next() {
            let prefix = prefix.parse::<u8>().map_err(|_| "Invalid tunnel CIDR prefix.".to_string())?;
            if prefix > if address.is_ipv4() { 32 } else { 128 } { return Err("Tunnel CIDR prefix is out of range.".to_string()); }
        }
        if parts.next().is_some() || address.is_unspecified() || address.is_multicast() {
            return Err("Use a specific unicast inner tunnel address with a valid CIDR prefix.".to_string());
        }
        if check.auto_create_interface {
            if let Some(peer) = check.inner_probe.as_deref().and_then(|peer| peer.parse::<IpAddr>().ok()) {
                if address.is_ipv4() != peer.is_ipv4() || address == peer {
                    return Err("Local and peer inner tunnel IPs must be different addresses in the same IP family.".to_string());
                }
            }
            if matches!(check.protocol, TunnelProtocol::Ipv4IpInIp | TunnelProtocol::Ipip | TunnelProtocol::Encap) && address.is_ipv6() {
                return Err("IPIP / GUE requires IPv4 inner tunnel addresses.".to_string());
            }
            if check.protocol == TunnelProtocol::Ipv6Encapsulation && address.is_ipv4() {
                return Err("SIT / IPv6 encapsulation requires IPv6 inner tunnel addresses.".to_string());
            }
        }
    }
    if check.auto_create_interface {
        if let Some(peer) = check.inner_probe.as_deref() {
            let peer = peer.parse::<IpAddr>().map_err(|_| "The inner peer of a managed tunnel must be an IP literal.".to_string())?;
            if peer.is_unspecified() || peer.is_multicast() { return Err("Use a specific unicast inner peer IP address.".to_string()); }
        }
    }
    if check.transport_port == Some(0) || check.listen_port == Some(0) {
        return Err("Tunnel transport and listener ports must be between 1 and 65535.".to_string());
    }
    if let Some(local) = check.local_outer.as_deref() {
        let address = local.parse::<IpAddr>().map_err(|_| "Local Outer must be an IP literal assigned to this host.".to_string())?;
        if address.is_unspecified() || address.is_multicast() { return Err("Local Outer must be a specific unicast IP address.".to_string()); }
    }
    if check.auto_create_interface && check.protocol == TunnelProtocol::Etherip {
        return Err("Standard Linux has no native EtherIP link type. Monitor an externally managed EtherIP interface, or choose GRETAP / VXLAN for a managed Ethernet tunnel.".to_string());
    }
    if let Some(mtu) = check.mtu {
        if !(576..=9000).contains(&mtu) { return Err("Tunnel MTU must be between 576 and 9000 bytes.".to_string()); }
        let inner_ipv6 = check.inner_probe.as_deref().and_then(|ip| ip.parse::<IpAddr>().ok()).is_some_and(|ip| ip.is_ipv6())
            || check.inner_local_cidr.as_deref().and_then(extract_ip_from_cidr).is_some_and(|ip| ip.contains(':'));
        if inner_ipv6 && mtu < 1280 { return Err("IPv6 inner tunnels require an MTU of at least 1280 bytes.".to_string()); }
    }
    if check.ttl == Some(0) { return Err("Outer TTL / hop limit must be between 1 and 255; leave blank for the kernel default.".to_string()); }
    if (check.ttl.is_some() || check.traffic_class.is_some()) && !tunnel_supports_outer_packet_settings(check.protocol) {
        return Err("Outer TTL / traffic class is supported by GRE, GRETAP, IPIP, SIT, GUE, VXLAN, and GENEVE. This mode supports MTU only.".to_string());
    }
    if matches!(check.protocol, TunnelProtocol::Vxlan | TunnelProtocol::Geneve) {
        if !matches!(check.vni.unwrap_or(42), 1..=16_777_215) { return Err("VXLAN / GENEVE VNI must be between 1 and 16777215, with the same value on both peers.".to_string()); }
    } else if check.vni.is_some() { return Err("VNI is only used by VXLAN and GENEVE.".to_string()); }
    if let Some(lanes) = check.tun_lanes {
        if !(1..=8).contains(&lanes) { return Err("TUN lanes must be between 1 and 8.".to_string()); }
        if check.protocol != TunnelProtocol::Tun || !matches!(normalized_tun_transport(check).as_str(), "tcp" | "icmp") {
            return Err("Configurable TUN lanes are available only for TCP and ICMP transport.".to_string());
        }
        if normalized_tun_transport(check) == "icmp" {
            icmp_tun_local_forward_ports(check.listen_port.unwrap_or(56000), usize::from(lanes))?;
        }
    }
    if check.auto_create_interface && !matches!(check.protocol, TunnelProtocol::Tun | TunnelProtocol::Ssh | TunnelProtocol::ReverseSsh | TunnelProtocol::Wireguard) {
        let remote = check.outer_remote.as_deref().ok_or_else(|| "Managed kernel tunnels require the peer's outer IP address.".to_string())?
            .parse::<IpAddr>().map_err(|_| "Kernel tunnel outer endpoints must be IP literals, not hostnames.".to_string())?;
        if remote.is_unspecified() || remote.is_multicast() { return Err("Use a specific unicast peer outer IP address.".to_string()); }
        if let Some(local) = check.local_outer.as_deref() {
            let local = local.parse::<IpAddr>().map_err(|_| "The local outer address must be an IP literal assigned to this host.".to_string())?;
            if local.is_ipv4() != remote.is_ipv4() || local.is_unspecified() || local.is_multicast() || local == remote {
                return Err("Local and peer outer IPs must be different unicast addresses in the same IP family.".to_string());
            }
        }
        if check.protocol == TunnelProtocol::Encap && remote.is_ipv6() {
            return Err("Kernel IPIP over GUE currently requires IPv4 outer endpoints.".to_string());
        }
        if matches!(check.protocol, TunnelProtocol::Ipip | TunnelProtocol::Ipv4IpInIp | TunnelProtocol::Encap)
            && check.inner_probe.as_deref().and_then(|ip| ip.parse::<IpAddr>().ok()).is_some_and(|ip| ip.is_ipv6()) {
            return Err("IPIP / GUE carries IPv4 inner traffic. Use GRE, VXLAN, GENEVE, or IPv6 encapsulation for IPv6 inner traffic.".to_string());
        }
        if matches!(check.protocol, TunnelProtocol::Gre | TunnelProtocol::Gretap) {
            if let Some(key) = check.tunnel_key.as_deref() {
                let key = key.trim();
                let hexadecimal = key.strip_prefix("0x").or_else(|| key.strip_prefix("0X"))
                    .is_some_and(|digits| u32::from_str_radix(digits, 16).is_ok());
                if key.parse::<u32>().is_err() && key.parse::<Ipv4Addr>().is_err() && !hexadecimal {
                    return Err("GRE / GRETAP keys must be unsigned 32-bit decimal or hexadecimal (0x...) numbers, or dotted IPv4-style values.".to_string());
                }
            }
        }
    }
    if matches!(check.protocol, TunnelProtocol::Tun)
        && !matches!(normalized_tun_transport(check).as_str(), "udp" | "tcp" | "icmp" | "bip") {
        return Err("Unsupported TUN transport. Choose UDP, TCP, or ICMP; BIP is a legacy UDP alias.".to_string());
    }
    if matches!(check.protocol, TunnelProtocol::L2tp)
        && !matches!(check.l2tp_encapsulation.as_deref().unwrap_or("udp").to_ascii_lowercase().as_str(), "udp" | "ip") {
        return Err("L2TP encapsulation must be UDP or IP.".to_string());
    }
    if matches!(check.protocol, TunnelProtocol::L2tp) && [check.l2tp_tunnel_id, check.l2tp_peer_tunnel_id, check.l2tp_session_id, check.l2tp_peer_session_id].into_iter().flatten().any(|id| id == 0) {
        return Err("L2TP tunnel and session identifiers must be nonzero, and mirrored on the peer.".to_string());
    }
    if check.protocol == TunnelProtocol::Tun && normalized_tun_transport(check) == "icmp" && tunnel_outer_uses_ipv6(check) {
        return Err("The existing ptunnel-ng ICMP carrier requires IPv4 outer endpoints. Choose a kernel IPv6-capable mode for IPv6 outer traffic.".to_string());
    }
    if check.auto_create_interface && check.protocol == TunnelProtocol::Ipv6Encapsulation {
        if check.inner_probe.as_deref().and_then(|ip| ip.parse::<IpAddr>().ok()).is_some_and(|ip| ip.is_ipv4()) {
            return Err("SIT / IPv6 encapsulation carries IPv6 inner traffic. Choose GRE or IPIP for IPv4 inner traffic.".to_string());
        }
    }
    if check.auto_create_interface && matches!(check.protocol, TunnelProtocol::Ssh) {
        let peer = check.inner_probe.as_deref().ok_or_else(|| "Managed SSH tunnels require the peer's inner tunnel IP.".to_string())?;
        if peer.trim().parse::<IpAddr>().is_err() {
            return Err("SSH peer tunnel addresses must be IP literals, without a CIDR prefix or shell text.".to_string());
        }
    }
    if check.auto_create_interface && matches!(check.protocol, TunnelProtocol::Wireguard) {
        for (label, key, required) in [
            ("WireGuard private key", check.wireguard_private_key.as_deref(), true),
            ("WireGuard peer public key", check.wireguard_peer_public_key.as_deref(), true),
            ("WireGuard preshared key", check.wireguard_preshared_key.as_deref(), false),
        ] {
            if let Some(key) = key {
                if decode_base64_lenient(key).map_or(true, |bytes| bytes.len() != 32) {
                    return Err(format!("{label} must be a valid base64-encoded 32-byte WireGuard key."));
                }
            } else if required { return Err(format!("{label} is required for managed WireGuard tunnels.")); }
        }
    }
    if check.protocol == TunnelProtocol::Esp && check.esp_cipher == EspCipher::AesCbcHmacSha256
        && check.esp_key_derivation != EspKeyDerivation::HkdfSha256 {
        return Err("Managed AES-CBC/HMAC-SHA256 ESP requires HKDF-SHA256 derivation and the same random shared secret on both peers.".to_string());
    }
    if matches!(check.protocol, TunnelProtocol::Esp) && check.esp_key_derivation == EspKeyDerivation::HkdfSha256 {
        let secret = check.tunnel_key.as_deref().unwrap_or("");
        if !(32..=128).contains(&secret.len()) || !secret.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err("Secure ESP needs the same random shared secret on both peers (32–128 ASCII characters, no spaces).".to_string());
        }
        if esp_shared_seed(check).is_none() { return Err("Secure ESP needs valid local and peer inner tunnel IPs.".to_string()); }
    }
    Ok(())
}

fn run_v2ray_simulation(check: &V2raySimulationCheck) -> CheckResult {
    let observed_at = unix_now();
    let started = Instant::now();
    let mut details = BTreeMap::new();
    details.insert("proxy_type".to_string(), json!(check.proxy_type.as_str()));
    details.insert(
        "local_entry_type".to_string(),
        json!(check.local_entry_type.as_str()),
    );
    if let Some(proxy_host) = &check.proxy_host {
        details.insert("proxy_host".to_string(), json!(proxy_host));
    }
    if let Some(proxy_port) = check.proxy_port {
        details.insert("proxy_port".to_string(), json!(proxy_port));
    }
    if let Some(test_url) = &check.test_url {
        details.insert("test_url".to_string(), json!(test_url));
    }
    if let Some(server_host) = &check.server_host {
        details.insert("server_host".to_string(), json!(server_host));
    }
    if let Some(server_port) = check.server_port {
        details.insert("server_port".to_string(), json!(server_port));
    }
    if let Some(server_name) = &check.server_name {
        details.insert("server_name".to_string(), json!(server_name));
    }
    if let Some(transport) = &check.transport {
        details.insert("transport".to_string(), json!(transport));
    }
    if let Some(interface) = &check.wireguard_interface {
        details.insert("wireguard_interface".to_string(), json!(interface));
    }
    if let Some(peer) = &check.wireguard_peer {
        details.insert("wireguard_peer".to_string(), json!(peer));
    }
    if let Some(inner_probe) = &check.inner_probe {
        details.insert("inner_probe".to_string(), json!(inner_probe));
    }
    if let Some(source_interface) = &check.source_interface {
        details.insert("source_interface".to_string(), json!(source_interface));
    }
    if let Some(max_handshake_age_secs) = check.max_handshake_age_secs {
        details.insert(
            "max_handshake_age_secs".to_string(),
            json!(max_handshake_age_secs),
        );
    }

    match check.proxy_type {
        ProxyType::Socks5 | ProxyType::Http | ProxyType::Https => {
            run_native_proxy_v2ray_simulation(check, observed_at, started, details)
        }
        ProxyType::Wireguard => {
            run_wireguard_v2ray_simulation(check, observed_at, started, details)
        }
        _ => run_xray_family_v2ray_simulation(check, observed_at, started, details),
    }
}

fn run_native_proxy_v2ray_simulation(
    check: &V2raySimulationCheck,
    observed_at: u64,
    started: Instant,
    details: BTreeMap<String, Value>,
) -> CheckResult {
    let entry_type = native_proxy_entry_type(check.proxy_type);
    perform_proxy_style_v2ray_request(
        check,
        observed_at,
        started,
        details,
        entry_type,
        "proxy simulation request succeeded".to_string(),
    )
}

fn run_xray_family_v2ray_simulation(
    check: &V2raySimulationCheck,
    observed_at: u64,
    started: Instant,
    details: BTreeMap<String, Value>,
) -> CheckResult {
    if has_local_proxy_entry(check) {
        return perform_proxy_style_v2ray_request(
            check,
            observed_at,
            started,
            details,
            check.local_entry_type,
            "request succeeded".to_string(),
        );
    }

    if !matches!(check.local_entry_type, LocalEntryType::Direct)
        && (check.proxy_host.is_some() || check.proxy_port.is_some())
    {
        return make_result(
            &check.id,
            "v2ray_simulation",
            CheckStatus::Down,
            format!(
                "{} local entry is configured but incomplete; add the missing host or port and the probe will use {} automatically when Test URL is left empty",
                check.local_entry_type.as_str(),
                default_v2ray_probe_url()
            ),
            observed_at,
            started,
            None,
            Some(check.ip_version),
            v2ray_result_endpoint(check, None),
            details,
        );
    }

    if !matches!(check.local_entry_type, LocalEntryType::Direct) {
        return make_result(
            &check.id,
            "v2ray_simulation",
            CheckStatus::Down,
            "this VMess/VLESS/Trojan/Shadowsocks monitor needs a local SOCKS/HTTP entry to do a real client-style simulation; switch Local Entry Type to Direct only if you intentionally want listener reachability instead"
                .to_string(),
            observed_at,
            started,
            None,
            Some(check.ip_version),
            v2ray_result_endpoint(check, None),
            details,
        );
    }

    let server_host = match check.server_host.as_deref() {
        Some(value) => value,
        None => {
            return make_result(
                &check.id,
                "v2ray_simulation",
                CheckStatus::Down,
                "direct listener mode needs a remote listener host and port".to_string(),
                observed_at,
                started,
                None,
                Some(check.ip_version),
                v2ray_result_endpoint(check, None),
                details,
            )
        }
    };
    let server_port = match check.server_port {
        Some(value) => value,
        None => {
            return make_result(
                &check.id,
                "v2ray_simulation",
                CheckStatus::Down,
                "remote listener port is required when no local entry is configured".to_string(),
                observed_at,
                started,
                None,
                Some(check.ip_version),
                v2ray_result_endpoint(check, None),
                details,
            )
        }
    };

    let mut details = details;
    details.insert(
        "simulation_mode".to_string(),
        json!("direct_listener_reachability"),
    );
    match resolve_socket_addr(server_host, server_port, check.ip_version) {
        Ok(address) => {
            details.insert("resolved_address".to_string(), json!(address.to_string()));
            match connect_with_timeouts(address, check.timeout_ms) {
                Ok(_) => make_result(
                    &check.id,
                    "v2ray_simulation",
                    CheckStatus::Up,
                    format!(
                        "{} direct listener TCP reachability check succeeded; this is not a full proxy simulation",
                        check.proxy_type.as_str()
                    ),
                    observed_at,
                    started,
                    None,
                    Some(ip_version_from_addr(address)),
                    Some(address.to_string()),
                    details,
                ),
                Err(error) => make_result(
                    &check.id,
                    "v2ray_simulation",
                    CheckStatus::Down,
                    format!(
                        "{} direct listener TCP connect failed: {error}",
                        check.proxy_type.as_str()
                    ),
                    observed_at,
                    started,
                    None,
                    Some(ip_version_from_addr(address)),
                    Some(address.to_string()),
                    details,
                ),
            }
        }
        Err(error) => make_result(
            &check.id,
            "v2ray_simulation",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            v2ray_result_endpoint(check, None),
            details,
        ),
    }
}

fn perform_proxy_style_v2ray_request(
    check: &V2raySimulationCheck,
    observed_at: u64,
    started: Instant,
    mut details: BTreeMap<String, Value>,
    entry_type: LocalEntryType,
    success_message: String,
) -> CheckResult {
    let proxy_host = match check.proxy_host.as_deref() {
        Some(value) => value,
        None => {
            return make_result(
                &check.id,
                "v2ray_simulation",
                CheckStatus::Down,
                "proxy host is required for proxy-backed simulation".to_string(),
                observed_at,
                started,
                None,
                Some(check.ip_version),
                v2ray_result_endpoint(check, None),
                details,
            )
        }
    };
    let proxy_port = match check.proxy_port {
        Some(value) => value,
        None => {
            return make_result(
                &check.id,
                "v2ray_simulation",
                CheckStatus::Down,
                "proxy port is required for proxy-backed simulation".to_string(),
                observed_at,
                started,
                None,
                Some(check.ip_version),
                v2ray_result_endpoint(check, None),
                details,
            )
        }
    };
    let test_url = match check.test_url.as_deref() {
        Some(value) if !value.trim().is_empty() => value,
        _ => default_v2ray_probe_url(),
    };
    let missing_test_url = check
        .test_url
        .as_ref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true);
    if missing_test_url {
        details.insert(
            "default_test_url".to_string(),
            json!(default_v2ray_probe_url()),
        );
    }

    let configured_proxy_endpoint = format!("{proxy_host}:{proxy_port}");
    details.insert(
        "configured_proxy_endpoint".to_string(),
        json!(configured_proxy_endpoint.clone()),
    );

    let mut active_proxy_port = proxy_port;
    let mut active_proxy_endpoint = configured_proxy_endpoint.clone();
    details.insert("proxy_endpoint".to_string(), json!(active_proxy_endpoint.clone()));

    let mut active_proxy_address =
        match resolve_socket_addr(proxy_host, active_proxy_port, IpVersion::Any) {
            Ok(address) => {
                details.insert("proxy_resolved_address".to_string(), json!(address.to_string()));
                address
            }
            Err(error) => {
                return make_result(
                    &check.id,
                    "v2ray_simulation",
                    CheckStatus::Down,
                    proxy_resolution_error_message(
                        check,
                        entry_type,
                        &active_proxy_endpoint,
                        error,
                    ),
                    observed_at,
                    started,
                    None,
                    Some(check.ip_version),
                    Some(active_proxy_endpoint),
                    details,
                )
            }
        };

    let mut embedded_entry = None;
    if let Err(error) = connect_with_timeouts(active_proxy_address, check.timeout_ms) {
        details.insert("proxy_connect_error".to_string(), json!(error.clone()));
        if should_attempt_embedded_xray_entry(check, entry_type, proxy_host) {
            match spawn_embedded_xray_entry(
                check,
                entry_type,
                proxy_host,
                proxy_port,
                &mut details,
            ) {
                Ok((entry, actual_proxy_port)) => {
                    embedded_entry = Some(entry);
                    active_proxy_port = actual_proxy_port;
                    active_proxy_endpoint = format!("{proxy_host}:{active_proxy_port}");
                    details.insert("proxy_endpoint".to_string(), json!(active_proxy_endpoint.clone()));
                    details.insert(
                        "embedded_local_entry_port".to_string(),
                        json!(active_proxy_port),
                    );
                    active_proxy_address = match resolve_socket_addr(
                        proxy_host,
                        active_proxy_port,
                        IpVersion::Any,
                    ) {
                        Ok(address) => {
                            details.insert(
                                "proxy_resolved_address".to_string(),
                                json!(address.to_string()),
                            );
                            address
                        }
                        Err(error) => {
                            return make_result(
                                &check.id,
                                "v2ray_simulation",
                                CheckStatus::Down,
                                proxy_resolution_error_message(
                                    check,
                                    entry_type,
                                    &active_proxy_endpoint,
                                    error,
                                ),
                                observed_at,
                                started,
                                None,
                                Some(check.ip_version),
                                Some(active_proxy_endpoint),
                                details,
                            )
                        }
                    };
                    details.remove("proxy_connect_error");
                    if let Err(post_spawn_error) =
                        connect_with_timeouts(active_proxy_address, check.timeout_ms)
                    {
                        details.insert(
                            "proxy_connect_error".to_string(),
                            json!(post_spawn_error.clone()),
                        );
                        return make_result(
                            &check.id,
                            "v2ray_simulation",
                            CheckStatus::Down,
                            proxy_unreachable_message(
                                check,
                                entry_type,
                                &active_proxy_endpoint,
                                &post_spawn_error,
                            ),
                            observed_at,
                            started,
                            None,
                            Some(ip_version_from_addr(active_proxy_address)),
                            Some(active_proxy_address.to_string()),
                            details,
                        );
                    }
                }
                Err(spawn_error) => {
                    return make_result(
                        &check.id,
                        "v2ray_simulation",
                        CheckStatus::Down,
                        spawn_error,
                        observed_at,
                        started,
                        None,
                        Some(check.ip_version),
                        Some(active_proxy_endpoint),
                        details,
                    );
                }
            }
        } else {
            return make_result(
                &check.id,
                "v2ray_simulation",
                CheckStatus::Down,
                proxy_unreachable_message(check, entry_type, &active_proxy_endpoint, &error),
                observed_at,
                started,
                None,
                Some(ip_version_from_addr(active_proxy_address)),
                Some(active_proxy_address.to_string()),
                details,
            );
        }
    }

    let _embedded_entry_guard = embedded_entry;
    match perform_v2ray_curl_exchange(
        check,
        entry_type,
        proxy_host,
        active_proxy_port,
        test_url,
    ) {
        Ok(summary) => {
            details.insert("status_line".to_string(), json!(summary.status_line.clone()));
            details.insert("status_code".to_string(), json!(summary.status_code));
            details.insert(
                "body_preview".to_string(),
                json!(truncate(&summary.body_preview, 240)),
            );
            let expected_match = if check.expected_status.is_empty() {
                (200..=399).contains(&summary.status_code)
            } else {
                check.expected_status.contains(&summary.status_code)
            };

            if !expected_match {
                return make_result(
                    &check.id,
                    "v2ray_simulation",
                    CheckStatus::Down,
                    format!("unexpected proxy test status: {}", summary.status_code),
                    observed_at,
                    started,
                    None,
                    Some(check.ip_version),
                    v2ray_result_endpoint(check, Some(active_proxy_endpoint.clone())),
                    details,
                );
            }

            if let Some(needle) = &check.body_contains {
                if !summary.body_preview.contains(needle) {
                    return make_result(
                        &check.id,
                        "v2ray_simulation",
                        CheckStatus::Down,
                        format!("proxy test body did not contain expected text: {needle}"),
                        observed_at,
                        started,
                        None,
                        Some(check.ip_version),
                        v2ray_result_endpoint(check, Some(active_proxy_endpoint.clone())),
                        details,
                    );
                }
            }

            make_result(
                &check.id,
                "v2ray_simulation",
                CheckStatus::Up,
                success_message,
                observed_at,
                started,
                Some(elapsed_ms(started)),
                Some(check.ip_version),
                v2ray_result_endpoint(check, Some(active_proxy_endpoint.clone())),
                details,
            )
        }
        Err(error) => make_result(
            &check.id,
            "v2ray_simulation",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            v2ray_result_endpoint(check, Some(active_proxy_endpoint)),
            details,
        ),
    }
}

struct EmbeddedXrayEntry {
    child: Child,
    work_dir: PathBuf,
}

impl Drop for EmbeddedXrayEntry {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.work_dir);
    }
}

#[derive(Debug)]
struct EmbeddedXrayProfile {
    proxy_type: ProxyType,
    address: String,
    port: u16,
    user_id: Option<String>,
    password: Option<String>,
    method: Option<String>,
    alter_id: u16,
    user_security: Option<String>,
    network: String,
    stream_security: String,
    header_type: Option<String>,
    host: Option<String>,
    path: Option<String>,
    service_name: Option<String>,
    mode: Option<String>,
    flow: Option<String>,
    sni: Option<String>,
    alpn: Option<String>,
    fingerprint: Option<String>,
    reality_public_key: Option<String>,
    reality_short_id: Option<String>,
    reality_spider_x: Option<String>,
    plugin: Option<String>,
}

fn should_attempt_embedded_xray_entry(
    check: &V2raySimulationCheck,
    entry_type: LocalEntryType,
    proxy_host: &str,
) -> bool {
    if !matches!(entry_type, LocalEntryType::Socks5 | LocalEntryType::Http) {
        return false;
    }
    if check
        .profile_import
        .as_ref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        return false;
    }
    if !is_loopback_host(proxy_host) {
        return false;
    }

    matches!(
        check.proxy_type,
        ProxyType::Vmess | ProxyType::Vless | ProxyType::Trojan | ProxyType::Shadowsocks
    )
}

fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim().trim_matches(|char| char == '[' || char == ']');
    if trimmed.eq_ignore_ascii_case("localhost") {
        return true;
    }
    trimmed
        .parse::<IpAddr>()
        .map(|address| address.is_loopback())
        .unwrap_or(false)
}

fn spawn_embedded_xray_entry(
    check: &V2raySimulationCheck,
    entry_type: LocalEntryType,
    proxy_host: &str,
    proxy_port: u16,
    details: &mut BTreeMap<String, Value>,
) -> Result<(EmbeddedXrayEntry, u16), String> {
    let raw_profile = check
        .profile_import
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "embedded local Xray startup needs the original imported share link or config"
                .to_string()
        })?;
    let profile = parse_embedded_xray_profile(raw_profile)?;
    if profile.proxy_type != check.proxy_type {
        return Err(format!(
            "embedded local Xray profile type mismatch: monitor expects {}, but the saved profile is {}",
            check.proxy_type.as_str(),
            profile.proxy_type.as_str()
        ));
    }
    if matches!(entry_type, LocalEntryType::Https) {
        return Err(
            "embedded local Xray can provision SOCKS5 or HTTP entries, but not HTTPS proxy entries"
                .to_string(),
        );
    }
    if matches!(profile.proxy_type, ProxyType::Shadowsocks) && profile.plugin.is_some() {
        return Err(
            "embedded local Xray does not support Shadowsocks SIP003 plugins yet; use a plugin-free ss:// link or a manually managed local proxy entry"
                .to_string(),
        );
    }

    let binary_path = locate_xray_binary()?;
    let actual_remote_host = check
        .server_host
        .clone()
        .unwrap_or_else(|| profile.address.clone());
    let actual_remote_port = check.server_port.unwrap_or(profile.port);
    let profile_endpoint = format!("{actual_remote_host}:{actual_remote_port}");
    let mut attempted_ports = Vec::new();
    let mut last_error = None;

    for candidate_port in embedded_xray_port_candidates(proxy_port) {
        attempted_ports.push(candidate_port);
        match spawn_embedded_xray_entry_once(
            check,
            entry_type,
            proxy_host,
            candidate_port,
            &binary_path,
            &profile,
        ) {
            Ok(entry) => {
                details.insert("embedded_local_entry".to_string(), json!(true));
                details.insert(
                    "embedded_local_entry_mode".to_string(),
                    json!(entry_type.as_str()),
                );
                details.insert(
                    "embedded_local_entry_binary".to_string(),
                    json!(binary_path.to_string_lossy().to_string()),
                );
                details.insert(
                    "embedded_local_entry_profile".to_string(),
                    json!(profile.proxy_type.as_str()),
                );
                details.insert(
                    "embedded_remote_listener".to_string(),
                    json!(profile_endpoint),
                );
                details.insert(
                    "embedded_local_entry_requested_port".to_string(),
                    json!(proxy_port),
                );
                if candidate_port != proxy_port {
                    details.insert(
                        "embedded_local_entry_port_retry".to_string(),
                        json!(candidate_port),
                    );
                }
                return Ok((entry, candidate_port));
            }
            Err(error) => {
                let retryable = is_retryable_embedded_xray_bind_error(&error);
                last_error = Some(error);
                if !retryable {
                    break;
                }
            }
        }
    }

    let attempted_ports_text = attempted_ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let suffix = last_error.unwrap_or_else(|| "embedded local Xray failed to start".to_string());
    if attempted_ports.len() > 1 {
        Err(format!(
            "embedded local Xray failed across local ports {attempted_ports_text}: {suffix}"
        ))
    } else {
        Err(suffix)
    }
}

fn spawn_embedded_xray_entry_once(
    check: &V2raySimulationCheck,
    entry_type: LocalEntryType,
    proxy_host: &str,
    proxy_port: u16,
    binary_path: &Path,
    profile: &EmbeddedXrayProfile,
) -> Result<EmbeddedXrayEntry, String> {
    let work_dir = build_embedded_xray_work_dir(&check.id, proxy_port);
    fs::create_dir_all(&work_dir)
        .map_err(|error| format!("failed to create embedded xray work dir: {error}"))?;

    let config_value =
        build_embedded_xray_config(check, entry_type, proxy_host, proxy_port, &profile)?;
    let config_path = work_dir.join("config.json");
    let config_bytes = serde_json::to_vec_pretty(&config_value)
        .map_err(|error| format!("failed to serialize embedded xray config: {error}"))?;
    fs::write(&config_path, config_bytes)
        .map_err(|error| format!("failed to write embedded xray config: {error}"))?;

    let log_path = work_dir.join("xray.log");
    let stdout_log = fs::File::create(&log_path)
        .map_err(|error| format!("failed to create embedded xray log file: {error}"))?;
    let stderr_log = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_path)
        .map_err(|error| format!("failed to open embedded xray log file: {error}"))?;

    let child = Command::new(binary_path)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .current_dir(&work_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .spawn()
        .map_err(|error| format!("failed to launch embedded xray: {error}"))?;

    let mut entry = EmbeddedXrayEntry { child, work_dir };
    wait_for_embedded_xray_ready(&mut entry, proxy_host, proxy_port, check.timeout_ms, &log_path)?;

    Ok(entry)
}

fn embedded_xray_port_candidates(preferred_port: u16) -> Vec<u16> {
    let mut ports = Vec::with_capacity(8);
    ports.push(preferred_port);
    for offset in 1..=7 {
        if let Some(candidate) = preferred_port.checked_add(offset) {
            ports.push(candidate);
        }
    }
    ports
}

fn is_retryable_embedded_xray_bind_error(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("operation not permitted") || normalized.contains("permission denied") {
        return false;
    }
    normalized.contains("failed to listen")
        || normalized.contains("address already in use")
        || normalized.contains("bind:")
}

fn locate_xray_binary() -> Result<PathBuf, String> {
    let candidates = [
        "/var/www/.xui_bundle_v260/usr/local/x-ui/bin/xray-linux-amd64",
        "/usr/local/x-ui/bin/xray-linux-amd64",
        "/usr/bin/xray",
        "/usr/local/bin/xray",
    ];

    for candidate in candidates {
        let path = Path::new(candidate);
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
    }

    Err("could not find an Xray binary for embedded local-entry simulation".to_string())
}

fn build_embedded_xray_work_dir(check_id: &str, proxy_port: u16) -> PathBuf {
    let safe_id: String = check_id
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() || matches!(char, '-' | '_') {
                char
            } else {
                '-'
            }
        })
        .collect();
    std::env::temp_dir().join(format!(
        "iranmonitor-xray-{safe_id}-{proxy_port}-{}",
        unix_now_millis()
    ))
}

fn wait_for_embedded_xray_ready(
    entry: &mut EmbeddedXrayEntry,
    proxy_host: &str,
    proxy_port: u16,
    timeout_ms: u64,
    log_path: &Path,
) -> Result<(), String> {
    let address = resolve_socket_addr(proxy_host, proxy_port, IpVersion::Any).map_err(|error| {
        format!("embedded local Xray resolved an invalid proxy endpoint {proxy_host}:{proxy_port}: {error}")
    })?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1_500).min(6_000));
    loop {
        if connect_with_timeouts(address, 250).is_ok() {
            return Ok(());
        }

        if let Some(status) = entry
            .child
            .try_wait()
            .map_err(|error| format!("failed to inspect embedded xray process: {error}"))?
        {
            let log_tail = read_embedded_xray_log(log_path);
            let suffix = if log_tail.is_empty() {
                String::new()
            } else {
                format!(" | log: {log_tail}")
            };
            return Err(format!(
                "embedded local Xray exited before the proxy became ready (status: {status}){suffix}"
            ));
        }

        if Instant::now() >= deadline {
            let log_tail = read_embedded_xray_log(log_path);
            let suffix = if log_tail.is_empty() {
                String::new()
            } else {
                format!(" | log: {log_tail}")
            };
            return Err(format!(
                "embedded local Xray did not become ready on {proxy_host}:{proxy_port}{suffix}"
            ));
        }

        thread::sleep(Duration::from_millis(100));
    }
}

fn read_embedded_xray_log(path: &Path) -> String {
    fs::read_to_string(path)
        .map(|content| summarize_embedded_xray_log(&content))
        .unwrap_or_default()
}

fn summarize_embedded_xray_log(content: &str) -> String {
    let tail_lines = content
        .lines()
        .rev()
        .filter(|line| !line.trim().is_empty())
        .take(12)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    truncate(tail_lines.trim(), 1_200)
}

fn build_embedded_xray_config(
    check: &V2raySimulationCheck,
    entry_type: LocalEntryType,
    proxy_host: &str,
    proxy_port: u16,
    profile: &EmbeddedXrayProfile,
) -> Result<Value, String> {
    let remote_host = check
        .server_host
        .clone()
        .unwrap_or_else(|| profile.address.clone());
    let remote_port = check.server_port.unwrap_or(profile.port);
    let remote_server_name = first_non_empty(&[
        check.server_name.clone(),
        profile.sni.clone(),
        profile.host.clone(),
    ]);

    let inbound_protocol = match entry_type {
        LocalEntryType::Socks5 => "socks",
        LocalEntryType::Http => "http",
        LocalEntryType::Https => {
            return Err(
                "embedded local Xray does not provide an HTTPS proxy listener".to_string(),
            )
        }
        LocalEntryType::Direct => {
            return Err("embedded local Xray is only used for proxy-backed simulations".to_string())
        }
    };
    let inbound_settings = match entry_type {
        LocalEntryType::Socks5 => json!({
            "auth": "noauth",
            "udp": false,
        }),
        LocalEntryType::Http => json!({}),
        LocalEntryType::Https | LocalEntryType::Direct => json!({}),
    };

    let outbound_settings = match profile.proxy_type {
        ProxyType::Vmess => json!({
            "vnext": [{
                "address": remote_host,
                "port": remote_port,
                "users": [{
                    "id": required_profile_field(&profile.user_id, "vmess id")?,
                    "alterId": profile.alter_id,
                    "security": profile
                        .user_security
                        .clone()
                        .unwrap_or_else(|| "auto".to_string()),
                }]
            }]
        }),
        ProxyType::Vless => {
            let mut user = serde_json::Map::new();
            user.insert(
                "id".to_string(),
                json!(required_profile_field(&profile.user_id, "vless id")?),
            );
            user.insert(
                "encryption".to_string(),
                json!(
                    profile
                        .user_security
                        .clone()
                        .unwrap_or_else(|| "none".to_string())
                ),
            );
            if let Some(flow) = profile.flow.as_deref().filter(|value| !value.trim().is_empty()) {
                user.insert("flow".to_string(), json!(flow.trim()));
            }
            json!({
                "vnext": [{
                    "address": remote_host,
                    "port": remote_port,
                    "users": [Value::Object(user)]
                }]
            })
        }
        ProxyType::Trojan => json!({
            "servers": [{
                "address": remote_host,
                "port": remote_port,
                "password": required_profile_field(&profile.password, "trojan password")?,
            }]
        }),
        ProxyType::Shadowsocks => json!({
            "servers": [{
                "address": remote_host,
                "port": remote_port,
                "method": required_profile_field(&profile.method, "shadowsocks method")?,
                "password": required_profile_field(&profile.password, "shadowsocks password")?,
            }]
        }),
        _ => {
            return Err(format!(
                "embedded local Xray does not support {} profiles",
                profile.proxy_type.as_str()
            ))
        }
    };

    let stream_settings = build_embedded_stream_settings(profile, remote_server_name)?;
    Ok(json!({
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [{
            "tag": "local-in",
            "listen": proxy_host,
            "port": proxy_port,
            "protocol": inbound_protocol,
            "settings": inbound_settings,
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        }],
        "outbounds": [{
            "tag": "proxy-out",
            "protocol": profile.proxy_type.as_str(),
            "settings": outbound_settings,
            "streamSettings": stream_settings
        }],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{
                "type": "field",
                "inboundTag": ["local-in"],
                "outboundTag": "proxy-out"
            }]
        }
    }))
}

fn build_embedded_stream_settings(
    profile: &EmbeddedXrayProfile,
    remote_server_name: Option<String>,
) -> Result<Value, String> {
    let network = normalize_stream_network(&profile.network);
    let security = normalize_stream_security(&profile.stream_security);
    let mut settings = serde_json::Map::new();
    settings.insert("network".to_string(), json!(network));
    settings.insert("security".to_string(), json!(security));

    match network.as_str() {
        "tcp" => {
            let header_type = profile
                .header_type
                .clone()
                .unwrap_or_else(|| "none".to_string());
            let mut tcp_settings = serde_json::Map::new();
            let mut header = serde_json::Map::new();
            header.insert("type".to_string(), json!(header_type.clone()));
            if header_type.eq_ignore_ascii_case("http") {
                let hosts = split_csv_like(profile.host.as_deref().unwrap_or(""));
                let paths = split_csv_like(profile.path.as_deref().unwrap_or(""));
                if !hosts.is_empty() || !paths.is_empty() {
                    header.insert(
                        "request".to_string(),
                        json!({
                            "path": paths,
                            "headers": {
                                "Host": hosts
                            }
                        }),
                    );
                }
            }
            tcp_settings.insert("header".to_string(), Value::Object(header));
            settings.insert("tcpSettings".to_string(), Value::Object(tcp_settings));
        }
        "ws" => {
            let mut ws_settings = serde_json::Map::new();
            ws_settings.insert(
                "path".to_string(),
                json!(profile.path.clone().unwrap_or_else(|| "/".to_string())),
            );
            if let Some(host) = profile.host.as_deref().filter(|value| !value.trim().is_empty()) {
                ws_settings.insert(
                    "headers".to_string(),
                    json!({
                        "Host": host.trim()
                    }),
                );
            }
            settings.insert("wsSettings".to_string(), Value::Object(ws_settings));
        }
        "grpc" => {
            let mut grpc_settings = serde_json::Map::new();
            grpc_settings.insert(
                "serviceName".to_string(),
                json!(profile.service_name.clone().or(profile.path.clone()).unwrap_or_default()),
            );
            if let Some(authority) =
                profile.host.as_deref().filter(|value| !value.trim().is_empty())
            {
                grpc_settings.insert("authority".to_string(), json!(authority.trim()));
            }
            if let Some(mode) = profile.mode.as_deref() {
                grpc_settings.insert(
                    "multiMode".to_string(),
                    json!(mode.eq_ignore_ascii_case("multi")),
                );
            }
            settings.insert("grpcSettings".to_string(), Value::Object(grpc_settings));
        }
        "httpupgrade" => {
            let mut upgrade_settings = serde_json::Map::new();
            if let Some(host) = profile.host.as_deref().filter(|value| !value.trim().is_empty()) {
                upgrade_settings.insert("host".to_string(), json!(host.trim()));
            }
            if let Some(path) = profile.path.as_deref().filter(|value| !value.trim().is_empty()) {
                upgrade_settings.insert("path".to_string(), json!(path.trim()));
            }
            settings.insert(
                "httpupgradeSettings".to_string(),
                Value::Object(upgrade_settings),
            );
        }
        unsupported => {
            return Err(format!(
                "embedded local Xray does not support the imported transport network {unsupported}"
            ))
        }
    }

    match security.as_str() {
        "none" => {}
        "tls" => {
            let mut tls_settings = serde_json::Map::new();
            if let Some(server_name) = remote_server_name.as_deref().filter(|value| !value.trim().is_empty()) {
                tls_settings.insert("serverName".to_string(), json!(server_name.trim()));
            }
            if let Some(alpn) = profile.alpn.as_deref() {
                let values = split_csv_like(alpn);
                if !values.is_empty() {
                    tls_settings.insert("alpn".to_string(), json!(values));
                }
            }
            if let Some(fingerprint) =
                profile.fingerprint.as_deref().filter(|value| !value.trim().is_empty())
            {
                tls_settings.insert("fingerprint".to_string(), json!(fingerprint.trim()));
            }
            settings.insert("tlsSettings".to_string(), Value::Object(tls_settings));
        }
        "reality" => {
            let mut reality_settings = serde_json::Map::new();
            if let Some(server_name) =
                remote_server_name.as_deref().filter(|value| !value.trim().is_empty())
            {
                reality_settings.insert("serverName".to_string(), json!(server_name.trim()));
            }
            if let Some(fingerprint) =
                profile.fingerprint.as_deref().filter(|value| !value.trim().is_empty())
            {
                reality_settings.insert("fingerprint".to_string(), json!(fingerprint.trim()));
            }
            if let Some(public_key) = profile
                .reality_public_key
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                reality_settings.insert("publicKey".to_string(), json!(public_key.trim()));
            }
            if let Some(short_id) = profile
                .reality_short_id
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                reality_settings.insert("shortId".to_string(), json!(short_id.trim()));
            }
            if let Some(spider_x) = profile
                .reality_spider_x
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                reality_settings.insert("spiderX".to_string(), json!(spider_x.trim()));
            }
            settings.insert("realitySettings".to_string(), Value::Object(reality_settings));
        }
        unsupported => {
            return Err(format!(
                "embedded local Xray does not support imported stream security {unsupported}"
            ))
        }
    }

    Ok(Value::Object(settings))
}

fn normalize_stream_network(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => "tcp".to_string(),
        "splithttp" | "split_http" | "xhttp" => "httpupgrade".to_string(),
        other => other.to_string(),
    }
}

fn normalize_stream_security(raw: &str) -> String {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        "none".to_string()
    } else {
        normalized
    }
}

fn required_profile_field(value: &Option<String>, label: &str) -> Result<String, String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("embedded local Xray profile is missing {label}"))
}

fn split_csv_like(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_embedded_xray_profile(raw: &str) -> Result<EmbeddedXrayProfile, String> {
    let trimmed = raw.trim();
    if trimmed.starts_with("vmess://") {
        return parse_embedded_vmess_profile(trimmed);
    }
    if trimmed.starts_with("vless://") {
        return parse_embedded_uri_profile(trimmed, ProxyType::Vless);
    }
    if trimmed.starts_with("trojan://") {
        return parse_embedded_uri_profile(trimmed, ProxyType::Trojan);
    }
    if trimmed.starts_with("ss://") {
        return parse_embedded_shadowsocks_profile(trimmed);
    }

    Err("embedded local Xray currently supports vmess://, vless://, trojan://, and ss:// imports".to_string())
}

fn parse_embedded_vmess_profile(raw: &str) -> Result<EmbeddedXrayProfile, String> {
    let payload = raw
        .trim()
        .strip_prefix("vmess://")
        .ok_or_else(|| "vmess import must start with vmess://".to_string())?;
    let decoded = decode_base64_lenient(payload)?;
    let decoded_text = String::from_utf8(decoded)
        .map_err(|error| format!("vmess import was not valid utf-8: {error}"))?;
    let json: Value = serde_json::from_str(&decoded_text)
        .map_err(|error| format!("failed to parse vmess json payload: {error}"))?;

    let address = json_string_value(&json, &["add", "address", "host"])
        .ok_or_else(|| "vmess import did not contain an address".to_string())?;
    let port = json_u16_value(&json, &["port"])
        .ok_or_else(|| "vmess import did not contain a valid port".to_string())?;
    let user_id = json_string_value(&json, &["id"])
        .ok_or_else(|| "vmess import did not contain a uuid".to_string())?;
    let network = json_string_value(&json, &["net"]).unwrap_or_else(|| "tcp".to_string());
    let mut stream_security =
        json_string_value(&json, &["tls"]).unwrap_or_else(|| "none".to_string());
    if stream_security.trim().is_empty() {
        stream_security = "none".to_string();
    }
    let host = json_string_value(&json, &["host"]);
    let sni = first_non_empty(&[json_string_value(&json, &["sni"]), host.clone()]);
    let path = json_string_value(&json, &["path"]);
    let service_name = if network.eq_ignore_ascii_case("grpc") {
        json_string_value(&json, &["serviceName"]).or(path.clone())
    } else {
        json_string_value(&json, &["serviceName"])
    };

    Ok(EmbeddedXrayProfile {
        proxy_type: ProxyType::Vmess,
        address,
        port,
        user_id: Some(user_id),
        password: None,
        method: None,
        alter_id: json_u16_value(&json, &["aid", "alterId"]).unwrap_or(0),
        user_security: Some(
            json_string_value(&json, &["scy"]).unwrap_or_else(|| "auto".to_string()),
        ),
        network,
        stream_security,
        header_type: json_string_value(&json, &["type"]),
        host,
        path,
        service_name,
        mode: json_string_value(&json, &["mode"]),
        flow: None,
        sni,
        alpn: json_string_value(&json, &["alpn"]),
        fingerprint: json_string_value(&json, &["fp"]),
        reality_public_key: json_string_value(&json, &["pbk"]),
        reality_short_id: json_string_value(&json, &["sid"]),
        reality_spider_x: json_string_value(&json, &["spx"]),
        plugin: None,
    })
}

fn parse_embedded_uri_profile(
    raw: &str,
    proxy_type: ProxyType,
) -> Result<EmbeddedXrayProfile, String> {
    let (scheme, remainder) = raw
        .split_once("://")
        .ok_or_else(|| "import uri must contain a scheme".to_string())?;
    let (body_without_fragment, _fragment) = split_once_or_self(remainder, '#');
    let (authority, query_text) = split_once_or_self(body_without_fragment, '?');
    let (userinfo, host_port) = authority
        .rsplit_once('@')
        .ok_or_else(|| format!("{scheme} import must contain user@host:port"))?;
    let (address, port) = parse_host_port_text(host_port)?;
    let query = parse_url_query_text(query_text.unwrap_or(""));
    let host = query.get("host").cloned();
    let network = query
        .get("type")
        .cloned()
        .unwrap_or_else(|| "tcp".to_string());
    let mut stream_security = query
        .get("security")
        .cloned()
        .unwrap_or_else(|| match proxy_type {
            ProxyType::Trojan => "tls".to_string(),
            _ => "none".to_string(),
        });
    if stream_security.trim().is_empty() {
        stream_security = "none".to_string();
    }

    Ok(EmbeddedXrayProfile {
        proxy_type,
        address,
        port,
        user_id: match proxy_type {
            ProxyType::Vless => Some(http::url_decode(userinfo)),
            _ => None,
        },
        password: match proxy_type {
            ProxyType::Trojan => Some(http::url_decode(userinfo)),
            _ => None,
        },
        method: None,
        alter_id: 0,
        user_security: query
            .get("encryption")
            .cloned()
            .or_else(|| match proxy_type {
                ProxyType::Vless => Some("none".to_string()),
                _ => None,
            }),
        network,
        stream_security,
        header_type: query.get("headerType").cloned(),
        host: host.clone(),
        path: query.get("path").cloned(),
        service_name: query.get("serviceName").cloned(),
        mode: query.get("mode").cloned(),
        flow: query.get("flow").cloned(),
        sni: first_non_empty(&[
            query.get("sni").cloned(),
            query.get("servername").cloned(),
            query.get("peer").cloned(),
            host,
        ]),
        alpn: query.get("alpn").cloned(),
        fingerprint: first_non_empty(&[
            query.get("fp").cloned(),
            query.get("fingerprint").cloned(),
        ]),
        reality_public_key: query.get("pbk").cloned(),
        reality_short_id: query.get("sid").cloned(),
        reality_spider_x: query.get("spx").cloned(),
        plugin: None,
    })
}

fn parse_embedded_shadowsocks_profile(raw: &str) -> Result<EmbeddedXrayProfile, String> {
    let payload = raw
        .trim()
        .strip_prefix("ss://")
        .ok_or_else(|| "shadowsocks import must start with ss://".to_string())?;
    let (body_without_fragment, _fragment) = split_once_or_self(payload, '#');
    let (body, query_text) = split_once_or_self(body_without_fragment, '?');

    let decoded_body = if body.contains('@') {
        let (left, right) = body
            .rsplit_once('@')
            .ok_or_else(|| "invalid shadowsocks authority".to_string())?;
        if left.contains(':') {
            format!("{left}@{right}")
        } else {
            let decoded_left = decode_base64_text_local(left, "shadowsocks credentials")?;
            format!("{decoded_left}@{right}")
        }
    } else {
        decode_base64_text_local(body, "shadowsocks body")?
    };

    let (credentials, host_port) = decoded_body
        .rsplit_once('@')
        .ok_or_else(|| "shadowsocks import must contain method:password@host:port".to_string())?;
    let (method, password) = credentials
        .split_once(':')
        .ok_or_else(|| "shadowsocks credentials must look like method:password".to_string())?;
    let (address, port) = parse_host_port_text(host_port)?;
    let query = parse_url_query_text(query_text.unwrap_or(""));

    Ok(EmbeddedXrayProfile {
        proxy_type: ProxyType::Shadowsocks,
        address,
        port,
        user_id: None,
        password: Some(password.to_string()),
        method: Some(method.to_string()),
        alter_id: 0,
        user_security: None,
        network: "tcp".to_string(),
        stream_security: "none".to_string(),
        header_type: None,
        host: None,
        path: None,
        service_name: None,
        mode: None,
        flow: None,
        sni: None,
        alpn: None,
        fingerprint: None,
        reality_public_key: None,
        reality_short_id: None,
        reality_spider_x: None,
        plugin: query.get("plugin").cloned(),
    })
}

fn decode_base64_text_local(raw: &str, label: &str) -> Result<String, String> {
    let decoded = decode_base64_lenient(raw)?;
    String::from_utf8(decoded).map_err(|error| format!("{label} was not valid utf-8: {error}"))
}

fn parse_host_port_text(raw: &str) -> Result<(String, u16), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("host:port value was empty".to_string());
    }

    if trimmed.starts_with('[') {
        let closing = trimmed
            .find(']')
            .ok_or_else(|| format!("invalid bracketed host: {trimmed}"))?;
        let host = trimmed[1..closing].trim();
        let port_text = trimmed[closing + 1..]
            .strip_prefix(':')
            .ok_or_else(|| format!("missing port after {trimmed}"))?;
        let port = port_text
            .trim()
            .parse::<u16>()
            .map_err(|error| format!("invalid port in {trimmed}: {error}"))?;
        if host.is_empty() || port == 0 {
            return Err(format!("invalid host:port value: {trimmed}"));
        }
        return Ok((host.to_string(), port));
    }

    let (host, port_text) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| format!("missing port in {trimmed}"))?;
    let port = port_text
        .trim()
        .parse::<u16>()
        .map_err(|error| format!("invalid port in {trimmed}: {error}"))?;
    let host = host.trim();
    if host.is_empty() || port == 0 {
        Err(format!("invalid host:port value: {trimmed}"))
    } else {
        Ok((host.to_string(), port))
    }
}

fn parse_url_query_text(input: &str) -> BTreeMap<String, String> {
    let mut output = BTreeMap::new();
    for pair in input.split('&') {
        let trimmed = pair.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (name, value) = trimmed.split_once('=').unwrap_or((trimmed, ""));
        output.insert(http::url_decode(name), http::url_decode(value));
    }
    output
}

fn split_once_or_self(input: &str, delimiter: char) -> (&str, Option<&str>) {
    if let Some((left, right)) = input.split_once(delimiter) {
        (left, Some(right))
    } else {
        (input, None)
    }
}

fn json_string_value(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(found) = value.get(*key) {
            if let Some(string) = found.as_str() {
                let trimmed = string.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            } else if found.is_number() {
                return Some(found.to_string());
            }
        }
    }
    None
}

fn json_u16_value(value: &Value, keys: &[&str]) -> Option<u16> {
    for key in keys {
        if let Some(found) = value.get(*key) {
            if let Some(number) = found.as_u64() {
                if let Ok(port) = u16::try_from(number) {
                    if port > 0 {
                        return Some(port);
                    }
                }
            }
            if let Some(string) = found.as_str() {
                if let Ok(port) = string.trim().parse::<u16>() {
                    if port > 0 {
                        return Some(port);
                    }
                }
            }
        }
    }
    None
}

fn first_non_empty(values: &[Option<String>]) -> Option<String> {
    values
        .iter()
        .filter_map(|value| value.as_deref())
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

fn run_wireguard_v2ray_simulation(
    check: &V2raySimulationCheck,
    observed_at: u64,
    started: Instant,
    mut details: BTreeMap<String, Value>,
) -> CheckResult {
    let mut endpoint = v2ray_result_endpoint(check, None);
    let interface = check.wireguard_interface.as_deref();

    if interface.is_none() && check.inner_probe.is_none() {
        if check.server_host.is_some() && check.server_port.is_some() {
            return run_wireguard_endpoint_probe(check, observed_at, started, details);
        }
    }

    if let Some(interface) = interface {
        endpoint = Some(interface.to_string());
        let interface_path = Path::new("/sys/class/net").join(interface);
        if !interface_path.exists() {
            return make_result(
                &check.id,
                "v2ray_simulation",
                CheckStatus::Down,
                format!("WireGuard interface not found: {interface}"),
                observed_at,
                started,
                None,
                Some(check.ip_version),
                endpoint,
                details,
            );
        }

        match read_trimmed(interface_path.join("operstate")) {
            Ok(operstate) => {
                details.insert("operstate".to_string(), json!(operstate.clone()));
                if operstate.eq_ignore_ascii_case("down") {
                    return make_result(
                        &check.id,
                        "v2ray_simulation",
                        CheckStatus::Down,
                        format!("WireGuard interface {interface} is down"),
                        observed_at,
                        started,
                        None,
                        Some(check.ip_version),
                        endpoint,
                        details,
                    );
                }
            }
            Err(error) => {
                return make_result(
                    &check.id,
                    "v2ray_simulation",
                    CheckStatus::Down,
                    format!("failed to read WireGuard interface operstate: {error}"),
                    observed_at,
                    started,
                    None,
                    Some(check.ip_version),
                    endpoint,
                    details,
                )
            }
        }

        if let Ok(counters) = read_interface_counters(interface) {
            details.insert("rx_packets".to_string(), json!(counters.rx_packets));
            details.insert("tx_packets".to_string(), json!(counters.tx_packets));
            details.insert("rx_bytes".to_string(), json!(counters.rx_bytes));
            details.insert("tx_bytes".to_string(), json!(counters.tx_bytes));
        }
    }

    if interface.is_some()
        && (check.max_handshake_age_secs.is_some() || check.wireguard_peer.is_some())
    {
        match inspect_wireguard_peer(check) {
            Ok(peer) => {
                details.insert("selected_peer".to_string(), json!(peer.peer_id.clone()));
                if let Some(endpoint_value) = &peer.endpoint {
                    details.insert("peer_endpoint".to_string(), json!(endpoint_value));
                }
                if let Some(handshake_unix) = peer.latest_handshake_unix {
                    details.insert(
                        "latest_handshake_unix".to_string(),
                        json!(handshake_unix),
                    );
                    let handshake_age_secs = unix_now().saturating_sub(handshake_unix);
                    details.insert(
                        "handshake_age_secs".to_string(),
                        json!(handshake_age_secs),
                    );
                    if let Some(max_age) = check.max_handshake_age_secs {
                        if handshake_age_secs > max_age {
                            return make_result(
                                &check.id,
                                "v2ray_simulation",
                                CheckStatus::Down,
                                format!(
                                    "WireGuard handshake is older than {} seconds",
                                    max_age
                                ),
                                observed_at,
                                started,
                                None,
                                Some(check.ip_version),
                                endpoint,
                                details,
                            );
                        }
                    }
                } else if check.max_handshake_age_secs.is_some() {
                    return make_result(
                        &check.id,
                        "v2ray_simulation",
                        CheckStatus::Down,
                        "matching WireGuard peer has no recorded handshake yet".to_string(),
                        observed_at,
                        started,
                        None,
                        Some(check.ip_version),
                        endpoint,
                        details,
                    );
                }
            }
            Err(error) => {
                return make_result(
                    &check.id,
                    "v2ray_simulation",
                    CheckStatus::Down,
                    error,
                    observed_at,
                    started,
                    None,
                    Some(check.ip_version),
                    endpoint,
                    details,
                )
            }
        }
    }

    if let Some(inner_probe) = &check.inner_probe {
        endpoint = Some(inner_probe.clone());
        match run_ping(
            inner_probe,
            check.ip_version,
            check.timeout_ms,
            check.source_interface
                .as_deref()
                .or(check.wireguard_interface.as_deref()),
        ) {
            Ok(outcome) => {
                if let Some(latency_ms) = outcome.latency_ms {
                    details.insert("inner_probe_rtt_ms".to_string(), json!(latency_ms));
                }
                details.insert("inner_probe_output".to_string(), json!(outcome.summary));
                return make_result(
                    &check.id,
                    "v2ray_simulation",
                    CheckStatus::Up,
                    "WireGuard inner probe succeeded",
                    observed_at,
                    started,
                    outcome.latency_ms.or(Some(elapsed_ms(started))),
                    Some(check.ip_version),
                    endpoint,
                    details,
                );
            }
            Err(error) => {
                return make_result(
                    &check.id,
                    "v2ray_simulation",
                    CheckStatus::Down,
                    format!("WireGuard inner probe failed: {error}"),
                    observed_at,
                    started,
                    None,
                    Some(check.ip_version),
                    endpoint,
                    details,
                )
            }
        }
    }

    make_result(
        &check.id,
        "v2ray_simulation",
        CheckStatus::Up,
        "WireGuard interface and peer state look healthy",
        observed_at,
        started,
        Some(elapsed_ms(started)),
        Some(check.ip_version),
        endpoint,
        details,
    )
}

fn run_wireguard_endpoint_probe(
    check: &V2raySimulationCheck,
    observed_at: u64,
    started: Instant,
    mut details: BTreeMap<String, Value>,
) -> CheckResult {
    let server_host = match check.server_host.as_deref() {
        Some(value) => value,
        None => {
            return make_result(
                &check.id,
                "v2ray_simulation",
                CheckStatus::Down,
                "WireGuard endpoint host is missing".to_string(),
                observed_at,
                started,
                None,
                Some(check.ip_version),
                v2ray_result_endpoint(check, None),
                details,
            )
        }
    };
    let server_port = match check.server_port {
        Some(value) => value,
        None => {
            return make_result(
                &check.id,
                "v2ray_simulation",
                CheckStatus::Down,
                "WireGuard endpoint port is missing".to_string(),
                observed_at,
                started,
                None,
                Some(check.ip_version),
                v2ray_result_endpoint(check, None),
                details,
            )
        }
    };

    match resolve_socket_addr(server_host, server_port, check.ip_version) {
        Ok(address) => {
            details.insert("resolved_address".to_string(), json!(address.to_string()));
            let bind_address = match address {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            };

            match UdpSocket::bind(bind_address) {
                Ok(socket) => {
                    if let Err(error) = socket.set_write_timeout(Some(timeout_duration(check.timeout_ms)))
                    {
                        return make_result(
                            &check.id,
                            "v2ray_simulation",
                            CheckStatus::Down,
                            format!("failed to set WireGuard UDP timeout: {error}"),
                            observed_at,
                            started,
                            None,
                            Some(ip_version_from_addr(address)),
                            Some(address.to_string()),
                            details,
                        );
                    }
                    if let Err(error) = socket.connect(address) {
                        return make_result(
                            &check.id,
                            "v2ray_simulation",
                            CheckStatus::Down,
                            format!("WireGuard endpoint connect failed: {error}"),
                            observed_at,
                            started,
                            None,
                            Some(ip_version_from_addr(address)),
                            Some(address.to_string()),
                            details,
                        );
                    }
                    match socket.send(b"iranmonitor-wireguard-probe") {
                        Ok(bytes_sent) => {
                            details.insert("bytes_sent".to_string(), json!(bytes_sent));
                            match run_ping(
                                server_host,
                                check.ip_version,
                                check.timeout_ms,
                                check.source_interface.as_deref(),
                            ) {
                                Ok(outcome) => {
                                    if let Some(latency_ms) = outcome.latency_ms {
                                        details.insert("outer_probe_rtt_ms".to_string(), json!(latency_ms));
                                    }
                                    details.insert("outer_probe_output".to_string(), json!(outcome.summary));
                                    make_result(
                                        &check.id,
                                        "v2ray_simulation",
                                        CheckStatus::Degraded,
                                        "Host ping succeeded; WireGuard handshake is unverified. Add a WireGuard interface or inner tunnel probe",
                                        observed_at,
                                        started,
                                        Some(elapsed_ms(started)),
                                        Some(ip_version_from_addr(address)),
                                        Some(address.to_string()),
                                        details,
                                    )
                                }
                                Err(error) => {
                                    details.insert("outer_probe_error".to_string(), json!(error.clone()));
                                    make_result(
                                        &check.id,
                                        "v2ray_simulation",
                                        CheckStatus::Degraded,
                                        "WireGuard UDP endpoint probe was sent; add an interface or inner probe for deeper validation"
                                            .to_string(),
                                        observed_at,
                                        started,
                                        Some(elapsed_ms(started)),
                                        Some(ip_version_from_addr(address)),
                                        Some(address.to_string()),
                                        details,
                                    )
                                }
                            }
                        }
                        Err(error) => make_result(
                            &check.id,
                            "v2ray_simulation",
                            CheckStatus::Down,
                            format!("WireGuard UDP probe send failed: {error}"),
                            observed_at,
                            started,
                            None,
                            Some(ip_version_from_addr(address)),
                            Some(address.to_string()),
                            details,
                        ),
                    }
                }
                Err(error) => make_result(
                    &check.id,
                    "v2ray_simulation",
                    CheckStatus::Down,
                    format!("failed to bind UDP socket for WireGuard probe: {error}"),
                    observed_at,
                    started,
                    None,
                    Some(ip_version_from_addr(address)),
                    Some(address.to_string()),
                    details,
                ),
            }
        }
        Err(error) => make_result(
            &check.id,
            "v2ray_simulation",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            v2ray_result_endpoint(check, None),
            details,
        ),
    }
}

fn native_proxy_entry_type(proxy_type: ProxyType) -> LocalEntryType {
    match proxy_type {
        ProxyType::Http => LocalEntryType::Http,
        ProxyType::Https => LocalEntryType::Https,
        _ => LocalEntryType::Socks5,
    }
}

fn has_local_proxy_entry(check: &V2raySimulationCheck) -> bool {
    !matches!(check.local_entry_type, LocalEntryType::Direct)
        && check.proxy_host.is_some()
        && check.proxy_port.is_some()
}

fn default_v2ray_probe_url() -> &'static str {
    "https://www.google.com/generate_204"
}

fn proxy_resolution_error_message(
    check: &V2raySimulationCheck,
    entry_type: LocalEntryType,
    proxy_endpoint: &str,
    error: String,
) -> String {
    match check.proxy_type {
        ProxyType::Socks5 | ProxyType::Http | ProxyType::Https => {
            format!(
                "{} proxy host could not be resolved at {proxy_endpoint}: {error}",
                check.proxy_type.as_str()
            )
        }
        _ => format!(
            "local {} entry host could not be resolved at {proxy_endpoint}: {error}. Keep Direct listener only if you only want a listener reachability check, or point this monitor at the real local Xray/V2Ray/Sing-box entry.",
            entry_type.as_str()
        ),
    }
}

fn proxy_unreachable_message(
    check: &V2raySimulationCheck,
    entry_type: LocalEntryType,
    proxy_endpoint: &str,
    error: &str,
) -> String {
    match check.proxy_type {
        ProxyType::Socks5 | ProxyType::Http | ProxyType::Https => format!(
            "{} proxy is not reachable at {proxy_endpoint}: {error}",
            check.proxy_type.as_str()
        ),
        _ => format!(
            "local {} entry is not reachable at {proxy_endpoint}: {error}. Start the local Xray/V2Ray/Sing-box client on this server, update the local entry host and port, or switch Local Entry Type to Direct listener only if you only want a listener reachability check.",
            entry_type.as_str()
        ),
    }
}

fn v2ray_result_endpoint(
    check: &V2raySimulationCheck,
    fallback: Option<String>,
) -> Option<String> {
    if let (Some(host), Some(port)) = (&check.server_host, check.server_port) {
        return Some(format!("{host}:{port}"));
    }
    if let Some(interface) = &check.wireguard_interface {
        return Some(interface.clone());
    }
    if let Some(inner_probe) = &check.inner_probe {
        return Some(inner_probe.clone());
    }
    if let (Some(host), Some(port)) = (&check.proxy_host, check.proxy_port) {
        return Some(format!("{host}:{port}"));
    }
    fallback
}

fn run_interface_tunnel(
    check: &TunnelCheck,
    state: &Arc<Mutex<PersistedState>>,
    observed_at: u64,
    started: Instant,
    mut details: BTreeMap<String, Value>,
) -> CheckResult {
    let interface = match populate_tunnel_details(check, &mut details) {
        Ok(interface) => interface,
        Err(error) => {
            return make_result(
                &check.id,
                "tunnel",
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(check.ip_version),
                None,
                details,
            )
        }
    };
    if let Err(error) = ensure_managed_tunnel_interface(check, &mut details) {
        return make_result(
            &check.id,
            "tunnel",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
                Some(check.ip_version),
                None,
                details,
            );
    }
    evaluate_tunnel_interface(check, &interface, state, observed_at, started, details)
}

fn populate_tunnel_details(
    check: &TunnelCheck,
    details: &mut BTreeMap<String, Value>,
) -> Result<String, String> {
    let interface = check
        .interface
        .as_deref()
        .ok_or_else(|| "interface-based tunnel checks need an interface name".to_string())?
        .to_string();
    details.insert("interface".to_string(), json!(interface.clone()));
    details.insert(
        "auto_create_interface".to_string(),
        json!(check.auto_create_interface),
    );
    if let Some(outer_remote) = &check.outer_remote {
        details.insert("outer_remote".to_string(), json!(outer_remote));
    }
    if let Some(local_outer) = &check.local_outer {
        details.insert("local_outer".to_string(), json!(local_outer));
    }
    if let Some(source_interface) = &check.source_interface {
        details.insert("source_interface".to_string(), json!(source_interface));
    }
    if let Some(inner_local_cidr) = &check.inner_local_cidr {
        details.insert("inner_local_cidr".to_string(), json!(inner_local_cidr));
    }
    details.insert("shared_key_configured".to_string(), json!(check.tunnel_key.is_some()));
    if let Some(tun_transport) = &check.tun_transport {
        details.insert("tun_transport".to_string(), json!(tun_transport));
    }
    if let Some(transport_port) = check.transport_port {
        details.insert("transport_port".to_string(), json!(transport_port));
    }
    if let Some(listen_port) = check.listen_port {
        details.insert("listen_port".to_string(), json!(listen_port));
    }
    if let Some(username) = &check.ssh_username {
        details.insert("ssh_username".to_string(), json!(username));
    }
    Ok(interface)
}

fn evaluate_tunnel_interface(
    check: &TunnelCheck,
    interface: &str,
    state: &Arc<Mutex<PersistedState>>,
    observed_at: u64,
    started: Instant,
    mut details: BTreeMap<String, Value>,
) -> CheckResult {
    let interface_path = Path::new("/sys/class/net").join(interface);

    let operstate = match read_trimmed(interface_path.join("operstate")) {
        Ok(value) => value,
        Err(error) => {
            return make_result(
                &check.id,
                "tunnel",
                CheckStatus::Down,
                format!("failed to read interface operstate: {error}"),
                observed_at,
                started,
                None,
                Some(check.ip_version),
                None,
                details,
            )
        }
    };
    details.insert("operstate".to_string(), json!(operstate.clone()));

    let mut counters = match read_interface_counters(interface) {
        Ok(counters) => counters,
        Err(error) => {
            return make_result(
                &check.id,
                "tunnel",
                CheckStatus::Down,
                format!("failed to read interface counters: {error}"),
                observed_at,
                started,
                None,
                Some(check.ip_version),
                None,
                details,
            )
        }
    };

    let mut status = if operstate_matches_expected(&operstate, &check.expected_operstate) {
        CheckStatus::Up
    } else {
        CheckStatus::Down
    };
    let mut message = if operstate.eq_ignore_ascii_case("unknown")
        && check.expected_operstate.eq_ignore_ascii_case("up")
    {
        format!(
            "interface {interface} is administratively up (kernel operstate is unknown for this tunnel type)"
        )
    } else {
        format!("interface {interface} is {operstate}")
    };
    let mut successful_inner_probe = false;

    if let Some(inner_probe) = &check.inner_probe {
        details.insert("inner_probe".to_string(), json!(inner_probe));
        details.insert("inner_probe_bind".to_string(), json!(interface));
        let probe_ip_version = effective_probe_ip_version(inner_probe, check.ip_version);
        details.insert(
            "inner_probe_ip_version".to_string(),
            json!(match probe_ip_version {
                IpVersion::Ipv4 => "ipv4",
                IpVersion::Ipv6 => "ipv6",
                IpVersion::Any => "any",
            }),
        );
        let probe_attempts = if check.auto_create_interface {
            (((check.timeout_ms.max(12_000)) + 999) / 1000).min(15) as usize
        } else {
            1
        };
        let mut last_error = None;
        let mut probe_outcome = None;
        for attempt in 0..probe_attempts {
            match run_ping(
                inner_probe,
                probe_ip_version,
                check.timeout_ms,
                Some(interface),
            ) {
                Ok(outcome) => {
                    probe_outcome = Some(outcome);
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    if attempt + 1 < probe_attempts {
                        // Give the peer a moment to finish interface bring-up and
                        // addressing before declaring a just-created tunnel down.
                        thread::sleep(Duration::from_millis(1_100));
                    }
                }
            }
        }
        match probe_outcome {
            Some(outcome) => {
                successful_inner_probe = true;
                status = CheckStatus::Up;
                if let Some(latency_ms) = outcome.latency_ms {
                    details.insert("inner_probe_rtt_ms".to_string(), json!(latency_ms));
                }
                details.insert("inner_probe_output".to_string(), json!(outcome.summary));
                message = format!("interface {interface} is ready and inner probe succeeded");
                if let Ok(updated_counters) = read_interface_counters(interface) {
                    counters = updated_counters;
                }
            }
            None => {
                status = CheckStatus::Down;
                let error = last_error.unwrap_or_else(|| "probe did not return a result".to_string());
                message = format!("interface exists but inner probe failed: {error}");
            }
        }
    }

    details.insert("rx_packets".to_string(), json!(counters.rx_packets));
    details.insert("tx_packets".to_string(), json!(counters.tx_packets));
    details.insert("rx_bytes".to_string(), json!(counters.rx_bytes));
    details.insert("tx_bytes".to_string(), json!(counters.tx_bytes));

    let previous = match update_tunnel_counter_state(state, &check.id, &counters, observed_at) {
        Ok(previous) => previous,
        Err(error) => {
            return make_result(
                &check.id,
                "tunnel",
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(check.ip_version),
                Some(interface.to_string()),
                details,
            )
        }
    };
    let rx_delta = previous
        .as_ref()
        .map(|previous| counters.rx_packets.saturating_sub(previous.rx_packets))
        .unwrap_or(0);
    let tx_delta = previous
        .as_ref()
        .map(|previous| counters.tx_packets.saturating_sub(previous.tx_packets))
        .unwrap_or(0);
    details.insert("rx_packets_delta".to_string(), json!(rx_delta));
    details.insert("tx_packets_delta".to_string(), json!(tx_delta));

    if check.require_bidirectional_traffic && status == CheckStatus::Up && !successful_inner_probe {
        if previous.is_some() {
            if rx_delta < check.min_rx_packets_delta || tx_delta < check.min_tx_packets_delta {
                status = CheckStatus::Degraded;
                message = format!(
                    "interface is up but traffic deltas are below threshold (rx_delta={rx_delta}, tx_delta={tx_delta})"
                );
            }
        } else if counters.rx_packets == 0 || counters.tx_packets == 0 {
            status = CheckStatus::Degraded;
            message = "interface is up but no bidirectional traffic baseline exists yet".to_string();
        }
    }

    make_result(
        &check.id,
        "tunnel",
        status,
        message,
        observed_at,
        started,
        Some(elapsed_ms(started)),
        Some(check.ip_version),
        Some(interface.to_string()),
        details,
    )
}

#[derive(Default)]
struct ManagedChildren {
    children: Vec<Child>,
    temp_paths: Vec<PathBuf>,
}

impl ManagedChildren {
    fn push(&mut self, child: Child) {
        self.children.push(child);
    }

    fn add_temp_path(&mut self, path: PathBuf) {
        self.temp_paths.push(path);
    }

    fn is_running(&mut self) -> bool {
        !self.children.is_empty() && self.children.iter_mut().all(|child| matches!(child.try_wait(), Ok(None)))
    }
}

#[derive(Default)]
struct PersistentTunnelRuntime {
    fingerprint: String,
    children: ManagedChildren,
    details: BTreeMap<String, Value>,
}

type TunnelRuntimeRegistry = BTreeMap<String, Arc<Mutex<PersistentTunnelRuntime>>>;
fn tunnel_runtime_registry() -> &'static Mutex<TunnelRuntimeRegistry> {
    static RUNTIMES: OnceLock<Mutex<TunnelRuntimeRegistry>> = OnceLock::new();
    RUNTIMES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn tunnel_runtime_fingerprint(check: &TunnelCheck) -> Result<String, String> {
    let mut value = serde_json::to_value(check).map_err(|error| error.to_string())?;
    if let Some(fields) = value.as_object_mut() {
        for field in ["interval_secs", "timeout_ms", "expected_operstate", "require_bidirectional_traffic",
            "min_rx_packets_delta", "min_tx_packets_delta", "speedtest_token", "speedtest_port"] {
            fields.remove(field);
        }
    }
    let encoded = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(ring::digest::digest(&ring::digest::SHA256, &encoded).as_ref().iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Retire forwarding helpers for removed, disabled, or no-longer-managed checks.
pub fn sync_tunnel_runtimes(checks: &[CheckDefinition]) {
    let active = checks.iter().filter_map(|definition| match definition {
        CheckDefinition::Tunnel(check) if check.auto_create_interface
            && matches!(check.protocol, TunnelProtocol::Tun | TunnelProtocol::Ssh) => Some(check.id.as_str()),
        _ => None,
    }).collect::<BTreeSet<_>>();
    let mut registry = tunnel_runtime_registry().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    registry.retain(|id, _| active.contains(id.as_str()));
}

/// An explicit check removal can stop forwarding immediately, before the next cycle.
pub fn retire_tunnel_runtime(check_id: &str) {
    let mut registry = tunnel_runtime_registry().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    registry.remove(check_id);
}

fn ensure_persistent_tunnel_runtime(check: &TunnelCheck, details: &mut BTreeMap<String, Value>,
    spawn: impl FnOnce(&mut BTreeMap<String, Value>) -> Result<ManagedChildren, String>) -> Result<(), String> {
    if !check.auto_create_interface {
        details.insert("managed_tunnel_mode".to_string(), json!("existing_interface"));
        return Ok(());
    }
    let fingerprint = tunnel_runtime_fingerprint(check)?;
    let runtime = {
        let mut registry = tunnel_runtime_registry().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(registry.entry(check.id.clone()).or_insert_with(|| Arc::new(Mutex::new(PersistentTunnelRuntime::default()))))
    };
    let mut runtime = runtime.lock().map_err(|_| "Managed tunnel runtime lock poisoned.".to_string())?;
    if runtime.fingerprint == fingerprint && runtime.children.is_running() {
        details.extend(runtime.details.clone());
        details.insert("managed_tunnel_reused".to_string(), json!(true));
        return Ok(());
    }
    // Drop old children before rebinding the same device/ports after a change.
    runtime.children = ManagedChildren::default();
    runtime.children = spawn(details)?;
    runtime.fingerprint = fingerprint;
    details.insert("managed_tunnel_reused".to_string(), json!(false));
    details.insert("managed_tunnel_persistent".to_string(), json!(true));
    runtime.details = details.clone();
    Ok(())
}

impl Drop for ManagedChildren {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        for path in &self.temp_paths {
            let _ = fs::remove_file(path);
        }
    }
}

fn run_tun_tunnel(
    check: &TunnelCheck,
    state: &Arc<Mutex<PersistedState>>,
    interval_secs: u64,
    observed_at: u64,
    started: Instant,
    mut details: BTreeMap<String, Value>,
) -> CheckResult {
    let _icmp_runtime_lock = icmp_tun_runtime_lock_for(check);
    let interface = match populate_tunnel_details(check, &mut details) {
        Ok(interface) => interface,
        Err(error) => {
            return make_result(
                &check.id,
                "tunnel",
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(check.ip_version),
                None,
                details,
            )
        }
    };

    if !check.auto_create_interface { return evaluate_tunnel_interface(check, &interface, state, observed_at, started, details); }
    // ptunnel-ng has no outer bind option; verify the route on every cycle,
    // including reuse, so the user's selected source is never silently ignored.
    let source_validation = if tun_uses_routed_outer_source(check) {
        validate_routed_outer_source(check, &mut details)
    } else { validate_bound_outer_interface(check, &mut details) };
    match source_validation.and_then(|()| ensure_persistent_tunnel_runtime(check, &mut details, |details| spawn_tun_runtime(check, &interface, interval_secs, details))) {
        Ok(()) => (),
        Err(error) => {
            return make_result(
                &check.id,
                "tunnel",
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(check.ip_version),
                None,
                details,
            )
        }
    };

    if let Err(error) = wait_for_interface(&interface, check.timeout_ms.max(12_000)) {
        return make_result(
            &check.id,
            "tunnel",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            None,
            details,
        );
    }
    if let Err(error) = bring_interface_up(&interface) {
        return make_result(
            &check.id,
            "tunnel",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            Some(interface),
            details,
        );
    }

    if let Err(error) = ensure_tunnel_inner_address(check, &interface, &mut details) {
        return make_result(
            &check.id,
            "tunnel",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            Some(interface),
            details,
        );
    }

    evaluate_tunnel_interface(check, &interface, state, observed_at, started, details)
}

fn run_ssh_tunnel(
    check: &TunnelCheck,
    state: &Arc<Mutex<PersistedState>>,
    _interval_secs: u64,
    observed_at: u64,
    started: Instant,
    mut details: BTreeMap<String, Value>,
) -> CheckResult {
    let interface = match populate_tunnel_details(check, &mut details) {
        Ok(interface) => interface,
        Err(error) => {
            return make_result(
                &check.id,
                "tunnel",
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(check.ip_version),
                None,
                details,
            )
        }
    };

    if !check.auto_create_interface { return evaluate_tunnel_interface(check, &interface, state, observed_at, started, details); }
    match validate_bound_outer_interface(check, &mut details)
        .and_then(|()| ensure_persistent_tunnel_runtime(check, &mut details, |details| spawn_ssh_runtime(check, &interface, details))) {
        Ok(()) => (),
        Err(error) => {
            return make_result(
                &check.id,
                "tunnel",
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(check.ip_version),
                None,
                details,
            )
        }
    };

    if let Err(error) = wait_for_interface(&interface, check.timeout_ms.max(14_000)) {
        return make_result(
            &check.id,
            "tunnel",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            None,
            details,
        );
    }
    if let Err(error) = bring_interface_up(&interface) {
        return make_result(
            &check.id,
            "tunnel",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            Some(interface),
            details,
        );
    }

    if let Err(error) = ensure_tunnel_inner_address(check, &interface, &mut details) {
        return make_result(
            &check.id,
            "tunnel",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            Some(interface),
            details,
        );
    }

    evaluate_tunnel_interface(check, &interface, state, observed_at, started, details)
}

fn run_reverse_ssh_tunnel(
    check: &TunnelCheck,
    state: &Arc<Mutex<PersistedState>>,
    interval_secs: u64,
    observed_at: u64,
    started: Instant,
    mut details: BTreeMap<String, Value>,
) -> CheckResult {
    let interface = match populate_tunnel_details(check, &mut details) {
        Ok(interface) => interface,
        Err(error) => {
            return make_result(
                &check.id,
                "tunnel",
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(check.ip_version),
                None,
                details,
            )
        }
    };

    if !check.auto_create_interface { return evaluate_tunnel_interface(check, &interface, state, observed_at, started, details); }
    if let Err(error) = validate_bound_outer_interface(check, &mut details) {
        return make_result(&check.id, "tunnel", CheckStatus::Down, error, observed_at, started,
            None, Some(check.ip_version), Some(interface), details);
    }
    if !Path::new("/sys/class/net").join(&interface).exists()
        && wait_for_interface(
            &interface,
            check
                .timeout_ms
                .max(ephemeral_overlap_window_ms(interval_secs, 20_000)),
        )
        .is_err()
    {
        return make_result(
            &check.id,
            "tunnel",
            CheckStatus::Down,
            format!(
                "reverse SSH tunnel is waiting for the peer to initiate a tunnel session on {interface}"
            ),
            observed_at,
            started,
            None,
            Some(check.ip_version),
            Some(interface),
            details,
        );
    }
    if let Err(error) = bring_interface_up(&interface) {
        return make_result(
            &check.id,
            "tunnel",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            Some(interface),
            details,
        );
    }

    if let Err(error) = ensure_tunnel_inner_address(check, &interface, &mut details) {
        return make_result(
            &check.id,
            "tunnel",
            CheckStatus::Down,
            error,
            observed_at,
            started,
            None,
            Some(check.ip_version),
            Some(interface),
            details,
        );
    }

    evaluate_tunnel_interface(check, &interface, state, observed_at, started, details)
}

fn bring_interface_up(interface: &str) -> Result<(), String> {
    run_command_owned(
        "ip",
        vec![
            "link".to_string(),
            "set".to_string(),
            "dev".to_string(),
            interface.to_string(),
            "up".to_string(),
        ],
    )
    .map_err(|error| format!("failed to bring interface {interface} up: {error}"))
}

fn spawn_tun_runtime(
    check: &TunnelCheck,
    interface: &str,
    interval_secs: u64,
    details: &mut BTreeMap<String, Value>,
) -> Result<ManagedChildren, String> {
    let outer_remote = check
        .outer_remote
        .as_deref()
        .ok_or_else(|| "TUN tunnel creation needs Outer Remote set to the peer address".to_string())?;
    let local_cidr = resolved_inner_local_cidr(check)?;
    let transport = normalized_tun_transport(check);
    let local_is_listener = local_tunnel_side_should_listen(check)?;
    let mut runtime = ManagedChildren::default();
    details.insert("tun_role".to_string(), json!(if local_is_listener { "listener" } else { "dialer" }));
    details.insert("managed_tunnel_mode".to_string(), json!(format!("tun-{transport}")));

    let effective_transport = if transport == "bip" { "udp" } else { transport.as_str() };
    if transport == "bip" {
        details.insert(
            "managed_tunnel_note".to_string(),
            json!("BIP compatibility mode uses the packet-oriented UDP carrier in this build"),
        );
    }

    match effective_transport {
        "udp" => {
            let port = check.transport_port.ok_or_else(|| {
                format!("TUN over {transport} needs a transport port")
            })?;
            let listener_peer = if local_is_listener { Some(resolve_tun_outer_peer_ip(check)?) } else { None };
            let peer_endpoint = listener_peer.map(|peer| peer.to_string()).unwrap_or_else(|| outer_remote.to_string());
            let socket_side = build_tun_socket_side(
                effective_transport,
                local_is_listener,
                &peer_endpoint,
                port,
                check.listen_port,
                tunnel_outer_uses_ipv6(check),
                check.local_outer.as_deref(),
            );
            let tun_side = format!(
                "TUN:{local_cidr},tun-name={interface},iff-up,iff-no-pi"
            );
            let args = vec![
                "-d".to_string(),
                "-d".to_string(),
                tun_side,
                socket_side,
            ];
            details.insert("managed_tunnel_command".to_string(), json!(vec![format!("socat {}", args.join(" "))]));
            runtime.push(spawn_quiet_child("socat", args)?);
        }
        "tcp" => {
            let port = check.transport_port.ok_or_else(|| {
                "TUN over TCP needs a transport port".to_string()
            })?;
            let log_path = tun_helper_log_path(interface);
            let (mode_flag, endpoint) = if local_is_listener {
                (
                    "--listen-addr".to_string(),
                    check.local_outer.as_deref().map(|ip| build_tun_helper_connect_addr(ip, port, tunnel_outer_uses_ipv6(check)))
                        .unwrap_or_else(|| build_tun_helper_listen_addr(tunnel_outer_uses_ipv6(check), port, false)),
                )
            } else {
                (
                    "--connect-addr".to_string(),
                    build_tun_helper_connect_addr(
                        outer_remote,
                        port,
                        tunnel_outer_uses_ipv6(check),
                    ),
                )
            };
            let lane_count = usize::from(check.tun_lanes.unwrap_or(1));
            let mut helper_args = vec![
                "tun-helper".to_string(),
                "--interface".to_string(),
                interface.to_string(),
                "--lanes".to_string(),
                lane_count.to_string(),
            ];
            for _ in 0..if local_is_listener { 1 } else { lane_count } {
                helper_args.push(mode_flag.clone());
                helper_args.push(endpoint.clone());
            }
            append_tun_helper_packet_limit(check, &mut helper_args);
            if !local_is_listener {
                if let Some(local) = check.local_outer.as_deref() { helper_args.extend(string_args(&["--source-ip", local])); }
            } else {
                append_tun_helper_allowed_peer(check, &mut helper_args)?;
            }
            details.insert("tun_lanes".to_string(), json!(lane_count));
            details.insert(
                "managed_tunnel_command".to_string(),
                json!(vec![format!(
                    "{} {}",
                    current_binary_path()?.display(),
                    helper_args.join(" ")
                )]),
            );
            details.insert(
                "managed_tunnel_log".to_string(),
                json!(log_path.to_string_lossy().to_string()),
            );
            runtime.push(spawn_logged_current_exe_child(helper_args, &log_path)?);
        }
        "icmp" => {
            let bridge_port = check.transport_port.ok_or_else(|| {
                "TUN over ICMP needs a bridge transport port".to_string()
            })?;
            let secret = check
                .tunnel_key
                .clone()
                .unwrap_or_else(|| format!("im-{:08x}", stable_tunnel_id(&check.id)));
            let lane_count = usize::from(check.tun_lanes.unwrap_or(icmp_tun_lane_count() as u8));
            details.insert("tun_secret_configured".to_string(), json!(true));
            details.insert("tun_lanes".to_string(), json!(lane_count));
            if local_is_listener {
                let log_path = tun_helper_log_path(interface);
                let mut helper_args = vec![
                    "tun-helper".to_string(),
                    "--interface".to_string(),
                    interface.to_string(),
                    "--listen-addr".to_string(),
                    build_tun_helper_listen_addr(false, bridge_port, true),
                    "--lanes".to_string(),
                    lane_count.to_string(),
                    "--stream-profile".to_string(),
                    "bulk".to_string(),
                ];
                append_tun_helper_packet_limit(check, &mut helper_args);
                details.insert(
                    "managed_tunnel_command".to_string(),
                    json!(vec![
                        format!(
                            "{} {}",
                            current_binary_path()?.display(),
                            helper_args.join(" ")
                        ),
                        format!(
                            "ptunnel-ng x{lane_count} -r127.0.0.1 -R{bridge_port} with per-lane authentication"
                        ),
                    ]),
                );
                details.insert(
                    "managed_tunnel_log".to_string(),
                    json!(log_path.to_string_lossy().to_string()),
                );
                runtime.push(spawn_logged_current_exe_child(helper_args, &log_path)?);
                for lane_index in 0..lane_count {
                    let lane_secret = icmp_tun_lane_secret(&secret, lane_index);
                    let lane_magic = icmp_tun_lane_magic(&secret, lane_index);
                    runtime.push(spawn_quiet_child(
                        "ptunnel-ng",
                        vec![
                            "-r127.0.0.1".to_string(),
                            format!("-R{bridge_port}"),
                            "-m".to_string(),
                            lane_magic.to_string(),
                            format!("-P{lane_secret}"),
                        ],
                    )?);
                }
            } else {
                let local_forward = check.listen_port.ok_or_else(|| {
                    "TUN over ICMP needs a local forward port".to_string()
                })?;
                let readiness_timeout = check
                    .timeout_ms
                    .max(ephemeral_overlap_window_ms(interval_secs, 20_000));
                let lane_forwards = icmp_tun_local_forward_ports(local_forward, lane_count)?;
                for (lane_index, lane_forward) in lane_forwards.iter().enumerate() {
                    let lane_secret = icmp_tun_lane_secret(&secret, lane_index);
                    let lane_magic = icmp_tun_lane_magic(&secret, lane_index);
                    let ptunnel_args = vec![
                        "-p".to_string(),
                        outer_remote.to_string(),
                        format!("-l{lane_forward}"),
                        "-r127.0.0.1".to_string(),
                        format!("-R{bridge_port}"),
                        "-m".to_string(),
                        lane_magic.to_string(),
                        format!("-P{lane_secret}"),
                    ];
                    runtime.push(spawn_ptunnel_client_until_ready(
                        ptunnel_args,
                        *lane_forward,
                        readiness_timeout,
                    )?);
                }
                let log_path = tun_helper_log_path(interface);
                let mut helper_args = vec![
                    "tun-helper".to_string(),
                    "--interface".to_string(),
                    interface.to_string(),
                    "--stream-profile".to_string(),
                    "bulk".to_string(),
                ];
                for lane_forward in &lane_forwards {
                    helper_args.push("--connect-addr".to_string());
                    helper_args.push(build_tun_helper_connect_addr(
                        "127.0.0.1",
                        *lane_forward,
                        false,
                    ));
                }
                append_tun_helper_packet_limit(check, &mut helper_args);
                details.insert(
                    "managed_tunnel_command".to_string(),
                    json!(vec![
                        format!(
                            "{} {}",
                            current_binary_path()?.display(),
                            helper_args.join(" ")
                        ),
                        format!(
                            "ptunnel-ng x{lane_count} from {outer_remote} local-forwards {:?} -> 127.0.0.1:{bridge_port} with per-lane authentication",
                            lane_forwards
                        ),
                    ]),
                );
                details.insert(
                    "managed_tunnel_log".to_string(),
                    json!(log_path.to_string_lossy().to_string()),
                );
                runtime.push(spawn_logged_current_exe_child(helper_args, &log_path)?);
            }
        }
        other => {
            return Err(format!(
                "unsupported TUN transport {other}; choose udp, tcp, icmp, or bip"
            ))
        }
    }

    Ok(runtime)
}

fn spawn_ssh_runtime(
    check: &TunnelCheck,
    interface: &str,
    details: &mut BTreeMap<String, Value>,
) -> Result<ManagedChildren, String> {
    let outer_remote = check
        .outer_remote
        .as_deref()
        .ok_or_else(|| "SSH tunnel creation needs Outer Remote set to the peer SSH host".to_string())?;
    let unit = ssh_tun_unit(interface)?;
    let ssh_port = check.transport_port.unwrap_or(22);
    let username = check
        .ssh_username
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("root");
    let auth = prepare_ssh_auth(check)?;
    let mut runtime = ManagedChildren::default();
    if let Some(path) = &auth.private_key_path {
        runtime.add_temp_path(path.clone());
    }
    details.insert("managed_tunnel_mode".to_string(), json!("ssh"));
    details.insert("ssh_tun_unit".to_string(), json!(unit));
    details.insert("ssh_endpoint".to_string(), json!(format!("{username}@{outer_remote}:{ssh_port}")));

    runtime.push(spawn_ssh_child(
        &auth,
        username,
        outer_remote,
        ssh_port,
        unit,
        check.local_outer.as_deref(),
    )?);
    wait_for_interface(interface, check.timeout_ms.max(4_000))?;

    let local_ip = resolved_inner_local_ip(check)?;
    if let Some(peer_ip) = check.inner_probe.as_deref() {
        let mtu_args = check.mtu.map(|mtu| format!(" mtu {mtu}")).unwrap_or_default();
        let remote_command = format!(
            "ip link set dev tun{unit}{mtu_args} up && ip address replace {peer_ip} peer {local_ip} dev tun{unit}"
        );
        run_ssh_command(&auth, username, outer_remote, ssh_port, &remote_command, check.local_outer.as_deref())?;
    }

    Ok(runtime)
}

struct SshAuthMaterial {
    password: Option<String>,
    private_key_path: Option<PathBuf>,
}

fn prepare_ssh_auth(check: &TunnelCheck) -> Result<SshAuthMaterial, String> {
    if let Some(private_key) = check
        .ssh_private_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let path = PathBuf::from(format!(
            "/tmp/iranmonitor-ssh-key-{}-{}",
            stable_tunnel_id(&check.id),
            unix_now()
        ));
        fs::write(&path, format!("{private_key}\n"))
            .map_err(|error| format!("failed to write temporary SSH private key: {error}"))?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("failed to secure temporary SSH private key: {error}"))?;
        return Ok(SshAuthMaterial {
            password: None,
            private_key_path: Some(path),
        });
    }

    Ok(SshAuthMaterial {
        password: check
            .ssh_password
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        private_key_path: None,
    })
}

fn spawn_ssh_child(
    auth: &SshAuthMaterial,
    username: &str,
    host: &str,
    port: u16,
    unit: u16,
    local_outer: Option<&str>,
) -> Result<Child, String> {
    let mut args = vec![
        "-N".to_string(),
        "-T".to_string(),
        "-o".to_string(),
        "ExitOnForwardFailure=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-o".to_string(),
        "ServerAliveInterval=5".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=2".to_string(),
        "-o".to_string(),
        "Tunnel=point-to-point".to_string(),
        "-w".to_string(),
        format!("{unit}:{unit}"),
        "-p".to_string(),
        port.to_string(),
    ];
    if let Some(path) = &auth.private_key_path {
        // Private-key material is held only for the lifetime of this helper.
        args.push("-i".to_string());
        args.push(path.to_string_lossy().to_string());
    }
    if let Some(local) = local_outer { args.extend(string_args(&["-b", local])); }
    args.push(format!("{username}@{host}"));

    if let Some(password) = &auth.password {
        let mut command_args = vec!["-p".to_string(), password.clone(), "ssh".to_string()];
        command_args.extend(args);
        spawn_quiet_child("sshpass", command_args)
    } else {
        spawn_quiet_child("ssh", args)
    }
}

fn run_ssh_command(
    auth: &SshAuthMaterial,
    username: &str,
    host: &str,
    port: u16,
    remote_command: &str,
    local_outer: Option<&str>,
) -> Result<(), String> {
    let mut args = vec![
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-p".to_string(),
        port.to_string(),
    ];
    if let Some(path) = &auth.private_key_path {
        args.push("-i".to_string());
        args.push(path.to_string_lossy().to_string());
    }
    if let Some(local) = local_outer { args.extend(string_args(&["-b", local])); }
    args.push(format!("{username}@{host}"));
    args.push(remote_command.to_string());

    if let Some(password) = &auth.password {
        let mut command_args = vec!["-p".to_string(), password.clone(), "ssh".to_string()];
        command_args.extend(args);
        run_command_owned("sshpass", command_args)
            .map_err(|error| format!("failed to configure remote SSH tunnel peer: {error}"))
    } else {
        run_command_owned("ssh", args)
            .map_err(|error| format!("failed to configure remote SSH tunnel peer: {error}"))
    }
}

fn resolved_inner_local_cidr(check: &TunnelCheck) -> Result<String, String> {
    check
        .inner_local_cidr
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_inner_local_address)
        .or_else(|| derive_inner_local_cidr(check))
        .ok_or_else(|| {
            "managed tunnel creation needs Local Tunnel Address / CIDR or an Inner Probe that lets IranMonitor derive it automatically"
                .to_string()
        })
}

fn normalize_inner_local_address(value: &str) -> String {
    let value = value.trim();
    if value.contains('/') {
        return value.to_string();
    }
    if value.parse::<std::net::Ipv4Addr>().is_ok() {
        return format!("{value}/30");
    }
    if value.parse::<std::net::Ipv6Addr>().is_ok() {
        return format!("{value}/127");
    }
    value.to_string()
}

fn resolved_inner_local_ip(check: &TunnelCheck) -> Result<String, String> {
    resolved_inner_local_cidr(check).map(|cidr| {
        cidr.split('/')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    })
}

fn normalized_tun_transport(check: &TunnelCheck) -> String {
    check
        .tun_transport
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("udp")
        .to_ascii_lowercase()
}

fn local_tunnel_side_should_listen(check: &TunnelCheck) -> Result<bool, String> {
    let local = check
        .local_outer
        .as_deref()
        .ok_or_else(|| "managed TUN creation needs Outer Local set to this server address".to_string())?;
    let remote = check
        .outer_remote
        .as_deref()
        .ok_or_else(|| "managed TUN creation needs Outer Remote set to the peer address".to_string())?;
    Ok(compare_tunnel_endpoints(local, remote) == std::cmp::Ordering::Less)
}

fn compare_tunnel_endpoints(left: &str, right: &str) -> std::cmp::Ordering {
    match (left.parse::<IpAddr>(), right.parse::<IpAddr>()) {
        (Ok(IpAddr::V4(left)), Ok(IpAddr::V4(right))) => left.octets().cmp(&right.octets()),
        (Ok(IpAddr::V6(left)), Ok(IpAddr::V6(right))) => left.octets().cmp(&right.octets()),
        _ => left.cmp(right),
    }
}

fn build_tun_socket_side(
    transport: &str,
    local_is_listener: bool,
    outer_remote: &str,
    port: u16,
    listen_port: Option<u16>,
    outer_is_ipv6: bool,
    local_outer: Option<&str>,
) -> String {
    let mut side = match (transport, local_is_listener, outer_is_ipv6) {
        ("udp", true, true) => format!("UDP6-LISTEN:{port},reuseaddr,range=[{outer_remote}]/128"),
        ("udp", true, false) => format!("UDP4-LISTEN:{port},reuseaddr,range={outer_remote}/32"),
        ("udp", false, true) => {
            let mut side = format!("UDP6:[{outer_remote}]:{port}");
            if let Some(listen_port) = listen_port {
                side.push_str(&format!(",sourceport={listen_port}"));
            }
            side
        }
        ("udp", false, false) => {
            let mut side = format!("UDP4:{outer_remote}:{port}");
            if let Some(listen_port) = listen_port {
                side.push_str(&format!(",sourceport={listen_port}"));
            }
            side
        }
        ("tcp", true, true) => format!("TCP6-LISTEN:{port},reuseaddr,nodelay"),
        ("tcp", true, false) => format!("TCP4-LISTEN:{port},reuseaddr,nodelay"),
        ("tcp", false, true) => format!("TCP6:[{outer_remote}]:{port},nodelay"),
        ("tcp", false, false) => format!("TCP4:{outer_remote}:{port},nodelay"),
        _ => format!("TCP4:{outer_remote}:{port},nodelay"),
    };
    if let Some(local) = local_outer {
        // Socat's bind option also parses a port; brackets keep IPv6 colons
        // inside the address rather than treating them as that separator.
        if address_looks_like_ipv6(local) {
            side.push_str(&format!(",bind=[{}]", local.trim_matches(&['[', ']'][..])));
        } else {
            side.push_str(&format!(",bind={local}"));
        }
    }
    side
}

fn resolve_tun_outer_peer_ip(check: &TunnelCheck) -> Result<IpAddr, String> {
    let remote = check.outer_remote.as_deref().ok_or_else(|| "Managed TUN listeners require the configured peer outer address.".to_string())?;
    let local = check.local_outer.as_deref().and_then(|value| value.parse::<IpAddr>().ok());
    let peer = (remote, 0).to_socket_addrs().map_err(|error| format!("Could not resolve configured TUN peer {remote}: {error}"))?
        .find(|address| local.map_or(true, |local| local.is_ipv4() == address.is_ipv4()))
        .map(|address| address.ip()).ok_or_else(|| format!("Configured TUN peer {remote} has no address in the Local Outer IP family."))?;
    if peer.is_unspecified() || peer.is_multicast() { return Err("Managed TUN listeners require a specific unicast peer outer address.".to_string()); }
    Ok(peer)
}

fn append_tun_helper_allowed_peer(check: &TunnelCheck, args: &mut Vec<String>) -> Result<(), String> {
    args.extend(string_args(&["--allowed-peer", &resolve_tun_outer_peer_ip(check)?.to_string()]));
    Ok(())
}

fn build_tun_helper_listen_addr(outer_is_ipv6: bool, port: u16, loopback_only: bool) -> String {
    match (outer_is_ipv6, loopback_only) {
        (true, true) => format!("[::1]:{port}"),
        (true, false) => format!("[::]:{port}"),
        (false, true) => format!("127.0.0.1:{port}"),
        (false, false) => format!("0.0.0.0:{port}"),
    }
}

fn build_tun_helper_connect_addr(host: &str, port: u16, ipv6: bool) -> String {
    if ipv6 || address_looks_like_ipv6(host) {
        format!("[{}]:{port}", host.trim_matches(&['[', ']'][..]))
    } else {
        format!("{host}:{port}")
    }
}

fn current_binary_path() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map_err(|error| format!("failed to resolve current iranmonitor binary path: {error}"))
}

fn tun_helper_log_path(interface: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/iranmonitor-tun-helper-{interface}.log"))
}

fn icmp_tun_lane_count() -> usize {
    // Ptunnel's ICMP transport is sensitive to reordering and session churn, so
    // one lane is more stable than round-robin striping on the same host pair.
    1
}

fn append_tun_helper_packet_limit(check: &TunnelCheck, args: &mut Vec<String>) {
    if let Some(mtu) = check.mtu { args.extend(string_args(&["--packet-limit", &mtu.to_string()])); }
}

fn icmp_tun_lane_secret(base_secret: &str, lane_index: usize) -> String {
    format!("{base_secret}-lane{lane_index}")
}

fn icmp_tun_lane_magic(base_secret: &str, lane_index: usize) -> u32 {
    stable_tunnel_id(&format!("{base_secret}:lane{lane_index}:magic"))
}

fn icmp_tun_local_forward_ports(base_port: u16, lanes: usize) -> Result<Vec<u16>, String> {
    if lanes == 0 {
        return Err("ICMP TUN lanes must be at least 1".to_string());
    }

    let last_port = u32::from(base_port)
        .checked_add(lanes.saturating_sub(1) as u32)
        .ok_or_else(|| {
            format!(
                "failed to allocate {lanes} ICMP tunnel local forward ports starting at {base_port}"
            )
        })?;
    if last_port > u16::MAX as u32 {
        return Err(format!(
            "ICMP tunnel needs {lanes} consecutive local forward ports, but the range {base_port}-{last_port} exceeds 65535"
        ));
    }

    Ok((0..lanes)
        .map(|offset| base_port.saturating_add(offset as u16))
        .collect())
}

fn spawn_logged_current_exe_child(args: Vec<String>, log_path: &Path) -> Result<Child, String> {
    let binary = current_binary_path()?;
    let stdout = fs::File::create(log_path).map_err(|error| {
        format!(
            "failed to open {} for tunnel helper stdout: {error}",
            log_path.display()
        )
    })?;
    let stderr = stdout.try_clone().map_err(|error| {
        format!(
            "failed to clone {} for tunnel helper stderr: {error}",
            log_path.display()
        )
    })?;

    Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("failed to start built-in tunnel helper: {error}"))
}

fn ephemeral_overlap_window_ms(interval_secs: u64, minimum_ms: u64) -> u64 {
    let interval_ms = interval_secs.saturating_mul(1_000);
    interval_ms
        .saturating_sub(5_000)
        .clamp(minimum_ms, 55_000)
}

fn spawn_ptunnel_client_until_ready(
    args: Vec<String>,
    local_forward_port: u16,
    timeout_ms: u64,
) -> Result<Child, String> {
    let deadline = Instant::now() + timeout_duration(timeout_ms.max(1_000));
    let log_path = PathBuf::from(format!(
        "/tmp/iranmonitor-ptunnel-{local_forward_port}.log"
    ));
    let mut last_exit = None;

    while Instant::now() < deadline {
        let _ = fs::remove_file(&log_path);
        let mut child = spawn_logged_child("ptunnel-ng", args.clone(), &log_path)?;
        loop {
            if local_tcp_listener_is_ready(local_forward_port) {
                return Ok(child);
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    let log_tail = fs::read_to_string(&log_path)
                        .ok()
                        .map(|text| truncate(first_non_empty_line(&text).trim(), 220))
                        .filter(|line| !line.is_empty());
                    last_exit = Some(match log_tail {
                        Some(line) => format!("{status}; {line}"),
                        None => status.to_string(),
                    });
                    break;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    thread::sleep(Duration::from_millis(200));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "failed while waiting for ptunnel-ng to expose 127.0.0.1:{local_forward_port}: {error}"
                    ));
                }
            }
        }

        thread::sleep(Duration::from_millis(350));
    }

    let suffix = last_exit
        .map(|status| format!("; ptunnel-ng kept exiting early with status {status}"))
        .unwrap_or_default();
    Err(format!(
        "local tunnel forward 127.0.0.1:{local_forward_port} did not become ready before the timeout{suffix}"
    ))
}

fn local_tcp_listener_is_ready(port: u16) -> bool {
    let Ok(output) = run_command_capture("ss", &["-H", "-ltn"]) else {
        return false;
    };

    output.lines().any(|line| {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        let Some(local_address) = columns.get(3) else {
            return false;
        };
        let candidates = [
            format!("127.0.0.1:{port}"),
            format!("0.0.0.0:{port}"),
            format!("[::]:{port}"),
            format!("*:{port}"),
        ];
        candidates.iter().any(|candidate| local_address == candidate)
    })
}

fn icmp_tun_runtime_lock_for(check: &TunnelCheck) -> Option<MutexGuard<'static, ()>> {
    (check.protocol == TunnelProtocol::Tun && normalized_tun_transport(check) == "icmp")
        .then(|| {
            icmp_tun_runtime_mutex()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        })
}

fn icmp_tun_runtime_mutex() -> &'static Mutex<()> {
    static ICMP_TUN_RUNTIME_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    ICMP_TUN_RUNTIME_MUTEX.get_or_init(|| Mutex::new(()))
}

fn spawn_quiet_child(command: &str, args: Vec<String>) -> Result<Child, String> {
    Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to start {command}: {error}"))
}

fn spawn_logged_child(command: &str, args: Vec<String>, log_path: &Path) -> Result<Child, String> {
    let stdout = fs::File::create(log_path)
        .map_err(|error| format!("failed to open {} for {command} stdout: {error}", log_path.display()))?;
    let stderr = stdout
        .try_clone()
        .map_err(|error| format!("failed to clone {} for {command} stderr: {error}", log_path.display()))?;

    Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("failed to start {command}: {error}"))
}

fn wait_for_interface(interface: &str, timeout_ms: u64) -> Result<(), String> {
    let deadline = Instant::now() + timeout_duration(timeout_ms.max(1_000));
    let path = Path::new("/sys/class/net").join(interface);
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "managed tunnel creation did not produce interface {interface} before the timeout"
    ))
}

fn ssh_tun_unit(interface: &str) -> Result<u16, String> {
    let trimmed = interface.trim();
    let suffix = trimmed
        .strip_prefix("tun")
        .ok_or_else(|| format!("SSH tunnels need an interface name like tun42, got {trimmed}"))?;
    suffix.parse::<u16>().map_err(|_| {
        format!("SSH tunnels need an interface name like tun42, got {trimmed}")
    })
}

struct TunnelCreatePlan {
    commands: Vec<Vec<String>>,
    mode_label: &'static str,
}

fn ensure_managed_tunnel_interface(
    check: &TunnelCheck,
    details: &mut BTreeMap<String, Value>,
) -> Result<(), String> {
    let interface = check
        .interface
        .as_deref()
        .ok_or_else(|| "interface-based tunnel checks need an interface name".to_string())?;
    let interface_path = Path::new("/sys/class/net").join(interface);
    let mut interface_exists = interface_path.exists();
    if !check.auto_create_interface {
        if !interface_exists { return Err(format!("network interface not found: {interface}")); }
        details.insert("managed_tunnel_mode".to_string(), json!("existing_interface"));
        details.insert("managed_tunnel_created".to_string(), json!(false));
        return Ok(());
    }
    if check.protocol == TunnelProtocol::Geneve
        || (check.protocol == TunnelProtocol::Wireguard && (check.local_outer.is_some() || check.source_interface.is_some())) {
        validate_routed_outer_source(check, details)?;
    }
    if interface_exists && matches!(check.protocol, TunnelProtocol::Esp) {
        let expected_if_id = resolve_xfrm_if_id(check);
        if let Some(current_if_id) = read_xfrm_interface_if_id(interface)? {
            details.insert(
                "managed_tunnel_current_if_id".to_string(),
                json!(format!("0x{current_if_id:x}")),
            );
            details.insert(
                "managed_tunnel_expected_if_id".to_string(),
                json!(format!("0x{expected_if_id:x}")),
            );
            if current_if_id != expected_if_id {
                run_command_owned(
                    "ip",
                    vec![
                        "link".to_string(),
                        "delete".to_string(),
                        "dev".to_string(),
                        interface.to_string(),
                    ],
                )
                .map_err(|error| {
                    format!(
                        "managed ESP/XFRM interface {interface} exists with wrong if_id and could not be recreated: {error}"
                    )
                })?;
                interface_exists = false;
                details.insert("managed_tunnel_recreated".to_string(), json!(true));
            }
        }
    }
    if !interface_exists {
        if !check.auto_create_interface {
            return Err(format!("network interface not found: {interface}"));
        }

        let plan = build_managed_tunnel_plan(check)?;
        details.insert("managed_tunnel_mode".to_string(), json!(plan.mode_label));
        details.insert(
            "managed_tunnel_command".to_string(),
            json!(
                plan.commands
                    .iter()
                    .map(|args| format!("ip {}", args.join(" ")))
                    .collect::<Vec<_>>()
            ),
        );

        for command in plan.commands {
            if let Err(error) = run_command_owned("ip", command) {
                if !(error.contains("File exists") && interface_path.exists()) {
                    return Err(format!(
                        "failed to create managed tunnel interface {interface}: {error}"
                    ));
                }
            }
        }

        if !interface_path.exists() {
            return Err(format!(
                "managed tunnel creation finished but interface is still missing: {interface}"
            ));
        }

        details.insert("managed_tunnel_created".to_string(), json!(true));
    } else {
        details.insert("managed_tunnel_created".to_string(), json!(false));
        details
            .entry("managed_tunnel_recreated".to_string())
            .or_insert(json!(false));
    }

    // Some tunnel types, especially SIT/IPv6 encapsulation, need the device
    // administratively up before peer routes can be installed successfully.
    run_command_owned(
        "ip",
        vec![
            "link".to_string(),
            "set".to_string(),
            "dev".to_string(),
            interface.to_string(),
            "up".to_string(),
        ],
    )
    .map_err(|error| {
        format!("managed tunnel {interface} exists but could not be brought up: {error}")
    })?;

    apply_managed_tunnel_runtime_config(check, interface, details)?;
    run_command_owned(
        "ip",
        vec![
            "link".to_string(),
            "set".to_string(),
            "dev".to_string(),
            interface.to_string(),
            "up".to_string(),
        ],
    )
    .map_err(|error| {
        format!("managed tunnel {interface} exists but could not be brought up: {error}")
    })?;
    Ok(())
}

fn build_managed_tunnel_plan(check: &TunnelCheck) -> Result<TunnelCreatePlan, String> {
    validate_tunnel_configuration(check)?;
    let interface = check
        .interface
        .as_deref()
        .ok_or_else(|| "managed tunnel creation needs an interface name".to_string())?;
    let remote = check
        .outer_remote
        .as_deref()
        .ok_or_else(|| "managed tunnel creation needs Outer Remote set to the other server address".to_string())?;
    let local = check.local_outer.as_deref();
    let outer_is_ipv6 = tunnel_outer_uses_ipv6(check);

    match check.protocol {
        TunnelProtocol::Gretap => {
            let mut args = string_args(&["link", "add", "name", interface, "type", if outer_is_ipv6 { "ip6gretap" } else { "gretap" }]);
            append_remote_local_args(&mut args, remote, local);
            append_tunnel_key_args(check, &mut args);
            append_outer_packet_settings(check, &mut args, outer_is_ipv6);
            append_outer_device(check, &mut args);
            Ok(TunnelCreatePlan { commands: vec![args], mode_label: if outer_is_ipv6 { "ip6gretap" } else { "gretap" } })
        }
        TunnelProtocol::Vxlan | TunnelProtocol::Geneve => {
            let mode = check.protocol.as_str();
            let mut args = string_args(&["link", "add", "name", interface, "type", mode, "id"]);
            args.push(check.vni.unwrap_or(42).to_string());
            args.extend(string_args(&["remote", remote]));
            if check.protocol == TunnelProtocol::Vxlan {
                if let Some(local) = local { args.extend(string_args(&["local", local])); }
                append_outer_device(check, &mut args);
                // A fixed peer flood entry carries ARP/ND and unknown unicast.
                // Disabling dynamic learning keeps this a deterministic pair.
                args.push("nolearning".to_string());
            }
            args.push("dstport".to_string());
            args.push(check.transport_port.unwrap_or(if check.protocol == TunnelProtocol::Vxlan { 4789 } else { 6081 }).to_string());
            // VXLAN/GENEVE use ttl/tos keywords for both outer families.
            append_outer_packet_settings(check, &mut args, false);
            Ok(TunnelCreatePlan { commands: vec![args], mode_label: if check.protocol == TunnelProtocol::Vxlan { "vxlan" } else { "geneve" } })
        }
        TunnelProtocol::Gre => {
            let mut args = Vec::new();
            if outer_is_ipv6 {
                args.extend(string_args(&["-6", "tunnel", "add"]));
                args.push(interface.to_string());
                args.extend(string_args(&["mode", "ip6gre"]));
            } else {
                args.extend(string_args(&["tunnel", "add"]));
                args.push(interface.to_string());
                args.extend(string_args(&["mode", "gre"]));
            }
            append_tunnel_key_args(check, &mut args);
            append_remote_local_args(&mut args, remote, local);
            append_outer_packet_settings(check, &mut args, outer_is_ipv6);
            append_outer_device(check, &mut args);
            Ok(TunnelCreatePlan {
                commands: vec![args],
                mode_label: if outer_is_ipv6 { "ip6gre" } else { "gre" },
            })
        }
        TunnelProtocol::Ipv4IpInIp | TunnelProtocol::Ipip => {
            let mut args = Vec::new();
            if outer_is_ipv6 {
                args.extend(string_args(&["-6", "tunnel", "add"]));
                args.push(interface.to_string());
                args.extend(string_args(&["mode", "ipip6"]));
            } else {
                args.extend(string_args(&["tunnel", "add"]));
                args.push(interface.to_string());
                args.extend(string_args(&["mode", "ipip"]));
            }
            append_remote_local_args(&mut args, remote, local);
            append_outer_packet_settings(check, &mut args, outer_is_ipv6);
            append_outer_device(check, &mut args);
            Ok(TunnelCreatePlan {
                commands: vec![args],
                mode_label: if outer_is_ipv6 { "ipip6" } else { "ipip" },
            })
        }
        TunnelProtocol::Ipv6Encapsulation => {
            let mut args = Vec::new();
            if outer_is_ipv6 {
                args.extend(string_args(&["-6", "tunnel", "add"]));
                args.push(interface.to_string());
                args.extend(string_args(&["mode", "ip6ip6"]));
            } else {
                args.extend(string_args(&["tunnel", "add"]));
                args.push(interface.to_string());
                args.extend(string_args(&["mode", "sit"]));
            }
            append_remote_local_args(&mut args, remote, local);
            append_outer_packet_settings(check, &mut args, outer_is_ipv6);
            append_outer_device(check, &mut args);
            Ok(TunnelCreatePlan {
                commands: vec![args],
                mode_label: if outer_is_ipv6 { "ip6ip6" } else { "sit" },
            })
        }
        TunnelProtocol::Etherip => {
            let mut args = Vec::new();
            args.extend(string_args(&["link", "add", "name"]));
            args.push(interface.to_string());
            args.extend(string_args(&["type", "etherip"]));
            append_remote_local_args(&mut args, remote, local);
            Ok(TunnelCreatePlan {
                commands: vec![args],
                mode_label: "etherip",
            })
        }
        TunnelProtocol::Encap => {
            if outer_is_ipv6 {
                return Err(
                    "managed ENCAP currently supports IPv4 outer endpoints only".to_string(),
                );
            }
            let encap_port = check.transport_port.unwrap_or(5555).to_string();
            let mut args = string_args(&["link", "add", "name"]);
            args.push(interface.to_string());
            args.extend(string_args(&["type", "ipip", "remote"]));
            args.push(remote.to_string());
            if let Some(local) = local {
                args.extend(string_args(&["local"]));
                args.push(local.to_string());
            }
            args.extend(string_args(&[
                "encap",
                "gue",
                "encap-sport",
                "auto",
                "encap-dport",
            ]));
            args.push(encap_port);
            append_outer_packet_settings(check, &mut args, false);
            append_outer_device(check, &mut args);
            Ok(TunnelCreatePlan {
                commands: vec![args],
                mode_label: "ipip+gue",
            })
        }
        TunnelProtocol::L2tp => {
            let local = local.ok_or_else(|| {
                "managed L2TP creation needs Outer Local set to this server address".to_string()
            })?;
            let tunnel_id = check.l2tp_tunnel_id.unwrap_or(1).to_string();
            let peer_tunnel_id = check.l2tp_peer_tunnel_id.unwrap_or(1).to_string();
            let session_id = check.l2tp_session_id.unwrap_or(1).to_string();
            let peer_session_id = check.l2tp_peer_session_id.unwrap_or(1).to_string();
            let encap = check
                .l2tp_encapsulation
                .as_deref()
                .unwrap_or("udp")
                .trim()
                .to_ascii_lowercase();

            let mut tunnel_args = string_args(&["l2tp", "add", "tunnel", "tunnel_id"]);
            tunnel_args.push(tunnel_id.clone());
            tunnel_args.extend(string_args(&["peer_tunnel_id"]));
            tunnel_args.push(peer_tunnel_id);
            tunnel_args.extend(string_args(&["encap", encap.as_str(), "local"]));
            tunnel_args.push(local.to_string());
            tunnel_args.extend(string_args(&["remote"]));
            tunnel_args.push(remote.to_string());
            if encap == "udp" {
                let udp_dport = check.transport_port.unwrap_or(1701).to_string();
                let udp_sport = check
                    .listen_port
                    .unwrap_or(check.transport_port.unwrap_or(1701))
                    .to_string();
                tunnel_args.extend(string_args(&["udp_sport"]));
                tunnel_args.push(udp_sport);
                tunnel_args.extend(string_args(&["udp_dport"]));
                tunnel_args.push(udp_dport);
            }

            let mut session_args =
                string_args(&["l2tp", "add", "session", "name", interface, "tunnel_id"]);
            session_args.push(tunnel_id);
            session_args.extend(string_args(&["session_id"]));
            session_args.push(session_id);
            session_args.extend(string_args(&["peer_session_id"]));
            session_args.push(peer_session_id);
            Ok(TunnelCreatePlan {
                commands: vec![tunnel_args, session_args],
                mode_label: "l2tp",
            })
        }
        TunnelProtocol::Esp => {
            let parent = resolve_parent_interface(check)?;
            let if_id = resolve_xfrm_if_id(check);
            Ok(TunnelCreatePlan {
                commands: vec![vec![
                    "link".to_string(),
                    "add".to_string(),
                    interface.to_string(),
                    "type".to_string(),
                    "xfrm".to_string(),
                    "dev".to_string(),
                    parent,
                    "if_id".to_string(),
                    format!("0x{if_id:x}"),
                ]],
                mode_label: "xfrm",
            })
        }
        TunnelProtocol::Wireguard => Ok(TunnelCreatePlan {
            commands: vec![vec![
                "link".to_string(),
                "add".to_string(),
                "dev".to_string(),
                interface.to_string(),
                "type".to_string(),
                "wireguard".to_string(),
            ]],
            mode_label: "wireguard",
        }),
        TunnelProtocol::Tun => Err("TUN tunnel runtime is handled by socat/ptunnel".to_string()),
        TunnelProtocol::Ssh => Err("SSH tunnel runtime is handled by OpenSSH".to_string()),
        TunnelProtocol::ReverseSsh => {
            Err("Reverse SSH tunnel runtime is handled by a peer-initiated OpenSSH session".to_string())
        }
    }
}

fn tunnel_outer_uses_ipv6(check: &TunnelCheck) -> bool {
    if let Some(remote) = check.outer_remote.as_deref() {
        if address_looks_like_ipv6(remote) {
            return true;
        }
        if remote.parse::<Ipv4Addr>().is_ok() {
            return false;
        }
    }

    if let Some(local) = check.local_outer.as_deref() {
        if address_looks_like_ipv6(local) {
            return true;
        }
        if local.parse::<Ipv4Addr>().is_ok() {
            return false;
        }
    }

    matches!(check.ip_version, IpVersion::Ipv6)
}

fn address_looks_like_ipv6(value: &str) -> bool {
    value.contains(':')
}

fn string_args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn append_remote_local_args(args: &mut Vec<String>, remote: &str, local: Option<&str>) {
    args.extend(string_args(&["remote"]));
    args.push(remote.to_string());
    if let Some(local) = local {
        args.extend(string_args(&["local"]));
        args.push(local.to_string());
    }
}

fn tunnel_supports_outer_packet_settings(protocol: TunnelProtocol) -> bool {
    matches!(protocol, TunnelProtocol::Gre | TunnelProtocol::Gretap | TunnelProtocol::Vxlan | TunnelProtocol::Geneve
        | TunnelProtocol::Ipv4IpInIp | TunnelProtocol::Ipip | TunnelProtocol::Ipv6Encapsulation | TunnelProtocol::Encap)
}

fn append_outer_packet_settings(check: &TunnelCheck, args: &mut Vec<String>, ipv6_keywords: bool) {
    if let Some(ttl) = check.ttl {
        args.extend(string_args(&[if ipv6_keywords { "hoplimit" } else { "ttl" }]));
        args.push(ttl.to_string());
    }
    if let Some(class) = check.traffic_class {
        args.extend(string_args(&[if ipv6_keywords { "tclass" } else { "tos" }]));
        args.push(format!("0x{class:02x}"));
    }
}

fn append_outer_device(check: &TunnelCheck, args: &mut Vec<String>) {
    if let Some(device) = check.source_interface.as_deref() { args.extend(string_args(&["dev", device])); }
}

fn build_outer_packet_update(check: &TunnelCheck, interface: &str) -> Option<Vec<String>> {
    if !tunnel_supports_outer_packet_settings(check.protocol) || (check.ttl.is_none() && check.traffic_class.is_none()) { return None; }
    let ipv6 = tunnel_outer_uses_ipv6(check);
    let kind = match check.protocol {
        TunnelProtocol::Gre => if ipv6 { "ip6gre" } else { "gre" },
        TunnelProtocol::Gretap => if ipv6 { "ip6gretap" } else { "gretap" },
        TunnelProtocol::Ipv4IpInIp | TunnelProtocol::Ipip => if ipv6 { "ip6tnl" } else { "ipip" },
        TunnelProtocol::Ipv6Encapsulation => if ipv6 { "ip6tnl" } else { "sit" },
        TunnelProtocol::Encap => "ipip",
        TunnelProtocol::Vxlan => "vxlan",
        TunnelProtocol::Geneve => "geneve",
        _ => return None,
    };
    let mut args = string_args(&["link", "set", "dev", interface, "type", kind]);
    // iproute2 requires the existing VNI even for an in-place GENEVE change.
    if check.protocol == TunnelProtocol::Geneve { args.extend(string_args(&["id", &check.vni.unwrap_or(42).to_string()])); }
    if check.protocol == TunnelProtocol::Encap {
        // iproute2 6.1 reads saved encapsulation ports in network byte order,
        // then swaps them again on an update. Supply our configured ports so
        // repeated TTL/TOS updates cannot alternate the live destination port.
        args.extend(string_args(&["encap", "gue", "encap-sport", "auto", "encap-dport", &check.transport_port.unwrap_or(5555).to_string()]));
    }
    append_outer_packet_settings(check, &mut args, ipv6 && !matches!(check.protocol, TunnelProtocol::Vxlan | TunnelProtocol::Geneve));
    Some(args)
}

fn apply_tunnel_mtu(check: &TunnelCheck, interface: &str, details: &mut BTreeMap<String, Value>) -> Result<(), String> {
    if !check.auto_create_interface { return Ok(()); }
    if let Some(mtu) = check.mtu {
        let current = fs::read_to_string(Path::new("/sys/class/net").join(interface).join("mtu")).ok()
            .and_then(|value| value.trim().parse::<u16>().ok());
        if current != Some(mtu) {
            run_command_owned("ip", string_args(&["link", "set", "dev", interface, "mtu", &mtu.to_string()]))
                .map_err(|error| format!("Failed to set tunnel MTU to {mtu} on {interface}: {error}"))?;
        }
        details.insert("mtu".to_string(), json!(mtu));
        details.insert("packet_size_ceiling".to_string(), json!(mtu));
    }
    Ok(())
}

fn tun_uses_routed_outer_source(check: &TunnelCheck) -> bool {
    check.auto_create_interface && check.protocol == TunnelProtocol::Tun && normalized_tun_transport(check) == "icmp"
}

fn routed_outer_source_label(check: &TunnelCheck) -> &'static str {
    match check.protocol {
        TunnelProtocol::Wireguard => "WireGuard",
        TunnelProtocol::Tun if normalized_tun_transport(check) == "icmp" => "ICMP TUN",
        TunnelProtocol::Tun => "TUN",
        TunnelProtocol::Ssh => "SSH",
        TunnelProtocol::ReverseSsh => "Reverse SSH",
        _ => "GENEVE",
    }
}

fn build_bound_outer_route_args(check: &TunnelCheck) -> Result<Vec<String>, String> {
    let label = routed_outer_source_label(check);
    let remote = check.outer_remote.as_deref().ok_or_else(|| format!("{label} source-interface validation requires the peer outer IP."))?;
    let peer = remote.parse::<IpAddr>().map_err(|_| format!("To verify the selected {label} source interface, use a literal peer endpoint IP. Hostname resolution can select a different route."))?;
    let mut args = if peer.is_ipv6() { string_args(&["-6", "-o", "route", "get", remote]) }
        else { string_args(&["-o", "route", "get", remote]) };
    // Socket-based carriers bind Local Outer directly. Validate the device for
    // that bound address instead of incorrectly requiring the default source.
    if let Some(local) = check.local_outer.as_deref() { args.extend(string_args(&["from", local])); }
    Ok(args)
}

fn check_bound_outer_route_interface(check: &TunnelCheck, device: Option<&str>) -> Result<(), String> {
    if let Some(expected) = check.source_interface.as_deref() {
        if device != Some(expected) {
            let label = routed_outer_source_label(check);
            let source = check.local_outer.as_deref().unwrap_or("the host-selected source");
            return Err(format!("{label} uses the route's interface, {}, for Local Outer {source}. Configured source interface {expected} is not selected; adjust the host route or source-IP rules before using this tunnel.", device.unwrap_or("unavailable")));
        }
    }
    Ok(())
}

fn validate_bound_outer_interface(check: &TunnelCheck, details: &mut BTreeMap<String, Value>) -> Result<(), String> {
    if check.source_interface.is_none() { return Ok(()); }
    let args = build_bound_outer_route_args(check)?;
    let route = run_command_capture("ip", &args.iter().map(String::as_str).collect::<Vec<_>>())?;
    let device = parse_route_output_for_dev(&route);
    check_bound_outer_route_interface(check, device.as_deref())?;
    details.insert("outer_source_mode".to_string(), json!(if check.protocol == TunnelProtocol::ReverseSsh { "return_route" } else { "bound_socket_route" }));
    details.insert("outer_route_source".to_string(), json!(check.local_outer));
    details.insert("outer_route_interface".to_string(), json!(device));
    Ok(())
}

fn validate_routed_outer_source(check: &TunnelCheck, details: &mut BTreeMap<String, Value>) -> Result<(), String> {
    let label = routed_outer_source_label(check);
    let remote = check.outer_remote.as_deref().ok_or_else(|| format!("{label} source-route validation requires the peer outer IP."))?;
    remote.parse::<IpAddr>().map_err(|_| format!("To verify the selected {label} source IP/interface, use a literal peer endpoint IP. Hostname resolution can select a different route."))?;
    let args = if tunnel_outer_uses_ipv6(check) { vec!["-6", "-o", "route", "get", remote] } else { vec!["-o", "route", "get", remote] };
    let route = run_command_capture("ip", &args)?;
    let source = route.split_whitespace().collect::<Vec<_>>().windows(2)
        .find_map(|pair| if pair[0] == "src" { Some(pair[1].to_string()) } else { None });
    let device = parse_route_output_for_dev(&route);
    check_route_selected_outer_source(check, source.as_deref(), device.as_deref())?;
    details.insert("outer_source_mode".to_string(), json!("kernel_route"));
    details.insert("outer_route_source".to_string(), json!(source));
    details.insert("outer_route_interface".to_string(), json!(device));
    Ok(())
}

fn check_route_selected_outer_source(check: &TunnelCheck, source: Option<&str>, device: Option<&str>) -> Result<(), String> {
    let label = routed_outer_source_label(check);
    if let Some(expected) = check.local_outer.as_deref() {
        if source.and_then(|ip| ip.parse::<IpAddr>().ok()) != expected.parse::<IpAddr>().ok() {
            return Err(format!("{label} uses the route's source IP, {}. Configured Local Outer {expected} is not selected; adjust the host route or source-IP rules before using this tunnel.", source.unwrap_or("unavailable")));
        }
    }
    if let Some(expected) = check.source_interface.as_deref() {
        if device != Some(expected) { return Err(format!("{label} uses the route's interface, {}. Configured source interface {expected} is not selected; adjust the host route.", device.unwrap_or("unavailable"))); }
    }
    Ok(())
}

fn append_tunnel_key_args(check: &TunnelCheck, args: &mut Vec<String>) {
    if let Some(key) = check.tunnel_key.as_deref() {
        args.extend(string_args(&["key"]));
        args.push(key.trim().to_string());
    }
}

fn resolve_parent_interface(check: &TunnelCheck) -> Result<String, String> {
    if let Some(source_interface) = check.source_interface.as_deref() {
        return Ok(source_interface.to_string());
    }
    if let Some(local_outer) = check.local_outer.as_deref() {
        if let Some(interface) = infer_interface_from_local_outer(local_outer) {
            return Ok(interface);
        }
    }
    if let Some(remote) = check.outer_remote.as_deref() {
        if let Some(interface) = infer_interface_from_route_target(remote, tunnel_outer_uses_ipv6(check)) {
            return Ok(interface);
        }
    }
    if let Some(interface) = infer_default_route_interface(tunnel_outer_uses_ipv6(check)) {
        return Ok(interface);
    }
    Err(
        "managed ESP/XFRM interface creation needs a source interface, an Outer Local address that can be matched to an uplink, or a routable Outer Remote/default route"
            .to_string(),
    )
}

fn infer_interface_from_local_outer(local_outer: &str) -> Option<String> {
    let output = run_command_capture("ip", &["-o", "addr", "show", "up", "scope", "global"]).ok()?;
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let interface = parts[1].trim_end_matches(':').trim();
        let address = parts[3].split('/').next().unwrap_or("").trim();
        if address == local_outer {
            return Some(interface.to_string());
        }
    }
    None
}

fn infer_interface_from_route_target(target: &str, ipv6: bool) -> Option<String> {
    let args = if ipv6 {
        vec!["-6", "-o", "route", "get", target]
    } else {
        vec!["-o", "route", "get", target]
    };
    let output = run_command_capture("ip", &args).ok()?;
    parse_route_output_for_dev(&output)
}

fn infer_default_route_interface(ipv6: bool) -> Option<String> {
    let args = if ipv6 {
        vec!["-6", "-o", "route", "show", "default"]
    } else {
        vec!["-o", "route", "show", "default"]
    };
    let output = run_command_capture("ip", &args).ok()?;
    parse_route_output_for_dev(&output)
}

fn parse_route_output_for_dev(output: &str) -> Option<String> {
    for line in output.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        for window in parts.windows(2) {
            if window[0] == "dev" && !window[1].trim().is_empty() {
                return Some(window[1].trim().to_string());
            }
        }
    }
    None
}

fn resolve_xfrm_if_id(check: &TunnelCheck) -> u32 {
    if let Some(raw) = check.tunnel_key.as_deref() {
        let trimmed = raw.trim();
        if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            if let Ok(value) = u32::from_str_radix(hex, 16) {
                return value;
            }
        }
        if let Ok(value) = trimmed.parse::<u32>() {
            return value;
        }
    }
    if matches!(check.protocol, TunnelProtocol::Esp) {
        if let Some(seed) = esp_shared_seed(check) {
            return stable_tunnel_id(&seed);
        }
    }
    stable_tunnel_id(&check.id)
}

fn stable_tunnel_id(seed: &str) -> u32 {
    let mut hash = 2166136261_u32;
    for byte in seed.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16777619);
    }
    if hash == 0 { 1 } else { hash }
}

fn esp_shared_seed(check: &TunnelCheck) -> Option<String> {
    let local_inner = resolve_configured_inner_local_ip(check)?;
    let remote_inner = check.inner_probe.as_deref()?.trim();
    if remote_inner.is_empty() {
        return None;
    }
    let (first, second) = normalize_ip_pair(&local_inner, remote_inner)?;
    Some(format!("esp|{first}|{second}"))
}

fn resolve_configured_inner_local_ip(check: &TunnelCheck) -> Option<String> {
    if let Some(cidr) = check.inner_local_cidr.as_deref() {
        return extract_ip_from_cidr(cidr);
    }
    derive_inner_local_cidr(check).and_then(|cidr| extract_ip_from_cidr(&cidr))
}

fn extract_ip_from_cidr(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let ip = trimmed.split('/').next()?.trim().parse::<IpAddr>().ok()?;
    Some(ip.to_string())
}

fn normalize_ip_pair(left: &str, right: &str) -> Option<(String, String)> {
    let left_ip = left.trim().parse::<IpAddr>().ok()?;
    let right_ip = right.trim().parse::<IpAddr>().ok()?;
    if ip_sort_key(&left_ip) <= ip_sort_key(&right_ip) {
        Some((left_ip.to_string(), right_ip.to_string()))
    } else {
        Some((right_ip.to_string(), left_ip.to_string()))
    }
}

fn ip_sort_key(ip: &IpAddr) -> (u8, Vec<u8>) {
    match ip {
        IpAddr::V4(address) => (4, address.octets().to_vec()),
        IpAddr::V6(address) => (6, address.octets().to_vec()),
    }
}

fn read_xfrm_interface_if_id(interface: &str) -> Result<Option<u32>, String> {
    let output = run_command_capture("ip", &["-d", "link", "show", interface])?;
    for line in output.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        for window in parts.windows(2) {
            if window[0] == "if_id" {
                let raw = window[1].trim().trim_end_matches(',');
                if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
                    if let Ok(value) = u32::from_str_radix(hex, 16) {
                        return Ok(Some(value));
                    }
                } else if let Ok(value) = raw.parse::<u32>() {
                    return Ok(Some(value));
                }
            }
        }
    }
    Ok(None)
}

fn apply_managed_tunnel_runtime_config(
    check: &TunnelCheck,
    interface: &str,
    details: &mut BTreeMap<String, Value>,
) -> Result<(), String> {
    apply_tunnel_mtu(check, interface, details)?;
    if let Some(args) = build_outer_packet_update(check, interface) {
        run_command_owned("ip", args).map_err(|error| format!("Failed to apply outer packet settings on {interface}: {error}"))?;
        details.insert("outer_ttl".to_string(), json!(check.ttl));
        details.insert("outer_traffic_class".to_string(), json!(check.traffic_class));
    }
    if matches!(check.protocol, TunnelProtocol::Vxlan | TunnelProtocol::Geneve) {
        details.insert("vni".to_string(), json!(check.vni.unwrap_or(42)));
        details.insert("encryption".to_string(), json!("none; use WireGuard or ESP for encryption"));
    }
    if matches!(check.protocol, TunnelProtocol::Encap) {
        configure_encap_receive_port(check, details)?;
    }
    if matches!(check.protocol, TunnelProtocol::Wireguard) {
        configure_wireguard_interface(check, interface, details)?;
    }
    ensure_tunnel_inner_address(check, interface, details)?;
    if matches!(check.protocol, TunnelProtocol::Esp) {
        configure_esp_xfrm_tunnel(check, interface, details)?;
    }
    Ok(())
}

fn configure_esp_xfrm_tunnel(
    check: &TunnelCheck,
    interface: &str,
    details: &mut BTreeMap<String, Value>,
) -> Result<(), String> {
    let remote_outer = check
        .outer_remote
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "ESP tunnel creation needs Outer Remote set to the other server IP".to_string())?;
    let local_outer = resolve_effective_local_outer(check)?;
    let remote_inner = check
        .inner_probe
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "ESP tunnel creation needs Inner Probe set to the remote tunnel IP".to_string())?;
    let local_inner = resolve_live_interface_inner_ip(interface, effective_probe_ip_version(remote_inner, check.ip_version))?
        .ok_or_else(|| format!("ESP tunnel interface {interface} has no local inner IP configured"))?;
    let if_id = resolve_xfrm_if_id(check);
    let reqid = resolve_esp_reqid(check);
    let outbound_spi = resolve_esp_spi(&local_outer, remote_outer, if_id, "out");
    let inbound_spi = resolve_esp_spi(remote_outer, &local_outer, if_id, "out");
    let outbound_crypto = derive_esp_state_crypto(check, &local_outer, remote_outer)?;
    let inbound_crypto = derive_esp_state_crypto(check, remote_outer, &local_outer)?;
    let inner_wildcard = if local_inner.contains(':') { "::/0" } else { "0.0.0.0/0" };

    // Preserve live SAs, replay counters, and protected traffic when unchanged.
    // Reading only these exact states also works after a panel service restart.
    if esp_state_configuration_matches(&local_outer, remote_outer, outbound_spi, reqid, if_id, &outbound_crypto)
        && esp_state_configuration_matches(remote_outer, &local_outer, inbound_spi, reqid, if_id, &inbound_crypto)
        && esp_policy_exists("out", &local_inner, remote_inner, if_id, reqid)
        && esp_policy_exists("in", remote_inner, &local_inner, if_id, reqid)
        && esp_policy_exists("fwd", remote_inner, &local_inner, if_id, reqid) {
        details.insert("esp_configuration_reused".to_string(), json!(true));
        details.insert("esp_if_id".to_string(), json!(format!("0x{if_id:x}")));
        details.insert("esp_reqid".to_string(), json!(reqid));
        return Ok(());
    }

    // Static AES-GCM cannot safely restart its nonce sequence after SA loss.
    // Never remove an existing legacy SA here or recreate it with the same key.
    ensure_esp_creation_safe(check)?;

    cleanup_esp_xfrm_runtime(
        &local_outer,
        remote_outer,
        &local_inner,
        remote_inner,
        reqid,
        if_id,
        outbound_spi,
        inbound_spi,
    );

    for state in [
        build_esp_state_add_command(&local_outer, remote_outer, outbound_spi, reqid, if_id, inner_wildcard, &outbound_crypto),
        build_esp_state_add_command(remote_outer, &local_outer, inbound_spi, reqid, if_id, inner_wildcard, &inbound_crypto),
    ] {
        run_command_owned("ip", state)
            .map_err(|error| format!("failed to configure ESP XFRM state on {interface}: {error}"))?;
    }

    let local_selector = host_selector(&local_inner);
    let remote_selector = host_selector(remote_inner);
    for policy in [
        vec![
            "xfrm".to_string(),
            "policy".to_string(),
            "add".to_string(),
            "dir".to_string(),
            "out".to_string(),
            "if_id".to_string(),
            format!("0x{if_id:x}"),
            "src".to_string(),
            local_selector.clone(),
            "dst".to_string(),
            remote_selector.clone(),
            "tmpl".to_string(),
            "src".to_string(),
            local_outer.clone(),
            "dst".to_string(),
            remote_outer.to_string(),
            "proto".to_string(),
            "esp".to_string(),
            "reqid".to_string(),
            reqid.to_string(),
            "mode".to_string(),
            "tunnel".to_string(),
        ],
        vec![
            "xfrm".to_string(),
            "policy".to_string(),
            "add".to_string(),
            "dir".to_string(),
            "in".to_string(),
            "if_id".to_string(),
            format!("0x{if_id:x}"),
            "src".to_string(),
            remote_selector.clone(),
            "dst".to_string(),
            local_selector.clone(),
            "tmpl".to_string(),
            "src".to_string(),
            remote_outer.to_string(),
            "dst".to_string(),
            local_outer.clone(),
            "proto".to_string(),
            "esp".to_string(),
            "reqid".to_string(),
            reqid.to_string(),
            "mode".to_string(),
            "tunnel".to_string(),
        ],
        vec![
            "xfrm".to_string(),
            "policy".to_string(),
            "add".to_string(),
            "dir".to_string(),
            "fwd".to_string(),
            "if_id".to_string(),
            format!("0x{if_id:x}"),
            "src".to_string(),
            remote_selector.clone(),
            "dst".to_string(),
            local_selector.clone(),
            "tmpl".to_string(),
            "src".to_string(),
            remote_outer.to_string(),
            "dst".to_string(),
            local_outer.clone(),
            "proto".to_string(),
            "esp".to_string(),
            "reqid".to_string(),
            reqid.to_string(),
            "mode".to_string(),
            "tunnel".to_string(),
        ],
    ] {
        run_command_owned("ip", policy)
            .map_err(|error| format!("failed to configure ESP XFRM policy on {interface}: {error}"))?;
    }

    details.insert("esp_if_id".to_string(), json!(format!("0x{if_id:x}")));
    details.insert("esp_reqid".to_string(), json!(reqid));
    details.insert("esp_local_outer".to_string(), json!(local_outer));
    details.insert("esp_remote_outer".to_string(), json!(remote_outer));
    details.insert("esp_local_inner".to_string(), json!(local_inner));
    details.insert("esp_remote_inner".to_string(), json!(remote_inner));
    Ok(())
}

fn resolve_effective_local_outer(check: &TunnelCheck) -> Result<String, String> {
    if let Some(local_outer) = check
        .local_outer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(local_outer.to_string());
    }
    if let Some(remote_outer) = check
        .outer_remote
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let args = if tunnel_outer_uses_ipv6(check) {
            vec!["-6", "-o", "route", "get", remote_outer]
        } else {
            vec!["-o", "route", "get", remote_outer]
        };
        if let Ok(output) = run_command_capture("ip", &args) {
            if let Some(src) = parse_route_output_for_src(&output) {
                return Ok(src);
            }
        }
    }
    if let Some(parent) = resolve_parent_interface(check).ok() {
        let args = ["-o", "addr", "show", "dev", parent.as_str(), "scope", "global"];
        if let Ok(output) = run_command_capture("ip", &args) {
            for line in output.lines() {
                let parts = line.split_whitespace().collect::<Vec<_>>();
                if parts.len() >= 4 {
                    let family = parts[2];
                    let raw_ip = parts[3].split('/').next().unwrap_or("").trim();
                    if raw_ip.is_empty() {
                        continue;
                    }
                    let wants_v6 = tunnel_outer_uses_ipv6(check);
                    if (wants_v6 && family == "inet6") || (!wants_v6 && family == "inet") {
                        return Ok(raw_ip.to_string());
                    }
                }
            }
        }
    }
    Err("failed to determine the local outer IP for ESP/XFRM".to_string())
}

fn parse_route_output_for_src(output: &str) -> Option<String> {
    for line in output.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        for window in parts.windows(2) {
            if window[0] == "src" && !window[1].trim().is_empty() {
                return Some(window[1].trim().to_string());
            }
        }
    }
    None
}

fn resolve_live_interface_inner_ip(interface: &str, family: IpVersion) -> Result<Option<String>, String> {
    let output = run_command_capture("ip", &["-o", "addr", "show", "dev", interface])?;
    for line in output.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 4 {
            continue;
        }
        match (family, parts[2]) {
            (IpVersion::Ipv4 | IpVersion::Any, "inet") => {
                let value = parts[3].split('/').next().unwrap_or("").trim();
                if !value.is_empty() {
                    return Ok(Some(value.to_string()));
                }
            }
            (IpVersion::Ipv6 | IpVersion::Any, "inet6") => {
                let value = parts[3].split('/').next().unwrap_or("").trim().to_ascii_lowercase();
                if !value.is_empty() && !value.starts_with("fe80:") {
                    return Ok(Some(value));
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

fn resolve_esp_reqid(check: &TunnelCheck) -> u32 {
    let seed = esp_shared_seed(check).unwrap_or_else(|| format!("esp|{}", check.id));
    (stable_tunnel_id(&format!("reqid|{seed}")) & 0xffff).max(1)
}

fn resolve_esp_spi(local_outer: &str, remote_outer: &str, if_id: u32, direction: &str) -> u32 {
    (stable_tunnel_id(&format!("spi|{direction}|{local_outer}|{remote_outer}|{if_id:x}")) & 0x0fff_ffff)
        .max(0x100)
}

#[derive(Debug, PartialEq, Eq)]
enum EspStateCrypto {
    LegacyGcm { key: String },
    CbcHmacSha256 { encryption_key: String, authentication_key: String },
}

fn ensure_esp_creation_safe(check: &TunnelCheck) -> Result<(), String> {
    if check.esp_cipher == EspCipher::LegacyAesGcm {
        return Err("Static AES-GCM ESP cannot be safely created or recreated after SA loss/reboot because its nonce may repeat (RFC 4106). Existing exact live states are preserved. Configure dynamic IKE externally and select monitoring only, or coordinate both peers to AES-CBC/HMAC-SHA256 + HKDF with a new random secret, or WireGuard.".to_string());
    }
    Ok(())
}

fn derive_esp_state_crypto(check: &TunnelCheck, source: &str, destination: &str) -> Result<EspStateCrypto, String> {
    if check.esp_cipher == EspCipher::LegacyAesGcm {
        return derive_esp_key_hex(check, source, destination).map(|key| EspStateCrypto::LegacyGcm { key });
    }
    if check.esp_key_derivation != EspKeyDerivation::HkdfSha256 {
        return Err("AES-CBC/HMAC-SHA256 ESP requires HKDF-SHA256 derivation.".to_string());
    }
    let secret = check.tunnel_key.as_deref().ok_or_else(|| "ESP requires a random shared secret.".to_string())?;
    let seed = esp_shared_seed(check).ok_or_else(|| "ESP key derivation requires both inner peer IPs.".to_string())?;
    let source = source.parse::<IpAddr>().map_err(|_| "ESP source must be an IP literal.".to_string())?;
    let destination = destination.parse::<IpAddr>().map_err(|_| "ESP destination must be an IP literal.".to_string())?;
    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"iMonitor ESP CBC HMAC v3");
    let prk = salt.extract(secret.as_bytes());
    let derive = |role: &str| -> Result<String, String> {
        let context = format!("{seed}|src:{source}|dst:{destination}|{role}");
        let info = [context.as_bytes()];
        let key = prk.expand(&info, ring::hkdf::HKDF_SHA256).map_err(|_| "ESP key derivation failed.".to_string())?;
        let mut bytes = [0_u8; 32];
        key.fill(&mut bytes).map_err(|_| "ESP key derivation failed.".to_string())?;
        Ok(format!("0x{}", bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()))
    };
    // AES-256 encryption and HMAC-SHA256 authentication use independently
    // expanded keys, distinct for each traffic direction. Linux supplies IVs.
    Ok(EspStateCrypto::CbcHmacSha256 { encryption_key: derive("encryption")?, authentication_key: derive("authentication")? })
}

fn build_esp_state_add_command(source: &str, destination: &str, spi: u32, reqid: u32, if_id: u32, inner_wildcard: &str, crypto: &EspStateCrypto) -> Vec<String> {
    let mut args = string_args(&["xfrm", "state", "add", "src", source, "dst", destination, "proto", "esp", "spi", &format!("0x{spi:x}"), "reqid", &reqid.to_string(), "mode", "tunnel"]);
    match crypto {
        EspStateCrypto::LegacyGcm { key } => args.extend(string_args(&["aead", "rfc4106(gcm(aes))", key, "128"])),
        EspStateCrypto::CbcHmacSha256 { encryption_key, authentication_key } => args.extend(string_args(&["auth-trunc", "hmac(sha256)", authentication_key, "128", "enc", "cbc(aes)", encryption_key])),
    }
    args.extend(string_args(&["if_id", &format!("0x{if_id:x}"), "sel", "src", inner_wildcard, "dst", inner_wildcard]));
    args
}

fn derive_esp_key_hex(check: &TunnelCheck, source: &str, destination: &str) -> Result<String, String> {
    let seed = esp_shared_seed(check).unwrap_or_else(|| format!("esp|{}", check.id));
    if check.esp_key_derivation == EspKeyDerivation::HkdfSha256 {
        let secret = check.tunnel_key.as_deref().ok_or_else(|| "Secure ESP requires a shared secret.".to_string())?;
        let source = source.parse::<IpAddr>().map(|ip| ip.to_string()).unwrap_or_else(|_| source.to_string());
        let destination = destination.parse::<IpAddr>().map(|ip| ip.to_string()).unwrap_or_else(|_| destination.to_string());
        let direction = format!("{seed}|src:{source}|dst:{destination}");
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"iMonitor ESP HKDF v2");
        let prk = salt.extract(secret.as_bytes());
        let info = [direction.as_bytes()];
        let key = prk.expand(&info, ring::hkdf::HKDF_SHA256).map_err(|_| "ESP key derivation failed.".to_string())?;
        let mut derived = [0_u8; 32];
        key.fill(&mut derived).map_err(|_| "ESP key derivation failed.".to_string())?;
        // Retained only to identify and reuse a saved live GCM state. Direction
        // binding does not prevent nonce reuse after state recreation/reboot.
        return Ok(format!("0x{}", derived[..20].iter().map(|byte| format!("{byte:02x}")).collect::<String>()));
    }
    let mut bytes = Vec::with_capacity(20);
    for index in 0..5 {
        let chunk = stable_tunnel_id(&format!("key|{seed}|{index}")).to_be_bytes();
        bytes.extend_from_slice(&chunk);
    }
    let body = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("0x{body}"))
}

fn host_selector(value: &str) -> String {
    if value.contains(':') {
        format!("{value}/128")
    } else {
        format!("{value}/32")
    }
}

fn esp_state_configuration_matches(source: &str, destination: &str, spi: u32, reqid: u32, if_id: u32, crypto: &EspStateCrypto) -> bool {
    let spi_text = format!("0x{spi:x}");
    let Ok(output) = run_command_capture("ip", &["xfrm", "state", "get", "src", source, "dst", destination, "proto", "esp", "spi", &spi_text]) else { return false; };
    esp_state_output_matches(&output, reqid, if_id, crypto)
}

fn esp_state_output_matches(output: &str, reqid: u32, if_id: u32, crypto: &EspStateCrypto) -> bool {
    let words = output.split_whitespace().collect::<Vec<_>>();
    let expected_reqid = reqid.to_string();
    let parse_number = |raw: &str| raw.strip_prefix("0x").map_or_else(|| raw.parse::<u32>().ok(), |hex| u32::from_str_radix(hex, 16).ok());
    let crypto_matches = match crypto {
        EspStateCrypto::LegacyGcm { key } => words.windows(4).any(|part| part[0] == "aead" && part[1] == "rfc4106(gcm(aes))" && part[2].eq_ignore_ascii_case(key) && part[3] == "128"),
        EspStateCrypto::CbcHmacSha256 { encryption_key, authentication_key } =>
            words.windows(3).any(|part| part[0] == "enc" && part[1] == "cbc(aes)" && part[2].eq_ignore_ascii_case(encryption_key))
            && words.windows(4).any(|part| part[0] == "auth-trunc" && part[1] == "hmac(sha256)" && part[2].eq_ignore_ascii_case(authentication_key) && part[3] == "128"),
    };
    crypto_matches && words.windows(2).any(|pair| pair[0] == "reqid" && pair[1] == expected_reqid)
        && words.windows(2).any(|pair| pair[0] == "if_id" && parse_number(pair[1]) == Some(if_id))
}

fn esp_policy_exists(direction: &str, source: &str, destination: &str, if_id: u32, reqid: u32) -> bool {
    let local = host_selector(source);
    let remote = host_selector(destination);
    let id = format!("0x{if_id:x}");
    let Ok(output) = run_command_capture("ip", &["xfrm", "policy", "get", "dir", direction, "src", &local, "dst", &remote, "if_id", &id]) else { return false; };
    let words = output.split_whitespace().collect::<Vec<_>>();
    words.windows(2).any(|part| part == ["proto", "esp"])
        && words.windows(2).any(|part| part[0] == "reqid" && part[1] == reqid.to_string())
}

fn cleanup_esp_xfrm_runtime(
    local_outer: &str,
    remote_outer: &str,
    local_inner: &str,
    remote_inner: &str,
    reqid: u32,
    if_id: u32,
    outbound_spi: u32,
    inbound_spi: u32,
) {
    let local_selector = host_selector(local_inner);
    let remote_selector = host_selector(remote_inner);
    let cleanup_commands: Vec<Vec<String>> = vec![
        vec![
            "xfrm".to_string(),
            "policy".to_string(),
            "delete".to_string(),
            "dir".to_string(),
            "out".to_string(),
            "if_id".to_string(),
            format!("0x{if_id:x}"),
            "src".to_string(),
            local_selector.clone(),
            "dst".to_string(),
            remote_selector.clone(),
        ],
        vec![
            "xfrm".to_string(),
            "policy".to_string(),
            "delete".to_string(),
            "dir".to_string(),
            "in".to_string(),
            "if_id".to_string(),
            format!("0x{if_id:x}"),
            "src".to_string(),
            remote_selector.clone(),
            "dst".to_string(),
            local_selector.clone(),
        ],
        vec![
            "xfrm".to_string(),
            "policy".to_string(),
            "delete".to_string(),
            "dir".to_string(),
            "fwd".to_string(),
            "if_id".to_string(),
            format!("0x{if_id:x}"),
            "src".to_string(),
            remote_selector.clone(),
            "dst".to_string(),
            local_selector.clone(),
        ],
        vec![
            "xfrm".to_string(),
            "state".to_string(),
            "delete".to_string(),
            "src".to_string(),
            local_outer.to_string(),
            "dst".to_string(),
            remote_outer.to_string(),
            "proto".to_string(),
            "esp".to_string(),
            "spi".to_string(),
            format!("0x{outbound_spi:x}"),
        ],
        vec![
            "xfrm".to_string(),
            "state".to_string(),
            "delete".to_string(),
            "src".to_string(),
            remote_outer.to_string(),
            "dst".to_string(),
            local_outer.to_string(),
            "proto".to_string(),
            "esp".to_string(),
            "spi".to_string(),
            format!("0x{inbound_spi:x}"),
        ],
    ];
    for command in cleanup_commands {
        let _ = run_command_owned("ip", command);
    }
    let _ = reqid;
}

fn configure_encap_receive_port(
    check: &TunnelCheck,
    details: &mut BTreeMap<String, Value>,
) -> Result<(), String> {
    let port = check.transport_port.unwrap_or(5555).to_string();
    let existing = run_command_capture("ip", &["fou", "show"])?;
    if gue_port_exists(&existing, check.transport_port.unwrap_or(5555)) {
        details.insert("encap_receive_port".to_string(), json!(port));
        details.insert("encap_receive_port_reused".to_string(), json!(true));
        return Ok(());
    }
    run_command_owned(
        "ip",
        vec![
            "fou".to_string(),
            "add".to_string(),
            "port".to_string(),
            port.clone(),
            "gue".to_string(),
        ],
    )
    .map_err(|error| format!("failed to configure GUE receive port {port}: {error}"))?;
    details.insert("encap_receive_port".to_string(), json!(port));
    details.insert("encap_receive_port_reused".to_string(), json!(false));
    Ok(())
}

fn gue_port_exists(output: &str, port: u16) -> bool {
    output.lines().any(|line| {
        let words = line.split_whitespace().collect::<Vec<_>>();
        words.contains(&"gue") && !words.contains(&"-6")
            && words.windows(2).any(|pair| pair[0] == "port" && pair[1].parse::<u16>() == Ok(port))
    })
}

fn configure_wireguard_interface(
    check: &TunnelCheck,
    interface: &str,
    details: &mut BTreeMap<String, Value>,
) -> Result<(), String> {
    let private_key = check
        .wireguard_private_key
        .as_deref()
        .ok_or_else(|| "WireGuard tunnel creation needs a private key".to_string())?;
    let peer_public_key = check
        .wireguard_peer_public_key
        .as_deref()
        .ok_or_else(|| "WireGuard tunnel creation needs a peer public key".to_string())?;
    let allowed_ips = check
        .wireguard_allowed_ips
        .as_deref()
        .unwrap_or("0.0.0.0/0,::/0");
    let endpoint_host = check.outer_remote.as_deref().ok_or_else(|| {
        "WireGuard tunnel creation needs Outer Remote set to the peer endpoint".to_string()
    })?;
    let endpoint_port = check.transport_port.ok_or_else(|| {
        "WireGuard tunnel creation needs a transport port for the peer endpoint".to_string()
    })?;

    let mut config_text = format!("[Interface]\nPrivateKey = {}\n", private_key.trim());
    if let Some(listen_port) = check.listen_port {
        config_text.push_str(&format!("ListenPort = {listen_port}\n"));
    }
    config_text.push_str("\n[Peer]\n");
    config_text.push_str(&format!("PublicKey = {}\n", peer_public_key.trim()));
    if let Some(preshared_key) = check.wireguard_preshared_key.as_deref() {
        config_text.push_str(&format!("PresharedKey = {}\n", preshared_key.trim()));
    }
    config_text.push_str(&format!("AllowedIPs = {}\n", allowed_ips.trim()));
    config_text.push_str(&format!("Endpoint = {}\n", wireguard_endpoint(endpoint_host, endpoint_port)));
    config_text.push_str("PersistentKeepalive = 25\n");

    let temp_dir = wireguard_config_directory();
    let temp_path = temp_dir.join(format!(
        "iranmonitor-wireguard-{}-{}.conf",
        interface,
        unix_now()
    ));
    fs::write(&temp_path, config_text)
        .map_err(|error| format!("failed to write temporary WireGuard config: {error}"))?;
    #[cfg(unix)]
    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("failed to secure temporary WireGuard config: {error}"))?;
    let result = run_command_owned(
        "wg",
        vec![
            "syncconf".to_string(),
            interface.to_string(),
            temp_path.to_string_lossy().to_string(),
        ],
    )
    .map_err(|error| format!("failed to configure WireGuard interface {interface}: {error}"));
    let _ = fs::remove_file(&temp_path);
    result?;

    details.insert("wireguard_configured".to_string(), json!(true));
    details.insert(
        "wireguard_config_path".to_string(),
        json!(temp_dir.to_string_lossy().to_string()),
    );
    Ok(())
}

fn wireguard_endpoint(host: &str, port: u16) -> String {
    let host = host.trim();
    if host.contains(':') && !host.starts_with('[') { format!("[{host}]:{port}") }
    else { format!("{host}:{port}") }
}

fn wireguard_config_directory() -> PathBuf {
    let preferred = PathBuf::from("/etc/wireguard");
    if preferred.exists() {
        return preferred;
    }
    if fs::create_dir_all(&preferred).is_ok() {
        return preferred;
    }
    if let Ok(current) = std::env::current_dir() {
        return current;
    }
    PathBuf::from("/tmp")
}

fn ensure_tunnel_inner_address(
    check: &TunnelCheck,
    interface: &str,
    details: &mut BTreeMap<String, Value>,
) -> Result<(), String> {
    if !check.auto_create_interface { return Ok(()); }
    apply_tunnel_mtu(check, interface, details)?;
    let resolved_cidr = if let Some(cidr) = check.inner_local_cidr.as_ref() {
        details.insert("managed_inner_address_source".to_string(), json!("configured"));
        Some(normalize_inner_local_address(cidr))
    } else if let Some(derived) = derive_inner_local_cidr(check) {
        details.insert(
            "managed_inner_address_source".to_string(),
            json!("derived_from_inner_probe"),
        );
        Some(derived)
    } else {
        None
    };

    if let Some(cidr) = resolved_cidr {
        if tunnel_uses_peer_addressing(check) {
            let peer = check
                .inner_probe
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    format!(
                        "managed tunnel {interface} needs Inner Probe set so its point-to-point peer address can be configured"
                    )
                })?;
            let local_ip = cidr
                .split('/')
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    format!("failed to parse local tunnel address from {cidr} for {interface}")
                })?;
            run_command_owned(
                "ip",
                vec![
                    "address".to_string(),
                    "replace".to_string(),
                    local_ip.to_string(),
                    "peer".to_string(),
                    peer.to_string(),
                    "dev".to_string(),
                    interface.to_string(),
                ],
            )
            .map_err(|error| {
                format!(
                    "failed to configure point-to-point tunnel address {local_ip} peer {peer} on {interface}: {error}"
                )
            })?;
            details.insert(
                "managed_inner_address_mode".to_string(),
                json!("point_to_point_peer"),
            );
        } else {
            run_command_owned(
                "ip",
                vec![
                    "address".to_string(),
                    "replace".to_string(),
                    cidr.clone(),
                    "dev".to_string(),
                    interface.to_string(),
                ],
            )
            .map_err(|error| {
                format!("failed to configure inner tunnel address {cidr} on {interface}: {error}")
            })?;
        }
        details.insert("managed_inner_local_cidr".to_string(), json!(cidr));
        if !tunnel_uses_peer_addressing(check) {
            ensure_tunnel_peer_route(check, interface, details)?;
        }
        return Ok(());
    }

    if interface_has_usable_inner_address(interface)? {
        details.insert(
            "managed_inner_address_source".to_string(),
            json!("existing_on_interface"),
        );
        return Ok(());
    }

    if check.inner_probe.is_some()
        && matches!(
            check.protocol,
            TunnelProtocol::Gre
                | TunnelProtocol::Gretap
                | TunnelProtocol::Vxlan
                | TunnelProtocol::Geneve
                | TunnelProtocol::Ipv4IpInIp
                | TunnelProtocol::Ipip
                | TunnelProtocol::Ipv6Encapsulation
                | TunnelProtocol::Etherip
                | TunnelProtocol::Encap
                | TunnelProtocol::L2tp
                | TunnelProtocol::Esp
                | TunnelProtocol::Wireguard
        )
    {
        return Err(
            "managed tunnel interface exists but has no usable local inner address; set Tunnel Address / CIDR or use a peer Inner Probe that lets IranMonitor derive the local /30 or /127 automatically"
                .to_string(),
        );
    }

    Ok(())
}

fn tunnel_uses_peer_addressing(check: &TunnelCheck) -> bool {
    matches!(
        check.protocol,
        TunnelProtocol::L2tp | TunnelProtocol::Ssh | TunnelProtocol::ReverseSsh
    )
}

fn ensure_tunnel_peer_route(
    check: &TunnelCheck,
    interface: &str,
    details: &mut BTreeMap<String, Value>,
) -> Result<(), String> {
    let Some(inner_probe) = check.inner_probe.as_deref() else {
        return Ok(());
    };
    let target = inner_probe.trim();
    if target.is_empty() {
        return Ok(());
    }

    let (route_target, route_family): (String, &str) = if let Ok(ipv6) = target.parse::<Ipv6Addr>() {
        (format!("{ipv6}/128"), "-6")
    } else if let Ok(ipv4) = target.parse::<Ipv4Addr>() {
        (format!("{ipv4}/32"), "-4")
    } else {
        return Ok(());
    };

    run_command_owned(
        "ip",
        vec![
            route_family.to_string(),
            "route".to_string(),
            "replace".to_string(),
            route_target.clone(),
            "dev".to_string(),
            interface.to_string(),
        ],
    )
    .map_err(|error| {
        format!("failed to install inner peer route {route_target} on {interface}: {error}")
    })?;
    details.insert("managed_inner_peer_route".to_string(), json!(route_target));
    Ok(())
}

fn derive_inner_local_cidr(check: &TunnelCheck) -> Option<String> {
    let inner_probe = check.inner_probe.as_deref()?.trim();
    if let Ok(ipv4) = inner_probe.parse::<Ipv4Addr>() {
        let raw = u32::from(ipv4);
        let network = raw & !0b11;
        let host_a = network + 1;
        let host_b = network + 2;
        if raw == host_a {
            return Some(format!("{}/30", Ipv4Addr::from(host_b)));
        }
        if raw == host_b {
            return Some(format!("{}/30", Ipv4Addr::from(host_a)));
        }
    }
    if let Ok(ipv6) = inner_probe.parse::<Ipv6Addr>() {
        let raw = u128::from(ipv6);
        let sibling = if raw & 1 == 0 {
            raw.saturating_add(1)
        } else {
            raw.saturating_sub(1)
        };
        return Some(format!("{}/127", Ipv6Addr::from(sibling)));
    }
    None
}

fn interface_has_usable_inner_address(interface: &str) -> Result<bool, String> {
    let output = run_command_capture("ip", &["-o", "addr", "show", "dev", interface])?;
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        match parts[2] {
            "inet" => return Ok(true),
            "inet6" => {
                let address = parts[3]
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                if !address.starts_with("fe80:") {
                    return Ok(true);
                }
            }
            _ => {}
        }
    }
    Ok(false)
}

fn update_tunnel_counter_state(
    state: &Arc<Mutex<PersistedState>>,
    check_id: &str,
    counters: &InterfaceCounters,
    observed_at: u64,
) -> Result<Option<TunnelCounterState>, String> {
    let mut guard = state
        .lock()
        .map_err(|_| "failed to lock tunnel state".to_string())?;
    let previous = guard.tunnel_counters.get(check_id).cloned();
    guard.tunnel_counters.insert(
        check_id.to_string(),
        TunnelCounterState {
            rx_packets: counters.rx_packets,
            tx_packets: counters.tx_packets,
            observed_at_unix: observed_at,
        },
    );
    Ok(previous)
}

fn operstate_matches_expected(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
        || (expected.eq_ignore_ascii_case("up") && actual.eq_ignore_ascii_case("unknown"))
}

fn run_esp_tunnel(
    check: &TunnelCheck,
    state: &Arc<Mutex<PersistedState>>,
    observed_at: u64,
    started: Instant,
    mut details: BTreeMap<String, Value>,
) -> CheckResult {
    details.insert("esp_key_derivation".to_string(), json!(match check.esp_key_derivation {
        EspKeyDerivation::Legacy => "legacy", EspKeyDerivation::HkdfSha256 => "hkdf_sha256",
    }));
    details.insert("esp_cipher".to_string(), json!(check.esp_cipher));
    if check.esp_cipher == EspCipher::LegacyAesGcm {
        details.insert("security_warning".to_string(), json!("Legacy static AES-GCM requires dynamic IKE management. Exact live states are preserved, but cannot be recreated safely after SA loss/reboot. Coordinate both peers to WireGuard or AES-CBC/HMAC-SHA256 with HKDF and a new random secret. Legacy predictable derivation must also be replaced."));
    } else {
        details.insert("esp_key_management".to_string(), json!("manual shared secret; no automatic rekey or forward secrecy; WireGuard is the recommended Secure profile"));
    }
    if let Some(interface) = &check.interface {
        details.insert("interface".to_string(), json!(interface));
        details.insert(
            "auto_create_interface".to_string(),
            json!(check.auto_create_interface),
        );
        if let Err(error) = ensure_managed_tunnel_interface(check, &mut details) {
            return make_result(
                &check.id,
                "tunnel",
                CheckStatus::Down,
                error,
                observed_at,
                started,
                None,
                Some(check.ip_version),
                Some(interface.clone()),
                details,
            );
        }
    }

    let xfrm_output = match run_command_capture("ip", &["xfrm", "state"]) {
        Ok(output) => output,
        Err(error) => {
            return make_result(
                &check.id,
                "tunnel",
                CheckStatus::Down,
                format!("failed to inspect xfrm state with iproute2: {error}"),
                observed_at,
                started,
                None,
                Some(check.ip_version),
                None,
                details,
            )
        }
    };

    let state_present = xfrm_state_matches(&xfrm_output, check.local_outer.as_deref(), check.outer_remote.as_deref());

    details.insert("xfrm_state_present".to_string(), json!(state_present));
    if let Some(local_outer) = &check.local_outer {
        details.insert("local_outer".to_string(), json!(local_outer));
    }
    if let Some(outer_remote) = &check.outer_remote {
        details.insert("outer_remote".to_string(), json!(outer_remote));
    }

    if let Some(interface) = &check.interface {
        details.insert("interface".to_string(), json!(interface));
        if let Ok(counters) = read_interface_counters(interface) {
            let previous = update_tunnel_counter_state(state, &check.id, &counters, observed_at)
                .unwrap_or(None);
            let rx_delta = previous
                .as_ref()
                .map(|previous| counters.rx_packets.saturating_sub(previous.rx_packets))
                .unwrap_or(0);
            let tx_delta = previous
                .as_ref()
                .map(|previous| counters.tx_packets.saturating_sub(previous.tx_packets))
                .unwrap_or(0);

            details.insert("rx_packets".to_string(), json!(counters.rx_packets));
            details.insert("tx_packets".to_string(), json!(counters.tx_packets));
            details.insert("rx_packets_delta".to_string(), json!(rx_delta));
            details.insert("tx_packets_delta".to_string(), json!(tx_delta));
        }
    }

    if !state_present {
        return make_result(
            &check.id,
            "tunnel",
            CheckStatus::Down,
            "matching xfrm state was not found",
            observed_at,
            started,
            None,
            Some(check.ip_version),
            check.outer_remote.clone(),
            details,
        );
    }

    if let Some(inner_probe) = &check.inner_probe {
        details.insert("inner_probe".to_string(), json!(inner_probe));
        if let Some(interface) = &check.interface {
            details.insert("inner_probe_bind".to_string(), json!(interface));
        }
        match run_ping(
            inner_probe,
            effective_probe_ip_version(inner_probe, check.ip_version),
            check.timeout_ms,
            check.interface
                .as_deref()
                .or(check.source_interface.as_deref()),
        ) {
            Ok(outcome) => {
                if let Some(latency_ms) = outcome.latency_ms {
                    details.insert("inner_probe_rtt_ms".to_string(), json!(latency_ms));
                }
                details.insert("inner_probe_output".to_string(), json!(outcome.summary));
                return make_result(
                    &check.id,
                    "tunnel",
                    CheckStatus::Up,
                    "esp xfrm state found and protected probe succeeded",
                    observed_at,
                    started,
                    outcome.latency_ms,
                    Some(check.ip_version),
                    Some(inner_probe.clone()),
                    details,
                );
            }
            Err(error) => {
                return make_result(
                    &check.id,
                    "tunnel",
                    CheckStatus::Down,
                    format!("xfrm state found but protected probe failed: {error}"),
                    observed_at,
                    started,
                    None,
                    Some(check.ip_version),
                    Some(inner_probe.clone()),
                    details,
                )
            }
        }
    }

    make_result(
        &check.id,
        "tunnel",
        CheckStatus::Degraded,
        "matching xfrm state found; add an inner tunnel probe to verify protected traffic",
        observed_at,
        started,
        Some(elapsed_ms(started)),
        Some(check.ip_version),
        check.outer_remote.clone(),
        details,
    )
}

fn xfrm_state_matches(output: &str, expected_source: Option<&str>, expected_destination: Option<&str>) -> bool {
    let equal_address = |actual: &str, expected: &str| match (actual.parse::<IpAddr>(), expected.parse::<IpAddr>()) {
        (Ok(actual), Ok(expected)) => actual == expected,
        _ => actual.eq_ignore_ascii_case(expected),
    };
    let mut matching_endpoints = false;
    for line in output.lines() {
        let words = line.split_whitespace().collect::<Vec<_>>();
        if words.first() == Some(&"src") {
            let source = words.windows(2).find(|pair| pair[0] == "src").map(|pair| pair[1]);
            let destination = words.windows(2).find(|pair| pair[0] == "dst").map(|pair| pair[1]);
            matching_endpoints = source.is_some_and(|source| expected_source.map_or(true, |expected| equal_address(source, expected)))
                && destination.is_some_and(|destination| expected_destination.map_or(true, |expected| equal_address(destination, expected)));
        }
        if matching_endpoints && words.windows(2).any(|pair| pair == ["proto", "esp"]) { return true; }
    }
    false
}

struct PingOutcome {
    latency_ms: Option<u64>,
    summary: String,
}

struct HttpResponseSummary {
    status_code: u16,
    status_line: String,
    body_preview: String,
    remote_ip: Option<IpAddr>,
}

struct WireguardPeerStatus {
    peer_id: String,
    endpoint: Option<String>,
    latest_handshake_unix: Option<u64>,
}

struct DnsResponseSummary {
    rcode: String,
    answer_count: u16,
    answers: Vec<String>,
}

struct InterfaceCounters {
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
}

fn run_ping(
    target: &str,
    ip_version: IpVersion,
    timeout_ms: u64,
    interface: Option<&str>,
) -> Result<PingOutcome, String> {
    let timeout_secs = ((timeout_ms + 999) / 1000).max(1);
    let mut args: Vec<String> = vec![
        "-n".to_string(),
        "-c".to_string(),
        "1".to_string(),
        "-W".to_string(),
        timeout_secs.to_string(),
    ];

    match ip_version {
        IpVersion::Ipv4 => args.push("-4".to_string()),
        IpVersion::Ipv6 => args.push("-6".to_string()),
        IpVersion::Any => {}
    }

    if let Some(interface) = interface {
        args.push("-I".to_string());
        args.push(interface.to_string());
    }

    args.push(target.to_string());

    let output = Command::new("ping")
        .args(&args)
        .output()
        .map_err(|error| format!("failed to run ping: {error}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let summary = if stdout.trim().is_empty() {
        stderr.trim().to_string()
    } else if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        format!("{}\n{}", stdout.trim(), stderr.trim())
    };

    if output.status.success() {
        Ok(PingOutcome {
            latency_ms: parse_ping_latency(&summary),
            summary: truncate(&summary, 220),
        })
    } else {
        Err(format!("ping failed: {}", truncate(first_non_empty_line(&summary), 220)))
    }
}

fn effective_probe_ip_version(target: &str, requested: IpVersion) -> IpVersion {
    match target.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => IpVersion::Ipv4,
        Ok(IpAddr::V6(_)) => IpVersion::Ipv6,
        Err(_) => requested,
    }
}

fn connect_with_timeouts(address: SocketAddr, timeout_ms: u64) -> Result<TcpStream, String> {
    let stream = TcpStream::connect_timeout(&address, timeout_duration(timeout_ms))
        .map_err(|error| format!("connect failed: {error}"))?;
    stream
        .set_read_timeout(Some(timeout_duration(timeout_ms)))
        .map_err(|error| format!("failed to set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout_duration(timeout_ms)))
        .map_err(|error| format!("failed to set write timeout: {error}"))?;
    Ok(stream)
}

fn resolve_socket_addr(target: &str, port: u16, ip_version: IpVersion) -> Result<SocketAddr, String> {
    resolve_socket_addresses(target, port, ip_version).map(|addresses| addresses[0])
}

fn resolve_socket_addresses(target: &str, port: u16, ip_version: IpVersion) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip_address) = target.parse::<IpAddr>() {
        if !matches_ip_version(ip_address, ip_version) {
            return Err(format!(
                "target {target} does not match requested ip version {:?}",
                ip_version
            ));
        }
        return Ok(vec![SocketAddr::new(ip_address, port)]);
    }

    let mut resolved = Vec::new();
    for address in (target, port)
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve {target}:{port}: {error}"))?
    {
        if matches_ip_version(address.ip(), ip_version) && !resolved.contains(&address) && resolved.len() < 8 {
            resolved.push(address);
        }
    }

    if resolved.is_empty() { Err(format!("no addresses found for {target}:{port} matching {:?}", ip_version)) } else { Ok(resolved) }
}

fn connect_tcp_candidates(addresses: &[SocketAddr], timeout_ms: u64) -> Result<(TcpStream, SocketAddr), String> {
    let deadline = Instant::now() + timeout_duration(timeout_ms);
    let mut errors = Vec::new();
    for (index, address) in addresses.iter().enumerate() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else { break; };
        // Share the deadline across addresses so an unavailable IPv6 address
        // does not mask a healthy IPv4 endpoint (or vice versa).
        let timeout = (remaining / (addresses.len() - index) as u32).max(Duration::from_millis(1));
        match TcpStream::connect_timeout(address, timeout) {
            Ok(stream) => return Ok((stream, *address)),
            Err(error) => errors.push(format!("{address}: {error}")),
        }
    }
    Err(format!("tcp connection failed: {}", errors.join("; ")))
}

fn matches_ip_version(address: IpAddr, ip_version: IpVersion) -> bool {
    match ip_version {
        IpVersion::Any => true,
        IpVersion::Ipv4 => address.is_ipv4(),
        IpVersion::Ipv6 => address.is_ipv6(),
    }
}

fn ip_version_from_addr(address: SocketAddr) -> IpVersion {
    match address {
        SocketAddr::V4(_) => IpVersion::Ipv4,
        SocketAddr::V6(_) => IpVersion::Ipv6,
    }
}

fn read_ssh_banner(reader: &mut BufReader<TcpStream>) -> Result<String, String> {
    let timeout = reader.get_ref().read_timeout().ok().flatten().unwrap_or(Duration::from_secs(3));
    let deadline = Instant::now() + timeout;
    for _ in 0..4 {
        let line = read_bounded_ssh_line(reader, deadline)?;
        let banner = line.trim().to_string();
        if banner.starts_with("SSH-") {
            if line.len() > 255 { return Err("SSH identification exceeded the RFC 4253 limit of 255 bytes.".to_string()); }
            return Ok(banner);
        }
    }

    Err("ssh service did not send a valid banner".to_string())
}

fn read_bounded_ssh_line(reader: &mut BufReader<TcpStream>, deadline: Instant) -> Result<String, String> {
    let mut line = Vec::new();
    loop {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or_else(|| "SSH banner deadline exceeded.".to_string())?;
        reader.get_ref().set_read_timeout(Some(remaining)).map_err(|error| error.to_string())?;
        let available = reader.fill_buf().map_err(|error| format!("Failed to read SSH banner: {error}"))?;
        if available.is_empty() { break; }
        let used = available.iter().position(|byte| *byte == b'\n').map_or(available.len(), |position| position + 1);
        if line.len() + used > 1024 { return Err("SSH pre-banner line exceeded the 1024-byte probe limit.".to_string()); }
        let finished = available[used - 1] == b'\n';
        line.extend_from_slice(&available[..used]);
        reader.consume(used);
        if finished { break; }
    }
    if line.is_empty() { return Err("SSH peer closed before sending a banner.".to_string()); }
    String::from_utf8(line).map_err(|_| "SSH banner was not valid UTF-8/ASCII.".to_string())
}

fn perform_curl_exchange(
    check: &WebCheck,
    use_tls: bool,
    port: u16,
) -> Result<HttpResponseSummary, String> {
    const STATUS_MARKER: &str = "\n__IRANMONITOR_STATUS__:";
    let connect_host = check.connect_host.as_deref().unwrap_or(&check.host);
    let host_header = check.host_header.as_deref().unwrap_or(&check.host);
    let authority_host = if use_tls {
        check.tls_server_name
            .as_deref()
            .or(check.host_header.as_deref())
            .unwrap_or(&check.host)
    } else {
        host_header
    };
    let scheme = if use_tls { "https" } else { "http" };
    let authority = url_authority(authority_host, port, use_tls);
    let path = normalized_path(&check.path);
    let url = format!("{scheme}://{authority}{path}");
    let timeout_secs = ((check.timeout_ms + 999) / 1000).max(1);

    let mut args = vec![
        "--silent".to_string(),
        "--show-error".to_string(),
        "--connect-timeout".to_string(),
        timeout_secs.to_string(),
        "--max-time".to_string(),
        timeout_secs.to_string(),
        "--request".to_string(),
        check.method.to_uppercase(),
        "--output".to_string(),
        "-".to_string(),
        "--write-out".to_string(),
        format!("{STATUS_MARKER}%{{http_code}}|%{{remote_ip}}"),
    ];

    match check.ip_version {
        IpVersion::Ipv4 => args.push("--ipv4".to_string()),
        IpVersion::Ipv6 => args.push("--ipv6".to_string()),
        IpVersion::Any => {}
    }

    if host_header != authority_host {
        args.push("--header".to_string());
        args.push(format!("Host: {host_header}"));
    }

    for (name, value) in &check.headers {
        args.push("--header".to_string());
        args.push(format!("{name}: {value}"));
    }

    if connect_host != authority_host {
        args.push("--connect-to".to_string());
        args.push(format!(
            "{}:{}:{}:{}",
            curl_resolve_target(authority_host),
            port,
            curl_resolve_target(connect_host),
            port,
        ));
    }

    args.push(url);

    let output = Command::new("curl")
        .args(&args)
        .output()
        .map_err(|error| format!("failed to execute curl: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl request failed: {}", truncate(stderr.trim(), 220)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let marker_index = stdout
        .rfind(STATUS_MARKER)
        .ok_or_else(|| "curl output did not include an http status marker".to_string())?;
    let body = stdout[..marker_index].to_string();
    let metadata = stdout[marker_index + STATUS_MARKER.len()..].trim();
    let (status_code_text, remote_ip) = metadata.split_once('|').ok_or_else(|| "curl output was missing peer metadata".to_string())?;
    let status_code = status_code_text
        .parse::<u16>()
        .map_err(|error| format!("failed to parse curl http status: {error}"))?;

    Ok(HttpResponseSummary {
        status_code,
        status_line: format!("HTTP status {status_code}"),
        body_preview: body,
        remote_ip: remote_ip.parse::<IpAddr>().ok(),
    })
}

fn perform_v2ray_curl_exchange(
    check: &V2raySimulationCheck,
    entry_type: LocalEntryType,
    proxy_host: &str,
    proxy_port: u16,
    test_url: &str,
) -> Result<HttpResponseSummary, String> {
    const STATUS_MARKER: &str = "\n__IRANMONITOR_PROXY_STATUS__:";
    let timeout_secs = ((check.timeout_ms + 999) / 1000).max(1);
    let mut args = vec![
        "--silent".to_string(),
        "--show-error".to_string(),
        "--connect-timeout".to_string(),
        timeout_secs.to_string(),
        "--max-time".to_string(),
        timeout_secs.to_string(),
        "--output".to_string(),
        "-".to_string(),
        "--write-out".to_string(),
        format!("{STATUS_MARKER}%{{http_code}}"),
    ];

    match check.ip_version {
        IpVersion::Ipv4 => args.push("--ipv4".to_string()),
        IpVersion::Ipv6 => args.push("--ipv6".to_string()),
        IpVersion::Any => {}
    }

    match entry_type {
        LocalEntryType::Socks5 => {
            args.push("--socks5-hostname".to_string());
            args.push(format!("{proxy_host}:{proxy_port}"));
        }
        LocalEntryType::Http | LocalEntryType::Https => {
            args.push("--proxy".to_string());
            args.push(format!(
                "{}://{}:{}",
                entry_type.as_str(),
                proxy_host,
                proxy_port
            ));
        }
        LocalEntryType::Direct => {
            return Err(
                "direct entry mode does not support curl-based proxy simulation".to_string(),
            )
        }
    }

    if let Some(username) = &check.username {
        let password = check.password.as_deref().unwrap_or("");
        args.push("--proxy-user".to_string());
        args.push(format!("{username}:{password}"));
    }

    args.push(test_url.to_string());

    let output = Command::new("curl")
        .args(&args)
        .output()
        .map_err(|error| format!("failed to execute curl for proxy simulation: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "proxy simulation failed: {}",
            truncate(stderr.trim(), 220)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let marker_index = stdout
        .rfind(STATUS_MARKER)
        .ok_or_else(|| "curl output did not include a proxy simulation status marker".to_string())?;
    let body = stdout[..marker_index].to_string();
    let status_code = stdout[marker_index + STATUS_MARKER.len()..]
        .trim()
        .parse::<u16>()
        .map_err(|error| format!("failed to parse proxy simulation status: {error}"))?;

    Ok(HttpResponseSummary {
        status_code,
        status_line: format!("HTTP status {status_code}"),
        body_preview: body,
        remote_ip: None,
    })
}

fn inspect_wireguard_peer(check: &V2raySimulationCheck) -> Result<WireguardPeerStatus, String> {
    let interface = check
        .wireguard_interface
        .as_deref()
        .ok_or_else(|| "WireGuard interface is required for peer inspection".to_string())?;

    let latest_output = run_command_capture("wg", &["show", interface, "latest-handshakes"])
        .map_err(|error| format!("failed to inspect WireGuard handshakes: {error}"))?;
    let endpoints_output = run_command_capture("wg", &["show", interface, "endpoints"])
        .map_err(|error| format!("failed to inspect WireGuard endpoints: {error}"))?;

    let handshakes = parse_wireguard_latest_handshakes(&latest_output);
    let endpoints = parse_wireguard_endpoints(&endpoints_output);

    if let Some(filter) = check.wireguard_peer.as_deref() {
        return select_wireguard_peer_by_filter(&handshakes, &endpoints, filter).ok_or_else(
            || format!("no WireGuard peer matched the provided peer filter: {filter}"),
        );
    }

    if let Some((peer_id, handshake_unix)) = newest_wireguard_handshake(&handshakes) {
        return Ok(WireguardPeerStatus {
            peer_id: peer_id.clone(),
            endpoint: endpoints.get(&peer_id).cloned(),
            latest_handshake_unix: if handshake_unix > 0 {
                Some(handshake_unix)
            } else {
                None
            },
        });
    }

    if endpoints.len() == 1 {
        let (peer_id, endpoint) = endpoints.into_iter().next().unwrap();
        return Ok(WireguardPeerStatus {
            peer_id,
            endpoint: Some(endpoint),
            latest_handshake_unix: None,
        });
    }

    Err(
        "WireGuard peer selection is ambiguous; set a peer filter or handshake age target"
            .to_string(),
    )
}

fn parse_wireguard_latest_handshakes(output: &str) -> BTreeMap<String, u64> {
    let mut handshakes = BTreeMap::new();
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let peer_id = match parts.next() {
            Some(value) if !value.trim().is_empty() => value.trim(),
            _ => continue,
        };
        let handshake_unix = parts
            .next()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0);
        handshakes.insert(peer_id.to_string(), handshake_unix);
    }
    handshakes
}

fn parse_wireguard_endpoints(output: &str) -> BTreeMap<String, String> {
    let mut endpoints = BTreeMap::new();
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let peer_id = match parts.next() {
            Some(value) if !value.trim().is_empty() => value.trim(),
            _ => continue,
        };
        let endpoint = match parts.next() {
            Some(value) if !value.trim().is_empty() => value.trim(),
            _ => continue,
        };
        endpoints.insert(peer_id.to_string(), endpoint.to_string());
    }
    endpoints
}

fn select_wireguard_peer_by_filter(
    handshakes: &BTreeMap<String, u64>,
    endpoints: &BTreeMap<String, String>,
    filter: &str,
) -> Option<WireguardPeerStatus> {
    for (peer_id, endpoint) in endpoints {
        if peer_id.contains(filter) || endpoint.contains(filter) {
            return Some(WireguardPeerStatus {
                peer_id: peer_id.clone(),
                endpoint: Some(endpoint.clone()),
                latest_handshake_unix: handshakes.get(peer_id).copied().filter(|value| *value > 0),
            });
        }
    }

    for (peer_id, handshake_unix) in handshakes {
        if peer_id.contains(filter) {
            return Some(WireguardPeerStatus {
                peer_id: peer_id.clone(),
                endpoint: endpoints.get(peer_id).cloned(),
                latest_handshake_unix: if *handshake_unix > 0 {
                    Some(*handshake_unix)
                } else {
                    None
                },
            });
        }
    }

    None
}

fn newest_wireguard_handshake(handshakes: &BTreeMap<String, u64>) -> Option<(String, u64)> {
    handshakes
        .iter()
        .max_by_key(|(_, handshake_unix)| *handshake_unix)
        .map(|(peer_id, handshake_unix)| (peer_id.clone(), *handshake_unix))
}

fn url_authority(host: &str, port: u16, use_tls: bool) -> String {
    let default_port = if use_tls { 443 } else { 80 };
    let bracketed_host = if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == default_port {
        bracketed_host
    } else {
        format!("{bracketed_host}:{port}")
    }
}

fn curl_resolve_target(connect_host: &str) -> String {
    if connect_host.contains(':') && !connect_host.starts_with('[') && !connect_host.ends_with(']') {
        format!("[{connect_host}]")
    } else {
        connect_host.to_string()
    }
}

fn build_dns_query(query_id: u16, record_name: &str, record_type: DnsRecordType) -> Result<Vec<u8>, String> {
    let mut query = Vec::with_capacity(512);
    query.extend_from_slice(&query_id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());

    encode_dns_name(record_name, &mut query)?;
    query.extend_from_slice(&record_type.code().to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn parse_dns_response(packet: &[u8], expected_query_id: u16, expected_name: &str, expected_type: DnsRecordType) -> Result<DnsResponseSummary, String> {
    if packet.len() < 12 {
        return Err("dns response packet was shorter than the header".to_string());
    }

    let query_id = read_u16(packet, 0)?;
    if query_id != expected_query_id {
        return Err("dns response query id did not match".to_string());
    }

    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 == 0 { return Err("DNS packet was a query, not a response.".to_string()); }
    if flags & 0x7800 != 0 { return Err("DNS response used an unexpected opcode.".to_string()); }
    if flags & 0x0200 != 0 { return Err("DNS response remained truncated after TCP retry.".to_string()); }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(format!("dns server returned rcode {}", dns_rcode_name(rcode)));
    }

    let question_count = read_u16(packet, 4)?;
    let answer_count = read_u16(packet, 6)?;
    let mut offset = 12_usize;
    if question_count != 1 { return Err("DNS response must echo the original question.".to_string()); }

    for _ in 0..question_count {
        let (question_name, next_offset) = parse_dns_name(packet, offset)?;
        if !question_name.trim_end_matches('.').eq_ignore_ascii_case(expected_name.trim().trim_end_matches('.'))
            || read_u16(packet, next_offset)? != expected_type.code()
            || read_u16(packet, next_offset + 2)? != 1 {
            return Err("DNS response question did not match the requested name/type.".to_string());
        }
        offset = next_offset + 4;
        if offset > packet.len() {
            return Err("dns question section overflowed packet length".to_string());
        }
    }

    let mut answers = Vec::new();
    for _ in 0..answer_count {
        let (_, next_offset) = parse_dns_name(packet, offset)?;
        offset = next_offset;
        let record_type = read_u16(packet, offset)?;
        offset += 2;
        let class = read_u16(packet, offset)?;
        offset += 2;
        let _ttl = read_u32(packet, offset)?;
        offset += 4;
        let rdlength = read_u16(packet, offset)? as usize;
        offset += 2;
        if offset + rdlength > packet.len() {
            return Err("dns answer overflowed packet length".to_string());
        }

        let answer = decode_dns_rdata(packet, offset, rdlength, record_type)?;
        if class == 1 && record_type == expected_type.code() { answers.push(answer); }
        offset += rdlength;
    }

    Ok(DnsResponseSummary {
        rcode: dns_rcode_name(rcode).to_string(),
        answer_count: answers.len() as u16,
        answers,
    })
}

fn encode_dns_name(name: &str, output: &mut Vec<u8>) -> Result<(), String> {
    let trimmed = name.trim().trim_end_matches('.');
    if !trimmed.is_ascii() || trimmed.len() > 253 {
        return Err("DNS names must use ASCII/Punycode and fit within 253 characters.".to_string());
    }
    if trimmed.is_empty() {
        output.push(0);
        return Ok(());
    }

    for label in trimmed.split('.') {
        let length = label.len();
        if length == 0 || length > 63 {
            return Err(format!("invalid dns label length in {name}"));
        }
        output.push(length as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

fn parse_dns_name(packet: &[u8], mut offset: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_offset = offset;
    let mut hop_count = 0_usize;

    loop {
        if offset >= packet.len() {
            return Err("dns name offset exceeded packet length".to_string());
        }

        let length = packet[offset];
        if length & 0xc0 == 0xc0 {
            if offset + 1 >= packet.len() {
                return Err("dns compression pointer exceeded packet length".to_string());
            }
            let pointer = (((length & 0x3f) as usize) << 8) | packet[offset + 1] as usize;
            if !jumped {
                next_offset = offset + 2;
                jumped = true;
            }
            offset = pointer;
            hop_count += 1;
            if hop_count > packet.len() {
                return Err("dns name contained a compression loop".to_string());
            }
            continue;
        }
        if length & 0xc0 != 0 { return Err("DNS label used an invalid length encoding.".to_string()); }

        if length == 0 {
            if !jumped {
                next_offset = offset + 1;
            }
            break;
        }

        offset += 1;
        let end = offset + length as usize;
        if end > packet.len() {
            return Err("dns label exceeded packet length".to_string());
        }
        labels.push(String::from_utf8_lossy(&packet[offset..end]).to_string());
        if labels.iter().map(|label| label.len() + 1).sum::<usize>() > 254 {
            return Err("DNS name exceeded the wire-format length limit.".to_string());
        }
        offset = end;
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Ok((name, next_offset))
}

fn decode_dns_rdata(packet: &[u8], offset: usize, rdlength: usize, record_type: u16) -> Result<String, String> {
    match record_type {
        1 if rdlength == 4 => Ok(Ipv4Addr::new(
            packet[offset],
            packet[offset + 1],
            packet[offset + 2],
            packet[offset + 3],
        )
        .to_string()),
        28 if rdlength == 16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&packet[offset..offset + 16]);
            Ok(Ipv6Addr::from(octets).to_string())
        }
        1 | 28 => Err("DNS address record had an invalid data length.".to_string()),
        5 | 2 => {
            let (name, next) = parse_dns_name(packet, offset)?;
            if next > offset + rdlength { return Err("DNS name exceeded its record data length.".to_string()); }
            Ok(name)
        }
        15 => {
            if rdlength < 3 {
                return Err("dns mx record was too short".to_string());
            }
            let priority = read_u16(packet, offset)?;
            let (exchange, next) = parse_dns_name(packet, offset + 2)?;
            if next > offset + rdlength { return Err("DNS MX exchange exceeded its record length.".to_string()); }
            Ok(format!("{priority} {exchange}"))
        }
        16 => {
            if rdlength == 0 {
                return Ok(String::new());
            }
            let mut cursor = offset;
            let end = offset + rdlength;
            let mut chunks = Vec::new();
            while cursor < end {
                let length = packet[cursor] as usize;
                cursor += 1;
                let next = cursor + length;
                if next > end { return Err("DNS TXT segment exceeded its record length.".to_string()); }
                chunks.push(String::from_utf8_lossy(&packet[cursor..next]).to_string());
                cursor = next;
            }
            Ok(chunks.join(""))
        }
        _ => Ok(format!("type_{record_type}_len_{rdlength}")),
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, String> {
    if offset + 2 > packet.len() {
        return Err("read_u16 exceeded packet length".to_string());
    }
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > packet.len() {
        return Err("read_u32 exceeded packet length".to_string());
    }
    Ok(u32::from_be_bytes([
        packet[offset],
        packet[offset + 1],
        packet[offset + 2],
        packet[offset + 3],
    ]))
}

fn dns_rcode_name(rcode: u16) -> &'static str {
    match rcode {
        0 => "no_error",
        1 => "format_error",
        2 => "server_failure",
        3 => "name_error",
        4 => "not_implemented",
        5 => "refused",
        _ => "unknown",
    }
}

fn dns_query_id() -> u16 {
    let time = unix_now() as u16;
    let pid = std::process::id() as u16;
    time ^ pid
}

fn read_ftp_response(reader: &mut BufReader<TcpStream>) -> Result<String, String> {
    let mut first_line = String::new();
    reader
        .read_line(&mut first_line)
        .map_err(|error| format!("failed to read ftp response: {error}"))?;
    if first_line.is_empty() {
        return Err("ftp server closed the connection".to_string());
    }

    let mut response = first_line.clone();
    let is_multiline = first_line.as_bytes().get(3) == Some(&b'-');
    if is_multiline {
        let expected_code = &first_line[..3];
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|error| format!("failed to read ftp multiline response: {error}"))?;
            if line.is_empty() {
                break;
            }
            response.push_str(&line);
            if line.starts_with(expected_code) && line.as_bytes().get(3) == Some(&b' ') {
                break;
            }
        }
    }

    Ok(response.trim().to_string())
}

fn write_ftp_command(stream: &mut TcpStream, command: &str) -> io::Result<()> {
    stream.write_all(command.as_bytes())?;
    stream.write_all(b"\r\n")?;
    stream.flush()
}

fn read_interface_counters(interface: &str) -> Result<InterfaceCounters, String> {
    let base = PathBuf::from("/sys/class/net")
        .join(interface)
        .join("statistics");
    Ok(InterfaceCounters {
        rx_packets: read_u64_file(base.join("rx_packets"))?,
        tx_packets: read_u64_file(base.join("tx_packets"))?,
        rx_bytes: read_u64_file(base.join("rx_bytes"))?,
        tx_bytes: read_u64_file(base.join("tx_bytes"))?,
    })
}

fn read_trimmed(path: PathBuf) -> Result<String, String> {
    fs::read_to_string(&path)
        .map(|content| content.trim().to_string())
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn read_u64_file(path: PathBuf) -> Result<u64, String> {
    let content = read_trimmed(path)?;
    content
        .parse::<u64>()
        .map_err(|error| format!("failed to parse counter value: {error}"))
}

fn run_command_capture(command: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|error| format!("failed to execute {command}: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn run_command_owned(command: &str, args: Vec<String>) -> Result<(), String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|error| format!("failed to execute {command}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn make_result(
    id: &str,
    kind: &str,
    status: CheckStatus,
    message: impl Into<String>,
    observed_at_unix: u64,
    started: Instant,
    latency_ms: Option<u64>,
    ip_version: Option<IpVersion>,
    endpoint: Option<String>,
    details: BTreeMap<String, Value>,
) -> CheckResult {
    CheckResult {
        id: id.to_string(),
        kind: canonical_kind_name(kind).to_string(),
        status,
        message: message.into(),
        observed_at_unix,
        duration_ms: elapsed_ms(started),
        latency_ms,
        ip_version: ip_version.map(ip_version_label),
        endpoint,
        details,
    }
}

fn canonical_kind_name(kind: &str) -> &str {
    if kind.eq_ignore_ascii_case("v2ray_simulation") {
        "v2ray"
    } else {
        kind
    }
}

fn ip_version_label(ip_version: IpVersion) -> String {
    match ip_version {
        IpVersion::Ipv4 => "ipv4".to_string(),
        IpVersion::Ipv6 => "ipv6".to_string(),
        IpVersion::Any => "any".to_string(),
    }
}

fn normalized_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn timeout_duration(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms.max(1))
}

fn elapsed_ms(started: Instant) -> u64 {
    let millis = started.elapsed().as_millis();
    if millis > u64::MAX as u128 {
        u64::MAX
    } else {
        millis as u64
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn unix_now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn current_hostname() -> String {
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        let hostname = hostname.trim();
        if !hostname.is_empty() {
            return hostname.to_string();
        }
    }

    if let Ok(hostname) = fs::read_to_string("/etc/hostname") {
        let hostname = hostname.trim();
        if !hostname.is_empty() {
            return hostname.to_string();
        }
    }

    "unknown-host".to_string()
}

fn parse_ping_latency(text: &str) -> Option<u64> {
    let marker = "time=";
    let start = text.find(marker)?;
    let value = &text[start + marker.len()..];
    let end = value
        .find(" ms")
        .or_else(|| value.find(' '))
        .unwrap_or(value.len());
    let number = value[..end].trim();
    let parsed = number.parse::<f64>().ok()?;
    Some(parsed.round() as u64)
}

fn first_non_empty_line(text: &str) -> &str {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or(text)
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    text.chars().take(max_chars).collect::<String>() + "..."
}

#[cfg(test)]
mod tests {
    use super::*;
    static RUNTIME_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn tunnel_config() -> TunnelCheck {
        serde_json::from_value(json!({"id": "test-tunnel", "protocol": "esp", "interface": "imtest0",
            "inner_local_cidr": "10.20.0.1/30", "inner_probe": "10.20.0.2",
            "local_outer": "192.0.2.1", "outer_remote": "192.0.2.2"})).unwrap()
    }

    #[test]
    fn managed_kernel_overlay_plans_use_real_modes_and_packet_settings() {
        let mut check = tunnel_config();
        check.protocol = TunnelProtocol::Vxlan;
        check.vni = Some(321);
        check.transport_port = Some(4789);
        check.ttl = Some(64);
        check.traffic_class = Some(184);
        check.source_interface = Some("eth0".to_string());
        let plan = build_managed_tunnel_plan(&check).unwrap();
        assert_eq!(plan.mode_label, "vxlan");
        assert_eq!(plan.commands, vec![string_args(&["link", "add", "name", "imtest0", "type", "vxlan", "id", "321", "remote", "192.0.2.2", "local", "192.0.2.1", "dev", "eth0", "nolearning", "dstport", "4789", "ttl", "64", "tos", "0xb8"])]);
        check.protocol = TunnelProtocol::Geneve;
        check.transport_port = None;
        let plan = build_managed_tunnel_plan(&check).unwrap();
        assert_eq!(plan.commands, vec![string_args(&["link", "add", "name", "imtest0", "type", "geneve", "id", "321", "remote", "192.0.2.2", "dstport", "6081", "ttl", "64", "tos", "0xb8"])]);
        assert_eq!(build_outer_packet_update(&check, "imtest0"), Some(string_args(&["link", "set", "dev", "imtest0", "type", "geneve", "id", "321", "ttl", "64", "tos", "0xb8"])));
        // The portable GENEVE plan uses routing; mismatched sources fail explicitly.
        assert!(check_route_selected_outer_source(&check, Some("192.0.2.1"), Some("eth0")).is_ok());
        assert!(check_route_selected_outer_source(&check, Some("192.0.2.9"), Some("eth0")).is_err());
        assert!(check_route_selected_outer_source(&check, Some("192.0.2.1"), Some("eth9")).is_err());
        check.protocol = TunnelProtocol::Gretap;
        check.vni = None;
        check.local_outer = Some("2001:db8::1".to_string());
        check.outer_remote = Some("2001:db8::2".to_string());
        check.tunnel_key = Some("42".to_string());
        let plan = build_managed_tunnel_plan(&check).unwrap();
        assert_eq!(plan.commands, vec![string_args(&["link", "add", "name", "imtest0", "type", "ip6gretap", "remote", "2001:db8::2", "local", "2001:db8::1", "key", "42", "hoplimit", "64", "tclass", "0xb8", "dev", "eth0"])]);
        let update = build_outer_packet_update(&check, "imtest0").unwrap();
        assert_eq!(update, string_args(&["link", "set", "dev", "imtest0", "type", "ip6gretap", "hoplimit", "64", "tclass", "0xb8"]));
    }

    #[test]
    fn gaming_gue_plan_keeps_kernel_transport_and_reuses_receiver_port() {
        let mut check = tunnel_config();
        check.protocol = TunnelProtocol::Encap;
        check.mtu = Some(1400);
        check.ttl = Some(64);
        check.traffic_class = Some(0);
        let plan = build_managed_tunnel_plan(&check).unwrap();
        assert_eq!(plan.commands, vec![string_args(&["link", "add", "name", "imtest0", "type", "ipip", "remote", "192.0.2.2", "local", "192.0.2.1", "encap", "gue", "encap-sport", "auto", "encap-dport", "5555", "ttl", "64", "tos", "0x00"])]);
        assert_eq!(build_outer_packet_update(&check, "imtest0"), Some(string_args(&["link", "set", "dev", "imtest0", "type", "ipip", "encap", "gue", "encap-sport", "auto", "encap-dport", "5555", "ttl", "64", "tos", "0x00"])));
        // A non-symmetric port catches updates that rely on iproute2 6.1's
        // byte-swapping preservation of existing encapsulation port values.
        check.transport_port = Some(6201);
        let update = build_outer_packet_update(&check, "imtest0").unwrap();
        assert!(update.windows(2).any(|pair| pair == ["encap-dport", "6201"]));
        assert!(update.windows(2).any(|pair| pair == ["encap-sport", "auto"]));
        assert_eq!(update, build_outer_packet_update(&check, "imtest0").unwrap());
        assert!(gue_port_exists("port 5555 gue\nport 1701 ipproto 115", 5555));
        assert!(!gue_port_exists("port 5555 ipproto 4\nport 5556 gue", 5555));
        assert!(!gue_port_exists("port 5555 gue -6", 5555));
        check.outer_remote = Some("2001:db8::2".to_string());
        assert!(build_managed_tunnel_plan(&check).is_err());
    }

    #[test]
    fn wireguard_reports_selected_source_route_mismatches() {
        let mut check = tunnel_config();
        check.protocol = TunnelProtocol::Wireguard;
        check.source_interface = Some("eth0".to_string());
        assert!(check_route_selected_outer_source(&check, Some("192.0.2.1"), Some("eth0")).is_ok());
        let error = check_route_selected_outer_source(&check, Some("192.0.2.9"), Some("eth0")).unwrap_err();
        assert!(error.contains("WireGuard") && error.contains("192.0.2.9") && error.contains("192.0.2.1"));
        assert!(check_route_selected_outer_source(&check, Some("192.0.2.1"), Some("eth9")).is_err());
        assert!(check_route_selected_outer_source(&check, None, Some("eth0")).is_err());
        check.local_outer = Some("2001:db8::1".to_string());
        assert!(check_route_selected_outer_source(&check, Some("2001:0db8:0:0:0:0:0:1"), Some("eth0")).is_ok());
    }

    #[test]
    fn icmp_tun_checks_selected_source_before_creation_and_reuse() {
        let mut check = tunnel_config();
        check.protocol = TunnelProtocol::Tun;
        check.auto_create_interface = true;
        check.tun_transport = Some("icmp".to_string());
        check.source_interface = Some("eth0".to_string());
        assert!(tun_uses_routed_outer_source(&check));
        assert!(check_route_selected_outer_source(&check, Some("192.0.2.1"), Some("eth0")).is_ok());
        let error = check_route_selected_outer_source(&check, Some("192.0.2.9"), Some("eth0")).unwrap_err();
        assert!(error.contains("ICMP TUN") && error.contains("Local Outer 192.0.2.1") && error.contains("host route or source-IP rules"));
        let error = check_route_selected_outer_source(&check, Some("192.0.2.1"), Some("eth9")).unwrap_err();
        assert!(error.contains("source interface eth0") && error.contains("host route"));
        assert!(check_route_selected_outer_source(&check, None, None).is_err());
        check.auto_create_interface = false;
        assert!(!tun_uses_routed_outer_source(&check));
        check.auto_create_interface = true;
        check.tun_transport = Some("udp".to_string());
        assert!(!tun_uses_routed_outer_source(&check));
        check.tun_transport = Some("tcp".to_string());
        assert!(!tun_uses_routed_outer_source(&check));
    }

    #[test]
    fn bound_tun_and_ssh_source_interface_checks_use_the_bound_local_address() {
        let mut check = tunnel_config();
        check.source_interface = Some("uplink0".to_string());
        // This selected address differs from the default route's source. A
        // carrier that binds it must validate `route get PEER from LOCAL`.
        check.local_outer = Some("192.0.2.9".to_string());
        for protocol in [TunnelProtocol::Tun, TunnelProtocol::Ssh, TunnelProtocol::ReverseSsh] {
            check.protocol = protocol;
            assert_eq!(build_bound_outer_route_args(&check).unwrap(), string_args(&["-o", "route", "get", "192.0.2.2", "from", "192.0.2.9"]));
            let matching_route = "192.0.2.2 from 192.0.2.9 dev uplink0 uid 0\n    cache";
            assert!(check_bound_outer_route_interface(&check, parse_route_output_for_dev(matching_route).as_deref()).is_ok());
            let wrong_route = "192.0.2.2 from 192.0.2.9 dev uplink1 uid 0\n    cache";
            let error = check_bound_outer_route_interface(&check, parse_route_output_for_dev(wrong_route).as_deref()).unwrap_err();
            assert!(error.contains("uplink1") && error.contains("source interface uplink0") && error.contains("192.0.2.9"));
            assert!(check_bound_outer_route_interface(&check, None).is_err());
        }
        check.local_outer = Some("2001:db8::9".to_string());
        check.outer_remote = Some("2001:db8::2".to_string());
        assert_eq!(build_bound_outer_route_args(&check).unwrap(), string_args(&["-6", "-o", "route", "get", "2001:db8::2", "from", "2001:db8::9"]));
        check.local_outer = None;
        assert_eq!(build_bound_outer_route_args(&check).unwrap(), string_args(&["-6", "-o", "route", "get", "2001:db8::2"]));
        check.outer_remote = Some("peer.example".to_string());
        assert!(build_bound_outer_route_args(&check).unwrap_err().contains("literal peer endpoint IP"));
    }

    #[test]
    fn managed_tun_listeners_filter_the_declared_outer_peer() {
        let mut check = tunnel_config();
        check.protocol = TunnelProtocol::Tun;
        let mut args = string_args(&["--interface", "imtest0", "--listen-addr", "192.0.2.1:19021"]);
        append_tun_helper_allowed_peer(&check, &mut args).unwrap();
        assert!(args.windows(2).any(|pair| pair == ["--allowed-peer", "192.0.2.2"]));
        let parsed = TunHelperArgs::parse(args).unwrap();
        assert_eq!(parsed.allowed_peer, Some("192.0.2.2".parse().unwrap()));
        assert_eq!(build_tun_socket_side("udp", true, "192.0.2.2", 19021, None, false, None), "UDP4-LISTEN:19021,reuseaddr,range=192.0.2.2/32");
        assert_eq!(build_tun_socket_side("udp", true, "2001:db8::2", 19021, None, true, None), "UDP6-LISTEN:19021,reuseaddr,range=[2001:db8::2]/128");
        check.local_outer = Some("2001:db8::1".to_string());
        check.outer_remote = Some("2001:db8::2".to_string());
        assert_eq!(resolve_tun_outer_peer_ip(&check).unwrap(), "2001:db8::2".parse::<IpAddr>().unwrap());
        check.outer_remote = Some("192.0.2.2".to_string());
        assert!(resolve_tun_outer_peer_ip(&check).is_err());
    }

    #[test]
    fn managed_tun_udp_commands_quote_ipv6_bind_addresses() {
        assert_eq!(
            build_tun_socket_side("udp", true, "2001:db8:1::2", 19021, None, true, Some("2001:db8:1::1")),
            "UDP6-LISTEN:19021,reuseaddr,range=[2001:db8:1::2]/128,bind=[2001:db8:1::1]",
        );
        assert_eq!(
            build_tun_socket_side("udp", false, "2001:db8:1::1", 19021, Some(19022), true, Some("2001:db8:1::2")),
            "UDP6:[2001:db8:1::1]:19021,sourceport=19022,bind=[2001:db8:1::2]",
        );
        assert_eq!(
            build_tun_socket_side("udp", true, "192.0.2.2", 19021, None, false, Some("192.0.2.1")),
            "UDP4-LISTEN:19021,reuseaddr,range=192.0.2.2/32,bind=192.0.2.1",
        );
        assert_eq!(
            build_tun_socket_side("udp", false, "192.0.2.1", 19021, Some(19022), false, Some("192.0.2.2")),
            "UDP4:192.0.2.1:19021,sourceport=19022,bind=192.0.2.2",
        );
    }

    #[test]
    fn tun_helper_allowed_peer_option_is_explicit_and_listener_only() {
        let basic = string_args(&["--interface", "imtest0", "--listen-addr", "127.0.0.1:19021"]);
        assert_eq!(TunHelperArgs::parse(basic.clone()).unwrap().allowed_peer, None);
        for peer in ["127.0.0.1", "::1"] {
            let mut args = basic.clone();
            args.extend(string_args(&["--allowed-peer", peer]));
            assert_eq!(TunHelperArgs::parse(args).unwrap().allowed_peer, Some(peer.parse().unwrap()));
        }
        for peer in ["peer.example", "0.0.0.0", "::", "224.0.0.1", "ff02::1"] {
            let mut args = basic.clone();
            args.extend(string_args(&["--allowed-peer", peer]));
            assert!(TunHelperArgs::parse(args).is_err(), "accepted invalid peer {peer}");
        }
        let mut missing = basic;
        missing.push("--allowed-peer".to_string());
        assert!(TunHelperArgs::parse(missing).is_err());
        assert!(TunHelperArgs::parse(string_args(&["--interface", "imtest0", "--connect-addr", "127.0.0.1:19021", "--allowed-peer", "127.0.0.1"])).is_err());
    }

    #[test]
    fn tun_listener_rejects_unexpected_source_then_accepts_declared_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(4);
            loop {
                match accept_tun_peer(&listener, Some("127.0.0.1".parse().unwrap())) {
                    Ok(mut stream) => { stream.write_all(b"OK").unwrap(); return; }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                    Err(error) => panic!("bounded peer acceptance failed: {error}"),
                }
            }
        });
        let mut alien = connect_tun_stream(address, Some("127.0.0.2".parse().unwrap())).unwrap();
        alien.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut rejected_payload = [0; 2];
        match alien.read(&mut rejected_payload) {
            Ok(0) => (),
            Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => (),
            other => panic!("unexpected source was not closed before accepting a lane: {other:?}"),
        }
        let mut peer = connect_tun_stream(address, Some("127.0.0.1".parse().unwrap())).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut accepted_payload = [0; 2];
        peer.read_exact(&mut accepted_payload).unwrap();
        assert_eq!(&accepted_payload, b"OK");
        worker.join().unwrap();
    }

    #[test]
    fn packet_settings_validate_bounds_families_and_supported_modes() {
        let mut check = tunnel_config();
        check.protocol = TunnelProtocol::Vxlan;
        check.mtu = Some(575);
        assert!(validate_tunnel_configuration(&check).is_err());
        check.mtu = Some(9001);
        assert!(validate_tunnel_configuration(&check).is_err());
        check.mtu = Some(1400);
        check.ttl = Some(0);
        assert!(validate_tunnel_configuration(&check).is_err());
        check.ttl = Some(255);
        check.vni = Some(16_777_216);
        assert!(validate_tunnel_configuration(&check).is_err());
        check.vni = Some(16_777_215);
        assert!(validate_tunnel_configuration(&check).is_ok());
        check.inner_probe = Some("2001:db8:1::2".to_string());
        check.inner_local_cidr = Some("2001:db8:1::1/64".to_string());
        check.mtu = Some(1279);
        assert!(validate_tunnel_configuration(&check).is_err());
        check.mtu = Some(1280);
        assert!(validate_tunnel_configuration(&check).is_ok());
        check.protocol = TunnelProtocol::Esp;
        check.vni = None;
        assert!(validate_tunnel_configuration(&check).is_err());
        check.ttl = None;
        assert!(validate_tunnel_configuration(&check).is_ok());
        check.source_interface = Some("eth0;bad".to_string());
        assert!(validate_tunnel_configuration(&check).is_err());
    }

    #[test]
    fn existing_saved_packet_defaults_and_gre_commands_are_preserved() {
        let mut check = tunnel_config();
        check.protocol = TunnelProtocol::Gre;
        assert!(check.mtu.is_none() && check.ttl.is_none() && check.traffic_class.is_none() && check.vni.is_none() && check.tun_lanes.is_none());
        let plan = build_managed_tunnel_plan(&check).unwrap();
        assert_eq!(plan.commands, vec![string_args(&["tunnel", "add", "imtest0", "mode", "gre", "remote", "192.0.2.2", "local", "192.0.2.1"])]);
        assert!(build_outer_packet_update(&check, "imtest0").is_none());
    }

    #[test]
    fn saved_hexadecimal_gre_keys_remain_compatible() {
        let mut check = tunnel_config();
        check.protocol = TunnelProtocol::Gre;
        for key in ["0x100", "0XFFFFFFFF", "4294967295", "1.2.3.4"] {
            check.tunnel_key = Some(key.to_string());
            let saved = serde_json::to_value(&check).unwrap();
            let restored: TunnelCheck = serde_json::from_value(saved).unwrap();
            let plan = build_managed_tunnel_plan(&restored).unwrap();
            assert!(plan.commands[0].windows(2).any(|pair| pair[0] == "key" && pair[1] == key));
        }
        for key in ["0x", "0x100000000", "0xGG", "-1", "4294967296"] {
            check.tunnel_key = Some(key.to_string());
            assert!(validate_tunnel_configuration(&check).is_err(), "accepted invalid GRE key {key}");
        }
        check.protocol = TunnelProtocol::Gretap;
        check.tunnel_key = Some("0x100".to_string());
        assert!(build_managed_tunnel_plan(&check).is_ok());
    }

    #[test]
    fn native_tun_packet_ceiling_and_lane_limits_are_enforced() {
        assert!(TunnelProtocol::from_str("unknown_custom_protocol").is_err());
        assert!(validate_tun_packet_size(1400, 1400).is_ok());
        assert!(validate_tun_packet_size(1401, 1400).is_err());
        assert!(validate_tun_packet_size(65536, 65535).is_err());
        assert!(TunHelperArgs::parse(string_args(&["--interface", "tun42", "--listen-addr", "127.0.0.1:4444", "--lanes", "9"])).is_err());
        assert!(TunHelperArgs::parse(string_args(&["--interface", "tun42", "--listen-addr", "127.0.0.1:4444", "--packet-limit", "65536"])).is_err());
        let args = TunHelperArgs::parse(string_args(&["--interface", "tun42", "--listen-addr", "127.0.0.1:4444", "--lanes", "4", "--packet-limit", "1400"])).unwrap();
        assert_eq!(args.lanes, 4);
        assert_eq!(args.packet_limit, 1400);
        let mut check = tunnel_config();
        check.protocol = TunnelProtocol::Tun;
        check.tun_transport = Some("icmp".to_string());
        check.tun_lanes = Some(8);
        check.listen_port = Some(65530);
        assert!(validate_tunnel_configuration(&check).is_err());
        check.listen_port = Some(56000);
        assert!(validate_tunnel_configuration(&check).is_ok());
    }

    #[test]
    fn oversized_tun_frame_is_rejected_before_receiving_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let mut socket = TcpStream::connect(address).unwrap();
            socket.write_all(&1401_u16.to_be_bytes()).unwrap();
            thread::sleep(Duration::from_millis(150));
        });
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let fixture = std::env::temp_dir().join(format!("imonitor-frame-{}-{}.tmp", std::process::id(), unix_now_millis()));
        fs::write(&fixture, b"isolated packet fixture").unwrap();
        let file = fs::File::open(&fixture).unwrap();
        let result = bridge_single_inbound_stream(&mut socket, Arc::new(Mutex::new(file)), &AtomicBool::new(true), 1400);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        peer.join().unwrap();
        fs::remove_file(fixture).unwrap();
    }

    /// Exports synthetic test fixtures only; does not execute networking tools.
    #[test]
    #[ignore = "manual exporter for disposable Linux acceptance namespaces"]
    fn export_kernel_acceptance_plans() {
        let directory = std::env::var_os("IMONITOR_KERNEL_PLAN_DIR").map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/kernel-acceptance"));
        fs::create_dir_all(&directory).unwrap();
        let modes = [
            ("gre4", TunnelProtocol::Gre, false, false), ("gre6", TunnelProtocol::Gre, true, false),
            ("ipip4", TunnelProtocol::Ipip, false, false), ("ipip6", TunnelProtocol::Ipip, true, false),
            ("sit4", TunnelProtocol::Ipv6Encapsulation, false, true), ("ip6ip6", TunnelProtocol::Ipv6Encapsulation, true, true),
            ("gretap4", TunnelProtocol::Gretap, false, false), ("gretap6", TunnelProtocol::Gretap, true, false),
            ("vxlan4", TunnelProtocol::Vxlan, false, false), ("vxlan6", TunnelProtocol::Vxlan, true, false),
            ("geneve4", TunnelProtocol::Geneve, false, false), ("geneve6", TunnelProtocol::Geneve, true, false),
            ("gue4", TunnelProtocol::Encap, false, false),
            ("esp4", TunnelProtocol::Esp, false, false), ("esp6", TunnelProtocol::Esp, true, true),
            ("wireguard4", TunnelProtocol::Wireguard, false, false), ("wireguard6", TunnelProtocol::Wireguard, true, true),
        ];
        let mut manifest = Vec::new();
        let mut mode_list = String::new();
        for (name, protocol, outer_ipv6, inner_ipv6) in modes {
            let mode_dir = directory.join(name);
            fs::create_dir_all(&mode_dir).unwrap();
            mode_list.push_str(name); mode_list.push('\n');
            let outer = if outer_ipv6 { ["2001:db8:1::1", "2001:db8:1::2"] } else { ["192.0.2.1", "192.0.2.2"] };
            let inner = if inner_ipv6 { ["2001:db8:2::1", "2001:db8:2::2"] } else { ["10.20.0.1", "10.20.0.2"] };
            let cidrs = if inner_ipv6 { ["2001:db8:2::1/64", "2001:db8:2::2/64"] } else { ["10.20.0.1/30", "10.20.0.2/30"] };
            let port = match protocol { TunnelProtocol::Vxlan => 4789, TunnelProtocol::Geneve => 6081, TunnelProtocol::Encap => 5555, TunnelProtocol::Wireguard => 51820, _ => 0 };
            for side in 0..2 {
                let peer = 1 - side;
                let mut check = tunnel_config();
                check.id = format!("accept-{name}-{}", if side == 0 { "a" } else { "b" });
                check.protocol = protocol;
                check.interface = Some("imtest0".to_string());
                check.source_interface = Some("underlay0".to_string());
                check.local_outer = Some(outer[side].to_string());
                check.outer_remote = Some(outer[peer].to_string());
                check.inner_local_cidr = Some(cidrs[side].to_string());
                check.inner_probe = Some(inner[peer].to_string());
                check.ip_version = if inner_ipv6 { IpVersion::Ipv6 } else { IpVersion::Ipv4 };
                check.mtu = Some(1400);
                check.timeout_ms = 5000;
                check.require_bidirectional_traffic = false;
                if tunnel_supports_outer_packet_settings(protocol) { check.ttl = Some(64); check.traffic_class = Some(184); }
                if matches!(protocol, TunnelProtocol::Vxlan | TunnelProtocol::Geneve) { check.vni = Some(42); }
                if port != 0 { check.transport_port = Some(port); }
                if protocol == TunnelProtocol::Esp {
                    check.esp_key_derivation = EspKeyDerivation::HkdfSha256;
                    check.esp_cipher = EspCipher::AesCbcHmacSha256;
                    check.tunnel_key = Some("TEST-FIXTURE-ONLY-DO-NOT-USE-IN-PRODUCTION-2026".to_string());
                }
                if protocol == TunnelProtocol::Wireguard {
                    // Public RFC 7748 section 6.1 vectors, never production keys.
                    let private = ["dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", "XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os="];
                    let public = ["hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=", "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08="];
                    check.wireguard_private_key = Some(private[side].to_string());
                    check.wireguard_peer_public_key = Some(public[peer].to_string());
                    check.wireguard_allowed_ips = Some(format!("{}/{}", inner[peer], if inner_ipv6 { 128 } else { 32 }));
                    check.listen_port = Some(51820);
                }
                let plan = build_managed_tunnel_plan(&check).unwrap();
                let label = if side == 0 { "a" } else { "b" };
                fs::write(mode_dir.join(format!("{label}.json")), serde_json::to_vec_pretty(&check).unwrap()).unwrap();
                let mut commands = plan.commands;
                commands.push(string_args(&["link", "set", "dev", "imtest0", "mtu", "1400", "up"]));
                if let Some(update) = build_outer_packet_update(&check, "imtest0") { commands.push(update); }
                if protocol == TunnelProtocol::Encap { commands.push(string_args(&["fou", "add", "port", "5555", "gue"])); }
                commands.push(string_args(&["address", "replace", cidrs[side], "dev", "imtest0"]));
                commands.push(string_args(&[if inner_ipv6 { "-6" } else { "-4" }, "route", "replace", &format!("{}/{}", inner[peer], if inner_ipv6 { 128 } else { 32 }), "dev", "imtest0"]));
                let mut script = String::from("#!/usr/bin/env bash\nset -eu\n# Generated from runner command plans; use only in a disposable test namespace.\n");
                if matches!(protocol, TunnelProtocol::Esp | TunnelProtocol::Wireguard) {
                    script.push_str("# This mode requires the Linux runtime test for its authenticated state/config.\n");
                }
                for command in &commands {
                    script.push_str("ip ");
                    script.push_str(&command.iter().map(|arg| format!("'{}'", arg.replace('\'', "'\\''"))).collect::<Vec<_>>().join(" "));
                    script.push('\n');
                }
                fs::write(mode_dir.join(format!("{label}.sh")), script).unwrap();
                manifest.push(json!({"mode":name, "side":label, "check":check, "commands":commands, "runtime_required":matches!(protocol, TunnelProtocol::Esp | TunnelProtocol::Wireguard)}));
            }
            let env = format!("OUTER_FAMILY={}\nINNER_FAMILY={}\nOUTER_A='{}'\nOUTER_B='{}'\nINNER_A='{}'\nINNER_B='{}'\nMTU=1400\nTUNNEL_PROTOCOL='{}'\nPACKET_SETTINGS={}\n",
                if outer_ipv6 { 6 } else { 4 }, if inner_ipv6 { 6 } else { 4 }, outer[0], outer[1], inner[0], inner[1], protocol.as_str(), if tunnel_supports_outer_packet_settings(protocol) { 1 } else { 0 });
            fs::write(mode_dir.join("mode.env"), env).unwrap();
        }
        fs::write(directory.join("modes.txt"), mode_list).unwrap();
        fs::write(directory.join("manifest.json"), serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        println!("Exported synthetic kernel acceptance fixtures to {}", directory.display());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a disposable privileged Linux namespace and exported fixture"]
    fn linux_kernel_fixture_runtime() {
        let path = std::env::var_os("IMONITOR_KERNEL_CHECK_FILE").expect("IMONITOR_KERNEL_CHECK_FILE is required");
        let check: TunnelCheck = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert!(check.id.starts_with("accept-") && check.interface.as_deref() == Some("imtest0"), "only synthetic acceptance fixtures are allowed");
        let mut details = BTreeMap::new();
        validate_tunnel_configuration(&check).unwrap();
        eprintln!("Fixture phase: first interface ensure begins for {}", check.id);
        ensure_managed_tunnel_interface(&check, &mut details).unwrap();
        eprintln!("Fixture phase: first interface ensure completed for {}", check.id);
        if check.protocol == TunnelProtocol::Encap {
            let live = run_command_capture("ip", &["-d", "link", "show", "imtest0"]).unwrap();
            eprintln!("GUE live settings after first ensure: {live}");
            assert!(live.contains(&format!("encap-dport {} ", check.transport_port.unwrap_or(5555))), "first ensure changed the configured GUE destination port");
        }
        let if_index = read_trimmed("/sys/class/net/imtest0/ifindex".into()).unwrap();
        eprintln!("Fixture phase: second interface ensure begins for {}", check.id);
        ensure_managed_tunnel_interface(&check, &mut details).unwrap();
        eprintln!("Fixture phase: second interface ensure completed for {}", check.id);
        if check.protocol == TunnelProtocol::Encap {
            let live = run_command_capture("ip", &["-d", "link", "show", "imtest0"]).unwrap();
            eprintln!("GUE live settings after second ensure: {live}");
            assert!(live.contains(&format!("encap-dport {} ", check.transport_port.unwrap_or(5555))), "second ensure changed the configured GUE destination port");
        }
        assert_eq!(read_trimmed("/sys/class/net/imtest0/ifindex".into()).unwrap(), if_index, "unchanged configuration recreated the device");
        assert_eq!(read_trimmed("/sys/class/net/imtest0/mtu".into()).unwrap(), "1400");
        if check.protocol == TunnelProtocol::Esp { assert_eq!(details.get("esp_configuration_reused"), Some(&json!(true))); }
        if check.protocol == TunnelProtocol::Encap { assert_eq!(details.get("encap_receive_port_reused"), Some(&json!(true))); }
        if std::env::var("IMONITOR_EXPECT_PEER").as_deref() == Ok("1") {
            let state = Arc::new(Mutex::new(PersistedState::default()));
            eprintln!("Fixture phase: monitor with interface-bound inner probe begins for {}", check.id);
            let result = run_tunnel(&check, &state, 60);
            eprintln!("Fixture phase: monitor with interface-bound inner probe completed for {}", check.id);
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            assert_eq!(result.status, CheckStatus::Up, "configured tunnel did not exchange real peer traffic: {}", result.message);
        }
        println!("Managed runtime reused {} on {}", check.protocol.as_str(), check.id);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires two configured disposable Linux tunnel namespaces"]
    fn linux_native_tunnel_speed_fixture() {
        let path = std::env::var_os("IMONITOR_KERNEL_CHECK_FILE").expect("IMONITOR_KERNEL_CHECK_FILE is required");
        let check: TunnelCheck = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert!(check.id.starts_with("accept-") && check.interface.as_deref() == Some("imtest0"));
        let local: IpAddr = extract_ip_from_cidr(check.inner_local_cidr.as_deref().unwrap()).unwrap().parse().unwrap();
        let remote: IpAddr = check.inner_probe.as_deref().unwrap().parse().unwrap();
        let token = "TEST-FIXTURE-ONLY-NATIVE-SPEED-TOKEN-2026";
        if std::env::var("IMONITOR_SPEED_ROLE").as_deref() == Ok("server") {
            crate::speedtest::sync_servers(vec![crate::speedtest::ServerConfig { bind: SocketAddr::new(local, 5201), token: token.to_string(), allowed_peer: Some(remote) }]).unwrap();
            println!("Native speed-test peer ready on {local}:5201");
            // The namespace harness terminates this dedicated fixture process.
            thread::sleep(Duration::from_secs(30));
            return;
        }
        let peer = SocketAddr::new(remote, 5201);
        assert!(crate::speedtest::measure(peer, local, "INCORRECT-TEST-TOKEN-0000000000000000", crate::speedtest::Direction::Upload, Duration::from_millis(500), 1, |_| {}).is_err());
        for (label, direction) in [("upload", crate::speedtest::Direction::Upload), ("download", crate::speedtest::Direction::Download)] {
            let result = crate::speedtest::measure(peer, local, token, direction, Duration::from_millis(500), 4, |_| {}).unwrap();
            assert!(result.bytes > 0 && result.mbps > 0.0 && result.seconds > 0.0);
            println!("{}", json!({"mode":check.protocol.as_str(), "direction":label, "bytes":result.bytes, "seconds":result.seconds, "mbps":result.mbps, "streams":4}));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a production TUN listener in a disposable Linux namespace"]
    fn linux_tun_listener_peer_rejection_fixture() {
        assert_eq!(std::env::var("IMONITOR_ACCEPT_DISPOSABLE").as_deref(), Ok("1"));
        let path = std::env::var_os("IMONITOR_KERNEL_CHECK_FILE").expect("IMONITOR_KERNEL_CHECK_FILE is required");
        let check: TunnelCheck = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert!(check.id.starts_with("accept-") && check.interface.as_deref() == Some("imtest0"));
        let listener: IpAddr = check.local_outer.as_deref().unwrap().parse().unwrap();
        let alien: IpAddr = std::env::var("IMONITOR_TUN_ALIEN_SOURCE").unwrap().parse().unwrap();
        assert_ne!(alien, check.outer_remote.as_deref().unwrap().parse::<IpAddr>().unwrap());
        let endpoint = SocketAddr::new(listener, check.transport_port.unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stream = loop {
            match connect_tun_stream(endpoint, Some(alien)) {
                Ok(stream) => break stream,
                Err(error) if Instant::now() < deadline => { println!("Waiting for production listener: {error}"); thread::sleep(Duration::from_millis(100)); }
                Err(error) => panic!("Production listener did not become available: {error}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut payload = [0; 1];
        match stream.read(&mut payload) {
            Ok(0) => (),
            Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => (),
            other => panic!("Production listener accepted the unexpected peer instead of closing before lane allocation: {other:?}"),
        }
        println!("Production TUN listener rejected unexpected source {alien}");
    }

    fn dns_answer(query: &[u8], flags: u16) -> Vec<u8> {
        let mut packet = query[..2].to_vec();
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
        packet.extend_from_slice(&query[12..]);
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 10]);
        packet
    }

    #[test]
    fn dns_rejects_query_packets_wrong_questions_and_malformed_records() {
        let query = build_dns_query(42, "example.com", DnsRecordType::A).unwrap();
        assert!(parse_dns_response(&dns_answer(&query, 0x0100), 42, "example.com", DnsRecordType::A).is_err());
        assert!(parse_dns_response(&dns_answer(&query, 0x8180), 42, "another.example", DnsRecordType::A).is_err());
        let mut malformed = dns_answer(&query, 0x8180);
        let rdlength = malformed.len() - 6;
        malformed[rdlength + 1] = 3;
        assert!(parse_dns_response(&malformed, 42, "example.com", DnsRecordType::A).is_err());
        let valid = parse_dns_response(&dns_answer(&query, 0x8180), 42, "example.com", DnsRecordType::A).unwrap();
        assert_eq!(valid.answer_count, 1);
        assert_eq!(valid.answers, vec!["192.0.2.10"]);
    }

    #[test]
    fn dns_truncation_retries_tcp_and_ignores_stale_datagrams() {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(address).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let server = thread::spawn(move || {
            let mut query = [0_u8; 512];
            let (received, peer) = udp.recv_from(&mut query).unwrap();
            let mut stale = dns_answer(&query[..received], 0x8180);
            stale[0] ^= 0x40;
            udp.send_to(&stale, peer).unwrap();
            let mut truncated = query[..received].to_vec();
            truncated[2..4].copy_from_slice(&0x8380_u16.to_be_bytes());
            udp.send_to(&truncated, peer).unwrap();
            let (mut stream, _) = tcp.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut length = [0_u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut query = vec![0_u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut query).unwrap();
            let answer = dns_answer(&query, 0x8180);
            stream.write_all(&(answer.len() as u16).to_be_bytes()).unwrap();
            stream.write_all(&answer).unwrap();
        });
        let check: DnsCheck = serde_json::from_value(json!({"id": "dns-local", "server": "127.0.0.1",
            "port": address.port(), "record_name": "example.com", "timeout_ms": 2000})).unwrap();
        let result = run_dns(&check);
        assert_eq!(result.status, CheckStatus::Up, "{}", result.message);
        assert_eq!(result.details.get("dns_transport"), Some(&json!("tcp")));
        server.join().unwrap();
    }

    #[test]
    fn udp_requires_a_reply_to_claim_service_health() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let send_only: UdpCheck = serde_json::from_value(json!({"id": "udp-local", "target": "127.0.0.1",
            "port": address.port(), "payload": "probe", "expect_response": false})).unwrap();
        assert_eq!(run_udp(&send_only).status, CheckStatus::Degraded);
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        // Consume the initial send-only probe before starting the echo server.
        let mut buffer = [0_u8; 64];
        socket.recv_from(&mut buffer).unwrap();
        let server = thread::spawn(move || {
            let (_, peer) = socket.recv_from(&mut buffer).unwrap();
            socket.send_to(b"acknowledged", peer).unwrap();
        });
        let mut with_reply = send_only;
        with_reply.expect_response = true;
        with_reply.response_contains = Some("acknowledged".to_string());
        assert_eq!(run_udp(&with_reply).status, CheckStatus::Up);
        server.join().unwrap();
    }

    #[test]
    fn tcp_tries_other_addresses_within_one_deadline() {
        let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_address = unavailable.local_addr().unwrap();
        let available = TcpListener::bind("127.0.0.1:0").unwrap();
        let live_address = available.local_addr().unwrap();
        drop(unavailable);
        let (_, connected) = connect_tcp_candidates(&[closed_address, live_address], 1000).unwrap();
        assert_eq!(connected, live_address);
    }

    #[test]
    fn http_connect_host_alias_preserves_host_and_checks_full_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut reader = BufReader::new(stream);
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" { break; }
                headers.push_str(&line);
                assert!(headers.len() < 16384);
            }
            let body = format!("{} expected-marker", "a".repeat(512));
            reader.get_mut().write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).unwrap();
            headers
        });
        let check: WebCheck = serde_json::from_value(json!({"id": "http-local", "host": "service.example.invalid",
            "connect_host": "localhost", "port": port, "body_contains": "expected-marker", "ip_version": "ipv4", "timeout_ms": 2000})).unwrap();
        let result = run_http(&check, false);
        assert_eq!(result.status, CheckStatus::Up, "{}", result.message);
        assert_eq!(result.ip_version.as_deref(), Some("ipv4"));
        assert!(server.join().unwrap().to_ascii_lowercase().contains("host: service.example.invalid"));
    }

    #[test]
    fn esp_keys_are_peer_symmetric_directional_and_secret_bound() {
        let mut first = tunnel_config();
        first.esp_key_derivation = EspKeyDerivation::HkdfSha256;
        first.tunnel_key = Some("0123456789abcdef0123456789abcdef".to_string());
        let mut second = first.clone();
        second.inner_local_cidr = Some("10.20.0.2/30".to_string());
        second.inner_probe = Some("10.20.0.1".to_string());
        let outbound = derive_esp_key_hex(&first, "192.0.2.1", "192.0.2.2").unwrap();
        assert_eq!(outbound, derive_esp_key_hex(&second, "192.0.2.1", "192.0.2.2").unwrap());
        assert_ne!(outbound, derive_esp_key_hex(&first, "192.0.2.2", "192.0.2.1").unwrap());
        second.tunnel_key = Some("ffffffffffffffffffffffffffffffff".to_string());
        assert_ne!(outbound, derive_esp_key_hex(&second, "192.0.2.1", "192.0.2.2").unwrap());
        let legacy = tunnel_config();
        assert_eq!(legacy.esp_key_derivation, EspKeyDerivation::Legacy);
        assert_eq!(derive_esp_key_hex(&legacy, "192.0.2.1", "192.0.2.2").unwrap(), derive_esp_key_hex(&legacy, "192.0.2.2", "192.0.2.1").unwrap());
    }

    #[test]
    fn xfrm_requires_matching_endpoints_in_the_same_esp_state() {
        let mismatched = "src 192.0.2.1 dst 192.0.2.9\n proto esp spi 0x100\nsrc 192.0.2.9 dst 192.0.2.2\n proto esp spi 0x200";
        assert!(!xfrm_state_matches(mismatched, Some("192.0.2.1"), Some("192.0.2.2")));
        assert!(xfrm_state_matches("src 192.0.2.1 dst 192.0.2.2\n proto esp spi 0x100", Some("192.0.2.1"), Some("192.0.2.2")));
        assert!(!xfrm_state_matches("src 192.0.2.1 dst 192.0.2.2\n proto ah spi 0x100", Some("192.0.2.1"), Some("192.0.2.2")));
    }

    #[test]
    fn ipv6_wireguard_endpoints_and_esp_live_state_validation() {
        assert_eq!(wireguard_endpoint("2001:db8::1", 51820), "[2001:db8::1]:51820");
        assert_eq!(wireguard_endpoint("[2001:db8::1]", 51820), "[2001:db8::1]:51820");
        assert_eq!(wireguard_endpoint("peer.example", 51820), "peer.example:51820");
        let state = "src 192.0.2.1 dst 192.0.2.2\n proto esp spi 0x100 reqid 12 mode tunnel\n aead rfc4106(gcm(aes)) 0x12345678 128\n if_id 0xab";
        let crypto = EspStateCrypto::LegacyGcm { key: "0x12345678".to_string() };
        assert!(esp_state_output_matches(state, 12, 0xab, &crypto));
        assert!(!esp_state_output_matches(state, 12, 0xab, &EspStateCrypto::LegacyGcm { key: "0xdeadbeef".to_string() }));
        assert!(!esp_state_output_matches(state, 12, 0xac, &crypto));
    }

    #[test]
    fn manual_esp_cbc_uses_independent_directional_keys_and_authenticated_command() {
        let mut first = tunnel_config();
        first.esp_cipher = EspCipher::AesCbcHmacSha256;
        first.esp_key_derivation = EspKeyDerivation::HkdfSha256;
        first.tunnel_key = Some("0123456789abcdef0123456789abcdef".to_string());
        validate_tunnel_configuration(&first).unwrap();
        ensure_esp_creation_safe(&first).unwrap();
        let mut second = first.clone();
        second.inner_local_cidr = Some("10.20.0.2/30".to_string());
        second.inner_probe = Some("10.20.0.1".to_string());
        let outbound = derive_esp_state_crypto(&first, "192.0.2.1", "192.0.2.2").unwrap();
        assert_eq!(outbound, derive_esp_state_crypto(&second, "192.0.2.1", "192.0.2.2").unwrap());
        assert_ne!(outbound, derive_esp_state_crypto(&first, "192.0.2.2", "192.0.2.1").unwrap());
        let EspStateCrypto::CbcHmacSha256 { encryption_key, authentication_key } = &outbound else { panic!("wrong ESP cipher"); };
        assert_ne!(encryption_key, authentication_key);
        assert_eq!(encryption_key.len(), 66);
        assert_eq!(authentication_key.len(), 66);
        let command = build_esp_state_add_command("192.0.2.1", "192.0.2.2", 0x100, 12, 0xab, "0.0.0.0/0", &outbound);
        assert!(!command.iter().any(|arg| arg == "aead"));
        assert!(command.windows(4).any(|part| part == ["auth-trunc", "hmac(sha256)", authentication_key, "128"]));
        assert!(command.windows(3).any(|part| part == ["enc", "cbc(aes)", encryption_key]));
        let state = format!("src 192.0.2.1 dst 192.0.2.2 proto esp spi 0x100 reqid 12 mode tunnel auth-trunc hmac(sha256) {authentication_key} 128 enc cbc(aes) {encryption_key} if_id 0xab");
        assert!(esp_state_output_matches(&state, 12, 0xab, &outbound));
        assert!(!esp_state_output_matches(&state.replace(" 128 ", " 96 "), 12, 0xab, &outbound));
        second.tunnel_key = Some("ffffffffffffffffffffffffffffffff".to_string());
        assert_ne!(outbound, derive_esp_state_crypto(&second, "192.0.2.1", "192.0.2.2").unwrap());
        first.esp_key_derivation = EspKeyDerivation::Legacy;
        assert!(validate_tunnel_configuration(&first).is_err());
    }

    #[test]
    fn saved_esp_gcm_is_identifiable_but_cannot_be_recreated_with_static_keys() {
        let legacy = tunnel_config();
        assert_eq!(legacy.esp_cipher, EspCipher::LegacyAesGcm);
        validate_tunnel_configuration(&legacy).unwrap();
        let crypto = derive_esp_state_crypto(&legacy, "192.0.2.1", "192.0.2.2").unwrap();
        let EspStateCrypto::LegacyGcm { key } = &crypto else { panic!("legacy cipher changed"); };
        let state = format!("src 192.0.2.1 dst 192.0.2.2 proto esp spi 0x100 reqid 12 mode tunnel aead rfc4106(gcm(aes)) {key} 128 if_id 0xab");
        assert!(esp_state_output_matches(&state, 12, 0xab, &crypto));
        let error = ensure_esp_creation_safe(&legacy).unwrap_err();
        assert!(error.contains("RFC 4106") && error.contains("IKE") && error.contains("Existing exact live states are preserved"));
    }

    #[test]
    fn managed_ssh_rejects_non_address_peer_values_before_remote_shell_commands() {
        let mut check = tunnel_config();
        check.protocol = TunnelProtocol::Ssh;
        check.interface = Some("tun42".to_string());
        assert!(validate_tunnel_configuration(&check).is_ok());
        check.inner_probe = Some("10.20.0.2; echo unexpected-command".to_string());
        assert!(validate_tunnel_configuration(&check).is_err());
    }

    #[test]
    fn ssh_monitor_rejects_oversized_identification_and_bounds_slow_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.write_all(format!("SSH-2.0-{}\r\n", "x".repeat(300)).as_bytes());
        });
        let stream = connect_with_timeouts(address, 1000).unwrap();
        assert!(read_ssh_banner(&mut BufReader::new(stream)).unwrap_err().contains("255"));
        server.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for _ in 0..30 {
                if stream.write_all(b"a").is_err() { break; }
                thread::sleep(Duration::from_millis(20));
            }
        });
        let stream = connect_with_timeouts(address, 100).unwrap();
        let started = Instant::now();
        let result = read_ssh_banner(&mut BufReader::new(stream));
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    #[ignore = "Subprocess fixture exercised by the persistent runtime lifecycle test"]
    fn runtime_child_wait() {
        thread::sleep(Duration::from_secs(60));
    }

    fn spawn_test_tunnel_children() -> ManagedChildren {
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "runner::tests::runtime_child_wait", "--ignored"])
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let mut children = ManagedChildren::default();
        children.push(child);
        children
    }

    #[test]
    fn persistent_forwarder_survives_probe_and_restarts_after_exit_or_config_change() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap();
        let mut check = tunnel_config();
        check.id = "test-persistent-child-lifecycle".to_string();
        check.protocol = TunnelProtocol::Tun;
        let mut details = BTreeMap::new();
        ensure_persistent_tunnel_runtime(&check, &mut details, |_| Ok(spawn_test_tunnel_children())).unwrap();
        let runtime = Arc::clone(tunnel_runtime_registry().lock().unwrap().get(&check.id).unwrap());
        let initial_id = runtime.lock().unwrap().children.children[0].id();
        // A second probe keeps the same live process; no new helper is started.
        ensure_persistent_tunnel_runtime(&check, &mut details, |_| panic!("Running forwarder was restarted by a probe")).unwrap();
        assert_eq!(runtime.lock().unwrap().children.children[0].id(), initial_id);
        // Changing only monitoring cadence also preserves the forwarding process.
        check.interval_secs += 30;
        ensure_persistent_tunnel_runtime(&check, &mut details, |_| panic!("Monitoring cadence restarted forwarding")).unwrap();
        // A changed transport is applied by replacing the old process.
        check.transport_port = Some(55001);
        ensure_persistent_tunnel_runtime(&check, &mut details, |_| Ok(spawn_test_tunnel_children())).unwrap();
        let changed_id = runtime.lock().unwrap().children.children[0].id();
        assert_ne!(changed_id, initial_id);
        {
            let mut runtime = runtime.lock().unwrap();
            runtime.children.children[0].kill().unwrap();
            runtime.children.children[0].wait().unwrap();
        }
        ensure_persistent_tunnel_runtime(&check, &mut details, |_| Ok(spawn_test_tunnel_children())).unwrap();
        assert_ne!(runtime.lock().unwrap().children.children[0].id(), changed_id);
        // Simulate the next cycle after disabling or deleting the monitor.
        drop(runtime);
        retire_tunnel_runtime(&check.id);
        assert!(!tunnel_runtime_registry().lock().unwrap().contains_key(&check.id));
    }

    #[test]
    fn bounded_scheduler_preserves_cached_result_order_and_retires_removed_checks() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap();
        let mut state = PersistedState::default();
        let mut checks = Vec::new();
        let now = unix_now();
        for index in 0..150 {
            let id = format!("cached-{index}");
            checks.push(serde_json::from_value(json!({"kind": "tcp", "id": id, "target": "no-lookup.example.invalid", "port": 443, "interval_secs": 60})).unwrap());
            state.last_check_run_unix.insert(id.clone(), now);
            state.last_results.insert(id.clone(), CheckResult { id, kind: "tcp".to_string(), status: CheckStatus::Up,
                message: "cached successful probe".to_string(), observed_at_unix: now, duration_ms: 1, latency_ms: Some(1),
                ip_version: Some("ipv4".to_string()), endpoint: None, details: BTreeMap::new() });
        }
        state.last_check_run_unix.insert("deleted".to_string(), now);
        let config = AgentConfig { agent_id: "scheduler-test".to_string(), interval_secs: 60, output_file: None, history_file: None, state_file: None, checks };
        let snapshot = run_cycle(&config, &mut state);
        assert_eq!(snapshot.results.len(), 150);
        for (index, result) in snapshot.results.iter().enumerate() { assert_eq!(result.id, format!("cached-{index}")); }
        assert!(!state.last_check_run_unix.contains_key("deleted"));
        assert_eq!(state.last_results.len(), 150);
    }

    #[test]
    fn parses_ping_latency_from_iputils_output() {
        let output = "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.7 ms";
        assert_eq!(parse_ping_latency(output), Some(13));
    }

    #[test]
    fn renders_url_authority_for_ipv6_hosts() {
        assert_eq!(url_authority("2001:db8::1", 443, true), "[2001:db8::1]");
        assert_eq!(
            url_authority("2001:db8::1", 8443, true),
            "[2001:db8::1]:8443"
        );
    }

    #[test]
    fn encodes_dns_name() {
        let mut buffer = Vec::new();
        encode_dns_name("example.com", &mut buffer).unwrap();
        assert_eq!(
            buffer,
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
    }

    #[test]
    fn normalizes_bare_tunnel_addresses_for_simple_setup() {
        assert_eq!(normalize_inner_local_address("10.10.10.2"), "10.10.10.2/30");
        assert_eq!(normalize_inner_local_address("10.10.10.2/29"), "10.10.10.2/29");
        assert_eq!(normalize_inner_local_address("2001:db8::2"), "2001:db8::2/127");
    }
}
