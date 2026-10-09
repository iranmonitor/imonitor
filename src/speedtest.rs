//! Authenticated, bounded TCP throughput measurement between tunnel peers.
//! Results count received bytes across the tunnel, not internet access speed.
use ring::{hmac, rand::{SecureRandom, SystemRandom}};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}, Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_PORT: u16 = 5201;
const MAX_DURATION_MS: u32 = 15_000;
const MAX_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_STREAMS: usize = 8;
const BUFFER_SIZE: usize = 64 * 1024;
const TRANSFER_DRAIN_GRACE: Duration = Duration::from_secs(10);
const PREFACE: &[u8] = b"IMONITOR-SPEED/1\n";

#[derive(Clone)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub token: String,
    pub allowed_peer: Option<IpAddr>,
}

struct ServerHandle {
    config: Arc<RwLock<ServerConfig>>,
    stop: Arc<AtomicBool>,
}
static SERVERS: OnceLock<Mutex<BTreeMap<SocketAddr, ServerHandle>>> = OnceLock::new();
static CLIENT_TESTS: AtomicUsize = AtomicUsize::new(0);

struct ClientSlot;
impl Drop for ClientSlot {
    fn drop(&mut self) { CLIENT_TESTS.fetch_sub(1, Ordering::AcqRel); }
}

fn acquire_slot(counter: &AtomicUsize, limit: usize) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    while current < limit {
        match counter.compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(updated) => current = updated,
        }
    }
    false
}

#[derive(Clone, Copy)]
pub enum Direction { Upload, Download }
impl Direction {
    fn code(self) -> u8 { if matches!(self, Self::Upload) { 1 } else { 2 } }
}

pub struct Sample {
    pub seconds: f64,
    pub bytes: u64,
    pub current_mbps: f64,
    pub average_mbps: f64,
}

#[derive(Debug)]
pub struct Measurement {
    pub bytes: u64,
    pub seconds: f64,
    pub mbps: f64,
}

pub fn validate_token(token: &str) -> Result<(), String> {
    if !(32..=128).contains(&token.len()) || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("Set the same speed-test token on both peers (32–128 ASCII characters, no spaces).".to_string());
    }
    Ok(())
}

fn validate_bind(address: SocketAddr) -> Result<(), String> {
    if address.ip().is_unspecified() || address.ip().is_multicast() || address.port() == 0 {
        return Err("Speed-test listener requires a specific tunnel IP and a nonzero port.".to_string());
    }
    Ok(())
}

/// Replace active endpoints, update credentials, and retire removed peers.
pub fn sync_servers(configs: Vec<ServerConfig>) -> Result<(), String> {
    let mut desired = BTreeMap::new();
    for config in configs {
        validate_bind(config.bind)?;
        validate_token(&config.token)?;
        if desired.insert(config.bind, config).is_some() {
            return Err("Two tunnels use the same native speed-test address. Choose different ports.".to_string());
        }
    }
    let mut servers = SERVERS.get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock().map_err(|_| "Speed-test registry lock poisoned.".to_string())?;
    servers.retain(|address, handle| {
        if desired.contains_key(address) { true } else {
            handle.stop.store(true, Ordering::Release);
            false
        }
    });
    let mut errors = Vec::new();
    for (address, config) in desired {
        if let Some(handle) = servers.get(&address) {
            if let Ok(mut current) = handle.config.write() { *current = config; }
            continue;
        }
        match TcpListener::bind(address) {
            Ok(listener) => {
                listener.set_nonblocking(true).map_err(|error| error.to_string())?;
                let config = Arc::new(RwLock::new(config));
                let stop = Arc::new(AtomicBool::new(false));
                let worker_config = Arc::clone(&config);
                let worker_stop = Arc::clone(&stop);
                thread::spawn(move || serve(listener, worker_config, worker_stop));
                servers.insert(address, ServerHandle { config, stop });
            }
            Err(error) => errors.push(format!("Native speed-test listener {address}: {error}. Check that the tunnel interface is up.")),
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join(" ")) }
}

pub fn run_server_cli(arguments: Vec<String>) -> Result<(), String> {
    let mut bind = None;
    let mut token = None;
    let mut peer = None;
    let mut index = 0;
    while index < arguments.len() {
        let key = &arguments[index];
        index += 1;
        let value = arguments.get(index).ok_or_else(|| format!("Missing value for {key}"))?;
        match key.as_str() {
            "--bind" => bind = Some(value.parse::<SocketAddr>().map_err(|_| "Invalid --bind tunnel IP:port.".to_string())?),
            "--token" => token = Some(value.clone()),
            "--peer" => peer = Some(value.parse::<IpAddr>().map_err(|_| "Invalid --peer tunnel IP.".to_string())?),
            _ => return Err(format!("Unknown speedtest-server argument: {key}")),
        }
        index += 1;
    }
    let config = ServerConfig {
        bind: bind.ok_or_else(|| "Use speedtest-server --bind TUNNEL_IP:5201 --token SHARED_TOKEN [--peer PEER_TUNNEL_IP].".to_string())?,
        token: token.ok_or_else(|| "speedtest-server requires --token.".to_string())?,
        allowed_peer: peer,
    };
    validate_bind(config.bind)?;
    validate_token(&config.token)?;
    let listener = TcpListener::bind(config.bind).map_err(|error| format!("Cannot bind native speed-test endpoint: {error}"))?;
    listener.set_nonblocking(true).map_err(|error| error.to_string())?;
    eprintln!("Native tunnel speed-test endpoint listening on {}", config.bind);
    serve(listener, Arc::new(RwLock::new(config)), Arc::new(AtomicBool::new(false)));
    Ok(())
}

fn serve(listener: TcpListener, config: Arc<RwLock<ServerConfig>>, stop: Arc<AtomicBool>) {
    let active = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let current = match config.read() { Ok(current) => current.clone(), Err(_) => continue };
                if current.allowed_peer.is_some_and(|allowed| allowed != peer.ip()) { continue; }
                if !acquire_slot(&active, MAX_STREAMS) { continue; }
                let active = Arc::clone(&active);
                thread::spawn(move || {
                    let result = serve_stream(stream, &current.token);
                    #[cfg(test)]
                    if let Err(error) = &result { eprintln!("Native speed-test fixture peer {peer}: {error}"); }
                    let _ = result;
                    active.fetch_sub(1, Ordering::AcqRel);
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
}

fn configure_stream(stream: &TcpStream) -> Result<(), String> {
    stream.set_nodelay(true).map_err(|error| error.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).map_err(|error| error.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(3))).map_err(|error| error.to_string())?;
    Ok(())
}

fn read_before(stream: &mut TcpStream, mut buffer: &mut [u8], deadline: Instant) -> Result<(), String> {
    while !buffer.is_empty() {
        let remaining = deadline.checked_duration_since(Instant::now()).filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "Native speed-test read deadline exceeded.".to_string())?;
        stream.set_read_timeout(Some(remaining)).map_err(|error| error.to_string())?;
        let received = stream.read(buffer).map_err(|error| error.to_string())?;
        if received == 0 { return Err("Native speed-test peer closed the connection.".to_string()); }
        buffer = &mut buffer[received..];
    }
    Ok(())
}

fn serve_stream(mut stream: TcpStream, token: &str) -> Result<(), String> {
    configure_stream(&stream)?;
    let handshake_deadline = Instant::now() + Duration::from_secs(3);
    let mut preface = [0_u8; PREFACE.len()];
    read_before(&mut stream, &mut preface, handshake_deadline)?;
    if preface != PREFACE { return Err("Unsupported speed-test protocol.".to_string()); }
    let mut challenge = [0_u8; 32];
    SystemRandom::new().fill(&mut challenge).map_err(|_| "Cannot generate speed-test challenge.".to_string())?;
    stream.write_all(&challenge).map_err(|error| error.to_string())?;
    let mut request = [0_u8; 37];
    read_before(&mut stream, &mut request, handshake_deadline)?;
    let duration_ms = u32::from_be_bytes(request[1..5].try_into().unwrap());
    let mut signed = challenge.to_vec();
    signed.extend_from_slice(&request[..5]);
    let key = hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes());
    if !matches!(request[0], 1 | 2) || !(100..=MAX_DURATION_MS).contains(&duration_ms)
        || hmac::verify(&key, &signed, &request[5..]).is_err() {
        let _ = stream.write_all(&[0]);
        return Err("Speed-test authentication or limits rejected.".to_string());
    }
    // Allocate and fill once, before timing; avoid compressible zero-filled data.
    let mut buffer = payload_buffer()?;
    stream.write_all(&[1]).map_err(|error| error.to_string())?;
    configure_stream(&stream)?;
    let started = Instant::now();
    let duration = Duration::from_millis(duration_ms as u64);
    // The sender can finish its timed write phase while TCP still has queued
    // payload. Include the bounded real drain in the peer's byte/time count.
    let deadline = started + duration + TRANSFER_DRAIN_GRACE;
    let mut bytes = 0_u64;
    if request[0] == 1 {
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| "Upload exceeded speed-test deadline.".to_string())?;
            stream.set_read_timeout(Some(remaining.min(Duration::from_secs(3)))).map_err(|error| error.to_string())?;
            let received = stream.read(&mut buffer).map_err(|error| error.to_string())?;
            if received == 0 { break; }
            bytes = bytes.saturating_add(received as u64);
            if bytes > MAX_BYTES { return Err("Upload exceeded byte limit.".to_string()); }
        }
        let mut result = bytes.to_be_bytes().to_vec();
        result.extend_from_slice(&(started.elapsed().as_nanos().min(u64::MAX as u128) as u64).to_be_bytes());
        stream.write_all(&result).map_err(|error| error.to_string())?;
    } else {
        while started.elapsed() < duration && bytes < MAX_BYTES {
            let written = stream.write(&buffer).map_err(|error| error.to_string())?;
            if written == 0 { return Err("Peer closed download stream.".to_string()); }
            bytes += written as u64;
        }
        let _ = stream.shutdown(Shutdown::Write);
    }
    Ok(())
}

fn payload_buffer() -> Result<Vec<u8>, String> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    SystemRandom::new().fill(&mut buffer).map_err(|_| "Cannot generate speed-test payload.".to_string())?;
    Ok(buffer)
}

pub fn measure(peer: SocketAddr, local_ip: IpAddr, token: &str, direction: Direction,
    duration: Duration, streams: usize, mut observe: impl FnMut(Sample)) -> Result<Measurement, String> {
    validate_token(token)?;
    if peer.ip().is_unspecified() || peer.ip().is_multicast() || peer.port() == 0
        || peer.ip().is_ipv4() != local_ip.is_ipv4() || local_ip.is_unspecified() {
        return Err("Speed test requires valid local and peer tunnel IPs of the same family.".to_string());
    }
    let duration_ms = duration.as_millis();
    if !(100..=MAX_DURATION_MS as u128).contains(&duration_ms) || !(1..=4).contains(&streams) {
        return Err("Speed-test duration must be 0.1–15 seconds with 1–4 streams.".to_string());
    }
    if !acquire_slot(&CLIENT_TESTS, 2) {
        return Err("Two native throughput tests are already active. Wait for completion.".to_string());
    }
    let _slot = ClientSlot;
    let progress = Arc::new(AtomicU64::new(0));
    let (send, receive) = std::sync::mpsc::channel();
    let started = Instant::now();
    let deadline = started + duration + Duration::from_secs(12);
    for _ in 0..streams {
        let send = send.clone();
        let token = token.to_string();
        let progress = Arc::clone(&progress);
        thread::spawn(move || { let _ = send.send(measure_stream(peer, local_ip, &token, direction, duration_ms as u32, progress, deadline)); });
    }
    drop(send);
    let mut completed = 0;
    let mut total_bytes = 0_u64;
    let mut measured_seconds = 0.0_f64;
    let mut last_bytes = 0_u64;
    let mut last_sample = Instant::now();
    let mut errors = Vec::new();
    while completed < streams {
        match receive.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => {
                completed += 1;
                match result {
                    Ok(result) => { total_bytes += result.bytes; measured_seconds = measured_seconds.max(result.seconds); }
                    Err(error) => errors.push(error),
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {},
            Err(_) => return Err("Speed-test worker stopped unexpectedly.".to_string()),
        }
        if last_sample.elapsed() >= Duration::from_secs(1) {
            let bytes = progress.load(Ordering::Relaxed);
            let seconds = started.elapsed().as_secs_f64();
            observe(Sample { seconds, bytes,
                current_mbps: bytes.saturating_sub(last_bytes) as f64 * 8.0 / last_sample.elapsed().as_secs_f64() / 1e6,
                average_mbps: bytes as f64 * 8.0 / seconds / 1e6 });
            last_bytes = bytes;
            last_sample = Instant::now();
        }
        if Instant::now() >= deadline {
            return Err("Speed test exceeded its deadline. Check the peer and tunnel route.".to_string());
        }
    }
    if !errors.is_empty() { return Err(format!("Native tunnel speed test failed: {}", errors.join("; "))); }
    if total_bytes == 0 || measured_seconds <= 0.0 || !measured_seconds.is_finite() {
        return Err("Peer transferred no measurable data.".to_string());
    }
    Ok(Measurement { bytes: total_bytes, seconds: measured_seconds, mbps: total_bytes as f64 * 8.0 / measured_seconds / 1e6 })
}

fn measure_stream(peer: SocketAddr, local_ip: IpAddr, token: &str, direction: Direction,
    duration_ms: u32, progress: Arc<AtomicU64>, overall_deadline: Instant) -> Result<Measurement, String> {
    let socket = Socket::new(Domain::for_address(peer), Type::STREAM, Some(Protocol::TCP)).map_err(|error| error.to_string())?;
    socket.bind(&SocketAddr::new(local_ip, 0).into()).map_err(|error| format!("Cannot bind local tunnel IP {local_ip}: {error}"))?;
    socket.connect_timeout(&peer.into(), Duration::from_secs(3)).map_err(|error| format!("Cannot reach native peer {peer}: {error}. Run iMonitor with the same speed-test token on the peer."))?;
    let mut stream: TcpStream = socket.into();
    configure_stream(&stream)?;
    let handshake_deadline = Instant::now() + Duration::from_secs(3);
    stream.write_all(PREFACE).map_err(|error| error.to_string())?;
    let mut challenge = [0_u8; 32];
    read_before(&mut stream, &mut challenge, handshake_deadline).map_err(|error| format!("Peer is not a native iMonitor speed-test endpoint: {error}"))?;
    let mut request = vec![direction.code()];
    request.extend_from_slice(&duration_ms.to_be_bytes());
    let mut signed = challenge.to_vec();
    signed.extend_from_slice(&request);
    request.extend_from_slice(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes()), &signed).as_ref());
    stream.write_all(&request).map_err(|error| error.to_string())?;
    let mut ready = [0_u8; 1];
    read_before(&mut stream, &mut ready, handshake_deadline)?;
    if ready[0] != 1 { return Err("Peer rejected the speed-test token. Set the same token on both peers.".to_string()); }
    configure_stream(&stream)?;
    let mut buffer = payload_buffer()?;
    let started = Instant::now();
    let duration = Duration::from_millis(duration_ms as u64);
    let mut bytes = 0_u64;
    if matches!(direction, Direction::Upload) {
        while started.elapsed() < duration && bytes < MAX_BYTES {
            let written = stream.write(&buffer).map_err(|error| error.to_string())?;
            if written == 0 { return Err("Peer closed upload stream.".to_string()); }
            bytes += written as u64;
            progress.fetch_add(written as u64, Ordering::Relaxed);
        }
        stream.shutdown(Shutdown::Write).map_err(|error| error.to_string())?;
        let mut result = [0_u8; 16];
        read_before(&mut stream, &mut result, overall_deadline).map_err(|error| format!("Peer did not acknowledge received upload bytes: {error}"))?;
        let acknowledged = u64::from_be_bytes(result[..8].try_into().unwrap());
        if acknowledged != bytes { return Err("Peer acknowledged a different upload byte count.".to_string()); }
        let seconds = u64::from_be_bytes(result[8..].try_into().unwrap()) as f64 / 1e9;
        return Ok(Measurement { bytes, seconds, mbps: bytes as f64 * 8.0 / seconds / 1e6 });
    }
    let drain_deadline = (started + duration + TRANSFER_DRAIN_GRACE).min(overall_deadline);
    loop {
        let remaining = drain_deadline.checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "Download exceeded its deadline.".to_string())?;
        stream.set_read_timeout(Some(remaining.min(Duration::from_secs(3)))).map_err(|error| error.to_string())?;
        let received = stream.read(&mut buffer).map_err(|error| error.to_string())?;
        if received == 0 { break; }
        bytes += received as u64;
        progress.fetch_add(received as u64, Ordering::Relaxed);
        if bytes > MAX_BYTES { return Err("Download exceeded byte limit.".to_string()); }
    }
    let seconds = started.elapsed().as_secs_f64();
    if seconds < duration.as_secs_f64() * 0.8 && bytes < MAX_BYTES {
        return Err("Peer closed download before the requested test duration.".to_string());
    }
    Ok(Measurement { bytes, seconds, mbps: bytes as f64 * 8.0 / seconds / 1e6 })
}

#[cfg(test)]
mod tests {
    use super::*;
    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn local_peer() -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = serve_stream(stream, TOKEN);
        });
        (address, handle)
    }

    #[test]
    fn upload_counts_bytes_acknowledged_by_peer() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (peer, server) = local_peer();
        let result = measure(peer, "127.0.0.1".parse().unwrap(), TOKEN, Direction::Upload,
            Duration::from_millis(150), 1, |_| {}).unwrap();
        assert!(result.bytes > 0 && result.seconds >= 0.1 && result.mbps > 0.0);
        server.join().unwrap();
    }

    #[test]
    fn download_counts_received_bytes() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (peer, server) = local_peer();
        let result = measure(peer, "127.0.0.1".parse().unwrap(), TOKEN, Direction::Download,
            Duration::from_millis(150), 1, |_| {}).unwrap();
        assert!(result.bytes > 0 && result.seconds >= 0.1 && result.mbps > 0.0);
        server.join().unwrap();
    }

    #[test]
    fn wrong_token_is_rejected_before_bulk_transfer() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (peer, server) = local_peer();
        let result = measure(peer, "127.0.0.1".parse().unwrap(), "ffffffffffffffffffffffffffffffff",
            Direction::Upload, Duration::from_millis(150), 1, |_| {});
        assert!(result.unwrap_err().contains("token"));
        server.join().unwrap();
    }

    #[test]
    fn wildcard_listener_and_unbounded_requests_rejected() {
        assert!(validate_bind("0.0.0.0:5201".parse().unwrap()).is_err());
        assert!(measure("127.0.0.1:1".parse().unwrap(), "127.0.0.1".parse().unwrap(), TOKEN,
            Direction::Upload, Duration::from_secs(60), 1, |_| {}).is_err());
    }

    #[test]
    fn four_parallel_streams_measure_peer_throughput() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            thread::scope(|scope| {
                for _ in 0..4 {
                    let (stream, _) = listener.accept().unwrap();
                    scope.spawn(move || serve_stream(stream, TOKEN).unwrap());
                }
            });
        });
        let result = measure(peer, "127.0.0.1".parse().unwrap(), TOKEN, Direction::Upload,
            Duration::from_millis(150), 4, |_| {}).unwrap();
        assert!(result.bytes > 0 && result.mbps > 0.0);
        server.join().unwrap();
    }

    #[test]
    fn authenticated_peer_cannot_request_an_unbounded_duration() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (peer, server) = local_peer();
        let mut stream = TcpStream::connect(peer).unwrap();
        configure_stream(&stream).unwrap();
        stream.write_all(PREFACE).unwrap();
        let mut challenge = [0_u8; 32];
        stream.read_exact(&mut challenge).unwrap();
        let mut request = vec![1];
        request.extend_from_slice(&60_000_u32.to_be_bytes());
        let mut signed = challenge.to_vec();
        signed.extend_from_slice(&request);
        request.extend_from_slice(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, TOKEN.as_bytes()), &signed).as_ref());
        stream.write_all(&request).unwrap();
        let mut ready = [1_u8; 1];
        stream.read_exact(&mut ready).unwrap();
        assert_eq!(ready[0], 0);
        server.join().unwrap();
    }

    fn accept_test_peer(listener: &TcpListener) -> std::io::Result<TcpStream> {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    // Windows accepted sockets inherit the listener's mode;
                    // the bounded polling listener is only a fixture detail.
                    stream.set_nonblocking(false)?;
                    return Ok(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        }
    }

    // Relay genuine protocol traffic to a real native server. Small steady
    // chunks exercise an upload still arriving after the sender has closed;
    // delaying only the result tests that client accounting waits for the
    // actual peer count rather than reporting queued socket bytes as success.
    fn upload_relay(chunk_delay: Option<Duration>, ack_delay: Duration) -> (
        SocketAddr,
        thread::JoinHandle<std::io::Result<(u64, u64)>>,
        thread::JoinHandle<Result<(), String>>,
    ) {
        let native = TcpListener::bind("127.0.0.1:0").unwrap();
        let native_address = native.local_addr().unwrap();
        let relay = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_address = relay.local_addr().unwrap();
        let server = thread::spawn(move || {
            let stream = accept_test_peer(&native).map_err(|error| error.to_string())?;
            serve_stream(stream, TOKEN)
        });
        let relay = thread::spawn(move || -> std::io::Result<(u64, u64)> {
            let mut client = accept_test_peer(&relay)?;
            let mut peer = TcpStream::connect_timeout(&native_address, Duration::from_secs(2))?;
            for stream in [&client, &peer] {
                stream.set_nodelay(true)?;
                stream.set_read_timeout(Some(Duration::from_secs(8)))?;
                stream.set_write_timeout(Some(Duration::from_secs(8)))?;
            }
            let mut result_client = client.try_clone()?;
            let mut result_peer = peer.try_clone()?;
            thread::scope(|scope| {
                let result_worker = scope.spawn(move || -> std::io::Result<u64> {
                    let mut challenge = [0_u8; 32];
                    result_peer.read_exact(&mut challenge)?;
                    result_client.write_all(&challenge)?;
                    let mut ready = [0_u8; 1];
                    result_peer.read_exact(&mut ready)?;
                    result_client.write_all(&ready)?;
                    let mut result = [0_u8; 16];
                    result_peer.read_exact(&mut result)?;
                    thread::sleep(ack_delay);
                    // Fragment the acknowledgement as a real TCP relay can.
                    result_client.write_all(&result[..8])?;
                    thread::sleep(Duration::from_millis(20));
                    result_client.write_all(&result[8..])?;
                    result_client.shutdown(Shutdown::Write)?;
                    Ok(u64::from_be_bytes(result[..8].try_into().unwrap()))
                });
                let payload_result = (|| -> std::io::Result<u64> {
                    let mut preface = [0_u8; PREFACE.len()];
                    client.read_exact(&mut preface)?;
                    peer.write_all(&preface)?;
                    let mut request = [0_u8; 37];
                    client.read_exact(&mut request)?;
                    peer.write_all(&request)?;
                    let mut bytes = 0_u64;
                    let mut chunk = [0_u8; 1024];
                    loop {
                        let received = client.read(&mut chunk)?;
                        if received == 0 { break; }
                        if let Some(delay) = chunk_delay { thread::sleep(delay); }
                        peer.write_all(&chunk[..received])?;
                        bytes += received as u64;
                    }
                    peer.shutdown(Shutdown::Write)?;
                    Ok(bytes)
                })();
                // Always join the relay worker before surfacing either error.
                let acknowledgement = result_worker.join().unwrap();
                Ok((payload_result?, acknowledgement?))
            })
        });
        (relay_address, relay, server)
    }

    #[test]
    fn upload_server_counts_a_steady_slow_relay_tail_after_sender_fin() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (peer, relay, server) = upload_relay(Some(Duration::from_millis(55)), Duration::ZERO);
        let client_result = (|| -> Result<(u64, f64), String> {
            let mut stream = TcpStream::connect_timeout(&peer, Duration::from_secs(2)).map_err(|error| error.to_string())?;
            configure_stream(&stream)?;
            stream.set_read_timeout(Some(Duration::from_secs(8))).map_err(|error| error.to_string())?;
            stream.write_all(PREFACE).map_err(|error| error.to_string())?;
            let mut challenge = [0_u8; 32];
            stream.read_exact(&mut challenge).map_err(|error| error.to_string())?;
            let mut request = vec![1_u8];
            request.extend_from_slice(&150_u32.to_be_bytes());
            let mut signed = challenge.to_vec();
            signed.extend_from_slice(&request);
            request.extend_from_slice(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, TOKEN.as_bytes()), &signed).as_ref());
            stream.write_all(&request).map_err(|error| error.to_string())?;
            let mut ready = [0_u8; 1];
            stream.read_exact(&mut ready).map_err(|error| error.to_string())?;
            if ready[0] != 1 { return Err("Real native peer rejected the fixture request.".to_string()); }
            stream.write_all(&payload_buffer()?).map_err(|error| error.to_string())?;
            stream.shutdown(Shutdown::Write).map_err(|error| error.to_string())?;
            let mut result = [0_u8; 16];
            stream.read_exact(&mut result).map_err(|error| error.to_string())?;
            Ok((u64::from_be_bytes(result[..8].try_into().unwrap()), u64::from_be_bytes(result[8..].try_into().unwrap()) as f64 / 1e9))
        })();
        let relay_result = relay.join().unwrap();
        let server_result = server.join().unwrap();
        let (acknowledged, seconds) = client_result.unwrap();
        let (forwarded, peer_count) = relay_result.unwrap();
        server_result.unwrap();
        assert_eq!(acknowledged, BUFFER_SIZE as u64);
        assert_eq!((forwarded, peer_count), (acknowledged, acknowledged));
        assert!(seconds >= 3.2 && seconds < 8.0, "The elapsed time must include the real slow relay tail: {seconds}");
    }

    #[test]
    fn upload_client_waits_for_a_delayed_fragmented_peer_acknowledgement() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (peer, relay, server) = upload_relay(None, Duration::from_millis(3200));
        let started = Instant::now();
        let measured = measure(peer, "127.0.0.1".parse().unwrap(), TOKEN, Direction::Upload,
            Duration::from_millis(150), 1, |_| {});
        let relay_result = relay.join().unwrap();
        let server_result = server.join().unwrap();
        let measurement = measured.unwrap();
        let (forwarded, acknowledged) = relay_result.unwrap();
        server_result.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(3200));
        assert_eq!(measurement.bytes, forwarded);
        assert_eq!(measurement.bytes, acknowledged);
        assert!(measurement.bytes > 0 && measurement.seconds > 0.0 && measurement.mbps > 0.0);
    }
}
