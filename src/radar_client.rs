use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ring::{aead, digest, hmac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Write as _;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::Command;
use crate::util::random_bytes;

pub const IRANMONITOR_RADAR_URL: &str = "https://irnmo.ir/api/radar";
// Keep the authenticated transport contract stable; payload.app_version carries 1.2.2.
pub const IRANMONITOR_RADAR_USER_AGENT: &str = "imonitor V1.0";
pub const IRANMONITOR_RADAR_CONTENT_TYPE: &str = "application/vnd.imonitor.radar+json";
pub const IRANMONITOR_RADAR_DEFAULT_SHARED_SECRET: &str =
    "2f36b4d8f8f0dfbd4fd4f4c75e6d7a7f2bc4f7a4dbd44ad8b46dd6c6a9fc7f7c";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub alg: String,
    pub iv: String,
    pub tag: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadarStatusRequestPayload {
    pub action: String,
    pub timestamp: u64,
    pub timestamp_hash: String,
    pub app_version: String,
    pub device_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadarReportRequestPayload {
    pub action: String,
    pub timestamp: u64,
    pub timestamp_hash: String,
    pub app_version: String,
    pub device_label: String,
    pub asn: String,
    pub dc_name: String,
    pub results: Vec<RadarCheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RadarStatusResponse {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub generated_at: String,
    #[serde(default)]
    pub interval_seconds: u64,
    #[serde(default)]
    pub checks: Vec<RadarStatusCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RadarStatusCheck {
    pub code: String,
    #[serde(rename = "type")]
    pub check_type: String,
    pub target: String,
    #[serde(default)]
    pub interval_seconds: u64,
    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RadarReportResponse {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadarCheckResult {
    pub code: String,
    #[serde(rename = "type")]
    pub check_type: String,
    pub target: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    pub tested_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_loss_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RadarClientConfig {
    pub device_label: String,
    pub shared_secret: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadarAction {
    Status,
    Report,
}

impl RadarAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Report => "report",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RadarClientErrorKind {
    InvalidConfiguration,
    Transport,
    DnsProtection,
    Crypto,
    Protocol,
}

#[derive(Debug, Clone)]
pub struct RadarClientError {
    kind: RadarClientErrorKind,
    pub code: String,
    pub message: String,
}

impl RadarClientError {
    fn new(kind: RadarClientErrorKind, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone)]
struct TransportResponse {
    remote_ip: String,
    body: Vec<u8>,
}

pub struct IranMonitorRadarClient {
    endpoint: &'static str,
}

impl Default for IranMonitorRadarClient {
    fn default() -> Self {
        Self::new()
    }
}

impl IranMonitorRadarClient {
    pub fn new() -> Self {
        Self {
            endpoint: IRANMONITOR_RADAR_URL,
        }
    }

    pub fn fetch_status(
        &self,
        config: &RadarClientConfig,
    ) -> Result<RadarStatusResponse, RadarClientError> {
        let timestamp = crate::platform::unix_now();
        let nonce = random_nonce()?;
        let payload = RadarStatusRequestPayload {
            action: RadarAction::Status.as_str().to_string(),
            timestamp,
            timestamp_hash: build_timestamp_hash(&config.shared_secret, timestamp, &nonce),
            app_version: crate::app::IMONITOR_RELEASE_VERSION.to_string(),
            device_label: config.device_label.trim().to_string(),
        };
        let raw_envelope = encrypt_request_payload(&config.shared_secret, &payload)?;
        let signature = build_request_signature(&config.shared_secret, &raw_envelope, timestamp, &nonce);
        let transport = self.send_encrypted_request(
            "/status",
            &raw_envelope,
            timestamp,
            &nonce,
            &signature,
        )?;
        decrypt_response_payload(&config.shared_secret, &transport.body)
    }

    pub fn send_report(
        &self,
        config: &RadarClientConfig,
        asn: &str,
        dc_name: &str,
        results: Vec<RadarCheckResult>,
    ) -> Result<RadarReportResponse, RadarClientError> {
        let timestamp = crate::platform::unix_now();
        let nonce = random_nonce()?;
        let payload = RadarReportRequestPayload {
            action: RadarAction::Report.as_str().to_string(),
            timestamp,
            timestamp_hash: build_timestamp_hash(&config.shared_secret, timestamp, &nonce),
            app_version: crate::app::IMONITOR_RELEASE_VERSION.to_string(),
            device_label: config.device_label.trim().to_string(),
            asn: asn.trim().to_string(),
            dc_name: dc_name.trim().to_string(),
            results,
        };
        let raw_envelope = encrypt_request_payload(&config.shared_secret, &payload)?;
        let signature = build_request_signature(&config.shared_secret, &raw_envelope, timestamp, &nonce);
        let transport = self.send_encrypted_request(
            "/report",
            &raw_envelope,
            timestamp,
            &nonce,
            &signature,
        )?;
        decrypt_response_payload(&config.shared_secret, &transport.body)
    }

    fn send_encrypted_request(
        &self,
        path: &str,
        raw_body: &[u8],
        timestamp: u64,
        nonce: &str,
        signature: &str,
    ) -> Result<TransportResponse, RadarClientError> {
        send_via_curl(
            self.endpoint,
            path,
            raw_body,
            timestamp,
            nonce,
            signature,
        )
    }
}

fn ensure_radar_endpoint(endpoint: &str, path: &str) -> Result<(), RadarClientError> {
    if !endpoint.starts_with("https://") {
        return Err(RadarClientError::new(
            RadarClientErrorKind::InvalidConfiguration,
            "insecure_endpoint",
            "IranMonitor radar endpoint must use HTTPS only",
        ));
    }
    let without_scheme = endpoint.trim_start_matches("https://");
    let host_port = without_scheme.split('/').next().unwrap_or("");
    let host = host_port
        .strip_prefix('[')
        .and_then(|value| value.split(']').next())
        .unwrap_or_else(|| host_port.split(':').next().unwrap_or(""));
    if !host.eq_ignore_ascii_case("irnmo.ir")
        && !host.eq_ignore_ascii_case("iranmonitor.net")
    {
        return Err(RadarClientError::new(
            RadarClientErrorKind::InvalidConfiguration,
            "unexpected_host",
            "IranMonitor radar endpoint host must be irnmo.ir or iranmonitor.net",
        ));
    }
    let endpoint_path = without_scheme
        .split_once('/')
        .map(|(_, value)| format!("/{}", value.trim_end_matches('/')))
        .unwrap_or_default();
    let expected_full_path = format!("/api/radar{path}");
    if endpoint_path != "/api/radar" && endpoint_path != expected_full_path {
        return Err(RadarClientError::new(
            RadarClientErrorKind::InvalidConfiguration,
            "unexpected_path",
            format!("IranMonitor radar endpoint path must be /api/radar{path}"),
        ));
    }
    Ok(())
}

fn encrypt_request_payload<T: Serialize>(
    shared_secret: &str,
    payload: &T,
) -> Result<Vec<u8>, RadarClientError> {
    let plaintext = serde_json::to_vec(payload).map_err(|error| {
        RadarClientError::new(
            RadarClientErrorKind::Protocol,
            "payload_encode_failed",
            format!("failed to serialize radar payload: {error}"),
        )
    })?;
    let envelope = encrypt_envelope(shared_secret, &plaintext)?;
    serde_json::to_vec(&envelope).map_err(|error| {
        RadarClientError::new(
            RadarClientErrorKind::Protocol,
            "envelope_encode_failed",
            format!("failed to serialize encrypted radar envelope: {error}"),
        )
    })
}

fn decrypt_response_payload<T: for<'de> Deserialize<'de>>(
    shared_secret: &str,
    encrypted_body: &[u8],
) -> Result<T, RadarClientError> {
    let plaintext = decrypt_envelope(shared_secret, encrypted_body)?;
    serde_json::from_slice(&plaintext).map_err(|error| {
        RadarClientError::new(
            RadarClientErrorKind::Protocol,
            "response_decode_failed",
            format!("failed to decode decrypted radar response: {error}"),
        )
    })
}

fn encrypt_envelope(shared_secret: &str, plaintext: &[u8]) -> Result<EncryptedEnvelope, RadarClientError> {
    let key_bytes = derive_aes_key(shared_secret);
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).map_err(|_| {
        RadarClientError::new(
            RadarClientErrorKind::Crypto,
            "aead_key_failed",
            "failed to initialize AES-256-GCM key",
        )
    })?;
    let key = aead::LessSafeKey::new(unbound);
    let iv = random_bytes(12).map_err(|error| {
        RadarClientError::new(
            RadarClientErrorKind::Crypto,
            "iv_generation_failed",
            error,
        )
    })?;
    let nonce = aead::Nonce::assume_unique_for_key(copy_iv_to_array(&iv)?);
    let mut ciphertext = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(nonce, aead::Aad::empty(), &mut ciphertext)
        .map_err(|_| {
            RadarClientError::new(
                RadarClientErrorKind::Crypto,
                "aes_gcm_encrypt_failed",
                "failed to encrypt radar payload with AES-256-GCM",
            )
        })?;

    Ok(EncryptedEnvelope {
        alg: "AES-256-GCM".to_string(),
        iv: BASE64_STANDARD.encode(iv),
        tag: BASE64_STANDARD.encode(tag.as_ref()),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    })
}

fn decrypt_envelope(shared_secret: &str, encrypted_body: &[u8]) -> Result<Vec<u8>, RadarClientError> {
    let envelope: EncryptedEnvelope = serde_json::from_slice(encrypted_body).map_err(|error| {
        RadarClientError::new(
            RadarClientErrorKind::Protocol,
            "response_not_encrypted_json",
            format!("radar server did not return a valid encrypted JSON envelope: {error}"),
        )
    })?;
    if !envelope.alg.trim().eq_ignore_ascii_case("aes-256-gcm") {
        return Err(RadarClientError::new(
            RadarClientErrorKind::Protocol,
            "unexpected_algorithm",
            format!("unsupported response encryption algorithm: {}", envelope.alg),
        ));
    }
    let iv = BASE64_STANDARD.decode(envelope.iv.trim()).map_err(|error| {
        RadarClientError::new(
            RadarClientErrorKind::Protocol,
            "response_iv_invalid",
            format!("invalid response IV base64: {error}"),
        )
    })?;
    let ciphertext = BASE64_STANDARD
        .decode(envelope.ciphertext.trim())
        .map_err(|error| {
            RadarClientError::new(
                RadarClientErrorKind::Protocol,
                "response_ciphertext_invalid",
                format!("invalid response ciphertext base64: {error}"),
            )
        })?;
    let tag = BASE64_STANDARD.decode(envelope.tag.trim()).map_err(|error| {
        RadarClientError::new(
            RadarClientErrorKind::Protocol,
            "response_tag_invalid",
            format!("invalid response tag base64: {error}"),
        )
    })?;
    let key_bytes = derive_aes_key(shared_secret);
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).map_err(|_| {
        RadarClientError::new(
            RadarClientErrorKind::Crypto,
            "aead_key_failed",
            "failed to initialize AES-256-GCM key",
        )
    })?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(copy_iv_to_array(&iv)?);
    let mut in_out = ciphertext;
    in_out.extend_from_slice(&tag);
    let plaintext = key
        .open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| {
            RadarClientError::new(
                RadarClientErrorKind::Crypto,
                "aes_gcm_decrypt_failed",
                "failed to decrypt the radar server response",
            )
        })?;
    Ok(plaintext.to_vec())
}

fn build_timestamp_hash(shared_secret: &str, timestamp: u64, nonce: &str) -> String {
    let input = format!("{timestamp}|{nonce}|{IRANMONITOR_RADAR_USER_AGENT}");
    hmac_sha256_hex(shared_secret.as_bytes(), input.as_bytes())
}

fn build_request_signature(
    shared_secret: &str,
    raw_body: &[u8],
    timestamp: u64,
    nonce: &str,
) -> String {
    let mut bytes = Vec::with_capacity(raw_body.len() + nonce.len() + 32);
    bytes.extend_from_slice(raw_body);
    bytes.extend_from_slice(b"|");
    bytes.extend_from_slice(timestamp.to_string().as_bytes());
    bytes.extend_from_slice(b"|");
    bytes.extend_from_slice(nonce.as_bytes());
    bytes.extend_from_slice(b"|");
    bytes.extend_from_slice(IRANMONITOR_RADAR_USER_AGENT.as_bytes());
    hmac_sha256_hex(shared_secret.as_bytes(), &bytes)
}

fn send_via_curl(
    endpoint: &str,
    path: &str,
    raw_body: &[u8],
    timestamp: u64,
    nonce: &str,
    signature: &str,
) -> Result<TransportResponse, RadarClientError> {
    ensure_radar_endpoint(endpoint, path)?;
    let temp_root = std::env::temp_dir();
    let token = random_temp_token().map_err(|error| {
        RadarClientError::new(
            RadarClientErrorKind::Transport,
            "request_temp_token_failed",
            error,
        )
    })?;
    let request_path = temp_root.join(format!("imonitor-radar-{token}-request.json"));
    let response_path = temp_root.join(format!("imonitor-radar-{token}-response.bin"));
    let config_path = temp_root.join(format!("imonitor-radar-{token}.curl"));

    fs::write(&request_path, raw_body).map_err(|error| {
        RadarClientError::new(
            RadarClientErrorKind::Transport,
            "request_body_write_failed",
            format!("failed to write radar payload for curl: {error}"),
        )
    })?;
    let config_body = build_curl_config(
        endpoint,
        path,
        &request_path,
        &response_path,
        timestamp,
        nonce,
        signature,
    );
    fs::write(&config_path, config_body).map_err(|error| {
        RadarClientError::new(
            RadarClientErrorKind::Transport,
            "request_config_write_failed",
            format!("failed to write radar curl config: {error}"),
        )
    })?;

    let output = Command::new("curl")
        .arg("--config")
        .arg(&config_path)
        .output()
        .map_err(|error| {
            cleanup_temp_files(&[&request_path, &response_path, &config_path]);
            RadarClientError::new(
                RadarClientErrorKind::Transport,
                "curl_execute_failed",
                format!("failed to execute curl for iranmonitor radar: {error}"),
            )
        })?;

    let response_bytes = fs::read(&response_path).unwrap_or_default();
    cleanup_temp_files(&[&request_path, &response_path, &config_path]);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(RadarClientError::new(
            RadarClientErrorKind::Transport,
            "curl_transport_failed",
            if stderr.is_empty() {
                "curl could not reach the iranmonitor radar endpoint".to_string()
            } else {
                stderr
            },
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines().rev();
    let effective_url = lines.next().unwrap_or("").trim().to_string();
    let remote_ip = lines.next().unwrap_or("").trim().to_string();
    let http_status = lines
        .next()
        .unwrap_or("0")
        .trim()
        .parse::<u16>()
        .unwrap_or(0);

    validate_resolved_ip(&remote_ip)?;
    ensure_radar_endpoint(&effective_url, path)?;
    if response_bytes.is_empty() {
        return Err(RadarClientError::new(
            RadarClientErrorKind::Protocol,
            "empty_radar_response",
            format!("radar server returned an empty response (HTTP {http_status})"),
        ));
    }

    Ok(TransportResponse {
        remote_ip,
        body: response_bytes,
    })
}

fn build_curl_config(
    endpoint: &str,
    path: &str,
    request_path: &PathBuf,
    response_path: &PathBuf,
    timestamp: u64,
    nonce: &str,
    signature: &str,
) -> String {
    let mut config = String::new();
    push_curl_flag(&mut config, "silent");
    push_curl_flag(&mut config, "show-error");
    push_curl_flag(&mut config, "request = \"POST\"");
    push_curl_flag(&mut config, &format!("url = {}", curl_quote(&format!("{endpoint}{path}"))));
    push_curl_flag(
        &mut config,
        &format!("user-agent = {}", curl_quote(IRANMONITOR_RADAR_USER_AGENT)),
    );
    push_curl_flag(
        &mut config,
        &format!(
            "header = {}",
            curl_quote(&format!("Content-Type: {IRANMONITOR_RADAR_CONTENT_TYPE}"))
        ),
    );
    push_curl_flag(
        &mut config,
        &format!("header = {}", curl_quote(&format!("X-IMonitor-Radar-Nonce: {nonce}"))),
    );
    push_curl_flag(
        &mut config,
        &format!(
            "header = {}",
            curl_quote(&format!("X-IMonitor-Radar-Timestamp: {timestamp}"))
        ),
    );
    push_curl_flag(
        &mut config,
        &format!(
            "header = {}",
            curl_quote(&format!("X-IMonitor-Radar-Signature: {signature}"))
        ),
    );
    push_curl_flag(
        &mut config,
        &format!(
            "data-binary = {}",
            curl_quote(&format!("@{}", request_path.display()))
        ),
    );
    push_curl_flag(
        &mut config,
        &format!("output = {}", curl_quote(&response_path.display().to_string())),
    );
    push_curl_flag(
        &mut config,
        &format!(
            "write-out = {}",
            curl_quote("\\n%{http_code}\\n%{remote_ip}\\n%{url_effective}")
        ),
    );
    push_curl_flag(&mut config, "proto = \"=https\"");
    push_curl_flag(&mut config, "proto-redir = \"=https\"");
    push_curl_flag(&mut config, "tlsv1.2");
    push_curl_flag(&mut config, "tls-max = \"1.3\"");
    push_curl_flag(&mut config, "connect-timeout = 10");
    push_curl_flag(&mut config, "max-time = 30");
    push_curl_flag(&mut config, "location");
    push_curl_flag(&mut config, "max-redirs = 3");
    push_curl_flag(&mut config, "post301");
    push_curl_flag(&mut config, "post302");
    push_curl_flag(&mut config, "post303");
    push_curl_flag(&mut config, "retry = 0");
    config
}

fn push_curl_flag(target: &mut String, line: &str) {
    target.push_str(line);
    target.push('\n');
}

fn curl_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn cleanup_temp_files(paths: &[&PathBuf]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}

fn derive_aes_key(shared_secret: &str) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, shared_secret.as_bytes());
    let mut key = [0_u8; 32];
    key.copy_from_slice(digest.as_ref());
    key
}

fn copy_iv_to_array(iv: &[u8]) -> Result<[u8; 12], RadarClientError> {
    if iv.len() != 12 {
        return Err(RadarClientError::new(
            RadarClientErrorKind::Protocol,
            "invalid_iv_length",
            format!("AES-256-GCM IV must be 12 bytes, got {}", iv.len()),
        ));
    }
    let mut array = [0_u8; 12];
    array.copy_from_slice(iv);
    Ok(array)
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    hex_encode(tag.as_ref())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn random_nonce() -> Result<String, RadarClientError> {
    random_temp_token().map_err(|error| {
        RadarClientError::new(
            RadarClientErrorKind::Crypto,
            "nonce_generation_failed",
            error,
        )
    })
}

fn random_temp_token() -> Result<String, String> {
    let bytes = crate::util::random_bytes(16)?;
    Ok(hex_encode(&bytes))
}

fn validate_resolved_ip(remote_ip: &str) -> Result<(), RadarClientError> {
    let ip = remote_ip.parse::<IpAddr>().map_err(|_| {
        RadarClientError::new(
            RadarClientErrorKind::DnsProtection,
            "remote_ip_missing",
            "could not validate the resolved iranmonitor.net address",
        )
    })?;
    if !ip_is_public(ip) {
        return Err(RadarClientError::new(
            RadarClientErrorKind::DnsProtection,
            "dns_rebinding_blocked",
            format!(
                "dns protection blocked a non-public iranmonitor.net target address: {remote_ip}"
            ),
        ));
    }
    Ok(())
}

fn ip_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ipv4_is_public(ip),
        IpAddr::V6(ip) => ipv6_is_public(ip),
    }
}

fn ipv4_is_public(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.octets()[0] == 0
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000) == 0b0100_0000)
        || (ip.octets()[0] >= 224))
}

fn ipv6_is_public(ip: Ipv6Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.segments()[0] & 0xfe00 == 0xfc00
        || (ip.segments()[0] & 0xffc0) == 0xfe80)
}

#[cfg(test)]
mod tests {
    use super::ensure_radar_endpoint;

    #[test]
    fn accepts_radar_base_and_effective_paths() {
        assert!(ensure_radar_endpoint("https://irnmo.ir/api/radar", "/status").is_ok());
        assert!(ensure_radar_endpoint("https://irnmo.ir/api/radar/status", "/status").is_ok());
        assert!(ensure_radar_endpoint("https://iranmonitor.net/api/radar/report", "/report").is_ok());
    }

    #[test]
    fn rejects_unexpected_radar_paths() {
        assert!(ensure_radar_endpoint("https://irnmo.ir/api/other", "/status").is_err());
    }
}
