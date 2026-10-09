use crate::types::{CheckResult, CheckStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UiLanguage {
    Fa,
    En,
}

impl UiLanguage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fa => "fa",
            Self::En => "en",
        }
    }

    pub fn from_str(value: &str) -> Self {
        if value.eq_ignore_ascii_case("en") {
            Self::En
        } else {
            Self::Fa
        }
    }

    pub fn is_rtl(self) -> bool {
        matches!(self, Self::Fa)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminSection {
    Overview,
    ServerHealth,
    Monitors,
    Tunnels,
    Guide,
    Folders,
    Notifications,
    Backups,
    Settings,
    NetworkControls,
    SourceIp,
    Forwarding,
    Sockets,
    Reports,
}

impl AdminSection {
    pub fn path(self) -> &'static str {
        match self {
            Self::Overview => "/admin/",
            Self::ServerHealth => "/admin/server-health",
            Self::Monitors => "/admin/monitors",
            Self::Tunnels => "/admin/tunnels",
            Self::Guide => "/admin/guide",
            Self::Folders => "/admin/folders",
            Self::Notifications => "/admin/notifications",
            Self::Backups => "/admin/backups",
            Self::Settings => "/admin/panel-settings",
            Self::NetworkControls => "/admin/network-controls",
            Self::SourceIp => "/admin/source-ip",
            Self::Forwarding => "/admin/forwarding",
            Self::Sockets => "/admin/sockets",
            Self::Reports => "/admin/reports",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub app_name: String,
    pub bind_addr: String,
    pub agent_id: String,
    pub interval_secs: u64,
    pub default_language: UiLanguage,
    pub public_title: String,
    pub public_subtitle: String,
    pub public_share_enabled: bool,
    pub public_history_points: usize,
    pub primary_color: String,
    pub secondary_color: String,
    pub background_color: String,
    pub dark_mode_default: bool,
    pub logo_url: String,
    pub favicon_url: String,
    pub contact_email: String,
    pub contact_telegram: String,
    pub contact_phone: String,
    pub telegram_bot_token: String,
    pub telegram_admin_chat_id: String,
    pub telegram_failure_threshold: u32,
    pub telegram_socks5_host: String,
    pub telegram_socks5_port: u16,
    pub telegram_socks5_username: String,
    pub telegram_socks5_password: String,
    pub public_base_url: String,
    pub admin_base_url: String,
    pub ssl_mode: String,
    pub ssl_cert_path: String,
    pub ssl_key_path: String,
    pub reverse_proxy_server_name: String,
    pub reverse_proxy_enabled: bool,
    pub free_report_enabled: bool,
    pub free_report_endpoint: String,
    pub free_report_token: String,
    pub free_report_websites: String,
    pub notes: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            app_name: "iMonitor".to_string(),
            bind_addr: "0.0.0.0:6060".to_string(),
            agent_id: "iranmonitor-node".to_string(),
            interval_secs: 60,
            default_language: UiLanguage::Fa,
            public_title: "وضعیت شبکه ایران مانیتور".to_string(),
            public_subtitle: "نمای زنده از وضعیت سرویس‌ها و سلامت شبکه".to_string(),
            public_share_enabled: true,
            public_history_points: 48,
            primary_color: "#22c55e".to_string(),
            secondary_color: "#16a34a".to_string(),
            background_color: "#06110a".to_string(),
            dark_mode_default: true,
            logo_url: String::new(),
            favicon_url: String::new(),
            contact_email: "support@example.com".to_string(),
            contact_telegram: "@iranmonitor".to_string(),
            contact_phone: String::new(),
            telegram_bot_token: String::new(),
            telegram_admin_chat_id: String::new(),
            telegram_failure_threshold: 3,
            telegram_socks5_host: String::new(),
            telegram_socks5_port: 1080,
            telegram_socks5_username: String::new(),
            telegram_socks5_password: String::new(),
            public_base_url: "http://127.0.0.1:6060/".to_string(),
            admin_base_url: "http://127.0.0.1:6060/admin".to_string(),
            ssl_mode: "reverse_proxy".to_string(),
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
            reverse_proxy_server_name: "status.example.com".to_string(),
            reverse_proxy_enabled: false,
            free_report_enabled: false,
            free_report_endpoint: String::new(),
            free_report_token: String::new(),
            free_report_websites: "https://www.google.com,https://www.cloudflare.com".to_string(),
            notes: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorCheckRow {
    pub db_id: i64,
    pub check_id: String,
    pub label: String,
    pub kind: String,
    pub enabled: bool,
    pub public_visible: bool,
    pub display_group: String,
    pub group_logo_url: String,
    pub group_logo_shape: String,
    pub check_json: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorFolder {
    pub name: String,
    pub logo_url: String,
    pub logo_shape: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSnapshot {
    pub id: i64,
    pub created_at_unix: u64,
    pub overall_status: String,
    pub system_json: String,
    pub results_json: String,
    pub summary_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSample {
    pub observed_at_unix: u64,
    pub cpu_percent: f64,
    pub ram_percent: f64,
    pub swap_percent: f64,
    pub disk_percent: f64,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub total_ram_bytes: u64,
    pub used_ram_bytes: u64,
    pub total_swap_bytes: u64,
    pub used_swap_bytes: u64,
    pub total_disk_bytes: u64,
    pub used_disk_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSummary {
    pub observed_at_unix: u64,
    pub total_checks: usize,
    pub up_checks: usize,
    pub degraded_checks: usize,
    pub down_checks: usize,
}

pub fn overall_status_from_counts(
    total_checks: usize,
    up_checks: usize,
    degraded_checks: usize,
    down_checks: usize,
) -> &'static str {
    if total_checks == 0 || (down_checks == 0 && degraded_checks == 0) {
        "up"
    } else if down_checks > 0 && down_checks.saturating_mul(2) >= total_checks {
        "down"
    } else if up_checks > 0 || degraded_checks > 0 || down_checks > 0 {
        "degraded"
    } else {
        "up"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicStatusPayload {
    pub settings: PublicBranding,
    pub summary: SnapshotSummary,
    pub latest_results: Vec<PublicCheckView>,
    pub history: Vec<HistoryPoint>,
    pub system_history: Vec<SystemSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicBranding {
    pub title: String,
    pub subtitle: String,
    pub logo_url: String,
    pub favicon_url: String,
    pub primary_color: String,
    pub secondary_color: String,
    pub background_color: String,
    pub dark_mode_default: bool,
    pub contact_email: String,
    pub contact_telegram: String,
    pub contact_phone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCheckHistoryPoint {
    pub observed_at_unix: u64,
    pub status: CheckStatus,
    #[serde(default)]
    pub latency_ms: Option<u64>,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCheckView {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub status: CheckStatus,
    pub message: String,
    pub latency_ms: Option<u64>,
    pub endpoint: Option<String>,
    pub observed_at_unix: u64,
    #[serde(default)]
    pub group_name: String,
    #[serde(default)]
    pub group_logo_url: String,
    #[serde(default)]
    pub group_logo_shape: String,
    #[serde(default)]
    pub history: Vec<PublicCheckHistoryPoint>,
    #[serde(default)]
    pub is_pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryPoint {
    pub observed_at_unix: u64,
    pub up_checks: usize,
    pub degraded_checks: usize,
    pub down_checks: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficWatcher {
    pub id: i64,
    pub label: String,
    pub family: String,
    pub direction: String,
    pub protocol: String,
    pub source_ip: String,
    pub target_port: u16,
    pub enabled: bool,
    pub last_packets: u64,
    pub last_bytes: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub current_bps: u64,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedLimitRule {
    pub id: i64,
    pub interface_name: String,
    pub protocol: String,
    pub port: u16,
    pub rate_value: u64,
    pub rate_unit: String,
    pub enabled: bool,
    pub applied: bool,
    pub last_status: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnLimitPolicy {
    pub id: i64,
    pub enabled: bool,
    pub target_port: u16,
    pub limit_per_ip: u32,
    pub last_status: String,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardRule {
    pub id: i64,
    pub label: String,
    pub protocol: String,
    pub family: String,
    pub interface_name: String,
    pub source_ip: String,
    pub listen_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub enabled: bool,
    pub last_status: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceIpRule {
    pub id: i64,
    pub label: String,
    #[serde(default = "crate::network_rules::default_source_ip_mode")]
    pub mode: String,
    pub family: String,
    pub protocol: String,
    pub match_port: u16,
    pub interface_name: String,
    pub destination_ip: String,
    pub source_ip: String,
    pub translate_ip: String,
    pub enabled: bool,
    pub last_status: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeReportRecord {
    pub id: i64,
    pub created_at_unix: u64,
    pub status: String,
    pub payload_json: String,
    pub response_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSocketRecord {
    pub proto: String,
    pub state: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub process: String,
    pub pid: String,
    pub service_unit: String,
    pub can_start: bool,
    pub can_stop: bool,
    pub can_restart: bool,
    pub is_protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIpInventoryEntry {
    pub interface: String,
    pub address: String,
    pub family: String,
    pub is_public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupTarget {
    pub id: i64,
    pub label: String,
    pub protocol: String,
    pub endpoint: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub remote_path: String,
    pub s3_bucket: String,
    pub s3_region: String,
    pub s3_endpoint: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub enabled: bool,
    pub last_status: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupJob {
    pub id: i64,
    pub label: String,
    pub source_paths: Vec<String>,
    pub include_hidden: bool,
    pub compression_format: String,
    pub schedule_kind: String,
    pub schedule_value: u32,
    pub retention_count: u32,
    pub enabled: bool,
    pub last_status: String,
    pub last_run_at_unix: u64,
    pub next_run_at_unix: u64,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupJobTargetLink {
    pub id: i64,
    pub job_id: i64,
    pub target_id: i64,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecord {
    pub id: i64,
    pub job_id: i64,
    pub target_id: i64,
    pub archive_name: String,
    pub archive_size_bytes: u64,
    pub status: String,
    pub remote_locator: String,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBrowserEntry {
    pub path: String,
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminDashboardData {
    pub settings: AppSettings,
    pub admin_username: String,
    pub current_release_version: String,
    pub latest_release_version: String,
    pub checks: Vec<MonitorCheckRow>,
    pub monitor_folders: Vec<MonitorFolder>,
    pub latest_results: Vec<CheckResult>,
    pub latest_summary: SnapshotSummary,
    pub latest_system: Option<SystemSample>,
    pub public_payload: PublicStatusPayload,
    pub traffic_watchers: Vec<TrafficWatcher>,
    pub speed_limits: Vec<SpeedLimitRule>,
    pub tcp_conn_limit: TcpConnLimitPolicy,
    pub backup_targets: Vec<BackupTarget>,
    pub backup_jobs: Vec<BackupJob>,
    pub backup_job_links: Vec<BackupJobTargetLink>,
    pub backup_records: Vec<BackupRecord>,
    pub source_ip_rules: Vec<SourceIpRule>,
    pub port_forward_rules: Vec<PortForwardRule>,
    pub recent_reports: Vec<FreeReportRecord>,
    pub socket_inventory: Vec<AppSocketRecord>,
    pub host_ip_inventory: Vec<HostIpInventoryEntry>,
    pub server_health: Option<ServerHealthReport>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerHealthProbe {
    pub code: String,
    pub label: String,
    pub country_code: String,
    pub ip: String,
    pub success: bool,
    pub avg_rtt_ms: Option<f64>,
    pub packet_loss_percent: Option<f64>,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerHealthReport {
    pub hostname: String,
    pub distro: String,
    pub kernel: String,
    pub cpu_model: String,
    pub cpu_count: u32,
    pub total_ram_bytes: u64,
    pub total_disk_bytes: u64,
    pub package_manager: String,
    pub updates_summary: String,
    pub updates_pending: u32,
    pub sample: Option<SystemSample>,
    pub accessible_regions: Vec<ServerHealthProbe>,
    pub blocked_regions: Vec<ServerHealthProbe>,
    pub generated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminMonitorHistoryPoint {
    pub observed_at_unix: u64,
    pub status: CheckStatus,
    pub latency_ms: Option<u64>,
    pub duration_ms: u64,
    pub message: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminMonitorAnalyticsSummary {
    pub total_points: usize,
    pub up_points: usize,
    pub degraded_points: usize,
    pub down_points: usize,
    pub availability_percent: f64,
    pub avg_latency_ms: Option<f64>,
    pub max_latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminMonitorAnalyticsPayload {
    pub check_id: String,
    pub label: String,
    pub kind: String,
    pub from_unix: u64,
    pub to_unix: u64,
    pub points: Vec<AdminMonitorHistoryPoint>,
    pub summary: AdminMonitorAnalyticsSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTunnelPingSummary {
    pub avg_latency_ms: Option<f64>,
    pub min_latency_ms: Option<f64>,
    pub max_latency_ms: Option<f64>,
    pub packet_loss_percent: Option<f64>,
    pub sample_count: u32,
    pub raw_output: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTunnelIperfSummary {
    pub mbps: Option<f64>,
    pub bytes: Option<u64>,
    pub retransmits: Option<u64>,
    pub seconds: Option<f64>,
    pub raw_output: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTunnelDiagnosticsPayload {
    pub check_id: String,
    pub label: String,
    pub interface: Option<String>,
    pub inner_probe: Option<String>,
    pub bind_ip: Option<String>,
    pub iperf_port: u16,
    pub ping: AdminTunnelPingSummary,
    pub upload: AdminTunnelIperfSummary,
    pub download: AdminTunnelIperfSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTunnelPingProgress {
    pub phase: String,
    pub avg_latency_ms: Option<f64>,
    pub min_latency_ms: Option<f64>,
    pub max_latency_ms: Option<f64>,
    pub packet_loss_percent: Option<f64>,
    pub sample_count: u32,
    pub completed_samples: u32,
    pub raw_output: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTunnelIperfProgress {
    pub phase: String,
    pub current_mbps: Option<f64>,
    pub avg_mbps: Option<f64>,
    pub peak_mbps: Option<f64>,
    pub bytes: Option<u64>,
    pub retransmits: Option<u64>,
    pub completed_seconds: u64,
    pub total_seconds: u64,
    pub raw_output: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTunnelDiagnosticsLivePayload {
    pub job_id: String,
    pub check_id: String,
    pub label: String,
    pub interface: Option<String>,
    pub inner_probe: Option<String>,
    pub bind_ip: Option<String>,
    pub iperf_port: u16,
    pub status: String,
    pub elapsed_seconds: u64,
    pub total_seconds: u64,
    pub started_at_unix: u64,
    pub finished_at_unix: Option<u64>,
    pub ping: AdminTunnelPingProgress,
    pub upload: AdminTunnelIperfProgress,
    pub download: AdminTunnelIperfProgress,
}

impl Default for TcpConnLimitPolicy {
    fn default() -> Self {
        Self {
            id: 1,
            enabled: false,
            target_port: 443,
            limit_per_ip: 150,
            last_status: "not_applied".to_string(),
            updated_at_unix: 0,
        }
    }
}

pub fn summarize_results(
    observed_at_unix: u64,
    results: &[CheckResult],
) -> SnapshotSummary {
    let mut up_checks = 0;
    let mut degraded_checks = 0;
    let mut down_checks = 0;

    for result in results {
        match result.status {
            CheckStatus::Up => up_checks += 1,
            CheckStatus::Degraded => degraded_checks += 1,
            CheckStatus::Down => down_checks += 1,
        }
    }

    SnapshotSummary {
        observed_at_unix,
        total_checks: results.len(),
        up_checks,
        degraded_checks,
        down_checks,
    }
}

pub fn build_public_views(
    rows: &[MonitorCheckRow],
    results: &[CheckResult],
) -> Vec<PublicCheckView> {
    let result_map: BTreeMap<_, _> = results
        .iter()
        .map(|result| (result.id.as_str(), result))
        .collect();

    rows
        .iter()
        .filter(|row| row.public_visible)
        .filter_map(|row| {
            result_map.get(row.check_id.as_str()).map(|result| PublicCheckView {
                id: result.id.clone(),
                label: row.label.clone(),
                kind: canonical_kind_name(&result.kind).to_string(),
                status: result.status,
                message: public_check_message(result.status).to_string(),
                latency_ms: result.latency_ms,
                endpoint: result.endpoint.as_deref().and_then(public_check_endpoint),
                observed_at_unix: result.observed_at_unix,
                group_name: row.display_group.clone(),
                group_logo_url: row.group_logo_url.clone(),
                group_logo_shape: row.group_logo_shape.clone(),
                history: Vec::new(),
                is_pending: false,
            })
        })
        .collect()
}

fn canonical_kind_name(kind: &str) -> &str {
    if kind.eq_ignore_ascii_case("v2ray_simulation") {
        "v2ray"
    } else {
        kind
    }
}

/// Public status uses a stable, simple description. Raw command errors and
/// authenticated URLs remain available only in the administrator's diagnostics.
pub fn public_check_message(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Up => "Service is responding normally.",
        CheckStatus::Degraded => "Service has reduced availability or performance.",
        CheckStatus::Down => "Service is unavailable.",
    }
}

fn public_check_endpoint(endpoint: &str) -> Option<String> {
    let clean = endpoint.split(['?', '#']).next().unwrap_or("").trim();
    let (scheme, authority) = clean.split_once("://").unwrap_or(("", clean));
    let host = authority.split('/').next().unwrap_or("").rsplit('@').next().unwrap_or("");
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || ".:-_[]".contains(c)) {
        return None;
    }
    if scheme.is_empty() {
        Some(host.to_string())
    } else if matches!(scheme, "http" | "https" | "tcp" | "udp" | "ssh" | "ftp" | "sftp") {
        Some(format!("{scheme}://{host}"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{overall_status_from_counts, AppSettings, SnapshotSummary};

    #[test]
    fn public_endpoints_strip_authentication_tokens_and_paths() {
        assert_eq!(super::public_check_endpoint("https://user:secret@example.com:443/private/token?api_key=secret#private"), Some("https://example.com:443".into()));
        assert_eq!(super::public_check_endpoint("[2001:db8::1]:443"), Some("[2001:db8::1]:443".into()));
        assert_eq!(super::public_check_endpoint("ip link tunnel key secret"), None);
        assert_eq!(super::public_check_endpoint("javascript:secret token"), None);
    }

    #[test]
    fn public_views_never_serialize_monitor_credentials_or_raw_diagnostics() {
        let row = super::MonitorCheckRow {
            db_id: 1,
            check_id: "private-tunnel".into(),
            label: "Public tunnel".into(),
            kind: "tunnel".into(),
            enabled: true,
            public_visible: true,
            display_group: String::new(),
            group_logo_url: String::new(),
            group_logo_shape: "rounded".into(),
            check_json: r#"{"tunnel_key":"config-secret","ssh_password":"ssh-secret","speedtest_token":"test-secret"}"#.into(),
            created_at_unix: 1,
            updated_at_unix: 1,
        };
        let result = crate::types::CheckResult {
            id: row.check_id.clone(),
            kind: "tunnel".into(),
            status: crate::types::CheckStatus::Down,
            message: "failed command with raw-secret".into(),
            observed_at_unix: 2,
            duration_ms: 5,
            latency_ms: None,
            ip_version: None,
            endpoint: Some("https://user:endpoint-secret@example.com/path?token=query-secret".into()),
            details: std::collections::BTreeMap::from([
                ("tunnel_key".into(), serde_json::json!("detail-secret")),
                ("ssh_private_key".into(), serde_json::json!("key-secret")),
            ]),
        };
        let views = super::build_public_views(&[row], &[result]);
        assert_eq!(views[0].status, crate::types::CheckStatus::Down);
        assert_eq!(views[0].endpoint.as_deref(), Some("https://example.com"));
        let json = serde_json::to_string(&views).unwrap();
        assert!(!json.contains("secret"));
        assert!(!json.contains("check_json"));
        assert!(!json.contains("details"));
    }

    #[test]
    fn settings_accept_legacy_licenses_without_preserving_credentials() {
        let mut legacy = serde_json::to_value(AppSettings::default()).unwrap();
        legacy["public_title"] = serde_json::json!("Existing status page");
        legacy["plan_mode"] = serde_json::json!("free");
        legacy["license_key"] = serde_json::json!("old-device-key");
        legacy["license_sealed_secret"] = serde_json::json!("old-secret");
        let settings: AppSettings = serde_json::from_value(legacy).unwrap();
        assert_eq!(settings.public_title, "Existing status page");
        let migrated = serde_json::to_value(settings).unwrap();
        assert!(migrated.get("plan_mode").is_none());
        assert!(migrated.get("license_key").is_none());
        assert!(migrated.get("license_sealed_secret").is_none());
    }

    #[test]
    fn historical_summaries_keep_counts_and_drop_the_old_plan() {
        let legacy = serde_json::json!({
            "observed_at_unix": 123,
            "total_checks": 8,
            "up_checks": 6,
            "degraded_checks": 1,
            "down_checks": 1,
            "mode": "premium"
        });
        let summary: SnapshotSummary = serde_json::from_value(legacy).unwrap();
        assert_eq!(summary.total_checks, 8);
        assert_eq!(summary.up_checks, 6);
        assert!(serde_json::to_value(summary).unwrap().get("mode").is_none());
    }

    #[test]
    fn overall_status_stays_degraded_for_minor_partial_failures() {
        assert_eq!(overall_status_from_counts(50, 49, 0, 1), "degraded");
        assert_eq!(overall_status_from_counts(28, 27, 0, 1), "degraded");
    }

    #[test]
    fn overall_status_turns_down_for_major_outages() {
        assert_eq!(overall_status_from_counts(10, 0, 0, 10), "down");
        assert_eq!(overall_status_from_counts(10, 4, 0, 6), "down");
    }

    #[test]
    fn overall_status_is_up_only_when_nothing_is_failing() {
        assert_eq!(overall_status_from_counts(0, 0, 0, 0), "up");
        assert_eq!(overall_status_from_counts(10, 10, 0, 0), "up");
        assert_eq!(overall_status_from_counts(10, 0, 10, 0), "degraded");
    }
}
