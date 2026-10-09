use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Up,
    Down,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub kind: String,
    pub status: CheckStatus,
    pub message: String,
    pub observed_at_unix: u64,
    pub duration_ms: u64,
    pub latency_ms: Option<u64>,
    pub ip_version: Option<String>,
    pub endpoint: Option<String>,
    pub details: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSnapshot {
    pub agent_id: String,
    pub hostname: String,
    pub generated_at_unix: u64,
    pub results: Vec<CheckResult>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    #[serde(default)]
    pub tunnel_counters: BTreeMap<String, TunnelCounterState>,
    #[serde(default)]
    pub failure_counters: BTreeMap<String, FailureCounterState>,
    #[serde(default)]
    pub last_check_run_unix: BTreeMap<String, u64>,
    #[serde(default)]
    pub last_results: BTreeMap<String, CheckResult>,
    #[serde(default)]
    pub telegram_update_offset: i64,
    #[serde(default)]
    pub radar_last_poll_unix: u64,
    #[serde(default)]
    pub radar_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelCounterState {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub observed_at_unix: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FailureCounterState {
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub notified: bool,
    #[serde(default)]
    pub last_status: Option<CheckStatus>,
    #[serde(default)]
    pub last_observed_at_unix: u64,
}
