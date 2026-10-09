use crate::app_types::{
    AdminUser, AppSettings, BackupJob, BackupJobTargetLink, BackupRecord, BackupTarget,
    FreeReportRecord, HistoryPoint, MonitorCheckRow, MonitorFolder, PortForwardRule,
    SourceIpRule, SpeedLimitRule, StoredSnapshot, SystemSample, TcpConnLimitPolicy, TrafficWatcher,
    UiLanguage,
};
use crate::types::CheckResult;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_STORED_SNAPSHOTS: u64 = 100_000;
const SQLITE_BUSY_TIMEOUT_MS: &str = "15000";

pub struct Database {
    path: PathBuf,
}

impl Database {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn init(&self) -> Result<(), String> {
        // WAL lets dashboard reads continue while the monitor cycle writes.
        self.exec("PRAGMA journal_mode=WAL;")?;
        let schema = r#"
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    kind TEXT NOT NULL,
    plan_required TEXT NOT NULL DEFAULT 'unrestricted',
    enabled INTEGER NOT NULL,
    public_visible INTEGER NOT NULL,
    display_group TEXT NOT NULL DEFAULT '',
    group_logo_url TEXT NOT NULL DEFAULT '',
    group_logo_shape TEXT NOT NULL DEFAULT 'rounded',
    check_json TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS monitor_folders (
    name TEXT PRIMARY KEY,
    logo_url TEXT NOT NULL DEFAULT '',
    logo_shape TEXT NOT NULL DEFAULT 'rounded',
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at_unix INTEGER NOT NULL,
    plan_mode TEXT NOT NULL DEFAULT 'unrestricted',
    overall_status TEXT NOT NULL,
    system_json TEXT NOT NULL,
    results_json TEXT NOT NULL,
    summary_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at_unix INTEGER NOT NULL,
    cpu_percent REAL NOT NULL,
    ram_percent REAL NOT NULL,
    swap_percent REAL NOT NULL,
    disk_percent REAL NOT NULL,
    rx_bps INTEGER NOT NULL,
    tx_bps INTEGER NOT NULL,
    load1 REAL NOT NULL,
    load5 REAL NOT NULL,
    load15 REAL NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_snapshots_created_at
    ON snapshots(created_at_unix, id);
CREATE INDEX IF NOT EXISTS idx_system_samples_observed_at
    ON system_samples(observed_at_unix, id);

CREATE TABLE IF NOT EXISTS free_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at_unix INTEGER NOT NULL,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    response_text TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_watchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    family TEXT NOT NULL,
    direction TEXT NOT NULL,
    protocol TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    enabled INTEGER NOT NULL,
    last_packets INTEGER NOT NULL,
    last_bytes INTEGER NOT NULL,
    total_packets INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    current_bps INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS speed_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    rate_value INTEGER NOT NULL,
    rate_unit TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    applied INTEGER NOT NULL,
    last_status TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tcp_conn_limit (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL,
    target_port INTEGER NOT NULL DEFAULT 443,
    limit_per_ip INTEGER NOT NULL,
    last_status TEXT NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS port_forward_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    family TEXT NOT NULL,
    protocol TEXT NOT NULL,
    interface_name TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    listen_port INTEGER NOT NULL,
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    enabled INTEGER NOT NULL,
    last_status TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS source_ip_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'paired',
    family TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'all',
    match_port INTEGER NOT NULL DEFAULT 0,
    interface_name TEXT NOT NULL DEFAULT '',
    destination_ip TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    translate_ip TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL,
    last_status TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    protocol TEXT NOT NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    username TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL DEFAULT '',
    remote_path TEXT NOT NULL DEFAULT '',
    s3_bucket TEXT NOT NULL DEFAULT '',
    s3_region TEXT NOT NULL DEFAULT '',
    s3_endpoint TEXT NOT NULL DEFAULT '',
    s3_access_key TEXT NOT NULL DEFAULT '',
    s3_secret_key TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_status TEXT NOT NULL DEFAULT 'pending',
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    source_paths_json TEXT NOT NULL,
    include_hidden INTEGER NOT NULL DEFAULT 0,
    compression_format TEXT NOT NULL DEFAULT 'tar.gz',
    schedule_kind TEXT NOT NULL DEFAULT 'daily',
    schedule_value INTEGER NOT NULL DEFAULT 1,
    retention_count INTEGER NOT NULL DEFAULT 8,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_status TEXT NOT NULL DEFAULT 'pending',
    last_run_at_unix INTEGER NOT NULL DEFAULT 0,
    next_run_at_unix INTEGER NOT NULL DEFAULT 0,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_job_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    archive_name TEXT NOT NULL,
    archive_size_bytes INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    remote_locator TEXT NOT NULL DEFAULT '',
    created_at_unix INTEGER NOT NULL
);
"#;

        self.exec(schema)?;
        // Keep the old NOT NULL plan columns as inert compatibility fields so
        // existing databases retain their check IDs, history, and foreign links.
        // Application settings no longer persist or read license credentials.
        self.exec("DELETE FROM settings WHERE key = 'plan_mode' OR substr(key, 1, 8) = 'license_';")?;
        self.ensure_column_exists(
            "tcp_conn_limit",
            "target_port",
            "INTEGER NOT NULL DEFAULT 443",
        )?;
        self.ensure_column_exists(
            "checks",
            "display_group",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column_exists(
            "checks",
            "group_logo_url",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column_exists(
            "checks",
            "group_logo_shape",
            "TEXT NOT NULL DEFAULT 'rounded'",
        )?;
        self.ensure_column_exists(
            "port_forward_rules",
            "interface_name",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column_exists(
            "port_forward_rules",
            "source_ip",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column_exists(
            "source_ip_rules",
            "protocol",
            "TEXT NOT NULL DEFAULT 'all'",
        )?;
        self.ensure_column_exists("source_ip_rules", "mode", "TEXT NOT NULL DEFAULT 'paired'")?;
        self.ensure_column_exists(
            "source_ip_rules",
            "match_port",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        self.ensure_column_exists(
            "source_ip_rules",
            "interface_name",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column_exists(
            "source_ip_rules",
            "translate_ip",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column_exists(
            "backup_targets",
            "endpoint",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column_exists(
            "backup_jobs",
            "next_run_at_unix",
            "INTEGER NOT NULL DEFAULT 0",
        )?;

        self.exec(
            "INSERT OR IGNORE INTO tcp_conn_limit (id, enabled, target_port, limit_per_ip, last_status, updated_at_unix)
             VALUES (1, 0, 443, 150, 'not_applied', 0);",
        )?;

        Ok(())
    }

    pub fn count_rows(&self, table: &str) -> Result<u64, String> {
        let sql = format!("SELECT COUNT(*) AS count FROM {table};");
        let rows = self.query_json(&sql)?;
        let count = rows
            .first()
            .and_then(|row| row.get("count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        Ok(count)
    }

    pub fn load_settings(&self) -> Result<AppSettings, String> {
        let rows = self.query_json("SELECT key, value FROM settings;")?;
        let mut settings = AppSettings::default();
        for row in rows {
            let key = row.get("key").and_then(Value::as_str).unwrap_or("");
            let value = row.get("value").and_then(Value::as_str).unwrap_or("");
            match key {
                "app_name" => settings.app_name = value.to_string(),
                "bind_addr" => settings.bind_addr = value.to_string(),
                "agent_id" => settings.agent_id = value.to_string(),
                "interval_secs" => settings.interval_secs = value.parse::<u64>().unwrap_or(60),
                "default_language" => settings.default_language = UiLanguage::from_str(value),
                "public_title" => settings.public_title = value.to_string(),
                "public_subtitle" => settings.public_subtitle = value.to_string(),
                "public_share_enabled" => settings.public_share_enabled = parse_bool(value),
                "public_history_points" => {
                    settings.public_history_points = value.parse::<usize>().unwrap_or(48)
                }
                "primary_color" => settings.primary_color = value.to_string(),
                "secondary_color" => settings.secondary_color = value.to_string(),
                "background_color" => settings.background_color = value.to_string(),
                "dark_mode_default" => settings.dark_mode_default = parse_bool(value),
                "logo_url" => settings.logo_url = value.to_string(),
                "favicon_url" => settings.favicon_url = value.to_string(),
                "contact_email" => settings.contact_email = value.to_string(),
                "contact_telegram" => settings.contact_telegram = value.to_string(),
                "contact_phone" => settings.contact_phone = value.to_string(),
                "telegram_bot_token" => settings.telegram_bot_token = value.to_string(),
                "telegram_admin_chat_id" => settings.telegram_admin_chat_id = value.to_string(),
                "telegram_failure_threshold" => {
                    settings.telegram_failure_threshold = value.parse::<u32>().unwrap_or(3).max(1)
                }
                "telegram_socks5_host" => settings.telegram_socks5_host = value.to_string(),
                "telegram_socks5_port" => {
                    settings.telegram_socks5_port = value.parse::<u16>().unwrap_or(1080)
                }
                "telegram_socks5_username" => settings.telegram_socks5_username = value.to_string(),
                "telegram_socks5_password" => settings.telegram_socks5_password = value.to_string(),
                "public_base_url" => settings.public_base_url = value.to_string(),
                "admin_base_url" => settings.admin_base_url = value.to_string(),
                "ssl_mode" => settings.ssl_mode = value.to_string(),
                "ssl_cert_path" => settings.ssl_cert_path = value.to_string(),
                "ssl_key_path" => settings.ssl_key_path = value.to_string(),
                "reverse_proxy_server_name" => settings.reverse_proxy_server_name = value.to_string(),
                "reverse_proxy_enabled" => settings.reverse_proxy_enabled = parse_bool(value),
                "free_report_enabled" => settings.free_report_enabled = parse_bool(value),
                "free_report_endpoint" => settings.free_report_endpoint = value.to_string(),
                "free_report_token" => settings.free_report_token = value.to_string(),
                "free_report_websites" => settings.free_report_websites = value.to_string(),
                "notes" => settings.notes = value.to_string(),
                _ => {}
            }
        }
        Ok(settings)
    }

    pub fn save_settings(&self, settings: &AppSettings) -> Result<(), String> {
        self.exec("DELETE FROM settings WHERE key = 'plan_mode' OR substr(key, 1, 8) = 'license_';")?;
        let entries = vec![
            ("app_name", settings.app_name.clone()),
            ("bind_addr", settings.bind_addr.clone()),
            ("agent_id", settings.agent_id.clone()),
            ("interval_secs", settings.interval_secs.to_string()),
            ("default_language", settings.default_language.as_str().to_string()),
            ("public_title", settings.public_title.clone()),
            ("public_subtitle", settings.public_subtitle.clone()),
            (
                "public_share_enabled",
                bool_to_sql_string(settings.public_share_enabled),
            ),
            (
                "public_history_points",
                settings.public_history_points.to_string(),
            ),
            ("primary_color", settings.primary_color.clone()),
            ("secondary_color", settings.secondary_color.clone()),
            ("background_color", settings.background_color.clone()),
            (
                "dark_mode_default",
                bool_to_sql_string(settings.dark_mode_default),
            ),
            ("logo_url", settings.logo_url.clone()),
            ("favicon_url", settings.favicon_url.clone()),
            ("contact_email", settings.contact_email.clone()),
            ("contact_telegram", settings.contact_telegram.clone()),
            ("contact_phone", settings.contact_phone.clone()),
            ("telegram_bot_token", settings.telegram_bot_token.clone()),
            (
                "telegram_admin_chat_id",
                settings.telegram_admin_chat_id.clone(),
            ),
            (
                "telegram_failure_threshold",
                settings.telegram_failure_threshold.to_string(),
            ),
            ("telegram_socks5_host", settings.telegram_socks5_host.clone()),
            (
                "telegram_socks5_port",
                settings.telegram_socks5_port.to_string(),
            ),
            (
                "telegram_socks5_username",
                settings.telegram_socks5_username.clone(),
            ),
            (
                "telegram_socks5_password",
                settings.telegram_socks5_password.clone(),
            ),
            ("public_base_url", settings.public_base_url.clone()),
            ("admin_base_url", settings.admin_base_url.clone()),
            ("ssl_mode", settings.ssl_mode.clone()),
            ("ssl_cert_path", settings.ssl_cert_path.clone()),
            ("ssl_key_path", settings.ssl_key_path.clone()),
            (
                "reverse_proxy_server_name",
                settings.reverse_proxy_server_name.clone(),
            ),
            (
                "reverse_proxy_enabled",
                bool_to_sql_string(settings.reverse_proxy_enabled),
            ),
            (
                "free_report_enabled",
                bool_to_sql_string(settings.free_report_enabled),
            ),
            ("free_report_endpoint", settings.free_report_endpoint.clone()),
            ("free_report_token", settings.free_report_token.clone()),
            ("free_report_websites", settings.free_report_websites.clone()),
            ("notes", settings.notes.clone()),
        ];

        for (key, value) in entries {
            let sql = format!(
                "INSERT INTO settings (key, value) VALUES ({}, {})
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                sql_quote(key),
                sql_quote(&value)
            );
            self.exec(&sql)?;
        }

        Ok(())
    }

    pub fn ensure_admin_user(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<bool, String> {
        let sql = format!(
            "INSERT OR IGNORE INTO admin_users (username, password_hash, created_at_unix)
             VALUES ({}, {}, {});",
            sql_quote(username),
            sql_quote(password_hash),
            unix_now()
        );
        let before = self.count_rows("admin_users")?;
        self.exec(&sql)?;
        let after = self.count_rows("admin_users")?;
        Ok(after > before)
    }

    pub fn get_admin_user_hash(&self, username: &str) -> Result<Option<(i64, String)>, String> {
        let sql = format!(
            "SELECT id, password_hash FROM admin_users WHERE username = {} LIMIT 1;",
            sql_quote(username)
        );
        let rows = self.query_json(&sql)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let user_id = row.get("id").and_then(Value::as_i64).unwrap_or(0);
        let password_hash = row
            .get("password_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok(Some((user_id, password_hash)))
    }

    pub fn first_admin_user(&self) -> Result<Option<AdminUser>, String> {
        let sql = "SELECT id, username, password_hash, created_at_unix
                   FROM admin_users
                   ORDER BY id ASC
                   LIMIT 1;";
        let rows = self.query_json(sql)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        Ok(Some(AdminUser {
            id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
            username: row
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            password_hash: row
                .get("password_hash")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            created_at_unix: row
                .get("created_at_unix")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        }))
    }

    pub fn update_admin_user(
        &self,
        user_id: i64,
        username: &str,
        password_hash: &str,
    ) -> Result<(), String> {
        let sql = format!(
            "UPDATE admin_users
             SET username = {username},
                 password_hash = {password_hash}
             WHERE id = {user_id};",
            username = sql_quote(username),
            password_hash = sql_quote(password_hash),
            user_id = user_id,
        );
        self.exec(&sql)
    }

    pub fn create_session(&self, user_id: i64, token: &str, expires_at_unix: u64) -> Result<(), String> {
        let sql = format!(
            "INSERT INTO admin_sessions (token, user_id, expires_at_unix, created_at_unix)
             VALUES ({}, {}, {}, {});",
            sql_quote(token),
            user_id,
            expires_at_unix,
            unix_now()
        );
        self.exec(&sql)
    }

    pub fn session_user_id(&self, token: &str) -> Result<Option<i64>, String> {
        let sql = format!(
            "SELECT user_id FROM admin_sessions
             WHERE token = {} AND expires_at_unix >= {}
             LIMIT 1;",
            sql_quote(token),
            unix_now()
        );
        let rows = self.query_json(&sql)?;
        Ok(rows
            .first()
            .and_then(|row| row.get("user_id"))
            .and_then(Value::as_i64))
    }

    pub fn delete_session(&self, token: &str) -> Result<(), String> {
        let sql = format!("DELETE FROM admin_sessions WHERE token = {};", sql_quote(token));
        self.exec(&sql)
    }

    pub fn clear_all_sessions(&self) -> Result<(), String> {
        self.exec("DELETE FROM admin_sessions;")
    }

    pub fn upsert_check(&self, row: &MonitorCheckRow) -> Result<(), String> {
        let sql = format!(
            "INSERT INTO checks
                (check_id, label, kind, plan_required, enabled, public_visible, display_group, group_logo_url, group_logo_shape, check_json, created_at_unix, updated_at_unix)
             VALUES
                ({check_id}, {label}, {kind}, 'unrestricted', {enabled}, {public_visible}, {display_group}, {group_logo_url}, {group_logo_shape}, {check_json}, {created_at}, {updated_at})
             ON CONFLICT(check_id) DO UPDATE SET
                label = excluded.label,
                kind = excluded.kind,
                enabled = excluded.enabled,
                public_visible = excluded.public_visible,
                display_group = excluded.display_group,
                group_logo_url = excluded.group_logo_url,
                group_logo_shape = excluded.group_logo_shape,
                check_json = excluded.check_json,
                updated_at_unix = excluded.updated_at_unix;",
            check_id = sql_quote(&row.check_id),
            label = sql_quote(&row.label),
            kind = sql_quote(&row.kind),
            enabled = bool_to_sql_int(row.enabled),
            public_visible = bool_to_sql_int(row.public_visible),
            display_group = sql_quote(&row.display_group),
            group_logo_url = sql_quote(&row.group_logo_url),
            group_logo_shape = sql_quote(&row.group_logo_shape),
            check_json = sql_quote(&row.check_json),
            created_at = row.created_at_unix,
            updated_at = row.updated_at_unix,
        );
        self.exec(&sql)
    }

    pub fn list_checks(&self) -> Result<Vec<MonitorCheckRow>, String> {
        let sql = "SELECT
                id AS db_id,
                check_id,
                label,
                kind,
                plan_required,
                enabled,
                public_visible,
                display_group,
                group_logo_url,
                group_logo_shape,
                check_json,
                created_at_unix,
                updated_at_unix
            FROM checks
            ORDER BY created_at_unix ASC, id ASC;";
        let rows = self.query_json(sql)?;
        Ok(rows
            .into_iter()
            .map(|row| MonitorCheckRow {
                db_id: row.get("db_id").and_then(Value::as_i64).unwrap_or(0),
                check_id: row
                    .get("check_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                label: row
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                kind: row
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                enabled: row.get("enabled").and_then(Value::as_i64).unwrap_or(0) != 0,
                public_visible: row
                    .get("public_visible")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    != 0,
                display_group: row
                    .get("display_group")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                group_logo_url: row
                    .get("group_logo_url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                group_logo_shape: row
                    .get("group_logo_shape")
                    .and_then(Value::as_str)
                    .unwrap_or("rounded")
                    .to_string(),
                check_json: row
                    .get("check_json")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                created_at_unix: row
                    .get("created_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                updated_at_unix: row
                    .get("updated_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            })
            .collect())
    }

    pub fn delete_check(&self, check_id: &str) -> Result<(), String> {
        let sql = format!("DELETE FROM checks WHERE check_id = {};", sql_quote(check_id));
        self.exec(&sql)
    }

    pub fn get_check(&self, check_id: &str) -> Result<Option<MonitorCheckRow>, String> {
        let sql = format!(
            "SELECT
                id AS db_id,
                check_id,
                label,
                kind,
                plan_required,
                enabled,
                public_visible,
                display_group,
                group_logo_url,
                group_logo_shape,
                check_json,
                created_at_unix,
                updated_at_unix
             FROM checks
             WHERE check_id = {}
             LIMIT 1;",
            sql_quote(check_id)
        );
        let rows = self.query_json(&sql)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        Ok(Some(MonitorCheckRow {
            db_id: row.get("db_id").and_then(Value::as_i64).unwrap_or(0),
            check_id: row
                .get("check_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            label: row
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            kind: row
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            enabled: row.get("enabled").and_then(Value::as_i64).unwrap_or(0) != 0,
            public_visible: row
                .get("public_visible")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                != 0,
            display_group: row
                .get("display_group")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            group_logo_url: row
                .get("group_logo_url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            group_logo_shape: row
                .get("group_logo_shape")
                .and_then(Value::as_str)
                .unwrap_or("rounded")
                .to_string(),
            check_json: row
                .get("check_json")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            created_at_unix: row
                .get("created_at_unix")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            updated_at_unix: row
                .get("updated_at_unix")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        }))
    }

    pub fn list_monitor_folders(&self) -> Result<Vec<MonitorFolder>, String> {
        let sql = "SELECT
                name,
                logo_url,
                logo_shape,
                created_at_unix,
                updated_at_unix
            FROM monitor_folders
            ORDER BY created_at_unix ASC, name ASC;";
        let rows = self.query_json(sql)?;
        Ok(rows
            .into_iter()
            .map(|row| MonitorFolder {
                name: row
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                logo_url: row
                    .get("logo_url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                logo_shape: row
                    .get("logo_shape")
                    .and_then(Value::as_str)
                    .unwrap_or("rounded")
                    .to_string(),
                created_at_unix: row
                    .get("created_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                updated_at_unix: row
                    .get("updated_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            })
            .collect())
    }

    pub fn save_monitor_folder(&self, folder: &MonitorFolder) -> Result<(), String> {
        let sql = format!(
            "INSERT INTO monitor_folders
                (name, logo_url, logo_shape, created_at_unix, updated_at_unix)
             VALUES
                ({name}, {logo_url}, {logo_shape}, {created_at}, {updated_at})
             ON CONFLICT(name) DO UPDATE SET
                logo_url = excluded.logo_url,
                logo_shape = excluded.logo_shape,
                updated_at_unix = excluded.updated_at_unix;",
            name = sql_quote(&folder.name),
            logo_url = sql_quote(&folder.logo_url),
            logo_shape = sql_quote(&folder.logo_shape),
            created_at = folder.created_at_unix,
            updated_at = folder.updated_at_unix,
        );
        self.exec(&sql)
    }

    pub fn delete_monitor_folder(&self, name: &str) -> Result<(), String> {
        let sql = format!(
            "DELETE FROM monitor_folders WHERE name = {};",
            sql_quote(name)
        );
        self.exec(&sql)
    }

    pub fn save_snapshot(
        &self,
        overall_status: &str,
        system_sample: Option<&SystemSample>,
        results: &[CheckResult],
        summary_json: &str,
    ) -> Result<(), String> {
        let created_at_unix = unix_now();
        let system_json = if let Some(sample) = system_sample {
            serde_json::to_string(sample)
                .map_err(|error| format!("failed to serialize system sample: {error}"))?
        } else {
            "{}".to_string()
        };
        let compact_results = results
            .iter()
            .cloned()
            .map(|mut result| {
                // Historical charts only need the summary fields. Runtime-only
                // diagnostic detail made the database grow by gigabytes.
                result.details.clear();
                result
            })
            .collect::<Vec<_>>();
        let results_json = serde_json::to_string(&compact_results)
            .map_err(|error| format!("failed to serialize check results: {error}"))?;
        let mut sql = format!(
            "BEGIN IMMEDIATE;
             INSERT INTO snapshots
                (created_at_unix, plan_mode, overall_status, system_json, results_json, summary_json)
             VALUES
                ({created_at}, 'unrestricted', {overall_status}, {system_json}, {results_json}, {summary_json});",
            created_at = created_at_unix,
            overall_status = sql_quote(overall_status),
            system_json = sql_quote(&system_json),
            results_json = sql_quote(&results_json),
            summary_json = sql_quote(summary_json)
        );
        if let Some(sample) = system_sample {
            let payload_json = serde_json::to_string(sample)
                .map_err(|error| format!("failed to serialize system sample payload: {error}"))?;
            sql.push_str(&format!(
                "INSERT INTO system_samples
                    (observed_at_unix, cpu_percent, ram_percent, swap_percent, disk_percent, rx_bps, tx_bps, load1, load5, load15, payload_json)
                 VALUES
                    ({observed_at}, {cpu}, {ram}, {swap}, {disk}, {rx_bps}, {tx_bps}, {load1}, {load5}, {load15}, {payload});",
                observed_at = sample.observed_at_unix,
                cpu = sample.cpu_percent,
                ram = sample.ram_percent,
                swap = sample.swap_percent,
                disk = sample.disk_percent,
                rx_bps = sample.rx_bps,
                tx_bps = sample.tx_bps,
                load1 = sample.load1,
                load5 = sample.load5,
                load15 = sample.load15,
                payload = sql_quote(&payload_json)
            ));
        }
        sql.push_str(&format!(
            "DELETE FROM snapshots
               WHERE id <= (SELECT COALESCE(MAX(id), 0) - {MAX_STORED_SNAPSHOTS} FROM snapshots);
             DELETE FROM system_samples
               WHERE id <= (SELECT COALESCE(MAX(id), 0) - {MAX_STORED_SNAPSHOTS} FROM system_samples);
             COMMIT;"
        ));
        self.exec(&sql)
    }

    pub fn latest_snapshot(&self) -> Result<Option<StoredSnapshot>, String> {
        let sql = "SELECT id, created_at_unix, plan_mode, overall_status, system_json, results_json, summary_json
            FROM snapshots
            ORDER BY created_at_unix DESC, id DESC
            LIMIT 1;";
        let rows = self.query_json(sql)?;
        Ok(rows.into_iter().next().map(|row| StoredSnapshot {
            id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
            created_at_unix: row
                .get("created_at_unix")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            overall_status: row
                .get("overall_status")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            system_json: row
                .get("system_json")
                .and_then(Value::as_str)
                .unwrap_or("{}")
                .to_string(),
            results_json: row
                .get("results_json")
                .and_then(Value::as_str)
                .unwrap_or("[]")
                .to_string(),
            summary_json: row
                .get("summary_json")
                .and_then(Value::as_str)
                .unwrap_or("{}")
                .to_string(),
        }))
    }

    pub fn recent_snapshots(&self, limit: usize) -> Result<Vec<StoredSnapshot>, String> {
        let sql = format!(
            "SELECT id, created_at_unix, plan_mode, overall_status, system_json, results_json, summary_json
             FROM snapshots
             ORDER BY created_at_unix DESC, id DESC
             LIMIT {};",
            limit.max(1)
        );
        let rows = self.query_json(&sql)?;
        let mut snapshots = rows
            .into_iter()
            .map(|row| StoredSnapshot {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                created_at_unix: row
                    .get("created_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                overall_status: row
                    .get("overall_status")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                system_json: row
                    .get("system_json")
                    .and_then(Value::as_str)
                    .unwrap_or("{}")
                    .to_string(),
                results_json: row
                    .get("results_json")
                    .and_then(Value::as_str)
                    .unwrap_or("[]")
                    .to_string(),
                summary_json: row
                    .get("summary_json")
                    .and_then(Value::as_str)
                    .unwrap_or("{}")
                    .to_string(),
            })
            .collect::<Vec<_>>();
        snapshots.reverse();
        Ok(snapshots)
    }

    pub fn snapshots_between(
        &self,
        from_unix: Option<u64>,
        to_unix: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredSnapshot>, String> {
        let mut conditions = Vec::new();
        if let Some(from_unix) = from_unix {
            conditions.push(format!("created_at_unix >= {from_unix}"));
        }
        if let Some(to_unix) = to_unix {
            conditions.push(format!("created_at_unix <= {to_unix}"));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };

        let sql = format!(
            "SELECT id, created_at_unix, plan_mode, overall_status, system_json, results_json, summary_json
             FROM snapshots
             {where_clause}
             ORDER BY created_at_unix ASC, id ASC
             LIMIT {};",
            limit.max(1)
        );
        let rows = self.query_json(&sql)?;
        Ok(rows
            .into_iter()
            .map(|row| StoredSnapshot {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                created_at_unix: row
                    .get("created_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                overall_status: row
                    .get("overall_status")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                system_json: row
                    .get("system_json")
                    .and_then(Value::as_str)
                    .unwrap_or("{}")
                    .to_string(),
                results_json: row
                    .get("results_json")
                    .and_then(Value::as_str)
                    .unwrap_or("[]")
                    .to_string(),
                summary_json: row
                    .get("summary_json")
                    .and_then(Value::as_str)
                    .unwrap_or("{}")
                    .to_string(),
            })
            .collect())
    }

    pub fn check_snapshots_between(
        &self,
        check_id: &str,
        from_unix: Option<u64>,
        to_unix: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredSnapshot>, String> {
        let mut time_conditions = Vec::new();
        if let Some(from_unix) = from_unix {
            time_conditions.push(format!("created_at_unix >= {from_unix}"));
        }
        if let Some(to_unix) = to_unix {
            time_conditions.push(format!("created_at_unix <= {to_unix}"));
        }
        let where_clause = if time_conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", time_conditions.join(" AND "))
        };
        let row_limit = limit.clamp(1, 2_000);
        let sql = format!(
            "WITH selected AS (
                 SELECT id, created_at_unix, plan_mode, overall_status,
                        system_json, results_json, summary_json
                   FROM snapshots
                   {where_clause}
                  ORDER BY created_at_unix DESC, id DESC
                  LIMIT {row_limit}
             )
             SELECT snapshot.id, snapshot.created_at_unix, snapshot.plan_mode,
                    snapshot.overall_status, snapshot.system_json,
                    json_array(json_object(
                        'id', json_extract(result.value, '$.id'),
                        'kind', json_extract(result.value, '$.kind'),
                        'status', json_extract(result.value, '$.status'),
                        'message', json_extract(result.value, '$.message'),
                        'observed_at_unix', json_extract(result.value, '$.observed_at_unix'),
                        'duration_ms', json_extract(result.value, '$.duration_ms'),
                        'latency_ms', json_extract(result.value, '$.latency_ms'),
                        'ip_version', json_extract(result.value, '$.ip_version'),
                        'endpoint', json_extract(result.value, '$.endpoint'),
                        'details', json('{{}}')
                    )) AS results_json,
                    snapshot.summary_json
               FROM selected AS snapshot
               JOIN json_each(snapshot.results_json) AS result
              WHERE json_extract(result.value, '$.id') = {}
              ORDER BY snapshot.created_at_unix ASC, snapshot.id ASC;",
            sql_quote(check_id),
        );
        let rows = self.query_json(&sql)?;
        Ok(rows
            .into_iter()
            .map(|row| StoredSnapshot {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                created_at_unix: row
                    .get("created_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                overall_status: row
                    .get("overall_status")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                system_json: row
                    .get("system_json")
                    .and_then(Value::as_str)
                    .unwrap_or("{}")
                    .to_string(),
                results_json: row
                    .get("results_json")
                    .and_then(Value::as_str)
                    .unwrap_or("[]")
                    .to_string(),
                summary_json: row
                    .get("summary_json")
                    .and_then(Value::as_str)
                    .unwrap_or("{}")
                    .to_string(),
            })
            .collect())
    }

    pub fn recent_history(&self, limit: usize) -> Result<Vec<HistoryPoint>, String> {
        let sql = format!(
            "SELECT summary_json FROM snapshots
             ORDER BY created_at_unix DESC, id DESC
             LIMIT {};",
            limit.max(1)
        );
        let rows = self.query_json(&sql)?;
        let mut points = Vec::new();
        for row in rows {
            let summary_json = row
                .get("summary_json")
                .and_then(Value::as_str)
                .unwrap_or("{}");
            if let Ok(value) = serde_json::from_str::<Value>(summary_json) {
                points.push(HistoryPoint {
                    observed_at_unix: value
                        .get("observed_at_unix")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    up_checks: value
                        .get("up_checks")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as usize,
                    degraded_checks: value
                        .get("degraded_checks")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as usize,
                    down_checks: value
                        .get("down_checks")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as usize,
                });
            }
        }
        points.reverse();
        Ok(points)
    }

    pub fn recent_system_samples(&self, limit: usize) -> Result<Vec<SystemSample>, String> {
        let sql = format!(
            "SELECT payload_json FROM system_samples
             ORDER BY observed_at_unix DESC, id DESC
             LIMIT {};",
            limit.max(1)
        );
        let rows = self.query_json(&sql)?;
        let mut samples = Vec::new();
        for row in rows {
            let payload_json = row
                .get("payload_json")
                .and_then(Value::as_str)
                .unwrap_or("{}");
            if let Ok(sample) = serde_json::from_str::<SystemSample>(payload_json) {
                samples.push(sample);
            }
        }
        samples.reverse();
        Ok(samples)
    }

    pub fn add_traffic_watcher(
        &self,
        label: &str,
        family: &str,
        direction: &str,
        protocol: &str,
        source_ip: &str,
        target_port: u16,
    ) -> Result<(), String> {
        let now = unix_now();
        let sql = format!(
            "INSERT INTO traffic_watchers
                (label, family, direction, protocol, source_ip, target_port, enabled, last_packets, last_bytes, total_packets, total_bytes, current_bps, created_at_unix, updated_at_unix)
             VALUES
                ({label}, {family}, {direction}, {protocol}, {source_ip}, {target_port}, 1, 0, 0, 0, 0, 0, {now}, {now});",
            label = sql_quote(label),
            family = sql_quote(family),
            direction = sql_quote(direction),
            protocol = sql_quote(protocol),
            source_ip = sql_quote(source_ip),
            target_port = target_port,
            now = now
        );
        self.exec(&sql)
    }

    pub fn list_traffic_watchers(&self) -> Result<Vec<TrafficWatcher>, String> {
        let sql = "SELECT * FROM traffic_watchers ORDER BY created_at_unix DESC, id DESC;";
        let rows = self.query_json(sql)?;
        Ok(rows
            .into_iter()
            .map(|row| TrafficWatcher {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                label: row
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                family: row
                    .get("family")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                direction: row
                    .get("direction")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                protocol: row
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                source_ip: row
                    .get("source_ip")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                target_port: row
                    .get("target_port")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u16,
                enabled: row.get("enabled").and_then(Value::as_i64).unwrap_or(0) != 0,
                last_packets: row
                    .get("last_packets")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                last_bytes: row.get("last_bytes").and_then(Value::as_u64).unwrap_or(0),
                total_packets: row
                    .get("total_packets")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                total_bytes: row
                    .get("total_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                current_bps: row.get("current_bps").and_then(Value::as_u64).unwrap_or(0),
                created_at_unix: row
                    .get("created_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                updated_at_unix: row
                    .get("updated_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            })
            .collect())
    }

    pub fn update_traffic_watcher_stats(
        &self,
        watcher_id: i64,
        packets: u64,
        bytes: u64,
        current_bps: u64,
    ) -> Result<(), String> {
        let now = unix_now();
        let sql = format!(
            "UPDATE traffic_watchers
             SET last_packets = {packets},
                 last_bytes = {bytes},
                 total_packets = {packets},
                 total_bytes = {bytes},
                 current_bps = {current_bps},
                 updated_at_unix = {now}
             WHERE id = {watcher_id};",
            packets = packets,
            bytes = bytes,
            current_bps = current_bps,
            now = now,
            watcher_id = watcher_id
        );
        self.exec(&sql)
    }

    pub fn delete_traffic_watcher(&self, watcher_id: i64) -> Result<(), String> {
        let sql = format!("DELETE FROM traffic_watchers WHERE id = {};", watcher_id);
        self.exec(&sql)
    }

    pub fn add_speed_limit(
        &self,
        interface_name: &str,
        protocol: &str,
        port: u16,
        rate_value: u64,
        rate_unit: &str,
    ) -> Result<(), String> {
        let now = unix_now();
        let sql = format!(
            "INSERT INTO speed_limits
                (interface_name, protocol, port, rate_value, rate_unit, enabled, applied, last_status, created_at_unix, updated_at_unix)
             VALUES
                ({interface_name}, {protocol}, {port}, {rate_value}, {rate_unit}, 1, 0, 'pending', {now}, {now});",
            interface_name = sql_quote(interface_name),
            protocol = sql_quote(protocol),
            port = port,
            rate_value = rate_value,
            rate_unit = sql_quote(rate_unit),
            now = now
        );
        self.exec(&sql)
    }

    pub fn list_speed_limits(&self) -> Result<Vec<SpeedLimitRule>, String> {
        let sql = "SELECT * FROM speed_limits ORDER BY created_at_unix DESC, id DESC;";
        let rows = self.query_json(sql)?;
        Ok(rows
            .into_iter()
            .map(|row| SpeedLimitRule {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                interface_name: row
                    .get("interface_name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                protocol: row
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                port: row.get("port").and_then(Value::as_u64).unwrap_or(0) as u16,
                rate_value: row
                    .get("rate_value")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                rate_unit: row
                    .get("rate_unit")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                enabled: row.get("enabled").and_then(Value::as_i64).unwrap_or(0) != 0,
                applied: row.get("applied").and_then(Value::as_i64).unwrap_or(0) != 0,
                last_status: row
                    .get("last_status")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                created_at_unix: row
                    .get("created_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                updated_at_unix: row
                    .get("updated_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            })
            .collect())
    }

    pub fn update_speed_limit_status(
        &self,
        rule_id: i64,
        applied: bool,
        last_status: &str,
    ) -> Result<(), String> {
        let sql = format!(
            "UPDATE speed_limits
             SET applied = {applied},
                 last_status = {last_status},
                 updated_at_unix = {updated_at}
             WHERE id = {rule_id};",
            applied = bool_to_sql_int(applied),
            last_status = sql_quote(last_status),
            updated_at = unix_now(),
            rule_id = rule_id
        );
        self.exec(&sql)
    }

    pub fn delete_speed_limit(&self, rule_id: i64) -> Result<(), String> {
        let sql = format!("DELETE FROM speed_limits WHERE id = {};", rule_id);
        self.exec(&sql)
    }

    pub fn load_tcp_conn_limit(&self) -> Result<TcpConnLimitPolicy, String> {
        let rows = self.query_json(
            "SELECT id, enabled, target_port, limit_per_ip, last_status, updated_at_unix
             FROM tcp_conn_limit
             WHERE id = 1
             LIMIT 1;",
        )?;
        if let Some(row) = rows.first() {
            Ok(TcpConnLimitPolicy {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(1),
                enabled: row.get("enabled").and_then(Value::as_i64).unwrap_or(0) != 0,
                target_port: row
                    .get("target_port")
                    .and_then(Value::as_u64)
                    .unwrap_or(443) as u16,
                limit_per_ip: row
                    .get("limit_per_ip")
                    .and_then(Value::as_u64)
                    .unwrap_or(150) as u32,
                last_status: row
                    .get("last_status")
                    .and_then(Value::as_str)
                    .unwrap_or("not_applied")
                    .to_string(),
                updated_at_unix: row
                    .get("updated_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            })
        } else {
            Ok(TcpConnLimitPolicy::default())
        }
    }

    pub fn save_tcp_conn_limit(&self, policy: &TcpConnLimitPolicy) -> Result<(), String> {
        let sql = format!(
            "INSERT INTO tcp_conn_limit (id, enabled, target_port, limit_per_ip, last_status, updated_at_unix)
             VALUES (1, {enabled}, {target_port}, {limit_per_ip}, {last_status}, {updated_at})
             ON CONFLICT(id) DO UPDATE SET
                enabled = excluded.enabled,
                target_port = excluded.target_port,
                limit_per_ip = excluded.limit_per_ip,
                last_status = excluded.last_status,
                updated_at_unix = excluded.updated_at_unix;",
            enabled = bool_to_sql_int(policy.enabled),
            target_port = policy.target_port,
            limit_per_ip = policy.limit_per_ip,
            last_status = sql_quote(&policy.last_status),
            updated_at = policy.updated_at_unix
        );
        self.exec(&sql)
    }

    pub fn add_port_forward_rule(
        &self,
        label: &str,
        protocol: &str,
        family: &str,
        interface_name: &str,
        source_ip: &str,
        listen_port: u16,
        target_host: &str,
        target_port: u16,
        enabled: bool,
    ) -> Result<(), String> {
        let now = unix_now();
        let sql = format!(
            "INSERT INTO port_forward_rules
                (label, family, protocol, interface_name, source_ip, listen_port, target_host, target_port, enabled, last_status, created_at_unix, updated_at_unix)
             VALUES
                ({label}, {family}, {protocol}, {interface_name}, {source_ip}, {listen_port}, {target_host}, {target_port}, {enabled}, 'pending', {now}, {now});",
            label = sql_quote(label),
            family = sql_quote(family),
            protocol = sql_quote(protocol),
            interface_name = sql_quote(interface_name),
            source_ip = sql_quote(source_ip),
            listen_port = listen_port,
            target_host = sql_quote(target_host),
            target_port = target_port,
            enabled = bool_to_sql_int(enabled),
            now = now
        );
        self.exec(&sql)
    }

    pub fn list_port_forward_rules(&self) -> Result<Vec<PortForwardRule>, String> {
        let sql = "SELECT * FROM port_forward_rules ORDER BY created_at_unix DESC, id DESC;";
        let rows = self.query_json(sql)?;
        Ok(rows
            .into_iter()
            .map(|row| PortForwardRule {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                label: row
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                protocol: row
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("tcp")
                    .to_string(),
                family: row
                    .get("family")
                    .and_then(Value::as_str)
                    .unwrap_or("ipv4")
                    .to_string(),
                interface_name: row
                    .get("interface_name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                source_ip: row
                    .get("source_ip")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                listen_port: row
                    .get("listen_port")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u16,
                target_host: row
                    .get("target_host")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                target_port: row
                    .get("target_port")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u16,
                enabled: row.get("enabled").and_then(Value::as_i64).unwrap_or(0) != 0,
                last_status: row
                    .get("last_status")
                    .and_then(Value::as_str)
                    .unwrap_or("pending")
                    .to_string(),
                created_at_unix: row
                    .get("created_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                updated_at_unix: row
                    .get("updated_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            })
            .collect())
    }

    pub fn add_source_ip_rule(
        &self,
        label: &str,
        mode: &str,
        family: &str,
        protocol: &str,
        match_port: u16,
        interface_name: &str,
        destination_ip: &str,
        source_ip: &str,
        translate_ip: &str,
        enabled: bool,
    ) -> Result<(), String> {
        let now = unix_now();
        let sql = format!(
            "INSERT INTO source_ip_rules
                (label, mode, family, protocol, match_port, interface_name, destination_ip, source_ip, translate_ip, enabled, last_status, created_at_unix, updated_at_unix)
             VALUES
                ({label}, {mode}, {family}, {protocol}, {match_port}, {interface_name}, {destination_ip}, {source_ip}, {translate_ip}, {enabled}, 'pending', {now}, {now});",
            label = sql_quote(label),
            mode = sql_quote(mode),
            family = sql_quote(family),
            protocol = sql_quote(protocol),
            match_port = match_port,
            interface_name = sql_quote(interface_name),
            destination_ip = sql_quote(destination_ip),
            source_ip = sql_quote(source_ip),
            translate_ip = sql_quote(translate_ip),
            enabled = if enabled { 1 } else { 0 },
            now = now
        );
        self.exec(&sql)
    }

    pub fn list_source_ip_rules(&self) -> Result<Vec<SourceIpRule>, String> {
        let sql = "SELECT * FROM source_ip_rules ORDER BY created_at_unix DESC, id DESC;";
        let rows = self.query_json(sql)?;
        let mut results = Vec::new();
        for row in rows {
            results.push(SourceIpRule {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                mode: row.get("mode").and_then(Value::as_str).unwrap_or("paired").to_string(),
                label: row
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                family: row
                    .get("family")
                    .and_then(Value::as_str)
                    .unwrap_or("ipv4")
                    .to_string(),
                protocol: row
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("all")
                    .to_string(),
                match_port: row
                    .get("match_port")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u16,
                interface_name: row
                    .get("interface_name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                destination_ip: row
                    .get("destination_ip")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                source_ip: row
                    .get("source_ip")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                translate_ip: row
                    .get("translate_ip")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                enabled: row
                    .get("enabled")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    == 1,
                last_status: row
                    .get("last_status")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                created_at_unix: row
                    .get("created_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                updated_at_unix: row
                    .get("updated_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            });
        }
        Ok(results)
    }

    pub fn update_source_ip_rule_status(
        &self,
        rule_id: i64,
        last_status: &str,
    ) -> Result<(), String> {
        let now = unix_now();
        let sql = format!(
            "UPDATE source_ip_rules
             SET last_status = {last_status}, updated_at_unix = {now}
             WHERE id = {rule_id};",
            last_status = sql_quote(last_status),
            now = now,
            rule_id = rule_id
        );
        self.exec(&sql)
    }

    pub fn delete_source_ip_rule(&self, rule_id: i64) -> Result<(), String> {
        let sql = format!("DELETE FROM source_ip_rules WHERE id = {};", rule_id);
        self.exec(&sql)
    }

    pub fn update_port_forward_rule_status(
        &self,
        rule_id: i64,
        enabled: bool,
        last_status: &str,
    ) -> Result<(), String> {
        let sql = format!(
            "UPDATE port_forward_rules
             SET enabled = {enabled},
                 last_status = {last_status},
                 updated_at_unix = {updated_at}
             WHERE id = {rule_id};",
            enabled = bool_to_sql_int(enabled),
            last_status = sql_quote(last_status),
            updated_at = unix_now(),
            rule_id = rule_id
        );
        self.exec(&sql)
    }

    pub fn delete_port_forward_rule(&self, rule_id: i64) -> Result<(), String> {
        let sql = format!("DELETE FROM port_forward_rules WHERE id = {};", rule_id);
        self.exec(&sql)
    }

    pub fn add_backup_target(
        &self,
        label: &str,
        protocol: &str,
        endpoint: &str,
        port: u16,
        username: &str,
        password: &str,
        remote_path: &str,
        s3_bucket: &str,
        s3_region: &str,
        s3_endpoint: &str,
        s3_access_key: &str,
        s3_secret_key: &str,
        enabled: bool,
    ) -> Result<(), String> {
        let now = unix_now();
        let sql = format!(
            "INSERT INTO backup_targets
                (label, protocol, endpoint, port, username, password, remote_path, s3_bucket, s3_region, s3_endpoint, s3_access_key, s3_secret_key, enabled, last_status, created_at_unix, updated_at_unix)
             VALUES
                ({label}, {protocol}, {endpoint}, {port}, {username}, {password}, {remote_path}, {s3_bucket}, {s3_region}, {s3_endpoint}, {s3_access_key}, {s3_secret_key}, {enabled}, 'pending', {now}, {now});",
            label = sql_quote(label),
            protocol = sql_quote(protocol),
            endpoint = sql_quote(endpoint),
            port = port,
            username = sql_quote(username),
            password = sql_quote(password),
            remote_path = sql_quote(remote_path),
            s3_bucket = sql_quote(s3_bucket),
            s3_region = sql_quote(s3_region),
            s3_endpoint = sql_quote(s3_endpoint),
            s3_access_key = sql_quote(s3_access_key),
            s3_secret_key = sql_quote(s3_secret_key),
            enabled = bool_to_sql_int(enabled),
            now = now
        );
        self.exec(&sql)
    }

    pub fn list_backup_targets(&self) -> Result<Vec<BackupTarget>, String> {
        let rows = self.query_json("SELECT * FROM backup_targets ORDER BY created_at_unix DESC, id DESC;")?;
        Ok(rows
            .into_iter()
            .map(|row| BackupTarget {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                label: row.get("label").and_then(Value::as_str).unwrap_or("").to_string(),
                protocol: row.get("protocol").and_then(Value::as_str).unwrap_or("").to_string(),
                endpoint: row.get("endpoint").and_then(Value::as_str).unwrap_or("").to_string(),
                port: row.get("port").and_then(Value::as_u64).unwrap_or(0) as u16,
                username: row.get("username").and_then(Value::as_str).unwrap_or("").to_string(),
                password: row.get("password").and_then(Value::as_str).unwrap_or("").to_string(),
                remote_path: row.get("remote_path").and_then(Value::as_str).unwrap_or("").to_string(),
                s3_bucket: row.get("s3_bucket").and_then(Value::as_str).unwrap_or("").to_string(),
                s3_region: row.get("s3_region").and_then(Value::as_str).unwrap_or("").to_string(),
                s3_endpoint: row.get("s3_endpoint").and_then(Value::as_str).unwrap_or("").to_string(),
                s3_access_key: row.get("s3_access_key").and_then(Value::as_str).unwrap_or("").to_string(),
                s3_secret_key: row.get("s3_secret_key").and_then(Value::as_str).unwrap_or("").to_string(),
                enabled: row.get("enabled").and_then(Value::as_i64).unwrap_or(0) == 1,
                last_status: row.get("last_status").and_then(Value::as_str).unwrap_or("").to_string(),
                created_at_unix: row.get("created_at_unix").and_then(Value::as_u64).unwrap_or(0),
                updated_at_unix: row.get("updated_at_unix").and_then(Value::as_u64).unwrap_or(0),
            })
            .collect())
    }

    pub fn update_backup_target_status(&self, target_id: i64, enabled: bool, last_status: &str) -> Result<(), String> {
        let sql = format!(
            "UPDATE backup_targets SET enabled = {enabled}, last_status = {last_status}, updated_at_unix = {updated_at} WHERE id = {target_id};",
            enabled = bool_to_sql_int(enabled),
            last_status = sql_quote(last_status),
            updated_at = unix_now(),
            target_id = target_id
        );
        self.exec(&sql)
    }

    pub fn delete_backup_target(&self, target_id: i64) -> Result<(), String> {
        self.exec(&format!("DELETE FROM backup_job_targets WHERE target_id = {};", target_id))?;
        self.exec(&format!("DELETE FROM backup_targets WHERE id = {};", target_id))
    }

    pub fn add_backup_job(
        &self,
        label: &str,
        source_paths_json: &str,
        include_hidden: bool,
        compression_format: &str,
        schedule_kind: &str,
        schedule_value: u32,
        retention_count: u32,
        enabled: bool,
        next_run_at_unix: u64,
    ) -> Result<i64, String> {
        let now = unix_now();
        let sql = format!(
            "INSERT INTO backup_jobs
                (label, source_paths_json, include_hidden, compression_format, schedule_kind, schedule_value, retention_count, enabled, last_status, last_run_at_unix, next_run_at_unix, created_at_unix, updated_at_unix)
             VALUES
                ({label}, {source_paths_json}, {include_hidden}, {compression_format}, {schedule_kind}, {schedule_value}, {retention_count}, {enabled}, 'pending', 0, {next_run_at_unix}, {now}, {now});",
            label = sql_quote(label),
            source_paths_json = sql_quote(source_paths_json),
            include_hidden = bool_to_sql_int(include_hidden),
            compression_format = sql_quote(compression_format),
            schedule_kind = sql_quote(schedule_kind),
            schedule_value = schedule_value.max(1),
            retention_count = retention_count.max(1),
            enabled = bool_to_sql_int(enabled),
            next_run_at_unix = next_run_at_unix,
            now = now
        );
        self.exec(&sql)?;
        let rows = self.query_json("SELECT last_insert_rowid() AS id;")?;
        Ok(rows
            .first()
            .and_then(|row| row.get("id"))
            .and_then(Value::as_i64)
            .unwrap_or(0))
    }

    pub fn list_backup_jobs(&self) -> Result<Vec<BackupJob>, String> {
        let rows = self.query_json("SELECT * FROM backup_jobs ORDER BY created_at_unix DESC, id DESC;")?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let source_paths = row
                    .get("source_paths_json")
                    .and_then(Value::as_str)
                    .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
                    .unwrap_or_default();
                BackupJob {
                    id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                    label: row.get("label").and_then(Value::as_str).unwrap_or("").to_string(),
                    source_paths,
                    include_hidden: row.get("include_hidden").and_then(Value::as_i64).unwrap_or(0) == 1,
                    compression_format: row.get("compression_format").and_then(Value::as_str).unwrap_or("tar.gz").to_string(),
                    schedule_kind: row.get("schedule_kind").and_then(Value::as_str).unwrap_or("daily").to_string(),
                    schedule_value: row.get("schedule_value").and_then(Value::as_u64).unwrap_or(1) as u32,
                    retention_count: row.get("retention_count").and_then(Value::as_u64).unwrap_or(8) as u32,
                    enabled: row.get("enabled").and_then(Value::as_i64).unwrap_or(0) == 1,
                    last_status: row.get("last_status").and_then(Value::as_str).unwrap_or("").to_string(),
                    last_run_at_unix: row.get("last_run_at_unix").and_then(Value::as_u64).unwrap_or(0),
                    next_run_at_unix: row.get("next_run_at_unix").and_then(Value::as_u64).unwrap_or(0),
                    created_at_unix: row.get("created_at_unix").and_then(Value::as_u64).unwrap_or(0),
                    updated_at_unix: row.get("updated_at_unix").and_then(Value::as_u64).unwrap_or(0),
                }
            })
            .collect())
    }

    pub fn update_backup_job_status(
        &self,
        job_id: i64,
        enabled: bool,
        last_status: &str,
        last_run_at_unix: u64,
        next_run_at_unix: u64,
    ) -> Result<(), String> {
        let sql = format!(
            "UPDATE backup_jobs
             SET enabled = {enabled},
                 last_status = {last_status},
                 last_run_at_unix = {last_run_at_unix},
                 next_run_at_unix = {next_run_at_unix},
                 updated_at_unix = {updated_at_unix}
             WHERE id = {job_id};",
            enabled = bool_to_sql_int(enabled),
            last_status = sql_quote(last_status),
            last_run_at_unix = last_run_at_unix,
            next_run_at_unix = next_run_at_unix,
            updated_at_unix = unix_now(),
            job_id = job_id
        );
        self.exec(&sql)
    }

    pub fn delete_backup_job(&self, job_id: i64) -> Result<(), String> {
        self.exec(&format!("DELETE FROM backup_job_targets WHERE job_id = {};", job_id))?;
        self.exec(&format!("DELETE FROM backup_records WHERE job_id = {};", job_id))?;
        self.exec(&format!("DELETE FROM backup_jobs WHERE id = {};", job_id))
    }

    pub fn replace_backup_job_targets(&self, job_id: i64, target_ids: &[i64]) -> Result<(), String> {
        self.exec(&format!("DELETE FROM backup_job_targets WHERE job_id = {};", job_id))?;
        let now = unix_now();
        for target_id in target_ids {
            let sql = format!(
                "INSERT INTO backup_job_targets (job_id, target_id, created_at_unix) VALUES ({job_id}, {target_id}, {now});",
                job_id = job_id,
                target_id = target_id,
                now = now
            );
            self.exec(&sql)?;
        }
        Ok(())
    }

    pub fn list_backup_job_targets(&self) -> Result<Vec<BackupJobTargetLink>, String> {
        let rows = self.query_json("SELECT * FROM backup_job_targets ORDER BY id ASC;")?;
        Ok(rows
            .into_iter()
            .map(|row| BackupJobTargetLink {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                job_id: row.get("job_id").and_then(Value::as_i64).unwrap_or(0),
                target_id: row.get("target_id").and_then(Value::as_i64).unwrap_or(0),
                created_at_unix: row.get("created_at_unix").and_then(Value::as_u64).unwrap_or(0),
            })
            .collect())
    }

    pub fn add_backup_record(
        &self,
        job_id: i64,
        target_id: i64,
        archive_name: &str,
        archive_size_bytes: u64,
        status: &str,
        remote_locator: &str,
    ) -> Result<(), String> {
        let sql = format!(
            "INSERT INTO backup_records
                (job_id, target_id, archive_name, archive_size_bytes, status, remote_locator, created_at_unix)
             VALUES
                ({job_id}, {target_id}, {archive_name}, {archive_size_bytes}, {status}, {remote_locator}, {created_at_unix});",
            job_id = job_id,
            target_id = target_id,
            archive_name = sql_quote(archive_name),
            archive_size_bytes = archive_size_bytes,
            status = sql_quote(status),
            remote_locator = sql_quote(remote_locator),
            created_at_unix = unix_now()
        );
        self.exec(&sql)
    }

    pub fn list_backup_records(&self, limit: usize) -> Result<Vec<BackupRecord>, String> {
        let rows = self.query_json(&format!(
            "SELECT * FROM backup_records ORDER BY created_at_unix DESC, id DESC LIMIT {};",
            limit.max(1)
        ))?;
        Ok(rows
            .into_iter()
            .map(|row| BackupRecord {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                job_id: row.get("job_id").and_then(Value::as_i64).unwrap_or(0),
                target_id: row.get("target_id").and_then(Value::as_i64).unwrap_or(0),
                archive_name: row.get("archive_name").and_then(Value::as_str).unwrap_or("").to_string(),
                archive_size_bytes: row.get("archive_size_bytes").and_then(Value::as_u64).unwrap_or(0),
                status: row.get("status").and_then(Value::as_str).unwrap_or("").to_string(),
                remote_locator: row.get("remote_locator").and_then(Value::as_str).unwrap_or("").to_string(),
                created_at_unix: row.get("created_at_unix").and_then(Value::as_u64).unwrap_or(0),
            })
            .collect())
    }

    pub fn list_backup_records_for_job_target(
        &self,
        job_id: i64,
        target_id: i64,
    ) -> Result<Vec<BackupRecord>, String> {
        let rows = self.query_json(&format!(
            "SELECT * FROM backup_records WHERE job_id = {} AND target_id = {} ORDER BY created_at_unix ASC, id ASC;",
            job_id, target_id
        ))?;
        Ok(rows
            .into_iter()
            .map(|row| BackupRecord {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                job_id: row.get("job_id").and_then(Value::as_i64).unwrap_or(0),
                target_id: row.get("target_id").and_then(Value::as_i64).unwrap_or(0),
                archive_name: row.get("archive_name").and_then(Value::as_str).unwrap_or("").to_string(),
                archive_size_bytes: row.get("archive_size_bytes").and_then(Value::as_u64).unwrap_or(0),
                status: row.get("status").and_then(Value::as_str).unwrap_or("").to_string(),
                remote_locator: row.get("remote_locator").and_then(Value::as_str).unwrap_or("").to_string(),
                created_at_unix: row.get("created_at_unix").and_then(Value::as_u64).unwrap_or(0),
            })
            .collect())
    }

    pub fn delete_backup_record(&self, record_id: i64) -> Result<(), String> {
        self.exec(&format!("DELETE FROM backup_records WHERE id = {};", record_id))
    }

    pub fn add_free_report(
        &self,
        status: &str,
        payload_json: &str,
        response_text: &str,
    ) -> Result<(), String> {
        let sql = format!(
            "INSERT INTO free_reports (created_at_unix, status, payload_json, response_text)
             VALUES ({created_at}, {status}, {payload_json}, {response_text});",
            created_at = unix_now(),
            status = sql_quote(status),
            payload_json = sql_quote(payload_json),
            response_text = sql_quote(response_text)
        );
        self.exec(&sql)
    }

    pub fn recent_free_reports(&self, limit: usize) -> Result<Vec<FreeReportRecord>, String> {
        let sql = format!(
            "SELECT id, created_at_unix, status, payload_json, response_text
             FROM free_reports
             ORDER BY created_at_unix DESC, id DESC
             LIMIT {};",
            limit.max(1)
        );
        let rows = self.query_json(&sql)?;
        Ok(rows
            .into_iter()
            .map(|row| FreeReportRecord {
                id: row.get("id").and_then(Value::as_i64).unwrap_or(0),
                created_at_unix: row
                    .get("created_at_unix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                status: row
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                payload_json: row
                    .get("payload_json")
                    .and_then(Value::as_str)
                    .unwrap_or("{}")
                    .to_string(),
                response_text: row
                    .get("response_text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            })
            .collect())
    }

    pub fn exec(&self, sql: &str) -> Result<(), String> {
        let output = Command::new("sqlite3")
            .arg("-cmd")
            .arg(format!(".timeout {SQLITE_BUSY_TIMEOUT_MS}"))
            .arg("-cmd")
            .arg("PRAGMA synchronous=NORMAL;")
            .arg(self.path.as_os_str())
            .arg(sql)
            .output()
            .map_err(|error| format!("failed to execute sqlite3: {error}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }

    pub fn query_json(&self, sql: &str) -> Result<Vec<Value>, String> {
        let output = Command::new("sqlite3")
            .arg("-cmd")
            .arg(format!(".timeout {SQLITE_BUSY_TIMEOUT_MS}"))
            .arg("-cmd")
            .arg("PRAGMA synchronous=NORMAL;")
            .arg("-json")
            .arg(self.path.as_os_str())
            .arg(sql)
            .output()
            .map_err(|error| format!("failed to execute sqlite3 json query: {error}"))?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str::<Vec<Value>>(trimmed)
            .map_err(|error| format!("failed to parse sqlite json output: {error}"))
    }

    fn ensure_column_exists(
        &self,
        table: &str,
        column: &str,
        definition: &str,
    ) -> Result<(), String> {
        let pragma = format!("PRAGMA table_info({table});");
        let columns = self.query_json(&pragma)?;
        let exists = columns.iter().any(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .map(|name| name == column)
                .unwrap_or(false)
        });

        if exists {
            return Ok(());
        }

        let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition};");
        self.exec(&sql)
    }

}

pub fn sql_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub fn bool_to_sql_int(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

pub fn bool_to_sql_string(value: bool) -> String {
    if value {
        "1".to_string()
    } else {
        "0".to_string()
    }
}

fn parse_bool(value: &str) -> bool {
    value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn active_check_count(rows: &[MonitorCheckRow]) -> usize {
    rows.iter().filter(|row| row.enabled).count()
}

pub fn serialize_summary(results: &[CheckResult]) -> Result<String, String> {
    let up_checks = results
        .iter()
        .filter(|result| matches!(result.status, crate::types::CheckStatus::Up))
        .count();
    let degraded_checks = results
        .iter()
        .filter(|result| matches!(result.status, crate::types::CheckStatus::Degraded))
        .count();
    let down_checks = results
        .iter()
        .filter(|result| matches!(result.status, crate::types::CheckStatus::Down))
        .count();
    serde_json::to_string(&json!({
        "observed_at_unix": unix_now(),
        "total_checks": results.len(),
        "up_checks": up_checks,
        "degraded_checks": degraded_checks,
        "down_checks": down_checks
    }))
    .map_err(|error| format!("failed to serialize summary: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{Database, unix_now, SourceIpRule};
    use crate::types::{CheckResult, CheckStatus};
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn upgrading_legacy_database_removes_credentials_and_retains_checks_and_history() {
        let path = std::env::temp_dir().join(format!(
            "imonitor-license-migration-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let db = Database::new(&path);
        db.init().expect("initialize legacy fixture");
        db.exec("INSERT INTO settings (key, value) VALUES
            ('plan_mode', 'free'), ('license_key', 'legacy-key'),
            ('license_shared_secret', 'legacy-secret'), ('public_title', 'Keep this title');
            INSERT INTO checks
            (check_id, label, kind, plan_required, enabled, public_visible, check_json, created_at_unix, updated_at_unix)
            VALUES ('legacy-dns', 'Keep DNS', 'dns', 'premium', 1, 1,
            '{\"kind\":\"dns\",\"id\":\"legacy-dns\",\"server\":\"1.1.1.1\",\"record_name\":\"example.com\",\"record_type\":\"a\",\"expect_answers_min\":1,\"ip_version\":\"ipv4\"}', 1, 1);
            INSERT INTO snapshots
            (created_at_unix, plan_mode, overall_status, system_json, results_json, summary_json)
            VALUES (1, 'premium', 'up', '{}', '[]', '{}');")
            .expect("write legacy settings, premium check and history");
        db.init().expect("upgrade legacy database");
        assert_eq!(db.load_settings().unwrap().public_title, "Keep this title");
        assert!(db.query_json("SELECT key FROM settings WHERE key = 'plan_mode' OR substr(key, 1, 8) = 'license_';").unwrap().is_empty());
        let mut check = db.get_check("legacy-dns").unwrap().unwrap();
        assert!(check.enabled);
        assert_eq!(check.label, "Keep DNS");
        check.label = "DNS available to everyone".to_string();
        db.upsert_check(&check).expect("update an existing formerly premium check");
        assert_eq!(db.get_check("legacy-dns").unwrap().unwrap().label, "DNS available to everyone");
        assert_eq!(db.recent_snapshots(10).unwrap().len(), 1);
        assert!(serde_json::to_value(check).unwrap().get("plan_required").is_none());
        db.save_snapshot("up", None, &[], "{}").expect("write history after migration");
        assert_eq!(db.recent_snapshots(10).unwrap().len(), 2);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn snapshot_storage_is_compact_and_check_query_is_filtered() {
        let path = std::env::temp_dir().join(format!(
            "imonitor-db-test-{}-{}.db",
            std::process::id(),
            crate::db::unix_now()
        ));
        let db = Database::new(&path);
        db.init().expect("initialize database");
        let mut details = BTreeMap::new();
        details.insert("large_runtime_detail".to_string(), json!("not historical"));
        let result = CheckResult {
            id: "test-monitor".to_string(),
            kind: "https".to_string(),
            status: CheckStatus::Up,
            message: "ok".to_string(),
            observed_at_unix: crate::db::unix_now(),
            duration_ms: 12,
            latency_ms: Some(12),
            ip_version: Some("ipv4".to_string()),
            endpoint: Some("example.com:443".to_string()),
            details,
        };
        db.save_snapshot("up", None, &[result], "{}")
            .expect("save snapshot");
        let snapshots = db
            .check_snapshots_between("test-monitor", None, None, 10)
            .expect("query filtered history");
        assert_eq!(snapshots.len(), 1);
        let stored: Vec<CheckResult> =
            serde_json::from_str(&snapshots[0].results_json).expect("stored results");
        assert_eq!(stored.len(), 1);
        assert!(stored[0].details.is_empty());
        let journal = db.query_json("PRAGMA journal_mode;").expect("journal mode");
        assert_eq!(
            journal
                .first()
                .and_then(|row| row.get("journal_mode"))
                .and_then(serde_json::Value::as_str),
            Some("wal")
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }
    #[test]
    fn legacy_source_ip_mode_migrates_without_changing_existing_rules(){
        let path=std::env::temp_dir().join(format!("imonitor-source-mode-{}-{}.db",std::process::id(),unix_now()));let db=Database::new(&path);db.init().unwrap();
        db.exec("DROP TABLE source_ip_rules; CREATE TABLE source_ip_rules(id INTEGER PRIMARY KEY,label TEXT NOT NULL,family TEXT NOT NULL,protocol TEXT NOT NULL,match_port INTEGER NOT NULL,interface_name TEXT NOT NULL,destination_ip TEXT NOT NULL,source_ip TEXT NOT NULL,translate_ip TEXT NOT NULL,enabled INTEGER NOT NULL,last_status TEXT NOT NULL,created_at_unix INTEGER NOT NULL,updated_at_unix INTEGER NOT NULL); INSERT INTO source_ip_rules VALUES(1,'Keep pair','ipv4','esp',0,'eth0','198.51.100.2','203.0.113.9','',1,'active',10,20);").unwrap();
        db.init().unwrap();let rules=db.list_source_ip_rules().unwrap();assert_eq!(rules.len(),1);assert_eq!(rules[0].mode,"paired");assert_eq!(rules[0].protocol,"esp");assert_eq!(rules[0].source_ip,"203.0.113.9");assert_eq!(rules[0].created_at_unix,10);
        let mut old=serde_json::to_value(&rules[0]).unwrap();old.as_object_mut().unwrap().remove("mode");let restored:SourceIpRule=serde_json::from_value(old).unwrap();assert_eq!(restored.mode,"paired");
        db.add_source_ip_rule("New SNAT","snat","ipv6","50",0,"eth0","2001:db8:2::/64","2001:db8:1::5","",true).unwrap();assert!(db.list_source_ip_rules().unwrap().iter().any(|rule|rule.mode=="snat"&&rule.family=="ipv6"));let _=std::fs::remove_file(path);
    }

}
