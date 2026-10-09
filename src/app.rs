use crate::app_types::{
    build_public_views, summarize_results, AdminDashboardData, AdminMonitorAnalyticsPayload,
    AdminMonitorAnalyticsSummary, AdminMonitorHistoryPoint, AdminSection, AppSettings,
    AdminTunnelDiagnosticsLivePayload, AdminTunnelDiagnosticsPayload, AdminTunnelIperfProgress,
    AdminTunnelIperfSummary, AdminTunnelPingProgress, AdminTunnelPingSummary, HistoryPoint,
    BackupJob, BackupTarget, FileBrowserEntry, HostIpInventoryEntry, MonitorCheckRow,
    MonitorFolder, PublicBranding, PublicCheckHistoryPoint, PublicCheckView,
    PublicStatusPayload, ServerHealthProbe, ServerHealthReport, SnapshotSummary, StoredSnapshot,
    SystemSample, UiLanguage,
    overall_status_from_counts, public_check_message,
};
use crate::config::{
    CheckDefinition, DnsCheck, DnsRecordType, FtpCheck, IcmpCheck, IpVersion, LocalEntryType,
    ProxyType, RdpCheck, SocketCheck, SshCheck, TunnelCheck, TunnelProtocol, UdpCheck,
    V2raySimulationCheck, WebCheck,
};
use crate::db::{self, serialize_summary, Database};
use crate::http::{self, Request, Response};
use crate::hardware::collect_hardware_snapshot;
use crate::radar_client::{
    IranMonitorRadarClient, RadarCheckResult, RadarClientConfig, RadarStatusCheck,
    IRANMONITOR_RADAR_DEFAULT_SHARED_SECRET,
};
use crate::platform::{
    sync_speed_limits, apply_tcp_conn_limit, collect_socket_inventory, collect_host_ip_inventory_detailed,
    collect_system_sample, generate_reverse_proxy_snippet, read_traffic_watcher_counters,
    sync_port_forward_rules, sync_source_ip_rules, sync_traffic_watchers, control_socket_app,
    CpuTimes, NetworkTotals,
};
use crate::runner;
use crate::types::{CheckResult, CheckStatus, FailureCounterState, PersistedState};
use crate::util::{
    bytes_to_human, create_password_hash, decode_base64_lenient, html_escape, normalize_branding_image,
    pick_free_tcp_port, random_hex, verify_password,
};
use crate::views;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write;
use std::fs;
use std::io::{self, Read, Write as IoWrite};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, TryLockError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const IMONITOR_INSTALLER_URL: &str = "https://irnmo.ir/download/imonitor/install.sh";
pub(crate) const IMONITOR_RELEASE_VERSION: &str = env!("CARGO_PKG_VERSION");
const IMONITOR_BUNDLE_SUMS_URL: &str = "https://irnmo.ir/download/imonitor/sha256sums.txt";
const IMONITOR_LATEST_VERSION_URL: &str = "https://irnmo.ir/download/imonitor/latest-version.txt";
const CHECK_HOST_NODES_URL: &str = "https://check-host.net/nodes/hosts";
const CHECK_HOST_PING_URL: &str = "https://check-host.net/check-ping";
const CHECK_HOST_RESULT_URL: &str = "https://check-host.net/check-result/";
const IMONITOR_ASCII_ART: &str = r#"
================================================================================
                                ≠≈∞∞∞≈                                      
                        ∞≈≈≈≈∞≈=÷÷÷÷÷=≠≈√√∞∞∞   π  √                        
                  ≈≈≈≈≈≠=÷÷÷=≠≈≈≈≈∞∞∞∞∞∞≈≠==≠≈√≈∞ -∞√π∞√√√                  
              ≠≠==××==≈≠≈≠≈∞              ≈≈∞≈≠÷=≠=  ≈≠==≠≈√√√              
           ≈≠=÷×÷=≠≠≈                         √≈≠÷÷≠≈  ≈√≈≠÷÷≠≈√=           
       =≠≠=÷×÷=≠≠-    =≠≈∞√        π≈∞∞∞≈∞∞√    ∞≠=÷≠=    π√≈≠==≠∞√√        
     ==÷××÷==≠      ≈≠÷÷÷≠         ∞=÷×÷÷÷÷=≈√    ≈÷÷÷≈      ∞∞∞≈≠÷≠∞∞√     
   ≠=÷×××=≠         ≠×××=   ≠≈≈≠≠≠  -÷×÷÷×÷÷÷=∞   ≠÷÷÷=√         √≠÷÷÷≠∞÷   
 ≈≠÷××-×-          ÷=×××=   ≠×××÷=≠≠÷×÷×××÷××÷∞   ≈÷÷÷÷≈          ÷=÷÷÷=∞   
   =÷÷××÷==         =×××=   ≈=÷××××××÷××÷××÷÷=∞   ≠÷÷÷=∞        ≠≈≠÷÷=≈∞√   
     ===÷×÷÷=≠      ≠÷××÷=    ≠=÷××××××××××÷≠≠    ≠÷=≈∞      √∞≈≠=÷≠∞∞      
        ==÷÷×÷÷==÷   ÷÷÷×÷=     ≠≠≠≠≠≠≠≈≠≈≠≈    π∞∞≈∞     ∞∞≈=÷÷=≈∞≈        
           ≠==÷××÷===  =÷×÷=≠                         √∞≈≠=÷÷=≠∞∞           
              ÷==÷÷×÷÷× -÷÷×÷=≠==÷             ≠==≈≈≈≠=÷÷=≠≈≈               
                  ====≠≠÷  ×≠≠=÷÷÷=≠≠≠≠≠≈≠≠≠≈≠÷÷÷×÷=≠≈≈≈≠≠                  
                        =≠≠    ≠≠=≠≠=÷÷×××÷=≠≈≠≠≠≠≠                         
================================================================================
"#;

pub fn entry() -> Result<(), String> {
    match parse_args(env::args().skip(1).collect())? {
        AppCommand::Help => {
            print_help();
            Ok(())
        }
        AppCommand::Manage(args) => run_manage_panel(args),
        AppCommand::Init(args) => init_instance(args),
        AppCommand::Serve(args) => serve_instance(args),
        AppCommand::TunHelper(args) => runner::run_tun_helper(args),
        AppCommand::SpeedtestServer(args) => crate::speedtest::run_server_cli(args),
        AppCommand::SampleCheck(kind) => {
            println!("{}", sample_check(kind.as_deref()));
            Ok(())
        }
    }
}

struct AppContext {
    db: Database,
    state_file: PathBuf,
    branding_dir: PathBuf,
    runtime: Mutex<RuntimeState>,
    live_metrics: Mutex<DashboardLiveState>,
    tunnel_diagnostics_jobs: Mutex<BTreeMap<String, AdminTunnelDiagnosticsLivePayload>>,
}

struct RuntimeState {
    monitor_state: PersistedState,
    previous_cpu: Option<CpuTimes>,
    previous_net: Option<NetworkTotals>,
}

struct DashboardLiveState {
    previous_cpu: Option<CpuTimes>,
    previous_net: Option<NetworkTotals>,
}

enum AppCommand {
    Help,
    Manage(AppArgs),
    Init(AppArgs),
    Serve(AppArgs),
    TunHelper(Vec<String>),
    SpeedtestServer(Vec<String>),
    SampleCheck(Option<String>),
}

#[derive(Clone)]
struct AppArgs {
    db_path: String,
    data_dir: String,
    listen_addr: String,
    username: String,
    password: Option<String>,
}

fn parse_args(arguments: Vec<String>) -> Result<AppCommand, String> {
    if arguments.is_empty() {
        return Ok(AppCommand::Manage(default_app_args()));
    }

    let mut args = arguments;
    let command = args.remove(0);
    if command == "help" || command == "--help" || command == "-h" {
        return Ok(AppCommand::Help);
    }
    if command == "sample-check" {
        return Ok(AppCommand::SampleCheck(args.into_iter().next()));
    }
    if command == "tun-helper" {
        return Ok(AppCommand::TunHelper(args));
    }
    if command == "speedtest-server" {
        return Ok(AppCommand::SpeedtestServer(args));
    }

    let mut app_args = default_app_args();

    let mut index = 0_usize;
    while index < args.len() {
        match args[index].as_str() {
            "--db" => {
                index += 1;
                app_args.db_path = required_arg(&args, index, "--db")?;
            }
            "--data-dir" => {
                index += 1;
                app_args.data_dir = required_arg(&args, index, "--data-dir")?;
            }
            "--listen" => {
                index += 1;
                app_args.listen_addr = required_arg(&args, index, "--listen")?;
            }
            "--username" => {
                index += 1;
                app_args.username = required_arg(&args, index, "--username")?;
            }
            "--password" => {
                index += 1;
                app_args.password = Some(required_arg(&args, index, "--password")?);
            }
            "--plan" => {
                index += 1;
                // Old service units may still include --plan. All features are
                // available now; consuming the value keeps those units working.
                let _ = required_arg(&args, index, "--plan")?;
            }
            unknown if command == "init" || command == "serve" || command == "manage" => {
                return Err(format!("unknown argument for {command}: {unknown}"))
            }
            _ => {}
        }
        index += 1;
    }

    match command.as_str() {
        "init" => Ok(AppCommand::Init(app_args)),
        "serve" => Ok(AppCommand::Serve(app_args)),
        "manage" => Ok(AppCommand::Manage(app_args)),
        other => Err(format!("unknown command: {other}")),
    }
}

fn required_arg(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn default_app_args() -> AppArgs {
    let data_dir = default_runtime_dir();
    AppArgs {
        db_path: format!("{data_dir}/iranmonitor.db"),
        data_dir,
        listen_addr: "0.0.0.0:6060".to_string(),
        username: "admin".to_string(),
        password: None,
    }
}

fn default_runtime_dir() -> String {
    if let Some(runtime) = detect_runtime_dir_from_service_units() {
        return runtime;
    }

    if let Ok(current_exe) = env::current_exe() {
        if let Some(root) = current_exe.parent().and_then(Path::parent) {
            let runtime = root.join("runtime");
            if runtime.exists()
                || root.join("bin").exists()
                || root.file_name().and_then(|value| value.to_str()) == Some("1.0")
            {
                return runtime.to_string_lossy().to_string();
            }
        }
    }

    "./runtime".to_string()
}

fn detect_runtime_dir_from_service_units() -> Option<String> {
    let candidates = [
        "/etc/systemd/system/iranmonitor-node.service",
        "/etc/systemd/system/imonitor.service",
        "/lib/systemd/system/iranmonitor-node.service",
        "/lib/systemd/system/imonitor.service",
    ];

    for path in candidates {
        let content = fs::read_to_string(path).ok()?;
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with("ExecStart=") {
                continue;
            }
            if let Some(runtime) = extract_flag_value(trimmed, "--data-dir") {
                if !runtime.trim().is_empty() {
                    return Some(runtime);
                }
            }
            if let Some(db_path) = extract_flag_value(trimmed, "--db") {
                let db = Path::new(&db_path);
                if let Some(parent) = db.parent() {
                    return Some(parent.to_string_lossy().to_string());
                }
            }
        }
    }

    None
}

fn extract_flag_value(line: &str, flag: &str) -> Option<String> {
    let marker = format!("{flag} ");
    let start = line.find(&marker)? + marker.len();
    let tail = &line[start..];
    let value = tail.split_whitespace().next()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn print_help() {
    println!(
        "\
iMonitor V{release}

Usage:
  iranmonitor_node
  iranmonitor_node manage [--db PATH] [--data-dir PATH]
  iranmonitor_node init [--db PATH] [--data-dir PATH] [--listen 0.0.0.0:6060] [--username admin] [--password secret]
  iranmonitor_node serve [--db PATH] [--data-dir PATH] [--listen 0.0.0.0:6060]
  iranmonitor_node sample-check [kind]
  iranmonitor_node speedtest-server --bind TUNNEL_IP:5201 --token SHARED_TOKEN

Behavior:
  - Running `imonitor` with no command opens the local CLI management panel
  - Stores all local state in a SQLite database
  - Serves a public panel on / and an admin panel on /admin from the same port
  - Persists monitor checks, snapshots, branding, tunnels, and network controls
  - Public installer: {installer}
"
        ,
        release = IMONITOR_RELEASE_VERSION,
        installer = IMONITOR_INSTALLER_URL
    );
}

fn run_manage_panel(args: AppArgs) -> Result<(), String> {
    ensure_dir(&args.data_dir)?;
    ensure_parent_dir(&args.db_path)?;

    let db = Database::new(&args.db_path);
    db.init()?;

    loop {
        let settings = db.load_settings()?;
        let admin_user = db.first_admin_user()?;

        print!("\x1B[2J\x1B[H");
        io::stdout()
            .flush()
            .map_err(|error| format!("failed to flush terminal: {error}"))?;
        print_cli_banner()?;
        println!("iMonitor V{} CLI Panel", IMONITOR_RELEASE_VERSION);
        println!("Runtime: {}", args.data_dir);
        println!("Listen: {}", settings.bind_addr);
        println!(
            "Admin: {}",
            admin_user
                .as_ref()
                .map(|user| user.username.as_str())
                .unwrap_or("not initialized")
        );
        println!();
        println!("1. Show current panel access");
        println!("2. Change panel port");
        println!("3. Change admin username");
        println!("4. Change admin password");
        println!("5. Update iMonitor from IranMonitor");
        println!("6. Restart iMonitor service");
        println!("7. Uninstall iMonitor completely");
        println!("0. Exit");
        println!();

        let choice = prompt_cli_input("Select an option")?;
        match choice.trim() {
            "1" => {
                show_cli_access_summary(&settings, admin_user.as_ref());
                pause_cli()?;
            }
            "2" => {
                cli_change_port(&db, &settings)?;
                pause_cli()?;
            }
            "3" => {
                cli_change_username(&db, admin_user.as_ref())?;
                pause_cli()?;
            }
            "4" => {
                cli_change_password(&db, admin_user.as_ref())?;
                pause_cli()?;
            }
            "5" => {
                cli_self_update()?;
                pause_cli()?;
            }
            "6" => {
                cli_restart_service()?;
                pause_cli()?;
            }
            "7" => {
                cli_uninstall()?;
                return Ok(());
            }
            "0" => break,
            _ => {
                println!("Unknown option.");
                pause_cli()?;
            }
        }
    }

    Ok(())
}

fn print_cli_banner() -> Result<(), String> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in IMONITOR_ASCII_ART.lines() {
        let trimmed = line.trim_end_matches([' ', '\t']);
        if trimmed.is_empty() {
            writeln!(out).map_err(|error| format!("failed to write banner: {error}"))?;
            continue;
        }
        writeln!(out, "{trimmed}").map_err(|error| format!("failed to write banner: {error}"))?;
    }
    writeln!(out).map_err(|error| format!("failed to write banner: {error}"))?;
    Ok(())
}

fn show_cli_access_summary(settings: &AppSettings, admin_user: Option<&crate::app_types::AdminUser>) {
    println!();
    println!("Panel listen address: {}", settings.bind_addr);
    println!(
        "Public URL: {}",
        if settings.public_base_url.trim().is_empty() {
            "-"
        } else {
            settings.public_base_url.as_str()
        }
    );
    println!(
        "Admin URL: {}",
        if settings.admin_base_url.trim().is_empty() {
            "-"
        } else {
            settings.admin_base_url.as_str()
        }
    );
    println!(
        "Admin username: {}",
        admin_user.map(|user| user.username.as_str()).unwrap_or("not initialized")
    );
    println!("Service unit: {}", detect_panel_service_name().unwrap_or_else(|| "not detected".to_string()));
}

fn cli_change_port(db: &Database, settings: &AppSettings) -> Result<(), String> {
    let current_port = extract_port(&settings.bind_addr);
    let next_port_input = prompt_cli_input(&format!("New panel port [{current_port}]"))?;
    let trimmed = next_port_input.trim();
    let next_port = if trimmed.is_empty() {
        current_port
    } else {
        trimmed
            .parse::<u16>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| "invalid port number".to_string())?
    };

    let bind_host = extract_bind_host(&settings.bind_addr);
    let mut next_settings = settings.clone();
    next_settings.bind_addr = format!("{bind_host}:{next_port}");
    next_settings.public_base_url = replace_url_port_if_possible(&next_settings.public_base_url, next_port);
    next_settings.admin_base_url = replace_url_port_if_possible(&next_settings.admin_base_url, next_port);
    db.save_settings(&next_settings)?;
    restart_panel_service_now()?;
    println!("Panel port updated to {next_port} and the service was restarted.");
    Ok(())
}

fn cli_change_username(
    db: &Database,
    admin_user: Option<&crate::app_types::AdminUser>,
) -> Result<(), String> {
    if admin_user.is_none() {
        return cli_initialize_admin_user(db, None);
    }
    let Some(admin_user) = admin_user else {
        return Err("no admin user exists yet; initialize the node first".to_string());
    };
    let next_username = prompt_cli_input(&format!("New admin username [{}]", admin_user.username))?;
    let next_username = next_username.trim();
    if next_username.is_empty() {
        println!("Username unchanged.");
        return Ok(());
    }
    db.update_admin_user(admin_user.id, next_username, &admin_user.password_hash)?;
    db.clear_all_sessions()?;
    println!("Admin username updated. Existing panel sessions were signed out.");
    Ok(())
}

fn cli_change_password(
    db: &Database,
    admin_user: Option<&crate::app_types::AdminUser>,
) -> Result<(), String> {
    if admin_user.is_none() {
        return cli_initialize_admin_user(db, Some("admin"));
    }
    let Some(admin_user) = admin_user else {
        return Err("no admin user exists yet; initialize the node first".to_string());
    };
    let new_password = prompt_cli_input("New admin password")?;
    if new_password.trim().is_empty() {
        return Err("password cannot be empty".to_string());
    }
    let confirm_password = prompt_cli_input("Confirm new admin password")?;
    if new_password != confirm_password {
        return Err("password confirmation does not match".to_string());
    }
    let password_hash = create_password_hash(new_password.trim())?;
    db.update_admin_user(admin_user.id, &admin_user.username, &password_hash)?;
    db.clear_all_sessions()?;
    println!("Admin password updated. Existing panel sessions were signed out.");
    Ok(())
}

fn cli_initialize_admin_user(db: &Database, default_username: Option<&str>) -> Result<(), String> {
    println!();
    println!("No admin user exists yet. Create the first admin account now.");

    let username_prompt = match default_username {
        Some(username) => format!("Initial admin username [{username}]"),
        None => "Initial admin username".to_string(),
    };
    let username_input = prompt_cli_input(&username_prompt)?;
    let username = if username_input.trim().is_empty() {
        default_username.unwrap_or("admin").trim()
    } else {
        username_input.trim()
    };
    if username.is_empty() {
        return Err("username cannot be empty".to_string());
    }

    let password = prompt_cli_input("Initial admin password")?;
    if password.trim().is_empty() {
        return Err("password cannot be empty".to_string());
    }
    let confirm_password = prompt_cli_input("Confirm initial admin password")?;
    if password != confirm_password {
        return Err("password confirmation does not match".to_string());
    }

    let password_hash = create_password_hash(password.trim())?;
    db.ensure_admin_user(username, &password_hash)?;
    db.clear_all_sessions()?;
    println!("Initial admin user `{username}` was created.");
    Ok(())
}

fn cli_self_update() -> Result<(), String> {
    perform_self_update()?;
    println!("iMonitor was updated from IranMonitor and the service was restarted.");
    Ok(())
}

fn release_version_tuple(version: &str) -> Option<(u32, u32, u32)> {
    let parts = version.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit())) { return None; }
    Some((parts[0].parse().ok()?, parts[1].parse().ok()?, parts[2].parse().ok()?))
}

fn release_checksum(manifest: &str, filename: &str) -> Result<String, String> {
    let mut matching = manifest.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let name = fields.next()?.trim_start_matches('*').trim_start_matches("./");
        (name == filename && fields.next().is_none()).then_some(digest)
    });
    let digest = matching.next().ok_or_else(|| format!("release checksum missing for {filename}"))?;
    if matching.next().is_some() || digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid release checksum for {filename}"));
    }
    Ok(digest.to_ascii_lowercase())
}

fn download_release_file(url: &str, destination: &Path) -> Result<(), String> {
    let status = Command::new("curl").args(["-fsSL", "--connect-timeout", "10", "--max-time", "120", url, "-o"])
        .arg(destination).status().map_err(|error| format!("failed to download release: {error}"))?;
    if status.success() { Ok(()) } else { Err("release download failed; current installation kept".into()) }
}

fn verify_release_file(path: &Path, expected: &str) -> Result<(), String> {
    let mut file = fs::File::open(path).map_err(|error| format!("failed to read release: {error}"))?;
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| format!("failed to hash release: {error}"))?;
        if count == 0 { break; }
        digest.update(&buffer[..count]);
    }
    let actual = digest.finish().as_ref().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    if actual == expected { Ok(()) } else { Err("release bundle checksum mismatch; current installation kept".into()) }
}

fn stage_release_member(archive: &Path, member: &str, destination: &Path, executable: bool) -> Result<(), String> {
    let output = Command::new("unzip").arg("-p").arg(archive).arg(member).output()
        .map_err(|error| format!("failed to extract release member {member}: {error}"))?;
    if !output.status.success() || output.stdout.is_empty() { return Err(format!("release bundle is missing {member}")); }
    fs::write(destination, output.stdout).map_err(|error| format!("failed to stage {member}: {error}"))?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(destination, fs::Permissions::from_mode(if executable { 0o755 } else { 0o600 }))
            .map_err(|error| format!("failed to set release permissions: {error}"))?;
    }
    #[cfg(not(unix))] let _ = executable;
    Ok(())
}

fn perform_self_update() -> Result<(), String> {
    let version = fetch_latest_release_version()?;
    let latest = release_version_tuple(&version).ok_or_else(|| "invalid release version marker".to_string())?;
    let current = release_version_tuple(IMONITOR_RELEASE_VERSION).ok_or_else(|| "invalid current version".to_string())?;
    if latest <= current { return Err(format!("iMonitor {} is current; published version {version} will not replace it", IMONITOR_RELEASE_VERSION)); }
    let arch = match env::consts::ARCH { "x86_64" => "amd64", "aarch64" => "arm64", other => return Err(format!("no update bundle for architecture {other}")) };
    let current_exe = env::current_exe().map_err(|error| format!("failed to locate binary: {error}"))?;
    let binary_dir = current_exe.parent().ok_or_else(|| "failed to locate binary directory".to_string())?;
    let install_root = binary_dir.parent().ok_or_else(|| "failed to locate installation root".to_string())?;
    let nonce = random_hex(8)?;
    let temp_root = env::temp_dir().join(format!("imonitor-update-{nonce}"));
    fs::create_dir(&temp_root).map_err(|error| format!("failed to create update staging directory: {error}"))?;
    // Stage on the destination filesystem so final renames are atomic on Linux.
    let staged_binary = binary_dir.join(format!(".imonitor-update-{nonce}"));
    let staged_helper = binary_dir.join(format!(".imonitor-bpf-update-{nonce}"));
    let bpf_dir = install_root.join("bpf");
    let staged_object = bpf_dir.join(format!(".xdp-update-{nonce}.o"));
    let outcome = (|| {
        let manifest_path = temp_root.join("sha256sums.txt");
        download_release_file(IMONITOR_BUNDLE_SUMS_URL, &manifest_path)?;
        let manifest = fs::read_to_string(manifest_path).map_err(|error| format!("failed to read checksums: {error}"))?;
        let binary_name = format!("imonitor-v{version}-linux-{arch}.zip");
        let binary_archive = temp_root.join(&binary_name);
        let binary_sum = release_checksum(&manifest, &binary_name)?;
        download_release_file(&format!("https://irnmo.ir/download/imonitor/{binary_name}"), &binary_archive)?;
        verify_release_file(&binary_archive, &binary_sum)?;
        stage_release_member(&binary_archive, "imonitor", &staged_binary, true)?;
        let help = Command::new(&staged_binary).arg("help").output().map_err(|error| format!("failed to inspect staged release: {error}"))?;
        if !help.status.success() || !String::from_utf8_lossy(&help.stdout).contains(&format!("iMonitor V{version}")) {
            return Err("staged binary version does not match the release marker".into());
        }
        let helper_name = format!("imonitor-bpf-v{version}-{arch}.zip");
        let helper_archive = temp_root.join(&helper_name);
        let helper_sum = release_checksum(&manifest, &helper_name)?;
        download_release_file(&format!("https://irnmo.ir/download/imonitor/{helper_name}"), &helper_archive)?;
        verify_release_file(&helper_archive, &helper_sum)?;
        fs::create_dir_all(&bpf_dir).map_err(|error| format!("failed to create BPF directory: {error}"))?;
        stage_release_member(&helper_archive, "imonitor-bpf", &staged_helper, true)?;
        stage_release_member(&helper_archive, "xdp_ingress.o", &staged_object, false)?;
        fs::rename(&staged_helper, binary_dir.join("imonitor-bpf")).map_err(|error| format!("failed to replace helper: {error}"))?;
        fs::rename(&staged_object, bpf_dir.join("xdp_ingress.o")).map_err(|error| format!("failed to replace XDP object: {error}"))?;
        fs::rename(&staged_binary, &current_exe).map_err(|error| format!("failed to replace binary: {error}"))?;
        restart_panel_service_now()
    })();
    for path in [&staged_binary, &staged_helper, &staged_object] { let _ = fs::remove_file(path); }
    let _ = fs::remove_dir_all(&temp_root);
    outcome
}

fn cli_restart_service() -> Result<(), String> {
    restart_panel_service_now()?;
    println!("iMonitor service restarted.");
    Ok(())
}

fn cli_uninstall() -> Result<(), String> {
    println!();
    println!("This will stop iMonitor, remove the service, delete the database, and remove installed files.");
    let confirmation = prompt_cli_input("Type REMOVE to confirm uninstall")?;
    if confirmation.trim() != "REMOVE" {
        println!("Uninstall canceled.");
        return Ok(());
    }

    stop_and_disable_panel_service()?;

    let current_exe = env::current_exe().map_err(|error| format!("failed to locate current binary: {error}"))?;
    let install_root = current_exe
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "failed to derive install root".to_string())?
        .to_path_buf();
    let install_root_str = install_root.to_string_lossy().to_string();
    if !(install_root_str.starts_with("/opt/imonitor")
        || install_root_str.starts_with("/opt/iranmonitor-node")
        || install_root_str.starts_with("/usr/local/imonitor"))
    {
        return Err(format!(
            "refusing to uninstall from an unexpected install root: {install_root_str}"
        ));
    }

    remove_file_if_exists("/etc/systemd/system/imonitor.service")?;
    remove_file_if_exists("/lib/systemd/system/imonitor.service")?;
    remove_file_if_exists("/etc/systemd/system/iranmonitor-node.service")?;
    remove_file_if_exists("/lib/systemd/system/iranmonitor-node.service")?;
    if Command::new("systemctl").arg("--version").output().is_ok() {
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        let _ = Command::new("systemctl").arg("reset-failed").status();
    }

    remove_file_if_exists("/etc/init.d/imonitor")?;
    remove_file_if_exists("/etc/init.d/iranmonitor-node")?;
    if Command::new("rc-update").arg("--version").output().is_ok() {
        let _ = Command::new("rc-update").args(["del", "imonitor", "default"]).status();
        let _ = Command::new("rc-update").args(["del", "iranmonitor-node", "default"]).status();
    }

    if let Ok(target) = fs::read_link("/usr/local/bin/imonitor") {
        if target == current_exe || target.starts_with(&install_root) {
            remove_file_if_exists("/usr/local/bin/imonitor")?;
        }
    }

    fs::remove_dir_all(&install_root)
        .map_err(|error| format!("failed to remove install root {}: {error}", install_root.display()))?;

    println!("iMonitor was uninstalled completely.");
    Ok(())
}

fn prompt_cli_input(label: &str) -> Result<String, String> {
    print!("{label}: ");
    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush prompt: {error}"))?;
    let mut buffer = String::new();
    let bytes_read = io::stdin()
        .read_line(&mut buffer)
        .map_err(|error| format!("failed to read input: {error}"))?;
    if bytes_read == 0 {
        return Err("stdin was closed".to_string());
    }
    Ok(buffer.trim_end_matches(['\r', '\n']).to_string())
}

fn pause_cli() -> Result<(), String> {
    match prompt_cli_input("Press Enter to continue") {
        Ok(_) => Ok(()),
        Err(error) if error == "stdin was closed" => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_file_if_exists(path: &str) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to remove {path}: {error}")),
    }
}

fn init_instance(args: AppArgs) -> Result<(), String> {
    ensure_dir(&args.data_dir)?;
    ensure_parent_dir(&args.db_path)?;
    ensure_source_ip_engine_key(&args.data_dir)?;
    let db = Database::new(&args.db_path);
    db.init()?;

    let mut settings = db.load_settings()?;
    settings.bind_addr = args.listen_addr.clone();
    settings.public_base_url = format!("http://127.0.0.1:{}/", extract_port(&args.listen_addr));
    settings.admin_base_url = format!("http://127.0.0.1:{}/admin", extract_port(&args.listen_addr));
    db.save_settings(&settings)?;

    let password = match args.password {
        Some(password) => password,
        None => random_hex(10)?,
    };
    let password_hash = create_password_hash(&password)?;
    let created = db.ensure_admin_user(&args.username, &password_hash)?;

    if db.count_rows("checks")? == 0 {
        seed_default_checks(&db)?;
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "db_path": args.db_path,
            "data_dir": args.data_dir,
            "listen_addr": args.listen_addr,
            "username": args.username,
            "password": password,
            "admin_user_created": created
        }))
        .map_err(|error| format!("failed to render init output: {error}"))?
    );
    Ok(())
}

fn serve_instance(args: AppArgs) -> Result<(), String> {
    ensure_dir(&args.data_dir)?;
    ensure_parent_dir(&args.db_path)?;
    ensure_source_ip_engine_key(&args.data_dir)?;
    let branding_dir = Path::new(&args.data_dir).join("branding");
    ensure_dir(branding_dir.to_string_lossy().as_ref())?;
    let db = Database::new(&args.db_path);
    db.init()?;

    let mut settings = db.load_settings()?;
    if settings.bind_addr.trim().is_empty() {
        settings.bind_addr = args.listen_addr.clone();
        db.save_settings(&settings)?;
    }

    let state_file = Path::new(&args.data_dir).join("monitor_state.json");
    let monitor_state = load_persisted_state(&state_file)?;

    let context = Arc::new(AppContext {
        db,
        state_file,
        branding_dir,
        runtime: Mutex::new(RuntimeState {
            monitor_state,
            previous_cpu: None,
            previous_net: None,
        }),
        live_metrics: Mutex::new(DashboardLiveState {
            previous_cpu: None,
            previous_net: None,
        }),
        tunnel_diagnostics_jobs: Mutex::new(BTreeMap::new()),
    });

    if let Err(error) = ensure_local_speedtest_servers(&context) {
        eprintln!("native speed-test helper warning: {error}");
    }

    if let Err(error) = sync_network_runtime_state(&context) {
        eprintln!("network controls startup warning: {error}");
    }
    let _ = sync_port_forward_rules_from_db(&context);

    let monitor_context = Arc::clone(&context);
    thread::spawn(move || loop {
        let cycle_started = Instant::now();
        let interval = match run_monitor_cycle(&monitor_context) {
            Ok(interval) => interval,
            Err(error) => {
                eprintln!("monitor cycle error: {error}");
                30
            }
        };
        let target_interval = interval.max(10);
        let elapsed = cycle_started.elapsed().as_secs();
        let sleep_secs = target_interval.saturating_sub(elapsed).max(1);
        thread::sleep(Duration::from_secs(sleep_secs));
    });

    let backup_context = Arc::clone(&context);
    thread::spawn(move || loop {
        if let Err(error) = run_backup_scheduler_cycle(&backup_context) {
            eprintln!("backup scheduler error: {error}");
        }
        thread::sleep(Duration::from_secs(60));
    });

    let handler_context = Arc::clone(&context);
    let handler = Arc::new(move |request: Request| handle_request(&handler_context, request));
    http::serve(&settings.bind_addr, handler)
}

fn handle_request(context: &Arc<AppContext>, request: Request) -> Response {
    let settings = match context.db.load_settings() {
        Ok(settings) => settings,
        Err(error) => {
            let branding = branding_from_settings(&AppSettings::default());
            let lang = UiLanguage::Fa;
            return Response::html(
                500,
                views::render_plain_error(&branding, lang, &format!("settings load failed: {error}")),
            );
        }
    };
    let lang = request_language(&request, settings.default_language);

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => {
            if !settings.public_share_enabled {
                return Response::html(
                    403,
                    views::render_plain_error(
                        &branding_from_settings(&settings),
                        lang,
                        "public status sharing is disabled",
                    ),
                );
            }
            match build_public_payload(context, &settings) {
                Ok(payload) => Response::html(200, views::render_public_page(&payload, lang)),
                Err(error) => Response::html(
                    500,
                    views::render_plain_error(&branding_from_settings(&settings), lang, &error),
                ),
            }
        }
        ("GET", "/status.json") if !settings.public_share_enabled => {
            Response::json(403, &json!({"error": "public status sharing is disabled"}))
        }
        ("GET", "/status.json") => match build_public_payload(context, &settings) {
            Ok(payload) => Response::json(
                200,
                &serde_json::to_value(payload).unwrap_or_else(|_| json!({})),
            ),
            Err(error) => Response::json(500, &json!({ "error": error })),
        },
        ("GET", "/assets/imonitor-mark.svg") => bundled_svg_response(include_bytes!("ui/brand/imonitor-mark.svg")),
        ("GET", "/assets/imonitor-wordmark.svg") => bundled_svg_response(include_bytes!("ui/brand/imonitor-wordmark.svg")),
        ("GET", "/assets/fonts/ibm-plex-sans.ttf") => bundled_font_response(include_bytes!("ui/fonts/ibm-plex-sans.ttf")),
        ("GET", "/assets/fonts/vazirmatn.ttf") => bundled_font_response(include_bytes!("ui/fonts/vazirmatn.ttf")),
        ("GET", "/assets/custom") => handle_custom_asset(context, &settings, &request),
        ("GET", "/assets/group-logo") => handle_group_logo_asset(context, &request),
        ("GET", "/admin") | ("GET", "/admin/") | ("GET", "/admin/dashboard") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                render_admin_dashboard_response(
                    context,
                    &settings,
                    lang,
                    request.query_value("flash"),
                    AdminSection::Overview,
                )
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/ads.json") => {
            let placement = request.query_value("placement");
            if placement == "admin" && authenticated_user_id(context, &request).is_none() {
                return Response::json(401, &json!({"creative": null}));
            }
            Response::json(200, &crate::ads::payload(placement, lang))
                .with_header("Cache-Control", "private, max-age=30")
        }
        ("GET", "/admin/tunnels") | ("GET", "/admin/guide") => {
            if authenticated_user_id(context, &request).is_some() {
                let section = if request.path == "/admin/tunnels" {
                    AdminSection::Tunnels
                } else { AdminSection::Guide };
                render_admin_dashboard_response(context, &settings, lang, request.query_value("flash"), section)
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/monitors") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                render_admin_dashboard_response(
                    context,
                    &settings,
                    lang,
                    request.query_value("flash"),
                    AdminSection::Monitors,
                )
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/server-health") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                render_admin_dashboard_response(
                    context,
                    &settings,
                    lang,
                    request.query_value("flash"),
                    AdminSection::ServerHealth,
                )
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/folders") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                render_admin_dashboard_response(
                    context,
                    &settings,
                    lang,
                    request.query_value("flash"),
                    AdminSection::Folders,
                )
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/notifications") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                render_admin_dashboard_response(
                    context,
                    &settings,
                    lang,
                    request.query_value("flash"),
                    AdminSection::Notifications,
                )
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/backups") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                render_admin_dashboard_response(
                    context,
                    &settings,
                    lang,
                    request.query_value("flash"),
                    AdminSection::Backups,
                )
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/backups/browse.json") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_backup_browser_json(request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("GET", "/admin/panel-settings") | ("GET", "/admin/branding") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                render_admin_dashboard_response(
                    context,
                    &settings,
                    lang,
                    request.query_value("flash"),
                    AdminSection::Settings,
                )
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/enterprise") => {
            Response::redirect(&format!("/admin/network-controls?lang={}", lang.as_str()))
        }
        ("GET", "/admin/network-controls") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                render_admin_dashboard_response(
                    context,
                    &settings,
                    lang,
                    request.query_value("flash"),
                    AdminSection::NetworkControls,
                )
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/forwarding") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                render_admin_dashboard_response(
                    context,
                    &settings,
                    lang,
                    request.query_value("flash"),
                    AdminSection::Forwarding,
                )
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/source-ip") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                render_admin_dashboard_response(
                    context,
                    &settings,
                    lang,
                    request.query_value("flash"),
                    AdminSection::SourceIp,
                )
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/sockets") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                render_admin_dashboard_response(
                    context,
                    &settings,
                    lang,
                    request.query_value("flash"),
                    AdminSection::Sockets,
                )
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/reports") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                Response::redirect(AdminSection::Settings.path())
            } else {
                Response::redirect(&format!("/admin/login?lang={}", lang.as_str()))
            }
        }
        ("GET", "/admin/monitors/history.json") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_admin_monitor_history_json(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("GET", "/admin/monitors/tunnel-diagnostics.json") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_admin_tunnel_diagnostics_json(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/monitors/tunnel-diagnostics/start") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_admin_tunnel_diagnostics_start(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("GET", "/admin/monitors/export.csv") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_admin_monitor_export(context, request, "csv")
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("GET", "/admin/monitors/export.pdf") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_admin_monitor_export(context, request, "pdf")
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("GET", "/admin/monitors/export.xlsx") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_admin_monitor_export(context, request, "xlsx")
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("GET", "/admin/live/system") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_admin_live_system(context, lang)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("GET", "/admin/login") => Response::html(
            200,
            views::render_admin_login(&branding_from_settings(&settings), lang, None),
        ),
        ("POST", "/admin/login") => handle_admin_login(context, &settings, request, lang),
        ("GET", "/admin/logout") => handle_logout(context, request),
        ("POST", "/admin/settings") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_settings_update(context, settings, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/access") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_access_update(context, settings, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/checks/save") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_check_save(context, settings, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/checks/delete") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_check_delete(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/folders/save") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_folder_save(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/folders/delete") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_folder_delete(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/folders/assign") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_folder_assignments(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/source-ip/save") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_source_ip_save(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/source-ip/delete") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_source_ip_delete(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/backups/target/save") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_backup_target_save(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/backups/target/delete") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_backup_target_delete(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/backups/job/save") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_backup_job_save(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/backups/job/delete") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_backup_job_delete(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/backups/job/run") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_backup_job_run(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/source-ip/apply") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_source_ip_apply(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/notifications/test") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_notification_test(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/notifications/test-bot") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_notification_bot_test(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/notifications/test-socks") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_notification_socks_test(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/traffic-watchers/save") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_traffic_watcher_save(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/traffic-watchers/delete") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_traffic_watcher_delete(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/speed-limits/save") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_speed_limit_save(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/speed-limits/delete") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_speed_limit_delete(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/controls/apply-speed-limits") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_apply_speed_limits(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/controls/tcp-limit") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_tcp_limit(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/forward-rules/save") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_port_forward_rule_save(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/forward-rules/delete") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_port_forward_rule_delete(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/controls/apply-forward-rules") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_apply_port_forward_rules(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/socket-control") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_socket_control(context, request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        ("POST", "/admin/self-update") => {
            if let Some(_user_id) = authenticated_user_id(context, &request) {
                handle_admin_self_update(request)
            } else {
                unauthorized_response(&settings, lang)
            }
        }
        _ => Response::text(404, "not found".to_string()),
    }
}

fn handle_custom_asset(context: &Arc<AppContext>, settings: &AppSettings, request: &Request) -> Response {
    let kind = request.query_value("kind");
    let candidate = if kind == "favicon" {
        settings.favicon_url.trim()
    } else {
        settings.logo_url.trim()
    };

    if candidate.is_empty() || candidate.starts_with("http://") || candidate.starts_with("https://") {
        return Response::text(404, "asset not found".to_string());
    }
    branding_asset_response(&context.branding_dir, candidate)
}

fn handle_group_logo_asset(context: &Arc<AppContext>, request: &Request) -> Response {
    let candidate = request.query_value("src").trim();
    if candidate.is_empty()
        || candidate.starts_with("http://")
        || candidate.starts_with("https://")
    {
        return Response::text(404, "asset not found".to_string());
    }

    // Requests may reference only an image already configured as a folder logo.
    // Legacy folders can also be represented by their assigned monitor rows.
    let configured = context.db.list_monitor_folders()
        .map(|folders| folders.iter().any(|folder| folder.logo_url.trim() == candidate))
        .unwrap_or(false)
        || context.db.list_checks()
            .map(|checks| checks.iter().any(|check| check.group_logo_url.trim() == candidate))
            .unwrap_or(false);
    if !configured {
        return Response::text(404, "asset not found".to_string());
    }
    branding_asset_response(&context.branding_dir, candidate)
}

const MAX_BRANDING_ASSET_BYTES: u64 = 2 * 1024 * 1024;

fn branding_asset_response(branding_dir: &Path, candidate: &str) -> Response {
    match read_branding_asset(branding_dir, Path::new(candidate)) {
        Ok((bytes, content_type)) => Response {
            status: 200,
            content_type: content_type.to_string(),
            headers: vec![
                ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
                ("Cache-Control".to_string(), "public, max-age=60".to_string()),
            ],
            body: bytes,
        },
        Err(_) => Response::text(404, "asset not found".to_string()),
    }
}

fn read_branding_asset(branding_dir: &Path, candidate: &Path) -> Result<(Vec<u8>, &'static str), String> {
    let (file, path) = open_branding_file(branding_dir, candidate)?;
    let extension = path.extension().and_then(|value| value.to_str()).unwrap_or("").to_ascii_lowercase();
    if !matches!(extension.as_str(), "png" | "jpg" | "jpeg" | "webp" | "gif" | "ico") {
        return Err("unsupported branding image format".to_string());
    }
    let metadata = file.metadata().map_err(|_| "invalid asset metadata")?;
    if !metadata.is_file() || metadata.len() > MAX_BRANDING_ASSET_BYTES {
        return Err("branding image exceeds the size limit".to_string());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_BRANDING_ASSET_BYTES + 1).read_to_end(&mut bytes).map_err(|_| "asset could not be read")?;
    if bytes.len() as u64 > MAX_BRANDING_ASSET_BYTES {
        return Err("branding image exceeds the size limit".to_string());
    }
    let content_type = branding_image_content_type(&extension, &bytes)
        .ok_or_else(|| "branding image contents do not match its format".to_string())?;
    Ok((bytes, content_type))
}

#[cfg(not(windows))]
fn open_branding_file(branding_dir: &Path, candidate: &Path) -> Result<(fs::File, PathBuf), String> {
    let root = fs::canonicalize(branding_dir).map_err(|_| "invalid asset directory")?;
    let path = fs::canonicalize(candidate).map_err(|_| "invalid asset path")?;
    if !path.starts_with(&root) {
        return Err("asset is outside the branding directory".to_string());
    }

    let file = fs::File::open(&path).map_err(|_| "asset could not be opened")?;
    Ok((file, path))
}

#[cfg(windows)]
fn open_branding_file(branding_dir: &Path, candidate: &Path) -> Result<(fs::File, PathBuf), String> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::AsRawHandle;
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(name: *const u16, access: u32, share: u32, security: *mut c_void,
            disposition: u32, flags: u32, template: *mut c_void) -> *mut c_void;
        fn GetFinalPathNameByHandleW(handle: *mut c_void, path: *mut u16, size: u32, flags: u32) -> u32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }
    fn final_path(handle: *mut c_void) -> Result<PathBuf, String> {
        let mut path = vec![0_u16; 32_768];
        // VOLUME_NAME_NT gives the normalized physical path without opening the
        // DOS volume, which Windows app sandboxes can deny. Both boundaries use
        // this same representation; junctions and symlinks remain resolved.
        let length = unsafe { GetFinalPathNameByHandleW(handle, path.as_mut_ptr(), path.len() as u32, 2) };
        if length == 0 || length as usize >= path.len() {
            return Err("asset path could not be resolved".to_string());
        }
        Ok(PathBuf::from(std::ffi::OsString::from_wide(&path[..length as usize])))
    }
    let root_name = branding_dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect::<Vec<_>>();
    let root_handle = unsafe {
        CreateFileW(root_name.as_ptr(), 0, 7, std::ptr::null_mut(), 3, 0x02000000, std::ptr::null_mut())
    };
    if root_handle as isize == -1 { return Err("invalid asset directory".to_string()); }
    let root = final_path(root_handle);
    unsafe { CloseHandle(root_handle); }
    let root = root?;
    let file = fs::File::open(candidate).map_err(|_| "asset could not be opened")?;
    let path = final_path(file.as_raw_handle())?;
    if !path.starts_with(&root) { return Err("asset is outside the branding directory".to_string()); }
    Ok((file, path))
}

fn branding_image_content_type(extension: &str, bytes: &[u8]) -> Option<&'static str> {
    match extension {
        "png" if bytes.starts_with(b"\x89PNG\r\n\x1a\n") => Some("image/png"),
        "jpg" | "jpeg" if bytes.starts_with(&[0xff, 0xd8, 0xff]) => Some("image/jpeg"),
        "gif" if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") => Some("image/gif"),
        "webp" if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" => Some("image/webp"),
        "ico" if bytes.len() >= 6 && bytes[..4] == [0, 0, 1, 0] && u16::from_le_bytes([bytes[4], bytes[5]]) > 0 => Some("image/x-icon"),
        _ => None,
    }
}

fn handle_admin_login(
    context: &Arc<AppContext>,
    settings: &AppSettings,
    request: Request,
    lang: UiLanguage,
) -> Response {
    let username = request.form_value("username").trim();
    let password = request.form_value("password");
    match context.db.get_admin_user_hash(username) {
        Ok(Some((user_id, stored_hash))) => match verify_password(password, &stored_hash) {
            Ok(true) => match random_hex(24)
                .and_then(|token| {
                    context.db.create_session(user_id, &token, db::unix_now() + 86400 * 30)?;
                    Ok(token)
                }) {
                Ok(token) => Response::redirect("/admin?flash=login_ok").with_header(
                    "Set-Cookie",
                    &format!(
                        "im_admin_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
                        86400 * 30
                    ),
                ),
                Err(error) => Response::html(
                    500,
                    views::render_admin_login(
                        &branding_from_settings(settings),
                        lang,
                        Some(&error),
                    ),
                ),
            },
            Ok(false) => Response::html(
                401,
                views::render_admin_login(
                    &branding_from_settings(settings),
                    lang,
                    Some("invalid username or password"),
                ),
            ),
            Err(error) => Response::html(
                500,
                views::render_admin_login(
                    &branding_from_settings(settings),
                    lang,
                    Some(&error),
                ),
            ),
        },
        Ok(None) => Response::html(
            401,
            views::render_admin_login(
                &branding_from_settings(settings),
                lang,
                Some("invalid username or password"),
            ),
        ),
        Err(error) => Response::html(
            500,
            views::render_admin_login(
                &branding_from_settings(settings),
                lang,
                Some(&error),
            ),
        ),
    }
}

fn handle_logout(context: &Arc<AppContext>, request: Request) -> Response {
    if let Some(token) = request.cookie("im_admin_session") {
        let _ = context.db.delete_session(token);
    }
    Response::redirect("/admin/login?flash=logout_ok").with_header(
        "Set-Cookie",
        "im_admin_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
    )
}

fn render_admin_dashboard_response(
    context: &Arc<AppContext>,
    settings: &AppSettings,
    lang: UiLanguage,
    flash_code: &str,
    section: AdminSection,
) -> Response {
    match build_admin_dashboard_data(context, settings, section) {
        Ok(data) => {
            let flash = flash_message(lang, flash_code).or_else(|| {
                if flash_code.is_empty() {
                    None
                } else {
                    Some(flash_code)
                }
            });
            Response::html(
                200,
                views::render_admin_dashboard(
                    &data,
                    lang,
                    flash,
                    &generate_reverse_proxy_snippet(settings),
                    section,
                ),
            )
        }
        Err(error) => Response::html(
            500,
            views::render_plain_error(&branding_from_settings(settings), lang, &error),
        ),
    }
}

fn resolve_admin_return_to(request: &Request, default_path: &str) -> String {
    let candidate = request.form_value("return_to").trim();
    if candidate.starts_with("/admin") {
        candidate.to_string()
    } else {
        default_path.to_string()
    }
}

fn redirect_with_flash(request: &Request, default_path: &str, flash: &str) -> Response {
    let return_to = resolve_admin_return_to(request, default_path);
    let separator = if return_to.contains('?') { '&' } else { '?' };
    Response::redirect(&format!(
        "{return_to}{separator}flash={}",
        http::url_encode(flash)
    ))
}

fn handle_admin_monitor_history_json(context: &Arc<AppContext>, request: Request) -> Response {
    match build_monitor_analytics_from_request(context, &request) {
        Ok(payload) => Response::json(
            200,
            &serde_json::to_value(payload).unwrap_or_else(|_| json!({})),
        ),
        Err(error) => Response::json(400, &json!({ "error": error })),
    }
}

fn handle_admin_tunnel_diagnostics_json(context: &Arc<AppContext>, request: Request) -> Response {
    let payload = if !request.query_value("job_id").trim().is_empty() {
        build_tunnel_diagnostics_live_from_request(context, &request)
            .map(|payload| serde_json::to_value(payload).unwrap_or_else(|_| json!({})))
    } else {
        build_tunnel_diagnostics_from_request(context, &request)
            .map(|payload| serde_json::to_value(payload).unwrap_or_else(|_| json!({})))
    };
    match payload {
        Ok(payload) => Response::json(200, &payload),
        Err(error) => Response::json(400, &json!({ "error": error })),
    }
}

fn handle_admin_tunnel_diagnostics_start(context: &Arc<AppContext>, request: Request) -> Response {
    match start_tunnel_diagnostics_from_request(context, &request) {
        Ok(payload) => Response::json(
            200,
            &serde_json::to_value(payload).unwrap_or_else(|_| json!({})),
        ),
        Err(error) => Response::json(400, &json!({ "error": error })),
    }
}

fn handle_admin_monitor_export(
    context: &Arc<AppContext>,
    request: Request,
    format: &str,
) -> Response {
    let payload = match build_monitor_analytics_from_request(context, &request) {
        Ok(payload) => payload,
        Err(error) => return Response::json(400, &json!({ "error": error })),
    };

    let file_stem = slugify_check_id("", &payload.check_id);
    let (content_type, body) = match format {
        "csv" => ("text/csv; charset=utf-8", render_monitor_analytics_csv(&payload)),
        "pdf" => ("application/pdf", render_monitor_analytics_pdf(&payload)),
        "xlsx" => match render_monitor_analytics_xlsx(&payload) {
            Ok(bytes) => (
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                bytes,
            ),
            Err(error) => return Response::json(500, &json!({ "error": error })),
        },
        _ => {
            return Response::json(400, &json!({
                "error": format!("unsupported export format: {format}")
            }))
        }
    };

    Response {
        status: 200,
        content_type: content_type.to_string(),
        headers: vec![(
            "Content-Disposition".to_string(),
            format!("attachment; filename=\"{}-analytics.{format}\"", file_stem),
        )],
        body,
    }
}

fn build_monitor_analytics_from_request(
    context: &Arc<AppContext>,
    request: &Request,
) -> Result<AdminMonitorAnalyticsPayload, String> {
    let check_id = request.query_value("check_id").trim();
    if check_id.is_empty() {
        return Err("check_id is required".to_string());
    }

    let mut from_unix = parse_query_u64(request, "from_unix");
    let mut to_unix = parse_query_u64(request, "to_unix");
    if let (Some(from), Some(to)) = (from_unix, to_unix) {
        if from > to {
            from_unix = Some(to);
            to_unix = Some(from);
        }
    }

    build_monitor_analytics(context, check_id, from_unix, to_unix)
}

const TUNNEL_DIAGNOSTICS_SECONDS: u64 = 10;
const TUNNEL_DIAGNOSTICS_PARALLEL: usize = 4;
const TUNNEL_DIAGNOSTICS_PING_COUNT: u32 = 4;
const TUNNEL_DIAGNOSTICS_JOB_TTL_SECONDS: u64 = 900;

fn build_tunnel_diagnostics_from_request(
    context: &Arc<AppContext>,
    request: &Request,
) -> Result<AdminTunnelDiagnosticsPayload, String> {
    let check_id = request.query_value("check_id").trim();
    if check_id.is_empty() {
        return Err("check_id is required".to_string());
    }
    build_tunnel_diagnostics(context, check_id)
}

fn build_tunnel_diagnostics_live_from_request(
    context: &Arc<AppContext>,
    request: &Request,
) -> Result<AdminTunnelDiagnosticsLivePayload, String> {
    let job_id = request.query_value("job_id").trim();
    if job_id.is_empty() {
        return Err("job_id is required".to_string());
    }
    get_tunnel_diagnostics_job(context, job_id)
}

fn start_tunnel_diagnostics_from_request(
    context: &Arc<AppContext>,
    request: &Request,
) -> Result<AdminTunnelDiagnosticsLivePayload, String> {
    let check_id = request
        .form_value("check_id")
        .trim()
        .to_string();
    if check_id.is_empty() {
        return Err("check_id is required".to_string());
    }
    start_tunnel_diagnostics_job(context, &check_id)
}

fn build_tunnel_diagnostics(
    context: &Arc<AppContext>,
    check_id: &str,
) -> Result<AdminTunnelDiagnosticsPayload, String> {
    let (row, tunnel) = load_tunnel_monitor(context, check_id)?;

    let _ = ensure_local_speedtest_servers(context);
    let bind_ip = resolve_tunnel_bind_ip(&tunnel);
    let ping = run_tunnel_ping_average(&tunnel);
    let upload = run_tunnel_speed_transfer(&tunnel, bind_ip.as_deref(), false);
    let download = run_tunnel_speed_transfer(&tunnel, bind_ip.as_deref(), true);

    Ok(AdminTunnelDiagnosticsPayload {
        check_id: row.check_id.clone(),
        label: row.label.clone(),
        interface: tunnel.interface.clone().or(tunnel.source_interface.clone()),
        inner_probe: tunnel.inner_probe.clone(),
        bind_ip,
        iperf_port: tunnel.speedtest_port,
        ping,
        upload,
        download,
    })
}

fn load_tunnel_monitor(
    context: &Arc<AppContext>,
    check_id: &str,
) -> Result<(MonitorCheckRow, TunnelCheck), String> {
    let checks = context.db.list_checks()?;
    let row = checks
        .into_iter()
        .find(|row| row.check_id == check_id)
        .ok_or_else(|| format!("monitor {check_id} was not found"))?;
    let definition = serde_json::from_str::<CheckDefinition>(&row.check_json)
        .map_err(|error| format!("failed to parse tunnel monitor definition: {error}"))?;
    let tunnel = match definition {
        CheckDefinition::Tunnel(check) => check,
        _ => return Err("speed diagnostics are only available for tunnel monitors".to_string()),
    };
    Ok((row, tunnel))
}

fn start_tunnel_diagnostics_job(
    context: &Arc<AppContext>,
    check_id: &str,
) -> Result<AdminTunnelDiagnosticsLivePayload, String> {
    let job_id = format!(
        "diag-{}-{}",
        slugify_check_id("", check_id),
        random_hex(4)?
    );
    let payload = initial_tunnel_diagnostics_job_payload(&job_id, check_id);
    store_tunnel_diagnostics_job(context, payload.clone())?;
    spawn_tunnel_diagnostics_job(Arc::clone(context), job_id, check_id.to_string());
    Ok(payload)
}

fn initial_tunnel_diagnostics_job_payload(
    job_id: &str,
    check_id: &str,
) -> AdminTunnelDiagnosticsLivePayload {
    AdminTunnelDiagnosticsLivePayload {
        job_id: job_id.to_string(),
        check_id: check_id.to_string(),
        label: check_id.to_string(),
        interface: None,
        inner_probe: None,
        bind_ip: None,
        iperf_port: crate::speedtest::DEFAULT_PORT,
        status: "running".to_string(),
        elapsed_seconds: 0,
        total_seconds: TUNNEL_DIAGNOSTICS_SECONDS * 2,
        started_at_unix: db::unix_now(),
        finished_at_unix: None,
        ping: AdminTunnelPingProgress {
            phase: "pending".to_string(),
            avg_latency_ms: None,
            min_latency_ms: None,
            max_latency_ms: None,
            packet_loss_percent: None,
            sample_count: TUNNEL_DIAGNOSTICS_PING_COUNT,
            completed_samples: 0,
            raw_output: String::new(),
            error: None,
        },
        upload: AdminTunnelIperfProgress {
            phase: "pending".to_string(),
            current_mbps: None,
            avg_mbps: None,
            peak_mbps: None,
            bytes: None,
            retransmits: None,
            completed_seconds: 0,
            total_seconds: TUNNEL_DIAGNOSTICS_SECONDS,
            raw_output: String::new(),
            error: None,
        },
        download: AdminTunnelIperfProgress {
            phase: "pending".to_string(),
            current_mbps: None,
            avg_mbps: None,
            peak_mbps: None,
            bytes: None,
            retransmits: None,
            completed_seconds: 0,
            total_seconds: TUNNEL_DIAGNOSTICS_SECONDS,
            raw_output: String::new(),
            error: None,
        },
    }
}

fn store_tunnel_diagnostics_job(
    context: &Arc<AppContext>,
    payload: AdminTunnelDiagnosticsLivePayload,
) -> Result<(), String> {
    let mut jobs = context
        .tunnel_diagnostics_jobs
        .lock()
        .map_err(|_| "tunnel diagnostics lock poisoned".to_string())?;
    cleanup_tunnel_diagnostics_jobs(&mut jobs);
    if jobs.values().any(|job| job.status == "running") {
        return Err("A tunnel speed test is already running. Wait for it to finish before starting another.".to_string());
    }
    jobs.insert(payload.job_id.clone(), payload);
    Ok(())
}

fn get_tunnel_diagnostics_job(
    context: &Arc<AppContext>,
    job_id: &str,
) -> Result<AdminTunnelDiagnosticsLivePayload, String> {
    let mut jobs = context
        .tunnel_diagnostics_jobs
        .lock()
        .map_err(|_| "tunnel diagnostics lock poisoned".to_string())?;
    cleanup_tunnel_diagnostics_jobs(&mut jobs);
    jobs
        .get(job_id)
        .cloned()
        .ok_or_else(|| format!("diagnostics job {job_id} was not found"))
}

fn update_tunnel_diagnostics_job(
    context: &Arc<AppContext>,
    job_id: &str,
    apply: impl FnOnce(&mut AdminTunnelDiagnosticsLivePayload),
) -> Result<(), String> {
    let mut jobs = context
        .tunnel_diagnostics_jobs
        .lock()
        .map_err(|_| "tunnel diagnostics lock poisoned".to_string())?;
    if let Some(job) = jobs.get_mut(job_id) {
        apply(job);
        Ok(())
    } else {
        Err(format!("diagnostics job {job_id} was not found"))
    }
}

fn cleanup_tunnel_diagnostics_jobs(
    jobs: &mut BTreeMap<String, AdminTunnelDiagnosticsLivePayload>,
) {
    let now = db::unix_now();
    jobs.retain(|_, job| {
        now.saturating_sub(job.started_at_unix) <= TUNNEL_DIAGNOSTICS_JOB_TTL_SECONDS
    });
    while jobs.len() > 32 {
        let Some(oldest_key) = jobs
            .iter()
            .min_by_key(|(_, job)| job.started_at_unix)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        jobs.remove(&oldest_key);
    }
}

fn spawn_tunnel_diagnostics_job(
    context: Arc<AppContext>,
    job_id: String,
    check_id: String,
) {
    thread::spawn(move || {
        let (row, tunnel) = match load_tunnel_monitor(&context, &check_id) {
            Ok(parts) => parts,
            Err(error) => {
                let _ = update_tunnel_diagnostics_job(&context, &job_id, |job| {
                    job.status = "failed".to_string();
                    job.finished_at_unix = Some(db::unix_now());
                    job.ping.phase = "error".to_string();
                    job.ping.error = Some(error.clone());
                    job.upload.phase = "error".to_string();
                    job.upload.error = Some(error.clone());
                    job.download.phase = "error".to_string();
                    job.download.error = Some(error.clone());
                });
                return;
            }
        };
        let bind_ip = resolve_tunnel_bind_ip(&tunnel);
        let _ = update_tunnel_diagnostics_job(&context, &job_id, |job| {
            job.label = row.label.clone();
            job.check_id = row.check_id.clone();
            job.interface = tunnel.interface.clone().or(tunnel.source_interface.clone());
            job.inner_probe = tunnel.inner_probe.clone();
            job.bind_ip = bind_ip.clone();
            job.iperf_port = tunnel.speedtest_port;
        });

        let ping_context = Arc::clone(&context);
        let ping_job_id = job_id.clone();
        let ping_tunnel = tunnel.clone();
        let ping_handle = thread::spawn(move || {
            run_tunnel_ping_live_worker(&ping_context, &ping_job_id, &ping_tunnel)
        });

        // Upload and download run sequentially so each measures available capacity.
        // A peer listener may already be running independently; local listener errors
        // must not prevent a client from reaching that peer.
        let _ = ensure_local_speedtest_servers(&context);
        let upload_ok = run_tunnel_speed_live_worker(&context, &job_id, &tunnel, bind_ip.as_deref(), false);
        let download_ok = run_tunnel_speed_live_worker(&context, &job_id, &tunnel, bind_ip.as_deref(), true);
        let ping_ok = ping_handle.join().unwrap_or(false);

        let final_status = if ping_ok && upload_ok && download_ok {
            "completed"
        } else {
            "failed"
        };
        let _ = update_tunnel_diagnostics_job(&context, &job_id, |job| {
            job.status = final_status.to_string();
            job.elapsed_seconds = job.elapsed_seconds.max(job.total_seconds);
            job.finished_at_unix = Some(db::unix_now());
        });
    });
}

fn build_monitor_analytics(
    context: &Arc<AppContext>,
    check_id: &str,
    from_unix: Option<u64>,
    to_unix: Option<u64>,
) -> Result<AdminMonitorAnalyticsPayload, String> {
    let checks = context.db.list_checks()?;
    let row = checks.iter().find(|row| row.check_id == check_id);
    let snapshots = context
        .db
        .check_snapshots_between(check_id, from_unix, to_unix, 10_000)?;
    let mut points = Vec::new();

    for snapshot in snapshots {
        let results = match serde_json::from_str::<Vec<CheckResult>>(&snapshot.results_json) {
            Ok(results) => results,
            Err(_) => continue,
        };
        if let Some(result) = results.into_iter().find(|result| result.id == check_id) {
            points.push(AdminMonitorHistoryPoint {
                observed_at_unix: result.observed_at_unix.max(snapshot.created_at_unix),
                status: result.status,
                latency_ms: result.latency_ms,
                duration_ms: result.duration_ms,
                message: result.message,
                endpoint: result.endpoint,
            });
        }
    }

    let summary = summarize_monitor_analytics(&points);
    let kind = row
        .map(|row| canonical_kind_name(&row.kind).to_string())
        .unwrap_or_else(|| "unknown".to_string());

    Ok(AdminMonitorAnalyticsPayload {
        check_id: check_id.to_string(),
        label: row
            .map(|row| row.label.clone())
            .unwrap_or_else(|| check_id.to_string()),
        kind,
        from_unix: points
            .first()
            .map(|point| point.observed_at_unix)
            .or(from_unix)
            .unwrap_or(0),
        to_unix: points
            .last()
            .map(|point| point.observed_at_unix)
            .or(to_unix)
            .unwrap_or_else(db::unix_now),
        points,
        summary,
    })
}

fn summarize_monitor_analytics(
    points: &[AdminMonitorHistoryPoint],
) -> AdminMonitorAnalyticsSummary {
    let mut up_points = 0_usize;
    let mut degraded_points = 0_usize;
    let mut down_points = 0_usize;
    let mut latency_total = 0_u64;
    let mut latency_count = 0_u64;
    let mut max_latency_ms: Option<u64> = None;

    for point in points {
        match point.status {
            CheckStatus::Up => up_points += 1,
            CheckStatus::Degraded => degraded_points += 1,
            CheckStatus::Down => down_points += 1,
        }
        if let Some(latency_ms) = point.latency_ms {
            latency_total = latency_total.saturating_add(latency_ms);
            latency_count += 1;
            max_latency_ms = Some(max_latency_ms.map(|current| current.max(latency_ms)).unwrap_or(latency_ms));
        }
    }

    let total_points = points.len();
    let availability_percent = if total_points == 0 {
        0.0
    } else {
        (up_points as f64 / total_points as f64) * 100.0
    };

    AdminMonitorAnalyticsSummary {
        total_points,
        up_points,
        degraded_points,
        down_points,
        availability_percent,
        avg_latency_ms: if latency_count == 0 {
            None
        } else {
            Some(latency_total as f64 / latency_count as f64)
        },
        max_latency_ms,
    }
}

fn bundled_svg_response(bytes: &[u8]) -> Response {
    // Only these authored, embedded SVGs are served. Arbitrary SVG uploads remain disabled.
    Response { status: 200, content_type: "image/svg+xml".into(),
        headers: vec![("Cache-Control".into(), "public, max-age=86400".into()),
            ("X-Content-Type-Options".into(), "nosniff".into()),
            ("Content-Security-Policy".into(), "default-src 'none'; style-src 'unsafe-inline'; sandbox".into())],
        body: bytes.to_vec() }
}

fn bundled_font_response(bytes: &[u8]) -> Response {
    Response {
        status: 200,
        content_type: "font/ttf".into(),
        headers: vec![("Cache-Control".into(), "public, max-age=86400".into()), ("X-Content-Type-Options".into(), "nosniff".into())],
        body: bytes.to_vec(),
    }
}

fn ensure_local_speedtest_servers(context: &Arc<AppContext>) -> Result<(), String> {
    let mut servers = Vec::new();
    for row in context.db.list_checks()? {
        if !row.enabled { continue; }
        let Ok(CheckDefinition::Tunnel(check)) = serde_json::from_str::<CheckDefinition>(&row.check_json) else { continue; };
        let Some(token) = check.speedtest_token.as_deref().filter(|value| !value.is_empty()) else { continue; };
        validate_tunnel_speedtest(&check)?;
        let Some(local_ip) = resolve_tunnel_bind_ip(&check).and_then(|value| value.parse::<IpAddr>().ok()) else { continue; };
        let allowed_peer = check.inner_probe.as_deref().and_then(|value| value.trim().parse::<IpAddr>().ok());
        servers.push(crate::speedtest::ServerConfig {
            bind: std::net::SocketAddr::new(local_ip, check.speedtest_port),
            token: token.to_string(),
            allowed_peer,
        });
    }
    crate::speedtest::sync_servers(servers)
}

fn validate_tunnel_speedtest(check: &TunnelCheck) -> Result<(), String> {
    if check.speedtest_port == 0 { return Err("Speed-test port must be between 1 and 65535.".to_string()); }
    if let Some(token) = check.speedtest_token.as_deref() {
        crate::speedtest::validate_token(token)?;
        let peer = check.inner_probe.as_deref().ok_or_else(|| "Native speed tests require the peer's inner tunnel IP.".to_string())?
            .trim().parse::<IpAddr>().map_err(|_| "Use an IP address for the speed-test peer inside the tunnel.".to_string())?;
        let local = check.inner_local_cidr.as_deref().and_then(|value| value.split('/').next())
            .ok_or_else(|| "Native speed tests require this server's inner tunnel IP/CIDR.".to_string())?
            .trim().parse::<IpAddr>().map_err(|_| "Invalid local inner tunnel IP.".to_string())?;
        if local.is_unspecified() || local.is_multicast() || peer.is_unspecified() || peer.is_multicast()
            || local == peer || local.is_ipv4() != peer.is_ipv4() {
            return Err("Native speed tests require different local and peer tunnel IPs of the same family.".to_string());
        }
    }
    Ok(())
}

fn tunnel_speedtest_parameters(check: &TunnelCheck, bind_ip: Option<&str>) -> Result<(std::net::SocketAddr, IpAddr, String), String> {
    let token = check.speedtest_token.as_deref().ok_or_else(|| "Set the same speed-test token on this tunnel and its peer to enable native throughput tests.".to_string())?;
    crate::speedtest::validate_token(token)?;
    let peer_ip = check.inner_probe.as_deref().unwrap_or("").trim().parse::<IpAddr>()
        .map_err(|_| "Set the peer's inner tunnel IP before running a speed test.".to_string())?;
    let local_ip = bind_ip.unwrap_or("").trim().parse::<IpAddr>()
        .map_err(|_| "Set this server's inner tunnel IP before running a speed test.".to_string())?;
    if local_ip == peer_ip { return Err("Speed tests need a remote tunnel peer; local loopback tests are not tunnel throughput.".to_string()); }
    Ok((std::net::SocketAddr::new(peer_ip, check.speedtest_port), local_ip, token.to_string()))
}

fn build_tunnel_ping_args(check: &TunnelCheck, target: &str, count: u32) -> Vec<String> {
    let timeout_secs = ((check.timeout_ms + 999) / 1000).max(1);
    let interface = check.interface.as_deref().or(check.source_interface.as_deref());
    let mut args = vec![
        "-n".to_string(),
        "-c".to_string(),
        count.to_string(),
        "-W".to_string(),
        timeout_secs.to_string(),
    ];

    match effective_tunnel_probe_ip_version(target, check.ip_version) {
        IpVersion::Ipv4 => args.push("-4".to_string()),
        IpVersion::Ipv6 => args.push("-6".to_string()),
        IpVersion::Any => {}
    }

    if let Some(interface) = interface {
        args.push("-I".to_string());
        args.push(interface.to_string());
    }
    args.push(target.to_string());
    args
}

fn run_tunnel_ping_live_worker(
    context: &Arc<AppContext>,
    job_id: &str,
    check: &TunnelCheck,
) -> bool {
    let Some(target) = check.inner_probe.as_deref().map(str::trim).filter(|value| !value.is_empty()) else {
        let _ = update_tunnel_diagnostics_job(context, job_id, |job| {
            job.ping.phase = "error".to_string();
            job.ping.error = Some("this tunnel monitor does not have an inner probe target".to_string());
        });
        return false;
    };

    let _ = update_tunnel_diagnostics_job(context, job_id, |job| {
        job.ping.phase = "running".to_string();
        job.ping.raw_output.clear();
        job.ping.error = None;
    });

    let mut latencies = Vec::new();
    let mut raw_chunks = Vec::new();
    let mut failed_samples = 0_u32;

    for sample_index in 0..TUNNEL_DIAGNOSTICS_PING_COUNT {
        let output = Command::new("ping")
            .args(build_tunnel_ping_args(check, target, 1))
            .output();

        let (summary, sample_latency_ms, sample_failed) = match output {
            Ok(output) => {
                let summary = merge_command_output(&output.stdout, &output.stderr);
                let (_, avg_latency_ms, _) = parse_ping_aggregate_latencies(&summary);
                let sample_failed = !output.status.success() || avg_latency_ms.is_none();
                (summary, avg_latency_ms, sample_failed)
            }
            Err(error) => (
                format!("failed to run ping: {error}"),
                None,
                true,
            ),
        };

        if let Some(latency) = sample_latency_ms {
            latencies.push(latency);
        } else if sample_failed {
            failed_samples = failed_samples.saturating_add(1);
        }
        raw_chunks.push(truncate_text(&summary, 220));

        let completed_samples = sample_index + 1;
        let avg_latency_ms = if latencies.is_empty() {
            None
        } else {
            Some(latencies.iter().sum::<f64>() / latencies.len() as f64)
        };
        let min_latency_ms = latencies.iter().copied().reduce(f64::min);
        let max_latency_ms = latencies.iter().copied().reduce(f64::max);
        let packet_loss_percent = if completed_samples == 0 {
            None
        } else {
            Some((failed_samples as f64 / completed_samples as f64) * 100.0)
        };

        let _ = update_tunnel_diagnostics_job(context, job_id, |job| {
            job.ping.avg_latency_ms = avg_latency_ms;
            job.ping.min_latency_ms = min_latency_ms;
            job.ping.max_latency_ms = max_latency_ms;
            job.ping.packet_loss_percent = packet_loss_percent;
            job.ping.completed_samples = completed_samples;
            job.ping.raw_output = truncate_text(&raw_chunks.join("\n\n"), 900);
            job.ping.phase = if completed_samples >= TUNNEL_DIAGNOSTICS_PING_COUNT {
                if latencies.is_empty() { "error" } else { "completed" }
            } else {
                "running"
            }
            .to_string();
            job.ping.error = if latencies.is_empty() && completed_samples >= TUNNEL_DIAGNOSTICS_PING_COUNT {
                Some("all ping samples failed".to_string())
            } else {
                None
            };
            job.elapsed_seconds = job.elapsed_seconds.max(completed_samples as u64);
        });

        if completed_samples < TUNNEL_DIAGNOSTICS_PING_COUNT {
            thread::sleep(Duration::from_secs(1));
        }
    }

    !latencies.is_empty()
}

fn run_tunnel_speed_live_worker(
    context: &Arc<AppContext>, job_id: &str, check: &TunnelCheck,
    bind_ip: Option<&str>, reverse: bool,
) -> bool {
    let _ = update_tunnel_diagnostics_job(context, job_id, |job| {
        let target = if reverse { &mut job.download } else { &mut job.upload };
        target.phase = "running".to_string();
        target.error = None;
        target.raw_output.clear();
    });
    let parameters = tunnel_speedtest_parameters(check, bind_ip);
    let result = parameters.and_then(|(peer, local_ip, token)| {
        crate::speedtest::measure(peer, local_ip, &token,
            if reverse { crate::speedtest::Direction::Download } else { crate::speedtest::Direction::Upload },
            Duration::from_secs(TUNNEL_DIAGNOSTICS_SECONDS), TUNNEL_DIAGNOSTICS_PARALLEL,
            |sample| {
                let _ = update_tunnel_diagnostics_job(context, job_id, |job| {
                    let target = if reverse { &mut job.download } else { &mut job.upload };
                    target.current_mbps = Some(sample.current_mbps);
                    target.avg_mbps = Some(sample.average_mbps);
                    target.peak_mbps = Some(target.peak_mbps.unwrap_or(0.0).max(sample.current_mbps));
                    target.bytes = Some(sample.bytes);
                    target.completed_seconds = (sample.seconds as u64).min(TUNNEL_DIAGNOSTICS_SECONDS);
                    target.raw_output = format!("Native TCP {}: {:.1} Mbps, {} bytes across the tunnel. Upload live samples count sent bytes; final upload counts peer-confirmed bytes.",
                        if reverse { "download" } else { "upload" }, sample.current_mbps, sample.bytes);
                    job.elapsed_seconds = job.upload.completed_seconds + job.download.completed_seconds;
                });
            })
    });
    let success = result.is_ok();
    let _ = update_tunnel_diagnostics_job(context, job_id, |job| {
        let target = if reverse { &mut job.download } else { &mut job.upload };
        match result {
            Ok(measurement) => {
                target.phase = "completed".to_string();
                target.current_mbps = Some(measurement.mbps);
                target.avg_mbps = Some(measurement.mbps);
                target.peak_mbps = Some(target.peak_mbps.unwrap_or(0.0).max(measurement.mbps));
                target.bytes = Some(measurement.bytes);
                target.completed_seconds = TUNNEL_DIAGNOSTICS_SECONDS;
                target.raw_output = format!("Native TCP {}: {:.1} Mbps, {} received bytes over {:.2}s (4 streams). This measures tunnel throughput, not internet speed.",
                    if reverse { "download" } else { "upload" }, measurement.mbps, measurement.bytes, measurement.seconds);
            }
            Err(error) => {
                target.phase = "error".to_string();
                target.error = Some(error.clone());
                target.raw_output = error;
            }
        }
        job.elapsed_seconds = job.upload.completed_seconds + job.download.completed_seconds;
    });
    success
}

fn run_tunnel_ping_average(check: &TunnelCheck) -> AdminTunnelPingSummary {
    let Some(target) = check.inner_probe.as_deref().map(str::trim).filter(|value| !value.is_empty()) else {
        return AdminTunnelPingSummary {
            avg_latency_ms: None,
            min_latency_ms: None,
            max_latency_ms: None,
            packet_loss_percent: None,
            sample_count: TUNNEL_DIAGNOSTICS_PING_COUNT,
            raw_output: String::new(),
            error: Some("this tunnel monitor does not have an inner probe target".to_string()),
        };
    };

    let output = match Command::new("ping")
        .args(build_tunnel_ping_args(check, target, TUNNEL_DIAGNOSTICS_PING_COUNT))
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return AdminTunnelPingSummary {
                avg_latency_ms: None,
                min_latency_ms: None,
                max_latency_ms: None,
                packet_loss_percent: None,
                sample_count: TUNNEL_DIAGNOSTICS_PING_COUNT,
                raw_output: String::new(),
                error: Some(format!("failed to run ping: {error}")),
            }
        }
    };

    let summary = merge_command_output(&output.stdout, &output.stderr);
    let (min_latency_ms, avg_latency_ms, max_latency_ms) = parse_ping_aggregate_latencies(&summary);
    let packet_loss_percent = parse_ping_packet_loss(&summary);
    let error = if output.status.success() {
        None
    } else {
        Some(format!("ping failed: {}", truncate_text(first_non_empty_line(&summary), 220)))
    };

    AdminTunnelPingSummary {
        avg_latency_ms,
        min_latency_ms,
        max_latency_ms,
        packet_loss_percent,
        sample_count: TUNNEL_DIAGNOSTICS_PING_COUNT,
        raw_output: truncate_text(&summary, 900),
        error,
    }
}

fn run_tunnel_speed_transfer(check: &TunnelCheck, bind_ip: Option<&str>, reverse: bool) -> AdminTunnelIperfSummary {
    let result = tunnel_speedtest_parameters(check, bind_ip).and_then(|(peer, local_ip, token)| {
        crate::speedtest::measure(peer, local_ip, &token,
            if reverse { crate::speedtest::Direction::Download } else { crate::speedtest::Direction::Upload },
            Duration::from_secs(TUNNEL_DIAGNOSTICS_SECONDS), TUNNEL_DIAGNOSTICS_PARALLEL, |_| {})
    });
    match result {
        Ok(measurement) => AdminTunnelIperfSummary {
            mbps: Some(measurement.mbps), bytes: Some(measurement.bytes), retransmits: None,
            seconds: Some(measurement.seconds),
            raw_output: format!("Native tunnel {}: {:.1} Mbps, {} received bytes over {:.2}s (4 TCP streams).",
                if reverse { "download" } else { "upload" }, measurement.mbps, measurement.bytes, measurement.seconds),
            error: None,
        },
        Err(error) => AdminTunnelIperfSummary { mbps: None, bytes: None, retransmits: None, seconds: None, raw_output: String::new(), error: Some(error) },
    }
}

fn effective_tunnel_probe_ip_version(target: &str, requested: IpVersion) -> IpVersion {
    match target.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => IpVersion::Ipv4,
        Ok(IpAddr::V6(_)) => IpVersion::Ipv6,
        Err(_) => requested,
    }
}

fn resolve_tunnel_bind_ip(check: &TunnelCheck) -> Option<String> {
    if let Some(value) = check.inner_local_cidr.as_deref() {
        let candidate = value.split('/').next().unwrap_or("").trim();
        if !candidate.is_empty() {
            return Some(candidate.to_string());
        }
    }

    let interface = check.interface.as_deref()?;
    let output = Command::new("ip")
        .args(["-o", "addr", "show", "dev", interface])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let target_family = check
        .inner_probe
        .as_deref()
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
        .map(|value| if value.is_ipv6() { "inet6" } else { "inet" });
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut fallback = None;

    for line in stdout.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 4 {
            continue;
        }
        let family = parts[2];
        let address = parts[3].split('/').next().unwrap_or("").trim();
        if address.is_empty() {
            continue;
        }
        if fallback.is_none() {
            fallback = Some(address.to_string());
        }
        if target_family.map(|candidate| candidate == family).unwrap_or(false) {
            return Some(address.to_string());
        }
    }

    fallback
}

fn parse_ping_aggregate_latencies(text: &str) -> (Option<f64>, Option<f64>, Option<f64>) {
    for line in text.lines() {
        if !(line.contains("min/avg/max") && line.contains('=')) {
            continue;
        }
        let values = line
            .split('=')
            .nth(1)
            .unwrap_or("")
            .trim()
            .split_whitespace()
            .next()
            .unwrap_or("")
            .split('/')
            .collect::<Vec<_>>();
        if values.len() < 3 {
            continue;
        }
        let min_value = values[0].trim().parse::<f64>().ok();
        let avg_value = values[1].trim().parse::<f64>().ok();
        let max_value = values[2].trim().parse::<f64>().ok();
        return (min_value, avg_value, max_value);
    }
    (None, None, None)
}

fn parse_ping_packet_loss(text: &str) -> Option<f64> {
    for line in text.lines() {
        let marker = "packet loss";
        let Some(index) = line.find(marker) else {
            continue;
        };
        let prefix = &line[..index];
        let value = prefix
            .split(',')
            .next_back()
            .unwrap_or("")
            .replace('%', "")
            .trim()
            .to_string();
        if let Ok(parsed) = value.parse::<f64>() {
            return Some(parsed);
        }
    }
    None
}

fn merge_command_output(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout_text = String::from_utf8_lossy(stdout).trim().to_string();
    let stderr_text = String::from_utf8_lossy(stderr).trim().to_string();
    if stdout_text.is_empty() {
        stderr_text
    } else if stderr_text.is_empty() {
        stdout_text
    } else {
        format!("{stdout_text}\n{stderr_text}")
    }
}

fn first_non_empty_line(text: &str) -> &str {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or(text)
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        text.chars().take(max_chars).collect::<String>() + "..."
    }
}

fn parse_query_u64(request: &Request, key: &str) -> Option<u64> {
    request.query_value(key).trim().parse::<u64>().ok()
}

fn canonical_kind_name(kind: &str) -> &str {
    if kind.eq_ignore_ascii_case("v2ray_simulation") {
        "v2ray"
    } else {
        kind
    }
}

fn check_status_name(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Up => "up",
        CheckStatus::Degraded => "degraded",
        CheckStatus::Down => "down",
    }
}

fn render_monitor_analytics_csv(payload: &AdminMonitorAnalyticsPayload) -> Vec<u8> {
    let mut csv = String::from("timestamp_unix,status,latency_ms,duration_ms,message,endpoint\n");
    for point in &payload.points {
        let _ = writeln!(
            csv,
            "{},{},{},{},{},{}",
            point.observed_at_unix,
            check_status_name(point.status),
            point
                .latency_ms
                .map(|value| value.to_string())
                .unwrap_or_default(),
            point.duration_ms,
            csv_escape_field(&point.message),
            csv_escape_field(point.endpoint.as_deref().unwrap_or("")),
        );
    }
    csv.into_bytes()
}

fn csv_escape_field(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

fn render_monitor_analytics_pdf(payload: &AdminMonitorAnalyticsPayload) -> Vec<u8> {
    let mut lines = vec![
        format!("IranMonitor analytics: {}", payload.check_id),
        format!("Label: {}", payload.label),
        format!("Kind: {}", payload.kind),
        format!(
            "Availability: {:.2}% | Up: {} | Degraded: {} | Down: {}",
            payload.summary.availability_percent,
            payload.summary.up_points,
            payload.summary.degraded_points,
            payload.summary.down_points
        ),
        format!(
            "Average latency: {} | Max latency: {}",
            payload
                .summary
                .avg_latency_ms
                .map(|value| format!("{value:.1} ms"))
                .unwrap_or_else(|| "-".to_string()),
            payload
                .summary
                .max_latency_ms
                .map(|value| format!("{value} ms"))
                .unwrap_or_else(|| "-".to_string())
        ),
        String::new(),
        "timestamp_unix | status | latency_ms | duration_ms | endpoint | message".to_string(),
    ];

    for point in &payload.points {
        lines.push(format!(
            "{} | {} | {} | {} | {} | {}",
            point.observed_at_unix,
            check_status_name(point.status),
            point
                .latency_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            point.duration_ms,
            point.endpoint.as_deref().unwrap_or("-"),
            point.message
        ));
    }

    build_simple_pdf_document(&lines)
}

fn build_simple_pdf_document(lines: &[String]) -> Vec<u8> {
    let lines_per_page = 44_usize;
    let pages = lines
        .chunks(lines_per_page)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();

    let mut objects = Vec::<Vec<u8>>::new();
    objects.push(Vec::new());
    objects.push(Vec::new());
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_vec());

    let mut page_ids = Vec::new();
    for (index, page_lines) in pages.iter().enumerate() {
        let page_id = 4 + (index as i32 * 2);
        let content_id = page_id + 1;
        page_ids.push(page_id);

        let mut stream = String::from("BT\n/F1 10 Tf\n50 770 Td\n14 TL\n");
        for line in page_lines {
            let sanitized = pdf_escape_text(line);
            let _ = writeln!(stream, "({sanitized}) Tj");
            stream.push_str("T*\n");
        }
        stream.push_str("ET\n");

        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
            )
            .into_bytes(),
        );
        objects.push(
            format!(
                "<< /Length {} >>\nstream\n{}endstream",
                stream.len(),
                stream
            )
            .into_bytes(),
        );
    }

    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>".to_vec();
    objects[1] = format!(
        "<< /Type /Pages /Kids [{}] /Count {} >>",
        page_ids
            .iter()
            .map(|id| format!("{id} 0 R"))
            .collect::<Vec<_>>()
            .join(" "),
        page_ids.len()
    )
    .into_bytes();

    let mut pdf = b"%PDF-1.4\n".to_vec();
    let mut offsets = vec![0_usize];
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        pdf.extend_from_slice(object);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    let xref_offset = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF",
            objects.len() + 1,
            xref_offset
        )
        .as_bytes(),
    );
    pdf
}

fn pdf_escape_text(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii() { ch } else { '?' })
        .collect::<String>()
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

fn render_monitor_analytics_xlsx(
    payload: &AdminMonitorAnalyticsPayload,
) -> Result<Vec<u8>, String> {
    let temp_root = PathBuf::from(format!(
        "/tmp/iranmonitor-xlsx-{}",
        random_hex(6)?
    ));
    let package_dir = temp_root.join("package");
    fs::create_dir_all(package_dir.join("_rels"))
        .map_err(|error| format!("failed to create xlsx rels directory: {error}"))?;
    fs::create_dir_all(package_dir.join("xl/_rels"))
        .map_err(|error| format!("failed to create xlsx workbook rels directory: {error}"))?;
    fs::create_dir_all(package_dir.join("xl/worksheets"))
        .map_err(|error| format!("failed to create xlsx sheet directory: {error}"))?;

    let mut sheet_rows = String::new();
    let mut row_index = 1_u32;
    push_xlsx_inline_row(
        &mut sheet_rows,
        row_index,
        &[
            "Check ID".to_string(),
            payload.check_id.clone(),
            "Label".to_string(),
            payload.label.clone(),
        ],
    );
    row_index += 1;
    push_xlsx_inline_row(
        &mut sheet_rows,
        row_index,
        &[
            "Kind".to_string(),
            payload.kind.clone(),
            "Availability %".to_string(),
            format!("{:.2}", payload.summary.availability_percent),
        ],
    );
    row_index += 1;
    push_xlsx_inline_row(
        &mut sheet_rows,
        row_index,
        &[
            "Avg latency ms".to_string(),
            payload
                .summary
                .avg_latency_ms
                .map(|value| format!("{value:.1}"))
                .unwrap_or_default(),
            "Max latency ms".to_string(),
            payload
                .summary
                .max_latency_ms
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ],
    );
    row_index += 2;
    push_xlsx_inline_row(
        &mut sheet_rows,
        row_index,
        &[
            "timestamp_unix".to_string(),
            "status".to_string(),
            "latency_ms".to_string(),
            "duration_ms".to_string(),
            "endpoint".to_string(),
            "message".to_string(),
        ],
    );
    row_index += 1;
    for point in &payload.points {
        push_xlsx_inline_row(
            &mut sheet_rows,
            row_index,
            &[
                point.observed_at_unix.to_string(),
                check_status_name(point.status).to_string(),
                point
                    .latency_ms
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                point.duration_ms.to_string(),
                point.endpoint.clone().unwrap_or_default(),
                point.message.clone(),
            ],
        );
        row_index += 1;
    }

    fs::write(
        package_dir.join("[Content_Types].xml"),
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"#,
    )
    .map_err(|error| format!("failed to write xlsx content types: {error}"))?;
    fs::write(
        package_dir.join("_rels/.rels"),
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#,
    )
    .map_err(|error| format!("failed to write xlsx root rels: {error}"))?;
    fs::write(
        package_dir.join("xl/workbook.xml"),
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Analytics" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>"#,
    )
    .map_err(|error| format!("failed to write xlsx workbook: {error}"))?;
    fs::write(
        package_dir.join("xl/_rels/workbook.xml.rels"),
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"#,
    )
    .map_err(|error| format!("failed to write xlsx workbook rels: {error}"))?;
    fs::write(
        package_dir.join("xl/styles.xml"),
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>
  <fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"#,
    )
    .map_err(|error| format!("failed to write xlsx styles: {error}"))?;
    fs::write(
        package_dir.join("xl/worksheets/sheet1.xml"),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    {sheet_rows}
  </sheetData>
</worksheet>"#
        ),
    )
    .map_err(|error| format!("failed to write xlsx sheet: {error}"))?;

    let output_file = temp_root.join("analytics.xlsx");
    let output = Command::new("zip")
        .arg("-qr")
        .arg(&output_file)
        .arg(".")
        .current_dir(&package_dir)
        .output()
        .map_err(|error| format!("failed to run zip for xlsx export: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let bytes = fs::read(&output_file)
        .map_err(|error| format!("failed to read generated xlsx export: {error}"))?;
    let _ = fs::remove_dir_all(&temp_root);
    Ok(bytes)
}

fn push_xlsx_inline_row(rows: &mut String, row_index: u32, values: &[String]) {
    let _ = write!(rows, r#"<row r="{row_index}">"#);
    for (column_index, value) in values.iter().enumerate() {
        let reference = format!("{}{}", xlsx_column_name(column_index), row_index);
        let escaped = xml_escape(value);
        let _ = write!(
            rows,
            r#"<c r="{reference}" t="inlineStr"><is><t>{escaped}</t></is></c>"#
        );
    }
    rows.push_str("</row>");
}

fn xlsx_column_name(index: usize) -> String {
    let mut value = index + 1;
    let mut label = String::new();
    while value > 0 {
        let remainder = (value - 1) % 26;
        label.insert(0, (b'A' + remainder as u8) as char);
        value = (value - 1) / 26;
    }
    label
}

fn xml_escape(value: &str) -> String {
    html_escape(value)
}

fn sync_network_runtime_state(context: &Arc<AppContext>) -> Result<(), String> {
    let mut errors = Vec::new();
    let traffic = context.db.list_traffic_watchers().and_then(|watchers|sync_traffic_watchers(&watchers));
    if let Err(error) = traffic { errors.push(format!("traffic watchers: {error}")); }
    if let Err(error) = sync_speed_limits_from_db(context) {errors.push(format!("speed limits: {error}"));}
    let connection = context.db.load_tcp_conn_limit().and_then(|mut policy| {
        match apply_tcp_conn_limit(&policy) {
            Ok(message) => {policy.last_status=message; context.db.save_tcp_conn_limit(&policy)},
            Err(error) => {policy.last_status=format!("failed to apply: {error}"); context.db.save_tcp_conn_limit(&policy)?; Err(error)},
        }
    });
    if let Err(error) = connection {errors.push(format!("connection limits: {error}"));}
    if let Err(error) = sync_source_ip_rules_from_db(context) {errors.push(format!("source IP: {error}"));}
    if errors.is_empty() {Ok(())} else {Err(errors.join(" | "))}
}

fn handle_settings_update(
    context: &Arc<AppContext>,
    mut settings: AppSettings,
    request: Request,
) -> Response {
    update_string_field(&request, "public_title", &mut settings.public_title);
    update_string_field(&request, "public_subtitle", &mut settings.public_subtitle);
    update_string_field(&request, "primary_color", &mut settings.primary_color);
    update_string_field(&request, "secondary_color", &mut settings.secondary_color);
    update_string_field(&request, "background_color", &mut settings.background_color);
    update_string_field(&request, "logo_url", &mut settings.logo_url);
    update_string_field(&request, "favicon_url", &mut settings.favicon_url);
    update_string_field(&request, "contact_email", &mut settings.contact_email);
    update_string_field(&request, "contact_telegram", &mut settings.contact_telegram);
    update_string_field(&request, "contact_phone", &mut settings.contact_phone);
    update_string_field(&request, "telegram_bot_token", &mut settings.telegram_bot_token);
    update_string_field(
        &request,
        "telegram_admin_chat_id",
        &mut settings.telegram_admin_chat_id,
    );
    update_string_field(
        &request,
        "telegram_socks5_host",
        &mut settings.telegram_socks5_host,
    );
    update_string_field(
        &request,
        "telegram_socks5_username",
        &mut settings.telegram_socks5_username,
    );
    update_string_field(
        &request,
        "telegram_socks5_password",
        &mut settings.telegram_socks5_password,
    );
    update_string_field(&request, "bind_addr", &mut settings.bind_addr);
    update_string_field(&request, "public_base_url", &mut settings.public_base_url);
    update_string_field(&request, "admin_base_url", &mut settings.admin_base_url);
    update_string_field(&request, "ssl_mode", &mut settings.ssl_mode);
    update_string_field(
        &request,
        "reverse_proxy_server_name",
        &mut settings.reverse_proxy_server_name,
    );
    update_string_field(&request, "ssl_cert_path", &mut settings.ssl_cert_path);
    update_string_field(&request, "ssl_key_path", &mut settings.ssl_key_path);
    update_string_field(&request, "notes", &mut settings.notes);
    apply_theme_preset_selection(&request, &mut settings);
    settings.default_language = UiLanguage::from_str(request.form_value("default_language"));
    settings.dark_mode_default = parse_form_bool(&request, "dark_mode_default", settings.dark_mode_default);
    settings.telegram_failure_threshold = request
        .form_value("telegram_failure_threshold")
        .parse::<u32>()
        .ok()
        .filter(|value| *value >= 1)
        .unwrap_or(settings.telegram_failure_threshold)
        .max(1);
    settings.telegram_socks5_port = request
        .form_value("telegram_socks5_port")
        .parse::<u16>()
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(settings.telegram_socks5_port);
    if let Err(error) = apply_uploaded_branding_assets(context, &request, &mut settings) {
        return redirect_with_flash(&request, AdminSection::Settings.path(), &error);
    }
    match context.db.save_settings(&settings) {
        Ok(_) => redirect_with_flash(&request, AdminSection::Settings.path(), "settings_saved"),
        Err(error) => redirect_with_flash(
            &request,
            AdminSection::Settings.path(),
            &error,
        ),
    }
}

fn handle_access_update(
    context: &Arc<AppContext>,
    mut settings: AppSettings,
    request: Request,
) -> Response {
    let lang = request_language(&request, settings.default_language);
    let admin_user = match context.db.first_admin_user() {
        Ok(Some(user)) => user,
        Ok(None) => {
            return redirect_with_flash(
                &request,
                AdminSection::Settings.path(),
                "no admin user exists yet",
            );
        }
        Err(error) => {
            return redirect_with_flash(&request, AdminSection::Settings.path(), &error);
        }
    };

    let next_username = request.form_value("admin_username").trim();
    if next_username.is_empty() {
        return redirect_with_flash(
            &request,
            AdminSection::Settings.path(),
            "username cannot be empty",
        );
    }

    let new_password = request.form_value("new_password");
    let confirm_password = request.form_value("confirm_password");
    if !new_password.is_empty() && new_password != confirm_password {
        return redirect_with_flash(
            &request,
            AdminSection::Settings.path(),
            "new password and confirmation do not match",
        );
    }

    let password_hash = if new_password.is_empty() {
        admin_user.password_hash.clone()
    } else {
        match create_password_hash(new_password) {
            Ok(hash) => hash,
            Err(error) => {
                return redirect_with_flash(&request, AdminSection::Settings.path(), &error);
            }
        }
    };

    let current_port = extract_port(&settings.bind_addr);
    let next_port = request
        .form_value("listen_port")
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(current_port);
    let bind_host = extract_bind_host(&settings.bind_addr);
    settings.bind_addr = format!("{bind_host}:{next_port}");
    settings.public_base_url = replace_url_port_if_possible(&settings.public_base_url, next_port);
    settings.admin_base_url = replace_url_port_if_possible(&settings.admin_base_url, next_port);

    if let Err(error) = context.db.save_settings(&settings) {
        return redirect_with_flash(&request, AdminSection::Settings.path(), &error);
    }
    if let Err(error) = context
        .db
        .update_admin_user(admin_user.id, next_username, &password_hash)
    {
        return redirect_with_flash(&request, AdminSection::Settings.path(), &error);
    }

    if next_port != current_port {
        let restart_result = schedule_panel_service_restart();
        let mut next_admin_url = append_query_param(&settings.admin_base_url, "lang", lang.as_str());
        next_admin_url = append_query_param(&next_admin_url, "flash", "access_saved");
        return Response::html(
            200,
            views::render_access_restart_pending(
                &branding_from_settings(&settings),
                lang,
                &next_admin_url,
                restart_result.as_ref().err().map(String::as_str),
            ),
        );
    }

    redirect_with_flash(&request, AdminSection::Settings.path(), "access_saved")
}

fn handle_socket_control(_context: &Arc<AppContext>, request: Request) -> Response {
    let action = request.form_value("action").trim();
    if action.is_empty() {
        return redirect_with_flash(
            &request,
            AdminSection::Sockets.path(),
            "socket action is required",
        );
    }

    let service_unit = request.form_value("service_unit").trim();
    let pid = request.form_value("pid").trim();
    let is_protected = parse_form_bool(&request, "is_protected", false);

    match control_socket_app(
        action,
        if service_unit.is_empty() {
            None
        } else {
            Some(service_unit)
        },
        if pid.is_empty() { None } else { Some(pid) },
        is_protected,
    ) {
        Ok(message) => redirect_with_flash(&request, AdminSection::Sockets.path(), &message),
        Err(error) => redirect_with_flash(&request, AdminSection::Sockets.path(), &error),
    }
}

fn handle_admin_self_update(request: Request) -> Response {
    thread::spawn(|| {
        thread::sleep(Duration::from_millis(350));
        let _ = perform_self_update();
    });
    redirect_with_flash(&request, AdminSection::Settings.path(), "update_started")
}

fn handle_check_save(context: &Arc<AppContext>, _settings: AppSettings, request: Request) -> Response {
    let return_section = if request.form_value("kind").trim() == "tunnel" || request.form_value("return_section") == "tunnels" { AdminSection::Tunnels } else { AdminSection::Monitors };
    let label = request.form_value("label").trim();
    if label.is_empty() {
        return redirect_with_flash(&request, return_section.path(), "missing_check_fields");
    }

    let check_json_input = request.form_value("check_json").trim();
    let definition = if check_json_input.is_empty() {
        match build_check_definition_from_form(&request) {
            Ok(definition) => definition,
            Err(error) => {
                return redirect_with_flash(&request, return_section.path(), &error)
            }
        }
    } else {
        match serde_json::from_str::<CheckDefinition>(check_json_input) {
            Ok(definition) => definition,
            Err(error) => {
                return redirect_with_flash(
                    &request,
                    return_section.path(),
                    &format!("invalid check json: {error}"),
                )
            }
        }
    };
    let return_section = if matches!(definition, CheckDefinition::Tunnel(_)) { AdminSection::Tunnels } else { AdminSection::Monitors };
    let check_id = definition.id().to_string();
    let kind = definition.kind_name().to_string();
    let check_json = match serde_json::to_string_pretty(&definition) {
        Ok(json_text) => json_text,
        Err(error) => {
            return redirect_with_flash(
                &request,
                return_section.path(),
                &format!("failed to serialize monitor: {error}"),
            )
        }
    };

    let original_check_id = request.form_value("original_check_id").trim();
    let replaced_check_row = if !original_check_id.is_empty() {
        let lookup_id = if original_check_id == check_id {
            check_id.as_str()
        } else {
            original_check_id
        };
        context.db.get_check(lookup_id).ok().flatten()
    } else {
        context.db.get_check(&check_id).ok().flatten()
    };
    let (display_group, group_logo_url, group_logo_shape, created_at_unix) =
        if let Some(existing_row) = replaced_check_row.as_ref() {
            (
                existing_row.display_group.clone(),
                existing_row.group_logo_url.clone(),
                existing_row.group_logo_shape.clone(),
                existing_row.created_at_unix,
            )
        } else {
            (String::new(), String::new(), "rounded".to_string(), db::unix_now())
        };
    let row = MonitorCheckRow {
        db_id: 0,
        check_id: check_id.clone(),
        label: label.to_string(),
        kind,
        enabled: parse_form_bool(&request, "enabled", true),
        public_visible: parse_form_bool(&request, "public_visible", true),
        display_group,
        group_logo_url,
        group_logo_shape,
        check_json,
        created_at_unix,
        updated_at_unix: db::unix_now(),
    };
    if let Some(existing_row) = replaced_check_row.as_ref() {
        match load_stored_check_definition(existing_row) {
            Ok(existing_definition) => {
                if let Err(error) = validate_legacy_esp_resource_edit(&existing_definition, &definition, row.enabled) {
                    return redirect_with_flash(&request, return_section.path(), &error);
                }
                if should_cleanup_previous_resources(&existing_definition, &definition) {
                    if let Err(error) = cleanup_check_resources(context, &existing_definition) {
                        return redirect_with_flash(&request, return_section.path(), &error);
                    }
                }
            }
            Err(error) => {
                return redirect_with_flash(&request, return_section.path(), &error);
            }
        }
    }
    let retire_runtime = !row.enabled || original_check_id != "" && original_check_id != check_id
        || replaced_check_row.as_ref().and_then(|row| load_stored_check_definition(row).ok())
            .is_some_and(|previous| should_cleanup_previous_resources(&previous, &definition));
    match context.db.upsert_check(&row) {
        Ok(_) => {
            invalidate_check_runtime(context, &check_id, retire_runtime);
            if !original_check_id.is_empty() && original_check_id != check_id {
                invalidate_check_runtime(context, original_check_id, true);
                let _ = context.db.delete_check(original_check_id);
            }
            if let Err(error) = ensure_local_speedtest_servers(context) {
                eprintln!("native speed-test helper warning: {error}");
            }
            redirect_with_flash(&request, return_section.path(), "check_saved")
        }
        Err(error) => redirect_with_flash(&request, return_section.path(), &error),
    }
}

fn handle_check_delete(context: &Arc<AppContext>, request: Request) -> Response {
    let mut return_section = if request.form_value("return_section") == "tunnels" { AdminSection::Tunnels } else { AdminSection::Monitors };
    let check_id = request.form_value("check_id").trim().to_string();
    let existing = match context.db.get_check(&check_id) {
        Ok(row) => row,
        Err(error) => {
            return redirect_with_flash(&request, return_section.path(), &error);
        }
    };
    let cleanup_definition = existing
        .as_ref()
        .and_then(|row| load_stored_check_definition(row).ok());
    if matches!(cleanup_definition, Some(CheckDefinition::Tunnel(_))) {
        return_section = AdminSection::Tunnels;
    }
    match context.db.delete_check(&check_id) {
        Ok(_) => {
            invalidate_check_runtime(context, &check_id, true);
            if let Err(error) = ensure_local_speedtest_servers(context) {
                eprintln!("native speed-test helper warning: {error}");
            }
            if let Some(definition) = cleanup_definition.as_ref() {
                if let Err(error) = cleanup_check_resources(context, definition) {
                    return redirect_with_flash(&request, return_section.path(), &error);
                }
            }
            redirect_with_flash(&request, return_section.path(), "check_deleted")
        }
        Err(error) => redirect_with_flash(&request, return_section.path(), &error),
    }
}

// Editing, disabling or deleting a check must retire old helpers immediately
// and bypass interval caches when the next monitoring cycle begins.
fn invalidate_check_runtime(context: &Arc<AppContext>, check_id: &str, retire_runtime: bool) {
    if let Ok(mut runtime) = context.runtime.lock() {
        runtime.monitor_state.last_check_run_unix.remove(check_id);
        runtime.monitor_state.last_results.remove(check_id);
        if retire_runtime { runner::retire_tunnel_runtime(check_id); }
    }
}

fn handle_folder_save(context: &Arc<AppContext>, request: Request) -> Response {
    let folder_name = request.form_value("folder_name").trim();
    if folder_name.is_empty() {
        return redirect_with_flash(&request, AdminSection::Folders.path(), "missing_folder_name");
    }

    let original_folder_name = request.form_value("original_folder_name").trim().to_string();
    let now = db::unix_now();
    let existing_folders = match context.db.list_monitor_folders() {
        Ok(folders) => folders,
        Err(error) => return redirect_with_flash(&request, AdminSection::Folders.path(), &error),
    };

    let created_at_unix = existing_folders
        .iter()
        .find(|folder| folder.name.trim() == original_folder_name.trim() || folder.name.trim() == folder_name)
        .map(|folder| folder.created_at_unix)
        .unwrap_or(now);

    let folder = MonitorFolder {
        name: folder_name.to_string(),
        logo_url: request.form_value("folder_logo_url").trim().to_string(),
        logo_shape: normalize_group_logo_shape(request.form_value("folder_logo_shape")),
        created_at_unix,
        updated_at_unix: now,
    };

    if let Err(error) = context.db.save_monitor_folder(&folder) {
        return redirect_with_flash(&request, AdminSection::Folders.path(), &error);
    }

    let rows = match context.db.list_checks() {
        Ok(rows) => rows,
        Err(error) => return redirect_with_flash(&request, AdminSection::Folders.path(), &error),
    };
    for mut row in rows {
        let current_group = row.display_group.trim();
        if current_group.is_empty() {
            continue;
        }
        if current_group == folder_name
            || (!original_folder_name.is_empty() && current_group == original_folder_name)
        {
            row.display_group = folder.name.clone();
            row.group_logo_url = folder.logo_url.clone();
            row.group_logo_shape = folder.logo_shape.clone();
            row.updated_at_unix = now;
            if let Err(error) = context.db.upsert_check(&row) {
                return redirect_with_flash(&request, AdminSection::Folders.path(), &error);
            }
        }
    }

    if !original_folder_name.is_empty() && original_folder_name != folder.name {
        if let Err(error) = context.db.delete_monitor_folder(&original_folder_name) {
            return redirect_with_flash(&request, AdminSection::Folders.path(), &error);
        }
    }

    redirect_with_flash(&request, AdminSection::Folders.path(), "folder_saved")
}

fn handle_folder_delete(context: &Arc<AppContext>, request: Request) -> Response {
    let folder_name = request.form_value("folder_name").trim().to_string();
    if folder_name.is_empty() {
        return redirect_with_flash(&request, AdminSection::Folders.path(), "missing_folder_name");
    }

    let now = db::unix_now();
    let rows = match context.db.list_checks() {
        Ok(rows) => rows,
        Err(error) => return redirect_with_flash(&request, AdminSection::Folders.path(), &error),
    };
    for mut row in rows {
        if row.display_group.trim() != folder_name {
            continue;
        }
        row.display_group.clear();
        row.group_logo_url.clear();
        row.group_logo_shape = "rounded".to_string();
        row.updated_at_unix = now;
        if let Err(error) = context.db.upsert_check(&row) {
            return redirect_with_flash(&request, AdminSection::Folders.path(), &error);
        }
    }

    match context.db.delete_monitor_folder(&folder_name) {
        Ok(_) => redirect_with_flash(&request, AdminSection::Folders.path(), "folder_deleted"),
        Err(error) => redirect_with_flash(&request, AdminSection::Folders.path(), &error),
    }
}

fn handle_folder_assignments(context: &Arc<AppContext>, request: Request) -> Response {
    let now = db::unix_now();
    let folders = match context.db.list_monitor_folders() {
        Ok(folders) => folders,
        Err(error) => return redirect_with_flash(&request, AdminSection::Folders.path(), &error),
    };
    let folder_map = folders
        .into_iter()
        .map(|folder| (folder.name.clone(), folder))
        .collect::<BTreeMap<_, _>>();

    let rows = match context.db.list_checks() {
        Ok(rows) => rows,
        Err(error) => return redirect_with_flash(&request, AdminSection::Folders.path(), &error),
    };

    for mut row in rows {
        let form_key = format!("folder_for_{}", row.check_id);
        let selected = request.form_value(&form_key).trim().to_string();
        if selected.is_empty() {
            row.display_group.clear();
            row.group_logo_url.clear();
            row.group_logo_shape = "rounded".to_string();
        } else {
            row.display_group = selected.clone();
            if let Some(folder) = folder_map.get(&selected) {
                row.group_logo_url = folder.logo_url.clone();
                row.group_logo_shape = folder.logo_shape.clone();
            }
        }
        row.updated_at_unix = now;
        if let Err(error) = context.db.upsert_check(&row) {
            return redirect_with_flash(&request, AdminSection::Folders.path(), &error);
        }
    }

    redirect_with_flash(&request, AdminSection::Folders.path(), "folder_assignments_saved")
}

fn parse_telegram_admin_chat_ids(settings: &AppSettings) -> Vec<String> {
    settings
        .telegram_admin_chat_id
        .split(|character: char| matches!(character, ',' | '\n' | '\r' | ';' | '\t' | ' '))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(|value| value.parse::<i64>().ok())
        .map(|value| value.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn handle_notification_test(context: &Arc<AppContext>, request: Request) -> Response {
    let settings = match context.db.load_settings() {
        Ok(settings) => settings,
        Err(error) => {
            return redirect_with_flash(&request, AdminSection::Notifications.path(), &error);
        }
    };

    if settings.telegram_bot_token.trim().is_empty() {
        return redirect_with_flash(
            &request,
            AdminSection::Notifications.path(),
            "telegram bot token is not configured",
        );
    }
    let admin_chat_ids = parse_telegram_admin_chat_ids(&settings);
    if admin_chat_ids.is_empty() {
        return redirect_with_flash(
            &request,
            AdminSection::Notifications.path(),
            "telegram admin numeric ids are not configured",
        );
    }

    let rows = match context.db.list_checks() {
        Ok(rows) => rows,
        Err(error) => {
            return redirect_with_flash(&request, AdminSection::Notifications.path(), &error);
        }
    };
    let label_map = rows
        .iter()
        .map(|row| (row.check_id.clone(), row.label.clone()))
        .collect::<BTreeMap<_, _>>();
    let latest_snapshot = match context.db.latest_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return redirect_with_flash(&request, AdminSection::Notifications.path(), &error);
        }
    };
    let (summary, results) = if let Some(snapshot) = latest_snapshot {
        let results = serde_json::from_str::<Vec<CheckResult>>(&snapshot.results_json)
            .unwrap_or_default();
        let summary = serde_json::from_str::<SnapshotSummary>(&snapshot.summary_json)
            .unwrap_or_else(|_| summarize_results(snapshot.created_at_unix, &results));
        (summary, results)
    } else {
        (
            SnapshotSummary {
                observed_at_unix: db::unix_now(),
                total_checks: 0,
                up_checks: 0,
                degraded_checks: 0,
                down_checks: 0,
            },
            Vec::new(),
        )
    };

    let text = format!(
        "IranMonitor test message\n\n{}",
        build_telegram_overall_status_text(&settings, &summary, &results, &label_map)
    );

    let mut delivered = 0_u32;
    let mut last_error = None;
    for chat_id in &admin_chat_ids {
        match send_telegram_message_to_chat(&settings, chat_id, &text) {
            Ok(_) => delivered = delivered.saturating_add(1),
            Err(error) => last_error = Some(error),
        }
    }

    if delivered > 0 {
        redirect_with_flash(
            &request,
            AdminSection::Notifications.path(),
            "telegram_test_sent",
        )
    } else {
        redirect_with_flash(
            &request,
            AdminSection::Notifications.path(),
            last_error.as_deref().unwrap_or("telegram test message could not be delivered"),
        )
    }
}

fn handle_notification_bot_test(context: &Arc<AppContext>, request: Request) -> Response {
    let settings = match context.db.load_settings() {
        Ok(settings) => settings,
        Err(error) => {
            return redirect_with_flash(&request, AdminSection::Notifications.path(), &error);
        }
    };
    if settings.telegram_bot_token.trim().is_empty() {
        return redirect_with_flash(
            &request,
            AdminSection::Notifications.path(),
            "telegram bot token is not configured",
        );
    }

    match telegram_api_request(&settings, "getMe", &json!({})) {
        Ok(_) => redirect_with_flash(
            &request,
            AdminSection::Notifications.path(),
            "telegram bot test succeeded",
        ),
        Err(error) => redirect_with_flash(
            &request,
            AdminSection::Notifications.path(),
            &format!("telegram bot test failed: {error}"),
        ),
    }
}

fn handle_notification_socks_test(context: &Arc<AppContext>, request: Request) -> Response {
    let settings = match context.db.load_settings() {
        Ok(settings) => settings,
        Err(error) => {
            return redirect_with_flash(&request, AdminSection::Notifications.path(), &error);
        }
    };
    if settings.telegram_bot_token.trim().is_empty() {
        return redirect_with_flash(
            &request,
            AdminSection::Notifications.path(),
            "telegram bot token is not configured",
        );
    }
    if settings.telegram_socks5_host.trim().is_empty() {
        return redirect_with_flash(
            &request,
            AdminSection::Notifications.path(),
            "telegram socks5 host is not configured",
        );
    }

    match telegram_api_request_force_socks(&settings, "getMe", &json!({})) {
        Ok(_) => redirect_with_flash(
            &request,
            AdminSection::Notifications.path(),
            "telegram socks5 proxy test succeeded",
        ),
        Err(error) => redirect_with_flash(
            &request,
            AdminSection::Notifications.path(),
            &format!("telegram socks5 proxy test failed: {error}"),
        ),
    }
}

fn load_stored_check_definition(row: &MonitorCheckRow) -> Result<CheckDefinition, String> {
    serde_json::from_str::<CheckDefinition>(&row.check_json)
        .map_err(|error| format!("failed to parse stored monitor {}: {error}", row.check_id))
}

fn normalize_group_logo_shape(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "circle" => "circle".to_string(),
        "rect" | "rectangle" | "rectangular" => "rect".to_string(),
        _ => "rounded".to_string(),
    }
}

fn cleanup_check_resources(context: &Arc<AppContext>, definition: &CheckDefinition) -> Result<(), String> {
    match definition {
        CheckDefinition::Tunnel(check) => cleanup_tunnel_resources(context, check),
        _ => Ok(()),
    }
}

fn cleanup_tunnel_resources(context: &Arc<AppContext>, check: &TunnelCheck) -> Result<(), String> {
    // Monitor-only checks never own the system interfaces, policies, or ports.
    if check.auto_create_interface {
        if let Some(interface) = check.interface.as_deref() {
            if !managed_interface_is_shared(context, check)? {
                if !managed_protocol_resources_are_shared(context, check)? {
                    cleanup_protocol_specific_tunnel_state(check)?;
                }
                match run_command_status("ip", &["link", "delete", "dev", interface]) {
                    Ok(()) => {}
                    Err(error)
                        if error.contains("Cannot find device")
                            || error.contains("does not exist") => {}
                    Err(error) => {
                        return Err(format!(
                            "failed to remove tunnel interface {interface}: {error}"
                        ))
                    }
                }
            }
        }
    }
    clear_tunnel_counter_state(context, &check.id)?;
    Ok(())
}

fn managed_protocol_resources_are_shared(context: &Arc<AppContext>, check: &TunnelCheck) -> Result<bool, String> {
    for row in context.db.list_checks()? {
        if row.check_id == check.id { continue; }
        let Ok(CheckDefinition::Tunnel(other)) = load_stored_check_definition(&row) else { continue; };
        if !other.auto_create_interface || other.interface.is_none() || other.protocol != check.protocol { continue; }
        let shared = match check.protocol {
            TunnelProtocol::Encap => other.transport_port.unwrap_or(5555) == check.transport_port.unwrap_or(5555),
            TunnelProtocol::L2tp => other.l2tp_tunnel_id.unwrap_or(1) == check.l2tp_tunnel_id.unwrap_or(1),
            TunnelProtocol::Esp => resolve_cleanup_xfrm_if_id(&other) == resolve_cleanup_xfrm_if_id(check),
            _ => false,
        };
        if shared { return Ok(true); }
    }
    Ok(false)
}

fn cleanup_protocol_specific_tunnel_state(check: &TunnelCheck) -> Result<(), String> {
    cleanup_esp_objects(check)?;
    cleanup_l2tp_objects(check)?;
    cleanup_encap_receive_port(check)?;
    Ok(())
}

fn managed_interface_is_shared(context: &Arc<AppContext>, check: &TunnelCheck) -> Result<bool, String> {
    let interface = match check.interface.as_deref() {
        Some(interface) if !interface.trim().is_empty() => interface.trim(),
        _ => return Ok(false),
    };
    let rows = context.db.list_checks()?;
    for row in rows {
        if row.check_id == check.id {
            continue;
        }
        let definition = match load_stored_check_definition(&row) {
            Ok(definition) => definition,
            Err(_) => continue,
        };
        let other = match definition {
            CheckDefinition::Tunnel(other) => other,
            _ => continue,
        };
        if other.auto_create_interface
            && other
                .interface
                .as_deref()
                .map(|candidate| candidate.trim() == interface)
                .unwrap_or(false)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn should_cleanup_previous_resources(previous: &CheckDefinition, next: &CheckDefinition) -> bool {
    match (previous, next) {
        (CheckDefinition::Tunnel(previous), CheckDefinition::Tunnel(next)) => {
            managed_tunnel_resource_signature(previous)
                != managed_tunnel_resource_signature(next)
        }
        (CheckDefinition::Tunnel(_), _) => true,
        _ => false,
    }
}

fn validate_legacy_esp_resource_edit(previous: &CheckDefinition, next: &CheckDefinition, next_enabled: bool) -> Result<(), String> {
    let (CheckDefinition::Tunnel(previous_tunnel), CheckDefinition::Tunnel(next_tunnel)) = (previous, next) else { return Ok(()); };
    let remains_managed_gcm = next_enabled && previous_tunnel.auto_create_interface && next_tunnel.auto_create_interface
        && previous_tunnel.protocol == TunnelProtocol::Esp && next_tunnel.protocol == TunnelProtocol::Esp
        && previous_tunnel.esp_cipher == crate::config::EspCipher::LegacyAesGcm
        && next_tunnel.esp_cipher == crate::config::EspCipher::LegacyAesGcm;
    if remains_managed_gcm && (previous_tunnel.id != next_tunnel.id || should_cleanup_previous_resources(previous, next)) {
        return Err("This edit would retire a legacy static AES-GCM ESP session that cannot safely be recreated. Keep its ID, forwarding endpoints, interface, and keys unchanged, or explicitly migrate both peers to AES-CBC/HMAC-SHA256 + HKDF with a new random secret, or WireGuard. MTU and monitoring edits remain allowed.".to_string());
    }
    Ok(())
}

fn managed_tunnel_resource_signature(check: &TunnelCheck) -> Value {
    json!({
        "protocol": check.protocol.as_str(),
        "interface": check.interface,
        "auto_create_interface": check.auto_create_interface,
        "outer_remote": check.outer_remote,
        "local_outer": check.local_outer,
        "source_interface": check.source_interface,
        "inner_local_cidr": check.inner_local_cidr,
        "inner_probe": check.inner_probe,
        // ESP MTU updates are applied to the live interface and do not require
        // deleting its SAs or resetting replay state. Other helpers may restart
        // to apply their framing ceiling, so retain their existing cleanup rule.
        "mtu": if check.protocol == TunnelProtocol::Esp { None } else { check.mtu },
        "ttl": check.ttl,
        "traffic_class": check.traffic_class,
        "vni": check.vni,
        "tun_lanes": check.tun_lanes,
        "ip_version": check.ip_version,
        "tunnel_key": check.tunnel_key,
        "esp_key_derivation": check.esp_key_derivation,
        "esp_cipher": check.esp_cipher,
        "tun_transport": check.tun_transport,
        "transport_port": check.transport_port,
        "listen_port": check.listen_port,
        "l2tp_tunnel_id": check.l2tp_tunnel_id,
        "l2tp_peer_tunnel_id": check.l2tp_peer_tunnel_id,
        "l2tp_session_id": check.l2tp_session_id,
        "l2tp_peer_session_id": check.l2tp_peer_session_id,
        "l2tp_encapsulation": check.l2tp_encapsulation,
        "wireguard_private_key": check.wireguard_private_key,
        "wireguard_peer_public_key": check.wireguard_peer_public_key,
        "wireguard_preshared_key": check.wireguard_preshared_key,
        "wireguard_allowed_ips": check.wireguard_allowed_ips,
        "ssh_username": check.ssh_username,
        "ssh_password": check.ssh_password,
        "ssh_private_key": check.ssh_private_key,
    })
}

fn cleanup_l2tp_objects(check: &TunnelCheck) -> Result<(), String> {
    if !matches!(check.protocol, TunnelProtocol::L2tp) {
        return Ok(());
    }

    let tunnel_id = check.l2tp_tunnel_id.unwrap_or(1).to_string();
    let session_id = check.l2tp_session_id.unwrap_or(1).to_string();
    let session_args = [
        "l2tp",
        "del",
        "session",
        "tunnel_id",
        tunnel_id.as_str(),
        "session_id",
        session_id.as_str(),
    ];
    let _ = run_command_status("ip", &session_args);

    let tunnel_args = ["l2tp", "del", "tunnel", "tunnel_id", tunnel_id.as_str()];
    let _ = run_command_status("ip", &tunnel_args);
    Ok(())
}

fn cleanup_encap_receive_port(check: &TunnelCheck) -> Result<(), String> {
    if !matches!(check.protocol, TunnelProtocol::Encap) {
        return Ok(());
    }

    let port = check.transport_port.unwrap_or(5555).to_string();
    let args = ["fou", "del", "port", port.as_str(), "gue"];
    match run_command_status("ip", &args) {
        Ok(()) => Ok(()),
        Err(error)
            if error.contains("No such file")
                || error.contains("does not exist")
                || error.contains("Cannot find")
                || error.contains("Invalid argument") =>
        {
            Ok(())
        }
        Err(error) => Err(format!("failed to remove GUE receive port {port}: {error}")),
    }
}

fn cleanup_esp_objects(check: &TunnelCheck) -> Result<(), String> {
    if !matches!(check.protocol, TunnelProtocol::Esp) {
        return Ok(());
    }

    let Some(local_inner) = resolve_esp_inner_local_ip(check) else {
        return Ok(());
    };
    let Some(remote_inner) = check.inner_probe.as_deref().map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let Some(remote_outer) = check.outer_remote.as_deref().map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let Some(local_outer) = resolve_cleanup_local_outer(check) else {
        return Ok(());
    };

    let if_id = resolve_cleanup_xfrm_if_id(check);
    let reqid = ((stable_positive_u32(&format!("reqid|esp|{local_inner}|{remote_inner}")) & 0xffff).max(1)) as u32;
    let outbound_spi =
        (stable_positive_u32(&format!("spi|out|{local_outer}|{remote_outer}|{if_id:x}")) & 0x0fff_ffff)
            .max(0x100);
    let inbound_spi =
        (stable_positive_u32(&format!("spi|out|{remote_outer}|{local_outer}|{if_id:x}")) & 0x0fff_ffff)
            .max(0x100);
    let local_selector = host_selector(local_inner.as_str());
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
            local_outer.clone(),
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
            local_outer.clone(),
            "proto".to_string(),
            "esp".to_string(),
            "spi".to_string(),
            format!("0x{inbound_spi:x}"),
        ],
    ];

    for command in cleanup_commands {
        let args = command.iter().map(String::as_str).collect::<Vec<_>>();
        let _ = run_command_status("ip", &args);
    }
    let _ = reqid;
    Ok(())
}

fn resolve_esp_inner_local_ip(check: &TunnelCheck) -> Option<String> {
    if let Some(cidr) = check.inner_local_cidr.as_deref() {
        return extract_ip_from_cidr(cidr);
    }
    if let Some(inner_probe) = check.inner_probe.as_deref() {
        return derive_complementary_point_to_point_ip(inner_probe);
    }
    None
}

fn derive_complementary_point_to_point_ip(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if let Ok(ipv4) = trimmed.parse::<std::net::Ipv4Addr>() {
        let raw = u32::from(ipv4);
        let network = raw & !0b11;
        let host_a = network + 1;
        let host_b = network + 2;
        if raw == host_a {
            return Some(std::net::Ipv4Addr::from(host_b).to_string());
        }
        if raw == host_b {
            return Some(std::net::Ipv4Addr::from(host_a).to_string());
        }
    }
    if let Ok(ipv6) = trimmed.parse::<std::net::Ipv6Addr>() {
        let raw = u128::from(ipv6);
        let sibling = if raw & 1 == 0 {
            raw.saturating_add(1)
        } else {
            raw.saturating_sub(1)
        };
        return Some(std::net::Ipv6Addr::from(sibling).to_string());
    }
    None
}

fn resolve_cleanup_local_outer(check: &TunnelCheck) -> Option<String> {
    if let Some(local_outer) = check.local_outer.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        return Some(local_outer.to_string());
    }
    let remote_outer = check.outer_remote.as_deref()?.trim();
    if remote_outer.is_empty() {
        return None;
    }
    let output = Command::new("ip")
        .args(["-o", "route", "get", remote_outer])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        for window in parts.windows(2) {
            if window[0] == "src" && !window[1].trim().is_empty() {
                return Some(window[1].trim().to_string());
            }
        }
    }
    None
}

fn resolve_cleanup_xfrm_if_id(check: &TunnelCheck) -> u32 {
    if let Some(raw) = check.tunnel_key.as_deref() {
        let trimmed = raw.trim();
        if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
            if let Ok(value) = u32::from_str_radix(hex, 16) {
                return value;
            }
        }
        if let Ok(value) = trimmed.parse::<u32>() {
            return value;
        }
    }
    let seed = if let (Some(local_inner), Some(remote_inner)) = (
        resolve_esp_inner_local_ip(check),
        check.inner_probe.as_deref().map(str::trim).filter(|value| !value.is_empty()),
    ) {
        match normalize_ip_pair(&local_inner, remote_inner) {
            Some((first, second)) => format!("esp|{first}|{second}"),
            None => check.id.clone(),
        }
    } else {
        check.id.clone()
    };
    stable_positive_u32(&seed)
}

fn host_selector(value: &str) -> String {
    if value.contains(':') {
        format!("{value}/128")
    } else {
        format!("{value}/32")
    }
}

fn clear_tunnel_counter_state(context: &Arc<AppContext>, check_id: &str) -> Result<(), String> {
    let mut runtime = match context.runtime.try_lock() {
        Ok(runtime) => runtime,
        Err(TryLockError::WouldBlock) => return Ok(()),
        Err(TryLockError::Poisoned(_)) => {
            return Err("failed to lock runtime state".to_string())
        }
    };
    runtime.monitor_state.tunnel_counters.remove(check_id);
    save_persisted_state(&context.state_file, &runtime.monitor_state)
}

fn run_command_status(command: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|error| format!("failed to execute {command}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let message = if !stderr.is_empty() { stderr } else { stdout };
        Err(message)
    }
}

fn handle_traffic_watcher_save(context: &Arc<AppContext>, request: Request) -> Response {
    let result = context.db.add_traffic_watcher(
        request.form_value("label").trim(),
        request.form_value("family").trim(),
        request.form_value("direction").trim(),
        request.form_value("protocol").trim(),
        request.form_value("source_ip").trim(),
        request
            .form_value("target_port")
            .parse::<u16>()
            .unwrap_or(0),
    );

    match result.and_then(|_| context.db.list_traffic_watchers()).and_then(|watchers| sync_traffic_watchers(&watchers)) {
        Ok(_) => redirect_with_flash(&request, AdminSection::NetworkControls.path(), "watcher_saved"),
        Err(error) => redirect_with_flash(&request, AdminSection::NetworkControls.path(), &error),
    }
}

fn handle_traffic_watcher_delete(context: &Arc<AppContext>, request: Request) -> Response {
    let watcher_id=request.form_value("watcher_id").parse::<i64>().unwrap_or(0);
    let result=(||{let mut watchers=context.db.list_traffic_watchers()?;
        let watcher=watchers.iter_mut().find(|watcher|watcher.id==watcher_id).ok_or("traffic watcher does not exist")?;
        watcher.enabled=false;sync_traffic_watchers(&watchers)?;context.db.delete_traffic_watcher(watcher_id)})();
    match result {Ok(_)=>redirect_with_flash(&request,AdminSection::NetworkControls.path(),"watcher_deleted"),Err(error)=>redirect_with_flash(&request,AdminSection::NetworkControls.path(),&error)}
}

fn handle_speed_limit_save(context: &Arc<AppContext>, request: Request) -> Response {
    match context.db.add_speed_limit(
        request.form_value("interface_name").trim(),
        request.form_value("protocol").trim(),
        request.form_value("port").parse::<u16>().unwrap_or(0),
        request.form_value("rate_value").parse::<u64>().unwrap_or(0),
        request.form_value("rate_unit").trim(),
    ) {
        Ok(_) => redirect_with_flash(&request, AdminSection::NetworkControls.path(), "speed_limit_saved"),
        Err(error) => redirect_with_flash(&request, AdminSection::NetworkControls.path(), &error),
    }
}

fn handle_speed_limit_delete(context: &Arc<AppContext>, request: Request) -> Response {
    let rule_id = request.form_value("rule_id").parse::<i64>().unwrap_or(0);
    let cleanup = context.db.list_speed_limits().and_then(|rules| {
        if let Some(mut rule) = rules.into_iter().find(|rule| rule.id == rule_id) {
            rule.enabled = false;
            let statuses = sync_speed_limits(&[rule], &context_data_dir(context))?;
            if let Some((_, true, message)) = statuses.first() {
                return Err(message.clone());
            }
        }
        Ok(())
    });
    if let Err(error) = cleanup {
        return redirect_with_flash(&request, AdminSection::NetworkControls.path(), &error);
    }
    match context.db.delete_speed_limit(rule_id) {
        Ok(_) => redirect_with_flash(&request, AdminSection::NetworkControls.path(), "speed_limit_deleted"),
        Err(error) => redirect_with_flash(&request, AdminSection::NetworkControls.path(), &error),
    }
}

fn handle_apply_speed_limits(context: &Arc<AppContext>, request: Request) -> Response {
    match sync_speed_limits_from_db(context) {
        Ok(()) => redirect_with_flash(&request, AdminSection::NetworkControls.path(), "speed_limits_applied"),
        Err(error) => redirect_with_flash(&request, AdminSection::NetworkControls.path(), &error),
    }
}

fn sync_speed_limits_from_db(context: &Arc<AppContext>) -> Result<(), String> {
    let rules = context.db.list_speed_limits()?;
    let statuses = sync_speed_limits(&rules, &context_data_dir(context))?;
    let mut first_error = None;
    for (rule_id, applied, message) in statuses {
        context.db.update_speed_limit_status(rule_id, applied, &message)?;
        if message.starts_with("failed ") || rules.iter().find(|rule| rule.id == rule_id).is_some_and(|rule| applied != rule.enabled) {
            first_error.get_or_insert(message);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn handle_tcp_limit(context: &Arc<AppContext>, request: Request) -> Response {
    let mut policy = match context.db.load_tcp_conn_limit() {
        Ok(policy) => policy,
        Err(error) => {
            return redirect_with_flash(&request, AdminSection::NetworkControls.path(), &error);
        }
    };
    policy.enabled = parse_form_bool(&request, "enabled", policy.enabled);
    policy.target_port = request
        .form_value("target_port")
        .parse::<u16>()
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(policy.target_port);
    policy.limit_per_ip = request
        .form_value("limit_per_ip")
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(policy.limit_per_ip);
    match apply_tcp_conn_limit(&policy) {
        Ok(message) => {
            policy.last_status = message.clone();
            policy.updated_at_unix = db::unix_now();
            let _ = context.db.save_tcp_conn_limit(&policy);
            redirect_with_flash(&request, AdminSection::NetworkControls.path(), &message)
        }
        Err(error) => {
            policy.last_status = error.clone();
            policy.updated_at_unix = db::unix_now();
            let _ = context.db.save_tcp_conn_limit(&policy);
            redirect_with_flash(&request, AdminSection::NetworkControls.path(), &error)
        }
    }
}

fn sync_port_forward_rules_from_db(context: &Arc<AppContext>) -> Result<(), String> {
    let rules=context.db.list_port_forward_rules()?;
    sync_port_forward_rule_set(context,&rules)
}
fn sync_port_forward_rule_set(context:&Arc<AppContext>,rules:&[crate::app_types::PortForwardRule])->Result<(),String>{
    match sync_port_forward_rules(rules) {
        Ok(statuses)=>{for (id,_,status) in statuses {let enabled=rules.iter().find(|rule|rule.id==id).is_some_and(|rule|rule.enabled);context.db.update_port_forward_rule_status(id,enabled,&status)?;} Ok(())},
        Err(error)=>{for rule in rules {context.db.update_port_forward_rule_status(rule.id,rule.enabled,&format!("failed to synchronize forwarding: {error}"))?;}Err(error)},
    }
}

fn sync_source_ip_rules_from_db(context: &Arc<AppContext>) -> Result<(), String> {
    let rules = context.db.list_source_ip_rules()?;
    sync_source_ip_rule_set(context, &rules)
}

fn sync_source_ip_rule_set(context: &Arc<AppContext>, rules: &[crate::app_types::SourceIpRule]) -> Result<(), String> {
    let statuses = sync_source_ip_rules(rules, &context_data_dir(context))?;
    let mut errors = Vec::new();
    for (rule_id, applied, status) in statuses {
        context.db.update_source_ip_rule_status(rule_id, &status)?;
        if !applied && (status != "disabled" || rules.iter().any(|rule| rule.id == rule_id && rule.enabled)) {
            errors.push(status);
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join(" | ")) }
}

fn ensure_source_ip_engine_key(data_dir: &str) -> Result<(), String> {
    let key_path = Path::new(data_dir).join(".engine.key");
    if key_path.exists() {
        return Ok(());
    }
    let secret = random_hex(24)?;
    fs::write(&key_path, format!("{secret}\n"))
        .map_err(|error| format!("failed to write source ip engine key: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn handle_port_forward_rule_save(context: &Arc<AppContext>, request: Request) -> Response {
    let protocol = request.form_value("protocol").trim().to_ascii_lowercase();
    let family = request.form_value("family").trim().to_ascii_lowercase();
    let listen_port = request
        .form_value("listen_port")
        .parse::<u16>()
        .ok()
        .unwrap_or(0);
    let target_port = request
        .form_value("target_port")
        .parse::<u16>()
        .ok()
        .unwrap_or(0);
    let enabled = parse_form_bool(&request, "enabled", true);

    let result = context.db.add_port_forward_rule(
        request.form_value("label").trim(),
        &protocol,
        &family,
        request.form_value("interface_name").trim(),
        request.form_value("source_ip").trim(),
        listen_port,
        request.form_value("target_host").trim(),
        if protocol == "icmp" { 0 } else { target_port },
        enabled,
    );

    match result.and_then(|_| sync_port_forward_rules_from_db(context)) {
        Ok(_) => redirect_with_flash(&request, AdminSection::Forwarding.path(), "forward_rule_saved"),
        Err(error) => redirect_with_flash(&request, AdminSection::Forwarding.path(), &error),
    }
}

fn handle_source_ip_save(context: &Arc<AppContext>, request: Request) -> Response {
    let label = request.form_value("source_ip_label").trim();
    let mode = match request.form_value("source_ip_mode").trim() { "" => "paired", value => value };
    let family = request.form_value("source_ip_family").trim();
    let protocol = request.form_value("source_ip_protocol").trim();
    let match_port = match request.form_value("source_ip_match_port").trim() {
        "" => 0,
        value => match value.parse::<u16>() {
            Ok(value) => value,
            Err(_) => return redirect_with_flash(&request, AdminSection::SourceIp.path(), "port must be 0–65535"),
        },
    };
    let interface_name = request.form_value("source_ip_interface").trim();
    let destination_ip = request.form_value("source_ip_destination_ip").trim();
    let source_ip = request.form_value("source_ip_source_ip").trim();
    let translate_ip = request.form_value("source_ip_translate_ip").trim();
    let enabled = request.form_value("source_ip_enabled") == "1";

    if label.is_empty() {
        return redirect_with_flash(&request, AdminSection::SourceIp.path(), "missing_source_ip_label");
    }
    if let Err(error) = crate::network_rules::validate_source_ip(mode, family, protocol, match_port, interface_name, destination_ip, source_ip, translate_ip) {
        return redirect_with_flash(&request, AdminSection::SourceIp.path(), &error);
    }
    if mode == "paired" {
        let local_ips = local_ipv4_inventory_for_source_ip(context);
        if local_ips.contains(destination_ip) {
            return redirect_with_flash(
                &request,
                AdminSection::SourceIp.path(),
                "source_ip_destination_is_local",
            );
        }
        if !translate_ip.is_empty() && local_ips.contains(translate_ip) {
            return redirect_with_flash(
                &request,
                AdminSection::SourceIp.path(),
                "source_ip_translate_is_local",
            );
        }
    }
    let result = context.db.add_source_ip_rule(
        label,
        mode,
        family,
        protocol,
        match_port,
        interface_name,
        destination_ip,
        source_ip,
        translate_ip,
        enabled,
    );
    match result.and_then(|_| sync_source_ip_rules_from_db(context)) {
        Ok(_) => redirect_with_flash(&request, AdminSection::SourceIp.path(), "source_ip_saved"),
        Err(error) => redirect_with_flash(&request, AdminSection::SourceIp.path(), &error),
    }
}

fn local_ipv4_inventory_for_source_ip(context: &Arc<AppContext>) -> BTreeSet<String> {
    let _ = context;
    collect_host_ip_inventory_detailed()
        .into_iter()
        .filter_map(|entry| match entry.address.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => Some(entry.address),
            _ => None,
        })
        .collect()
}

fn handle_source_ip_delete(context: &Arc<AppContext>, request: Request) -> Response {
    let rule_id = request.form_value("source_ip_id").parse::<i64>().unwrap_or(0);
    if rule_id == 0 {
        return redirect_with_flash(&request, AdminSection::SourceIp.path(), "missing_source_ip_id");
    }
    let remove = (|| {
        let mut rules = context.db.list_source_ip_rules()?;
        let rule = rules.iter_mut().find(|rule| rule.id == rule_id).ok_or_else(|| "source IP rule does not exist".to_string())?;
        rule.enabled = false;
        sync_source_ip_rule_set(context, &rules)?;
        context.db.delete_source_ip_rule(rule_id)
    })();
    match remove
    {
        Ok(_) => redirect_with_flash(&request, AdminSection::SourceIp.path(), "source_ip_deleted"),
        Err(error) => redirect_with_flash(&request, AdminSection::SourceIp.path(), &error),
    }
}

fn handle_source_ip_apply(context: &Arc<AppContext>, request: Request) -> Response {
    match sync_source_ip_rules_from_db(context) {
        Ok(_) => redirect_with_flash(&request, AdminSection::SourceIp.path(), "source_ip_applied"),
        Err(error) => redirect_with_flash(&request, AdminSection::SourceIp.path(), &error),
    }
}

fn handle_backup_browser_json(request: Request) -> Response {
    let requested_path = request.query_value("path").trim();
    let mut current_path = if requested_path.is_empty() {
        PathBuf::from("/")
    } else {
        PathBuf::from(requested_path)
    };
    if !current_path.is_absolute() {
        current_path = PathBuf::from("/").join(current_path);
    }

    let current_path = fs::canonicalize(&current_path)
        .or_else(|_| fs::canonicalize(current_path.parent().unwrap_or(Path::new("/"))))
        .unwrap_or_else(|_| PathBuf::from("/"));

    let read_dir = match fs::read_dir(&current_path) {
        Ok(read_dir) => read_dir,
        Err(error) => {
            return Response::json(
                400,
                &json!({ "error": format!("failed to open path: {error}") }),
            );
        }
    };

    let mut entries = Vec::<FileBrowserEntry>::new();
    if current_path != Path::new("/") {
        let parent = current_path.parent().unwrap_or(Path::new("/"));
        entries.push(FileBrowserEntry {
            path: parent.to_string_lossy().to_string(),
            name: "..".to_string(),
            is_dir: true,
            size_bytes: 0,
        });
    }

    for entry in read_dir.flatten() {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        entries.push(FileBrowserEntry {
            path: path.to_string_lossy().to_string(),
            name: entry.file_name().to_string_lossy().to_string(),
            is_dir: metadata.is_dir(),
            size_bytes: if metadata.is_file() { metadata.len() } else { 0 },
        });
    }
    entries.sort_by(|left, right| {
        right
            .is_dir
            .cmp(&left.is_dir)
            .then_with(|| left.name.to_ascii_lowercase().cmp(&right.name.to_ascii_lowercase()))
    });

    Response::json(
        200,
        &json!({
            "current_path": current_path.to_string_lossy().to_string(),
            "entries": entries.iter().map(|entry| json!({
                "path": entry.path,
                "name": entry.name,
                "is_dir": entry.is_dir,
                "size_bytes": entry.size_bytes,
                "size_human": if entry.is_dir { "-".to_string() } else { bytes_to_human(entry.size_bytes) },
            })).collect::<Vec<_>>(),
        }),
    )
}

fn handle_backup_target_save(context: &Arc<AppContext>, request: Request) -> Response {
    let protocol = request.form_value("protocol").trim().to_ascii_lowercase();
    let label = request.form_value("label").trim();
    if label.is_empty() {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "backup target label is required");
    }
    if !matches!(protocol.as_str(), "ftp" | "sftp" | "s3") {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "backup target protocol is invalid");
    }
    if matches!(protocol.as_str(), "ftp" | "sftp") && request.form_value("endpoint").trim().is_empty() {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "backup target endpoint is required");
    }
    if protocol == "s3" && request.form_value("s3_bucket").trim().is_empty() {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "s3 bucket is required");
    }
    let enabled = parse_form_bool(&request, "enabled", true);
    match context.db.add_backup_target(
        label,
        &protocol,
        request.form_value("endpoint").trim(),
        request.form_value("port").trim().parse::<u16>().ok().unwrap_or(0),
        request.form_value("username").trim(),
        request.form_value("password").trim(),
        request.form_value("remote_path").trim(),
        request.form_value("s3_bucket").trim(),
        request.form_value("s3_region").trim(),
        request.form_value("s3_endpoint").trim(),
        request.form_value("s3_access_key").trim(),
        request.form_value("s3_secret_key").trim(),
        enabled,
    ) {
        Ok(_) => redirect_with_flash(&request, AdminSection::Backups.path(), "backup target saved"),
        Err(error) => redirect_with_flash(&request, AdminSection::Backups.path(), &error),
    }
}

fn handle_backup_target_delete(context: &Arc<AppContext>, request: Request) -> Response {
    let target_id = request.form_value("target_id").trim().parse::<i64>().ok().unwrap_or(0);
    if target_id <= 0 {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "backup target id is missing");
    }
    match context.db.delete_backup_target(target_id) {
        Ok(_) => redirect_with_flash(&request, AdminSection::Backups.path(), "backup target deleted"),
        Err(error) => redirect_with_flash(&request, AdminSection::Backups.path(), &error),
    }
}

fn handle_backup_job_save(context: &Arc<AppContext>, request: Request) -> Response {
    let label = request.form_value("label").trim();
    if label.is_empty() {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "backup job label is required");
    }
    let source_paths = request
        .form_value("source_paths")
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    if source_paths.is_empty() {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "at least one backup source path is required");
    }
    let target_ids = parse_form_multi_values(&request, "target_ids")
        .into_iter()
        .filter_map(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .collect::<Vec<_>>();
    if target_ids.is_empty() {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "select at least one backup target");
    }
    let compression_format = request.form_value("compression_format").trim();
    if !matches!(compression_format, "tar.gz" | "tar.xz" | "zip") {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "backup compression format is invalid");
    }
    let schedule_kind = request.form_value("schedule_kind").trim();
    if !matches!(schedule_kind, "minute" | "hour" | "day") {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "backup schedule type is invalid");
    }
    let schedule_value = request.form_value("schedule_value").trim().parse::<u32>().ok().unwrap_or(1).max(1);
    let retention_count = request.form_value("retention_count").trim().parse::<u32>().ok().unwrap_or(8).max(1);
    let include_hidden = parse_form_bool(&request, "include_hidden", false);
    let enabled = parse_form_bool(&request, "enabled", true);
    let next_run_at = schedule_next_run(schedule_kind, schedule_value, db::unix_now());
    let source_paths_json = match serde_json::to_string(&source_paths) {
        Ok(value) => value,
        Err(error) => return redirect_with_flash(&request, AdminSection::Backups.path(), &format!("failed to encode source paths: {error}")),
    };
    match context
        .db
        .add_backup_job(
            label,
            &source_paths_json,
            include_hidden,
            compression_format,
            schedule_kind,
            schedule_value,
            retention_count,
            enabled,
            next_run_at,
        )
        .and_then(|job_id| context.db.replace_backup_job_targets(job_id, &target_ids))
    {
        Ok(_) => redirect_with_flash(&request, AdminSection::Backups.path(), "backup job saved"),
        Err(error) => redirect_with_flash(&request, AdminSection::Backups.path(), &error),
    }
}

fn handle_backup_job_delete(context: &Arc<AppContext>, request: Request) -> Response {
    let job_id = request.form_value("job_id").trim().parse::<i64>().ok().unwrap_or(0);
    if job_id <= 0 {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "backup job id is missing");
    }
    match context.db.delete_backup_job(job_id) {
        Ok(_) => redirect_with_flash(&request, AdminSection::Backups.path(), "backup job deleted"),
        Err(error) => redirect_with_flash(&request, AdminSection::Backups.path(), &error),
    }
}

fn handle_backup_job_run(context: &Arc<AppContext>, request: Request) -> Response {
    let job_id = request.form_value("job_id").trim().parse::<i64>().ok().unwrap_or(0);
    if job_id <= 0 {
        return redirect_with_flash(&request, AdminSection::Backups.path(), "backup job id is missing");
    }
    match execute_backup_job(context, job_id) {
        Ok(message) => redirect_with_flash(&request, AdminSection::Backups.path(), &message),
        Err(error) => redirect_with_flash(&request, AdminSection::Backups.path(), &error),
    }
}

fn run_backup_scheduler_cycle(context: &Arc<AppContext>) -> Result<(), String> {
    let now = db::unix_now();
    for job in context.db.list_backup_jobs()?.into_iter().filter(|job| job.enabled) {
        if job.next_run_at_unix > 0 && job.next_run_at_unix > now {
            continue;
        }
        let _ = execute_backup_job(context, job.id);
    }
    Ok(())
}

fn execute_backup_job(context: &Arc<AppContext>, job_id: i64) -> Result<String, String> {
    let job = context
        .db
        .list_backup_jobs()?
        .into_iter()
        .find(|job| job.id == job_id)
        .ok_or_else(|| "backup job was not found".to_string())?;
    let selected_target_ids = context
        .db
        .list_backup_job_targets()?
        .into_iter()
        .filter(|link| link.job_id == job.id)
        .map(|link| link.target_id)
        .collect::<Vec<_>>();
    if selected_target_ids.is_empty() {
        let next_run_at = schedule_next_run(&job.schedule_kind, job.schedule_value, db::unix_now());
        let _ = context.db.update_backup_job_status(
            job.id,
            job.enabled,
            "no backup target is attached to this job",
            job.last_run_at_unix,
            next_run_at,
        );
        return Err("no backup target is attached to this job".to_string());
    }
    let targets = context
        .db
        .list_backup_targets()?
        .into_iter()
        .filter(|target| selected_target_ids.contains(&target.id))
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return Err("selected backup targets could not be loaded".to_string());
    }

    let archive = create_backup_archive(context, &job)?;
    let archive_name = archive
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("backup.archive")
        .to_string();
    let archive_size_bytes = fs::metadata(&archive).map(|metadata| metadata.len()).unwrap_or(0);
    let mut success_count = 0_u32;
    let mut failed = Vec::new();
    for target in targets {
        if !target.enabled {
            failed.push(format!("{}: disabled", target.label));
            continue;
        }
        let result = upload_backup_with_retention(context, &job, &target, &archive, &archive_name);
        match result {
            Ok(locator) => {
                let _ = context.db.add_backup_record(
                    job.id,
                    target.id,
                    &archive_name,
                    archive_size_bytes,
                    "uploaded",
                    &locator,
                );
                let _ = context.db.update_backup_target_status(target.id, true, "uploaded");
                success_count += 1;
            }
            Err(error) => {
                let _ = context.db.update_backup_target_status(target.id, target.enabled, &error);
                failed.push(format!("{}: {}", target.label, error));
            }
        }
    }
    let _ = fs::remove_file(&archive);
    let now = db::unix_now();
    let next_run_at = schedule_next_run(&job.schedule_kind, job.schedule_value, now);
    let status = if failed.is_empty() {
        format!("backup uploaded to {} target(s)", success_count)
    } else if success_count == 0 {
        failed.join(" | ")
    } else {
        format!(
            "uploaded to {} target(s); failed: {}",
            success_count,
            failed.join(" | ")
        )
    };
    let _ = context.db.update_backup_job_status(job.id, job.enabled, &status, now, next_run_at);
    if success_count == 0 {
        Err(status)
    } else {
        Ok(status)
    }
}

fn upload_backup_with_retention(
    context: &Arc<AppContext>,
    job: &BackupJob,
    target: &BackupTarget,
    archive_path: &Path,
    archive_name: &str,
) -> Result<String, String> {
    prune_old_backup_records(context, job, target, job.retention_count.saturating_sub(1) as usize)?;
    match upload_backup_to_target(target, archive_path, archive_name) {
        Ok(locator) => Ok(locator),
        Err(error) if backup_error_looks_like_no_space(&error) => {
            prune_old_backup_records(context, job, target, job.retention_count.saturating_sub(2) as usize)?;
            upload_backup_to_target(target, archive_path, archive_name)
        }
        Err(error) => Err(error),
    }
}

fn prune_old_backup_records(
    context: &Arc<AppContext>,
    job: &BackupJob,
    target: &BackupTarget,
    keep_existing: usize,
) -> Result<(), String> {
    let mut records = context.db.list_backup_records_for_job_target(job.id, target.id)?;
    while records.len() > keep_existing {
        let oldest = records.remove(0);
        let _ = delete_backup_from_target(target, &oldest.archive_name);
        context.db.delete_backup_record(oldest.id)?;
    }
    Ok(())
}

fn create_backup_archive(context: &Arc<AppContext>, job: &BackupJob) -> Result<PathBuf, String> {
    let data_dir = context_data_dir(context);
    let archive_dir = data_dir.join("backups").join("archives");
    fs::create_dir_all(&archive_dir)
        .map_err(|error| format!("failed to create backup archive directory: {error}"))?;
    let stamp = db::unix_now();
    let archive_name = format!(
        "{}-{}.{}",
        slugify_backup_label(&job.label),
        stamp,
        job.compression_format
    );
    let archive_path = archive_dir.join(&archive_name);

    let source_paths = job
        .source_paths
        .iter()
        .map(|path| PathBuf::from(path.trim()))
        .filter(|path| !path.as_os_str().is_empty())
        .collect::<Vec<_>>();
    if source_paths.is_empty() {
        return Err("backup job does not have any source path".to_string());
    }
    for source_path in &source_paths {
        if !source_path.exists() {
            return Err(format!("backup source does not exist: {}", source_path.display()));
        }
    }

    let mut command = if job.compression_format == "zip" {
        let mut command = Command::new("zip");
        command.arg("-r").arg(&archive_path);
        if !job.include_hidden {
            command.arg("-x").arg("*/.*").arg(".*");
        }
        command
    } else {
        let mut command = Command::new("tar");
        if job.compression_format == "tar.xz" {
            command.arg("-cJf");
        } else {
            command.arg("-czf");
        }
        command.arg(&archive_path).arg("--absolute-names");
        if !job.include_hidden {
            command.arg("--exclude=.git");
            command.arg("--exclude=*/.*");
            command.arg("--exclude=.*");
        }
        command
    };
    for source_path in &source_paths {
        command.arg(source_path);
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to build backup archive: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("backup archive command exited with status {}", output.status)
        } else {
            stderr
        });
    }
    Ok(archive_path)
}

fn upload_backup_to_target(
    target: &BackupTarget,
    archive_path: &Path,
    archive_name: &str,
) -> Result<String, String> {
    match target.protocol.as_str() {
        "ftp" | "sftp" => upload_backup_via_curl(target, archive_path, archive_name),
        "s3" => upload_backup_via_s3(target, archive_path, archive_name),
        _ => Err("unsupported backup target protocol".to_string()),
    }
}

fn upload_backup_via_curl(
    target: &BackupTarget,
    archive_path: &Path,
    archive_name: &str,
) -> Result<String, String> {
    let remote_url = format!("{}{}", backup_target_base_url(target), archive_name);
    let mut command = Command::new("curl");
    command.args(["-fsS", "--connect-timeout", "12", "--max-time", "0", "-T"]);
    command.arg(archive_path);
    if !target.username.trim().is_empty() || !target.password.trim().is_empty() {
        command.arg("--user");
        command.arg(format!("{}:{}", target.username, target.password));
    }
    command.arg(&remote_url);
    let output = command
        .output()
        .map_err(|error| format!("failed to start backup upload: {error}"))?;
    if output.status.success() {
        Ok(remote_url)
    } else {
        Err(stderr_or_status(&output, "backup upload failed"))
    }
}

fn upload_backup_via_s3(
    target: &BackupTarget,
    archive_path: &Path,
    archive_name: &str,
) -> Result<String, String> {
    let Some(_aws) = command_path("aws") else {
        return Err("aws cli is required for s3 backup targets".to_string());
    };
    let remote_uri = backup_target_s3_uri(target, archive_name);
    let mut command = Command::new("aws");
    command.args(["s3", "cp"]);
    command.arg(archive_path);
    command.arg(&remote_uri);
    if !target.s3_endpoint.trim().is_empty() {
        command.arg("--endpoint-url");
        command.arg(target.s3_endpoint.trim());
    }
    if !target.s3_region.trim().is_empty() {
        command.arg("--region");
        command.arg(target.s3_region.trim());
    }
    command.env("AWS_ACCESS_KEY_ID", target.s3_access_key.trim());
    command.env("AWS_SECRET_ACCESS_KEY", target.s3_secret_key.trim());
    if !target.s3_region.trim().is_empty() {
        command.env("AWS_DEFAULT_REGION", target.s3_region.trim());
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to start s3 upload: {error}"))?;
    if output.status.success() {
        Ok(remote_uri)
    } else {
        Err(stderr_or_status(&output, "s3 upload failed"))
    }
}

fn delete_backup_from_target(target: &BackupTarget, archive_name: &str) -> Result<(), String> {
    match target.protocol.as_str() {
        "ftp" | "sftp" => delete_backup_via_curl(target, archive_name),
        "s3" => delete_backup_via_s3(target, archive_name),
        _ => Ok(()),
    }
}

fn delete_backup_via_curl(target: &BackupTarget, archive_name: &str) -> Result<(), String> {
    let remote_dir = backup_target_base_url(target);
    let remote_file = build_target_relative_remote_file(target, archive_name);
    let mut command = Command::new("curl");
    command.args(["-fsS"]);
    if !target.username.trim().is_empty() || !target.password.trim().is_empty() {
        command.arg("--user");
        command.arg(format!("{}:{}", target.username, target.password));
    }
    command.arg("-Q");
    if target.protocol == "sftp" {
        command.arg(format!("rm {remote_file}"));
        command.arg(format!(
            "{}://{}{}",
            target.protocol,
            backup_target_host_port(target),
            "/"
        ));
    } else {
        command.arg(format!("DELE {}", archive_name));
        command.arg(remote_dir);
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to start remote delete: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let message = stderr_or_status(&output, "remote delete failed");
        if backup_error_looks_like_missing(&message) {
            Ok(())
        } else {
            Err(message)
        }
    }
}

fn delete_backup_via_s3(target: &BackupTarget, archive_name: &str) -> Result<(), String> {
    let Some(_aws) = command_path("aws") else {
        return Ok(());
    };
    let remote_uri = backup_target_s3_uri(target, archive_name);
    let mut command = Command::new("aws");
    command.args(["s3", "rm"]);
    command.arg(&remote_uri);
    if !target.s3_endpoint.trim().is_empty() {
        command.arg("--endpoint-url");
        command.arg(target.s3_endpoint.trim());
    }
    if !target.s3_region.trim().is_empty() {
        command.arg("--region");
        command.arg(target.s3_region.trim());
    }
    command.env("AWS_ACCESS_KEY_ID", target.s3_access_key.trim());
    command.env("AWS_SECRET_ACCESS_KEY", target.s3_secret_key.trim());
    if !target.s3_region.trim().is_empty() {
        command.env("AWS_DEFAULT_REGION", target.s3_region.trim());
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to start s3 delete: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let message = stderr_or_status(&output, "s3 delete failed");
        if backup_error_looks_like_missing(&message) {
            Ok(())
        } else {
            Err(message)
        }
    }
}

fn backup_target_base_url(target: &BackupTarget) -> String {
    let remote_path = target.remote_path.trim().trim_matches('/');
    if remote_path.is_empty() {
        format!("{}://{}/", target.protocol, backup_target_host_port(target))
    } else {
        format!(
            "{}://{}/{}/",
            target.protocol,
            backup_target_host_port(target),
            remote_path
        )
    }
}

fn backup_target_host_port(target: &BackupTarget) -> String {
    if target.port > 0 {
        format!("{}:{}", target.endpoint.trim(), target.port)
    } else {
        target.endpoint.trim().to_string()
    }
}

fn build_target_relative_remote_file(target: &BackupTarget, archive_name: &str) -> String {
    let remote_path = target.remote_path.trim().trim_matches('/');
    if remote_path.is_empty() {
        archive_name.to_string()
    } else {
        format!("{remote_path}/{archive_name}")
    }
}

fn backup_target_s3_uri(target: &BackupTarget, archive_name: &str) -> String {
    let prefix = target.remote_path.trim().trim_matches('/');
    if prefix.is_empty() {
        format!("s3://{}/{}", target.s3_bucket.trim(), archive_name)
    } else {
        format!("s3://{}/{}/{}", target.s3_bucket.trim(), prefix, archive_name)
    }
}

fn backup_error_looks_like_no_space(error: &str) -> bool {
    let lowered = error.to_ascii_lowercase();
    lowered.contains("no space left")
        || lowered.contains("quota exceeded")
        || lowered.contains("disk full")
        || lowered.contains("insufficient storage")
}

fn backup_error_looks_like_missing(error: &str) -> bool {
    let lowered = error.to_ascii_lowercase();
    lowered.contains("no such file")
        || lowered.contains("not found")
        || lowered.contains("404")
        || lowered.contains("couldn't open file")
}

fn schedule_next_run(kind: &str, value: u32, from_unix: u64) -> u64 {
    let multiplier = match kind {
        "minute" => 60,
        "hour" => 60 * 60,
        "day" => 60 * 60 * 24,
        _ => 60 * 60 * 24,
    };
    from_unix.saturating_add(u64::from(value.max(1)) * multiplier)
}

fn slugify_backup_label(input: &str) -> String {
    let mut slug = String::with_capacity(input.len());
    for character in input.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if character == '-' || character == '_' {
            slug.push(character);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "backup".to_string()
    } else {
        slug.to_string()
    }
}

fn context_data_dir(context: &Arc<AppContext>) -> PathBuf {
    context
        .state_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("./runtime"))
}

fn command_path(program: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path_var| {
        env::split_paths(&path_var)
            .map(|segment| segment.join(program))
            .find(|candidate| candidate.is_file())
    })
}

fn stderr_or_status(output: &std::process::Output, fallback: &str) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        stderr
    } else {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !stdout.is_empty() {
            stdout
        } else {
            format!("{fallback} (status {})", output.status)
        }
    }
}

fn parse_form_multi_values(request: &Request, name: &str) -> Vec<String> {
    let body = String::from_utf8_lossy(&request.body);
    body.split('&')
        .filter_map(|pair| pair.split_once('='))
        .filter_map(|(raw_name, raw_value)| {
            if http::url_decode(raw_name) == name {
                Some(http::url_decode(raw_value))
            } else {
                None
            }
        })
        .collect()
}

fn handle_port_forward_rule_delete(context: &Arc<AppContext>, request: Request) -> Response {
    let rule_id=request.form_value("rule_id").parse::<i64>().unwrap_or(0);
    let result=(||{
        let mut rules=context.db.list_port_forward_rules()?;
        let rule=rules.iter_mut().find(|rule|rule.id==rule_id).ok_or("forwarding rule does not exist")?;
        rule.enabled=false;
        sync_port_forward_rule_set(context,&rules)?;
        context.db.delete_port_forward_rule(rule_id)
    })();
    match result {Ok(_)=>redirect_with_flash(&request,AdminSection::Forwarding.path(),"forward_rule_deleted"),Err(error)=>redirect_with_flash(&request,AdminSection::Forwarding.path(),&error)}
}

fn handle_apply_port_forward_rules(context: &Arc<AppContext>, request: Request) -> Response {
    match sync_port_forward_rules_from_db(context) {
        Ok(_) => redirect_with_flash(&request, AdminSection::Forwarding.path(), "forward_rules_applied"),
        Err(error) => redirect_with_flash(&request, AdminSection::Forwarding.path(), &error),
    }
}

fn handle_admin_live_system(context: &Arc<AppContext>, lang: UiLanguage) -> Response {
    match collect_live_dashboard_sample(context) {
        Ok(sample) => Response::html(
            200,
            views::render_admin_system_metrics_fragment(Some(&sample), lang),
        ),
        Err(error) => Response::html(
            500,
            views::render_admin_system_metrics_fragment(None, lang)
                + &format!(
                    r#"<div class="inline-alert inline-alert--danger">{}</div>"#,
                    crate::util::html_escape(&error)
                ),
        ),
    }
}

fn build_admin_dashboard_data(
    context: &Arc<AppContext>,
    settings: &AppSettings,
    section: AdminSection,
) -> Result<AdminDashboardData, String> {
    let checks = context.db.list_checks()?;
    let monitor_folders = merged_monitor_folders(context.db.list_monitor_folders()?, &checks);
    let public_payload = build_public_payload(context, settings)?;
    let latest_snapshot = context.db.latest_snapshot()?;
    let (latest_results, latest_summary, latest_system) = if let Some(snapshot) = latest_snapshot {
        let results = serde_json::from_str::<Vec<CheckResult>>(&snapshot.results_json)
            .map_err(|error| format!("failed to parse stored check results: {error}"))?;
        let summary = match serde_json::from_str::<SnapshotSummary>(&snapshot.summary_json) {
            Ok(summary) => summary,
            Err(_) => summarize_results(snapshot.created_at_unix, &results),
        };
        let latest_system = if snapshot.system_json.trim() == "{}" {
            None
        } else {
            serde_json::from_str(&snapshot.system_json).ok()
        };
        (results, summary, latest_system)
    } else {
        (
            Vec::new(),
            SnapshotSummary {
                observed_at_unix: db::unix_now(),
                total_checks: 0,
                up_checks: 0,
                degraded_checks: 0,
                down_checks: 0,
            },
            None,
        )
    };

    let warnings = build_warnings(settings);
    let host_ip_inventory = collect_host_ip_inventory_detailed();
    let latest_release_version = cached_latest_release_version();
    let admin_username = context
        .db
        .first_admin_user()?
        .map(|user| user.username)
        .unwrap_or_else(|| "admin".to_string());
    let server_health = if matches!(section, AdminSection::ServerHealth)
    {
        Some(build_server_health_report(context, settings).unwrap_or_default())
    } else {
        None
    };
    Ok(AdminDashboardData {
        settings: settings.clone(),
        admin_username,
        current_release_version: IMONITOR_RELEASE_VERSION.to_string(),
        latest_release_version,
        checks,
        monitor_folders,
        latest_results,
        latest_summary,
        latest_system,
        public_payload,
        traffic_watchers: context.db.list_traffic_watchers()?,
        speed_limits: context.db.list_speed_limits()?,
        tcp_conn_limit: context.db.load_tcp_conn_limit()?,
        backup_targets: context.db.list_backup_targets()?,
        backup_jobs: context.db.list_backup_jobs()?,
        backup_job_links: context.db.list_backup_job_targets()?,
        backup_records: context.db.list_backup_records(40)?,
        source_ip_rules: context.db.list_source_ip_rules()?,
        port_forward_rules: context.db.list_port_forward_rules()?,
        recent_reports: context.db.recent_free_reports(12)?,
        socket_inventory: collect_socket_inventory(40).unwrap_or_default(),
        host_ip_inventory,
        server_health,
        warnings,
    })
}

fn cached_latest_release_version() -> String {
    static CACHE: std::sync::OnceLock<Mutex<(Option<String>, u64, bool)>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new((None, 0, false)));
    let Ok(mut entry) = cache.lock() else { return IMONITOR_RELEASE_VERSION.into(); };
    let now = db::unix_now();
    let value = entry.0.clone().unwrap_or_else(|| IMONITOR_RELEASE_VERSION.into());
    if !entry.2 && (entry.1 == 0 || now.saturating_sub(entry.1) >= 900) {
        entry.1 = now;
        entry.2 = true;
        drop(entry);
        thread::spawn(move || {
            let version = fetch_latest_release_version().ok().filter(|value| release_version_tuple(value).is_some());
            if let Ok(mut entry) = cache.lock() {
                if let Some(version) = version { entry.0 = Some(version); }
                entry.2 = false;
            }
        });
    }
    value
}

fn fetch_latest_release_version() -> Result<String, String> {
    let output = Command::new("curl")
        .args(["-fsSL", "--max-time", "6", IMONITOR_LATEST_VERSION_URL])
        .output()
        .map_err(|error| format!("failed to fetch latest version marker: {error}"))?;
    if !output.status.success() {
        return Err("version marker request failed".to_string());
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() {
        Err("latest version marker was empty".to_string())
    } else {
        Ok(version)
    }
}

fn build_server_health_report(
    _context: &Arc<AppContext>,
    settings: &AppSettings,
) -> Result<ServerHealthReport, String> {
    let sample = collect_system_sample(None, None).ok().map(|(sample, _, _)| sample);
    let (hostname, hardware) = collect_hardware_snapshot();
    let distro = detect_distro_label();
    let (package_manager, updates_pending, updates_summary) = detect_updates_summary();
    let probes = run_server_health_probes(settings);
    let (accessible_regions, blocked_regions): (Vec<_>, Vec<_>) =
        probes.into_iter().partition(|probe| probe.success);

    Ok(ServerHealthReport {
        hostname,
        distro,
        kernel: hardware.kernel,
        cpu_model: hardware.cpu_model,
        cpu_count: hardware.cpu_count,
        total_ram_bytes: sample.as_ref().map(|value| value.total_ram_bytes).unwrap_or(0),
        total_disk_bytes: sample.as_ref().map(|value| value.total_disk_bytes).unwrap_or(0),
        package_manager,
        updates_summary,
        updates_pending,
        sample,
        accessible_regions,
        blocked_regions,
        generated_at_unix: db::unix_now(),
    })
}

fn detect_distro_label() -> String {
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        let mut pretty = String::new();
        let mut name = String::new();
        let mut version = String::new();
        for line in content.lines() {
            if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
                pretty = value.trim_matches('"').to_string();
            } else if let Some(value) = line.strip_prefix("NAME=") {
                name = value.trim_matches('"').to_string();
            } else if let Some(value) = line.strip_prefix("VERSION=") {
                version = value.trim_matches('"').to_string();
            }
        }
        if !pretty.is_empty() {
            return pretty;
        }
        if !name.is_empty() && !version.is_empty() {
            return format!("{name} {version}");
        }
        if !name.is_empty() {
            return name;
        }
    }
    first_command_line(&[("uname", &["-sr"])])
        .unwrap_or_else(|| "Linux".to_string())
}

fn detect_updates_summary() -> (String, u32, String) {
    if Command::new("apt-get").arg("--version").output().is_ok() {
        let line_count = Command::new("sh")
            .arg("-lc")
            .arg("apt list --upgradable 2>/dev/null | tail -n +2 | wc -l")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(0);
        return (
            "apt".to_string(),
            line_count,
            if line_count == 0 {
                "System packages look up to date.".to_string()
            } else {
                format!("{line_count} package update(s) are waiting.")
            },
        );
    }
    if Command::new("dnf").arg("--version").output().is_ok() {
        let line_count = Command::new("sh")
            .arg("-lc")
            .arg("dnf -q check-update >/tmp/imonitor-dnf-check.$$ 2>/dev/null; status=$?; if [ \"$status\" = \"100\" ]; then wc -l < /tmp/imonitor-dnf-check.$$; else echo 0; fi; rm -f /tmp/imonitor-dnf-check.$$")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(0);
        return (
            "dnf".to_string(),
            line_count,
            if line_count == 0 {
                "No pending DNF updates were detected.".to_string()
            } else {
                format!("{line_count} DNF package line(s) need review.")
            },
        );
    }
    if Command::new("yum").arg("--version").output().is_ok() {
        return (
            "yum".to_string(),
            0,
            "YUM host detected. Update count is not precomputed on this node.".to_string(),
        );
    }
    if Command::new("pacman").arg("--version").output().is_ok() {
        return (
            "pacman".to_string(),
            0,
            "Pacman host detected. Use pacman -Syu for full review.".to_string(),
        );
    }
    ("unknown".to_string(), 0, "Package manager was not recognized.".to_string())
}

#[derive(Debug, Clone)]
struct CheckHostNodeSelection {
    hostname: String,
    country_code: String,
    country_name: String,
    city: String,
    ip: String,
}

fn run_server_health_probes(settings: &AppSettings) -> Vec<ServerHealthProbe> {
    let Some(target_host) = detect_server_health_target(settings) else {
        return vec![ServerHealthProbe {
            code: "target".to_string(),
            label: "Public Target".to_string(),
            country_code: "ZZ".to_string(),
            ip: String::new(),
            success: false,
            avg_rtt_ms: None,
            packet_loss_percent: None,
            error: "No public host or IP could be derived for remote health checks.".to_string(),
        }];
    };

    let Ok(nodes) = fetch_check_host_country_nodes() else {
        return vec![ServerHealthProbe {
            code: "check-host".to_string(),
            label: "Check-Host".to_string(),
            country_code: "ZZ".to_string(),
            ip: target_host,
            success: false,
            avg_rtt_ms: None,
            packet_loss_percent: None,
            error: "Unable to load the remote country probe list.".to_string(),
        }];
    };

    if nodes.is_empty() {
        return vec![ServerHealthProbe {
            code: "check-host".to_string(),
            label: "Check-Host".to_string(),
            country_code: "ZZ".to_string(),
            ip: target_host,
            success: false,
            avg_rtt_ms: None,
            packet_loss_percent: None,
            error: "The upstream country probe list was empty.".to_string(),
        }];
    }

    let mut probes = Vec::new();
    for batch in nodes.chunks(24) {
        match run_check_host_ping_batch(&target_host, batch) {
            Ok(mut batch_probes) => probes.append(&mut batch_probes),
            Err(error) => {
                probes.extend(batch.iter().map(|node| ServerHealthProbe {
                    code: node.hostname.clone(),
                    label: format!("{}, {}", node.country_name, node.city),
                    country_code: node.country_code.to_ascii_uppercase(),
                    ip: node.hostname.clone(),
                    success: false,
                    avg_rtt_ms: None,
                    packet_loss_percent: None,
                    error: error.clone(),
                }));
            }
        }
    }
    probes.sort_by(|left, right| {
        left.country_code
            .cmp(&right.country_code)
            .then_with(|| left.label.cmp(&right.label))
    });
    probes
}

fn detect_server_health_target(settings: &AppSettings) -> Option<String> {
    for candidate in [
        settings.public_base_url.trim(),
        settings.admin_base_url.trim(),
    ] {
        if let Some(host) = extract_host_from_url(candidate) {
            if is_public_host_or_ip(&host) {
                return Some(host);
            }
        }
    }

    collect_host_ip_inventory_detailed()
        .into_iter()
        .find(|entry| entry.is_public)
        .map(|entry| entry.address)
}

fn extract_host_from_url(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let remainder = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = remainder.split('/').next().unwrap_or("").trim();
    if authority.is_empty() {
        return None;
    }
    let without_auth = authority.rsplit('@').next().unwrap_or(authority);
    let host = if without_auth.starts_with('[') {
        without_auth
            .split(']')
            .next()
            .map(|value| value.trim_start_matches('[').to_string())
    } else {
        Some(without_auth.split(':').next().unwrap_or("").to_string())
    }?;
    let host = host.trim().trim_matches('/').trim_matches('.').to_string();
    if host.is_empty() { None } else { Some(host) }
}

fn is_public_host_or_ip(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("localhost")
        || trimmed.eq_ignore_ascii_case("127.0.0.1")
    {
        return false;
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(ip) => {
                !(ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_multicast()
                    || ip.is_unspecified())
            }
            IpAddr::V6(ip) => {
                let first_segment = ip.segments()[0];
                !(ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || (first_segment & 0xfe00) == 0xfc00
                    || (first_segment & 0xffc0) == 0xfe80)
            }
        };
    }
    true
}

fn fetch_check_host_country_nodes() -> Result<Vec<CheckHostNodeSelection>, String> {
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "20",
            "-H",
            "Accept: application/json",
            CHECK_HOST_NODES_URL,
        ])
        .output()
        .map_err(|error| format!("failed to load Check-Host nodes: {error}"))?;
    if !output.status.success() {
        return Err("Check-Host nodes request failed".to_string());
    }
    let payload: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("failed to parse Check-Host nodes response: {error}"))?;
    let mut per_country = BTreeMap::<String, CheckHostNodeSelection>::new();
    let Some(nodes) = payload.get("nodes").and_then(Value::as_object) else {
        return Err("Check-Host nodes response did not include a nodes map".to_string());
    };
    for (hostname, info) in nodes {
        if !hostname.contains(".node.check-host.net") {
            continue;
        }
        let location = info
            .get("location")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let country_code = location
            .first()
            .and_then(Value::as_str)
            .unwrap_or("zz")
            .to_string();
        if country_code.trim().is_empty() {
            continue;
        }
        let country_name = location
            .get(1)
            .and_then(Value::as_str)
            .unwrap_or(&country_code)
            .to_string();
        let city = location
            .get(2)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let selection = CheckHostNodeSelection {
            hostname: hostname.clone(),
            country_code: country_code.to_ascii_uppercase(),
            country_name,
            city,
            ip: info
                .get("ip")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        };
        match per_country.get(&selection.country_code) {
            Some(existing) if existing.hostname <= selection.hostname => {}
            _ => {
                per_country.insert(selection.country_code.clone(), selection);
            }
        }
    }
    Ok(per_country.into_values().collect())
}

fn run_check_host_ping_batch(
    target_host: &str,
    nodes: &[CheckHostNodeSelection],
) -> Result<Vec<ServerHealthProbe>, String> {
    let request_id = start_check_host_ping_request(target_host, nodes)?;
    poll_check_host_ping_results(&request_id, nodes)
}

fn start_check_host_ping_request(
    target_host: &str,
    nodes: &[CheckHostNodeSelection],
) -> Result<String, String> {
    let mut command = Command::new("curl");
    command.args([
        "-fsSL",
        "--max-time",
        "20",
        "-H",
        "Accept: application/json",
        "-G",
        CHECK_HOST_PING_URL,
        "--data-urlencode",
        &format!("host={target_host}"),
    ]);
    for node in nodes {
        command.arg("--data-urlencode");
        command.arg(format!("node={}", node.hostname));
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to start Check-Host ping request: {error}"))?;
    if !output.status.success() {
        return Err("Check-Host ping request failed".to_string());
    }
    let payload: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("failed to parse Check-Host request id: {error}"))?;
    let request_id = payload
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if request_id.is_empty() {
        Err("Check-Host returned an empty request id".to_string())
    } else {
        Ok(request_id)
    }
}

fn poll_check_host_ping_results(
    request_id: &str,
    nodes: &[CheckHostNodeSelection],
) -> Result<Vec<ServerHealthProbe>, String> {
    let mut last_value = Value::Null;
    for attempt in 0..6 {
        let output = Command::new("curl")
            .args([
                "-fsSL",
                "--max-time",
                "20",
                "-H",
                "Accept: application/json",
                &format!("{CHECK_HOST_RESULT_URL}{request_id}"),
            ])
            .output()
            .map_err(|error| format!("failed to fetch Check-Host results: {error}"))?;
        if !output.status.success() {
            return Err("Check-Host result request failed".to_string());
        }
        let value: Value = serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("failed to parse Check-Host result payload: {error}"))?;
        let ready_count = nodes
            .iter()
            .filter(|node| value.get(&node.hostname).map(|entry| !entry.is_null()).unwrap_or(false))
            .count();
        last_value = value;
        if ready_count == nodes.len() || attempt == 5 {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    Ok(nodes
        .iter()
        .map(|node| parse_check_host_ping_probe(node, last_value.get(&node.hostname)))
        .collect())
}

fn parse_check_host_ping_probe(
    node: &CheckHostNodeSelection,
    result: Option<&Value>,
) -> ServerHealthProbe {
    let mut ok_samples = 0_u32;
    let mut total_samples = 0_u32;
    let mut rtt_sum = 0.0_f64;
    let mut first_error = String::new();
    let mut observed_target_ip = node.hostname.clone();

    if let Some(value) = result {
        collect_check_host_ping_samples(
            value,
            &mut ok_samples,
            &mut total_samples,
            &mut rtt_sum,
            &mut first_error,
            &mut observed_target_ip,
        );
    } else {
        first_error = "No result was returned by the remote node.".to_string();
    }

    let success = ok_samples > 0;
    let avg_rtt_ms = if ok_samples > 0 {
        Some(rtt_sum / ok_samples as f64 * 1000.0)
    } else {
        None
    };
    let packet_loss_percent = if total_samples > 0 {
        Some(((total_samples - ok_samples) as f64 / total_samples as f64) * 100.0)
    } else {
        None
    };

    ServerHealthProbe {
        code: node.hostname.clone(),
        label: format!("{}, {}", node.country_name, node.city),
        country_code: node.country_code.clone(),
        ip: if observed_target_ip == node.hostname {
            format!("{} • {}", node.hostname, node.ip)
        } else {
            format!("{} → {}", node.hostname, observed_target_ip)
        },
        success,
        avg_rtt_ms,
        packet_loss_percent,
        error: if success { String::new() } else { first_error },
    }
}

fn collect_check_host_ping_samples(
    value: &Value,
    ok_samples: &mut u32,
    total_samples: &mut u32,
    rtt_sum: &mut f64,
    first_error: &mut String,
    observed_target_ip: &mut String,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_check_host_ping_samples(
                    item,
                    ok_samples,
                    total_samples,
                    rtt_sum,
                    first_error,
                    observed_target_ip,
                );
            }
        }
        Value::Null => {
            if first_error.is_empty() {
                *first_error = "The remote node did not finish the ping check in time.".to_string();
            }
        }
        _ => {
            let Some(sample) = value.as_array() else {
                return;
            };
            if sample.is_empty() {
                return;
            }
            if let Some(status) = sample.first().and_then(Value::as_str) {
                *total_samples += 1;
                if status.eq_ignore_ascii_case("OK") {
                    *ok_samples += 1;
                    if let Some(rtt) = sample.get(1).and_then(Value::as_f64) {
                        *rtt_sum += rtt;
                    }
                    if let Some(target_ip) = sample.get(2).and_then(Value::as_str) {
                        *observed_target_ip = target_ip.to_string();
                    }
                } else if first_error.is_empty() {
                    *first_error = status.to_string();
                }
            } else if sample.first().map(Value::is_null).unwrap_or(false) && first_error.is_empty() {
                *first_error = "The remote node could not resolve or complete the ping.".to_string();
            }
        }
    }
}

fn first_command_line(commands: &[(&str, &[&str])]) -> Option<String> {
    for (program, args) in commands {
        let Ok(output) = Command::new(program).args(*args).output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let line = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !line.is_empty() {
            return Some(line);
        }
    }
    None
}

fn merged_monitor_folders(
    stored_folders: Vec<MonitorFolder>,
    checks: &[MonitorCheckRow],
) -> Vec<MonitorFolder> {
    let mut merged = BTreeMap::new();

    for folder in stored_folders {
        merged.insert(folder.name.clone(), folder);
    }

    for row in checks {
        let name = row.display_group.trim();
        if name.is_empty() {
            continue;
        }
        let entry = merged.entry(name.to_string()).or_insert_with(|| MonitorFolder {
            name: name.to_string(),
            logo_url: String::new(),
            logo_shape: "rounded".to_string(),
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
        });
        if entry.logo_url.trim().is_empty() && !row.group_logo_url.trim().is_empty() {
            entry.logo_url = row.group_logo_url.clone();
        }
        if entry.logo_shape == "rounded" && !row.group_logo_shape.trim().is_empty() {
            entry.logo_shape = row.group_logo_shape.clone();
        }
        entry.updated_at_unix = entry.updated_at_unix.max(row.updated_at_unix);
    }

    merged.into_values().collect()
}

fn build_public_payload(
    context: &Arc<AppContext>,
    settings: &AppSettings,
) -> Result<PublicStatusPayload, String> {
    let branding = branding_from_settings(settings);
    let checks = context.db.list_checks()?;
    let effective_rows = effective_checks(&checks);
    let snapshots = context.db.recent_snapshots(settings.public_history_points)?;
    if let Some(snapshot) = snapshots.last() {
        let results = serde_json::from_str::<Vec<CheckResult>>(&snapshot.results_json)
            .map_err(|error| format!("failed to parse stored results: {error}"))?;
        let mut latest_results = build_public_views(&effective_rows, &results);
        append_pending_public_views(&effective_rows, &mut latest_results);
        hydrate_public_history_from_snapshots(&snapshots, &mut latest_results)?;
        let summary = summarize_public_views(&latest_results);
        let mut history = build_public_history(&effective_rows, &snapshots);
        push_latest_public_summary(&mut history, &summary);
        Ok(PublicStatusPayload {
            settings: branding,
            summary,
            latest_results,
            history,
            system_history: Vec::new(),
        })
    } else {
        let mut latest_results = Vec::new();
        append_pending_public_views(&effective_rows, &mut latest_results);
        hydrate_public_history_from_snapshots(&[], &mut latest_results)?;
        let summary = summarize_public_views(&latest_results);
        let mut history = Vec::new();
        push_latest_public_summary(&mut history, &summary);
        Ok(PublicStatusPayload {
            settings: branding,
            summary,
            latest_results,
            history,
            system_history: Vec::new(),
        })
    }
}

fn hydrate_public_history_from_snapshots(
    snapshots: &[StoredSnapshot],
    latest_results: &mut [PublicCheckView],
) -> Result<(), String> {
    if latest_results.is_empty() {
        return Ok(());
    }

    let mut histories = latest_results
        .iter()
        .map(|check| (check.id.clone(), Vec::<PublicCheckHistoryPoint>::new()))
        .collect::<BTreeMap<_, _>>();

    for snapshot in snapshots {
        let results = match serde_json::from_str::<Vec<CheckResult>>(&snapshot.results_json) {
            Ok(results) => results,
            Err(_) => continue,
        };

        let result_map = results
            .iter()
            .map(|result| (result.id.as_str(), result))
            .collect::<BTreeMap<_, _>>();

        for check in latest_results.iter() {
            if let Some(result) = result_map.get(check.id.as_str()) {
                if let Some(history) = histories.get_mut(&check.id) {
                    history.push(PublicCheckHistoryPoint {
                        observed_at_unix: result.observed_at_unix.max(snapshot.created_at_unix),
                        status: result.status,
                        latency_ms: result.latency_ms,
                        message: public_check_message(result.status).to_string(),
                    });
                }
            }
        }
    }

    for check in latest_results.iter_mut() {
        check.history = histories.remove(&check.id).unwrap_or_default();
        if check.history.is_empty() {
            check.history.push(PublicCheckHistoryPoint {
                observed_at_unix: check.observed_at_unix,
                status: check.status,
                latency_ms: check.latency_ms,
                message: check.message.clone(),
            });
        }
    }

    Ok(())
}

fn append_pending_public_views(rows: &[MonitorCheckRow], latest_results: &mut Vec<PublicCheckView>) {
    let existing_ids = latest_results
        .iter()
        .map(|check| check.id.clone())
        .collect::<BTreeSet<_>>();

    for row in rows.iter().filter(|row| row.public_visible) {
        if existing_ids.contains(&row.check_id) {
            continue;
        }
        latest_results.push(PublicCheckView {
            id: row.check_id.clone(),
            label: row.label.clone(),
            kind: canonical_kind_name(&row.kind).to_string(),
            status: CheckStatus::Degraded,
            message: "waiting for the first probe result".to_string(),
            latency_ms: None,
            endpoint: None,
            observed_at_unix: row.updated_at_unix.max(row.created_at_unix),
            history: Vec::new(),
            is_pending: true,
            group_name: row.display_group.clone(),
            group_logo_url: row.group_logo_url.clone(),
            group_logo_shape: row.group_logo_shape.clone(),
        });
    }
}

fn summarize_public_views(latest_results: &[PublicCheckView]) -> SnapshotSummary {
    let observed_at_unix = latest_results
        .iter()
        .map(|check| check.observed_at_unix)
        .max()
        .unwrap_or_else(db::unix_now);
    let mut up_checks = 0;
    let mut degraded_checks = 0;
    let mut down_checks = 0;

    for check in latest_results {
        match check.status {
            CheckStatus::Up => up_checks += 1,
            CheckStatus::Degraded => degraded_checks += 1,
            CheckStatus::Down => down_checks += 1,
        }
    }

    SnapshotSummary {
        observed_at_unix,
        total_checks: latest_results.len(),
        up_checks,
        degraded_checks,
        down_checks,
    }
}

fn build_public_history(rows: &[MonitorCheckRow], snapshots: &[StoredSnapshot]) -> Vec<HistoryPoint> {
    let mut history = Vec::new();

    for snapshot in snapshots {
        let results = match serde_json::from_str::<Vec<CheckResult>>(&snapshot.results_json) {
            Ok(results) => results,
            Err(_) => continue,
        };
        let latest_results = build_public_views(rows, &results);
        if latest_results.is_empty() {
            continue;
        }
        let summary = summarize_public_views(&latest_results);
        history.push(HistoryPoint {
            observed_at_unix: summary.observed_at_unix.max(snapshot.created_at_unix),
            up_checks: summary.up_checks,
            degraded_checks: summary.degraded_checks,
            down_checks: summary.down_checks,
        });
    }

    history
}

fn push_latest_public_summary(history: &mut Vec<HistoryPoint>, summary: &SnapshotSummary) {
    if summary.total_checks == 0 {
        return;
    }

    let next_point = HistoryPoint {
        observed_at_unix: summary.observed_at_unix,
        up_checks: summary.up_checks,
        degraded_checks: summary.degraded_checks,
        down_checks: summary.down_checks,
    };

    let should_push = match history.last() {
        Some(last) => {
            last.observed_at_unix != next_point.observed_at_unix
                || last.up_checks != next_point.up_checks
                || last.degraded_checks != next_point.degraded_checks
                || last.down_checks != next_point.down_checks
        }
        None => true,
    };

    if should_push {
        history.push(next_point);
    }
}

fn run_monitor_cycle(context: &Arc<AppContext>) -> Result<u64, String> {
    let settings = context.db.load_settings()?;
    let rows = context.db.list_checks()?;
    let filtered_rows = effective_checks(&rows);
    let check_labels = filtered_rows
        .iter()
        .map(|row| (row.check_id.clone(), row.label.clone()))
        .collect::<BTreeMap<_, _>>();
    let definitions = load_check_definitions(&filtered_rows)?;
    let cycle_interval_secs = min_check_interval_secs(&definitions);

    let snapshot = {
        let mut runtime = context
            .runtime
            .lock()
            .map_err(|_| "failed to lock runtime state".to_string())?;
        let agent_snapshot = runner::run_cycle(
            &crate::config::AgentConfig {
                agent_id: settings.agent_id.clone(),
                interval_secs: cycle_interval_secs,
                output_file: None,
                history_file: None,
                state_file: None,
                checks: definitions,
            },
            &mut runtime.monitor_state,
        );
        save_persisted_state(&context.state_file, &runtime.monitor_state)?;
        agent_snapshot
    };
    // Interfaces may have been created during this cycle. Retry binding native
    // peer endpoints, and retire listeners for disabled/deleted tunnel monitors.
    if let Err(error) = ensure_local_speedtest_servers(context) {
        eprintln!("native speed-test helper warning: {error}");
    }
    let summary = summarize_results(snapshot.generated_at_unix, &snapshot.results);

    let (system_sample, summary_json, overall_status) = {
        let mut runtime = context
            .runtime
            .lock()
            .map_err(|_| "failed to lock runtime state".to_string())?;
        let (system_sample, cpu, net) =
            collect_system_sample(runtime.previous_cpu, runtime.previous_net)?;
        runtime.previous_cpu = Some(cpu);
        runtime.previous_net = Some(net);
        let summary_json = serialize_summary(&snapshot.results)?;
        let overall_status = derive_overall_status(&snapshot.results);
        (system_sample, summary_json, overall_status)
    };

    context.db.save_snapshot(
        overall_status,
        Some(&system_sample),
        &snapshot.results,
        &summary_json,
    )?;

    if let Err(error) = maybe_process_telegram_notifications(
        context,
        &settings,
        &summary,
        &snapshot.results,
        &check_labels,
    ) {
        eprintln!("telegram notification cycle error: {error}");
    }

    if settings.free_report_enabled {
        if let Err(error) = maybe_run_radar_cycle(context, &settings) {
            eprintln!("radar cycle error: {error}");
        }
    }

    let watchers = context.db.list_traffic_watchers()?;
    if !watchers.is_empty() {
        if let Ok(counters) = read_traffic_watcher_counters(&watchers, cycle_interval_secs) {
            for watcher in watchers {
                if let Some((packets, bytes, current_bps)) = counters.get(&watcher.id).copied() {
                    let _ = context
                        .db
                        .update_traffic_watcher_stats(watcher.id, packets, bytes, current_bps);
                }
            }
        }
    }

    Ok(cycle_interval_secs)
}

fn min_check_interval_secs(definitions: &[CheckDefinition]) -> u64 {
    definitions
        .iter()
        .map(CheckDefinition::interval_secs)
        .min()
        .unwrap_or(60)
        .max(10)
}

fn maybe_run_radar_cycle(context: &Arc<AppContext>, settings: &AppSettings) -> Result<(), String> {
    let now = db::unix_now();
    {
        let runtime = context
            .runtime
            .lock()
            .map_err(|_| "failed to lock runtime state".to_string())?;
        let interval = runtime.monitor_state.radar_interval_secs.max(600);
        if runtime.monitor_state.radar_last_poll_unix > 0
            && now.saturating_sub(runtime.monitor_state.radar_last_poll_unix) < interval
        {
            return Ok(());
        }
    }

    let shared_secret = radar_shared_secret();
    let radar_client = IranMonitorRadarClient::new();
    let radar_config = RadarClientConfig {
        device_label: settings.agent_id.clone(),
        shared_secret,
    };
    let status = radar_client
        .fetch_status(&radar_config)
        .map_err(|error| format!("radar status request failed: {}", error.message))?;
    let results = run_radar_checks(&status.checks)?;
    let report = radar_client
        .send_report(
            &radar_config,
            &radar_asn_from_env(),
            &radar_dc_name_from_env(),
            results,
        )
        .map_err(|error| format!("radar report request failed: {}", error.message))?;

    {
        let mut runtime = context
            .runtime
            .lock()
            .map_err(|_| "failed to lock runtime state".to_string())?;
        runtime.monitor_state.radar_last_poll_unix = now;
        runtime.monitor_state.radar_interval_secs = status.interval_seconds.max(60);
        save_persisted_state(&context.state_file, &runtime.monitor_state)?;
    }

    if !report.ok && !report.message.trim().is_empty() {
        eprintln!("radar report warning: {}", report.message.trim());
    }
    Ok(())
}

fn run_radar_checks(checks: &[RadarStatusCheck]) -> Result<Vec<RadarCheckResult>, String> {
    let mut results = Vec::with_capacity(checks.len());
    for check in checks {
        let tested_at = iso8601_now();
        let result = match check.check_type.to_ascii_lowercase().as_str() {
            "https" => run_radar_https_check(check, &tested_at),
            "icmp" => run_radar_icmp_check(check, &tested_at),
            other => Ok(RadarCheckResult {
                code: check.code.clone(),
                check_type: other.to_string(),
                target: check.target.clone(),
                success: false,
                response_time_ms: None,
                http_status: None,
                error: format!("unsupported radar check type: {other}"),
                tested_at,
                avg_rtt_ms: None,
                packet_loss_percent: None,
                attempts: None,
            }),
        }?;
        results.push(result);
    }
    Ok(results)
}

fn run_radar_https_check(
    check: &RadarStatusCheck,
    tested_at: &str,
) -> Result<RadarCheckResult, String> {
    let timeout_secs = radar_timeout_seconds(check);
    let output = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--connect-timeout")
        .arg(timeout_secs.to_string())
        .arg("--max-time")
        .arg(timeout_secs.to_string())
        .arg("--request")
        .arg("GET")
        .arg("--output")
        .arg("-")
        .arg("--write-out")
        .arg("\n__IMONITOR_Radar_STATUS__:%{http_code}:%{time_total}")
        .arg("--proto")
        .arg("=https")
        .arg("--proto-redir")
        .arg("=https")
        .arg("--proxy")
        .arg("")
        .arg("--noproxy")
        .arg("*")
        .arg(&check.target)
        .output()
        .map_err(|error| format!("failed to execute curl for radar https check: {error}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let summary = if stdout.trim().is_empty() {
        stderr.trim().to_string()
    } else if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        format!("{}\n{}", stdout.trim(), stderr.trim())
    };

    if !output.status.success() {
        return Ok(RadarCheckResult {
            code: check.code.clone(),
            check_type: check.check_type.clone(),
            target: check.target.clone(),
            success: false,
            response_time_ms: None,
            http_status: None,
            error: format!("https request failed: {}", truncate(first_non_empty_line(&summary), 240)),
            tested_at: tested_at.to_string(),
            avg_rtt_ms: None,
            packet_loss_percent: None,
            attempts: None,
        });
    }

    // curl may return an empty body, and trim() removes the newline that
    // precedes --write-out. Match the stable marker itself in both cases.
    let marker = "__IMONITOR_Radar_STATUS__:";
    let marker_index = summary
        .rfind(marker)
        .ok_or_else(|| "curl output did not include a radar status marker".to_string())?;
    let tail = &summary[marker_index + marker.len()..];
    let mut tail_parts = tail.trim().split(':');
    let status_code = tail_parts
        .next()
        .unwrap_or("0")
        .trim()
        .parse::<u16>()
        .unwrap_or(0);
    let time_total = tail_parts
        .next()
        .unwrap_or("0")
        .trim()
        .parse::<f64>()
        .unwrap_or(0.0);

    let success = status_code == 204 || (200..=399).contains(&status_code);
    Ok(RadarCheckResult {
        code: check.code.clone(),
        check_type: check.check_type.clone(),
        target: check.target.clone(),
        success,
        response_time_ms: Some((time_total * 1000.0).max(0.0)),
        http_status: Some(status_code),
        error: if success {
            String::new()
        } else {
            format!("unexpected http status: {status_code}")
        },
        tested_at: tested_at.to_string(),
        avg_rtt_ms: None,
        packet_loss_percent: None,
        attempts: None,
    })
}

fn run_radar_icmp_check(
    check: &RadarStatusCheck,
    tested_at: &str,
) -> Result<RadarCheckResult, String> {
    let attempts = 4_u32;
    let timeout_secs = radar_timeout_seconds(check).max(4);
    let output = Command::new("ping")
        .arg("-n")
        .arg("-c")
        .arg(attempts.to_string())
        .arg("-W")
        .arg(timeout_secs.to_string())
        .arg(&check.target)
        .output()
        .map_err(|error| format!("failed to execute ping for radar icmp check: {error}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let summary = if stdout.trim().is_empty() {
        stderr.trim().to_string()
    } else if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        format!("{}\n{}", stdout.trim(), stderr.trim())
    };

    let packet_loss_percent = parse_ping_packet_loss_percent(&summary);
    let avg_rtt_ms = parse_ping_average_rtt_ms(&summary);
    let success = output.status.success();
    Ok(RadarCheckResult {
        code: check.code.clone(),
        check_type: check.check_type.clone(),
        target: check.target.clone(),
        success,
        response_time_ms: None,
        http_status: None,
        error: if success {
            String::new()
        } else {
            format!("ping failed: {}", truncate(first_non_empty_line(&summary), 240))
        },
        tested_at: tested_at.to_string(),
        avg_rtt_ms,
        packet_loss_percent,
        attempts: Some(attempts),
    })
}

fn radar_timeout_seconds(check: &RadarStatusCheck) -> u64 {
    let details_timeout = check
        .details
        .get("timeout_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(15);
    details_timeout.max(1)
}

fn parse_ping_average_rtt_ms(text: &str) -> Option<f64> {
    let line = text.lines().find(|line| line.contains("min/avg/max"))?;
    let right = line.split('=').nth(1)?.trim();
    let avg = right.split('/').nth(1)?.trim();
    avg.parse::<f64>().ok()
}

fn parse_ping_packet_loss_percent(text: &str) -> Option<f64> {
    for line in text.lines() {
        if line.contains("packet loss") {
            let percent = line.split(',').find_map(|segment| {
                let trimmed = segment.trim();
                if let Some(value) = trimmed.strip_suffix("% packet loss") {
                    return value.trim().parse::<f64>().ok();
                }
                None
            });
            if percent.is_some() {
                return percent;
            }
        }
    }
    None
}

fn radar_shared_secret() -> String {
    std::env::var("IRANMONITOR_RADAR_SHARED_SECRET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| IRANMONITOR_RADAR_DEFAULT_SHARED_SECRET.to_string())
}

fn radar_asn_from_env() -> String {
    std::env::var("IRANMONITOR_RADAR_ASN").unwrap_or_default()
}

fn radar_dc_name_from_env() -> String {
    std::env::var("IRANMONITOR_RADAR_DC_NAME").unwrap_or_default()
}

fn iso8601_now() -> String {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let output = Command::new("date")
        .arg("-u")
        .arg("-d")
        .arg(format!("@{unix}"))
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output();
    match output {
        Ok(result) if result.status.success() => String::from_utf8_lossy(&result.stdout).trim().to_string(),
        _ => unix.to_string(),
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    let mut truncated = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index >= max_chars {
            truncated.push_str("...");
            break;
        }
        truncated.push(ch);
    }
    truncated
}

#[derive(Clone)]
enum TelegramNotificationEvent {
    Failure { result: CheckResult, failures: u32 },
    Recovery { result: CheckResult, failures: u32 },
}

fn maybe_process_telegram_notifications(
    context: &Arc<AppContext>,
    settings: &AppSettings,
    summary: &SnapshotSummary,
    results: &[CheckResult],
    check_labels: &BTreeMap<String, String>,
) -> Result<(), String> {
    if settings.telegram_bot_token.trim().is_empty() {
        return Ok(());
    }
    let admin_chat_ids = parse_telegram_admin_chat_ids(settings);
    if admin_chat_ids.is_empty() {
        return Ok(());
    }

    let threshold = settings.telegram_failure_threshold.max(1);
    let mut notifications = Vec::new();
    let current_offset = {
        let mut runtime = context
            .runtime
            .lock()
            .map_err(|_| "failed to lock runtime state".to_string())?;

        runtime
            .monitor_state
            .failure_counters
            .retain(|check_id, _| results.iter().any(|result| result.id == *check_id));

        for result in results {
            let entry = runtime
                .monitor_state
                .failure_counters
                .entry(result.id.clone())
                .or_insert_with(FailureCounterState::default);

            if entry.last_observed_at_unix == result.observed_at_unix {
                continue;
            }

            if matches!(result.status, CheckStatus::Up) {
                if entry.notified && entry.consecutive_failures >= threshold {
                    notifications.push(TelegramNotificationEvent::Recovery {
                        result: result.clone(),
                        failures: entry.consecutive_failures,
                    });
                }
                entry.consecutive_failures = 0;
                entry.notified = false;
                entry.last_status = Some(CheckStatus::Up);
                entry.last_observed_at_unix = result.observed_at_unix;
                continue;
            }

            if matches!(entry.last_status, Some(CheckStatus::Up)) || entry.consecutive_failures == 0 {
                entry.consecutive_failures = 1;
            } else {
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            }

            if entry.consecutive_failures >= threshold && !entry.notified {
                notifications.push(TelegramNotificationEvent::Failure {
                    result: result.clone(),
                    failures: entry.consecutive_failures,
                });
                entry.notified = true;
            }
            entry.last_status = Some(result.status);
            entry.last_observed_at_unix = result.observed_at_unix;
        }

        save_persisted_state(&context.state_file, &runtime.monitor_state)?;
        runtime.monitor_state.telegram_update_offset
    };

    for notification in notifications {
        let text = build_telegram_notification_text(&notification, check_labels);
        for chat_id in &admin_chat_ids {
            if let Err(error) = send_telegram_message_to_chat(settings, chat_id, &text) {
                eprintln!("telegram alert send error: {error}");
            }
        }
    }

    match process_telegram_updates(
        settings,
        summary,
        results,
        check_labels,
        current_offset,
        &admin_chat_ids,
    ) {
        Ok(next_offset) if next_offset != current_offset => {
            let mut runtime = context
                .runtime
                .lock()
                .map_err(|_| "failed to lock runtime state".to_string())?;
            runtime.monitor_state.telegram_update_offset = next_offset;
            save_persisted_state(&context.state_file, &runtime.monitor_state)?;
        }
        Ok(_) => {}
        Err(error) => eprintln!("telegram bot update error: {error}"),
    }

    Ok(())
}

fn process_telegram_updates(
    settings: &AppSettings,
    summary: &SnapshotSummary,
    results: &[CheckResult],
    check_labels: &BTreeMap<String, String>,
    current_offset: i64,
    admin_chat_ids: &[String],
) -> Result<i64, String> {
    if admin_chat_ids.is_empty() {
        return Ok(current_offset);
    }

    let response = telegram_api_request(
        settings,
        "getUpdates",
        &json!({
            "offset": current_offset,
            "timeout": 0,
            "allowed_updates": ["message"],
        }),
    )?;
    let updates = response
        .get("result")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut next_offset = current_offset;
    for update in updates {
        if let Some(update_id) = update.get("update_id").and_then(Value::as_i64) {
            next_offset = next_offset.max(update_id + 1);
        }
        let message = match update.get("message") {
            Some(message) => message,
            None => continue,
        };
        let chat_id = match message
            .get("chat")
            .and_then(|chat| chat.get("id"))
            .map(telegram_json_scalar)
        {
            Some(chat_id) => chat_id,
            None => continue,
        };
        if !admin_chat_ids.iter().any(|admin_chat_id| admin_chat_id == &chat_id) {
            continue;
        }

        let text = message
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if text.is_empty() {
            continue;
        }

        let command = text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .split('@')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let reply = match command.as_str() {
            "/status" | "/summary" | "/overall" => {
                build_telegram_overall_status_text(settings, summary, results, check_labels)
            }
            "/start" => build_telegram_start_text(settings, summary, results, check_labels),
            "/help" => build_telegram_help_text(),
            _ => format!("Unknown command.\n\n{}", build_telegram_help_text()),
        };

        let _ = send_telegram_message_to_chat(settings, &chat_id, &reply);
    }

    Ok(next_offset)
}

fn build_telegram_help_text() -> String {
    "IranMonitor bot commands:\n/start\n/status\n/summary\n/help".to_string()
}

fn build_telegram_start_text(
    settings: &AppSettings,
    summary: &SnapshotSummary,
    results: &[CheckResult],
    check_labels: &BTreeMap<String, String>,
) -> String {
    if results.is_empty() {
        return format!(
            "{} status\n\nNo monitors found yet. Add a monitor in the panel to get updates.",
            settings.public_title
        );
    }

    let mut active = Vec::new();
    let mut inactive = Vec::new();
    for result in results {
        let label = telegram_check_label(&result.id, check_labels);
        match result.status {
            CheckStatus::Up => active.push(label),
            _ => inactive.push(format!("{} ({})", label, telegram_status_label(result.status))),
        }
    }

    let availability = if summary.total_checks == 0 {
        100.0
    } else {
        (summary.up_checks as f64 / summary.total_checks as f64) * 100.0
    };
    let mut lines = vec![
        format!("{} status", settings.public_title),
        format!("Availability: {:.1}%", availability),
        format!(
            "Total: {} | Up: {} | Degraded: {} | Down: {}",
            summary.total_checks, summary.up_checks, summary.degraded_checks, summary.down_checks
        ),
        format!("Updated: {}", summary.observed_at_unix),
        "".to_string(),
    ];
    if !active.is_empty() {
        lines.push("Active monitors:".to_string());
        for name in active.iter().take(12) {
            lines.push(format!("• {}", name));
        }
        if active.len() > 12 {
            lines.push(format!("…and {} more", active.len() - 12));
        }
    }
    if !inactive.is_empty() {
        if !active.is_empty() {
            lines.push("".to_string());
        }
        lines.push("Non-active monitors:".to_string());
        for name in inactive.iter().take(12) {
            lines.push(format!("• {}", name));
        }
        if inactive.len() > 12 {
            lines.push(format!("…and {} more", inactive.len() - 12));
        }
    }
    lines.join("\n")
}

fn build_telegram_notification_text(
    notification: &TelegramNotificationEvent,
    check_labels: &BTreeMap<String, String>,
) -> String {
    match notification {
        TelegramNotificationEvent::Failure { result, failures } => format!(
            "IranMonitor alert\n\nMonitor: {}\nStatus: {}\nConsecutive failures: {}\nMessage: {}\nEndpoint: {}\nObserved: {}",
            telegram_check_label(&result.id, check_labels),
            telegram_status_label(result.status),
            failures,
            result.message,
            result.endpoint.as_deref().unwrap_or("-"),
            result.observed_at_unix,
        ),
        TelegramNotificationEvent::Recovery { result, failures } => format!(
            "IranMonitor recovery\n\nMonitor: {}\nRecovered after {} failed checks\nLatency: {}\nObserved: {}",
            telegram_check_label(&result.id, check_labels),
            failures,
            result
                .latency_ms
                .map(|value| format!("{value} ms"))
                .unwrap_or_else(|| "-".to_string()),
            result.observed_at_unix,
        ),
    }
}

fn build_telegram_overall_status_text(
    settings: &AppSettings,
    summary: &SnapshotSummary,
    results: &[CheckResult],
    check_labels: &BTreeMap<String, String>,
) -> String {
    let overall = match overall_status_from_counts(
        summary.total_checks,
        summary.up_checks,
        summary.degraded_checks,
        summary.down_checks,
    ) {
        "down" => "Major outage",
        "degraded" => "Issues",
        _ => "Operational",
    };
    let availability = if summary.total_checks == 0 {
        100.0
    } else {
        (summary.up_checks as f64 / summary.total_checks as f64) * 100.0
    };
    let mut lines = vec![
        format!("{} status", settings.public_title),
        format!("Overall: {overall}"),
        format!("Availability: {:.1}%", availability),
        format!(
            "Total: {} | Up: {} | Degraded: {} | Down: {}",
            summary.total_checks, summary.up_checks, summary.degraded_checks, summary.down_checks
        ),
        format!("Updated: {}", summary.observed_at_unix),
    ];
    let failing = results
        .iter()
        .filter(|result| !matches!(result.status, CheckStatus::Up))
        .take(8)
        .collect::<Vec<_>>();
    if !failing.is_empty() {
        lines.push("Affected monitors:".to_string());
        for result in failing {
            lines.push(format!(
                "- {} [{}]: {}",
                telegram_check_label(&result.id, check_labels),
                telegram_status_label(result.status),
                result.message
            ));
        }
    }
    lines.join("\n")
}

fn telegram_check_label(check_id: &str, check_labels: &BTreeMap<String, String>) -> String {
    check_labels
        .get(check_id)
        .cloned()
        .unwrap_or_else(|| check_id.to_string())
}

fn telegram_status_label(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Up => "UP",
        CheckStatus::Down => "DOWN",
        CheckStatus::Degraded => "DEGRADED",
    }
}

fn telegram_json_scalar(value: &Value) -> String {
    if let Some(value) = value.as_str() {
        value.to_string()
    } else if let Some(value) = value.as_i64() {
        value.to_string()
    } else if let Some(value) = value.as_u64() {
        value.to_string()
    } else {
        value.to_string()
    }
}

fn send_telegram_message_to_chat(
    settings: &AppSettings,
    chat_id: &str,
    text: &str,
) -> Result<(), String> {
    let _ = telegram_api_request(
        settings,
        "sendMessage",
        &json!({
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": true,
        }),
    )?;
    Ok(())
}

fn telegram_api_request(
    settings: &AppSettings,
    method: &str,
    payload: &Value,
) -> Result<Value, String> {
    if settings.telegram_bot_token.trim().is_empty() {
        return Err("telegram bot token is not configured".to_string());
    }

    let payload_json = serde_json::to_string(payload)
        .map_err(|error| format!("failed to encode telegram request: {error}"))?;
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

    if !settings.telegram_socks5_host.trim().is_empty() {
        command.arg("--socks5-hostname").arg(format!(
            "{}:{}",
            settings.telegram_socks5_host.trim(),
            settings.telegram_socks5_port
        ));
        if !settings.telegram_socks5_username.trim().is_empty()
            || !settings.telegram_socks5_password.trim().is_empty()
        {
            command.arg("--proxy-user").arg(format!(
                "{}:{}",
                settings.telegram_socks5_username.trim(),
                settings.telegram_socks5_password.trim()
            ));
        }
    }

    let output = command
        .arg("--data")
        .arg(payload_json)
        .arg(format!(
            "https://api.telegram.org/bot{}/{}",
            settings.telegram_bot_token.trim(),
            method.trim()
        ))
        .output()
        .map_err(|error| format!("failed to execute curl for telegram api: {error}"))?;

    if !output.status.success() {
        return Err(
            String::from_utf8_lossy(&output.stderr)
                .trim()
                .to_string(),
        );
    }

    let response: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("failed to parse telegram api response: {error}"))?;
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(response)
    } else {
        Err(response
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("telegram api request failed")
            .to_string())
    }
}

fn telegram_api_request_force_socks(
    settings: &AppSettings,
    method: &str,
    payload: &Value,
) -> Result<Value, String> {
    if settings.telegram_bot_token.trim().is_empty() {
        return Err("telegram bot token is not configured".to_string());
    }
    if settings.telegram_socks5_host.trim().is_empty() {
        return Err("telegram socks5 host is not configured".to_string());
    }

    let payload_json = serde_json::to_string(payload)
        .map_err(|error| format!("failed to encode telegram request: {error}"))?;
    let mut command = Command::new("curl");
    command
        .arg("--silent")
        .arg("--show-error")
        .arg("--max-time")
        .arg("20")
        .arg("--request")
        .arg("POST")
        .arg("--header")
        .arg("Content-Type: application/json")
        .arg("--socks5-hostname")
        .arg(format!(
            "{}:{}",
            settings.telegram_socks5_host.trim(),
            settings.telegram_socks5_port
        ));

    let socks_user = settings.telegram_socks5_username.trim();
    let socks_pass = settings.telegram_socks5_password.trim();
    if !socks_user.is_empty() && !socks_pass.is_empty() {
        command
            .arg("--proxy-user")
            .arg(format!("{socks_user}:{socks_pass}"));
    }

    let output = command
        .arg("--data")
        .arg(payload_json)
        .arg(format!(
            "https://api.telegram.org/bot{}/{}",
            settings.telegram_bot_token.trim(),
            method.trim()
        ))
        .output()
        .map_err(|error| format!("failed to execute curl for telegram api: {error}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let response: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("failed to parse telegram api response: {error}"))?;
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(response)
    } else {
        Err(response
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("telegram api request failed")
            .to_string())
    }
}

fn build_warnings(settings: &AppSettings) -> Vec<String> {
    let mut warnings = Vec::new();
    let admin_chat_ids = parse_telegram_admin_chat_ids(settings);
    if settings.ssl_mode == "reverse_proxy" && settings.reverse_proxy_server_name.trim().is_empty() {
        warnings.push("reverse proxy ssl mode is enabled but no domain/server name is configured".to_string());
    }
    if !settings.telegram_bot_token.trim().is_empty() && admin_chat_ids.is_empty() {
        warnings.push("telegram bot token is configured but no valid telegram admin numeric ids are set".to_string());
    }
    if settings.telegram_bot_token.trim().is_empty() && !admin_chat_ids.is_empty() {
        warnings.push("telegram admin numeric ids are configured but the telegram bot token is empty".to_string());
    }
    warnings
}

/// All configured checks are available without plan restrictions or a count cap.
fn effective_checks(rows: &[MonitorCheckRow]) -> Vec<MonitorCheckRow> {
    rows.iter().filter(|row| row.enabled).cloned().collect()
}

fn load_check_definitions(rows: &[MonitorCheckRow]) -> Result<Vec<CheckDefinition>, String> {
    rows.iter()
        .map(|row| {
            serde_json::from_str::<CheckDefinition>(&row.check_json).map_err(|error| {
                format!("failed to parse check {} from database: {error}", row.check_id)
            })
        })
        .collect()
}

fn derive_overall_status(results: &[CheckResult]) -> &str {
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

    overall_status_from_counts(results.len(), up_checks, degraded_checks, down_checks)
}

fn branding_from_settings(settings: &AppSettings) -> PublicBranding {
    PublicBranding {
        title: settings.public_title.clone(),
        subtitle: settings.public_subtitle.clone(),
        logo_url: settings.logo_url.clone(),
        favicon_url: settings.favicon_url.clone(),
        primary_color: settings.primary_color.clone(),
        secondary_color: settings.secondary_color.clone(),
        background_color: settings.background_color.clone(),
        dark_mode_default: settings.dark_mode_default,
        contact_email: settings.contact_email.clone(),
        contact_telegram: settings.contact_telegram.clone(),
        contact_phone: settings.contact_phone.clone(),
    }
}

fn unauthorized_response(settings: &AppSettings, lang: UiLanguage) -> Response {
    Response::html(
        401,
        views::render_plain_error(
            &branding_from_settings(settings),
            lang,
            "authentication required",
        ),
    )
}

fn authenticated_user_id(context: &Arc<AppContext>, request: &Request) -> Option<i64> {
    let token = request.cookie("im_admin_session")?;
    context.db.session_user_id(token).ok().flatten()
}

fn request_language(request: &Request, default_language: UiLanguage) -> UiLanguage {
    let lang = request.query_value("lang");
    if !lang.is_empty() {
        return UiLanguage::from_str(lang);
    }
    if let Some(cookie_lang) = request.cookie("im_lang") {
        return UiLanguage::from_str(cookie_lang);
    }
    default_language
}

fn update_string_field(request: &Request, name: &str, target: &mut String) {
    if let Some(value) = request.form.get(name) {
        *target = value.trim().to_string();
    }
}

fn parse_form_bool(request: &Request, name: &str, default: bool) -> bool {
    if let Some(value) = request.form.get(name) {
        value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
    } else {
        default
    }
}

fn form_optional(request: &Request, name: &str) -> Option<String> {
    let value = request.form_value(name).trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn form_optional_any(request: &Request, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| form_optional(request, name))
}

fn infer_interface_from_outer_local(local_outer: &str) -> Option<String> {
    let target = local_outer.trim();
    if target.is_empty() {
        return None;
    }

    collect_host_ip_inventory_detailed()
        .into_iter()
        .find(|entry: &HostIpInventoryEntry| entry.address == target)
        .map(|entry| entry.interface)
}

fn default_tunnel_interface_name(protocol: TunnelProtocol, check_id: &str) -> Option<String> {
    if matches!(protocol, TunnelProtocol::Ssh | TunnelProtocol::ReverseSsh) {
        let unit = (stable_positive_u32(check_id) % 4000).max(10);
        return Some(format!("tun{unit}"));
    }

    let prefix = match protocol {
        TunnelProtocol::Gre => "gre",
        TunnelProtocol::Gretap => "gtap",
        TunnelProtocol::Vxlan => "vx",
        TunnelProtocol::Geneve => "gnv",
        TunnelProtocol::Ipv4IpInIp | TunnelProtocol::Ipip => "ipip",
        TunnelProtocol::Ipv6Encapsulation => "sit",
        TunnelProtocol::Etherip => "ethr",
        TunnelProtocol::Encap => "encp",
        TunnelProtocol::L2tp => "l2tp",
        TunnelProtocol::Esp => "xfrm",
        TunnelProtocol::Wireguard => "wg",
        TunnelProtocol::Tun => "tun",
        TunnelProtocol::Ssh | TunnelProtocol::ReverseSsh => unreachable!(),
    };

    let mut hash = 2166136261_u32;
    for byte in check_id.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16777619);
    }
    Some(format!("{prefix}{:06x}", hash & 0x00ff_ffff))
}

fn auto_fill_generated_tunnel_fields(check: &mut TunnelCheck) -> Result<(), String> {
    if matches!(check.protocol, TunnelProtocol::Vxlan | TunnelProtocol::Geneve) {
        check.vni.get_or_insert(42);
        check.transport_port.get_or_insert(if check.protocol == TunnelProtocol::Vxlan { 4789 } else { 6081 });
    }
    if matches!(check.protocol, TunnelProtocol::Tun) {
        if check.tun_transport.is_none() {
            check.tun_transport = Some("udp".to_string());
        }
        if check.transport_port.is_none() {
            check.transport_port = Some(default_generated_tun_port(check, 55_000));
        }
        if check.listen_port.is_none() {
            check.listen_port = Some(default_generated_tun_port(check, 56_000));
        }
        if check.tunnel_key.is_none() {
            check.tunnel_key = Some(format!("im-{:08x}", stable_positive_u32(&check.id)));
        }
    }

    if matches!(check.protocol, TunnelProtocol::Esp)
        && check.esp_key_derivation == crate::config::EspKeyDerivation::Legacy
        && check.tunnel_key.is_none() {
        if let Some(generated) = default_generated_esp_key(check) {
            check.tunnel_key = Some(generated);
        }
    }

    if matches!(check.protocol, TunnelProtocol::Ssh | TunnelProtocol::ReverseSsh) {
        if check.transport_port.is_none() {
            check.transport_port = Some(22);
        }
        if check.ssh_username.is_none() {
            check.ssh_username = Some("root".to_string());
        }
    }

    if matches!(check.protocol, TunnelProtocol::L2tp) {
        let ids = generated_l2tp_identifiers(check);
        check.l2tp_tunnel_id.get_or_insert(ids.local_tunnel_id);
        check
            .l2tp_peer_tunnel_id
            .get_or_insert(ids.peer_tunnel_id);
        check.l2tp_session_id.get_or_insert(ids.local_session_id);
        check
            .l2tp_peer_session_id
            .get_or_insert(ids.peer_session_id);
        if check.transport_port.is_none() {
            check.transport_port = Some(1701);
        }
        if check.l2tp_encapsulation.is_none() {
            check.l2tp_encapsulation = Some("udp".to_string());
        }
    }

    if matches!(check.protocol, TunnelProtocol::Wireguard) {
        if check.transport_port.is_none() {
            check.transport_port = Some(51820);
        }
        if check.listen_port.is_none() {
            check.listen_port = check.transport_port;
        }
        if check.wireguard_private_key.is_none() {
            check.wireguard_private_key = Some(generate_wireguard_secret("genkey")?);
        }
        // WireGuard's optional preshared key must be explicitly shared by both
        // peers. Independent automatic keys make otherwise correct peers fail.
        if check.wireguard_allowed_ips.is_none() {
            if let Some(inner_probe) = check.inner_probe.as_deref() {
                if let Some(allowed_ip) = default_wireguard_allowed_ip(inner_probe) {
                    check.wireguard_allowed_ips = Some(allowed_ip);
                }
            }
        }
    }

    Ok(())
}

struct GeneratedL2tpIdentifiers {
    local_tunnel_id: u32,
    peer_tunnel_id: u32,
    local_session_id: u32,
    peer_session_id: u32,
}

fn default_generated_tun_port(check: &TunnelCheck, base: u16) -> u16 {
    let offset = (stable_positive_u32(&format!(
        "{}|{}|{}|{}",
        check.id,
        check.protocol.as_str(),
        check.local_outer.as_deref().unwrap_or("local"),
        check.outer_remote.as_deref().unwrap_or("remote"),
    )) % 900) as u16;
    base.saturating_add(offset)
}

fn default_generated_esp_key(check: &TunnelCheck) -> Option<String> {
    let seed = esp_shared_seed(check)?;
    Some(format!("0x{:x}", stable_positive_u32(&seed)))
}

fn esp_shared_seed(check: &TunnelCheck) -> Option<String> {
    let local_inner = extract_ip_from_cidr(check.inner_local_cidr.as_deref()?)?;
    let remote_inner = check.inner_probe.as_deref()?.trim();
    if remote_inner.is_empty() {
        return None;
    }
    let (first, second) = normalize_ip_pair(&local_inner, remote_inner)?;
    Some(format!("esp|{first}|{second}"))
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

fn generated_l2tp_identifiers(check: &TunnelCheck) -> GeneratedL2tpIdentifiers {
    let local = check.local_outer.as_deref().unwrap_or("local");
    let remote = check.outer_remote.as_deref().unwrap_or("remote");
    let transport_port = check.transport_port.unwrap_or(1701);
    GeneratedL2tpIdentifiers {
        local_tunnel_id: stable_positive_u32(&format!(
            "l2tp-tunnel|{}|{}|{}|{}",
            check.protocol.as_str(),
            transport_port,
            local,
            remote
        )),
        peer_tunnel_id: stable_positive_u32(&format!(
            "l2tp-tunnel|{}|{}|{}|{}",
            check.protocol.as_str(),
            transport_port,
            remote,
            local
        )),
        local_session_id: stable_positive_u32(&format!(
            "l2tp-session|{}|{}|{}|{}",
            check.protocol.as_str(),
            transport_port,
            local,
            remote
        )),
        peer_session_id: stable_positive_u32(&format!(
            "l2tp-session|{}|{}|{}|{}",
            check.protocol.as_str(),
            transport_port,
            remote,
            local
        )),
    }
}

fn stable_positive_u32(seed: &str) -> u32 {
    let mut hash = 2166136261_u32;
    for byte in seed.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16777619);
    }
    (hash & 0x7fff_ffff).max(1)
}

fn generate_wireguard_secret(mode: &str) -> Result<String, String> {
    let output = Command::new("wg")
        .arg(mode)
        .output()
        .map_err(|error| format!("failed to execute wg {mode}: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            Err(format!("wg {mode} exited with status {}", output.status))
        } else {
            Err(stderr)
        }
    } else {
        let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if secret.is_empty() {
            Err(format!("wg {mode} returned an empty value"))
        } else {
            Ok(secret)
        }
    }
}

fn default_wireguard_allowed_ip(inner_probe: &str) -> Option<String> {
    let target = inner_probe.trim();
    if target.is_empty() {
        return None;
    }
    if target.contains(':') {
        Some(format!("{target}/128"))
    } else if target.chars().all(|character| character.is_ascii_digit() || character == '.') {
        Some(format!("{target}/32"))
    } else {
        None
    }
}

fn apply_uploaded_branding_assets(
    context: &Arc<AppContext>,
    request: &Request,
    settings: &mut AppSettings,
) -> Result<(), String> {
    apply_uploaded_branding_asset(
        request.form_value("logo_upload_data"),
        request.form_value("logo_upload_name"),
        &context.branding_dir.join("logo.png"),
        "logo",
        &mut settings.logo_url,
    )?;
    apply_uploaded_branding_asset(
        request.form_value("favicon_upload_data"),
        request.form_value("favicon_upload_name"),
        &context.branding_dir.join("favicon.ico"),
        "favicon",
        &mut settings.favicon_url,
    )?;
    Ok(())
}

fn apply_uploaded_branding_asset(
    payload: &str,
    upload_name: &str,
    output_path: &Path,
    kind: &str,
    target: &mut String,
) -> Result<(), String> {
    let payload = payload.trim();
    if payload.is_empty() {
        return Ok(());
    }

    let display_name = upload_name.trim();
    let bytes = decode_branding_upload_payload(payload)?;
    normalize_branding_image(&bytes, output_path, kind).map_err(|error| {
        if display_name.is_empty() {
            format!("{kind} upload failed: {error}")
        } else {
            format!("{kind} upload failed for {display_name}: {error}")
        }
    })?;
    *target = output_path.to_string_lossy().to_string();
    Ok(())
}

fn decode_branding_upload_payload(payload: &str) -> Result<Vec<u8>, String> {
    const MAX_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

    let Some(rest) = payload.strip_prefix("data:") else {
        return Err("uploaded image must be submitted as a data URL".to_string());
    };
    let Some((meta, encoded)) = rest.split_once(',') else {
        return Err("uploaded image data URL is invalid".to_string());
    };
    if !meta.to_ascii_lowercase().contains(";base64") {
        return Err("uploaded image must use base64 encoding".to_string());
    }

    let bytes = decode_base64_lenient(encoded)?;
    if bytes.is_empty() {
        return Err("uploaded image is empty".to_string());
    }
    if bytes.len() > MAX_UPLOAD_BYTES {
        return Err(format!(
            "uploaded image is too large (max {} MB)",
            MAX_UPLOAD_BYTES / 1024 / 1024
        ));
    }
    Ok(bytes)
}

fn required_form_value_any(request: &Request, names: &[&str], label: &str) -> Result<String, String> {
    form_optional_any(request, names).ok_or_else(|| format!("{label} is required"))
}

fn parse_u16_value(request: &Request, name: &str, default: u16) -> u16 {
    request
        .form_value(name)
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn parse_u16_value_any(request: &Request, names: &[&str], default: u16) -> u16 {
    names.iter()
        .find_map(|name| {
            request
                .form_value(name)
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|value| *value > 0)
        })
        .unwrap_or(default)
}

fn parse_optional_u16_value(request: &Request, name: &str) -> Option<u16> {
    request
        .form_value(name)
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|value| *value > 0)
}

fn parse_u64_value(request: &Request, name: &str, default: u64) -> u64 {
    request
        .form_value(name)
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn parse_optional_u64_value(request: &Request, name: &str) -> Option<u64> {
    request
        .form_value(name)
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
}

fn default_v2ray_probe_url() -> &'static str {
    "https://www.google.com/generate_204"
}

fn parse_csv_u16(input: &str) -> Vec<u16> {
    input
        .split([',', '\n', ' ', ';'])
        .filter_map(|chunk| chunk.trim().parse::<u16>().ok())
        .collect()
}

fn parse_header_lines(input: &str) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let key = name.trim();
            let val = value.trim();
            if !key.is_empty() && !val.is_empty() {
                headers.insert(key.to_string(), val.to_string());
            }
        }
    }
    headers
}

struct ImportedV2rayProfile {
    proxy_type: ProxyType,
    local_entry_type: Option<LocalEntryType>,
    proxy_host: Option<String>,
    proxy_port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    server_host: Option<String>,
    server_port: Option<u16>,
    server_name: Option<String>,
    transport: Option<String>,
    wireguard_peer: Option<String>,
    inner_probe: Option<String>,
}

fn parse_v2ray_profile_import(
    raw: &str,
    selected_type: ProxyType,
) -> Result<ImportedV2rayProfile, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("imported profile text is empty".to_string());
    }

    if trimmed.starts_with("vmess://") {
        return parse_vmess_import(trimmed);
    }
    if trimmed.starts_with("vless://") {
        return parse_uri_style_import(trimmed, ProxyType::Vless);
    }
    if trimmed.starts_with("trojan://") {
        return parse_uri_style_import(trimmed, ProxyType::Trojan);
    }
    if trimmed.starts_with("ss://") {
        return parse_shadowsocks_import(trimmed);
    }
    if trimmed.starts_with("socks5://") || trimmed.starts_with("socks://") {
        return parse_proxy_url_import(trimmed, ProxyType::Socks5, LocalEntryType::Socks5);
    }
    if trimmed.starts_with("http://") {
        return parse_proxy_url_import(trimmed, ProxyType::Http, LocalEntryType::Http);
    }
    if trimmed.starts_with("https://") {
        return parse_proxy_url_import(trimmed, ProxyType::Https, LocalEntryType::Https);
    }
    if looks_like_wireguard_config(trimmed) {
        return parse_wireguard_import(trimmed);
    }
    if trimmed.contains("://") {
        return parse_generic_xray_import(trimmed, selected_type);
    }

    Err("unsupported import format; paste a vmess/vless/trojan/ss link or a WireGuard config".to_string())
}

fn parse_vmess_import(raw: &str) -> Result<ImportedV2rayProfile, String> {
    let payload = raw
        .trim()
        .strip_prefix("vmess://")
        .ok_or_else(|| "vmess import must start with vmess://".to_string())?;
    let decoded = decode_base64_lenient(payload)?;
    let decoded_text = String::from_utf8(decoded)
        .map_err(|error| format!("vmess import was not valid utf-8: {error}"))?;
    let json: Value = serde_json::from_str(&decoded_text)
        .map_err(|error| format!("failed to parse vmess json payload: {error}"))?;

    let server_host = json_string(&json, &["add", "address", "host"])
        .ok_or_else(|| "vmess import did not contain an address".to_string())?;
    let server_port = json_u16(&json, &["port"])
        .ok_or_else(|| "vmess import did not contain a valid port".to_string())?;
    let server_name = json_string(&json, &["sni", "host"]);

    let mut transport_parts = Vec::new();
    push_transport_part(&mut transport_parts, "network", json_string(&json, &["net"]));
    push_transport_part(&mut transport_parts, "security", json_string(&json, &["tls"]));
    push_transport_part(&mut transport_parts, "header", json_string(&json, &["type"]));
    push_transport_part(&mut transport_parts, "cipher", json_string(&json, &["scy"]));
    push_transport_part(&mut transport_parts, "path", json_string(&json, &["path"]));
    push_transport_part(&mut transport_parts, "tag", json_string(&json, &["ps"]));

    Ok(ImportedV2rayProfile {
        proxy_type: ProxyType::Vmess,
        local_entry_type: None,
        proxy_host: None,
        proxy_port: None,
        username: None,
        password: None,
        server_host: Some(server_host),
        server_port: Some(server_port),
        server_name,
        transport: join_transport_parts(transport_parts),
        wireguard_peer: None,
        inner_probe: None,
    })
}

fn parse_uri_style_import(raw: &str, proxy_type: ProxyType) -> Result<ImportedV2rayProfile, String> {
    let (scheme, remainder) = raw
        .split_once("://")
        .ok_or_else(|| "import uri must contain a scheme".to_string())?;
    let (body_without_fragment, fragment) = split_once_or_self(remainder, '#');
    let (authority, query_text) = split_once_or_self(body_without_fragment, '?');
    let (_, host_port) = authority
        .rsplit_once('@')
        .ok_or_else(|| format!("{scheme} import must contain user@host:port"))?;
    let (server_host, server_port) = parse_host_port(host_port)?;
    let query = parse_url_query(query_text.unwrap_or(""));

    let server_name = first_non_empty(&[
        query.get("sni").cloned(),
        query.get("host").cloned(),
        query.get("servername").cloned(),
        query.get("peer").cloned(),
    ]);

    let mut transport_parts = Vec::new();
    push_transport_part(&mut transport_parts, "type", query.get("type").cloned());
    push_transport_part(&mut transport_parts, "security", query.get("security").cloned());
    push_transport_part(&mut transport_parts, "flow", query.get("flow").cloned());
    push_transport_part(&mut transport_parts, "service", query.get("serviceName").cloned());
    push_transport_part(&mut transport_parts, "path", query.get("path").cloned());
    push_transport_part(&mut transport_parts, "mode", query.get("mode").cloned());
    push_transport_part(&mut transport_parts, "tag", fragment.map(http::url_decode));

    Ok(ImportedV2rayProfile {
        proxy_type,
        local_entry_type: None,
        proxy_host: None,
        proxy_port: None,
        username: None,
        password: None,
        server_host: Some(server_host),
        server_port: Some(server_port),
        server_name,
        transport: join_transport_parts(transport_parts),
        wireguard_peer: None,
        inner_probe: None,
    })
}

fn parse_shadowsocks_import(raw: &str) -> Result<ImportedV2rayProfile, String> {
    let payload = raw
        .trim()
        .strip_prefix("ss://")
        .ok_or_else(|| "shadowsocks import must start with ss://".to_string())?;
    let (body_without_fragment, fragment) = split_once_or_self(payload, '#');
    let (body, query_text) = split_once_or_self(body_without_fragment, '?');

    let decoded_body = if body.contains('@') {
        let (left, right) = body
            .rsplit_once('@')
            .ok_or_else(|| "invalid shadowsocks authority".to_string())?;
        if left.contains(':') {
            format!("{left}@{right}")
        } else {
            let decoded_left = decode_base64_text(left, "shadowsocks credentials")?;
            format!("{decoded_left}@{right}")
        }
    } else {
        decode_base64_text(body, "shadowsocks body")?
    };

    let (credentials, host_port) = decoded_body
        .rsplit_once('@')
        .ok_or_else(|| "shadowsocks import must contain method:password@host:port".to_string())?;
    let (method, _password) = credentials
        .split_once(':')
        .ok_or_else(|| "shadowsocks credentials must look like method:password".to_string())?;
    let (server_host, server_port) = parse_host_port(host_port)?;
    let query = parse_url_query(query_text.unwrap_or(""));

    let mut transport_parts = Vec::new();
    push_transport_part(&mut transport_parts, "method", Some(method.to_string()));
    push_transport_part(&mut transport_parts, "plugin", query.get("plugin").cloned());
    push_transport_part(&mut transport_parts, "tag", fragment.map(http::url_decode));

    Ok(ImportedV2rayProfile {
        proxy_type: ProxyType::Shadowsocks,
        local_entry_type: None,
        proxy_host: None,
        proxy_port: None,
        username: None,
        password: None,
        server_host: Some(server_host),
        server_port: Some(server_port),
        server_name: None,
        transport: join_transport_parts(transport_parts),
        wireguard_peer: None,
        inner_probe: None,
    })
}

fn parse_proxy_url_import(
    raw: &str,
    proxy_type: ProxyType,
    local_entry_type: LocalEntryType,
) -> Result<ImportedV2rayProfile, String> {
    let (scheme, remainder) = raw
        .split_once("://")
        .ok_or_else(|| "proxy import must contain a scheme".to_string())?;
    let (body_without_fragment, _fragment) = split_once_or_self(remainder, '#');
    let (authority, _query) = split_once_or_self(body_without_fragment, '?');
    let (userinfo, host_port) = authority.rsplit_once('@').unwrap_or(("", authority));
    let (proxy_host, proxy_port) = parse_host_port(host_port)?;
    let (username, password) = if userinfo.is_empty() {
        (None, None)
    } else if let Some((user, pass)) = userinfo.split_once(':') {
        (Some(http::url_decode(user)), Some(http::url_decode(pass)))
    } else {
        (Some(http::url_decode(userinfo)), None)
    };

    let mut transport_parts = Vec::new();
    push_transport_part(&mut transport_parts, "scheme", Some(scheme.to_string()));

    Ok(ImportedV2rayProfile {
        proxy_type,
        local_entry_type: Some(local_entry_type),
        proxy_host: Some(proxy_host),
        proxy_port: Some(proxy_port),
        username,
        password,
        server_host: None,
        server_port: None,
        server_name: None,
        transport: join_transport_parts(transport_parts),
        wireguard_peer: None,
        inner_probe: None,
    })
}

fn parse_generic_xray_import(
    raw: &str,
    _selected_type: ProxyType,
) -> Result<ImportedV2rayProfile, String> {
    let (scheme, remainder) = raw
        .split_once("://")
        .ok_or_else(|| "import uri must contain a scheme".to_string())?;
    let normalized_scheme = scheme.trim().to_ascii_lowercase();
    match normalized_scheme.as_str() {
        "vmess" => parse_vmess_import(raw),
        "vless" => parse_uri_style_import(raw, ProxyType::Vless),
        "trojan" => parse_uri_style_import(raw, ProxyType::Trojan),
        "ss" => parse_shadowsocks_import(raw),
        "socks" | "socks5" => parse_proxy_url_import(raw, ProxyType::Socks5, LocalEntryType::Socks5),
        "http" => parse_proxy_url_import(raw, ProxyType::Http, LocalEntryType::Http),
        "https" => parse_proxy_url_import(raw, ProxyType::Https, LocalEntryType::Https),
        _ => {
            let (body_without_fragment, fragment) = split_once_or_self(remainder, '#');
            let (authority, query_text) = split_once_or_self(body_without_fragment, '?');
            let host_port = authority.rsplit_once('@').map(|(_, value)| value).unwrap_or(authority);
            let (server_host, server_port) = parse_host_port(host_port)?;
            let query = parse_url_query(query_text.unwrap_or(""));

            let mut transport_parts = Vec::new();
            push_transport_part(&mut transport_parts, "scheme", Some(normalized_scheme));
            push_transport_part(&mut transport_parts, "type", query.get("type").cloned());
            push_transport_part(&mut transport_parts, "security", query.get("security").cloned());
            push_transport_part(&mut transport_parts, "path", query.get("path").cloned());
            push_transport_part(&mut transport_parts, "tag", fragment.map(http::url_decode));

            Ok(ImportedV2rayProfile {
                proxy_type: ProxyType::OtherV2ray,
                local_entry_type: None,
                proxy_host: None,
                proxy_port: None,
                username: None,
                password: None,
                server_host: Some(server_host),
                server_port: Some(server_port),
                server_name: first_non_empty(&[
                    query.get("sni").cloned(),
                    query.get("host").cloned(),
                    query.get("peer").cloned(),
                ]),
                transport: join_transport_parts(transport_parts),
                wireguard_peer: None,
                inner_probe: None,
            })
        }
    }
}

fn parse_wireguard_import(raw: &str) -> Result<ImportedV2rayProfile, String> {
    let mut section = "";
    let mut address = None;
    let mut dns = None;
    let mut mtu = None;
    let mut allowed_ips = None;
    let mut peer_public_key = None;
    let mut endpoint = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.eq_ignore_ascii_case("[Interface]") {
            section = "interface";
            continue;
        }
        if trimmed.eq_ignore_ascii_case("[Peer]") {
            section = "peer";
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        match (section, key.as_str()) {
            ("interface", "address") => {
                address = value
                    .split(',')
                    .next()
                    .map(|chunk| chunk.trim().to_string())
                    .filter(|chunk| !chunk.is_empty());
            }
            ("interface", "dns") => dns = Some(value),
            ("interface", "mtu") => mtu = Some(value),
            ("peer", "allowedips") => allowed_ips = Some(value),
            ("peer", "publickey") => peer_public_key = Some(value),
            ("peer", "endpoint") => endpoint = Some(value),
            _ => {}
        }
    }

    let endpoint_text = endpoint.ok_or_else(|| "wireguard config did not contain an Endpoint".to_string())?;
    let (server_host, server_port) = parse_host_port(&endpoint_text)?;

    let mut transport_parts = vec!["transport=udp".to_string()];
    push_transport_part(&mut transport_parts, "address", address.clone());
    push_transport_part(&mut transport_parts, "dns", dns);
    push_transport_part(&mut transport_parts, "mtu", mtu);
    push_transport_part(&mut transport_parts, "allowed", allowed_ips);

    Ok(ImportedV2rayProfile {
        proxy_type: ProxyType::Wireguard,
        local_entry_type: None,
        proxy_host: None,
        proxy_port: None,
        username: None,
        password: None,
        server_host: Some(server_host),
        server_port: Some(server_port),
        server_name: None,
        transport: join_transport_parts(transport_parts),
        wireguard_peer: peer_public_key,
        inner_probe: None,
    })
}

fn looks_like_wireguard_config(raw: &str) -> bool {
    raw.contains("[Interface]")
        || raw.contains("[Peer]")
        || (raw.contains("PrivateKey =") && raw.contains("Endpoint ="))
}

fn decode_base64_text(raw: &str, label: &str) -> Result<String, String> {
    let decoded = decode_base64_lenient(raw)?;
    String::from_utf8(decoded).map_err(|error| format!("{label} was not valid utf-8: {error}"))
}

fn parse_host_port(raw: &str) -> Result<(String, u16), String> {
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

fn parse_url_query(input: &str) -> BTreeMap<String, String> {
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

fn push_transport_part(parts: &mut Vec<String>, label: &str, value: Option<String>) {
    let Some(value) = value.map(|item| item.trim().to_string()) else {
        return;
    };
    if value.is_empty() {
        return;
    }
    parts.push(format!("{label}={value}"));
}

fn join_transport_parts(parts: Vec<String>) -> Option<String> {
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

fn first_non_empty(values: &[Option<String>]) -> Option<String> {
    values
        .iter()
        .filter_map(|value| value.as_ref())
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn json_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        let Some(candidate) = value.get(*key) else {
            continue;
        };
        match candidate {
            Value::String(text) if !text.trim().is_empty() => return Some(text.trim().to_string()),
            Value::Number(number) => return Some(number.to_string()),
            _ => {}
        }
    }
    None
}

fn json_u16(value: &Value, keys: &[&str]) -> Option<u16> {
    for key in keys {
        let Some(candidate) = value.get(*key) else {
            continue;
        };
        match candidate {
            Value::Number(number) => {
                if let Some(raw) = number.as_u64() {
                    if raw > 0 && raw <= u16::MAX as u64 {
                        return Some(raw as u16);
                    }
                }
            }
            Value::String(text) => {
                if let Ok(raw) = text.trim().parse::<u16>() {
                    if raw > 0 {
                        return Some(raw);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn slugify_check_id(raw: &str, fallback: &str) -> String {
    let source = if raw.trim().is_empty() { fallback } else { raw };
    let mut slug = String::new();
    let mut last_dash = false;

    for ch in source.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if (ch.is_ascii_whitespace() || matches!(ch, '-' | '_' | '.')) && !last_dash {
            slug.push('-');
            last_dash = true;
        }
    }

    slug.trim_matches('-').to_string()
}

fn apply_theme_preset_selection(request: &Request, settings: &mut AppSettings) {
    let Some(preset) = request.form.get("theme_preset").map(|value| value.trim()) else {
        return;
    };

    let (primary, secondary, background) = match preset {
        "custom" => return,
        "green_night" => ("#22c55e", "#16a34a", "#06110a"),
        "ocean_night" => ("#38bdf8", "#0ea5e9", "#07111b"),
        "amber_night" => ("#f59e0b", "#d97706", "#140d04"),
        "graphite_night" => ("#a3e635", "#65a30d", "#0c0f0b"),
        "ruby_night" => ("#fb7185", "#e11d48", "#13070a"),
        "purple_night" => ("#a855f7", "#7e22ce", "#12061a"),
        "teal_night" => ("#2dd4bf", "#0f766e", "#05110f"),
        "slate_night" => ("#94a3b8", "#475569", "#0b1120"),
        _ => return,
    };

    settings.primary_color = primary.to_string();
    settings.secondary_color = secondary.to_string();
    settings.background_color = background.to_string();
}

fn build_check_definition_from_form(request: &Request) -> Result<CheckDefinition, String> {
    let kind = request.form_value("kind").trim().to_ascii_lowercase();
    if kind.is_empty() {
        return Err("monitor type is required".to_string());
    }

    let label = request.form_value("label").trim();
    let check_id = slugify_check_id(request.form_value("check_id"), label);
    if check_id.is_empty() {
        return Err("check id or label is required".to_string());
    }

    let interval_secs = parse_u64_value(request, "interval_secs", 60).max(10);
    let ip_version = IpVersion::from_str(request.form_value("ip_version"));
    let timeout_ms = parse_u64_value(request, "timeout_ms", 3_000);

    match kind.as_str() {
        "icmp" => Ok(CheckDefinition::Icmp(IcmpCheck {
            id: check_id,
            interval_secs,
            target: required_form_value_any(request, &["target", "simple_target"], "target")?,
            ip_version,
            timeout_ms,
        })),
        "tcp" => Ok(CheckDefinition::Tcp(SocketCheck {
            id: check_id,
            interval_secs,
            target: required_form_value_any(request, &["target", "simple_target"], "target")?,
            port: parse_u16_value_any(request, &["port", "simple_port"], 80),
            ip_version,
            timeout_ms,
        })),
        "udp" => Ok(CheckDefinition::Udp(UdpCheck {
            id: check_id,
            interval_secs,
            target: required_form_value_any(request, &["target", "simple_target"], "target")?,
            port: parse_u16_value_any(request, &["port", "simple_port"], 53),
            ip_version,
            timeout_ms,
            payload: form_optional(request, "udp_payload"),
            expect_response: parse_form_bool(request, "expect_response", false),
            response_contains: form_optional(request, "response_contains"),
        })),
        "ssh" => Ok(CheckDefinition::Ssh(SshCheck {
            id: check_id,
            interval_secs,
            target: required_form_value_any(request, &["target", "simple_target"], "target")?,
            port: parse_u16_value_any(request, &["port", "simple_port"], 22),
            ip_version,
            timeout_ms,
            expect_banner_prefix: form_optional(request, "expect_banner_prefix"),
        })),
        "sftp" => Ok(CheckDefinition::Sftp(SshCheck {
            id: check_id,
            interval_secs,
            target: required_form_value_any(request, &["target", "simple_target"], "target")?,
            port: parse_u16_value_any(request, &["port", "simple_port"], 22),
            ip_version,
            timeout_ms,
            expect_banner_prefix: form_optional(request, "expect_banner_prefix"),
        })),
        "http" | "https" => {
            let host = required_form_value_any(request, &["host", "simple_host"], "host")?;
            let path = form_optional(request, "path").unwrap_or_else(|| "/".to_string());
            let method = form_optional(request, "method").unwrap_or_else(|| "GET".to_string());
            let check = WebCheck {
                id: check_id,
                interval_secs,
                host,
                connect_host: form_optional(request, "connect_host"),
                host_header: form_optional(request, "host_header"),
                tls_server_name: form_optional(request, "tls_server_name"),
                port: parse_optional_u16_value(request, "port"),
                method,
                path,
                headers: parse_header_lines(request.form_value("headers")),
                expected_status: parse_csv_u16(request.form_value("expected_status")),
                body_contains: form_optional(request, "body_contains"),
                ip_version,
                timeout_ms,
            };
            if kind == "http" {
                Ok(CheckDefinition::Http(check))
            } else {
                Ok(CheckDefinition::Https(check))
            }
        }
        "dns" => Ok(CheckDefinition::Dns(DnsCheck {
            id: check_id,
            interval_secs,
            server: form_optional(request, "dns_server").unwrap_or_else(|| "1.1.1.1".to_string()),
            port: parse_u16_value(request, "dns_port", 53),
            record_name: required_form_value_any(request, &["record_name", "simple_record_name"], "record name")?,
            record_type: DnsRecordType::from_str(request.form_value("record_type")),
            expect_answers_min: parse_u16_value(request, "expect_answers_min", 1),
            ip_version,
            timeout_ms,
        })),
        "rdp" => Ok(CheckDefinition::Rdp(RdpCheck {
            id: check_id,
            interval_secs,
            target: required_form_value_any(request, &["target", "simple_target"], "target")?,
            port: parse_u16_value_any(request, &["port", "simple_port"], 3389),
            ip_version,
            timeout_ms,
        })),
        "ftp" => Ok(CheckDefinition::Ftp(FtpCheck {
            id: check_id,
            interval_secs,
            target: required_form_value_any(request, &["target", "simple_target"], "target")?,
            port: parse_u16_value_any(request, &["port", "simple_port"], 21),
            ip_version,
            timeout_ms,
            username: form_optional(request, "username"),
            password: form_optional(request, "password"),
        })),
        "tunnel" => {
            let protocol = TunnelProtocol::from_str(
                form_optional_any(request, &["tunnel_protocol", "simple_tunnel_protocol"])
                    .unwrap_or_else(|| "gre".to_string())
                    .as_str(),
            )?;
            let manual_interface = form_optional(request, "interface");
            let interface =
                manual_interface.clone().or_else(|| default_tunnel_interface_name(protocol, &check_id));
            let outer_remote = form_optional_any(request, &["outer_remote", "simple_outer_remote"]);
            let local_outer = form_optional(request, "local_outer");
            let inner_probe = form_optional_any(request, &["inner_probe", "simple_inner_probe"]);
            if manual_interface.is_none() && outer_remote.is_none() && inner_probe.is_none() {
                return Err(
                    "tunnel monitor needs at least an interface, outer remote, or inner probe"
                        .to_string(),
                );
            }
            let source_interface = form_optional(request, "source_interface")
                .or_else(|| local_outer.as_deref().and_then(infer_interface_from_outer_local));
            let mut check = TunnelCheck {
                id: check_id,
                interval_secs,
                protocol,
                interface,
                auto_create_interface: parse_form_bool(request, "auto_create_interface", true),
                outer_remote,
                local_outer,
                inner_probe,
                source_interface,
                inner_local_cidr: form_optional_any(
                    request,
                    &["inner_local_cidr", "simple_inner_local_cidr"],
                ),
                mtu: parse_optional_tunnel_number(request, "mtu")?,
                ttl: parse_optional_tunnel_number(request, "ttl")?,
                traffic_class: parse_optional_tunnel_number(request, "traffic_class")?,
                vni: parse_optional_tunnel_number(request, "vni")?,
                tun_lanes: parse_optional_tunnel_number(request, "tun_lanes")?,
                speedtest_token: form_optional(request, "speedtest_token"),
                speedtest_port: match request.form_value("speedtest_port").trim() {
                    "" => crate::speedtest::DEFAULT_PORT,
                    value => value.parse::<u16>().map_err(|_| "Speed-test port must be between 1 and 65535.".to_string())?,
                },
                tunnel_key: form_optional(request, "tunnel_key"),
                esp_key_derivation: match request.form_value("esp_key_derivation").trim() {
                    "" | "legacy" => crate::config::EspKeyDerivation::Legacy,
                    "hkdf_sha256" => crate::config::EspKeyDerivation::HkdfSha256,
                    _ => return Err("Unknown ESP key derivation. Choose legacy or hkdf_sha256.".to_string()),
                },
                esp_cipher: match request.form_value("esp_cipher").trim() {
                    "" | "aes_cbc_hmac_sha256" => crate::config::EspCipher::AesCbcHmacSha256,
                    "legacy_aes_gcm" => crate::config::EspCipher::LegacyAesGcm,
                    _ => return Err("Unknown ESP cipher. Choose aes_cbc_hmac_sha256 or preserve legacy_aes_gcm.".to_string()),
                },
                tun_transport: form_optional(request, "tun_transport"),
                transport_port: parse_optional_tunnel_number(request, "transport_port")?,
                listen_port: parse_optional_tunnel_number(request, "listen_port")?,
                l2tp_tunnel_id: parse_optional_tunnel_number(request, "l2tp_tunnel_id")?,
                l2tp_peer_tunnel_id: parse_optional_tunnel_number(request, "l2tp_peer_tunnel_id")?,
                l2tp_session_id: parse_optional_tunnel_number(request, "l2tp_session_id")?,
                l2tp_peer_session_id: parse_optional_tunnel_number(request, "l2tp_peer_session_id")?,
                l2tp_encapsulation: form_optional(request, "l2tp_encapsulation"),
                wireguard_private_key: form_optional(request, "wireguard_private_key"),
                wireguard_peer_public_key: form_optional(request, "wireguard_peer_public_key"),
                wireguard_preshared_key: form_optional(request, "wireguard_preshared_key"),
                wireguard_allowed_ips: form_optional(request, "wireguard_allowed_ips"),
                ssh_username: form_optional(request, "ssh_username"),
                ssh_password: form_optional(request, "ssh_password"),
                ssh_private_key: form_optional(request, "ssh_private_key"),
                ip_version,
                timeout_ms,
                expected_operstate: form_optional(request, "expected_operstate")
                    .unwrap_or_else(|| "up".to_string()),
                require_bidirectional_traffic: parse_form_bool(
                    request,
                    "require_bidirectional_traffic",
                    true,
                ),
                min_rx_packets_delta: parse_u64_value(request, "min_rx_packets_delta", 1),
                min_tx_packets_delta: parse_u64_value(request, "min_tx_packets_delta", 1),
            };
            auto_fill_generated_tunnel_fields(&mut check)?;
            crate::runner::validate_tunnel_configuration(&check)?;
            validate_tunnel_speedtest(&check)?;
            Ok(CheckDefinition::Tunnel(check))
        }
        "v2ray" | "v2ray_simulation" => {
            let selected_proxy_type = ProxyType::from_str(
                form_optional_any(request, &["proxy_type", "simple_proxy_type"])
                    .unwrap_or_else(|| "vless".to_string())
                    .as_str(),
            );
            let profile_import = form_optional_any(request, &["profile_import", "simple_profile_import"]);
            let imported_profile = profile_import
                .as_ref()
                .map(|raw| parse_v2ray_profile_import(raw, selected_proxy_type))
                .transpose()?;

            let mut proxy_type = selected_proxy_type;
            let mut local_entry_type =
                LocalEntryType::from_str(request.form_value("local_entry_type"));
            let mut proxy_host = form_optional(request, "proxy_host");
            let mut proxy_port = parse_optional_u16_value(request, "proxy_port");
            let mut test_url = form_optional(request, "test_url");
            let mut username = form_optional(request, "username");
            let mut password = form_optional(request, "password");
            let mut server_host = form_optional(request, "server_host");
            let mut server_port = parse_optional_u16_value(request, "server_port");
            let mut server_name = form_optional(request, "server_name");
            let mut transport = form_optional(request, "transport");
            let wireguard_interface = form_optional(request, "wireguard_interface");
            let mut wireguard_peer = form_optional(request, "wireguard_peer");
            let mut inner_probe = form_optional(request, "inner_probe");

            if let Some(imported_profile) = imported_profile {
                proxy_type = imported_profile.proxy_type;
                if let Some(imported_local_entry_type) = imported_profile.local_entry_type {
                    local_entry_type = imported_local_entry_type;
                }
                proxy_host = proxy_host.or(imported_profile.proxy_host);
                proxy_port = proxy_port.or(imported_profile.proxy_port);
                username = username.or(imported_profile.username);
                password = password.or(imported_profile.password);
                server_host = server_host.or(imported_profile.server_host);
                server_port = server_port.or(imported_profile.server_port);
                server_name = server_name.or(imported_profile.server_name);
                transport = transport.or(imported_profile.transport);
                wireguard_peer = wireguard_peer.or(imported_profile.wireguard_peer);
                inner_probe = inner_probe.or(imported_profile.inner_probe);
            }

            let can_auto_provision_local_entry = profile_import
                .as_ref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
                && matches!(
                    proxy_type,
                    ProxyType::Vmess
                        | ProxyType::Vless
                        | ProxyType::Trojan
                        | ProxyType::Shadowsocks
                )
                && !matches!(local_entry_type, LocalEntryType::Direct);
            if can_auto_provision_local_entry {
                if proxy_host.is_none() {
                    proxy_host = Some("127.0.0.1".to_string());
                }
                if proxy_port.is_none() {
                    proxy_port = Some(pick_free_tcp_port("127.0.0.1", 50_000, 60_000)?);
                }
                if test_url.is_none() {
                    test_url = Some(default_v2ray_probe_url().to_string());
                }
            }

            let has_proxy_socket = proxy_host.is_some() && proxy_port.is_some();
            if has_proxy_socket && test_url.is_none() && !matches!(local_entry_type, LocalEntryType::Direct) {
                test_url = Some(default_v2ray_probe_url().to_string());
            }

            match proxy_type {
                ProxyType::Socks5 | ProxyType::Http | ProxyType::Https => {
                    if proxy_host.is_none() || proxy_port.is_none() {
                        return Err(
                            "proxy simulation needs a proxy host and proxy port"
                                .to_string(),
                        );
                    }
                }
                ProxyType::Wireguard => {
                    let has_endpoint_listener = server_host.is_some() && server_port.is_some();
                    if wireguard_interface.is_none() && inner_probe.is_none() && !has_endpoint_listener {
                        return Err(
                            "wireguard simulation needs a WireGuard interface, an inner probe, or an imported endpoint"
                                .to_string(),
                        );
                    }
                }
                _ => {
                    let has_local_entry = !matches!(local_entry_type, LocalEntryType::Direct)
                        && proxy_host.is_some()
                        && proxy_port.is_some();
                    let has_direct_listener = server_host.is_some() && server_port.is_some();
                    if !has_local_entry
                        && has_direct_listener
                        && !matches!(local_entry_type, LocalEntryType::Direct)
                    {
                        return Err(
                            "for VMess/VLESS/Trojan/Shadowsocks, choose Direct listener only if you intentionally want a listener reachability check instead of a real local-entry simulation"
                                .to_string(),
                        );
                    }
                    if !has_local_entry && !has_direct_listener {
                        return Err(
                            "VMess/VLESS/Trojan-style simulation needs either a local entry host/port or a remote server host/port"
                                .to_string(),
                        );
                    }
                }
            }

            Ok(CheckDefinition::V2raySimulation(V2raySimulationCheck {
                id: check_id,
                interval_secs,
                proxy_type,
                local_entry_type,
                profile_import,
                proxy_host,
                proxy_port,
                test_url,
                username,
                password,
                expected_status: parse_csv_u16(request.form_value("expected_status")),
                body_contains: form_optional(request, "body_contains"),
                server_host,
                server_port,
                server_name,
                transport,
                wireguard_interface,
                wireguard_peer,
                inner_probe,
                source_interface: form_optional(request, "source_interface"),
                max_handshake_age_secs: parse_optional_u64_value(request, "max_handshake_age_secs"),
                ip_version,
                timeout_ms,
            }))
        }
        _ => Err(format!("unsupported monitor type: {kind}")),
    }
}

fn parse_optional_tunnel_number<T: std::str::FromStr>(request: &Request, field: &str) -> Result<Option<T>, String> {
    let value = request.form_value(field).trim();
    if value.is_empty() { return Ok(None); }
    value.parse::<T>().map(Some).map_err(|_| format!("Tunnel {} must be a valid whole number within its supported range.", field.replace('_', " ")))
}

fn collect_live_dashboard_sample(context: &Arc<AppContext>) -> Result<SystemSample, String> {
    let mut live_metrics = context
        .live_metrics
        .lock()
        .map_err(|_| "failed to lock live dashboard state".to_string())?;

    let (sample, cpu, net) = collect_system_sample(
        live_metrics.previous_cpu,
        live_metrics.previous_net,
    )?;
    live_metrics.previous_cpu = Some(cpu);
    live_metrics.previous_net = Some(net);
    Ok(sample)
}

fn load_persisted_state(path: &Path) -> Result<PersistedState, String> {
    if !path.exists() {
        return Ok(PersistedState::default());
    }
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read persisted state {}: {error}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|error| format!("failed to parse persisted state {}: {error}", path.display()))
}

fn save_persisted_state(path: &Path, state: &PersistedState) -> Result<(), String> {
    ensure_parent_dir(path.to_string_lossy().as_ref())?;
    let body = serde_json::to_string_pretty(state)
        .map_err(|error| format!("failed to serialize monitor state: {error}"))?;
    fs::write(path, body)
        .map_err(|error| format!("failed to write persisted state {}: {error}", path.display()))
}

fn seed_default_checks(db: &Database) -> Result<(), String> {
    let defaults = vec![
        (
            "Google HTTPS",
            true,
            true,
            r#"{"kind":"https","id":"google-https","host":"www.google.com","ip_version":"ipv4","path":"/","expected_status":[200,301,302]}"#,
        ),
        (
            "Cloudflare DNS",
            true,
            true,
            r#"{"kind":"dns","id":"cloudflare-dns","server":"1.1.1.1","ip_version":"ipv4","record_name":"example.com","record_type":"a","expect_answers_min":1}"#,
        ),
        (
            "V2Ray Example",
            false,
            false,
            r#"{"kind":"v2ray","id":"vless-local-entry-example","proxy_type":"vless","local_entry_type":"socks5","proxy_host":"127.0.0.1","proxy_port":1080,"server_host":"edge.example.com","server_port":443,"server_name":"edge.example.com","transport":"tcp+tls","test_url":"https://www.google.com/generate_204","expected_status":[204],"ip_version":"ipv4","timeout_ms":4000}"#,
        ),
    ];

    for (label, enabled, public_visible, json_text) in defaults {
        let definition = serde_json::from_str::<CheckDefinition>(json_text)
            .map_err(|error| format!("failed to seed default check: {error}"))?;
        db.upsert_check(&MonitorCheckRow {
            db_id: 0,
            check_id: definition.id().to_string(),
            label: label.to_string(),
            kind: definition.kind_name().to_string(),
                enabled,
            public_visible,
            display_group: String::new(),
            group_logo_url: String::new(),
            group_logo_shape: "rounded".to_string(),
            check_json: json_text.to_string(),
            created_at_unix: db::unix_now(),
            updated_at_unix: db::unix_now(),
        })?;
    }
    Ok(())
}

fn ensure_dir(path: &str) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("failed to create directory {path}: {error}"))
}

fn ensure_parent_dir(path: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                format!("failed to create parent directory {}: {error}", parent.display())
            })?;
        }
    }
    Ok(())
}

fn extract_port(listen_addr: &str) -> u16 {
    listen_addr
        .rsplit(':')
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(6060)
}

fn extract_bind_host(listen_addr: &str) -> String {
    let trimmed = listen_addr.trim();
    if trimmed.is_empty() {
        return "0.0.0.0".to_string();
    }

    if trimmed.starts_with('[') {
        if let Some(end_index) = trimmed.find(']') {
            return trimmed[..=end_index].to_string();
        }
    }

    if let Some((host, _port)) = trimmed.rsplit_once(':') {
        if !host.trim().is_empty() {
            return host.trim().to_string();
        }
    }

    trimmed.to_string()
}

fn replace_url_port_if_possible(url: &str, port: u16) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let Some((scheme, remainder)) = trimmed.split_once("://") else {
        return trimmed.to_string();
    };

    let suffix_index = remainder
        .char_indices()
        .find(|(_, value)| matches!(value, '/' | '?' | '#'))
        .map(|(index, _)| index)
        .unwrap_or(remainder.len());
    let authority = &remainder[..suffix_index];
    let suffix = &remainder[suffix_index..];
    if authority.is_empty() {
        return trimmed.to_string();
    }

    let host = if authority.starts_with('[') {
        if let Some(end_index) = authority.find(']') {
            authority[..=end_index].to_string()
        } else {
            authority.to_string()
        }
    } else if let Some((candidate_host, candidate_port)) = authority.rsplit_once(':') {
        if candidate_port.parse::<u16>().is_ok() && !candidate_host.trim().is_empty() {
            candidate_host.trim().to_string()
        } else {
            authority.to_string()
        }
    } else {
        authority.to_string()
    };

    format!("{scheme}://{host}:{port}{suffix}")
}

fn append_query_param(url: &str, key: &str, value: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}{key}={}", http::url_encode(value))
}

fn detect_panel_service_name() -> Option<String> {
    if Path::new("/etc/systemd/system/imonitor.service").exists()
        || Path::new("/lib/systemd/system/imonitor.service").exists()
    {
        return Some("imonitor.service".to_string());
    }
    if Path::new("/etc/systemd/system/iranmonitor-node.service").exists()
        || Path::new("/lib/systemd/system/iranmonitor-node.service").exists()
    {
        return Some("iranmonitor-node.service".to_string());
    }
    if Path::new("/etc/init.d/imonitor").exists() {
        return Some("imonitor".to_string());
    }
    if Path::new("/etc/init.d/iranmonitor-node").exists() {
        return Some("iranmonitor-node".to_string());
    }
    None
}

fn restart_panel_service_now() -> Result<(), String> {
    let Some(service_name) = detect_panel_service_name() else {
        return Err("could not detect the iMonitor service unit on this server".to_string());
    };

    if service_name.ends_with(".service") && Command::new("systemctl").arg("--version").output().is_ok() {
        let output = Command::new("systemctl")
            .args(["restart", &service_name])
            .output()
            .map_err(|error| format!("failed to restart {service_name}: {error}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("systemctl restart {service_name} failed")
        });
    }

    if Command::new("rc-service").arg("--version").output().is_ok() {
        let output = Command::new("rc-service")
            .args([&service_name, "restart"])
            .output()
            .map_err(|error| format!("failed to restart {service_name}: {error}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("rc-service restart {service_name} failed")
        });
    }

    Err("unsupported service manager; could not restart iMonitor automatically".to_string())
}

fn stop_and_disable_panel_service() -> Result<(), String> {
    let Some(service_name) = detect_panel_service_name() else {
        return Ok(());
    };

    if service_name.ends_with(".service") && Command::new("systemctl").arg("--version").output().is_ok() {
        let disable_output = Command::new("systemctl")
            .args(["disable", "--now", &service_name])
            .output()
            .map_err(|error| format!("failed to disable {service_name}: {error}"))?;
        if disable_output.status.success() {
            return Ok(());
        }
        let stop_output = Command::new("systemctl")
            .args(["stop", &service_name])
            .output()
            .map_err(|error| format!("failed to stop {service_name}: {error}"))?;
        if stop_output.status.success() {
            let _ = Command::new("systemctl").args(["disable", &service_name]).status();
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&disable_output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&disable_output.stdout).trim().to_string();
        return Err(if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("systemctl disable --now {service_name} failed")
        });
    }

    if Command::new("rc-service").arg("--version").output().is_ok() {
        let stop_output = Command::new("rc-service")
            .args([&service_name, "stop"])
            .output()
            .map_err(|error| format!("failed to stop {service_name}: {error}"))?;
        if !stop_output.status.success() {
            let stderr = String::from_utf8_lossy(&stop_output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&stop_output.stdout).trim().to_string();
            if !stderr.is_empty() || !stdout.is_empty() {
                return Err(if !stderr.is_empty() { stderr } else { stdout });
            }
        }
        if Command::new("rc-update").arg("--version").output().is_ok() {
            let _ = Command::new("rc-update")
                .args(["del", &service_name, "default"])
                .status();
        }
        return Ok(());
    }

    Ok(())
}

fn schedule_panel_service_restart() -> Result<(), String> {
    let Some(service_name) = detect_panel_service_name() else {
        return Err("access saved, but the iMonitor service unit could not be detected".to_string());
    };
    let transient_unit = format!("iranmonitor-apply-{}", db::unix_now());
    let output = Command::new("systemd-run")
        .args([
            "--quiet",
            "--collect",
            "--unit",
            &transient_unit,
            "--on-active=1s",
            "/bin/systemctl",
            "restart",
            &service_name,
        ])
        .output()
        .map_err(|error| format!("failed to schedule panel restart: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            "systemd-run did not provide an error message".to_string()
        };
        Err(format!("access saved, but automatic panel restart could not be scheduled: {detail}"))
    } else {
        Ok(())
    }
}

fn flash_message(lang: UiLanguage, code: &str) -> Option<&'static str> {
    match code {
        "login_ok" => Some(if matches!(lang, UiLanguage::Fa) {
            "ورود با موفقیت انجام شد."
        } else {
            "Login successful."
        }),
        "logout_ok" => Some(if matches!(lang, UiLanguage::Fa) {
            "با موفقیت خارج شدید."
        } else {
            "You have been logged out."
        }),
        "access_saved" => Some(if matches!(lang, UiLanguage::Fa) {
            "تنظیمات دسترسی ذخیره شد."
        } else {
            "Access settings saved."
        }),
        "settings_saved" => Some(if matches!(lang, UiLanguage::Fa) {
            "تنظیمات ذخیره شد."
        } else {
            "Settings saved."
        }),
        "update_started" => Some(if matches!(lang, UiLanguage::Fa) {
            "به‌روزرسانی شروع شد. اگر سرویس ری‌استارت شود چند لحظه صفحه از دسترس خارج می‌شود."
        } else {
            "Update started. The panel may go offline briefly while the service restarts."
        }),
        "check_saved" => Some(if matches!(lang, UiLanguage::Fa) {
            "مانیتور ذخیره شد."
        } else {
            "Monitor saved."
        }),
        "check_deleted" => Some(if matches!(lang, UiLanguage::Fa) {
            "مانیتور حذف شد."
        } else {
            "Monitor deleted."
        }),
        "watcher_saved" => Some(if matches!(lang, UiLanguage::Fa) {
            "ردیاب ترافیک ذخیره شد."
        } else {
            "Traffic watcher saved."
        }),
        "watcher_deleted" => Some(if matches!(lang, UiLanguage::Fa) {
            "ردیاب ترافیک حذف شد."
        } else {
            "Traffic watcher deleted."
        }),
        "speed_limit_saved" => Some(if matches!(lang, UiLanguage::Fa) {
            "قانون محدودیت سرعت ذخیره شد."
        } else {
            "Speed limit rule saved."
        }),
        "speed_limit_deleted" => Some(if matches!(lang, UiLanguage::Fa) {
            "قانون محدودیت سرعت حذف شد."
        } else {
            "Speed limit rule deleted."
        }),
        "forward_rule_saved" => Some(if matches!(lang, UiLanguage::Fa) {
            "قانون فوروارد ذخیره شد."
        } else {
            "Forwarding rule saved."
        }),
        "forward_rule_deleted" => Some(if matches!(lang, UiLanguage::Fa) {
            "قانون فوروارد حذف شد."
        } else {
            "Forwarding rule deleted."
        }),
        "forward_rules_applied" => Some(if matches!(lang, UiLanguage::Fa) {
            "قوانین فوروارد اعمال شدند."
        } else {
            "Forwarding rules applied."
        }),
        "source_ip_saved" => Some(if matches!(lang, UiLanguage::Fa) {
            "قانون IP مبدأ ذخیره شد."
        } else {
            "Source IP rule saved."
        }),
        "source_ip_deleted" => Some(if matches!(lang, UiLanguage::Fa) {
            "قانون IP مبدأ حذف شد."
        } else {
            "Source IP rule deleted."
        }),
        "source_ip_applied" => Some(if matches!(lang, UiLanguage::Fa) {
            "قوانین IP مبدأ اعمال شدند."
        } else {
            "Source IP rules applied."
        }),
        "backup target saved" => Some(if matches!(lang, UiLanguage::Fa) {
            "مقصد بکاپ ذخیره شد."
        } else {
            "Backup target saved."
        }),
        "backup target deleted" => Some(if matches!(lang, UiLanguage::Fa) {
            "مقصد بکاپ حذف شد."
        } else {
            "Backup target deleted."
        }),
        "backup job saved" => Some(if matches!(lang, UiLanguage::Fa) {
            "وظیفه‌ی بکاپ ذخیره شد."
        } else {
            "Backup job saved."
        }),
        "backup job deleted" => Some(if matches!(lang, UiLanguage::Fa) {
            "وظیفه‌ی بکاپ حذف شد."
        } else {
            "Backup job deleted."
        }),
        "missing_source_ip_label" => Some(if matches!(lang, UiLanguage::Fa) {
            "عنوان قانون IP مبدأ خالی است."
        } else {
            "Source IP label is missing."
        }),
        "missing_source_ip_id" => Some(if matches!(lang, UiLanguage::Fa) {
            "شناسه‌ی قانون IP مبدأ یافت نشد."
        } else {
            "Source IP rule id is missing."
        }),
        "source_ip_destination_is_local" => Some(if matches!(lang, UiLanguage::Fa) {
            "IP مقصد نباید IP همین سرور باشد. در این بخش باید IP واقعی سرور مقابل را وارد کنید."
        } else {
            "Destination IP cannot be one of this server's own IPs. Enter the peer server's real IP here."
        }),
        "source_ip_translate_is_local" => Some(if matches!(lang, UiLanguage::Fa) {
            "IP ترجمه برگشت نباید IP همین سرور باشد. در این بخش باید IP واقعی سرور مقابل را وارد کنید."
        } else {
            "Return Translate IP cannot be one of this server's own IPs. Enter the peer server's real IP here."
        }),
        "missing_check_fields" => Some(if matches!(lang, UiLanguage::Fa) {
            "فیلدهای مانیتور کامل نیست."
        } else {
            "Monitor fields are incomplete."
        }),
        _ => None,
    }
}

fn sample_check(kind: Option<&str>) -> String {
    let value = match kind.unwrap_or("https") {
        "dns" => json!({
            "kind": "dns",
            "id": "cloudflare-dns",
            "server": "1.1.1.1",
            "record_name": "example.com",
            "record_type": "a",
            "expect_answers_min": 1,
            "ip_version": "ipv4"
        }),
        "tcp" => json!({
            "kind": "tcp",
            "id": "tcp-443",
            "target": "example.com",
            "port": 443,
            "ip_version": "ipv4"
        }),
        "v2ray" | "v2ray_simulation" => json!({
            "kind": "v2ray",
            "id": "vless-local-entry-example",
            "proxy_type": "vless",
            "local_entry_type": "socks5",
            "proxy_host": "127.0.0.1",
            "proxy_port": 1080,
            "server_host": "edge.example.com",
            "server_port": 443,
            "server_name": "edge.example.com",
            "transport": "tcp+tls",
            "test_url": "https://www.google.com/generate_204",
            "expected_status": [204],
            "ip_version": "ipv4",
            "timeout_ms": 4000
        }),
        _ => json!({
            "kind": "https",
            "id": "google-https",
            "host": "www.google.com",
            "path": "/",
            "expected_status": [200, 301, 302],
            "ip_version": "ipv4"
        }),
    };
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod release_update_tests {
    use super::{release_checksum, release_version_tuple};
    #[test]
    fn versions_are_strict_and_never_compare_lexicographically() {
        assert!(release_version_tuple("1.2.2").unwrap() < release_version_tuple("2.0.0").unwrap());
        assert!(release_version_tuple("2.9.0").unwrap() < release_version_tuple("2.10.0").unwrap());
        for value in ["2.0", "2.0.0/../../../tmp", "v2.0.0", "2.0.0-alpha", "2.0.0\n"] { assert!(release_version_tuple(value).is_none()); }
    }
    #[test]
    fn manifest_requires_one_exact_filename_regardless_of_file_order() {
        let digest = "a".repeat(64);
        let manifest = format!("{}  ./imonitor-bpf-v2.0.0-amd64.zip\n{digest}  ./imonitor-v2.0.0-linux-amd64.zip\n", "b".repeat(64));
        assert_eq!(release_checksum(&manifest, "imonitor-v2.0.0-linux-amd64.zip").unwrap(), digest);
        assert!(release_checksum(&manifest, "imonitor-linux-amd64.zip").is_err());
        assert!(release_checksum(&(manifest.clone() + &manifest), "imonitor-v2.0.0-linux-amd64.zip").is_err());
        assert!(release_checksum("invalid  file.zip", "file.zip").is_err());
    }
}

#[cfg(test)]
mod unrestricted_access_tests {
    use super::{effective_checks, hydrate_public_history_from_snapshots, parse_args, AppCommand};
    use crate::app_types::MonitorCheckRow;

    #[test]
    fn old_service_plan_flags_remain_compatible() {
        let command = parse_args(vec!["serve".into(), "--plan".into(), "free".into()]).unwrap();
        assert!(matches!(command, AppCommand::Serve(_)));
    }

    #[test]
    fn public_history_does_not_publish_old_command_errors() {
        let result = crate::types::CheckResult {
            id: "test-tunnel".into(),
            kind: "tunnel".into(),
            status: crate::types::CheckStatus::Down,
            message: "failed command with credential-secret".into(),
            observed_at_unix: 1,
            duration_ms: 10,
            latency_ms: None,
            ip_version: None,
            endpoint: None,
            details: Default::default(),
        };
        let snapshot = crate::app_types::StoredSnapshot {
            id: 1,
            created_at_unix: 1,
            overall_status: "down".into(),
            system_json: "{}".into(),
            results_json: serde_json::to_string(&vec![result]).unwrap(),
            summary_json: "{}".into(),
        };
        let mut checks = vec![crate::app_types::PublicCheckView {
            id: "test-tunnel".into(),
            label: "Tunnel".into(),
            kind: "tunnel".into(),
            status: crate::types::CheckStatus::Down,
            message: "Service is unavailable.".into(),
            latency_ms: None,
            endpoint: None,
            observed_at_unix: 1,
            group_name: String::new(),
            group_logo_url: String::new(),
            group_logo_shape: "rounded".into(),
            history: Vec::new(),
            is_pending: false,
        }];
        hydrate_public_history_from_snapshots(&[snapshot], &mut checks).unwrap();
        assert_eq!(checks[0].history.len(), 1);
        assert_eq!(checks[0].history[0].message, "Service is unavailable.");
        assert!(!serde_json::to_string(&checks).unwrap().contains("secret"));
    }

    #[test]
    fn all_enabled_protocols_run_without_a_monitor_limit() {
        let kinds = ["icmp", "tcp", "udp", "ssh", "sftp", "http", "https", "dns", "rdp", "ftp", "v2ray", "tunnel"];
        let mut rows = kinds.iter().enumerate().map(|(index, kind)| {
            // Deserialize a v1.2.2 row to exercise migration of its old plan field.
            serde_json::from_value::<MonitorCheckRow>(serde_json::json!({
                "db_id": index as i64,
                "check_id": format!("check-{index}"),
                "label": kind,
                "kind": kind,
                "plan_required": "enterprise",
                "enabled": true,
                "public_visible": true,
                "display_group": "",
                "group_logo_url": "",
                "group_logo_shape": "rounded",
                "check_json": "{}",
                "created_at_unix": 1,
                "updated_at_unix": 1
            })).unwrap()
        }).collect::<Vec<_>>();
        assert_eq!(effective_checks(&rows).len(), kinds.len());
        rows[0].enabled = false;
        let selected = effective_checks(&rows);
        assert_eq!(selected.len(), kinds.len() - 1);
        assert!(!selected.iter().any(|row| row.check_id == "check-0"));
        assert!(selected.iter().any(|row| row.kind == "tunnel"));
    }
}

#[cfg(test)]
mod tunnel_cleanup_tests {
    use super::*;

    fn tunnel() -> TunnelCheck {
        serde_json::from_value(json!({"id": "cleanup-test", "protocol": "encap", "interface": "external0",
            "auto_create_interface": false, "inner_local_cidr": "10.20.0.1/30", "inner_probe": "10.20.0.2"})).unwrap()
    }

    #[test]
    fn monitor_only_removal_preserves_external_system_resources() {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-fixtures")
            .join(format!("tunnel-cleanup-{}-{}", std::process::id(), random_hex(6).unwrap()));
        fs::create_dir_all(&directory).unwrap();
        let context = Arc::new(AppContext {
            db: Database::new(directory.join("must-not-access.db")),
            state_file: directory.join("state.json"), branding_dir: directory.join("branding"),
            runtime: Mutex::new(RuntimeState { monitor_state: PersistedState::default(), previous_cpu: None, previous_net: None }),
            live_metrics: Mutex::new(DashboardLiveState { previous_cpu: None, previous_net: None }),
            tunnel_diagnostics_jobs: Mutex::new(BTreeMap::new()),
        });
        // This succeeds without looking up ownership in SQLite or executing ip.
        // Both would fail here; the monitor points at an externally managed link.
        cleanup_tunnel_resources(&context, &tunnel()).unwrap();
        assert!(!directory.join("must-not-access.db").exists());
        assert!(directory.join("state.json").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn forwarding_changes_trigger_cleanup_but_monitoring_changes_preserve_it() {
        let mut original = tunnel();
        original.protocol = TunnelProtocol::Esp;
        original.auto_create_interface = true;
        let signature = managed_tunnel_resource_signature(&original);
        let mut changed = original.clone();
        changed.interval_secs += 30;
        changed.speedtest_token = Some("0123456789abcdef0123456789abcdef".to_string());
        assert_eq!(signature, managed_tunnel_resource_signature(&changed));
        changed.inner_probe = Some("10.20.0.3".to_string());
        assert_ne!(signature, managed_tunnel_resource_signature(&changed));
        changed = original;
        changed.esp_key_derivation = crate::config::EspKeyDerivation::HkdfSha256;
        assert_ne!(signature, managed_tunnel_resource_signature(&changed));
    }

    #[test]
    fn legacy_gcm_mtu_and_monitoring_edits_preserve_live_resources() {
        let mut original = tunnel();
        original.protocol = TunnelProtocol::Esp;
        original.auto_create_interface = true;
        let previous = CheckDefinition::Tunnel(original.clone());
        let mut changed = original.clone();
        changed.mtu = Some(1400);
        changed.interval_secs += 30;
        changed.timeout_ms += 1000;
        changed.require_bidirectional_traffic = false;
        changed.speedtest_token = Some("0123456789abcdef0123456789abcdef".to_string());
        let next = CheckDefinition::Tunnel(changed);
        assert!(!should_cleanup_previous_resources(&previous, &next));
        validate_legacy_esp_resource_edit(&previous, &next, true).unwrap();
        // Native TUN helpers still retire to apply a changed framing ceiling.
        original.protocol = TunnelProtocol::Tun;
        let previous = CheckDefinition::Tunnel(original.clone());
        original.mtu = Some(1400);
        assert!(should_cleanup_previous_resources(&previous, &CheckDefinition::Tunnel(original)));
    }

    #[test]
    fn legacy_gcm_guard_rejects_retiring_edits_before_migration() {
        let mut original = tunnel();
        original.protocol = TunnelProtocol::Esp;
        original.auto_create_interface = true;
        let previous = CheckDefinition::Tunnel(original.clone());
        for (field, value) in [
            ("id", json!("renamed-check")),
            ("interface", json!("different0")),
            ("outer_remote", json!("192.0.2.9")),
            ("inner_probe", json!("10.20.0.3")),
            ("tunnel_key", json!("0123456789abcdef0123456789abcdef")),
            ("esp_key_derivation", json!("hkdf_sha256")),
        ] {
            let mut edited = serde_json::to_value(&original).unwrap();
            edited[field] = value;
            let next = CheckDefinition::Tunnel(serde_json::from_value(edited).unwrap());
            let error = validate_legacy_esp_resource_edit(&previous, &next, true).unwrap_err();
            assert!(error.contains("migrate both peers") && error.contains("MTU and monitoring edits remain allowed"), "{field}");
            // Explicit disable is a deliberate teardown, not an unsafe restart.
            validate_legacy_esp_resource_edit(&previous, &next, false).unwrap();
        }
        let mut migrated = original.clone();
        migrated.esp_cipher = crate::config::EspCipher::AesCbcHmacSha256;
        migrated.esp_key_derivation = crate::config::EspKeyDerivation::HkdfSha256;
        migrated.tunnel_key = Some("0123456789abcdef0123456789abcdef".to_string());
        let next = CheckDefinition::Tunnel(migrated);
        assert!(should_cleanup_previous_resources(&previous, &next));
        validate_legacy_esp_resource_edit(&previous, &next, true).unwrap();
        let mut next = original.clone();
        next.protocol = TunnelProtocol::Wireguard;
        validate_legacy_esp_resource_edit(&previous, &CheckDefinition::Tunnel(next), true).unwrap();
        original.auto_create_interface = false;
        validate_legacy_esp_resource_edit(&previous, &CheckDefinition::Tunnel(original), true).unwrap();
    }
}

#[cfg(test)]
mod branding_asset_security_tests {
    use super::{branding_image_content_type, read_branding_asset, MAX_BRANDING_ASSET_BYTES};
    use std::fs;
    use std::path::PathBuf;

    fn fixture_directory() -> PathBuf {
        // Windows app sandboxes can allow temporary file writes while denying
        // directory canonicalization in their redirected system temp folder.
        let base = std::env::var_os("IMONITOR_TEST_TMP").map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-fixtures"));
        let directory = base.join(format!(
            "imonitor-branding-security-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(directory.join("branding")).unwrap();
        directory
    }

    #[test]
    fn configured_images_are_bounded_by_the_canonical_branding_directory() {
        let directory = fixture_directory();
        let branding = directory.join("branding");
        let png = branding.join("logo.PNG");
        fs::write(&png, b"\x89PNG\r\n\x1a\nimage-data").unwrap();
        let (_, content_type) = read_branding_asset(&branding, &png).unwrap();
        assert_eq!(content_type, "image/png");

        let outside = directory.join("private.png");
        fs::write(&outside, b"\x89PNG\r\n\x1a\nprivate-data").unwrap();
        assert!(read_branding_asset(&branding, &outside).is_err());
        assert!(read_branding_asset(&branding, &branding.join("../private.png")).is_err());
        let non_image = branding.join("database.png");
        fs::write(&non_image, b"SQLite format 3\0private credentials").unwrap();
        assert!(read_branding_asset(&branding, &non_image).is_err());
        let svg = branding.join("script.svg");
        fs::write(&svg, b"<svg><script>alert(1)</script></svg>").unwrap();
        assert!(read_branding_asset(&branding, &svg).is_err());
        let oversize = branding.join("large.png");
        fs::File::create(&oversize).unwrap().set_len(MAX_BRANDING_ASSET_BYTES + 1).unwrap();
        assert!(read_branding_asset(&branding, &oversize).is_err());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn image_extension_must_match_its_binary_signature() {
        assert_eq!(branding_image_content_type("png", b"\x89PNG\r\n\x1a\n"), Some("image/png"));
        assert_eq!(branding_image_content_type("jpg", &[0xff, 0xd8, 0xff]), Some("image/jpeg"));
        assert_eq!(branding_image_content_type("gif", b"GIF89a"), Some("image/gif"));
        assert_eq!(branding_image_content_type("webp", b"RIFF\x04\0\0\0WEBP"), Some("image/webp"));
        assert_eq!(branding_image_content_type("ico", &[0, 0, 1, 0, 1, 0]), Some("image/x-icon"));
        assert_eq!(branding_image_content_type("png", b"<html>private</html>"), None);
        assert_eq!(branding_image_content_type("jpg", b"\x89PNG\r\n\x1a\n"), None);
        assert_eq!(branding_image_content_type("ico", &[0, 0, 1, 0, 0, 0]), None);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_cannot_escape_the_branding_directory() {
        let directory = fixture_directory();
        let branding = directory.join("branding");
        let outside = directory.join("private.png");
        fs::write(&outside, b"\x89PNG\r\n\x1a\nprivate-data").unwrap();
        let symlink = branding.join("escape.png");
        std::os::unix::fs::symlink(&outside, &symlink).unwrap();
        assert!(read_branding_asset(&branding, &symlink).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
