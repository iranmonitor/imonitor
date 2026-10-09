use std::fs;
use std::process::Command;

/// Local hardware information used by the server health page. No device
/// fingerprint, serial number, MAC address, or licensing cache is collected.
#[derive(Debug, Clone, Default)]
pub struct HardwareSnapshot {
    pub cpu_model: String,
    pub cpu_count: u32,
    pub kernel: String,
}

pub fn collect_hardware_snapshot() -> (String, HardwareSnapshot) {
    let hostname = command_output("hostname", &[])
        .or_else(|| fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_default()
        .trim()
        .to_string();
    let cpu_model = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.trim()
                    .eq_ignore_ascii_case("model name")
                    .then(|| value.trim().to_string())
            })
        })
        .unwrap_or_default();
    let cpu_count = std::thread::available_parallelism()
        .map(|count| count.get() as u32)
        .unwrap_or(0);
    let kernel = command_output("uname", &["-srmo"])
        .or_else(|| command_output("uname", &["-a"]))
        .unwrap_or_default();

    (hostname, HardwareSnapshot { cpu_model, cpu_count, kernel })
}

fn command_output(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}
