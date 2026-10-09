use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest_dir.join("src/bpf/xdp_ingress.c");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-env-changed=IMONITOR_SKIP_BPF_BUILD");
    // The panel and its diagnostics can be tested on other operating systems.
    // Production Linux builds compile the optional XDP helper by default.
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "linux"
        || env::var("IMONITOR_SKIP_BPF_BUILD").as_deref() == Ok("1")
    {
        println!("cargo:warning=XDP object build skipped; network controls need the separately built Linux helper");
        return;
    }

    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let target_dir = manifest_dir.join("target/bpf");
    let output = target_dir.join("xdp_ingress.o");

    if let Err(error) = std::fs::create_dir_all(&target_dir) {
        panic!("failed to create BPF target dir: {error}");
    }

    let (arch_define, include_triplet) = match env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default().as_str() {
        "x86_64" => ("__TARGET_ARCH_x86", "x86_64-linux-gnu"),
        "aarch64" => ("__TARGET_ARCH_arm64", "aarch64-linux-gnu"),
        "arm" => ("__TARGET_ARCH_arm", "arm-linux-gnueabihf"),
        other => panic!("unsupported target arch for XDP build: {other}"),
    };

    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=IMONITOR_BPF_SYSROOT");
    let sysroot = PathBuf::from(env::var("IMONITOR_BPF_SYSROOT").unwrap_or_else(|_| "/".into()));
    let include_root = sysroot.join("usr/include");
    let status = Command::new(&clang)
        .args([
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-D",
            arch_define,
            "-c",
        ])
        .arg("-I").arg(&include_root)
        .arg("-I").arg(include_root.join(include_triplet))
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .status()
        .unwrap_or_else(|error| panic!("failed to launch clang for XDP build: {error}"));

    if !status.success() {
        panic!("clang failed to build {}", Path::new(&source).display());
    }
}
