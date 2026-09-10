use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap();
    let ebpf_obj = workspace_root.join("target/bpfel-unknown-none/release/jittersnoop-ebpf");

    println!("cargo:rerun-if-changed=../jittersnoop-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../jittersnoop-common/src/lib.rs");
    println!("cargo:rerun-if-changed=src/dashboard.html");

    let needs_build = !ebpf_obj.exists() || {
        let obj_modified = std::fs::metadata(&ebpf_obj)
            .and_then(|m| m.modified())
            .ok();
        let src_modified = std::fs::metadata(workspace_root.join("jittersnoop-ebpf/src/main.rs"))
            .and_then(|m| m.modified())
            .ok();
        match (obj_modified, src_modified) {
            (Some(obj), Some(src)) => src > obj,
            _ => true,
        }
    };

    if needs_build {
        eprintln!("Building eBPF probe (this is slow the first time)...");
        let status = Command::new("cargo")
            .args([
                "+nightly", "build",
                "-p", "jittersnoop-ebpf",
                "--target", "bpfel-unknown-none",
                "-Z", "build-std=core",
                "--release",
            ])
            .env_remove("RUSTUP_TOOLCHAIN")
            .env_remove("RUSTC")
            .env_remove("RUSTC_WRAPPER")
            .current_dir(workspace_root)
            .status()
            .expect("failed to invoke cargo — is rustup nightly installed?");

        if !status.success() {
            panic!("eBPF probe build failed");
        }
    }

    let ebpf_obj = ebpf_obj.canonicalize().expect("eBPF object not found");
    println!("cargo:rustc-env=EBPF_OBJ={}", ebpf_obj.display());
}
