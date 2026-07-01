use anyhow::{bail, Context};
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let bpf_dir = manifest_dir.join("../profiler-bpf");
    let src = bpf_dir.join("profiler.bpf.c");
    let include_dir = bpf_dir.join("include");

    println!("cargo:rerun-if-changed={}", src.display());
    println!(
        "cargo:rerun-if-changed={}",
        bpf_dir.join("bpf_helpers.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("profiler.h").display()
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let out_obj = out_dir.join("profiler.bpf.o");

    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let status = Command::new(&clang)
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-target",
            "bpf",
            "-I",
            include_dir.to_str().unwrap(),
            "-I",
            bpf_dir.to_str().unwrap(),
            "-c",
            src.to_str().unwrap(),
            "-o",
            out_obj.to_str().unwrap(),
        ])
        .status()
        .with_context(|| {
            format!(
                "failed to invoke `{clang} -target bpf`; on macOS this requires a clang/LLVM \
                 build with the BPF backend enabled (Apple's system clang does NOT include it) \
                 - install Homebrew's LLVM (`brew install llvm`) and set \
                 CLANG=$(brew --prefix llvm)/bin/clang, or build inside a Linux container"
            )
        })?;
    if !status.success() {
        bail!("clang failed to compile {}", src.display());
    }

    println!("cargo:rustc-env=PROFILER_BPF_OBJ={}", out_obj.display());
    Ok(())
}
