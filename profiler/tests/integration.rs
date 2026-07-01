//! End-to-end integration test: profile `examples/cpu_bound.c` and check
//! that its recursive call chain shows up in the folded-stack output.
//!
//! Requires Linux, root (perf_event_open + bpf()), and a release build of
//! the profiler. Not run by default - `cargo test` skips `#[ignore]`d
//! tests. Run explicitly with:
//!
//!   cargo build --release -p profiler
//!   sudo cargo test -p profiler --test integration -- --ignored --nocapture
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[test]
#[ignore = "requires Linux, root, and a real kernel with eBPF/perf_event_open support"]
fn profiles_recursive_fibonacci_workload() {
    let root = workspace_root();
    let example_src = root.join("examples/cpu_bound.c");
    let example_bin = std::env::temp_dir().join("flamegraph_profiler_cpu_bound_test");

    let status = Command::new("cc")
        .args(["-O2", "-fno-omit-frame-pointer", "-o"])
        .arg(&example_bin)
        .arg(&example_src)
        .status()
        .expect("failed to invoke cc");
    assert!(status.success(), "failed to compile examples/cpu_bound.c");

    let mut workload = Command::new(&example_bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start cpu_bound workload");

    let profiler_bin = root.join("target/release/flamegraph-profiler");
    let output = Command::new(&profiler_bin)
        .args([
            "record",
            "-p",
            &workload.id().to_string(),
            "-d",
            "5",
            "--format",
            "folded",
        ])
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "failed to run {} ({e}); build it first with `cargo build --release -p profiler`",
                profiler_bin.display()
            )
        });

    workload.kill().ok();

    assert!(
        output.status.success(),
        "profiler exited with an error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let folded = String::from_utf8_lossy(&output.stdout);
    assert!(folded.lines().count() > 0, "no folded stacks were produced");
    assert!(
        folded.contains("fib"),
        "expected 'fib' to appear in a sampled stack:\n{folded}"
    );
}
