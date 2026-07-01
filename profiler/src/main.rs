#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    profiler::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "flamegraph-profiler requires Linux (eBPF, perf_event_open, /proc/kallsyms); \
         this platform is unsupported."
    );
    std::process::exit(1);
}
