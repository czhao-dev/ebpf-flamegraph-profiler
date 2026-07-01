pub mod cli;
pub mod folded;
pub mod kallsyms;
pub mod svg;
pub mod symbolize;
pub mod usersym;

#[cfg(target_os = "linux")]
pub mod maps;
#[cfg(target_os = "linux")]
pub mod perf;

#[cfg(target_os = "linux")]
pub fn run() -> anyhow::Result<()> {
    use std::io::Write;
    use std::time::Instant;

    use clap::Parser;

    use cli::{Cli, Command, OutputFormat};

    env_logger::init();
    let cli = Cli::parse();
    let Command::Record(args) = cli.command;

    bump_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(env!("PROFILER_BPF_OBJ")))?;

    perf::configure_targets(&mut ebpf, &args.pids)?;
    let _links = perf::attach_all_cpus(&mut ebpf, args.frequency)?;

    let kallsyms = kallsyms::Kallsyms::load()?;
    if !kallsyms.is_available() {
        log::warn!(
            "kernel symbol addresses in /proc/kallsyms are all zero (kptr_restrict?); \
             kernel frames will show as [unknown]"
        );
    }
    let mut usersyms = usersym::UserSymbolCache::new();
    let mut aggregator = folded::Aggregator::new();

    let start = Instant::now();
    while start.elapsed() < args.duration {
        std::thread::sleep(args.drain_interval());
        maps::drain_into(&mut ebpf, &mut aggregator, &kallsyms, &mut usersyms)?;
    }
    // Final drain to catch samples from the last partial interval.
    maps::drain_into(&mut ebpf, &mut aggregator, &kallsyms, &mut usersyms)?;

    if aggregator.is_empty() {
        log::warn!("no samples were collected");
    }

    match args.format {
        OutputFormat::Folded => match &args.output {
            Some(path) => {
                let mut f = std::fs::File::create(path)?;
                aggregator.write_folded(&mut f)?;
            }
            None => {
                aggregator.write_folded(&mut std::io::stdout().lock())?;
            }
        },
        OutputFormat::Svg => {
            let path = args.output.clone().unwrap_or_else(|| "profile.svg".into());
            let tree = svg::build_tree(&aggregator);
            let mut f = std::fs::File::create(&path)?;
            svg::render(&tree, &mut f)?;
            writeln!(std::io::stderr(), "wrote {}", path.display())?;
        }
    }

    Ok(())
}

/// Raises `RLIMIT_MEMLOCK` to unlimited; older kernels (pre-5.11) charge
/// BPF map memory against it and the default limit is too low to load
/// this profiler's maps.
#[cfg(target_os = "linux")]
fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::warn!(
            "failed to raise RLIMIT_MEMLOCK: {}",
            std::io::Error::last_os_error()
        );
    }
}
