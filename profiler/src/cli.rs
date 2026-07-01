use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "flamegraph-profiler", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Sample on-CPU stacks system-wide (or for specific PIDs) and emit a
    /// flame graph.
    Record(RecordArgs),
}

#[derive(Parser, Debug)]
pub struct RecordArgs {
    /// Restrict profiling to these PIDs (repeatable). Default: all processes.
    #[arg(short, long = "pid", value_name = "PID")]
    pub pids: Vec<u32>,

    /// How long to sample, in seconds.
    #[arg(short, long, default_value = "30", value_parser = parse_seconds)]
    pub duration: Duration,

    /// Sampling frequency in Hz.
    #[arg(short = 'F', long, default_value_t = 99)]
    pub frequency: u64,

    /// How often to drain BPF maps, in milliseconds.
    #[arg(long = "drain-interval-ms", default_value_t = 1000)]
    pub drain_interval_ms: u64,

    /// Output file path. Defaults to stdout for `--format=folded`, or
    /// `profile.svg` for `--format=svg`.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Svg)]
    pub format: OutputFormat,
}

impl RecordArgs {
    pub fn drain_interval(&self) -> Duration {
        Duration::from_millis(self.drain_interval_ms)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Folded,
    Svg,
}

fn parse_seconds(s: &str) -> Result<Duration, String> {
    s.parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|e| format!("invalid duration '{s}': {e}"))
}
