//! Attaches `profile_cpu` to a `PERF_TYPE_SOFTWARE`/`PERF_COUNT_SW_CPU_CLOCK`
//! event on every online CPU, and configures the BPF-side PID filter.

use anyhow::{anyhow, Context};
use aya::maps::{Array, HashMap};
use aya::programs::perf_event::{
    PerfEvent, PerfEventConfig, PerfEventLinkId, PerfEventScope, SamplePolicy, SoftwareEvent,
};
use aya::util::online_cpus;
use aya::Ebpf;

/// Writes the BPF-side PID allowlist (`targets`) and the `config.filter_enabled`
/// flag. An empty `pids` list means "profile everything" - the BPF program
/// only consults `targets` when `filter_enabled` is set, since a bare lookup
/// miss can't distinguish "map is empty" from "this pid isn't targeted".
pub fn configure_targets(ebpf: &mut Ebpf, pids: &[u32]) -> anyhow::Result<()> {
    let filter_enabled: u32 = if pids.is_empty() { 0 } else { 1 };

    {
        let mut config: Array<_, u32> = Array::try_from(
            ebpf.map_mut("config")
                .ok_or_else(|| anyhow!("BPF map 'config' not found"))?,
        )?;
        config
            .set(0, filter_enabled, 0)
            .context("writing config.filter_enabled")?;
    }

    if !pids.is_empty() {
        let mut targets: HashMap<_, u32, u8> = HashMap::try_from(
            ebpf.map_mut("targets")
                .ok_or_else(|| anyhow!("BPF map 'targets' not found"))?,
        )?;
        for &pid in pids {
            targets
                .insert(pid, 1u8, 0)
                .with_context(|| format!("adding pid {pid} to targets"))?;
        }
    }

    Ok(())
}

/// Loads and attaches `profile_cpu` to every online CPU at `freq_hz`.
/// The returned link ids must be kept for as long as sampling should stay
/// attached (dropping `ebpf` itself detaches everything on process exit).
pub fn attach_all_cpus(ebpf: &mut Ebpf, freq_hz: u64) -> anyhow::Result<Vec<PerfEventLinkId>> {
    let program: &mut PerfEvent = ebpf
        .program_mut("profile_cpu")
        .ok_or_else(|| anyhow!("BPF program 'profile_cpu' not found"))?
        .try_into()?;
    program.load().context("loading profile_cpu program")?;

    let cpus = online_cpus().map_err(|(msg, err)| anyhow!("{msg}: {err}"))?;
    let mut link_ids = Vec::with_capacity(cpus.len());
    for cpu in cpus {
        let link_id = program
            .attach(
                PerfEventConfig::Software(SoftwareEvent::CpuClock),
                PerfEventScope::AllProcessesOneCpu { cpu },
                SamplePolicy::Frequency(freq_hz),
                true,
            )
            .with_context(|| format!("attaching profile_cpu to cpu {cpu}"))?;
        link_ids.push(link_id);
    }
    Ok(link_ids)
}
