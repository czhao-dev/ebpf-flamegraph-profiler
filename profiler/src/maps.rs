//! Drains the `counts` and `stack_traces` BPF maps once per interval,
//! resolves each stack's instruction pointers to symbols, and feeds the
//! results into the folded-stack aggregator.

use std::collections::HashSet;

use anyhow::anyhow;
use aya::maps::{HashMap as AyaHashMap, StackTraceMap};
use aya::Ebpf;
use profiler_common::SampleKey;

use crate::folded::Aggregator;
use crate::kallsyms::Kallsyms;
use crate::symbolize::{self, Frame};
use crate::usersym::UserSymbolCache;

/// Matches `MAX_ENTRIES` in profiler-bpf/profiler.bpf.c.
const COUNTS_MAX_ENTRIES: usize = 10240;

pub fn drain_into(
    ebpf: &mut Ebpf,
    agg: &mut Aggregator,
    kallsyms: &Kallsyms,
    usersyms: &mut UserSymbolCache,
) -> anyhow::Result<()> {
    // Snapshot this interval's samples (immutable borrow of `ebpf`).
    let samples: Vec<(SampleKey, u64)> = {
        let counts: AyaHashMap<_, SampleKey, u64> = AyaHashMap::try_from(
            ebpf.map("counts")
                .ok_or_else(|| anyhow!("BPF map 'counts' not found"))?,
        )?;
        counts.iter().collect::<Result<Vec<_>, _>>()?
    };

    if samples.is_empty() {
        return Ok(());
    }

    if samples.len() as f64 >= 0.95 * COUNTS_MAX_ENTRIES as f64 {
        log::warn!(
            "counts map is near capacity ({}/{COUNTS_MAX_ENTRIES} unique stacks this interval); \
             samples may be silently dropped",
            samples.len()
        );
    }

    // Refresh /proc/<pid>/maps once per distinct pid seen this cycle,
    // since mmap/exec can change mappings between drain cycles.
    let mut seen_pids = HashSet::new();
    for (key, _) in &samples {
        if seen_pids.insert(key.tgid) {
            let _ = usersyms.refresh_proc_maps(key.tgid);
        }
    }

    {
        let stack_traces: StackTraceMap<_> = StackTraceMap::try_from(
            ebpf.map("stack_traces")
                .ok_or_else(|| anyhow!("BPF map 'stack_traces' not found"))?,
        )?;

        for (key, count) in &samples {
            let mut frames = Vec::new();

            // User frames first (root/outer to leaf/inner)...
            if key.user_stack_id >= 0 {
                if let Ok(trace) = stack_traces.get(&(key.user_stack_id as u32), 0) {
                    let mut user_frames: Vec<Frame> = trace
                        .frames()
                        .iter()
                        .map(|f| symbolize::resolve_user(usersyms, key.tgid, f.ip))
                        .collect();
                    user_frames.reverse(); // bpf_get_stackid returns leaf-first
                    frames.extend(user_frames);
                }
            }
            // ...then kernel frames, since a kernel stack represents the
            // thread having entered the kernel (e.g. via syscall) from
            // that user-space point.
            if key.kern_stack_id >= 0 {
                if let Ok(trace) = stack_traces.get(&(key.kern_stack_id as u32), 0) {
                    let mut kern_frames: Vec<Frame> = trace
                        .frames()
                        .iter()
                        .map(|f| symbolize::resolve_kernel(kallsyms, f.ip))
                        .collect();
                    kern_frames.reverse();
                    frames.extend(kern_frames);
                }
            }
            if frames.is_empty() {
                frames.push(Frame::Unknown);
            }

            agg.add(frames, *count);
        }
    }

    // Clear drained entries so the next interval only reflects new samples.
    {
        let mut counts: AyaHashMap<_, SampleKey, u64> = AyaHashMap::try_from(
            ebpf.map_mut("counts")
                .ok_or_else(|| anyhow!("BPF map 'counts' not found"))?,
        )?;
        for (key, _) in &samples {
            let _ = counts.remove(key);
        }
    }

    Ok(())
}
