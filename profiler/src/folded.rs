//! Folded-stack aggregation: accumulates `(frame chain, count)` samples
//! and emits the canonical `frame1;frame2;frame3 count` text format
//! consumed by `flamegraph.pl` and this profiler's own SVG renderer.

use std::collections::HashMap;
use std::io::Write;

use crate::symbolize::Frame;

#[derive(Default)]
pub struct Aggregator {
    counts: HashMap<Vec<Frame>, u64>,
}

impl Aggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, frames: Vec<Frame>, count: u64) {
        *self.counts.entry(frames).or_insert(0) += count;
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Vec<Frame>, &u64)> {
        self.counts.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Writes one `frame1;frame2;...;frameN count` line per unique stack,
    /// sorted for deterministic output.
    pub fn write_folded(&self, w: &mut impl Write) -> std::io::Result<()> {
        let mut lines: Vec<(String, u64)> = self
            .counts
            .iter()
            .map(|(frames, count)| {
                let chain = frames
                    .iter()
                    .map(Frame::label)
                    .collect::<Vec<_>>()
                    .join(";");
                (chain, *count)
            })
            .collect();
        lines.sort();
        for (chain, count) in lines {
            writeln!(w, "{chain} {count}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(names: &[&str]) -> Vec<Frame> {
        names.iter().map(|n| Frame::User(n.to_string())).collect()
    }

    #[test]
    fn aggregates_repeated_stacks() {
        let mut agg = Aggregator::new();
        agg.add(frames(&["main", "work"]), 3);
        agg.add(frames(&["main", "work"]), 2);
        agg.add(frames(&["main", "idle"]), 1);

        assert_eq!(agg.total(), 6);
        let mut out = Vec::new();
        agg.write_folded(&mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text, "main;idle 1\nmain;work 5\n");
    }

    #[test]
    fn empty_aggregator_produces_no_output() {
        let agg = Aggregator::new();
        assert!(agg.is_empty());
        let mut out = Vec::new();
        agg.write_folded(&mut out).unwrap();
        assert!(out.is_empty());
    }
}
