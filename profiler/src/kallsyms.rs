//! Kernel symbol resolution via `/proc/kallsyms`.

/// A sorted snapshot of `/proc/kallsyms`, resolvable by binary search.
pub struct Kallsyms {
    /// Sorted by address, ascending.
    entries: Vec<(u64, String)>,
    /// False if every address read as zero (e.g. `kptr_restrict` hides
    /// addresses from unprivileged reads) - in that case kernel frames
    /// can't be resolved at all.
    available: bool,
}

impl Kallsyms {
    pub fn load() -> anyhow::Result<Self> {
        let text = std::fs::read_to_string("/proc/kallsyms")?;
        Ok(Self::parse(&text))
    }

    fn parse(text: &str) -> Self {
        let all: Vec<(u64, String)> = text
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let addr = u64::from_str_radix(parts.next()?, 16).ok()?;
                let _kind = parts.next()?;
                let name = parts.next()?;
                Some((addr, name.to_string()))
            })
            .collect();
        let available = all.iter().any(|(addr, _)| *addr != 0);
        // Zero-address entries (unlocated symbols) are never a meaningful
        // "lower bound" for a real instruction pointer; drop them so they
        // can't be picked up by the binary search below.
        let mut entries: Vec<(u64, String)> =
            all.into_iter().filter(|(addr, _)| *addr != 0).collect();
        entries.sort_by_key(|(addr, _)| *addr);
        Self { entries, available }
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    /// Resolves `ip` to `(symbol_name, offset)`, attributing addresses
    /// between two consecutive entries to the lower symbol.
    pub fn resolve(&self, ip: u64) -> Option<(&str, u64)> {
        if !self.available {
            return None;
        }
        let idx = self.entries.partition_point(|(addr, _)| *addr <= ip);
        if idx == 0 {
            return None;
        }
        let (addr, name) = &self.entries[idx - 1];
        Some((name.as_str(), ip - addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
0000000000000000 A fixed_percpu_data
ffffffff81000000 T startup_64
ffffffff81000000 T _stext
ffffffff81200000 T secondary_startup_64
ffffffff81400000 t do_idle
ffffffff81400500 T schedule
";

    #[test]
    fn resolves_exact_match() {
        let k = Kallsyms::parse(FIXTURE);
        assert_eq!(
            k.resolve(0xffffffff81200000),
            Some(("secondary_startup_64", 0))
        );
    }

    #[test]
    fn resolves_offset_between_symbols() {
        let k = Kallsyms::parse(FIXTURE);
        assert_eq!(k.resolve(0xffffffff81400200), Some(("do_idle", 0x200)));
    }

    #[test]
    fn ip_before_first_symbol_is_unresolved() {
        let k = Kallsyms::parse(FIXTURE);
        // Only the zero-address entry sorts before this, and zero-address
        // entries are never a valid "lower bound" symbol for real IPs
        // since they represent unlocated/undefined symbols.
        assert_eq!(k.resolve(0x10), None);
    }

    #[test]
    fn detects_all_zero_addresses_as_unavailable() {
        let restricted = "0000000000000000 T startup_64\n0000000000000000 T schedule\n";
        let k = Kallsyms::parse(restricted);
        assert!(!k.is_available());
        assert_eq!(k.resolve(0x1234), None);
    }

    #[test]
    fn picks_last_symbol_at_or_before_ip_with_duplicates() {
        let k = Kallsyms::parse(FIXTURE);
        // Two symbols share address 0xffffffff81000000 (_stext is listed
        // after startup_64); binary search should still resolve cleanly.
        assert_eq!(k.resolve(0xffffffff81000000), Some(("_stext", 0)));
    }
}
