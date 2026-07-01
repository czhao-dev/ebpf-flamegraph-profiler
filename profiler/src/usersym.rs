//! User-space symbol resolution: `/proc/<pid>/maps` + ELF symbol tables,
//! cached per binary by `(dev, inode)` so a library shared across many
//! processes is only parsed once.

use std::collections::HashMap;
use std::path::Path;

use object::{Object, ObjectSymbol, SymbolKind};

#[derive(Clone, Debug)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub dev: u64,
    pub inode: u64,
    pub path: Option<String>,
}

pub struct ProcMaps {
    entries: Vec<MapEntry>,
}

impl ProcMaps {
    pub fn load(pid: u32) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
        Ok(Self::parse(&text))
    }

    fn parse(text: &str) -> Self {
        let entries = text.lines().filter_map(parse_maps_line).collect();
        Self { entries }
    }

    /// The mapping containing `ip`, if it's backed by a real file
    /// (anonymous mappings have `inode == 0` and are never resolvable).
    pub fn find(&self, ip: u64) -> Option<&MapEntry> {
        self.entries
            .iter()
            .find(|e| e.inode != 0 && e.path.is_some() && ip >= e.start && ip < e.end)
    }
}

fn parse_maps_line(line: &str) -> Option<MapEntry> {
    // Collect all whitespace-separated tokens rather than pulling the path
    // via a single `.next()`: paths can (rarely) contain spaces, and the
    // fixed fields before it never do, so anything from the 6th token
    // onward is rejoined as the path.
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 5 {
        return None;
    }
    let (start_s, end_s) = tokens[0].split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;
    let file_offset = u64::from_str_radix(tokens[2], 16).ok()?;
    let (maj_s, min_s) = tokens[3].split_once(':')?;
    let maj = u64::from_str_radix(maj_s, 16).ok()?;
    let min = u64::from_str_radix(min_s, 16).ok()?;
    let dev = (maj << 8) | min;
    let inode: u64 = tokens[4].parse().ok()?;
    let path = (tokens.len() > 5).then(|| tokens[5..].join(" "));
    Some(MapEntry {
        start,
        end,
        file_offset,
        dev,
        inode,
        path,
    })
}

/// Sorted, file-relative-address symbol table for one ELF binary.
pub struct BinarySymbolTable {
    entries: Vec<(u64, String)>,
}

impl BinarySymbolTable {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        let file = object::File::parse(&*data)?;

        let mut entries = collect_text_symbols(&file, false);
        if entries.is_empty() {
            // Binary is stripped of .symtab; fall back to the dynamic
            // symbol table (exported symbols only).
            entries = collect_text_symbols(&file, true);
        }
        entries.sort_by_key(|(addr, _)| *addr);
        entries.dedup_by_key(|(addr, _)| *addr);
        Ok(Self { entries })
    }

    pub fn resolve(&self, file_vaddr: u64) -> Option<(&str, u64)> {
        let idx = self
            .entries
            .partition_point(|(addr, _)| *addr <= file_vaddr);
        if idx == 0 {
            return None;
        }
        let (addr, name) = &self.entries[idx - 1];
        Some((name.as_str(), file_vaddr - addr))
    }
}

fn collect_text_symbols(file: &object::File, dynamic: bool) -> Vec<(u64, String)> {
    let symbols: Box<dyn Iterator<Item = object::Symbol>> = if dynamic {
        Box::new(file.dynamic_symbols())
    } else {
        Box::new(file.symbols())
    };
    symbols
        .filter(|s| s.kind() == SymbolKind::Text)
        .filter_map(|s| {
            let name = s.name().ok()?;
            if name.is_empty() {
                return None;
            }
            Some((s.address(), name.to_string()))
        })
        .collect()
}

/// Resolves user-space instruction pointers to `(function_name, offset)`,
/// caching parsed ELF symbol tables by `(dev, inode)` and process memory
/// maps by pid.
pub struct UserSymbolCache {
    tables: HashMap<(u64, u64), BinarySymbolTable>,
    proc_maps: HashMap<u32, ProcMaps>,
}

impl UserSymbolCache {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
            proc_maps: HashMap::new(),
        }
    }

    /// Re-reads `/proc/<pid>/maps`. Call once per drain cycle before
    /// resolving IPs for `pid`, since mmap/exec can change mappings
    /// between cycles.
    pub fn refresh_proc_maps(&mut self, pid: u32) -> anyhow::Result<()> {
        self.proc_maps.insert(pid, ProcMaps::load(pid)?);
        Ok(())
    }

    #[cfg(test)]
    fn set_proc_maps(&mut self, pid: u32, maps: ProcMaps) {
        self.proc_maps.insert(pid, maps);
    }

    pub fn resolve(&mut self, pid: u32, ip: u64) -> Option<(String, u64)> {
        let entry = self.proc_maps.get(&pid)?.find(ip)?.clone();
        let path = entry.path.as_ref()?;
        let key = (entry.dev, entry.inode);
        let table = match self.tables.entry(key) {
            std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => {
                let table = BinarySymbolTable::load(Path::new(path)).ok()?;
                v.insert(table)
            }
        };
        let file_vaddr = ip - entry.start + entry.file_offset;
        table
            .resolve(file_vaddr)
            .map(|(name, off)| (name.to_string(), off))
    }

    pub fn cached_binary_count(&self) -> usize {
        self.tables.len()
    }
}

impl Default for UserSymbolCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS_FIXTURE: &str = "\
00400000-00401000 r-xp 00000000 08:01 123456 /usr/bin/fixture
00401000-00402000 rw-p 00001000 08:01 123456 /usr/bin/fixture
7f0000000000-7f0000010000 r-xp 00000000 08:01 654321 /usr/lib/libfixture.so
7fff00000000-7fff00021000 rw-p 00000000 00:00 0 [stack]
";

    #[test]
    fn parses_proc_maps_lines() {
        let maps = ProcMaps::parse(MAPS_FIXTURE);
        let e = maps.find(0x400500).unwrap();
        assert_eq!(e.dev, 0x801);
        assert_eq!(e.inode, 123456);
        assert_eq!(e.path.as_deref(), Some("/usr/bin/fixture"));
    }

    #[test]
    fn anonymous_mappings_are_unresolvable() {
        let maps = ProcMaps::parse(MAPS_FIXTURE);
        assert!(maps.find(0x7fff00000100).is_none());
    }

    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fixture.o")
    }

    #[test]
    fn resolves_elf_symbols_by_address() {
        let table = BinarySymbolTable::load(&fixture_path()).unwrap();
        assert_eq!(table.resolve(0x0), Some(("helper_one", 0)));
        assert_eq!(table.resolve(0x10), Some(("helper_two", 0)));
        assert_eq!(table.resolve(0x25), Some(("main_entry", 5)));
    }

    #[test]
    fn caches_binary_symbol_table_across_resolves() {
        let mut cache = UserSymbolCache::new();
        let fixture = fixture_path().to_str().unwrap().to_string();
        let maps_text = format!("00000000-00001000 r-xp 00000000 08:01 999 {fixture}\n");
        cache.set_proc_maps(42, ProcMaps::parse(&maps_text));

        let first = cache.resolve(42, 0x0);
        let second = cache.resolve(42, 0x10);

        assert_eq!(first, Some(("helper_one".to_string(), 0)));
        assert_eq!(second, Some(("helper_two".to_string(), 0)));
        assert_eq!(cache.cached_binary_count(), 1);
    }
}
