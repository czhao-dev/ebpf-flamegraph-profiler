#![allow(non_camel_case_types, non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub type SampleKey = sample_key;

// Safety: `SampleKey` is a `#[repr(C)]` struct of plain integer fields with
// no padding-sensitive invariants, generated from the same header the BPF
// program uses as its map key type.
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for SampleKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn sample_key_layout_matches_c_struct() {
        // 4 x u32/i32 fields, no padding expected.
        assert_eq!(size_of::<SampleKey>(), 16);
    }

    #[test]
    fn sample_key_is_plain_data() {
        let key = SampleKey {
            pid: 1,
            tgid: 2,
            kern_stack_id: -1,
            user_stack_id: -1,
        };
        let copy = key;
        assert_eq!(key, copy);
    }
}
