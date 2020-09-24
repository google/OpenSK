#![no_main]
extern crate alloc;

use alloc::vec::Vec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = cbor::read(data) {
        let mut result = Vec::new();
        assert!(cbor::write(value, &mut result));
        assert_eq!(result, data);
    };
});
