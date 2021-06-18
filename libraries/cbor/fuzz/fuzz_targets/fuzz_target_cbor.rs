#![no_main]
extern crate alloc;

use alloc::vec::Vec;
use libfuzzer_sys::fuzz_target;
use sk_cbor as cbor;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = cbor::read(data) {
        let mut result = Vec::new();
        assert!(cbor::write(value, &mut result).is_ok());
        assert_eq!(result, data);
    };
});
