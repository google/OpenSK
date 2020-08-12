#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate alloc;
extern crate cbor;

use alloc::vec::Vec;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = cbor::read(data) {
        let mut result = Vec::new();
        assert!(cbor::write(value, &mut result));
        assert_eq!(result, data);
    };
});
