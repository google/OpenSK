#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate alloc;
extern crate cbor;

use alloc::vec::Vec;

fuzz_target!(|data: &[u8]| {
    let encoded = cbor::read(data);
    if let Ok(value) = encoded {
	let mut decoded = Vec::new();
	let result = cbor::write(value, &mut decoded);
	assert!(result);
	assert_eq!(decoded, data);
    };
});

