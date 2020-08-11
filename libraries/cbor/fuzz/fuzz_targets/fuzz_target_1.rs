#![no_main]
#[macro_use] 
extern crate libfuzzer_sys;
extern crate cbor;
extern crate alloc;

use alloc::vec::Vec;

fuzz_target!(|data: &[u8]| {
    let encoded = cbor::read(data);
    match encoded{
    	Ok(value) => {
    		let mut decoded = Vec::new();
    		let _ = cbor::write(value, &mut decoded);
    		assert_eq!(decoded, data);
    	}
    	Err(_) => {}
    };
});

