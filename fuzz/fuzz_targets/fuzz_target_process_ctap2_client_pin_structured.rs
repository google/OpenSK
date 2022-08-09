#![no_main]

use fuzz_helper::{process_ctap_structured, InputType};
use libfuzzer_sys::fuzz_target;

// Fuzz inputs as CTAP2 client pin command parameters.
// The inputs will used to construct arbitrary client pin parameters.
fuzz_target!(|data: &[u8]| {
    process_ctap_structured(data, InputType::CborClientPinParameter).ok();
});
