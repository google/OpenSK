#![no_main]

use fuzz_helper::{InputType, process_ctap_structured};
use libfuzzer_sys::fuzz_target;

// Fuzz inputs as CTAP2 get assertion command parameters.
// The inputs will used to construct arbitrary get assertion parameters.
fuzz_target!(|data: &[u8]| {
    process_ctap_structured(data, InputType::CborGetAssertionParameter).ok();
});
