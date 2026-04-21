#![no_main]

use fuzz_helper::{InputType, process_ctap_structured};
use libfuzzer_sys::fuzz_target;

// Fuzz inputs as CTAP2 make credential command parameters.
// The inputs will used to construct arbitrary make credential parameters.
fuzz_target!(|data: &[u8]| {
    process_ctap_structured(data, InputType::CborMakeCredentialParameter).ok();
});
