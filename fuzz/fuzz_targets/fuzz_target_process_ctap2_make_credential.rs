#![no_main]

use fuzz_helper::{process_input, InputType};
use libfuzzer_sys::fuzz_target;

// Fuzz inputs as CTAP2 make credential command parameters encoded in cbor.
fuzz_target!(|data: &[u8]| {
    process_input(data, InputType::CborMakeCredentialParameter);
});
