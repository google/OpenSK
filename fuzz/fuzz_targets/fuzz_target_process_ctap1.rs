#![no_main]

use fuzz_helper::{process_input, InputType};
use libfuzzer_sys::fuzz_target;

// Fuzz inputs as CTAP1 U2F raw message.
fuzz_target!(|data: &[u8]| {
    process_input(data, InputType::Ctap1);
});
