#![no_main]

use fuzz_helper::{process_ctap_specific_type, InputType};
use libfuzzer_sys::fuzz_target;

// Fuzz inputs as CTAP2 client pin command parameters encoded in cbor.
// For a more generic fuzz target including all CTAP commands, you can use
// fuzz_target_process_ctap_command.
fuzz_target!(|data: &[u8]| {
    process_ctap_specific_type(data, InputType::CborClientPinParameter).ok();
});
