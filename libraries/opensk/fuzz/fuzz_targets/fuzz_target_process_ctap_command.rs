#![no_main]

use fuzz_helper::process_ctap_any_type;
use libfuzzer_sys::fuzz_target;

// Generically fuzz inputs as CTAP commands.
fuzz_target!(|data: &[u8]| {
    process_ctap_any_type(data).ok();
});
