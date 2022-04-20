#![no_main]

use fuzz_helper::split_assemble_hid_packets;
use libfuzzer_sys::fuzz_target;

// Fuzzing HID packets splitting and assembling functions.
fuzz_target!(|data: &[u8]| {
    split_assemble_hid_packets(data).ok();
});
