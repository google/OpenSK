#![no_main]

extern crate ctap2;
extern crate libtock_drivers;
extern crate crypto;

use libfuzzer_sys::fuzz_target;
use ctap2::ctap::hid::receive::MessageAssembler;
use ctap2::ctap::hid::send::HidPacketIterator;
use ctap2::ctap::hid::{Message, CtapHid};
use ctap2::ctap::CtapState;
use libtock_drivers::timer::{Timestamp, ClockValue};
use crypto::rng256;

const CLOCK_FREQUENCY_HZ: usize = 32768;
const DUMMY_TIMESTAMP: Timestamp<isize> = Timestamp::from_ms(0);
const DUMMY_CLOCK_VALUE: ClockValue = ClockValue::new(0, CLOCK_FREQUENCY_HZ);

/* Fuzzing message splitting, assembling and packets processing at CTAP HID level.
Inputs: well-formed Message type deriving from Arbitrary trait */
fuzz_target!(|data: Message| {
    if let Some(hid_packet_iterator) = HidPacketIterator::new(data){
        let mut assembler_reply = MessageAssembler::new();
        let mut rng = rng256::ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);
        let mut ctap_hid = CtapHid::new();
        for pkt_request in hid_packet_iterator {
            for pkt_reply in
                ctap_hid.process_hid_packet(&pkt_request, DUMMY_CLOCK_VALUE, &mut ctap_state)
            {
                // Only checks for assembling crashes, not for semantics
                assembler_reply.parse_packet(&pkt_reply, DUMMY_TIMESTAMP);
            }
        }
    }
});
