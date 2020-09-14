#![no_main]

extern crate ctap2;
extern crate libtock_drivers;
extern crate crypto;
#[macro_use]
extern crate arrayref;

use libfuzzer_sys::fuzz_target;

use ctap2::ctap::hid::receive::MessageAssembler;
use ctap2::ctap::hid::send::HidPacketIterator;
use ctap2::ctap::hid::{CtapHid, Message};
use ctap2::ctap::CtapState;
use libtock_drivers::timer::{Timestamp, ClockValue};
use crypto::rng256::ThreadRng256;

const CLOCK_FREQUENCY_HZ: usize = 32768;
const DUMMY_TIMESTAMP: Timestamp<isize> = Timestamp::from_ms(0);
const DUMMY_CLOCK_VALUE: ClockValue = ClockValue::new(0, CLOCK_FREQUENCY_HZ);

fn raw_to_message(data: &[u8], len: usize) -> Message{
    if len <= 4 {
        let mut cid = [0;4];
        cid[..len].copy_from_slice(data);
        Message{
            cid,
            cmd: 0,
            payload: vec![],
        }
    }
    else if len == 5{
        Message{
            cid: array_ref!(data,0,4).clone(),
            cmd: data[4],
            payload: vec![],
        }
    }
    else{
        Message {
            cid: array_ref!(data,0,4).clone(),
            cmd: data[4],
            payload: data[5..].to_vec(),
        }
    }
}

/* Fuzzing message splitting, assembling and packets processing at CTAP HID level,
treating inputs as CTAP1 U2F raw message. */
fuzz_target!(|data: &[u8]| {
    let mut new_data = vec![0xff, 0xff, 0xff, 0xff, 0x03];
    new_data.extend(data);
    let message = raw_to_message(&new_data, new_data.len());
    if let Some(hid_packet_iterator) = HidPacketIterator::new(message){
        let mut assembler_reply = MessageAssembler::new();
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);
        let mut ctap_hid = CtapHid::new();
        for pkt_request in hid_packet_iterator {
            for pkt_reply in ctap_hid.process_hid_packet(&pkt_request, DUMMY_CLOCK_VALUE, &mut ctap_state)
            {
                assembler_reply.parse_packet(&pkt_reply, DUMMY_TIMESTAMP);
            }
        }
    }
});
