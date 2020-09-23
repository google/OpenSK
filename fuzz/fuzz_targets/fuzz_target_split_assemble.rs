#![no_main]

// This explicit "extern crate" is needed to make the linker aware of the
// `libtock_alloc_init` symbol.
extern crate lang_items;

use arrayref::array_ref;
use ctap2::ctap::hid::receive::MessageAssembler;
use ctap2::ctap::hid::send::HidPacketIterator;
use ctap2::ctap::hid::{HidPacket, Message};
use libfuzzer_sys::fuzz_target;
use libtock_drivers::timer::Timestamp;

const DUMMY_TIMESTAMP: Timestamp<isize> = Timestamp::from_ms(0);
const PACKET_TYPE_MASK: u8 = 0x80;

// Converts a byte slice into Message
fn raw_to_message(data: &[u8]) -> Message {
    if data.len() <= 4 {
        let mut cid = [0; 4];
        cid[..data.len()].copy_from_slice(data);
        Message {
            cid,
            cmd: 0,
            payload: vec![],
        }
    } else {
        Message {
            cid: array_ref!(data, 0, 4).clone(),
            cmd: data[4],
            payload: data[5..].to_vec(),
        }
    }
}

/* Fuzzing HID packets splitting and assembling functions*/
fuzz_target!(|data: &[u8]| {
    let mut message = raw_to_message(data);
    if let Some(hid_packet_iterator) = HidPacketIterator::new(message.clone()) {
        let mut assembler = MessageAssembler::new();
        let packets: Vec<HidPacket> = hid_packet_iterator.collect();
        if let Some((last_packet, first_packets)) = packets.split_last() {
            for packet in first_packets {
                assert_eq!(assembler.parse_packet(packet, DUMMY_TIMESTAMP), Ok(None));
            }
            message.cmd &= !PACKET_TYPE_MASK;
            assert_eq!(
                assembler.parse_packet(last_packet, DUMMY_TIMESTAMP),
                Ok(Some(message))
            );
        }
    }
});
