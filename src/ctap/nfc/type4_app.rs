// use super::{ApduHeader, CapabilityContainer};
use super::CapabilityContainer;

// FILE ID: 0xe1 0x03
const NFC_CC: CapabilityContainer = CapabilityContainer {
    cclen_hi: 0x00, cclen_lo: 0x0f,
    version: 0x20,
    MLe_hi: 0x00, MLe_lo: 0x7f,
    MLc_hi: 0x00, MLc_lo: 0x7f,
    tlv: [0x04, 0x06, 0xe1, 0x04, 0x00, 0x7f, 0x00, 0x00],
};

// FILE ID: 0xe1 0x04
const NDEF_META: &'static [u8] = b"\x00\x0f\xd1\x01\x0b\x55opensk.dev/";
