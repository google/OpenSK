#![allow(dead_code)]
/*
    // CTAP specification (version 20190130) section 8.2
    // TODO: Conformance [APDU definition], section 8.2.1
    // TODO: Protocol, section 8.2.2
    // TODO: Applet selection, section 8.2.3
    // TODO: Framing, section 8.2.4
    {
        // TODO: Commands, section 8.2.4.1
        // CLA  | INS  |  P1  |  P2  |    Lc    |          DATA IN          | Le
        // 0x80 | 0x10 | 0x00 | 0x00 | Variable | CTAP CMD BYTE ║ CBOR Data | Variable
        // 1st packet: 02 | 00 | a4 | 04 | 00 | 08 | a0 00 00 06 47 2f 00 01 | 00
        // 1st packet: 1. | 2. | 3. | 4. | 5. | 6. |            7.           | 8.
        /*
        1. ISO7816 APDU encapsulation over ISO14443-A protocol.
        2. CLA: Instruction class - indicates the type of command
        3. INS: Instruction code - indicates the specific command
        4. P1:  Instruction parameter for the command
        5. P2:  Instruction parameter for the command
        6. Lc:  Encodes the number (Nc) of bytes of `command data` to follow
        7. AID: RID | PIX
        8. Le:  Encodes the maximum number (Ne) of `response bytes` expected
        */
        // Le: Encodes the maximum number (Ne) of response bytes expected
    }
    // TODO: Fragmentation, section 8.2.5
    {
        // Short APDU Chaining commands
        // CLA  | INS  |  P1  |  P2  | DATA IN
        // 0x90 | 0x10 | 0x00 | 0x00 | CTAP Payload
    }
    // TODO: Commands, section 8.2.6
    {
        // TODO: NFCCTAP_MSG (0x10), section 8.2.6.1
        // TODO: NFCCTAP_GETRESPONSE (0x11), section 8.2.6.2
    }
*/

pub mod type4_app;
pub mod ctap_app;


#[allow(non_snake_case)]
pub struct CapabilityContainer {
    cclen_hi: u8,
    cclen_lo: u8,
    version: u8,
    MLe_lo: u8,
    MLe_hi: u8,
    MLc_hi: u8,
    MLc_lo: u8,
    tlv: [u8; 8],
}

const COMMAND_LEN: u8 = 1;å

#[allow(non_camel_case_types)]
pub enum NfcCommand {
    REQA: u8 = 0x26,
    WUPA: u8 = 0x52,
    HALT: u8 = 0x50,
    RATS: u8 = 0xe0,
    /// ISO14443A cmd NXP DESELECT
    DESELECT: u8 =  0xC2,
    Unknown,
}

impl From<u8> for NfcCommand {
    fn from(cmd: u8) -> Self {
        match cmd {
            0x26 => NfcCommand::REQA,
            0x52 => NfcCommand::WUPA,
            0x50 => NfcCommand::HALT,
            0xe0 => NfcCommand::RATS,
            0xC2 => NfcCommand::DESELECT,
            _    => NfcCommand::Unknown,
        }
    }
}

pub type NfcPacket = [u8; 256];

#[allow(non_camel_case_types)]
pub enum NfcStatusCode {
    INVALID_CMD,
    Apdu(ApduStatusCode),
}

pub struct NfcFrame {
    // can be either (0x02 or 0x03) or NFC command
    command: u8,
    apdu: APDU,
}

impl NfcFrame {
    pub fn new(command: u8) -> Self {
        Self {
            command: command,
            apdu: Default::default();
        }
    }
}

impl TryFrom<&[u8]> for NfcFrame {
    type Error = NfcStatusCode;

    // TODO: what calls this should send only the received amount of data
    fn try_from(frame: &[u8]) -> Result<Self, NfcStatusCode> {
        let command: NfcCommand = frame[0].into();
        match command {
            NfcCommand::Unknown => {
                if frame[0] != 0x02 && frame[0] != 0x03 {
                    return Err(NfcStatusCode::INVALID_CMD);
                }
                NfcFrame {
                    command: frame[0],
                    // TODO: handle the result correctly
                    apdu: APDU::try_from(frame[COMMAND_LEN..]),
                }
            }
            _ => NfcFrame::new(command),
        }
    }
}

pub trait HandleApdu {
    fn get_header(&self) -> ApduHeader;
    fn get_cla(&self);
}

#[allow(non_camel_case_types)]
pub enum Applet {
    AID_NDEF_TYPE_4,
    AID_CAPABILITY_CONTAINER,
    AID_NDEF_TAG,
    AID_FIDO,
}

impl Applet {
    fn value(&self) -> &[u8] {
        match *self {
            Applet::AID_NDEF_TYPE_4 => b"\xD2\x76\x00\x00\x85\x01\x01",
            Applet::AID_CAPABILITY_CONTAINER => b"\xE1\x03",
            Applet::AID_NDEF_TAG => b"\xE1\x04",
            Applet::AID_FIDO => b"\xa0\x00\x00\x06\x47\x2f\x00\x01",
        }
    }
}

