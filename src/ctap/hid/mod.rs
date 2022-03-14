// Copyright 2019-2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod receive;
mod send;

// Implementation details must be public for testing (in particular fuzzing).
#[cfg(feature = "std")]
pub use self::receive::MessageAssembler;
#[cfg(not(feature = "std"))]
use self::receive::MessageAssembler;
pub use self::send::HidPacketIterator;
use super::super::clock::{ClockInt, CtapInstant};
use super::status_code::Ctap2StatusCode;
use crate::env::Env;
use alloc::vec;
use alloc::vec::Vec;
use arrayref::{array_ref, array_refs};
use embedded_time::duration::Milliseconds;
#[cfg(test)]
use enum_iterator::IntoEnumIterator;

pub type HidPacket = [u8; 64];
pub type ChannelID = [u8; 4];

/// CTAPHID commands
///
/// See section 11.2.9. of FIDO 2.1 (2021-06-15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(IntoEnumIterator))]
pub enum CtapHidCommand {
    Ping = 0x01,
    Msg = 0x03,
    // Lock is optional and may be used in the future.
    Lock = 0x04,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10,
    Cancel = 0x11,
    Keepalive = 0x3B,
    Error = 0x3F,
    // The vendor range starts here, going from 0x40 to 0x7F.
}

impl From<u8> for CtapHidCommand {
    fn from(cmd: u8) -> Self {
        match cmd {
            x if x == CtapHidCommand::Ping as u8 => CtapHidCommand::Ping,
            x if x == CtapHidCommand::Msg as u8 => CtapHidCommand::Msg,
            x if x == CtapHidCommand::Lock as u8 => CtapHidCommand::Lock,
            x if x == CtapHidCommand::Init as u8 => CtapHidCommand::Init,
            x if x == CtapHidCommand::Wink as u8 => CtapHidCommand::Wink,
            x if x == CtapHidCommand::Cbor as u8 => CtapHidCommand::Cbor,
            x if x == CtapHidCommand::Cancel as u8 => CtapHidCommand::Cancel,
            x if x == CtapHidCommand::Keepalive as u8 => CtapHidCommand::Keepalive,
            // This includes the actual error code 0x3F. Error is not used for incoming packets in
            // the specification, so we can safely reuse it for unknown bytes.
            _ => CtapHidCommand::Error,
        }
    }
}

/// CTAPHID errors
///
/// See section 11.2.9.1.6. of FIDO 2.1 (2021-06-15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtapHidError {
    /// The command in the request is invalid.
    InvalidCmd = 0x01,
    /// A parameter in the request is invalid.
    _InvalidPar = 0x02,
    /// The length of a message is too big.
    InvalidLen = 0x03,
    /// Expected a continuation packet with a specific sequence number, got another sequence number.
    ///
    /// This error code is also used if we expect a continuation packet, and receive an init
    /// packet. We interpreted it as invalid seq number 0.
    InvalidSeq = 0x04,
    /// This packet arrived after a timeout.
    MsgTimeout = 0x05,
    /// A packet arrived on one channel while another is busy.
    ChannelBusy = 0x06,
    /// Command requires channel lock.
    _LockRequired = 0x0A,
    /// The requested channel ID is invalid.
    InvalidChannel = 0x0B,
    /// Unspecified error.
    _Other = 0x7F,
    /// This error is silently ignored.
    UnexpectedContinuation,
}

/// Describes the structure of a parsed HID packet.
///
/// A packet is either an Init or a Continuation packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessedPacket<'a> {
    InitPacket {
        cmd: u8,
        len: usize,
        data: &'a [u8; 57],
    },
    ContinuationPacket {
        seq: u8,
        data: &'a [u8; 59],
    },
}

/// An assembled CTAPHID command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    // Channel ID.
    pub cid: ChannelID,
    // Command.
    pub cmd: CtapHidCommand,
    // Bytes of the message.
    pub payload: Vec<u8>,
}

/// A keepalive packet reports the reason why a command does not finish.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepaliveStatus {
    Processing = 0x01,
    UpNeeded = 0x02,
}

/// Holds all state for receiving and sending HID packets.
///
/// This includes
/// - state from not fully processed messages,
/// - all allocated channels.
///
/// To process a packet and receive the response, call `parse_packet`. If you didn't receive any
/// message or preprocessing discarded it, stop. Else process the message further, by handling the
/// commands:
///
/// - PING (optional)
/// - MSG
/// - WINK
/// - CBOR
///
/// To get packets to send from your processed message, call `split_message`. Summary:
///
/// 1.  `HidPacket` -> `Option<Message>`
/// 2.  `Option<Message>` -> `Message`
/// 3.  `Message` -> `Message`
/// 4.  `Message` -> `HidPacketIterator`
///
/// These steps correspond to:
///
/// 1.  `parse_packet` assembles the message and preprocesses all pure HID commands and errors.
/// 2.  If you didn't receive any message or preprocessing discarded it, stop.
/// 3.  Handles all CTAP protocol interactions.
/// 4.  `split_message` creates packets out of the response message.
pub struct CtapHid {
    assembler: MessageAssembler,
    // The specification only requires unique CIDs, the allocation algorithm is vendor specific.
    // We allocate them incrementally, that is all `cid` such that 1 <= cid <= allocated_cids are
    // allocated.
    // In packets, the ID encoding is Big Endian to match what is used throughout CTAP (with the
    // u32::to/from_be_bytes methods).
    // TODO(kaczmarczyck) We might want to limit or timeout open channels.
    allocated_cids: usize,
}

impl CtapHid {
    // We implement CTAP 2.1 from 2021-06-15. Please see section
    // 11.2. USB Human Interface Device (USB HID)
    const CHANNEL_RESERVED: ChannelID = [0, 0, 0, 0];
    const CHANNEL_BROADCAST: ChannelID = [0xFF, 0xFF, 0xFF, 0xFF];
    const TYPE_INIT_BIT: u8 = 0x80;
    const PACKET_TYPE_MASK: u8 = 0x80;

    // See section 11.2.9.1.3. CTAPHID_INIT (0x06).
    const PROTOCOL_VERSION: u8 = 2;
    // The device version number is vendor-defined.
    const DEVICE_VERSION_MAJOR: u8 = 1;
    const DEVICE_VERSION_MINOR: u8 = 0;
    const DEVICE_VERSION_BUILD: u8 = 0;

    const CAPABILITY_WINK: u8 = 0x01;
    const CAPABILITY_CBOR: u8 = 0x04;
    #[cfg(not(feature = "with_ctap1"))]
    const CAPABILITY_NMSG: u8 = 0x08;

    // Capabilitites currently supported by this device.
    #[cfg(feature = "with_ctap1")]
    const CAPABILITIES: u8 = Self::CAPABILITY_WINK | Self::CAPABILITY_CBOR;
    #[cfg(not(feature = "with_ctap1"))]
    const CAPABILITIES: u8 = Self::CAPABILITY_WINK | Self::CAPABILITY_CBOR | Self::CAPABILITY_NMSG;
    // TODO: Is this timeout duration specified?
    const TIMEOUT_DURATION: Milliseconds<ClockInt> = Milliseconds(100 as ClockInt);

    pub fn new() -> CtapHid {
        CtapHid {
            assembler: MessageAssembler::new(),
            allocated_cids: 0,
        }
    }

    /// Parses a packet, and preprocesses some messages and errors.
    ///
    /// The preprocessed commands are:
    /// - INIT
    /// - CANCEL
    /// - ERROR
    /// - Unknown and unexpected commands like KEEPALIVE
    /// - LOCK is not implemented and currently treated like an unknown command
    ///
    /// Commands that may still be processed:
    /// - PING
    /// - MSG
    /// - WINK
    /// - CBOR
    ///
    /// You may ignore PING, it's behaving correctly by default (input == output).
    /// Ignoring the others is incorrect behavior. You have to at least replace them with an error
    /// message:
    /// `CtapHid::error_message(message.cid, CtapHid::ERR_INVALID_CMD)`
    pub fn parse_packet(
        &mut self,
        env: &mut impl Env,
        packet: &HidPacket,
        clock_value: CtapInstant,
    ) -> Option<Message> {
        match self.assembler.parse_packet(packet, clock_value) {
            Ok(Some(message)) => {
                debug_ctap!(env, "Received message: {:02x?}", message);
                self.preprocess_message(message)
            }
            Ok(None) => {
                // Waiting for more packets to assemble the message, nothing to send for now.
                None
            }
            Err((cid, error)) => {
                if matches!(error, CtapHidError::UnexpectedContinuation) {
                    None
                } else if !self.is_allocated_channel(cid) {
                    Some(CtapHid::error_message(cid, CtapHidError::InvalidChannel))
                } else {
                    Some(CtapHid::error_message(cid, error))
                }
            }
        }
    }

    /// Processes HID-only commands of a message and returns an outgoing message if necessary.
    ///
    /// The preprocessed commands are:
    /// - INIT
    /// - CANCEL
    /// - ERROR
    /// - Unknown and unexpected commands like KEEPALIVE
    /// - LOCK is not implemented and currently treated like an unknown command
    fn preprocess_message(&mut self, message: Message) -> Option<Message> {
        let cid = message.cid;
        if !self.has_valid_channel(&message) {
            return Some(CtapHid::error_message(cid, CtapHidError::InvalidChannel));
        }

        match message.cmd {
            CtapHidCommand::Msg => Some(message),
            CtapHidCommand::Cbor => Some(message),
            // CTAP 2.1 from 2021-06-15, section 11.2.9.1.3.
            CtapHidCommand::Init => {
                if message.payload.len() != 8 {
                    return Some(CtapHid::error_message(cid, CtapHidError::InvalidLen));
                }

                let new_cid = if cid == CtapHid::CHANNEL_BROADCAST {
                    // TODO: Prevent allocating 2^32 channels.
                    self.allocated_cids += 1;
                    (self.allocated_cids as u32).to_be_bytes()
                } else {
                    // Sync the channel and discard the current transaction.
                    cid
                };

                let mut payload = vec![0; 17];
                payload[..8].copy_from_slice(&message.payload);
                payload[8..12].copy_from_slice(&new_cid);
                payload[12] = CtapHid::PROTOCOL_VERSION;
                payload[13] = CtapHid::DEVICE_VERSION_MAJOR;
                payload[14] = CtapHid::DEVICE_VERSION_MINOR;
                payload[15] = CtapHid::DEVICE_VERSION_BUILD;
                payload[16] = CtapHid::CAPABILITIES;

                Some(Message {
                    cid,
                    cmd: CtapHidCommand::Init,
                    payload,
                })
            }
            // CTAP 2.1 from 2021-06-15, section 11.2.9.1.4.
            CtapHidCommand::Ping => {
                // Pong the same message.
                Some(message)
            }
            // CTAP 2.1 from 2021-06-15, section 11.2.9.1.5.
            CtapHidCommand::Cancel => {
                // Authenticators MUST NOT reply to this message.
                // CANCEL is handled during user presence checks in main.
                None
            }
            CtapHidCommand::Wink => Some(message),
            _ => {
                // Unknown or unsupported command.
                Some(CtapHid::error_message(cid, CtapHidError::InvalidCmd))
            }
        }
    }

    fn has_valid_channel(&self, message: &Message) -> bool {
        match message.cid {
            // Only INIT commands use the broadcast channel.
            CtapHid::CHANNEL_BROADCAST => message.cmd == CtapHidCommand::Init,
            // Check that the channel is allocated.
            _ => self.is_allocated_channel(message.cid),
        }
    }

    fn is_allocated_channel(&self, cid: ChannelID) -> bool {
        cid != CtapHid::CHANNEL_RESERVED && u32::from_be_bytes(cid) as usize <= self.allocated_cids
    }

    pub fn error_message(cid: ChannelID, error_code: CtapHidError) -> Message {
        Message {
            cid,
            cmd: CtapHidCommand::Error,
            payload: vec![error_code as u8],
        }
    }

    /// Helper function to parse a raw packet.
    pub fn process_single_packet(packet: &HidPacket) -> (&ChannelID, ProcessedPacket) {
        let (cid, rest) = array_refs![packet, 4, 60];
        if rest[0] & CtapHid::PACKET_TYPE_MASK != 0 {
            let cmd = rest[0] & !CtapHid::PACKET_TYPE_MASK;
            let len = (rest[1] as usize) << 8 | (rest[2] as usize);
            (
                cid,
                ProcessedPacket::InitPacket {
                    cmd,
                    len,
                    data: array_ref!(rest, 3, 57),
                },
            )
        } else {
            (
                cid,
                ProcessedPacket::ContinuationPacket {
                    seq: rest[0],
                    data: array_ref!(rest, 1, 59),
                },
            )
        }
    }

    /// Splits the message and unwraps the result.
    ///
    /// Unwrapping handles the case of payload lengths > 7609 bytes. All responses are fixed
    /// length, with the exception of:
    /// - PING, but here output equals the (validated) input,
    /// - CBOR, where long responses are conceivable.
    ///
    /// Long CBOR responses should not happen, but we might not catch all edge cases, like for
    /// example long user names that are part of the output of an assertion. These cases should be
    /// correctly handled by the CTAP implementation. It is therefore an internal error from the
    /// HID perspective.
    pub fn split_message(message: Message) -> HidPacketIterator {
        let cid = message.cid;
        HidPacketIterator::new(message).unwrap_or_else(|| {
            // The error payload is 1 <= 7609 bytes, so unwrap() is safe.
            HidPacketIterator::new(Message {
                cid,
                cmd: CtapHidCommand::Cbor,
                payload: vec![Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR as u8],
            })
            .unwrap()
        })
    }

    /// Generates the HID response packets for a keepalive status.
    pub fn keepalive(cid: ChannelID, status: KeepaliveStatus) -> HidPacketIterator {
        CtapHid::split_message(Message {
            cid,
            cmd: CtapHidCommand::Keepalive,
            payload: vec![status as u8],
        })
    }

    #[cfg(test)]
    pub fn new_initialized() -> (CtapHid, ChannelID) {
        (
            CtapHid {
                assembler: MessageAssembler::new(),
                allocated_cids: 1,
            },
            [0x00, 0x00, 0x00, 0x01],
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;

    #[test]
    fn test_split_assemble() {
        for payload_len in 0..7609 {
            let message = Message {
                cid: [0x12, 0x34, 0x56, 0x78],
                cmd: CtapHidCommand::Cbor,
                payload: vec![0xFF; payload_len],
            };

            let mut messages = Vec::new();
            let mut assembler = MessageAssembler::new();
            for packet in HidPacketIterator::new(message.clone()).unwrap() {
                match assembler.parse_packet(&packet, CtapInstant::new(0)) {
                    Ok(Some(msg)) => messages.push(msg),
                    Ok(None) => (),
                    Err(_) => panic!("Couldn't assemble packet: {:02x?}", &packet as &[u8]),
                }
            }

            assert_eq!(messages, vec![message]);
        }
    }

    #[test]
    fn test_spurious_continuation_packet() {
        let mut env = TestEnv::new();
        let mut ctap_hid = CtapHid::new();
        let mut packet = [0x00; 64];
        packet[0..7].copy_from_slice(&[0xC1, 0xC1, 0xC1, 0xC1, 0x00, 0x51, 0x51]);
        // Continuation packets are silently ignored.
        assert_eq!(
            ctap_hid.parse_packet(&mut env, &packet, CtapInstant::new(0)),
            None
        );
    }

    #[test]
    fn test_command_init() {
        let mut ctap_hid = CtapHid::new();
        let init_message = Message {
            cid: CtapHid::CHANNEL_BROADCAST,
            cmd: CtapHidCommand::Init,
            payload: vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
        };
        let reply = ctap_hid.preprocess_message(init_message);
        assert_eq!(
            reply,
            Some(Message {
                cid: CtapHid::CHANNEL_BROADCAST,
                cmd: CtapHidCommand::Init,
                payload: vec![
                    0x12, // Nonce
                    0x34,
                    0x56,
                    0x78,
                    0x9A,
                    0xBC,
                    0xDE,
                    0xF0,
                    0x00, // Allocated CID
                    0x00,
                    0x00,
                    0x01,
                    0x02, // Protocol version
                    0x01, // Device version
                    0x00,
                    0x00,
                    CtapHid::CAPABILITIES
                ]
            })
        );
    }

    #[test]
    fn test_command_init_for_sync() {
        let mut env = TestEnv::new();
        let (mut ctap_hid, cid) = CtapHid::new_initialized();

        // Ping packet with a length longer than one packet.
        let mut packet1 = [0x51; 64];
        packet1[..4].copy_from_slice(&cid);
        packet1[4..7].copy_from_slice(&[0x81, 0x02, 0x00]);
        // Init packet on the same channel.
        let mut packet2 = [0x00; 64];
        packet2[..4].copy_from_slice(&cid);
        packet2[4..15].copy_from_slice(&[
            0x86, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        ]);
        assert_eq!(
            ctap_hid.parse_packet(&mut env, &packet1, CtapInstant::new(0)),
            None
        );
        assert_eq!(
            ctap_hid.parse_packet(&mut env, &packet2, CtapInstant::new(0)),
            Some(Message {
                cid,
                cmd: CtapHidCommand::Init,
                payload: vec![
                    0x12, // Nonce
                    0x34,
                    0x56,
                    0x78,
                    0x9A,
                    0xBC,
                    0xDE,
                    0xF0,
                    cid[0], // Allocated CID
                    cid[1],
                    cid[2],
                    cid[3],
                    0x02, // Protocol version
                    0x01, // Device version
                    0x00,
                    0x00,
                    CtapHid::CAPABILITIES
                ]
            })
        );
    }

    #[test]
    fn test_command_ping() {
        let mut env = TestEnv::new();
        let (mut ctap_hid, cid) = CtapHid::new_initialized();

        let mut ping_packet = [0x00; 64];
        ping_packet[..4].copy_from_slice(&cid);
        ping_packet[4..9].copy_from_slice(&[0x81, 0x00, 0x02, 0x99, 0x99]);
        assert_eq!(
            ctap_hid.parse_packet(&mut env, &ping_packet, CtapInstant::new(0)),
            Some(Message {
                cid,
                cmd: CtapHidCommand::Ping,
                payload: vec![0x99, 0x99]
            })
        );
    }

    #[test]
    fn test_command_cancel() {
        let mut env = TestEnv::new();
        let (mut ctap_hid, cid) = CtapHid::new_initialized();

        let mut cancel_packet = [0x00; 64];
        cancel_packet[..4].copy_from_slice(&cid);
        cancel_packet[4..7].copy_from_slice(&[0x91, 0x00, 0x00]);

        let response = ctap_hid.parse_packet(&mut env, &cancel_packet, CtapInstant::new(0));
        assert_eq!(response, None);
    }

    #[test]
    fn test_split_message() {
        let message = Message {
            cid: [0x12, 0x34, 0x56, 0x78],
            cmd: CtapHidCommand::Ping,
            payload: vec![0x99, 0x99],
        };
        let mut response = CtapHid::split_message(message);
        let mut expected_packet = [0x00; 64];
        expected_packet[..9]
            .copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x00, 0x02, 0x99, 0x99]);
        assert_eq!(response.next(), Some(expected_packet));
        assert_eq!(response.next(), None);
    }

    #[test]
    fn test_split_message_too_large() {
        let payload = vec![0xFF; 7609 + 1];
        let message = Message {
            cid: [0x12, 0x34, 0x56, 0x78],
            cmd: CtapHidCommand::Cbor,
            payload,
        };
        let mut response = CtapHid::split_message(message);
        let mut expected_packet = [0x00; 64];
        expected_packet[..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x00, 0x01, 0xF2]);
        assert_eq!(response.next(), Some(expected_packet));
        assert_eq!(response.next(), None);
    }

    #[test]
    fn test_keepalive() {
        for &status in [KeepaliveStatus::Processing, KeepaliveStatus::UpNeeded].iter() {
            let cid = [0x12, 0x34, 0x56, 0x78];
            let mut response = CtapHid::keepalive(cid, status);
            let mut expected_packet = [0x00; 64];
            expected_packet[..8].copy_from_slice(&[
                0x12,
                0x34,
                0x56,
                0x78,
                0xBB,
                0x00,
                0x01,
                status as u8,
            ]);
            assert_eq!(response.next(), Some(expected_packet));
            assert_eq!(response.next(), None);
        }
    }

    #[test]
    fn test_process_single_packet() {
        let cid = [0x12, 0x34, 0x56, 0x78];
        let mut packet = [0x00; 64];
        packet[..4].copy_from_slice(&cid);
        packet[4..9].copy_from_slice(&[0x81, 0x00, 0x02, 0x99, 0x99]);
        let (processed_cid, processed_packet) = CtapHid::process_single_packet(&packet);
        assert_eq!(processed_cid, &cid);
        let expected_packet = ProcessedPacket::InitPacket {
            cmd: CtapHidCommand::Ping as u8,
            len: 2,
            data: array_ref!(packet, 7, 57),
        };
        assert_eq!(processed_packet, expected_packet);
    }

    #[test]
    fn test_from_ctap_hid_command() {
        // 0x3E is unassigned.
        assert_eq!(CtapHidCommand::from(0x3E), CtapHidCommand::Error);
        for command in CtapHidCommand::into_enum_iter() {
            assert_eq!(CtapHidCommand::from(command as u8), command);
        }
    }

    #[test]
    fn test_error_message() {
        let cid = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(
            CtapHid::error_message(cid, CtapHidError::InvalidCmd),
            Message {
                cid,
                cmd: CtapHidCommand::Error,
                payload: vec![0x01],
            }
        );
    }
}
