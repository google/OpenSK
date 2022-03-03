// Copyright 2019-2021 Google LLC
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

pub mod receive;
pub mod send;

use self::receive::MessageAssembler;
use self::send::HidPacketIterator;
#[cfg(feature = "with_ctap1")]
use super::ctap1;
use super::status_code::Ctap2StatusCode;
use super::timed_permission::TimedPermission;
use super::CtapState;
use crate::env::Env;
use alloc::vec;
use alloc::vec::Vec;
use arrayref::{array_ref, array_refs};
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
#[cfg(feature = "debug_ctap")]
use libtock_drivers::console::Console;
use libtock_drivers::timer::{ClockValue, Duration, Timestamp};

pub type HidPacket = [u8; 64];
pub type ChannelID = [u8; 4];

/// CTAPHID commands
///
/// See section 11.2.9. of FIDO 2.1 (2021-06-15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    // VendorFirst and VendorLast describe a range, and are not commands themselves.
    _VendorFirst = 0x40,
    _VendorLast = 0x7F,
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

/// Describes the structure of a parsed HID packet.
///
/// A packet is either an Init or a Continuation packet.
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
pub enum KeepaliveStatus {
    Processing = 0x01,
    UpNeeded = 0x02,
}

/// Holds all state for receiving and sending HID packets.
///
/// This includes
/// - state from not fully processed messages,
/// - all allocated channels,
/// - information about requested winks.
///
/// The wink information can be polled to decide to i.e. blink LEDs.
///
/// To process a packet and receive the response, you can call `process_hid_packet`.
/// If you want more control, you can also do the processing in steps:
///
/// 1.  `HidPacket` -> `Option<Message>`
///     `parse_packet` assembles the message and preprocesses all pure HID commands and errors.
/// 2.  `Option<Message>` -> `Message`
///     If you didn't receive any message or preprocessing discarded it, stop.
/// 3.  `Message` -> `Message`
///     `process_message` handles all protocol interactions.
/// 4.  `Message` -> `HidPacketIterator
///     `split_message` creates packets out of the response message.
pub struct CtapHid {
    assembler: MessageAssembler,
    // The specification only requires unique CIDs, the allocation algorithm is vendor specific.
    // We allocate them incrementally, that is all `cid` such that 1 <= cid <= allocated_cids are
    // allocated.
    // In packets, the ID encoding is Big Endian to match what is used throughout CTAP (with the
    // u32::to/from_be_bytes methods).
    // TODO(kaczmarczyck) We might want to limit or timeout open channels.
    allocated_cids: usize,
    pub(crate) wink_permission: TimedPermission,
}

impl CtapHid {
    // We implement CTAP 2.1 from 2021-06-15. Please see section
    // 11.2. USB Human Interface Device (USB HID)
    const CHANNEL_RESERVED: ChannelID = [0, 0, 0, 0];
    const CHANNEL_BROADCAST: ChannelID = [0xFF, 0xFF, 0xFF, 0xFF];
    const TYPE_INIT_BIT: u8 = 0x80;
    const PACKET_TYPE_MASK: u8 = 0x80;

    const ERR_INVALID_CMD: u8 = 0x01;
    const _ERR_INVALID_PAR: u8 = 0x02;
    const ERR_INVALID_LEN: u8 = 0x03;
    const ERR_INVALID_SEQ: u8 = 0x04;
    const ERR_MSG_TIMEOUT: u8 = 0x05;
    const ERR_CHANNEL_BUSY: u8 = 0x06;
    const _ERR_LOCK_REQUIRED: u8 = 0x0A;
    const ERR_INVALID_CHANNEL: u8 = 0x0B;
    const _ERR_OTHER: u8 = 0x7F;

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
    const CAPABILITIES: u8 = CtapHid::CAPABILITY_WINK | CtapHid::CAPABILITY_CBOR;
    #[cfg(not(feature = "with_ctap1"))]
    const CAPABILITIES: u8 =
        CtapHid::CAPABILITY_WINK | CtapHid::CAPABILITY_CBOR | CtapHid::CAPABILITY_NMSG;

    // TODO: Is this timeout duration specified?
    const TIMEOUT_DURATION: Duration<isize> = Duration::from_ms(100);
    const WINK_TIMEOUT_DURATION: Duration<isize> = Duration::from_ms(5000);

    /// Creates a new idle HID state.
    pub fn new() -> CtapHid {
        CtapHid {
            assembler: MessageAssembler::new(),
            allocated_cids: 0,
            wink_permission: TimedPermission::waiting(),
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
    pub fn parse_packet(&mut self, packet: &HidPacket, clock_value: ClockValue) -> Option<Message> {
        match self
            .assembler
            .parse_packet(packet, Timestamp::<isize>::from_clock_value(clock_value))
        {
            Ok(Some(message)) => {
                #[cfg(feature = "debug_ctap")]
                writeln!(&mut Console::new(), "Received message: {:02x?}", message).unwrap();
                self.preprocess_message(message)
            }
            Ok(None) => {
                // Waiting for more packets to assemble the message, nothing to send for now.
                None
            }
            Err((cid, error)) => {
                if !self.is_allocated_channel(cid)
                    && error != receive::Error::UnexpectedContinuation
                {
                    Some(CtapHid::error_message(cid, CtapHid::ERR_INVALID_CHANNEL))
                } else {
                    match error {
                        receive::Error::UnexpectedChannel => {
                            Some(CtapHid::error_message(cid, CtapHid::ERR_CHANNEL_BUSY))
                        }
                        receive::Error::UnexpectedInit => {
                            // TODO: Should we send another error code in this case?
                            // Technically, we were expecting a sequence number and got another
                            // byte, although the command/seqnum bit has higher-level semantics
                            // than sequence numbers.
                            Some(CtapHid::error_message(cid, CtapHid::ERR_INVALID_SEQ))
                        }
                        receive::Error::UnexpectedContinuation => {
                            // CTAP specification (version 20190130) section 8.1.5.4
                            // Spurious continuation packets will be ignored.
                            None
                        }
                        receive::Error::UnexpectedSeq => {
                            Some(CtapHid::error_message(cid, CtapHid::ERR_INVALID_SEQ))
                        }
                        receive::Error::UnexpectedLen => {
                            Some(CtapHid::error_message(cid, CtapHid::ERR_INVALID_LEN))
                        }
                        receive::Error::Timeout => {
                            Some(CtapHid::error_message(cid, CtapHid::ERR_MSG_TIMEOUT))
                        }
                    }
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
            return Some(CtapHid::error_message(cid, CtapHid::ERR_INVALID_CHANNEL));
        }

        match message.cmd {
            CtapHidCommand::Msg => Some(message),
            CtapHidCommand::Cbor => Some(message),
            // CTAP 2.1 from 2021-06-15, section 11.2.9.1.3.
            CtapHidCommand::Init => {
                if message.payload.len() != 8 {
                    return Some(CtapHid::error_message(cid, CtapHid::ERR_INVALID_LEN));
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
                Some(CtapHid::error_message(cid, CtapHid::ERR_INVALID_CMD))
            }
        }
    }

    /// Processes a message's commands that affect the protocol outside HID.
    pub fn process_message(
        &mut self,
        env: &mut impl Env,
        message: Message,
        clock_value: ClockValue,
        ctap_state: &mut CtapState,
    ) -> Message {
        // If another command arrives, stop winking to prevent accidential button touches.
        self.wink_permission = TimedPermission::waiting();

        let cid = message.cid;
        match message.cmd {
            // CTAP 2.1 from 2021-06-15, section 11.2.9.1.1.
            CtapHidCommand::Msg => {
                // If we don't have CTAP1 backward compatibilty, this command is invalid.
                #[cfg(not(feature = "with_ctap1"))]
                return CtapHid::error_message(cid, CtapHid::ERR_INVALID_CMD);

                #[cfg(feature = "with_ctap1")]
                match ctap1::Ctap1Command::process_command(
                    env,
                    &message.payload,
                    ctap_state,
                    clock_value,
                ) {
                    Ok(payload) => CtapHid::ctap1_success_message(cid, &payload),
                    Err(ctap1_status_code) => CtapHid::ctap1_error_message(cid, ctap1_status_code),
                }
            }
            // CTAP 2.1 from 2021-06-15, section 11.2.9.1.2.
            CtapHidCommand::Cbor => {
                // Each transaction is atomic, so we process the command directly here and
                // don't handle any other packet in the meantime.
                // TODO: Send "Processing" type keep-alive packets in the meantime.
                let response = ctap_state.process_command(env, &message.payload, cid, clock_value);
                Message {
                    cid,
                    cmd: CtapHidCommand::Cbor,
                    payload: response,
                }
            }
            // CTAP 2.1 from 2021-06-15, section 11.2.9.2.1.
            CtapHidCommand::Wink => {
                if message.payload.is_empty() {
                    self.wink_permission =
                        TimedPermission::granted(clock_value, CtapHid::WINK_TIMEOUT_DURATION);
                    // The response is empty like the request.
                    message
                } else {
                    CtapHid::error_message(cid, CtapHid::ERR_INVALID_LEN)
                }
            }
            // All other commands have already been processed, keep them as is.
            _ => message,
        }
    }

    /// Processes an incoming USB HID packet, and returns an iterator for all outgoing packets.
    pub fn process_hid_packet(
        &mut self,
        env: &mut impl Env,
        packet: &HidPacket,
        clock_value: ClockValue,
        ctap_state: &mut CtapState,
    ) -> HidPacketIterator {
        if let Some(message) = self.parse_packet(packet, clock_value) {
            let processed_message = self.process_message(env, message, clock_value, ctap_state);
            #[cfg(feature = "debug_ctap")]
            writeln!(
                &mut Console::new(),
                "Sending message: {:02x?}",
                processed_message
            )
            .unwrap();
            CtapHid::split_message(processed_message)
        } else {
            HidPacketIterator::none()
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

    fn error_message(cid: ChannelID, error_code: u8) -> Message {
        Message {
            cid,
            cmd: CtapHidCommand::Error,
            payload: vec![error_code],
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
    fn split_message(message: Message) -> HidPacketIterator {
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
        // This unwrap is safe because the payload length is 1 <= 7609 bytes.
        CtapHid::split_message(Message {
            cid,
            cmd: CtapHidCommand::Keepalive,
            payload: vec![status as u8],
        })
    }

    pub fn should_wink(&self, now: ClockValue) -> bool {
        self.wink_permission.is_granted(now)
    }

    #[cfg(feature = "with_ctap1")]
    fn ctap1_error_message(cid: ChannelID, error_code: ctap1::Ctap1StatusCode) -> Message {
        let code: u16 = error_code.into();
        Message {
            cid,
            cmd: CtapHidCommand::Msg,
            payload: code.to_be_bytes().to_vec(),
        }
    }

    #[cfg(feature = "with_ctap1")]
    fn ctap1_success_message(cid: ChannelID, payload: &[u8]) -> Message {
        let mut response = payload.to_vec();
        let code: u16 = ctap1::Ctap1StatusCode::SW_SUCCESS.into();
        response.extend_from_slice(&code.to_be_bytes());
        Message {
            cid,
            cmd: CtapHidCommand::Msg,
            payload: response,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;

    const CLOCK_FREQUENCY_HZ: usize = 32768;
    // Except for tests for timeouts (done in ctap1.rs), transactions are time independant.
    const DUMMY_CLOCK_VALUE: ClockValue = ClockValue::new(0, CLOCK_FREQUENCY_HZ);
    const DUMMY_TIMESTAMP: Timestamp<isize> = Timestamp::from_ms(0);

    fn process_messages(
        env: &mut impl Env,
        ctap_hid: &mut CtapHid,
        ctap_state: &mut CtapState,
        request: Vec<Message>,
    ) -> Option<Vec<Message>> {
        let mut result = Vec::new();
        let mut assembler_reply = MessageAssembler::new();
        for msg_request in request {
            for pkt_request in HidPacketIterator::new(msg_request).unwrap() {
                for pkt_reply in
                    ctap_hid.process_hid_packet(env, &pkt_request, DUMMY_CLOCK_VALUE, ctap_state)
                {
                    match assembler_reply.parse_packet(&pkt_reply, DUMMY_TIMESTAMP) {
                        Ok(Some(message)) => result.push(message),
                        Ok(None) => (),
                        Err(_) => return None,
                    }
                }
            }
        }
        Some(result)
    }

    fn cid_from_init(
        env: &mut impl Env,
        ctap_hid: &mut CtapHid,
        ctap_state: &mut CtapState,
    ) -> ChannelID {
        let nonce = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let reply = process_messages(
            env,
            ctap_hid,
            ctap_state,
            vec![Message {
                cid: CtapHid::CHANNEL_BROADCAST,
                cmd: CtapHidCommand::Init,
                payload: nonce.clone(),
            }],
        );

        let mut cid_in_payload: ChannelID = Default::default();
        if let Some(messages) = reply {
            assert_eq!(messages.len(), 1);
            assert!(messages[0].payload.len() >= 12);
            assert_eq!(nonce, &messages[0].payload[..8]);
            cid_in_payload.copy_from_slice(&messages[0].payload[8..12]);
        } else {
            panic!("The init process was not successful to generate a valid channel ID.")
        }
        cid_in_payload
    }

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
                match assembler.parse_packet(&packet, DUMMY_TIMESTAMP) {
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
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        let mut ctap_hid = CtapHid::new();

        let mut packet = [0x00; 64];
        packet[0..7].copy_from_slice(&[0xC1, 0xC1, 0xC1, 0xC1, 0x00, 0x51, 0x51]);
        let mut assembler_reply = MessageAssembler::new();
        for pkt_reply in
            ctap_hid.process_hid_packet(&mut env, &packet, DUMMY_CLOCK_VALUE, &mut ctap_state)
        {
            // Continuation packets are silently ignored.
            assert_eq!(
                assembler_reply
                    .parse_packet(&pkt_reply, DUMMY_TIMESTAMP)
                    .unwrap(),
                None
            );
        }
    }

    #[test]
    fn test_command_init() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        let mut ctap_hid = CtapHid::new();

        let reply = process_messages(
            &mut env,
            &mut ctap_hid,
            &mut ctap_state,
            vec![Message {
                cid: CtapHid::CHANNEL_BROADCAST,
                cmd: CtapHidCommand::Init,
                payload: vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
            }],
        );

        assert_eq!(
            reply,
            Some(vec![Message {
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
            }])
        );
    }

    #[test]
    fn test_command_init_for_sync() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        let mut ctap_hid = CtapHid::new();
        let cid = cid_from_init(&mut env, &mut ctap_hid, &mut ctap_state);

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
        let mut result = Vec::new();
        let mut assembler_reply = MessageAssembler::new();
        for pkt_request in &[packet1, packet2] {
            for pkt_reply in ctap_hid.process_hid_packet(
                &mut env,
                pkt_request,
                DUMMY_CLOCK_VALUE,
                &mut ctap_state,
            ) {
                if let Some(message) = assembler_reply
                    .parse_packet(&pkt_reply, DUMMY_TIMESTAMP)
                    .unwrap()
                {
                    result.push(message);
                }
            }
        }
        assert_eq!(
            result,
            vec![Message {
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
            }]
        );
    }

    #[test]
    fn test_command_ping() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        let mut ctap_hid = CtapHid::new();
        let cid = cid_from_init(&mut env, &mut ctap_hid, &mut ctap_state);

        let reply = process_messages(
            &mut env,
            &mut ctap_hid,
            &mut ctap_state,
            vec![Message {
                cid,
                cmd: CtapHidCommand::Ping,
                payload: vec![0x99, 0x99],
            }],
        );

        assert_eq!(
            reply,
            Some(vec![Message {
                cid,
                cmd: CtapHidCommand::Ping,
                payload: vec![0x99, 0x99]
            }])
        );
    }
}
