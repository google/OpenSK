// Copyright 2019 Google LLC
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
use alloc::vec;
use alloc::vec::Vec;
use arrayref::{array_ref, array_refs};
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
use crypto::rng256::Rng256;
#[cfg(feature = "debug_ctap")]
use libtock_drivers::console::Console;
use libtock_drivers::timer::{ClockValue, Duration, Timestamp};

// CTAP specification (version 20190130) section 8.1
// TODO: Channel allocation, section 8.1.3?
// TODO: Transaction timeout, section 8.1.5.2

pub type HidPacket = [u8; 64];
pub type ChannelID = [u8; 4];

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

// An assembled CTAPHID command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    // Channel ID.
    pub cid: ChannelID,
    // Command.
    pub cmd: u8,
    // Bytes of the message.
    pub payload: Vec<u8>,
}

pub struct CtapHid {
    assembler: MessageAssembler,
    // The specification (version 20190130) only requires unique CIDs ; the allocation algorithm is
    // vendor specific.
    // We allocate them incrementally, that is all `cid` such that 1 <= cid <= allocated_cids are
    // allocated.
    // In packets, the ID encoding is Big Endian to match what is used throughout CTAP (with the
    // u32::to/from_be_bytes methods).
    allocated_cids: usize,
    pub wink_permission: TimedPermission,
}

#[allow(dead_code)]
pub enum KeepaliveStatus {
    Processing,
    UpNeeded,
}

#[allow(dead_code)]
// TODO(kaczmarczyck) disable the warning in the end
impl CtapHid {
    // CTAP specification (version 20190130) section 8.1.3
    const CHANNEL_RESERVED: ChannelID = [0, 0, 0, 0];
    const CHANNEL_BROADCAST: ChannelID = [0xFF, 0xFF, 0xFF, 0xFF];
    const TYPE_INIT_BIT: u8 = 0x80;
    const PACKET_TYPE_MASK: u8 = 0x80;

    // CTAP specification (version 20190130) section 8.1.9
    const COMMAND_PING: u8 = 0x01;
    const COMMAND_MSG: u8 = 0x03;
    const COMMAND_INIT: u8 = 0x06;
    const COMMAND_CBOR: u8 = 0x10;
    pub const COMMAND_CANCEL: u8 = 0x11;
    const COMMAND_KEEPALIVE: u8 = 0x3B;
    const COMMAND_ERROR: u8 = 0x3F;
    // TODO: optional lock command
    const COMMAND_LOCK: u8 = 0x04;
    const COMMAND_WINK: u8 = 0x08;
    const COMMAND_VENDOR_FIRST: u8 = 0x40;
    const COMMAND_VENDOR_LAST: u8 = 0x7F;

    // CTAP specification (version 20190130) section 8.1.9.1.6
    const ERR_INVALID_CMD: u8 = 0x01;
    const ERR_INVALID_PAR: u8 = 0x02;
    const ERR_INVALID_LEN: u8 = 0x03;
    const ERR_INVALID_SEQ: u8 = 0x04;
    const ERR_MSG_TIMEOUT: u8 = 0x05;
    const ERR_CHANNEL_BUSY: u8 = 0x06;
    const ERR_LOCK_REQUIRED: u8 = 0x0A;
    const ERR_INVALID_CHANNEL: u8 = 0x0B;
    const ERR_OTHER: u8 = 0x7F;

    // CTAP specification (version 20190130) section 8.1.9.1.3
    const PROTOCOL_VERSION: u8 = 2;

    // The device version number is vendor-defined.
    const DEVICE_VERSION_MAJOR: u8 = 1;
    const DEVICE_VERSION_MINOR: u8 = 0;
    const DEVICE_VERSION_BUILD: u8 = 0;

    const CAPABILITY_WINK: u8 = 0x01;
    const CAPABILITY_CBOR: u8 = 0x04;
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

    pub fn new() -> CtapHid {
        CtapHid {
            assembler: MessageAssembler::new(),
            allocated_cids: 0,
            wink_permission: TimedPermission::waiting(),
        }
    }

    // Process an incoming USB HID packet, and optionally returns a list of outgoing packets to
    // send as a reply.
    pub fn process_hid_packet<R, CheckUserPresence>(
        &mut self,
        packet: &HidPacket,
        clock_value: ClockValue,
        ctap_state: &mut CtapState<R, CheckUserPresence>,
    ) -> HidPacketIterator
    where
        R: Rng256,
        CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>,
    {
        // TODO: Send COMMAND_KEEPALIVE every 100ms?
        match self
            .assembler
            .parse_packet(packet, Timestamp::<isize>::from_clock_value(clock_value))
        {
            Ok(Some(message)) => {
                #[cfg(feature = "debug_ctap")]
                writeln!(&mut Console::new(), "Received message: {:02x?}", message).unwrap();

                let cid = message.cid;
                if !self.has_valid_channel(&message) {
                    #[cfg(feature = "debug_ctap")]
                    writeln!(&mut Console::new(), "Invalid channel: {:02x?}", cid).unwrap();
                    return CtapHid::error_message(cid, CtapHid::ERR_INVALID_CHANNEL);
                }
                // If another command arrives, stop winking to prevent accidential button touches.
                self.wink_permission = TimedPermission::waiting();

                match message.cmd {
                    // CTAP specification (version 20190130) section 8.1.9.1.1
                    CtapHid::COMMAND_MSG => {
                        // If we don't have CTAP1 backward compatibilty, this command in invalid.
                        #[cfg(not(feature = "with_ctap1"))]
                        return CtapHid::error_message(cid, CtapHid::ERR_INVALID_CMD);

                        #[cfg(feature = "with_ctap1")]
                        match ctap1::Ctap1Command::process_command(
                            &message.payload,
                            ctap_state,
                            clock_value,
                        ) {
                            Ok(payload) => CtapHid::ctap1_success_message(cid, &payload),
                            Err(ctap1_status_code) => {
                                CtapHid::ctap1_error_message(cid, ctap1_status_code)
                            }
                        }
                    }
                    // CTAP specification (version 20190130) section 8.1.9.1.2
                    CtapHid::COMMAND_CBOR => {
                        // CTAP specification (version 20190130) section 8.1.5.1
                        // Each transaction is atomic, so we process the command directly here and
                        // don't handle any other packet in the meantime.
                        // TODO: Send keep-alive packets in the meantime.
                        let response =
                            ctap_state.process_command(&message.payload, cid, clock_value);
                        if let Some(iterator) = CtapHid::split_message(Message {
                            cid,
                            cmd: CtapHid::COMMAND_CBOR,
                            payload: response,
                        }) {
                            iterator
                        } else {
                            // Handle the case of a payload > 7609 bytes.
                            // Although this shouldn't happen if the FIDO2 commands are implemented
                            // correctly, we reply with a vendor specific code instead of silently
                            // ignoring the error.
                            //
                            // The error payload that we send instead is 1 <= 7609 bytes, so it is
                            // safe to unwrap() the result.
                            CtapHid::split_message(Message {
                                cid,
                                cmd: CtapHid::COMMAND_CBOR,
                                payload: vec![
                                    Ctap2StatusCode::CTAP2_ERR_VENDOR_RESPONSE_TOO_LONG as u8,
                                ],
                            })
                            .unwrap()
                        }
                    }
                    // CTAP specification (version 20190130) section 8.1.9.1.3
                    CtapHid::COMMAND_INIT => {
                        if message.payload.len() != 8 {
                            return CtapHid::error_message(cid, CtapHid::ERR_INVALID_LEN);
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

                        // This unwrap is safe because the payload length is 17 <= 7609 bytes.
                        CtapHid::split_message(Message {
                            cid,
                            cmd: CtapHid::COMMAND_INIT,
                            payload,
                        })
                        .unwrap()
                    }
                    // CTAP specification (version 20190130) section 8.1.9.1.4
                    CtapHid::COMMAND_PING => {
                        // Pong the same message.
                        // This unwrap is safe because if we could parse the incoming message, it's
                        // payload length must be <= 7609 bytes.
                        CtapHid::split_message(message).unwrap()
                    }
                    // CTAP specification (version 20190130) section 8.1.9.1.5
                    CtapHid::COMMAND_CANCEL => {
                        // Authenticators MUST NOT reply to this message.
                        // CANCEL is handled during user presence checks in main.
                        HidPacketIterator::none()
                    }
                    // Optional commands
                    // CTAP specification (version 20190130) section 8.1.9.2.1
                    CtapHid::COMMAND_WINK => {
                        if !message.payload.is_empty() {
                            return CtapHid::error_message(cid, CtapHid::ERR_INVALID_LEN);
                        }
                        self.wink_permission =
                            TimedPermission::granted(clock_value, CtapHid::WINK_TIMEOUT_DURATION);
                        CtapHid::split_message(Message {
                            cid,
                            cmd: CtapHid::COMMAND_WINK,
                            payload: vec![],
                        })
                        .unwrap()
                    }
                    // CTAP specification (version 20190130) section 8.1.9.2.2
                    // TODO: implement LOCK
                    _ => {
                        // Unknown or unsupported command.
                        CtapHid::error_message(cid, CtapHid::ERR_INVALID_CMD)
                    }
                }
            }
            Ok(None) => {
                // Waiting for more packets to assemble the message, nothing to send for now.
                HidPacketIterator::none()
            }
            Err((cid, error)) => {
                if !self.is_allocated_channel(cid)
                    && error != receive::Error::UnexpectedContinuation
                {
                    CtapHid::error_message(cid, CtapHid::ERR_INVALID_CHANNEL)
                } else {
                    match error {
                        receive::Error::UnexpectedChannel => {
                            CtapHid::error_message(cid, CtapHid::ERR_CHANNEL_BUSY)
                        }
                        receive::Error::UnexpectedInit => {
                            // TODO: Should we send another error code in this case?
                            // Technically, we were expecting a sequence number and got another
                            // byte, although the command/seqnum bit has higher-level semantics
                            // than sequence numbers.
                            CtapHid::error_message(cid, CtapHid::ERR_INVALID_SEQ)
                        }
                        receive::Error::UnexpectedContinuation => {
                            // CTAP specification (version 20190130) section 8.1.5.4
                            // Spurious continuation packets will be ignored.
                            HidPacketIterator::none()
                        }
                        receive::Error::UnexpectedSeq => {
                            CtapHid::error_message(cid, CtapHid::ERR_INVALID_SEQ)
                        }
                        receive::Error::Timeout => {
                            CtapHid::error_message(cid, CtapHid::ERR_MSG_TIMEOUT)
                        }
                    }
                }
            }
        }
    }

    fn has_valid_channel(&self, message: &Message) -> bool {
        match message.cid {
            // Only INIT commands use the broadcast channel.
            CtapHid::CHANNEL_BROADCAST => message.cmd == CtapHid::COMMAND_INIT,
            // Check that the channel is allocated.
            _ => self.is_allocated_channel(message.cid),
        }
    }

    fn is_allocated_channel(&self, cid: ChannelID) -> bool {
        cid != CtapHid::CHANNEL_RESERVED && u32::from_be_bytes(cid) as usize <= self.allocated_cids
    }

    fn error_message(cid: ChannelID, error_code: u8) -> HidPacketIterator {
        // This unwrap is safe because the payload length is 1 <= 7609 bytes.
        CtapHid::split_message(Message {
            cid,
            cmd: CtapHid::COMMAND_ERROR,
            payload: vec![error_code],
        })
        .unwrap()
    }

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

    fn split_message(message: Message) -> Option<HidPacketIterator> {
        #[cfg(feature = "debug_ctap")]
        writeln!(&mut Console::new(), "Sending message: {:02x?}", message).unwrap();
        HidPacketIterator::new(message)
    }

    pub fn keepalive(cid: ChannelID, status: KeepaliveStatus) -> HidPacketIterator {
        let status_code = match status {
            KeepaliveStatus::Processing => 1,
            KeepaliveStatus::UpNeeded => 2,
        };
        // This unwrap is safe because the payload length is 1 <= 7609 bytes.
        CtapHid::split_message(Message {
            cid,
            cmd: CtapHid::COMMAND_KEEPALIVE,
            payload: vec![status_code],
        })
        .unwrap()
    }

    #[cfg(feature = "with_ctap1")]
    fn ctap1_error_message(
        cid: ChannelID,
        error_code: ctap1::Ctap1StatusCode,
    ) -> HidPacketIterator {
        // This unwrap is safe because the payload length is 2 <= 7609 bytes
        let code: u16 = error_code.into();
        CtapHid::split_message(Message {
            cid,
            cmd: CtapHid::COMMAND_MSG,
            payload: code.to_be_bytes().to_vec(),
        })
        .unwrap()
    }

    #[cfg(feature = "with_ctap1")]
    fn ctap1_success_message(cid: ChannelID, payload: &[u8]) -> HidPacketIterator {
        let mut response = payload.to_vec();
        let code: u16 = ctap1::Ctap1StatusCode::SW_SUCCESS.into();
        response.extend_from_slice(&code.to_be_bytes());
        CtapHid::split_message(Message {
            cid,
            cmd: CtapHid::COMMAND_MSG,
            payload: response,
        })
        .unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto::rng256::ThreadRng256;

    const CLOCK_FREQUENCY_HZ: usize = 32768;
    // Except for tests for timeouts (done in ctap1.rs), transactions are time independant.
    const DUMMY_CLOCK_VALUE: ClockValue = ClockValue::new(0, CLOCK_FREQUENCY_HZ);
    const DUMMY_TIMESTAMP: Timestamp<isize> = Timestamp::from_ms(0);

    fn process_messages<CheckUserPresence>(
        ctap_hid: &mut CtapHid,
        ctap_state: &mut CtapState<ThreadRng256, CheckUserPresence>,
        request: Vec<Message>,
    ) -> Option<Vec<Message>>
    where
        CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>,
    {
        let mut result = Vec::new();
        let mut assembler_reply = MessageAssembler::new();
        for msg_request in request {
            for pkt_request in HidPacketIterator::new(msg_request).unwrap() {
                for pkt_reply in
                    ctap_hid.process_hid_packet(&pkt_request, DUMMY_CLOCK_VALUE, ctap_state)
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

    fn cid_from_init<CheckUserPresence>(
        ctap_hid: &mut CtapHid,
        ctap_state: &mut CtapState<ThreadRng256, CheckUserPresence>,
    ) -> ChannelID
    where
        CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>,
    {
        let nonce = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let reply = process_messages(
            ctap_hid,
            ctap_state,
            vec![Message {
                cid: CtapHid::CHANNEL_BROADCAST,
                cmd: CtapHid::COMMAND_INIT,
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
                cmd: 0x00,
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
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        let mut ctap_hid = CtapHid::new();

        let mut packet = [0x00; 64];
        packet[0..7].copy_from_slice(&[0xC1, 0xC1, 0xC1, 0xC1, 0x00, 0x51, 0x51]);
        let mut assembler_reply = MessageAssembler::new();
        for pkt_reply in ctap_hid.process_hid_packet(&packet, DUMMY_CLOCK_VALUE, &mut ctap_state) {
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
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        let mut ctap_hid = CtapHid::new();

        let reply = process_messages(
            &mut ctap_hid,
            &mut ctap_state,
            vec![Message {
                cid: CtapHid::CHANNEL_BROADCAST,
                cmd: CtapHid::COMMAND_INIT,
                payload: vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
            }],
        );

        assert_eq!(
            reply,
            Some(vec![Message {
                cid: CtapHid::CHANNEL_BROADCAST,
                cmd: CtapHid::COMMAND_INIT,
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
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        let mut ctap_hid = CtapHid::new();
        let cid = cid_from_init(&mut ctap_hid, &mut ctap_state);

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
            for pkt_reply in
                ctap_hid.process_hid_packet(&pkt_request, DUMMY_CLOCK_VALUE, &mut ctap_state)
            {
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
                cmd: CtapHid::COMMAND_INIT,
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
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        let mut ctap_hid = CtapHid::new();
        let cid = cid_from_init(&mut ctap_hid, &mut ctap_state);

        let reply = process_messages(
            &mut ctap_hid,
            &mut ctap_state,
            vec![Message {
                cid,
                cmd: CtapHid::COMMAND_PING,
                payload: vec![0x99, 0x99],
            }],
        );

        assert_eq!(
            reply,
            Some(vec![Message {
                cid,
                cmd: CtapHid::COMMAND_PING,
                payload: vec![0x99, 0x99]
            }])
        );
    }
}
