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

use super::{
    ChannelID, CtapHid, CtapHidCommand, CtapHidError, HidPacket, Message, ProcessedPacket,
};
use crate::api::customization::Customization;
use crate::clock::CtapInstant;
use crate::env::Env;
use alloc::vec::Vec;
use core::mem::swap;

/// A structure to assemble CTAPHID commands from a series of incoming USB HID packets.
pub struct MessageAssembler {
    // Whether this is waiting to receive an initialization packet.
    idle: bool,
    // Current channel ID.
    cid: ChannelID,
    // Timestamp of the last packet received on the current channel.
    last_timestamp: CtapInstant,
    // Current command.
    cmd: u8,
    // Sequence number expected for the next packet.
    seq: u8,
    // Number of bytes left to fill the current message.
    remaining_payload_len: usize,
    // Buffer for the current payload.
    payload: Vec<u8>,
}

impl MessageAssembler {
    pub fn new() -> MessageAssembler {
        MessageAssembler {
            idle: true,
            cid: [0, 0, 0, 0],
            last_timestamp: CtapInstant::new(0),
            cmd: 0,
            seq: 0,
            remaining_payload_len: 0,
            payload: Vec::new(),
        }
    }

    // Resets the message assembler to the idle state.
    // The caller can reset the assembler for example due to a timeout.
    fn reset(&mut self) {
        self.idle = true;
        self.cid = [0, 0, 0, 0];
        self.last_timestamp = CtapInstant::new(0);
        self.cmd = 0;
        self.seq = 0;
        self.remaining_payload_len = 0;
        self.payload.clear();
    }

    // Returns:
    // - An Ok() result if the packet was parsed correctly. This contains either Some(Vec<u8>) if a
    // full message was assembled after this packet, or None if more packets are needed to fill the
    // message.
    // - An Err() result if there was a parsing error.
    // TODO: Implement timeouts. For example, have the caller pass us a timestamp of when this
    // packet was received.
    pub fn parse_packet(
        &mut self,
        env: &mut impl Env,
        packet: &HidPacket,
        timestamp: CtapInstant,
    ) -> Result<Option<Message>, (ChannelID, CtapHidError)> {
        // TODO: Support non-full-speed devices (i.e. packet len != 64)? This isn't recommended by
        // section 8.8.1
        let (cid, processed_packet) = CtapHid::process_single_packet(packet);

        if !self.idle && timestamp >= self.last_timestamp + CtapHid::TIMEOUT_DURATION {
            // The current channel timed out.
            // Save the channel ID and reset the state.
            let current_cid = self.cid;
            self.reset();

            // If the packet is from the timed-out channel, send back a timeout error.
            // Otherwise, proceed with processing the packet.
            if cid == current_cid {
                return Err((cid, CtapHidError::MsgTimeout));
            }
        }

        if self.idle {
            // Expecting an initialization packet.
            match processed_packet {
                ProcessedPacket::InitPacket { cmd, len, data } => {
                    self.parse_init_packet(env, cid, cmd, len, data, timestamp)
                }
                ProcessedPacket::ContinuationPacket { .. } => {
                    // CTAP specification (version 20190130) section 8.1.5.4
                    // Spurious continuation packets will be ignored.
                    Err((cid, CtapHidError::UnexpectedContinuation))
                }
            }
        } else {
            // Expecting a continuation packet from the current channel.

            // CTAP specification (version 20190130) section 8.1.5.1
            // Reject packets from other channels.
            if cid != self.cid {
                return Err((cid, CtapHidError::ChannelBusy));
            }

            match processed_packet {
                // Unexpected initialization packet.
                ProcessedPacket::InitPacket { cmd, len, data } => {
                    self.reset();
                    if cmd == CtapHidCommand::Init as u8 {
                        self.parse_init_packet(env, cid, cmd, len, data, timestamp)
                    } else {
                        Err((cid, CtapHidError::InvalidSeq))
                    }
                }
                ProcessedPacket::ContinuationPacket { seq, data } => {
                    if seq != self.seq {
                        // Reject packets with the wrong sequence number.
                        self.reset();
                        Err((cid, CtapHidError::InvalidSeq))
                    } else {
                        // Update the last timestamp.
                        self.last_timestamp = timestamp;
                        // Increment the sequence number for the next packet.
                        self.seq += 1;
                        Ok(self.append_payload(data))
                    }
                }
            }
        }
    }

    fn parse_init_packet(
        &mut self,
        env: &mut impl Env,
        cid: ChannelID,
        cmd: u8,
        len: usize,
        data: &[u8],
        timestamp: CtapInstant,
    ) -> Result<Option<Message>, (ChannelID, CtapHidError)> {
        // Reject invalid lengths early to reduce the risk of running out of memory.
        // TODO: also reject invalid commands early?
        if len > env.customization().max_msg_size() {
            return Err((cid, CtapHidError::InvalidLen));
        }
        self.cid = cid;
        self.last_timestamp = timestamp;
        self.cmd = cmd;
        self.seq = 0;
        self.remaining_payload_len = len;
        Ok(self.append_payload(data))
    }

    fn append_payload(&mut self, data: &[u8]) -> Option<Message> {
        if data.len() < self.remaining_payload_len {
            self.payload.extend_from_slice(data);
            self.idle = false;
            self.remaining_payload_len -= data.len();
            None
        } else {
            self.payload
                .extend_from_slice(&data[..self.remaining_payload_len]);
            self.idle = true;
            let mut payload = Vec::new();
            swap(&mut self.payload, &mut payload);
            Some(Message {
                cid: self.cid,
                cmd: CtapHidCommand::from(self.cmd),
                payload,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use crate::ctap::hid::CtapHid;
    use crate::env::test::TestEnv;
    use embedded_time::duration::Milliseconds;

    use super::*;

    fn byte_extend(bytes: &[u8], padding: u8) -> HidPacket {
        let len = bytes.len();
        assert!(len <= 64);
        let mut result = [0; 64];
        result[..len].copy_from_slice(bytes);
        for byte in result[len..].iter_mut() {
            *byte = padding;
        }
        result
    }

    fn zero_extend(bytes: &[u8]) -> HidPacket {
        byte_extend(bytes, 0)
    }

    #[test]
    fn test_empty_payload() {
        let mut env = TestEnv::new();
        let mut assembler = MessageAssembler::new();
        // Except for tests that exercise timeouts, all packets are synchronized at the same dummy
        // timestamp.
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x90]),
                CtapInstant::new(0)
            ),
            Ok(Some(Message {
                cid: [0x12, 0x34, 0x56, 0x78],
                cmd: CtapHidCommand::Cbor,
                payload: vec![]
            }))
        );
    }

    #[test]
    fn test_one_packet() {
        let mut env = TestEnv::new();
        let mut assembler = MessageAssembler::new();
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x00, 0x10]),
                CtapInstant::new(0)
            ),
            Ok(Some(Message {
                cid: [0x12, 0x34, 0x56, 0x78],
                cmd: CtapHidCommand::Cbor,
                payload: vec![0x00; 0x10]
            }))
        );
    }

    #[test]
    fn test_nonzero_padding() {
        let mut env = TestEnv::new();
        // CTAP specification (version 20190130) section 8.1.4
        // It is written that "Unused bytes SHOULD be set to zero", so we test that non-zero
        // padding is accepted as well.
        let mut assembler = MessageAssembler::new();
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &byte_extend(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x00, 0x10], 0xFF),
                CtapInstant::new(0)
            ),
            Ok(Some(Message {
                cid: [0x12, 0x34, 0x56, 0x78],
                cmd: CtapHidCommand::Cbor,
                payload: vec![0xFF; 0x10]
            }))
        );
    }

    #[test]
    fn test_two_packets() {
        let mut env = TestEnv::new();
        let mut assembler = MessageAssembler::new();
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x00, 0x40]),
                CtapInstant::new(0)
            ),
            Ok(None)
        );
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x00]),
                CtapInstant::new(0)
            ),
            Ok(Some(Message {
                cid: [0x12, 0x34, 0x56, 0x78],
                cmd: CtapHidCommand::Ping,
                payload: vec![0x00; 0x40]
            }))
        );
    }

    #[test]
    fn test_three_packets() {
        let mut env = TestEnv::new();
        let mut assembler = MessageAssembler::new();
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x00, 0x80]),
                CtapInstant::new(0)
            ),
            Ok(None)
        );
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x00]),
                CtapInstant::new(0)
            ),
            Ok(None)
        );
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x01]),
                CtapInstant::new(0)
            ),
            Ok(Some(Message {
                cid: [0x12, 0x34, 0x56, 0x78],
                cmd: CtapHidCommand::Ping,
                payload: vec![0x00; 0x80]
            }))
        );
    }

    #[test]
    fn test_max_packets() {
        let mut env = TestEnv::new();
        let mut assembler = MessageAssembler::new();
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x1D, 0xB9]),
                CtapInstant::new(0)
            ),
            Ok(None)
        );
        for seq in 0..0x7F {
            assert_eq!(
                assembler.parse_packet(
                    &mut env,
                    &zero_extend(&[0x12, 0x34, 0x56, 0x78, seq]),
                    CtapInstant::new(0)
                ),
                Ok(None)
            );
        }
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x7F]),
                CtapInstant::new(0)
            ),
            Ok(Some(Message {
                cid: [0x12, 0x34, 0x56, 0x78],
                cmd: CtapHidCommand::Ping,
                payload: vec![0x00; 0x1DB9]
            }))
        );
    }

    #[test]
    fn test_multiple_messages() {
        let mut env = TestEnv::new();
        // Check that after yielding a message, the assembler is ready to process new messages.
        let mut assembler = MessageAssembler::new();
        for i in 0..10 {
            // Introduce some variability in the messages.
            let cmd = CtapHidCommand::from(i + 1);
            let byte = 3 * i;

            assert_eq!(
                assembler.parse_packet(
                    &mut env,
                    &byte_extend(
                        &[0x12, 0x34, 0x56, 0x78, 0x80 | cmd as u8, 0x00, 0x80],
                        byte
                    ),
                    CtapInstant::new(0)
                ),
                Ok(None)
            );
            assert_eq!(
                assembler.parse_packet(
                    &mut env,
                    &byte_extend(&[0x12, 0x34, 0x56, 0x78, 0x00], byte),
                    CtapInstant::new(0)
                ),
                Ok(None)
            );
            assert_eq!(
                assembler.parse_packet(
                    &mut env,
                    &byte_extend(&[0x12, 0x34, 0x56, 0x78, 0x01], byte),
                    CtapInstant::new(0)
                ),
                Ok(Some(Message {
                    cid: [0x12, 0x34, 0x56, 0x78],
                    cmd,
                    payload: vec![byte; 0x80]
                }))
            );
        }
    }

    #[test]
    fn test_channel_switch() {
        let mut env = TestEnv::new();
        // Check that the assembler can process messages from multiple channels, sequentially.
        let mut assembler = MessageAssembler::new();
        for i in 0..10 {
            // Introduce some variability in the messages.
            let cid = 0x78 + i;
            let cmd = CtapHidCommand::from(i + 1);
            let byte = 3 * i;

            assert_eq!(
                assembler.parse_packet(
                    &mut env,
                    &byte_extend(&[0x12, 0x34, 0x56, cid, 0x80 | cmd as u8, 0x00, 0x80], byte),
                    CtapInstant::new(0)
                ),
                Ok(None)
            );
            assert_eq!(
                assembler.parse_packet(
                    &mut env,
                    &byte_extend(&[0x12, 0x34, 0x56, cid, 0x00], byte),
                    CtapInstant::new(0)
                ),
                Ok(None)
            );
            assert_eq!(
                assembler.parse_packet(
                    &mut env,
                    &byte_extend(&[0x12, 0x34, 0x56, cid, 0x01], byte),
                    CtapInstant::new(0)
                ),
                Ok(Some(Message {
                    cid: [0x12, 0x34, 0x56, cid],
                    cmd,
                    payload: vec![byte; 0x80]
                }))
            );
        }
    }

    #[test]
    fn test_unexpected_channel() {
        let mut env = TestEnv::new();
        let mut assembler = MessageAssembler::new();
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x00, 0x40]),
                CtapInstant::new(0)
            ),
            Ok(None)
        );

        // Check that many sorts of packets on another channel are ignored.
        for i in 0..=0xFF {
            let cmd = CtapHidCommand::from(i);
            for byte in 0..=0xFF {
                assert_eq!(
                    assembler.parse_packet(
                        &mut env,
                        &byte_extend(&[0x12, 0x34, 0x56, 0x9A, cmd as u8, 0x00], byte),
                        CtapInstant::new(0)
                    ),
                    Err(([0x12, 0x34, 0x56, 0x9A], CtapHidError::ChannelBusy))
                );
            }
        }

        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x00]),
                CtapInstant::new(0)
            ),
            Ok(Some(Message {
                cid: [0x12, 0x34, 0x56, 0x78],
                cmd: CtapHidCommand::Ping,
                payload: vec![0x00; 0x40]
            }))
        );
    }

    #[test]
    fn test_spurious_continuation_packets() {
        let mut env = TestEnv::new();
        // CTAP specification (version 20190130) section 8.1.5.4
        // Spurious continuation packets appearing without a prior initialization packet will be
        // ignored.
        let mut assembler = MessageAssembler::new();
        for i in 0..0x80 {
            // Some legit packet.
            let byte = 2 * i;
            assert_eq!(
                assembler.parse_packet(
                    &mut env,
                    &byte_extend(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x00, 0x10], byte),
                    CtapInstant::new(0)
                ),
                Ok(Some(Message {
                    cid: [0x12, 0x34, 0x56, 0x78],
                    cmd: CtapHidCommand::Ping,
                    payload: vec![byte; 0x10]
                }))
            );

            // Spurious continuation packet.
            let seq = i;
            assert_eq!(
                assembler.parse_packet(
                    &mut env,
                    &zero_extend(&[0x12, 0x34, 0x56, 0x78, seq]),
                    CtapInstant::new(0)
                ),
                Err((
                    [0x12, 0x34, 0x56, 0x78],
                    CtapHidError::UnexpectedContinuation
                ))
            );
        }
    }

    #[test]
    fn test_unexpected_init() {
        let mut env = TestEnv::new();
        let mut assembler = MessageAssembler::new();
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x00, 0x40]),
                CtapInstant::new(0)
            ),
            Ok(None)
        );
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x80]),
                CtapInstant::new(0)
            ),
            Err(([0x12, 0x34, 0x56, 0x78], CtapHidError::InvalidSeq))
        );
    }

    #[test]
    fn test_unexpected_seq() {
        let mut env = TestEnv::new();
        let mut assembler = MessageAssembler::new();
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x00, 0x40]),
                CtapInstant::new(0)
            ),
            Ok(None)
        );
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x01]),
                CtapInstant::new(0)
            ),
            Err(([0x12, 0x34, 0x56, 0x78], CtapHidError::InvalidSeq))
        );
    }

    #[test]
    fn test_timed_out_packet() {
        let mut env = TestEnv::new();
        let mut assembler = MessageAssembler::new();
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x00, 0x40]),
                CtapInstant::new(0)
            ),
            Ok(None)
        );
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x00]),
                CtapInstant::new(0) + CtapHid::TIMEOUT_DURATION
            ),
            Err(([0x12, 0x34, 0x56, 0x78], CtapHidError::MsgTimeout))
        );
    }

    #[test]
    fn test_just_in_time_packets() {
        let mut env = TestEnv::new();
        let mut timestamp: CtapInstant = CtapInstant::new(0);
        // Delay between each packet is just below the threshold.
        let delay = CtapHid::TIMEOUT_DURATION - Milliseconds(1_u32);

        let mut assembler = MessageAssembler::new();
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x1D, 0xB9]),
                timestamp
            ),
            Ok(None)
        );
        for seq in 0..0x7F {
            timestamp = timestamp + delay;
            assert_eq!(
                assembler.parse_packet(
                    &mut env,
                    &zero_extend(&[0x12, 0x34, 0x56, 0x78, seq]),
                    timestamp
                ),
                Ok(None)
            );
        }
        timestamp = timestamp + delay;
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[0x12, 0x34, 0x56, 0x78, 0x7F]),
                timestamp
            ),
            Ok(Some(Message {
                cid: [0x12, 0x34, 0x56, 0x78],
                cmd: CtapHidCommand::Ping,
                payload: vec![0x00; 0x1DB9]
            }))
        );
    }

    #[test]
    fn test_init_sync() {
        let mut env = TestEnv::new();
        let mut assembler = MessageAssembler::new();
        // Ping packet with a length longer than one packet.
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &byte_extend(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x02, 0x00], 0x51),
                CtapInstant::new(0)
            ),
            Ok(None)
        );
        // Init packet on the same channel.
        assert_eq!(
            assembler.parse_packet(
                &mut env,
                &zero_extend(&[
                    0x12, 0x34, 0x56, 0x78, 0x86, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
                    0xDE, 0xF0
                ]),
                CtapInstant::new(0)
            ),
            Ok(Some(Message {
                cid: [0x12, 0x34, 0x56, 0x78],
                cmd: CtapHidCommand::Init,
                payload: vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]
            }))
        );
    }

    // TODO: more tests
}
