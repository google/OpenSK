// Copyright 2019-2023 Google LLC
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

use super::{HidPacket, Message};

const TYPE_INIT_BIT: u8 = 0x80;

/// Iterator for HID packets.
///
/// The `new` constructor splits the CTAP `Message` into `HidPacket`s for sending over USB.
pub struct HidPacketIterator(Option<MessageSplitter>);

impl HidPacketIterator {
    pub fn new(message: Message) -> Option<HidPacketIterator> {
        let splitter = MessageSplitter::new(message);
        if splitter.is_some() {
            Some(HidPacketIterator(splitter))
        } else {
            None
        }
    }

    pub fn none() -> HidPacketIterator {
        HidPacketIterator(None)
    }

    pub fn has_data(&self) -> bool {
        if let Some(ms) = &self.0 {
            ms.finished()
        } else {
            false
        }
    }
}

impl Iterator for HidPacketIterator {
    type Item = HidPacket;

    fn next(&mut self) -> Option<HidPacket> {
        match &mut self.0 {
            Some(splitter) => splitter.next(),
            None => None,
        }
    }
}

struct MessageSplitter {
    message: Message,
    packet: HidPacket,
    seq: Option<u8>,
    i: usize,
}

impl MessageSplitter {
    /// Try to split this message into an iterator of HID packets.
    ///
    /// This fails if the message is too long to fit into a sequence of HID packets.
    pub fn new(message: Message) -> Option<MessageSplitter> {
        if message.payload.len() > 7609 {
            None
        } else {
            // Cache the CID, as it is constant for all packets in this message.
            let mut packet = [0; 64];
            packet[..4].copy_from_slice(&message.cid);

            Some(MessageSplitter {
                message,
                packet,
                seq: None,
                i: 0,
            })
        }
    }

    /// Copy as many bytes as possible from data to dst, and return how many bytes are copied.
    ///
    /// Contrary to copy_from_slice, this doesn't require slices of the same length.
    /// All unused bytes in dst are set to zero, as if the data was padded with zeros to match.
    fn consume_data(dst: &mut [u8], data: &[u8]) -> usize {
        let dst_len = dst.len();
        let data_len = data.len();

        if data_len <= dst_len {
            // data fits in dst, copy all the bytes.
            dst[..data_len].copy_from_slice(data);
            for byte in dst[data_len..].iter_mut() {
                *byte = 0;
            }
            data_len
        } else {
            // Fill all of dst.
            dst.copy_from_slice(&data[..dst_len]);
            dst_len
        }
    }

    // Is there more data to iterate over?
    fn finished(&self) -> bool {
        let payload_len = self.message.payload.len();
        match self.seq {
            None => true,
            Some(_) => self.i < payload_len,
        }
    }
}

impl Iterator for MessageSplitter {
    type Item = HidPacket;

    fn next(&mut self) -> Option<HidPacket> {
        let payload_len = self.message.payload.len();
        match self.seq {
            None => {
                // First, send an initialization packet.
                self.packet[4] = self.message.cmd as u8 | TYPE_INIT_BIT;
                self.packet[5] = (payload_len >> 8) as u8;
                self.packet[6] = payload_len as u8;

                self.seq = Some(0);
                self.i =
                    MessageSplitter::consume_data(&mut self.packet[7..], &self.message.payload);
                Some(self.packet)
            }
            Some(seq) => {
                // Send the next continuation packet, if any.
                if self.i < payload_len {
                    self.packet[4] = seq;
                    self.seq = Some(seq + 1);
                    self.i += MessageSplitter::consume_data(
                        &mut self.packet[5..],
                        &self.message.payload[self.i..],
                    );
                    Some(self.packet)
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::CtapHidCommand;
    use super::*;

    fn assert_packet_output_equality(message: Message, expected_packets: Vec<HidPacket>) {
        let packets: Vec<HidPacket> = HidPacketIterator::new(message).unwrap().collect();
        assert_eq!(packets.len(), expected_packets.len());
        for (packet, expected_packet) in packets.iter().zip(expected_packets.iter()) {
            assert_eq!(packet as &[u8], expected_packet as &[u8]);
        }
    }

    #[test]
    fn test_hid_packet_iterator_single_packet() {
        let message = Message {
            cid: [0x12, 0x34, 0x56, 0x78],
            cmd: CtapHidCommand::Cbor,
            payload: vec![0xAA, 0xBB],
        };
        let expected_packets: Vec<HidPacket> = vec![[
            0x12, 0x34, 0x56, 0x78, 0x90, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]];
        assert_packet_output_equality(message, expected_packets);
    }

    #[test]
    fn test_hid_packet_iterator_big_single_packet() {
        let message = Message {
            cid: [0x12, 0x34, 0x56, 0x78],
            cmd: CtapHidCommand::Cbor,
            payload: vec![0xAA; 64 - 7],
        };
        let expected_packets: Vec<HidPacket> = vec![[
            0x12, 0x34, 0x56, 0x78, 0x90, 0x00, 0x39, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        ]];
        assert_packet_output_equality(message, expected_packets);
    }

    #[test]
    fn test_hid_packet_iterator_two_packets() {
        let message = Message {
            cid: [0x12, 0x34, 0x56, 0x78],
            cmd: CtapHidCommand::Cbor,
            payload: vec![0xAA; 64 - 7 + 1],
        };
        let expected_packets: Vec<HidPacket> = vec![
            [
                0x12, 0x34, 0x56, 0x78, 0x90, 0x00, 0x3A, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            ],
            [
                0x12, 0x34, 0x56, 0x78, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        ];
        assert_packet_output_equality(message, expected_packets);
    }

    #[test]
    fn test_hid_packet_iterator_two_full_packets() {
        let mut payload = vec![0xAA; 64 - 7];
        payload.extend(vec![0xBB; 64 - 5]);
        let message = Message {
            cid: [0x12, 0x34, 0x56, 0x78],
            cmd: CtapHidCommand::Cbor,
            payload,
        };
        let expected_packets: Vec<HidPacket> = vec![
            [
                0x12, 0x34, 0x56, 0x78, 0x90, 0x00, 0x74, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            ],
            [
                0x12, 0x34, 0x56, 0x78, 0x00, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            ],
        ];
        assert_packet_output_equality(message, expected_packets);
    }

    #[test]
    fn test_hid_packet_iterator_max_packets() {
        let mut payload = vec![0xFF; 64 - 7];
        for i in 0..128 {
            payload.extend(vec![i + 1; 64 - 5]);
        }

        // Sanity check for the length of the payload.
        assert_eq!(payload.len(), 0x1db9);

        let message = Message {
            cid: [0x12, 0x34, 0x56, 0x78],
            cmd: CtapHidCommand::Msg,
            payload,
        };

        let mut expected_packets: Vec<HidPacket> = vec![[
            0x12, 0x34, 0x56, 0x78, 0x83, 0x1D, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ]];
        for i in 0..128 {
            let mut packet: HidPacket = [0; 64];
            packet[0] = 0x12;
            packet[1] = 0x34;
            packet[2] = 0x56;
            packet[3] = 0x78;
            packet[4] = i;
            for byte in packet.iter_mut().skip(5) {
                *byte = i + 1;
            }
            expected_packets.push(packet);
        }

        assert_packet_output_equality(message, expected_packets);
    }

    #[test]
    fn test_hid_packet_iterator_payload_one_too_large() {
        let payload = vec![0xFF; (64 - 7) + 128 * (64 - 5) + 1];
        assert_eq!(payload.len(), 0x1dba);
        let message = Message {
            cid: [0x12, 0x34, 0x56, 0x78],
            cmd: CtapHidCommand::Msg,
            payload,
        };
        assert!(HidPacketIterator::new(message).is_none());
    }

    #[test]
    fn test_hid_packet_iterator_payload_way_too_large() {
        // Check that overflow of u16 doesn't bypass the size limit.
        let payload = vec![0xFF; 0x10000];
        let message = Message {
            cid: [0x12, 0x34, 0x56, 0x78],
            cmd: CtapHidCommand::Msg,
            payload,
        };
        assert!(HidPacketIterator::new(message).is_none());
    }
}
