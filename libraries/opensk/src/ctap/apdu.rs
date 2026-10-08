// Copyright 2020-2023 Google LLC
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

use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::convert::TryFrom;

const APDU_HEADER_LEN: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types, dead_code)]
pub enum ApduStatusCode {
    SW_SUCCESS = 0x90_00,
    /// Command successfully executed; 'XX' bytes of data are
    /// available and can be requested using GET RESPONSE.
    SW_GET_RESPONSE = 0x61_00,
    SW_MEMERR = 0x65_01,
    SW_WRONG_DATA = 0x6a_80,
    SW_WRONG_LENGTH = 0x67_00,
    SW_COND_USE_NOT_SATISFIED = 0x69_85,
    SW_COMMAND_NOT_ALLOWED = 0x69_86,
    SW_FILE_NOT_FOUND = 0x6a_82,
    SW_INCORRECT_P1P2 = 0x6a_86,
    /// Instruction code not supported or invalid
    SW_INS_INVALID = 0x6d_00,
    SW_CLA_INVALID = 0x6e_00,
    SW_INTERNAL_EXCEPTION = 0x6f_00,
}

impl From<ApduStatusCode> for u16 {
    fn from(code: ApduStatusCode) -> Self {
        code as u16
    }
}

#[allow(dead_code)]
pub enum ApduInstructions {
    Select = 0xA4,
    ReadBinary = 0xB0,
    GetResponse = 0xC0,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub struct ApduHeader {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
}

impl From<&[u8; APDU_HEADER_LEN]> for ApduHeader {
    fn from(header: &[u8; APDU_HEADER_LEN]) -> Self {
        ApduHeader {
            cla: header[0],
            ins: header[1],
            p1: header[2],
            p2: header[3],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// The structure of the length fields of a command APDU. The variants follow
/// the cases of ISO 7816-3:2006 section 12.1.3, and their names describe the
/// fields: for example, `Lc3DataLe2` is a 3-byte Lc, followed by the command
/// data and a 2-byte Le.
pub enum Case {
    /// Case 2S: no command data, 1-byte Le.
    Le1,
    /// Case 3S: 1-byte Lc, command data, no Le.
    Lc1Data,
    /// Case 4S: 1-byte Lc, command data, 1-byte Le.
    Lc1DataLe1,
    /// Case 3E: 3-byte Lc, command data, no Le.
    Lc3Data,
    /// Not encodable per ISO 7816-3: an extended Lc must be followed by a
    /// 2-byte Le. This form is tolerated for backwards compatibility with
    /// clients that append a short Le after an extended Lc.
    Lc3DataLe1,
    /// Case 4E: 3-byte Lc, command data, 2-byte Le.
    Lc3DataLe2,
    /// Case 2E: no command data, 3-byte Le.
    Le3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ApduType {
    Instruction,
    Short(Case),
    Extended(Case),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub struct Apdu {
    pub header: ApduHeader,
    pub lc: u16,
    pub data: Vec<u8>,
    pub le: u32,
    pub case_type: ApduType,
}

impl TryFrom<&[u8]> for Apdu {
    type Error = ApduStatusCode;

    /// Parses a command APDU, following the case table of ISO 7816-3:2006
    /// section 12.1.3:
    ///
    /// Case | Lc field | Le field | Total length
    /// -----|----------|----------|-------------------------
    /// 1    | none     | none     | 4 bytes
    /// 2S   | none     | 1 byte   | 5 bytes
    /// 2E   | none     | 3 bytes  | 7 bytes
    /// 3S   | 1 byte   | none     | 5 + Lc bytes
    /// 3E   | 3 bytes  | none     | 7 + Lc bytes
    /// 4S   | 1 byte   | 1 byte   | 6 + Lc bytes
    /// 4E   | 3 bytes  | 2 bytes  | 9 + Lc bytes
    ///
    /// In the extended form, Lc and Le are big-endian 16-bit values and the
    /// leading 0x00 of their 3-byte field is a marker. A Le of 0 means the
    /// maximum expected length: 256 in the short form, 65536 in the extended
    /// form.
    fn try_from(frame: &[u8]) -> Result<Self, ApduStatusCode> {
        if frame.len() < APDU_HEADER_LEN {
            return Err(ApduStatusCode::SW_WRONG_DATA);
        }
        //        +-----+-----+----+----+
        // header | CLA | INS | P1 | P2 |
        //        +-----+-----+----+----+
        let (header, payload) = frame.split_at(APDU_HEADER_LEN);
        let header: ApduHeader = array_ref!(header, 0, APDU_HEADER_LEN).into();

        if payload.is_empty() {
            // Case 1: there is no Lc nor Le.
            return Ok(Apdu {
                header,
                lc: 0x00,
                data: Vec::new(),
                le: 0x00,
                case_type: ApduType::Instruction,
            });
        }
        let byte_0 = payload[0];

        if payload.len() == 1 {
            // With a single byte after the header, that byte is necessarily a
            // short Le: there is no room for command data (case 2S).
            return Ok(Apdu {
                header,
                lc: 0x00,
                data: Vec::new(),
                le: if byte_0 == 0x00 {
                    // Ne = 256
                    0x100
                } else {
                    byte_0.into()
                },
                case_type: ApduType::Short(Case::Le1),
            });
        }

        if byte_0 != 0x00 {
            // The short form: byte_0 holds the length of the command data.
            let lc = byte_0 as usize;
            if payload.len() == 1 + lc {
                // Case 3S: Lc covers the rest of the payload, so there is no Le.
                return Ok(Apdu {
                    header,
                    lc: byte_0.into(),
                    data: payload[1..].to_vec(),
                    le: 0x00,
                    case_type: ApduType::Short(Case::Lc1Data),
                });
            }
            if payload.len() == 2 + lc {
                // Case 4S: one byte of Le follows the command data.
                let last_byte = payload[payload.len() - 1];
                return Ok(Apdu {
                    header,
                    lc: byte_0.into(),
                    data: payload[1..payload.len() - 1].to_vec(),
                    le: if last_byte == 0x00 {
                        // Ne = 256
                        0x100
                    } else {
                        last_byte.into()
                    },
                    case_type: ApduType::Short(Case::Lc1DataLe1),
                });
            }
            // The command data is truncated, or the payload has trailing bytes
            // that cannot be decoded.
            return Err(ApduStatusCode::SW_WRONG_LENGTH);
        }

        if payload.len() < 3 {
            // The payload starts with the 0x00 marker of an extended field,
            // but is too short to hold one.
            return Err(ApduStatusCode::SW_WRONG_LENGTH);
        }
        let extended_field = BigEndian::read_u16(&payload[1..3]) as usize;
        if payload.len() == 3 {
            // Case 2E: the 3-byte field is an extended Le and there is no
            // command data.
            return Ok(Apdu {
                header,
                lc: 0x00,
                data: Vec::new(),
                le: if extended_field == 0x00 {
                    // Ne = 65536
                    0x10000
                } else {
                    extended_field as u32
                },
                case_type: ApduType::Extended(Case::Le3),
            });
        }

        // The 3-byte field is an extended Lc: `0x00 Lc1 Lc2` followed by the
        // command data, possibly followed by a 2-byte Le (cases 3E and 4E).
        if payload.len() < 3 + extended_field {
            // The command data is truncated.
            return Err(ApduStatusCode::SW_WRONG_LENGTH);
        }
        let le_len = payload
            .len()
            .checked_sub(3 + extended_field)
            .ok_or(ApduStatusCode::SW_WRONG_LENGTH)?;
        match le_len {
            0 => Ok(Apdu {
                // Case 3E: Lc covers the rest of the payload.
                header,
                lc: extended_field as u16,
                data: payload[3..].to_vec(),
                le: 0x00,
                case_type: ApduType::Extended(Case::Lc3Data),
            }),
            1 => {
                // Not encodable per ISO 7816-3: an extended Lc must be followed
                // by a 2-byte Le. Tolerated for backwards compatibility with
                // clients that append a short Le after an extended Lc.
                let last_byte = payload[payload.len() - 1];
                Ok(Apdu {
                    header,
                    lc: extended_field as u16,
                    data: payload[3..payload.len() - 1].to_vec(),
                    le: if last_byte == 0x00 {
                        // Ne = 256
                        0x100
                    } else {
                        last_byte.into()
                    },
                    case_type: ApduType::Extended(Case::Lc3DataLe1),
                })
            }
            2 => {
                // Case 4E: an extended Le follows the command data.
                let le = BigEndian::read_u16(&payload[payload.len() - 2..]);
                Ok(Apdu {
                    header,
                    lc: extended_field as u16,
                    data: payload[3..payload.len() - 2].to_vec(),
                    le: if le == 0x00 {
                        // Ne = 65536
                        0x10000
                    } else {
                        le as u32
                    },
                    case_type: ApduType::Extended(Case::Lc3DataLe2),
                })
            }
            // A 3-byte Le after command data is not encodable either: the
            // 0x00 marker of the extended Le is only allowed when Lc is
            // absent, i.e. in case 2E.
            _ => Err(ApduStatusCode::SW_WRONG_LENGTH),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn pass_frame(frame: &[u8]) -> Result<Apdu, ApduStatusCode> {
        Apdu::try_from(frame)
    }

    #[test]
    fn test_case_type_1() {
        let frame: [u8; 4] = [0x00, 0x12, 0x00, 0x80];
        let response = pass_frame(&frame);
        assert!(response.is_ok());
        let expected = Apdu {
            header: ApduHeader {
                cla: 0x00,
                ins: 0x12,
                p1: 0x00,
                p2: 0x80,
            },
            lc: 0x00,
            data: Vec::new(),
            le: 0x00,
            case_type: ApduType::Instruction,
        };
        assert_eq!(Ok(expected), response);
    }

    #[test]
    fn test_case_type_2_short() {
        let frame: [u8; 5] = [0x00, 0xb0, 0x00, 0x00, 0x0f];
        let response = pass_frame(&frame);
        let expected = Apdu {
            header: ApduHeader {
                cla: 0x00,
                ins: 0xb0,
                p1: 0x00,
                p2: 0x00,
            },
            lc: 0x00,
            data: Vec::new(),
            le: 0x0f,
            case_type: ApduType::Short(Case::Le1),
        };
        assert_eq!(Ok(expected), response);
    }

    #[test]
    fn test_case_type_2_short_le() {
        let frame: [u8; 5] = [0x00, 0xb0, 0x00, 0x00, 0x00];
        let response = pass_frame(&frame);
        let expected = Apdu {
            header: ApduHeader {
                cla: 0x00,
                ins: 0xb0,
                p1: 0x00,
                p2: 0x00,
            },
            lc: 0x00,
            data: Vec::new(),
            le: 0x100,
            case_type: ApduType::Short(Case::Le1),
        };
        assert_eq!(Ok(expected), response);
    }

    #[test]
    fn test_case_type_3_short() {
        let frame: [u8; 7] = [0x00, 0xa4, 0x00, 0x0c, 0x02, 0xe1, 0x04];
        let payload = [0xe1, 0x04];
        let response = pass_frame(&frame);
        let expected = Apdu {
            header: ApduHeader {
                cla: 0x00,
                ins: 0xa4,
                p1: 0x00,
                p2: 0x0c,
            },
            lc: 0x02,
            data: payload.to_vec(),
            le: 0x00,
            case_type: ApduType::Short(Case::Lc1Data),
        };
        assert_eq!(Ok(expected), response);
    }

    #[test]
    fn test_case_type_4_short() {
        let frame: [u8; 13] = [
            0x00, 0xa4, 0x04, 0x00, 0x07, 0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0xff,
        ];
        let payload = [0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];
        let response = pass_frame(&frame);
        let expected = Apdu {
            header: ApduHeader {
                cla: 0x00,
                ins: 0xa4,
                p1: 0x04,
                p2: 0x00,
            },
            lc: 0x07,
            data: payload.to_vec(),
            le: 0xff,
            case_type: ApduType::Short(Case::Lc1DataLe1),
        };
        assert_eq!(Ok(expected), response);
    }

    #[test]
    fn test_case_type_4_short_le() {
        let frame: [u8; 13] = [
            0x00, 0xa4, 0x04, 0x00, 0x07, 0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
        ];
        let payload = [0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];
        let response = pass_frame(&frame);
        let expected = Apdu {
            header: ApduHeader {
                cla: 0x00,
                ins: 0xa4,
                p1: 0x04,
                p2: 0x00,
            },
            lc: 0x07,
            data: payload.to_vec(),
            le: 0x100,
            case_type: ApduType::Short(Case::Lc1DataLe1),
        };
        assert_eq!(Ok(expected), response);
    }

    #[test]
    fn test_invalid_apdu_header_length() {
        let frame: [u8; 3] = [0x00, 0x12, 0x00];
        let response = pass_frame(&frame);
        assert_eq!(Err(ApduStatusCode::SW_WRONG_DATA), response);
    }

    #[test]
    fn test_extended_length_apdu() {
        let frame: [u8; 186] = [
            0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0xb1, 0x60, 0xc5, 0xb3, 0x42, 0x58, 0x6b, 0x49,
            0xdb, 0x3e, 0x72, 0xd8, 0x24, 0x4b, 0xa5, 0x6c, 0x8d, 0x79, 0x2b, 0x65, 0x08, 0xe8,
            0xda, 0x9b, 0x0e, 0x2b, 0xc1, 0x63, 0x0d, 0xbc, 0xf3, 0x6d, 0x66, 0xa5, 0x46, 0x72,
            0xb2, 0x22, 0xc4, 0xcf, 0x95, 0xe1, 0x51, 0xed, 0x8d, 0x4d, 0x3c, 0x76, 0x7a, 0x6c,
            0xc3, 0x49, 0x43, 0x59, 0x43, 0x79, 0x4e, 0x88, 0x4f, 0x3d, 0x02, 0x3a, 0x82, 0x29,
            0xfd, 0x70, 0x3f, 0x8b, 0xd4, 0xff, 0xe0, 0xa8, 0x93, 0xdf, 0x1a, 0x58, 0x34, 0x16,
            0xb0, 0x1b, 0x8e, 0xbc, 0xf0, 0x2d, 0xc9, 0x99, 0x8d, 0x6f, 0xe4, 0x8a, 0xb2, 0x70,
            0x9a, 0x70, 0x3a, 0x27, 0x71, 0x88, 0x3c, 0x75, 0x30, 0x16, 0xfb, 0x02, 0x11, 0x4d,
            0x30, 0x54, 0x6c, 0x4e, 0x8c, 0x76, 0xb2, 0xf0, 0xa8, 0x4e, 0xd6, 0x90, 0xe4, 0x40,
            0x25, 0x6a, 0xdd, 0x64, 0x63, 0x3e, 0x83, 0x4f, 0x8b, 0x25, 0xcf, 0x88, 0x68, 0x80,
            0x01, 0x07, 0xdb, 0xc8, 0x64, 0xf7, 0xca, 0x4f, 0xd1, 0xc7, 0x95, 0x7c, 0xe8, 0x45,
            0xbc, 0xda, 0xd4, 0xef, 0x45, 0x63, 0x5a, 0x7a, 0x65, 0x3f, 0xaa, 0x22, 0x67, 0xe7,
            0x8a, 0xf2, 0x5f, 0xe8, 0x59, 0x2e, 0x0b, 0xc6, 0x85, 0xc6, 0xf7, 0x0e, 0x9e, 0xdb,
            0xb6, 0x2b, 0x00, 0x00,
        ];
        let payload: &[u8] = &frame[7..frame.len() - 2];
        let response = pass_frame(&frame);
        let expected = Apdu {
            header: ApduHeader {
                cla: 0x00,
                ins: 0x02,
                p1: 0x03,
                p2: 0x00,
            },
            lc: 0xb1,
            data: payload.to_vec(),
            le: 0x10000,
            case_type: ApduType::Extended(Case::Lc3DataLe2),
        };
        assert_eq!(Ok(expected), response);
    }

    #[test]
    fn test_previously_unsupported_case_type() {
        let frame: [u8; 73] = [
            0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x40, 0xe3, 0x8f, 0xde, 0x51, 0x3d, 0xac, 0x9d,
            0x1c, 0x6e, 0x86, 0x76, 0x31, 0x40, 0x25, 0x96, 0x86, 0x4d, 0x29, 0xe8, 0x07, 0xb3,
            0x56, 0x19, 0xdf, 0x4a, 0x00, 0x02, 0xae, 0x2a, 0x8c, 0x9d, 0x5a, 0xab, 0xc3, 0x4b,
            0x4e, 0xb9, 0x78, 0xb9, 0x11, 0xe5, 0x52, 0x40, 0xf3, 0x45, 0x64, 0x9c, 0xd3, 0xd7,
            0xe8, 0xb5, 0x83, 0xfb, 0xe0, 0x66, 0x98, 0x4d, 0x98, 0x81, 0xf7, 0xb5, 0x49, 0x4d,
            0xcb, 0x00, 0x00,
        ];
        let payload: &[u8] = &frame[7..frame.len() - 2];
        let response = pass_frame(&frame);
        let expected = Apdu {
            header: ApduHeader {
                cla: 0x00,
                ins: 0x01,
                p1: 0x03,
                p2: 0x00,
            },
            lc: 0x40,
            data: payload.to_vec(),
            le: 0x10000,
            case_type: ApduType::Extended(Case::Lc3DataLe2),
        };
        assert_eq!(Ok(expected), response);
    }

    #[test]
    fn test_case_type_2_extended() {
        // An extended Le with no command data (case 2E), as reported in #565.
        let frame: [u8; 7] = [0x00, 0xb0, 0x00, 0x00, 0x00, 0x12, 0x34];
        let response = pass_frame(&frame);
        let expected = Apdu {
            header: ApduHeader {
                cla: 0x00,
                ins: 0xb0,
                p1: 0x00,
                p2: 0x00,
            },
            lc: 0x00,
            data: Vec::new(),
            le: 0x1234,
            case_type: ApduType::Extended(Case::Le3),
        };
        assert_eq!(Ok(expected), response);
    }

    #[test]
    fn test_case_type_2_extended_le() {
        // A zero extended Le means the maximum expected length of 65536 bytes.
        let frame: [u8; 7] = [0x00, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00];
        let response = pass_frame(&frame);
        let expected = Apdu {
            header: ApduHeader {
                cla: 0x00,
                ins: 0xb0,
                p1: 0x00,
                p2: 0x00,
            },
            lc: 0x00,
            data: Vec::new(),
            le: 0x10000,
            case_type: ApduType::Extended(Case::Le3),
        };
        assert_eq!(Ok(expected), response);
    }

    #[test]
    fn test_case_type_3_extended() {
        // An extended Lc covering the rest of the payload (case 3E), with no Le.
        let frame: [u8; 9] = [0x00, 0xa4, 0x00, 0x0c, 0x00, 0x00, 0x02, 0xe1, 0x04];
        let response = pass_frame(&frame);
        let expected = Apdu {
            header: ApduHeader {
                cla: 0x00,
                ins: 0xa4,
                p1: 0x00,
                p2: 0x0c,
            },
            lc: 0x02,
            data: vec![0xe1, 0x04],
            le: 0x00,
            case_type: ApduType::Extended(Case::Lc3Data),
        };
        assert_eq!(Ok(expected), response);
    }

    #[test]
    fn test_malformed_extended_le_after_data() {
        // A 3-byte Le after command data is not encodable per ISO 7816-3: the
        // 0x00 marker of the extended Le is only allowed when Lc is absent
        // (case 2E). See #565.
        let frame: [u8; 14] = [
            0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x04, 0xd1, 0xd2, 0xd3, 0xd4, 0x00, 0x00, 0x40,
        ];
        let response = pass_frame(&frame);
        assert_eq!(Err(ApduStatusCode::SW_WRONG_LENGTH), response);
    }

    #[test]
    fn test_extended_form_truncated_command_data() {
        // The extended Lc announces 0x10 bytes of command data, but only 4
        // bytes are present.
        let frame: [u8; 11] = [
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x10, 0xd1, 0xd2, 0xd3, 0xd4,
        ];
        let response = pass_frame(&frame);
        assert_eq!(Err(ApduStatusCode::SW_WRONG_LENGTH), response);
    }

    #[test]
    fn test_short_form_truncated_command_data() {
        // The short Lc announces 0x40 bytes of command data, but only 0x0A
        // bytes are present.
        let frame: [u8; 15] = [
            0x00, 0xa4, 0x00, 0x0c, 0x40, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
            0xda,
        ];
        let response = pass_frame(&frame);
        assert_eq!(Err(ApduStatusCode::SW_WRONG_LENGTH), response);
    }

    #[test]
    fn test_incomplete_extended_le() {
        // The 0x00 marker announces a 3-byte extended field, but only 2 bytes
        // are present.
        let frame: [u8; 6] = [0x00, 0xb0, 0x00, 0x00, 0x00, 0x12];
        let response = pass_frame(&frame);
        assert_eq!(Err(ApduStatusCode::SW_WRONG_LENGTH), response);
    }
}
