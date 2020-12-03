use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::convert::TryFrom;

type ByteArray = &'static [u8];

const APDU_HEADER_LEN: usize = 4;

#[cfg_attr(test, derive(Clone, Debug))]
#[allow(non_camel_case_types)]
#[derive(PartialEq)]
pub enum ApduStatusCode {
    SW_SUCCESS,
    /// Command successfully executed; 'XX' bytes of data are
    /// available and can be requested using GET RESPONSE.
    SW_GET_RESPONSE,
    SW_WRONG_DATA,
    SW_WRONG_LENGTH,
    SW_COND_USE_NOT_SATISFIED,
    SW_FILE_NOT_FOUND,
    SW_INCORRECT_P1P2,
    /// Instruction code not supported or invalid
    SW_INS_INVALID,
    SW_CLA_INVALID,
    SW_INTERNAL_EXCEPTION,
}

impl From<ApduStatusCode> for ByteArray {
    fn from(status_code: ApduStatusCode) -> ByteArray {
        match status_code {
            ApduStatusCode::SW_SUCCESS => b"\x90\x00",
            ApduStatusCode::SW_GET_RESPONSE => b"\x61\x00",
            ApduStatusCode::SW_WRONG_DATA => b"\x6A\x80",
            ApduStatusCode::SW_WRONG_LENGTH => b"\x67\x00",
            ApduStatusCode::SW_COND_USE_NOT_SATISFIED => b"\x69\x85",
            ApduStatusCode::SW_FILE_NOT_FOUND => b"\x6a\x82",
            ApduStatusCode::SW_INCORRECT_P1P2 => b"\x6a\x86",
            ApduStatusCode::SW_INS_INVALID => b"\x6d\x00",
            ApduStatusCode::SW_CLA_INVALID => b"\x6e\x00",
            ApduStatusCode::SW_INTERNAL_EXCEPTION => b"\x6f\x00",
        }
    }
}

#[allow(dead_code)]
pub enum ApduInstructions {
    Select = 0xA4,
    ReadBinary = 0xB0,
    GetResponse = 0xC0,
}

#[cfg_attr(test, derive(Clone, Debug))]
#[allow(dead_code)]
#[derive(Default, PartialEq)]
pub struct ApduHeader {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
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

#[cfg_attr(test, derive(Clone, Debug))]
#[derive(PartialEq)]
/// The APDU cases
pub enum Case {
    Le1,
    Lc1Data,
    Lc1DataLe1,
    Lc3Data,
    Lc3DataLe1,
    Lc3DataLe2,
    Le3,
}

#[cfg_attr(test, derive(Clone, Debug))]
#[allow(dead_code)]
#[derive(PartialEq)]
pub enum ApduType {
    Instruction,
    Short(Case),
    Extended(Case),
    Unknown,
}

impl Default for ApduType {
    fn default() -> ApduType {
        ApduType::Unknown
    }
}

#[cfg_attr(test, derive(Clone, Debug))]
#[allow(dead_code)]
#[derive(Default, PartialEq)]
pub struct APDU {
    header: ApduHeader,
    lc: u16,
    data: Vec<u8>,
    le: u32,
    case_type: ApduType,
}

impl TryFrom<&[u8]> for APDU {
    type Error = ApduStatusCode;

    fn try_from(frame: &[u8]) -> Result<Self, ApduStatusCode> {
        if frame.len() < APDU_HEADER_LEN as usize {
            return Err(ApduStatusCode::SW_WRONG_DATA);
        }
        //        +-----+-----+----+----+
        // header | CLA | INS | P1 | P2 |
        //        +-----+-----+----+----+
        let (header, payload) = frame.split_at(APDU_HEADER_LEN);

        if payload.is_empty() {
            // Lc is zero-bytes in length
            return Ok(APDU {
                header: array_ref!(header, 0, APDU_HEADER_LEN).into(),
                lc: 0x00,
                data: Vec::new(),
                le: 0x00,
                case_type: ApduType::Instruction,
            });
        } else {
            // Lc is not zero-bytes in length, let's figure out how long it is
            let byte_0 = payload[0];
            if payload.len() == 1 {
                // There is only one byte in the payload, that byte cannot be Lc because that would
                // entail at *least* one another byte in the payload (for the command data)
                return Ok(APDU {
                    header: array_ref!(header, 0, APDU_HEADER_LEN).into(),
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
            if payload.len() == 1 + (byte_0 as usize) && byte_0 != 0 {
                // Lc is one-byte long and since the size specified by Lc covers the rest of the
                // payload there's no Le at the end
                return Ok(APDU {
                    header: array_ref!(header, 0, APDU_HEADER_LEN).into(),
                    lc: byte_0.into(),
                    data: payload[1..].to_vec(),
                    case_type: ApduType::Short(Case::Lc1Data),
                    le: 0,
                });
            }
            if payload.len() == 2 + (byte_0 as usize) && byte_0 != 0 {
                // Lc is one-byte long and since the size specified by Lc covers the rest of the
                // payload with ONE additional byte that byte must be Le
                let last_byte: u32 = (*payload.last().unwrap()).into();
                return Ok(APDU {
                    header: array_ref!(header, 0, APDU_HEADER_LEN).into(),
                    lc: byte_0.into(),
                    data: payload[1..(payload.len() - 1)].to_vec(),
                    le: if last_byte == 0x00 { 0x100 } else { last_byte },
                    case_type: ApduType::Short(Case::Lc1DataLe1),
                });
            }
            if payload.len() > 2 {
                // Lc is possibly three-bytes long
                let extended_apdu_lc: usize = BigEndian::read_u16(&payload[1..]) as usize;
                let extended_apdu_le_len: usize = if payload.len() > extended_apdu_lc {
                    payload.len() - extended_apdu_lc - 3
                } else {
                    0
                };
                if byte_0 == 0 && extended_apdu_le_len <= 3 {
                    // If first byte is zero AND the next two bytes can be parsed as a big-endian
                    // length that covers the rest of the block (plus few additional bytes for Le), we
                    // have an extended-length APDU
                    let last_byte: u32 = (*payload.last().unwrap()).into();
                    return Ok(APDU {
                        header: array_ref!(header, 0, APDU_HEADER_LEN).into(),
                        lc: extended_apdu_lc as u16,
                        data: payload[3..(payload.len() - extended_apdu_le_len)].to_vec(),
                        le: match extended_apdu_le_len {
                            0 => 0,
                            1 => {
                                if last_byte == 0x00 {
                                    0x100
                                } else {
                                    last_byte
                                }
                            }
                            2 => BigEndian::read_u16(
                                &payload[payload.len() - extended_apdu_le_len..],
                            ) as u32,
                            3 => BigEndian::read_u32(
                                &payload[payload.len() - extended_apdu_le_len..],
                            ),
                            _ => 0,
                        },
                        case_type: ApduType::Extended(match extended_apdu_le_len {
                            0 => Case::Lc3Data,
                            1 => Case::Lc3DataLe1,
                            2 => Case::Lc3DataLe2,
                            3 => Case::Le3,
                            _ => return Err(ApduStatusCode::SW_COND_USE_NOT_SATISFIED),
                        }),
                    });
                }
            }
        }
        return Err(ApduStatusCode::SW_COND_USE_NOT_SATISFIED);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn pass_frame(frame: &[u8]) -> Result<APDU, ApduStatusCode> {
        APDU::try_from(frame)
    }

    #[test]
    fn test_case_type_1() {
        let frame: [u8; 4] = [0x00, 0x12, 0x00, 0x80];
        let response = pass_frame(&frame);
        assert!(response.is_ok());
        let expected = APDU {
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
        let expected = APDU {
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
        let expected = APDU {
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
        let expected = APDU {
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
        let expected = APDU {
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
        let expected = APDU {
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
        let expected = APDU {
            header: ApduHeader {
                cla: 0x00,
                ins: 0x02,
                p1: 0x03,
                p2: 0x00,
            },
            lc: 0xb1,
            data: payload.to_vec(),
            le: 0x00,
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
        let expected = APDU {
            header: ApduHeader {
                cla: 0x00,
                ins: 0x01,
                p1: 0x03,
                p2: 0x00,
            },
            lc: 0x40,
            data: payload.to_vec(),
            le: 0x00,
            case_type: ApduType::Extended(Case::Lc3DataLe2),
        };
        assert_eq!(Ok(expected), response);
    }
}
