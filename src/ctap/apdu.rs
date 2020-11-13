use alloc::vec::Vec;
use core::convert::TryFrom;

type ByteArray = &'static [u8];

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

#[allow(non_camel_case_types, dead_code)]
pub enum ApduIns {
    SELECT = 0xA4,
    READ_BINARY = 0xB0,
    GET_RESPONSE = 0xC0,
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

impl From<&[u8]> for ApduHeader {
    fn from(header: &[u8]) -> Self {
        ApduHeader {
            cla: header[0],
            ins: header[1],
            p1: header[2],
            p2: header[3],
        }
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
    case_type: u8,
}

const APDU_HEADER_LEN: u8 = 4;

impl TryFrom<&[u8]> for APDU {
    type Error = ApduStatusCode;

    fn try_from(frame: &[u8]) -> Result<Self, ApduStatusCode> {
        if frame.len() < APDU_HEADER_LEN as usize {
            return Err(ApduStatusCode::SW_WRONG_DATA);
        }
        //        +-----+-----+----+----+
        // header | CLA | INS | P1 | P2 |
        //        +-----+-----+----+----+
        let (header, payload) = frame.split_at(APDU_HEADER_LEN as usize);

        let mut apdu = APDU {
            header: header.into(),
            lc: 0x00,
            data: Vec::new(),
            le: 0x00,
            case_type: 0x00,
        };

        // case 1
        if payload.is_empty() {
            apdu.case_type = 0x01;
        } else {
            let byte_0 = payload[0];
            // case 2S (Le)
            if payload.len() == 1 {
                apdu.case_type = 0x02;
                apdu.le = if byte_0 == 0x00 {
                    // Ne = 256
                    0x100
                } else {
                    byte_0.into()
                }
            }
            // case 3S (Lc + data)
            if payload.len() == (1 + byte_0) as usize && byte_0 != 0 {
                apdu.case_type = 0x03;
                apdu.lc = byte_0.into();
                apdu.data = payload[1..].to_vec();
            }
            // case 4S (Lc + data + Le)
            if payload.len() == (1 + byte_0 + 1) as usize && byte_0 != 0 {
                apdu.case_type = 0x04;
                apdu.lc = byte_0.into();
                apdu.data = payload[1..(payload.len() - 1)].to_vec();
                apdu.le = (*payload.last().unwrap()).into();
                if apdu.le == 0x00 {
                    apdu.le = 0x100;
                }
            }
        }
        // TODO: Add extended length cases
        if apdu.case_type == 0x00 {
            return Err(ApduStatusCode::SW_COND_USE_NOT_SATISFIED);
        }
        Ok(apdu)
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
            case_type: 0x01,
        };
        assert_eq!(expected, response.unwrap());
    }

    #[test]
    fn test_case_type_2_short() {
        let frame: [u8; 5] = [0x00, 0xb0, 0x00, 0x00, 0x0f];
        let response = pass_frame(&frame);
        assert!(response.is_ok());
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
            case_type: 0x02,
        };
        assert_eq!(expected, response.unwrap());
    }

    #[test]
    fn test_case_type_2_short_le() {
        let frame: [u8; 5] = [0x00, 0xb0, 0x00, 0x00, 0x00];
        let response = pass_frame(&frame);
        assert!(response.is_ok());
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
            case_type: 0x02,
        };
        assert_eq!(expected, response.unwrap());
    }

    #[test]
    fn test_case_type_3_short() {
        let frame: [u8; 7] = [0x00, 0xa4, 0x00, 0x0c, 0x02, 0xe1, 0x04];
        let payload = [0xe1, 0x04];
        let response = pass_frame(&frame);
        assert!(response.is_ok());
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
            case_type: 0x03,
        };
        assert_eq!(expected, response.unwrap());
    }

    #[test]
    fn test_case_type_4_short() {
        let frame: [u8; 13] = [
            0x00, 0xa4, 0x04, 0x00, 0x07, 0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0xff,
        ];
        let payload = [0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];
        let response = pass_frame(&frame);
        assert!(response.is_ok());
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
            case_type: 0x04,
        };
        assert_eq!(expected, response.unwrap());
    }

    #[test]
    fn test_case_type_4_short_le() {
        let frame: [u8; 13] = [
            0x00, 0xa4, 0x04, 0x00, 0x07, 0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
        ];
        let payload = [0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];
        let response = pass_frame(&frame);
        assert!(response.is_ok());
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
            case_type: 0x04,
        };
        assert_eq!(expected, response.unwrap());
    }

    #[test]
    fn test_invalid_apdu_header_length() {
        let frame: [u8; 3] = [0x00, 0x12, 0x00];
        let response = pass_frame(&frame);
        assert!(response.is_err());
        assert_eq!(Some(ApduStatusCode::SW_WRONG_DATA), response.err());
    }

    #[test]
    fn test_unsupported_case_type() {
        let frame: [u8; 73] = [
            0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x40, 0xe3, 0x8f, 0xde, 0x51, 0x3d, 0xac, 0x9d,
            0x1c, 0x6e, 0x86, 0x76, 0x31, 0x40, 0x25, 0x96, 0x86, 0x4d, 0x29, 0xe8, 0x07, 0xb3,
            0x56, 0x19, 0xdf, 0x4a, 0x00, 0x02, 0xae, 0x2a, 0x8c, 0x9d, 0x5a, 0xab, 0xc3, 0x4b,
            0x4e, 0xb9, 0x78, 0xb9, 0x11, 0xe5, 0x52, 0x40, 0xf3, 0x45, 0x64, 0x9c, 0xd3, 0xd7,
            0xe8, 0xb5, 0x83, 0xfb, 0xe0, 0x66, 0x98, 0x4d, 0x98, 0x81, 0xf7, 0xb5, 0x49, 0x4d,
            0xcb, 0x00, 0x00,
        ];
        let response = pass_frame(&frame);
        assert!(response.is_err());
        assert_eq!(
            Some(ApduStatusCode::SW_COND_USE_NOT_SATISFIED),
            response.err()
        );
    }
}
