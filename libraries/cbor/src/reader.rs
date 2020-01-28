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

use super::values::{Constants, KeyType, SimpleValue, Value};
use alloc::collections::BTreeMap;
use alloc::str;
use alloc::vec::Vec;

#[derive(Debug, PartialEq)]
pub enum DecoderError {
    UnsupportedMajorType,
    UnknownAdditionalInfo,
    IncompleteCborData,
    IncorrectMapKeyType,
    TooMuchNesting,
    InvalidUtf8,
    ExtranousData,
    OutOfOrderKey,
    NonMinimalCborEncoding,
    UnsupportedSimpleValue,
    UnsupportedFloatingPointValue,
    OutOfRangeIntegerValue,
}

pub fn read(encoded_cbor: &[u8]) -> Result<Value, DecoderError> {
    let mut reader = Reader::new(encoded_cbor);
    let value = reader.decode_complete_data_item(Reader::MAX_NESTING_DEPTH)?;
    if !reader.remaining_cbor.is_empty() {
        return Err(DecoderError::ExtranousData);
    }
    Ok(value)
}

struct Reader<'a> {
    remaining_cbor: &'a [u8],
}

impl<'a> Reader<'a> {
    const MAX_NESTING_DEPTH: i8 = 4;

    pub fn new(cbor: &'a [u8]) -> Reader<'a> {
        Reader {
            remaining_cbor: cbor,
        }
    }

    pub fn decode_complete_data_item(
        &mut self,
        remaining_depth: i8,
    ) -> Result<Value, DecoderError> {
        if remaining_depth < 0 {
            return Err(DecoderError::TooMuchNesting);
        }

        match self.read_bytes(1) {
            Some([first_byte]) => {
                // Unsigned byte means logical shift, so only zeros get shifted in.
                let major_type_value = first_byte >> Constants::MAJOR_TYPE_BIT_SHIFT;
                let additional_info = first_byte & Constants::ADDITIONAL_INFORMATION_MASK;
                let size_result = self.read_variadic_length_integer(additional_info);
                match size_result {
                    Ok(size_value) => match major_type_value {
                        0 => self.decode_value_to_unsigned(size_value),
                        1 => self.decode_value_to_negative(size_value),
                        2 => self.read_byte_string_content(size_value),
                        3 => self.read_text_string_content(size_value),
                        4 => self.read_array_content(size_value, remaining_depth),
                        5 => self.read_map_content(size_value, remaining_depth),
                        7 => self.decode_to_simple_value(size_value, additional_info),
                        _ => Err(DecoderError::UnsupportedMajorType),
                    },
                    Err(decode_error) => Err(decode_error),
                }
            }
            _ => Err(DecoderError::IncompleteCborData),
        }
    }

    fn read_bytes(&mut self, num_bytes: usize) -> Option<&[u8]> {
        if num_bytes > self.remaining_cbor.len() {
            None
        } else {
            let (left, right) = self.remaining_cbor.split_at(num_bytes);
            self.remaining_cbor = right;
            Some(left)
        }
    }

    fn read_variadic_length_integer(&mut self, additional_info: u8) -> Result<u64, DecoderError> {
        let additional_bytes_num = match additional_info {
            0..=Constants::ADDITIONAL_INFORMATION_MAX_INT => return Ok(additional_info as u64),
            Constants::ADDITIONAL_INFORMATION_1_BYTE => 1,
            Constants::ADDITIONAL_INFORMATION_2_BYTES => 2,
            Constants::ADDITIONAL_INFORMATION_4_BYTES => 4,
            Constants::ADDITIONAL_INFORMATION_8_BYTES => 8,
            _ => return Err(DecoderError::UnknownAdditionalInfo),
        };
        match self.read_bytes(additional_bytes_num) {
            Some(bytes) => {
                let mut size_value = 0u64;
                for byte in bytes {
                    size_value <<= 8;
                    size_value += *byte as u64;
                }
                if (additional_bytes_num == 1 && size_value < 24)
                    || size_value < (1u64 << (8 * (additional_bytes_num >> 1)))
                {
                    Err(DecoderError::NonMinimalCborEncoding)
                } else {
                    Ok(size_value)
                }
            }
            None => Err(DecoderError::IncompleteCborData),
        }
    }

    fn decode_value_to_unsigned(&self, size_value: u64) -> Result<Value, DecoderError> {
        Ok(cbor_unsigned!(size_value))
    }

    fn decode_value_to_negative(&self, size_value: u64) -> Result<Value, DecoderError> {
        let signed_size = size_value as i64;
        if signed_size < 0 {
            Err(DecoderError::OutOfRangeIntegerValue)
        } else {
            Ok(Value::KeyValue(KeyType::Negative(-(size_value as i64) - 1)))
        }
    }

    fn read_byte_string_content(&mut self, size_value: u64) -> Result<Value, DecoderError> {
        match self.read_bytes(size_value as usize) {
            Some(bytes) => Ok(cbor_bytes_lit!(bytes)),
            None => Err(DecoderError::IncompleteCborData),
        }
    }

    fn read_text_string_content(&mut self, size_value: u64) -> Result<Value, DecoderError> {
        match self.read_bytes(size_value as usize) {
            Some(bytes) => match str::from_utf8(bytes) {
                Ok(s) => Ok(cbor_text!(s)),
                Err(_) => Err(DecoderError::InvalidUtf8),
            },
            None => Err(DecoderError::IncompleteCborData),
        }
    }

    fn read_array_content(
        &mut self,
        size_value: u64,
        remaining_depth: i8,
    ) -> Result<Value, DecoderError> {
        // Don't set the capacity already, it is an unsanitized input.
        let mut value_array = Vec::new();
        for _ in 0..size_value {
            value_array.push(self.decode_complete_data_item(remaining_depth - 1)?);
        }
        Ok(cbor_array_vec!(value_array))
    }

    fn read_map_content(
        &mut self,
        size_value: u64,
        remaining_depth: i8,
    ) -> Result<Value, DecoderError> {
        let mut value_map = BTreeMap::new();
        let mut last_key_option = None;
        for _ in 0..size_value {
            let key_value = self.decode_complete_data_item(remaining_depth - 1)?;
            if let Value::KeyValue(key) = key_value {
                if let Some(last_key) = last_key_option {
                    if last_key >= key {
                        return Err(DecoderError::OutOfOrderKey);
                    }
                }
                last_key_option = Some(key.clone());
                value_map.insert(key, self.decode_complete_data_item(remaining_depth - 1)?);
            } else {
                return Err(DecoderError::IncorrectMapKeyType);
            }
        }
        Ok(cbor_map_btree!(value_map))
    }

    fn decode_to_simple_value(
        &self,
        size_value: u64,
        additional_info: u8,
    ) -> Result<Value, DecoderError> {
        if additional_info > Constants::ADDITIONAL_INFORMATION_MAX_INT
            && additional_info != Constants::ADDITIONAL_INFORMATION_1_BYTE
        {
            // TODO(kaczmarczyck) the chromium C++ reference allows equality to 24 here, why?
            // Also, why not just disallow ANY additional_info != size_value?
            return Err(DecoderError::UnsupportedFloatingPointValue);
        }
        match SimpleValue::from_integer(size_value) {
            Some(simple_value) => Ok(Value::Simple(simple_value)),
            None => Err(DecoderError::UnsupportedSimpleValue),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_read_unsigned() {
        let cases = vec![
            (0, vec![0x00]),
            (1, vec![0x01]),
            (10, vec![0x0A]),
            (23, vec![0x17]),
            (24, vec![0x18, 0x18]),
            (255, vec![0x18, 0xFF]),
            (256, vec![0x19, 0x01, 0x00]),
            (65535, vec![0x19, 0xFF, 0xFF]),
            (65536, vec![0x1A, 0x00, 0x01, 0x00, 0x00]),
            (0xFFFFFFFF, vec![0x1A, 0xFF, 0xFF, 0xFF, 0xFF]),
            (
                0x100000000,
                vec![0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
            (
                std::i64::MAX,
                vec![0x1B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            ),
        ];
        for (unsigned, mut cbor) in cases {
            assert_eq!(read(&cbor), Ok(cbor_int!(unsigned)));
            cbor.push(0x01);
            assert_eq!(read(&cbor), Err(DecoderError::ExtranousData));
        }
    }

    #[test]
    fn test_read_unsigned_non_minimum_byte_length() {
        let encodings = vec![
            // Uint 23 encoded with 1 byte.
            vec![0x18, 0x17],
            // Uint 255 encoded with 2 bytes.
            vec![0x19, 0x00, 0xff],
            // Uint 65535 encoded with 4 bytes.
            vec![0x1a, 0x00, 0x00, 0xff, 0xff],
            // Uint 4294967295 encoded with 8 bytes.
            vec![0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
            // When decoding byte has more than one syntax error, the first syntax
            // error encountered during deserialization is returned as the error code.
            vec![
                0xa2, // map with non-minimally encoded key
                0x17, // key 24
                0x61, 0x42, // value :"B"
                0x18, 0x17, // key 23 encoded with extra byte
                0x61, 0x45, // value "E"
            ],
            vec![
                0xa2, // map with out of order and non-minimally encoded key
                0x18, 0x17, // key 23 encoded with extra byte
                0x61, 0x45, // value "E"
                0x17, // key 23
                0x61, 0x42, // value :"B"
            ],
            vec![
                0xa2, // map with duplicate non-minimally encoded key
                0x18, 0x17, // key 23 encoded with extra byte
                0x61, 0x45, // value "E"
                0x18, 0x17, // key 23 encoded with extra byte
                0x61, 0x42, // value :"B"
            ],
        ];
        for encoding in encodings {
            assert_eq!(read(&encoding), Err(DecoderError::NonMinimalCborEncoding));
        }
    }

    #[test]
    fn test_read_negative() {
        let cases = vec![
            (-1, vec![0x20]),
            (-24, vec![0x37]),
            (-25, vec![0x38, 0x18]),
            (-256, vec![0x38, 0xFF]),
            (-1000, vec![0x39, 0x03, 0xE7]),
            (-1000000, vec![0x3A, 0x00, 0x0F, 0x42, 0x3F]),
            (-4294967296, vec![0x3A, 0xFF, 0xFF, 0xFF, 0xFF]),
            (
                std::i64::MIN,
                vec![0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            ),
        ];
        for (negative, mut cbor) in cases {
            assert_eq!(read(&cbor), Ok(cbor_int!(negative)));
            cbor.push(0x01);
            assert_eq!(read(&cbor), Err(DecoderError::ExtranousData));
        }
    }

    #[test]
    fn test_read_byte_string() {
        let cases = vec![
            (Vec::new(), vec![0x40]),
            (
                vec![0x01, 0x02, 0x03, 0x04],
                vec![0x44, 0x01, 0x02, 0x03, 0x04],
            ),
        ];
        for (byte_string, mut cbor) in cases {
            assert_eq!(read(&cbor), Ok(cbor_bytes!(byte_string)));
            cbor.push(0x01);
            assert_eq!(read(&cbor), Err(DecoderError::ExtranousData));
        }
    }

    #[test]
    fn test_read_text_string() {
        let unicode_3byte = vec![0xE6, 0xB0, 0xB4];
        let cases = vec![
            ("", vec![0x60]),
            ("a", vec![0x61, 0x61]),
            ("IETF", vec![0x64, 0x49, 0x45, 0x54, 0x46]),
            ("\"\\", vec![0x62, 0x22, 0x5C]),
            ("ü", vec![0x62, 0xC3, 0xBC]),
            (
                std::str::from_utf8(&unicode_3byte).unwrap(),
                vec![0x63, 0xE6, 0xB0, 0xB4],
            ),
            ("𐅑", vec![0x64, 0xF0, 0x90, 0x85, 0x91]),
        ];
        for (text_string, mut cbor) in cases {
            assert_eq!(read(&cbor), Ok(cbor_text!(text_string)));
            cbor.push(0x01);
            assert_eq!(read(&cbor), Err(DecoderError::ExtranousData));
        }
    }

    #[test]
    fn test_read_text_string_with_nul() {
        let cases = vec![
            (
                "string_without_nul",
                vec![
                    0x72, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x5F, 0x77, 0x69, 0x74, 0x68, 0x6F,
                    0x75, 0x74, 0x5F, 0x6E, 0x75, 0x6C,
                ],
            ),
            (
                "nul_terminated_string\0",
                vec![
                    0x76, 0x6E, 0x75, 0x6C, 0x5F, 0x74, 0x65, 0x72, 0x6D, 0x69, 0x6E, 0x61, 0x74,
                    0x65, 0x64, 0x5F, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x00,
                ],
            ),
            (
                "embedded\0nul",
                vec![
                    0x6C, 0x65, 0x6D, 0x62, 0x65, 0x64, 0x64, 0x65, 0x64, 0x00, 0x6E, 0x75, 0x6C,
                ],
            ),
            (
                "trailing_nuls\0\0",
                vec![
                    0x6F, 0x74, 0x72, 0x61, 0x69, 0x6C, 0x69, 0x6E, 0x67, 0x5F, 0x6E, 0x75, 0x6C,
                    0x73, 0x00, 0x00,
                ],
            ),
        ];
        for (text_string, mut cbor) in cases {
            assert_eq!(read(&cbor), Ok(cbor_text!(text_string)));
            cbor.push(0x01);
            assert_eq!(read(&cbor), Err(DecoderError::ExtranousData));
        }
    }

    #[test]
    fn test_read_text_string_with_invalid_byte_sequence_after_nul() {
        assert_eq!(
            read(&vec![0x63, 0x00, 0x00, 0xA6]),
            Err(DecoderError::InvalidUtf8)
        );
    }

    #[test]
    fn test_read_array() {
        let value_vec: Vec<_> = (1..26).collect();
        let mut test_cbor = vec![
            0x98, 0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x18, 0x18,
            0x19,
        ];
        assert_eq!(read(&test_cbor.clone()), Ok(cbor_array_vec!(value_vec)));
        test_cbor.push(0x01);
        assert_eq!(read(&test_cbor), Err(DecoderError::ExtranousData));
    }

    #[test]
    fn test_read_map() {
        let value_map = cbor_map! {
            24 => "abc",
            "" => ".",
            "b" => "B",
            "aa" => "AA",
        };
        let mut test_cbor = vec![
            0xa4, // map with 4 key value pairs:
            0x18, 0x18, // 24
            0x63, 0x61, 0x62, 0x63, // "abc"
            0x60, // ""
            0x61, 0x2e, // "."
            0x61, 0x62, // "b"
            0x61, 0x42, // "B"
            0x62, 0x61, 0x61, // "aa"
            0x62, 0x41, 0x41, // "AA"
        ];
        assert_eq!(read(&test_cbor), Ok(value_map));
        test_cbor.push(0x01);
        assert_eq!(read(&test_cbor), Err(DecoderError::ExtranousData));
    }

    #[test]
    fn test_read_map_with_unsigned_keys() {
        let value_map = cbor_map! {
            1 => "a",
            9 => "b",
            999 => "c",
            1111 => "d",
        };
        let mut test_cbor = vec![
            0xa4, // map with 4 key value pairs:
            0x01, // key : 1
            0x61, 0x61, // value : "a"
            0x09, // key : 9
            0x61, 0x62, // value : "b"
            0x19, 0x03, 0xE7, // key : 999
            0x61, 0x63, // value "c"
            0x19, 0x04, 0x57, // key : 1111
            0x61, 0x64, // value : "d"
        ];
        assert_eq!(read(&test_cbor), Ok(value_map));
        test_cbor.push(0x01);
        assert_eq!(read(&test_cbor), Err(DecoderError::ExtranousData));
    }

    #[test]
    fn test_read_map_with_negative_keys() {
        let value_map = cbor_map! {
            -1 => 1,
            -2 => 2,
            -100 => 3,
        };
        let mut test_cbor = vec![
            0xA3, // map with 3 key value pairs
            0x20, // key : -1
            0x01, // value : 1
            0x21, // key : -2
            0x02, // value : 2
            0x38, 0x63, // key : -100
            0x03, // value : 3
        ];
        assert_eq!(read(&test_cbor), Ok(value_map));
        test_cbor.push(0x01);
        assert_eq!(read(&test_cbor), Err(DecoderError::ExtranousData));
    }

    #[test]
    fn test_read_map_with_array() {
        let value_map = cbor_map! {
            "a" => 1,
            "b" => cbor_array![2, 3],
        };
        let mut test_cbor = vec![
            0xa2, // map of 2 pairs
            0x61, 0x61, // "a"
            0x01, 0x61, 0x62, // "b"
            0x82, // array with 2 elements
            0x02, 0x03,
        ];
        assert_eq!(read(&test_cbor), Ok(value_map));
        test_cbor.push(0x01);
        assert_eq!(read(&test_cbor), Err(DecoderError::ExtranousData));
    }

    #[test]
    fn test_read_map_with_text_string_keys() {
        let value_map = cbor_map! {
            "k" => "v",
            "foo" => "bar",
        };
        let mut test_cbor = vec![
            0xa2, // map of 2 pairs
            0x61, b'k', // text string "k"
            0x61, b'v', 0x63, b'f', b'o', b'o', // text string "foo"
            0x63, b'b', b'a', b'r',
        ];
        assert_eq!(read(&test_cbor), Ok(value_map));
        test_cbor.push(0x01);
        assert_eq!(read(&test_cbor), Err(DecoderError::ExtranousData));
    }

    #[test]
    fn test_read_map_with_byte_string_keys() {
        let value_map = cbor_map! {
            b"k" => b"v",
            b"foo" => b"bar",
        };
        let mut test_cbor = vec![
            0xa2, // map of 2 pairs
            0x41, b'k', // text string "k"
            0x41, b'v', 0x43, b'f', b'o', b'o', // text string "foo"
            0x43, b'b', b'a', b'r',
        ];
        assert_eq!(read(&test_cbor), Ok(value_map));
        test_cbor.push(0x01);
        assert_eq!(read(&test_cbor), Err(DecoderError::ExtranousData));
    }

    #[test]
    fn test_read_nested_map() {
        let value_map = cbor_map! {
            "a" => 1,
            "b" => cbor_map! {
                "c" => 2,
                "d" => 3,
            },
        };
        let mut test_cbor = vec![
            0xa2, // map of 2 pairs
            0x61, 0x61, 0x01, // "a"
            0x61, 0x62, // "b"
            0xa2, // map of 2 pairs
            0x61, 0x63, 0x02, // "c"
            0x61, 0x64, 0x03, // "d"
        ];
        assert_eq!(read(&test_cbor), Ok(value_map));
        test_cbor.push(0x01);
        assert_eq!(read(&test_cbor), Err(DecoderError::ExtranousData));
    }

    #[test]
    fn test_read_integer_out_of_range() {
        let cases = vec![
            // The positive case is impossible since we support u64.
            // vec![0x1B, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x3B, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];
        for cbor in cases {
            assert_eq!(read(&cbor), Err(DecoderError::OutOfRangeIntegerValue));
        }
    }

    #[test]
    fn test_read_simple_value() {
        let cases = vec![
            (cbor_false!(), vec![0xF4]),
            (cbor_true!(), vec![0xF5]),
            (cbor_null!(), vec![0xF6]),
            (cbor_undefined!(), vec![0xF7]),
        ];
        for (simple, mut cbor) in cases {
            assert_eq!(read(&cbor.clone()), Ok(simple));
            cbor.push(0x01);
            assert_eq!(read(&cbor), Err(DecoderError::ExtranousData));
        }
    }

    #[test]
    fn test_read_unsupported_floating_point_numbers() {
        let cases = vec![
            vec![0xF9, 0x10, 0x00],
            vec![0xFA, 0x10, 0x00, 0x00, 0x00],
            vec![0xFB, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];
        for cbor in cases {
            assert_eq!(
                read(&cbor),
                Err(DecoderError::UnsupportedFloatingPointValue)
            );
        }
    }

    #[test]
    fn test_read_incomplete_cbor_data_error() {
        let cases = vec![
            vec![0x19, 0x03],
            vec![0x44, 0x01, 0x02, 0x03],
            vec![0x65, 0x49, 0x45, 0x54, 0x46],
            vec![0x82, 0x02],
            vec![0xA2, 0x61, 0x61, 0x01],
            vec![0x18],
            vec![0x99],
            vec![0xBA],
            vec![0x5B],
            vec![0x3B],
            vec![0x99, 0x01],
            vec![0xBA, 0x01, 0x02, 0x03],
            vec![0x3B, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        ];
        for cbor in cases {
            assert_eq!(read(&cbor), Err(DecoderError::IncompleteCborData));
        }
    }

    #[test]
    fn test_read_unsupported_map_key_format_error() {
        // While CBOR can handle all types as map keys, we only support a subset.
        let bad_map_cbor = vec![
            0xa2, // map of 2 pairs
            0x82, 0x01, 0x02, // invalid key : [1, 2]
            0x02, // value : 2
            0x61, 0x64, // key : "d"
            0x03, // value : 3
        ];
        assert_eq!(read(&bad_map_cbor), Err(DecoderError::IncorrectMapKeyType));
    }

    #[test]
    fn test_read_unknown_additional_info_error() {
        let cases = vec![
            vec![0x7C, 0x49, 0x45, 0x54, 0x46],
            vec![0x7D, 0x22, 0x5C],
            vec![0x7E, 0xC3, 0xBC],
            vec![0x7F, 0xE6, 0xB0, 0xB4],
            vec![0xFC],
            vec![0xFD],
            vec![0xFE],
            vec![0xFF],
        ];
        for cbor in cases {
            assert_eq!(read(&cbor), Err(DecoderError::UnknownAdditionalInfo));
        }
    }

    #[test]
    fn test_read_too_much_nesting_error() {
        let cases = vec![
            vec![0x18, 0x64],
            vec![0x44, 0x01, 0x02, 0x03, 0x04],
            vec![0x64, 0x49, 0x45, 0x54, 0x46],
            vec![0x80],
            vec![0xA0],
        ];
        for cbor in cases {
            let mut reader = Reader::new(&cbor);
            assert!(reader.decode_complete_data_item(0).is_ok());
        }
        let map_cbor = vec![
            0xa2, // map of 2 pairs
            0x61, 0x61, // "a"
            0x01, 0x61, 0x62, // "b"
            0x82, // array with 2 elements
            0x02, 0x03,
        ];
        let mut reader = Reader::new(&map_cbor);
        assert_eq!(
            reader.decode_complete_data_item(1),
            Err(DecoderError::TooMuchNesting)
        );
        reader = Reader::new(&map_cbor);
        assert!(reader.decode_complete_data_item(2).is_ok());
    }

    #[test]
    fn test_read_out_of_order_key_error() {
        let cases = vec![
            vec![
                0xa2, // map with 2 keys with same major type and length
                0x61, 0x62, // key "b"
                0x61, 0x42, // value "B"
                0x61, 0x61, // key "a" (out of order byte-wise lexically)
                0x61, 0x45, // value "E"
            ],
            vec![
                0xa2, // map with 2 keys with different major type
                0x61, 0x62, // key "b"
                0x02, // value 2
                // key 1000 (out of order since lower major type sorts first)
                0x19, 0x03, 0xe8, 0x61, 0x61, // value a
            ],
            vec![
                0xa2, // map with 2 keys with same major type
                0x19, 0x03, 0xe8, // key 1000  (out of order due to longer length)
                0x61, 0x61, //value "a"
                0x0a, // key 10
                0x61, 0x62, // value "b"
            ],
            vec![
                0xa2, // map with 2 text string keys
                0x62, b'a', b'a', // key text string "aa"
                // (out of order due to longer length)
                0x02, 0x61, b'b', // key "b"
                0x01,
            ],
            vec![
                0xa2, // map with 2 byte string keys
                0x42, b'x', b'x', // key byte string "xx"
                // (out of order due to longer length)
                0x02, 0x41, b'y', // key byte string "y"
                0x01,
            ],
        ];
        for cbor in cases {
            assert_eq!(read(&cbor), Err(DecoderError::OutOfOrderKey));
        }
    }

    #[test]
    fn test_read_duplicate_key_error() {
        let map_with_duplicate_key = vec![
            0xa6, // map of 6 pairs:
            0x60, // ""
            0x61, 0x2e, // "."
            0x61, 0x62, // "b"
            0x61, 0x42, // "B"
            0x61, 0x62, // "b" (Duplicate key)
            0x61, 0x43, // "C"
            0x61, 0x64, // "d"
            0x61, 0x44, // "D"
            0x61, 0x65, // "e"
            0x61, 0x44, // "D"
            0x62, 0x61, 0x61, // "aa"
            0x62, 0x41, 0x41, // "AA"
        ];
        assert_eq!(
            read(&map_with_duplicate_key),
            Err(DecoderError::OutOfOrderKey)
        );
    }

    #[test]
    fn test_read_incorrect_string_encoding_error() {
        let cases = vec![
            vec![0x63, 0xED, 0x9F, 0xBF],
            vec![0x63, 0xEE, 0x80, 0x80],
            vec![0x63, 0xEF, 0xBF, 0xBD],
        ];
        for cbor in cases {
            assert!(read(&cbor).is_ok());
        }
        let impossible_utf_byte = vec![0x64, 0xFE, 0xFE, 0xFF, 0xFF];
        assert_eq!(read(&impossible_utf_byte), Err(DecoderError::InvalidUtf8));
    }

    #[test]
    fn test_read_extranous_cbor_data_error() {
        let cases = vec![
            vec![0x19, 0x03, 0x05, 0x00],
            vec![0x44, 0x01, 0x02, 0x03, 0x04, 0x00],
            vec![0x64, 0x49, 0x45, 0x54, 0x46, 0x00],
            vec![0x82, 0x01, 0x02, 0x00],
            vec![0xa1, 0x61, 0x63, 0x02, 0x61, 0x64, 0x03],
        ];
        for cbor in cases {
            assert_eq!(read(&cbor), Err(DecoderError::ExtranousData));
        }
    }

    #[test]
    fn test_read_unsupported_simple_type() {
        let cases = vec![
            vec![0xE0],
            vec![0xF3],
            vec![0xF8, 0x18],
            vec![0xF8, 0x1C],
            vec![0xF8, 0x1D],
            vec![0xF8, 0x1E],
            vec![0xF8, 0x1F],
            vec![0xF8, 0x20],
            vec![0xF8, 0xFF],
        ];
        for cbor in cases {
            assert_eq!(read(&cbor), Err(DecoderError::UnsupportedSimpleValue));
        }
    }

    #[test]
    fn test_read_super_long_content_dont_crash() {
        let cases = vec![
            vec![0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            vec![0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        ];
        for cbor in cases {
            assert_eq!(read(&cbor), Err(DecoderError::IncompleteCborData));
        }
    }

    #[test]
    fn test_read_unsupported_major_type() {
        let cases = vec![
            vec![0xC0],
            vec![0xD8, 0xFF],
            // multi-dimensional array example using tags
            vec![
                0x82, 0x82, 0x02, 0x03, 0xd8, 0x41, 0x4a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,
                0x03, 0x00, 0x04, 0x00, 0x05,
            ],
        ];
        for cbor in cases {
            assert_eq!(read(&cbor), Err(DecoderError::UnsupportedMajorType));
        }
    }
}
