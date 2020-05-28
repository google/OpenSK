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

use super::values::{Constants, KeyType, Value};
use alloc::vec::Vec;

pub fn write(value: Value, encoded_cbor: &mut Vec<u8>) -> bool {
    let mut writer = Writer::new(encoded_cbor);
    writer.encode_cbor(value, Writer::MAX_NESTING_DEPTH)
}

struct Writer<'a> {
    encoded_cbor: &'a mut Vec<u8>,
}

impl<'a> Writer<'a> {
    const MAX_NESTING_DEPTH: i8 = 4;

    pub fn new(encoded_cbor: &mut Vec<u8>) -> Writer {
        Writer { encoded_cbor }
    }

    fn encode_cbor(&mut self, value: Value, remaining_depth: i8) -> bool {
        if remaining_depth < 0 {
            return false;
        }
        match value {
            Value::KeyValue(KeyType::Unsigned(unsigned)) => self.start_item(0, unsigned),
            Value::KeyValue(KeyType::Negative(negative)) => {
                self.start_item(1, -(negative + 1) as u64)
            }
            Value::KeyValue(KeyType::ByteString(byte_string)) => {
                self.start_item(2, byte_string.len() as u64);
                self.encoded_cbor.extend(byte_string);
            }
            Value::KeyValue(KeyType::TextString(text_string)) => {
                self.start_item(3, text_string.len() as u64);
                self.encoded_cbor.extend(text_string.into_bytes());
            }
            Value::Array(array) => {
                self.start_item(4, array.len() as u64);
                for el in array {
                    if !self.encode_cbor(el, remaining_depth - 1) {
                        return false;
                    }
                }
            }
            Value::Map(map) => {
                self.start_item(5, map.len() as u64);
                for (k, v) in map {
                    if !self.encode_cbor(Value::KeyValue(k), remaining_depth - 1) {
                        return false;
                    }
                    if !self.encode_cbor(v, remaining_depth - 1) {
                        return false;
                    }
                }
            }
            Value::Simple(simple_value) => self.start_item(7, simple_value as u64),
        }
        true
    }

    fn start_item(&mut self, type_label: u8, size: u64) {
        let (mut first_byte, shift) = match size {
            0..=23 => (size as u8, 0),
            24..=0xFF => (Constants::ADDITIONAL_INFORMATION_1_BYTE, 1),
            0x100..=0xFFFF => (Constants::ADDITIONAL_INFORMATION_2_BYTES, 2),
            0x10000..=0xFFFF_FFFF => (Constants::ADDITIONAL_INFORMATION_4_BYTES, 4),
            _ => (Constants::ADDITIONAL_INFORMATION_8_BYTES, 8),
        };
        first_byte |= type_label << Constants::MAJOR_TYPE_BIT_SHIFT;
        self.encoded_cbor.push(first_byte);

        for i in (0..shift).rev() {
            self.encoded_cbor.push((size >> (i * 8)) as u8);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn write_return(value: Value) -> Option<Vec<u8>> {
        let mut encoded_cbor = Vec::new();
        if write(value, &mut encoded_cbor) {
            Some(encoded_cbor)
        } else {
            None
        }
    }

    #[test]
    fn test_write_unsigned() {
        let cases = vec![
            (0, vec![0x00]),
            (1, vec![0x01]),
            (10, vec![0x0A]),
            (23, vec![0x17]),
            (24, vec![0x18, 0x18]),
            (25, vec![0x18, 0x19]),
            (100, vec![0x18, 0x64]),
            (1000, vec![0x19, 0x03, 0xE8]),
            (1000000, vec![0x1A, 0x00, 0x0F, 0x42, 0x40]),
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
        for (unsigned, correct_cbor) in cases {
            assert_eq!(write_return(cbor_int!(unsigned)), Some(correct_cbor));
        }
    }

    #[test]
    fn test_write_negative() {
        let cases = vec![
            (-1, vec![0x20]),
            (-10, vec![0x29]),
            (-23, vec![0x36]),
            (-24, vec![0x37]),
            (-25, vec![0x38, 0x18]),
            (-100, vec![0x38, 0x63]),
            (-1000, vec![0x39, 0x03, 0xE7]),
            (-4294967296, vec![0x3A, 0xFF, 0xFF, 0xFF, 0xFF]),
            (
                -4294967297,
                vec![0x3B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
            (
                std::i64::MIN,
                vec![0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            ),
        ];
        for (negative, correct_cbor) in cases {
            assert_eq!(write_return(cbor_int!(negative)), Some(correct_cbor));
        }
    }

    #[test]
    fn test_write_byte_string() {
        let cases = vec![
            (vec![], vec![0x40]),
            (
                vec![0x01, 0x02, 0x03, 0x04],
                vec![0x44, 0x01, 0x02, 0x03, 0x04],
            ),
        ];
        for (byte_string, correct_cbor) in cases {
            assert_eq!(write_return(cbor_bytes!(byte_string)), Some(correct_cbor));
        }
    }

    #[test]
    fn test_write_text_string() {
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
        for (text_string, correct_cbor) in cases {
            assert_eq!(write_return(cbor_text!(text_string)), Some(correct_cbor));
        }
    }

    #[test]
    fn test_write_array() {
        let value_vec: Vec<_> = (1..26).collect();
        let expected_cbor = vec![
            0x98, 0x19, // array of 25 elements
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19,
        ];
        assert_eq!(
            write_return(cbor_array_vec!(value_vec)),
            Some(expected_cbor)
        );
    }

    #[test]
    fn test_write_map() {
        let value_map = cbor_map! {
            "aa" => "AA",
            "e" => "E",
            "" => ".",
            -1 => "k",
            -24 => "l",
            -25 => "m",
            -256 => "n",
            -257 => "o",
            -65537 => "p",
            -4294967296_i64 => "q",
            -4294967297_i64 => "r",
            std::i64::MIN => "s",
            b"a" => 2,
            b"bar" => 3,
            b"foo" => 4,
            0 => "a",
            23 => "b",
            24 => "c",
            std::u8::MAX as i64 => "d",
            256 => "e",
            std::u16::MAX as i64 => "f",
            65536 => "g",
            std::u32::MAX as i64 => "h",
            4294967296_i64 => "i",
            std::i64::MAX => "j",
        };
        let expected_cbor = vec![
            0xb8, 0x19, // map of 25 pairs:
            0x00, // key 0
            0x61, 0x61, // value "a"
            0x17, // key 23
            0x61, 0x62, // value "b"
            0x18, 0x18, // key 24
            0x61, 0x63, // value "c"
            0x18, 0xFF, // key 255
            0x61, 0x64, // value "d"
            0x19, 0x01, 0x00, // key 256
            0x61, 0x65, // value "e"
            0x19, 0xFF, 0xFF, // key 65535
            0x61, 0x66, // value "f"
            0x1A, 0x00, 0x01, 0x00, 0x00, // key 65536
            0x61, 0x67, // value "g"
            0x1A, 0xFF, 0xFF, 0xFF, 0xFF, // key 4294967295
            0x61, 0x68, // value "h"
            // key 4294967296
            0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x61, 0x69, //  value "i"
            // key INT64_MAX
            0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x61, 0x6a, //  value "j"
            0x20, // key -1
            0x61, 0x6b, // value "k"
            0x37, // key -24
            0x61, 0x6c, // value "l"
            0x38, 0x18, // key -25
            0x61, 0x6d, // value "m"
            0x38, 0xFF, // key -256
            0x61, 0x6e, // value "n"
            0x39, 0x01, 0x00, // key -257
            0x61, 0x6f, // value "o"
            0x3A, 0x00, 0x01, 0x00, 0x00, // key -65537
            0x61, 0x70, // value "p"
            0x3A, 0xFF, 0xFF, 0xFF, 0xFF, // key -4294967296
            0x61, 0x71, // value "q"
            // key -4294967297
            0x3B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x61, 0x72, //  value "r"
            // key INT64_MIN
            0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x61, 0x73, //  value "s"
            0x41, b'a', // byte string "a"
            0x02, 0x43, b'b', b'a', b'r', // byte string "bar"
            0x03, 0x43, b'f', b'o', b'o', // byte string "foo"
            0x04, 0x60, // key ""
            0x61, 0x2e, // value "."
            0x61, 0x65, // key "e"
            0x61, 0x45, // value "E"
            0x62, 0x61, 0x61, // key "aa"
            0x62, 0x41, 0x41, // value "AA"
        ];
        assert_eq!(write_return(value_map), Some(expected_cbor));
    }

    #[test]
    fn test_write_map_with_array() {
        let value_map = cbor_map! {
            "a" => 1,
            "b" => cbor_array![2, 3],
        };
        let expected_cbor = vec![
            0xa2, // map of 2 pairs
            0x61, 0x61, // "a"
            0x01, 0x61, 0x62, // "b"
            0x82, // array with 2 elements
            0x02, 0x03,
        ];
        assert_eq!(write_return(value_map), Some(expected_cbor));
    }

    #[test]
    fn test_write_nested_map() {
        let value_map = cbor_map! {
            "a" => 1,
            "b" => cbor_map! {
                "c" => 2,
                "d" => 3,
            },
        };
        let expected_cbor = vec![
            0xa2, // map of 2 pairs
            0x61, 0x61, // "a"
            0x01, 0x61, 0x62, // "b"
            0xa2, // map of 2 pairs
            0x61, 0x63, // "c"
            0x02, 0x61, 0x64, // "d"
            0x03,
        ];
        assert_eq!(write_return(value_map), Some(expected_cbor));
    }

    #[test]
    fn test_write_simple() {
        let cases = vec![
            (cbor_false!(), vec![0xF4]),
            (cbor_true!(), vec![0xF5]),
            (cbor_null!(), vec![0xF6]),
            (cbor_undefined!(), vec![0xF7]),
        ];
        for (value, correct_cbor) in cases {
            assert_eq!(write_return(value), Some(correct_cbor));
        }
    }

    #[test]
    fn test_write_single_levels() {
        let simple_array: Value = cbor_array![2];
        let simple_map: Value = cbor_map! {"b" => 3};
        let positive_cases = vec![
            (cbor_int!(1), 0),
            (cbor_bytes!(vec![0x01, 0x02, 0x03, 0x04]), 0),
            (cbor_text!("a"), 0),
            (cbor_array![], 0),
            (cbor_map! {}, 0),
            (simple_array.clone(), 1),
            (simple_map.clone(), 1),
        ];
        let negative_cases = vec![(simple_array.clone(), 0), (simple_map.clone(), 0)];
        for (value, level) in positive_cases {
            let mut buf = Vec::new();
            let mut writer = Writer::new(&mut buf);
            assert!(writer.encode_cbor(value, level));
        }
        for (value, level) in negative_cases {
            let mut buf = Vec::new();
            let mut writer = Writer::new(&mut buf);
            assert!(!writer.encode_cbor(value, level));
        }
    }

    #[test]
    fn test_write_nested_map_levels() {
        let cbor_map: Value = cbor_map! {
            "a" => 1,
            "b" => cbor_map! {
                "c" => 2,
                "d" => 3,
            },
        };

        let mut buf = Vec::new();
        let mut writer = Writer::new(&mut buf);
        assert!(writer.encode_cbor(cbor_map.clone(), 2));
        writer = Writer::new(&mut buf);
        assert!(!writer.encode_cbor(cbor_map, 1));
    }

    #[test]
    fn test_write_unbalanced_nested_containers() {
        let cbor_array: Value = cbor_array![
            1,
            2,
            3,
            cbor_map! {
                "a" => 1,
                "b" => cbor_map! {
                    "c" => 2,
                    "d" => 3,
                },
            },
        ];

        let mut buf = Vec::new();
        let mut writer = Writer::new(&mut buf);
        assert!(writer.encode_cbor(cbor_array.clone(), 3));
        writer = Writer::new(&mut buf);
        assert!(!writer.encode_cbor(cbor_array, 2));
    }

    #[test]
    fn test_write_overly_nested() {
        let cbor_map: Value = cbor_map! {
            "a" => 1,
            "b" => cbor_map! {
                "c" => 2,
                "d" => 3,
                "h" => cbor_map! {
                    "e" => 4,
                    "f" => 5,
                    "g" => cbor_array![
                        6,
                        7,
                        cbor_array![
                            8
                        ]
                    ],
                },
            },
        };

        let mut buf = Vec::new();
        let mut writer = Writer::new(&mut buf);
        assert!(writer.encode_cbor(cbor_map.clone(), 5));
        writer = Writer::new(&mut buf);
        assert!(!writer.encode_cbor(cbor_map, 4));
    }
}
