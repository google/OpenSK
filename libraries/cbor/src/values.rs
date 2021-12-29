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

//! Types for expressing CBOR values.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;

/// Possible CBOR values.
#[derive(Clone, Debug)]
pub enum Value {
    /// Unsigned integer value (uint).
    Unsigned(u64),
    /// Signed integer value (nint). Only 63 bits of information are used here.
    Negative(i64),
    /// Byte string (bstr).
    ByteString(Vec<u8>),
    /// Text string (tstr).
    TextString(String),
    /// Array/tuple of values.
    Array(Vec<Value>),
    /// Map of key-value pairs.
    Map(Vec<(Value, Value)>),
    /// Tagged value.
    Tag(u64, Box<Value>),
    /// Simple value.
    Simple(SimpleValue),
}

/// Specific simple CBOR values.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SimpleValue {
    FalseValue = 20,
    TrueValue = 21,
    NullValue = 22,
    Undefined = 23,
}

/// Constant values required for CBOR encoding.
pub struct Constants {}

impl Constants {
    /// Number of bits used to shift left the major type of a CBOR type byte.
    pub const MAJOR_TYPE_BIT_SHIFT: u8 = 5;
    /// Mask to retrieve the additional information held in a CBOR type bytes,
    /// ignoring the major type.
    pub const ADDITIONAL_INFORMATION_MASK: u8 = 0x1F;
    /// Additional information value that indicates the largest inline value.
    pub const ADDITIONAL_INFORMATION_MAX_INT: u8 = 23;
    /// Additional information value indicating that a 1-byte length follows.
    pub const ADDITIONAL_INFORMATION_1_BYTE: u8 = 24;
    /// Additional information value indicating that a 2-byte length follows.
    pub const ADDITIONAL_INFORMATION_2_BYTES: u8 = 25;
    /// Additional information value indicating that a 4-byte length follows.
    pub const ADDITIONAL_INFORMATION_4_BYTES: u8 = 26;
    /// Additional information value indicating that an 8-byte length follows.
    pub const ADDITIONAL_INFORMATION_8_BYTES: u8 = 27;
}

impl Value {
    /// Create an appropriate CBOR integer value (uint/nint).
    /// For simplicity, this only takes i64. Construct directly for the last bit.
    pub fn integer(int: i64) -> Value {
        if int >= 0 {
            Value::Unsigned(int as u64)
        } else {
            Value::Negative(int)
        }
    }

    /// Create a CBOR boolean simple value.
    pub fn bool_value(b: bool) -> Value {
        if b {
            Value::Simple(SimpleValue::TrueValue)
        } else {
            Value::Simple(SimpleValue::FalseValue)
        }
    }

    /// Return the major type for the [`Value`].
    pub fn type_label(&self) -> u8 {
        // TODO use enum discriminant instead when stable
        // https://github.com/rust-lang/rust/issues/60553
        match self {
            Value::Unsigned(_) => 0,
            Value::Negative(_) => 1,
            Value::ByteString(_) => 2,
            Value::TextString(_) => 3,
            Value::Array(_) => 4,
            Value::Map(_) => 5,
            Value::Tag(_, _) => 6,
            Value::Simple(_) => 7,
        }
    }

    pub fn extract_unsigned(self) -> Option<u64> {
        match self {
            Value::Unsigned(unsigned) => Some(unsigned),
            _ => None,
        }
    }

    pub fn extract_integer(self) -> Option<i64> {
        match self {
            Value::Unsigned(unsigned) => {
                if unsigned <= core::i64::MAX as u64 {
                    Some(unsigned as i64)
                } else {
                    None
                }
            }
            Value::Negative(signed) => Some(signed),
            _ => None,
        }
    }

    pub fn extract_byte_string(self) -> Option<Vec<u8>> {
        match self {
            Value::ByteString(byte_string) => Some(byte_string),
            _ => None,
        }
    }

    pub fn extract_text_string(self) -> Option<String> {
        match self {
            Value::TextString(text_string) => Some(text_string),
            _ => None,
        }
    }

    pub fn extract_array(self) -> Option<Vec<Value>> {
        match self {
            Value::Array(array) => Some(array),
            _ => None,
        }
    }

    pub fn extract_map(self) -> Option<Vec<(Value, Value)>> {
        match self {
            Value::Map(map) => Some(map),
            _ => None,
        }
    }

    pub fn extract_tag(self) -> Option<(u64, Value)> {
        match self {
            Value::Tag(tag, value) => Some((tag, *value)),
            _ => None,
        }
    }

    pub fn extract_bool(self) -> Option<bool> {
        match self {
            Value::Simple(SimpleValue::FalseValue) => Some(false),
            Value::Simple(SimpleValue::TrueValue) => Some(true),
            _ => None,
        }
    }

    pub fn extract_null(self) -> Option<()> {
        match self {
            Value::Simple(SimpleValue::NullValue) => Some(()),
            _ => None,
        }
    }

    pub fn extract_undefined(self) -> Option<()> {
        match self {
            Value::Simple(SimpleValue::Undefined) => Some(()),
            _ => None,
        }
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Value) -> Ordering {
        use super::values::Value::{
            Array, ByteString, Map, Negative, Simple, Tag, TextString, Unsigned,
        };
        let self_type_value = self.type_label();
        let other_type_value = other.type_label();
        if self_type_value != other_type_value {
            return self_type_value.cmp(&other_type_value);
        }
        match (self, other) {
            (Unsigned(u1), Unsigned(u2)) => u1.cmp(u2),
            (Negative(n1), Negative(n2)) => n1.cmp(n2).reverse(),
            (ByteString(b1), ByteString(b2)) => b1.len().cmp(&b2.len()).then(b1.cmp(b2)),
            (TextString(t1), TextString(t2)) => t1.len().cmp(&t2.len()).then(t1.cmp(t2)),
            (Array(a1), Array(a2)) if a1.len() != a2.len() => a1.len().cmp(&a2.len()),
            (Array(a1), Array(a2)) => {
                // Arrays of same length.
                let mut ordering = Ordering::Equal;
                for (e1, e2) in a1.iter().zip(a2.iter()) {
                    ordering = e1.cmp(e2);
                    if !matches!(ordering, Ordering::Equal) {
                        break;
                    }
                }
                ordering
            }
            (Map(m1), Map(m2)) if m1.len() != m2.len() => m1.len().cmp(&m2.len()),
            (Map(m1), Map(m2)) => {
                // Maps of same length.
                let mut ordering = Ordering::Equal;
                for ((k1, v1), (k2, v2)) in m1.iter().zip(m2.iter()) {
                    ordering = k1.cmp(k2).then_with(|| v1.cmp(v2));
                    if !matches!(ordering, Ordering::Equal) {
                        break;
                    }
                }
                ordering
            }
            (Tag(t1, v1), Tag(t2, v2)) => t1.cmp(t2).then(v1.cmp(v2)),
            (Simple(s1), Simple(s2)) => s1.cmp(s2),
            (_, _) => {
                // The case of different major types is caught above.
                unreachable!();
            }
        }
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Value) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for Value {}

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl SimpleValue {
    /// Create a simple value from its encoded value.
    pub fn from_integer(int: u64) -> Option<SimpleValue> {
        match int {
            20 => Some(SimpleValue::FalseValue),
            21 => Some(SimpleValue::TrueValue),
            22 => Some(SimpleValue::NullValue),
            23 => Some(SimpleValue::Undefined),
            _ => None,
        }
    }
}

impl From<u64> for Value {
    fn from(unsigned: u64) -> Self {
        Value::Unsigned(unsigned)
    }
}

impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::integer(i)
    }
}

impl From<i32> for Value {
    fn from(i: i32) -> Self {
        Value::integer(i as i64)
    }
}

impl From<Vec<u8>> for Value {
    fn from(bytes: Vec<u8>) -> Self {
        Value::ByteString(bytes)
    }
}

impl From<&[u8]> for Value {
    fn from(bytes: &[u8]) -> Self {
        Value::ByteString(bytes.to_vec())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Self {
        Value::TextString(text)
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Value::TextString(text.to_string())
    }
}

impl From<Vec<Value>> for Value {
    fn from(array: Vec<Value>) -> Self {
        Value::Array(array)
    }
}

impl From<Vec<(Value, Value)>> for Value {
    fn from(map: Vec<(Value, Value)>) -> Self {
        Value::Map(map)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::bool_value(b)
    }
}

/// Trait that indicates that a type can be converted to a CBOR [`Value`].
pub trait IntoCborValue {
    /// Convert `self` into a CBOR [`Value`], consuming it along the way.
    fn into_cbor_value(self) -> Value;
}

impl<T> IntoCborValue for T
where
    Value: From<T>,
{
    fn into_cbor_value(self) -> Value {
        Value::from(self)
    }
}

/// Trait that indicates that a type can be converted to a CBOR [`Option<Value>`].
pub trait IntoCborValueOption {
    /// Convert `self` into a CBOR [`Option<Value>`], consuming it along the way.
    fn into_cbor_value_option(self) -> Option<Value>;
}

impl<T> IntoCborValueOption for T
where
    Value: From<T>,
{
    fn into_cbor_value_option(self) -> Option<Value> {
        Some(Value::from(self))
    }
}

impl<T> IntoCborValueOption for Option<T>
where
    Value: From<T>,
{
    fn into_cbor_value_option(self) -> Option<Value> {
        self.map(Value::from)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        cbor_array, cbor_bool, cbor_bytes, cbor_bytes_lit, cbor_int, cbor_map, cbor_null,
        cbor_tagged, cbor_text, cbor_undefined, cbor_unsigned,
    };
    use alloc::vec;

    #[test]
    fn test_extract_unsigned() {
        assert_eq!(cbor_int!(1).extract_unsigned(), Some(1));
        assert_eq!(cbor_int!(-1).extract_unsigned(), None);
        assert_eq!(cbor_bytes!(vec![]).extract_unsigned(), None);
        assert_eq!(cbor_text!("").extract_unsigned(), None);
        assert_eq!(cbor_array![].extract_unsigned(), None);
        assert_eq!(cbor_map! {}.extract_unsigned(), None);
        assert_eq!(cbor_tagged!(1, cbor_text!("s")).extract_unsigned(), None);
        assert_eq!(cbor_bool!(false).extract_unsigned(), None);
    }

    #[test]
    fn test_extract_unsigned_limits() {
        assert_eq!(
            cbor_unsigned!(core::u64::MAX).extract_unsigned(),
            Some(core::u64::MAX)
        );
        assert_eq!(
            cbor_unsigned!((core::i64::MAX as u64) + 1).extract_unsigned(),
            Some((core::i64::MAX as u64) + 1)
        );
        assert_eq!(
            cbor_int!(core::i64::MAX).extract_unsigned(),
            Some(core::i64::MAX as u64)
        );
        assert_eq!(cbor_int!(123).extract_unsigned(), Some(123));
        assert_eq!(cbor_int!(0).extract_unsigned(), Some(0));
        assert_eq!(cbor_int!(-123).extract_unsigned(), None);
        assert_eq!(cbor_int!(core::i64::MIN).extract_unsigned(), None);
    }

    #[test]
    fn test_extract_integer() {
        assert_eq!(cbor_int!(1).extract_integer(), Some(1));
        assert_eq!(cbor_int!(-1).extract_integer(), Some(-1));
        assert_eq!(cbor_bytes!(vec![]).extract_integer(), None);
        assert_eq!(cbor_text!("").extract_integer(), None);
        assert_eq!(cbor_array![].extract_integer(), None);
        assert_eq!(cbor_map! {}.extract_integer(), None);
        assert_eq!(cbor_tagged!(1, cbor_text!("s")).extract_integer(), None);
        assert_eq!(cbor_bool!(false).extract_integer(), None);
    }

    #[test]
    fn test_extract_integer_limits() {
        assert_eq!(cbor_unsigned!(core::u64::MAX).extract_integer(), None);
        assert_eq!(
            cbor_unsigned!((core::i64::MAX as u64) + 1).extract_integer(),
            None
        );
        assert_eq!(
            cbor_int!(core::i64::MAX).extract_integer(),
            Some(core::i64::MAX)
        );
        assert_eq!(cbor_int!(123).extract_integer(), Some(123));
        assert_eq!(cbor_int!(0).extract_integer(), Some(0));
        assert_eq!(cbor_int!(-123).extract_integer(), Some(-123));
        assert_eq!(
            cbor_int!(core::i64::MIN).extract_integer(),
            Some(core::i64::MIN)
        );
    }

    #[test]
    fn test_extract_byte_string() {
        assert_eq!(cbor_int!(1).extract_byte_string(), None);
        assert_eq!(cbor_int!(-1).extract_byte_string(), None);
        assert_eq!(cbor_bytes!(vec![]).extract_byte_string(), Some(Vec::new()));
        assert_eq!(
            cbor_bytes_lit!(b"bar").extract_byte_string(),
            Some(b"bar".to_vec())
        );
        assert_eq!(cbor_text!("").extract_byte_string(), None);
        assert_eq!(cbor_array![].extract_byte_string(), None);
        assert_eq!(cbor_map! {}.extract_byte_string(), None);
        assert_eq!(cbor_tagged!(1, cbor_text!("s")).extract_byte_string(), None);
        assert_eq!(cbor_bool!(false).extract_byte_string(), None);
    }

    #[test]
    fn test_extract_text_string() {
        assert_eq!(cbor_int!(1).extract_text_string(), None);
        assert_eq!(cbor_int!(-1).extract_text_string(), None);
        assert_eq!(cbor_bytes!(vec![]).extract_text_string(), None);
        assert_eq!(cbor_text!("").extract_text_string(), Some(String::new()));
        assert_eq!(cbor_text!("s").extract_text_string(), Some("s".to_string()));
        assert_eq!(cbor_array![].extract_text_string(), None);
        assert_eq!(cbor_map! {}.extract_text_string(), None);
        assert_eq!(cbor_tagged!(1, cbor_text!("s")).extract_text_string(), None);
        assert_eq!(cbor_bool!(false).extract_text_string(), None);
    }

    #[test]
    fn test_extract_array() {
        assert_eq!(cbor_int!(1).extract_array(), None);
        assert_eq!(cbor_int!(-1).extract_array(), None);
        assert_eq!(cbor_bytes!(vec![]).extract_array(), None);
        assert_eq!(cbor_text!("").extract_array(), None);
        assert_eq!(cbor_array![].extract_array(), Some(Vec::new()));
        assert_eq!(
            cbor_array![cbor_int!(1)].extract_array(),
            Some(vec![cbor_int!(1)])
        );
        assert_eq!(cbor_map! {}.extract_array(), None);
        assert_eq!(cbor_tagged!(1, cbor_text!("s")).extract_array(), None);
        assert_eq!(cbor_bool!(false).extract_array(), None);
    }

    #[test]
    fn test_extract_map() {
        assert_eq!(cbor_int!(1).extract_map(), None);
        assert_eq!(cbor_int!(-1).extract_map(), None);
        assert_eq!(cbor_bytes!(vec![]).extract_map(), None);
        assert_eq!(cbor_text!("").extract_map(), None);
        assert_eq!(cbor_array![].extract_map(), None);
        assert_eq!(cbor_map! {}.extract_map(), Some(Vec::new()));
        assert_eq!(
            cbor_map! {0 => 1}.extract_map(),
            Some(vec![(cbor_int!(0), cbor_int!(1))])
        );
        assert_eq!(cbor_tagged!(1, cbor_text!("s")).extract_map(), None);
        assert_eq!(cbor_bool!(false).extract_map(), None);
    }

    #[test]
    fn test_extract_tag() {
        assert_eq!(cbor_int!(1).extract_tag(), None);
        assert_eq!(cbor_int!(-1).extract_tag(), None);
        assert_eq!(cbor_bytes!(vec![]).extract_tag(), None);
        assert_eq!(cbor_text!("").extract_tag(), None);
        assert_eq!(cbor_array![].extract_tag(), None);
        assert_eq!(cbor_map! {}.extract_tag(), None);
        assert_eq!(
            cbor_tagged!(1, cbor_text!("s")).extract_tag(),
            Some((1, cbor_text!("s")))
        );
        assert_eq!(cbor_bool!(false).extract_tag(), None);
    }

    #[test]
    fn test_extract_bool() {
        assert_eq!(cbor_int!(1).extract_bool(), None);
        assert_eq!(cbor_int!(-1).extract_bool(), None);
        assert_eq!(cbor_bytes!(vec![]).extract_bool(), None);
        assert_eq!(cbor_text!("").extract_bool(), None);
        assert_eq!(cbor_array![].extract_bool(), None);
        assert_eq!(cbor_map! {}.extract_bool(), None);
        assert_eq!(cbor_tagged!(1, cbor_text!("s")).extract_bool(), None);
        assert_eq!(cbor_bool!(false).extract_bool(), Some(false));
        assert_eq!(cbor_bool!(true).extract_bool(), Some(true));
        assert_eq!(cbor_null!().extract_bool(), None);
        assert_eq!(cbor_undefined!().extract_bool(), None);
    }

    #[test]
    fn test_extract_null() {
        assert_eq!(cbor_int!(1).extract_null(), None);
        assert_eq!(cbor_int!(-1).extract_null(), None);
        assert_eq!(cbor_bytes!(vec![]).extract_null(), None);
        assert_eq!(cbor_text!("").extract_null(), None);
        assert_eq!(cbor_array![].extract_null(), None);
        assert_eq!(cbor_map! {}.extract_null(), None);
        assert_eq!(cbor_tagged!(1, cbor_text!("s")).extract_null(), None);
        assert_eq!(cbor_bool!(false).extract_null(), None);
        assert_eq!(cbor_bool!(true).extract_null(), None);
        assert_eq!(cbor_null!().extract_null(), Some(()));
        assert_eq!(cbor_undefined!().extract_null(), None);
    }

    #[test]
    fn test_extract_undefined() {
        assert_eq!(cbor_int!(1).extract_undefined(), None);
        assert_eq!(cbor_int!(-1).extract_undefined(), None);
        assert_eq!(cbor_bytes!(vec![]).extract_undefined(), None);
        assert_eq!(cbor_text!("").extract_undefined(), None);
        assert_eq!(cbor_array![].extract_undefined(), None);
        assert_eq!(cbor_map! {}.extract_undefined(), None);
        assert_eq!(cbor_tagged!(1, cbor_text!("s")).extract_undefined(), None);
        assert_eq!(cbor_bool!(false).extract_undefined(), None);
        assert_eq!(cbor_bool!(true).extract_undefined(), None);
        assert_eq!(cbor_null!().extract_undefined(), None);
        assert_eq!(cbor_undefined!().extract_undefined(), Some(()));
    }

    #[test]
    fn test_value_ordering() {
        assert!(cbor_int!(0) < cbor_int!(23));
        assert!(cbor_int!(23) < cbor_int!(24));
        assert!(cbor_int!(24) < cbor_int!(1000));
        assert!(cbor_int!(1000) < cbor_int!(1000000));
        assert!(cbor_int!(1000000) < cbor_int!(core::i64::MAX));
        assert!(cbor_int!(core::i64::MAX) < cbor_int!(-1));
        assert!(cbor_int!(-1) < cbor_int!(-23));
        assert!(cbor_int!(-23) < cbor_int!(-24));
        assert!(cbor_int!(-24) < cbor_int!(-1000));
        assert!(cbor_int!(-1000) < cbor_int!(-1000000));
        assert!(cbor_int!(-1000000) < cbor_int!(core::i64::MIN));
        assert!(cbor_int!(core::i64::MIN) < cbor_bytes!(vec![]));
        assert!(cbor_bytes!(vec![]) < cbor_bytes!(vec![0x00]));
        assert!(cbor_bytes!(vec![0x00]) < cbor_bytes!(vec![0x01]));
        assert!(cbor_bytes!(vec![0x01]) < cbor_bytes!(vec![0xFF]));
        assert!(cbor_bytes!(vec![0xFF]) < cbor_bytes!(vec![0x00, 0x00]));
        assert!(cbor_bytes!(vec![0x00, 0x00]) < cbor_text!(""));
        assert!(cbor_text!("") < cbor_text!("a"));
        assert!(cbor_text!("a") < cbor_text!("b"));
        assert!(cbor_text!("b") < cbor_text!("aa"));
        assert!(cbor_text!("aa") < cbor_array![]);
        assert!(cbor_array![] < cbor_array![0]);
        assert!(cbor_array![0] < cbor_array![-1]);
        assert!(cbor_array![1] < cbor_array![b""]);
        assert!(cbor_array![b""] < cbor_array![""]);
        assert!(cbor_array![""] < cbor_array![cbor_array![]]);
        assert!(cbor_array![cbor_array![]] < cbor_array![cbor_map! {}]);
        assert!(cbor_array![cbor_map! {}] < cbor_array![false]);
        assert!(cbor_array![false] < cbor_array![0, 0]);
        assert!(cbor_array![0, 0] < cbor_map! {});
        assert!(cbor_map! {} < cbor_map! {0 => 0});
        assert!(cbor_map! {0 => 0} < cbor_map! {0 => 1});
        assert!(cbor_map! {0 => 1} < cbor_map! {1 => 0});
        assert!(cbor_map! {1 => 0} < cbor_map! {-1 => 0});
        assert!(cbor_map! {-1 => 0} < cbor_map! {b"" => 0});
        assert!(cbor_map! {b"" => 0} < cbor_map! {"" => 0});
        assert!(cbor_map! {"" => 0} < cbor_map! {cbor_array![] => 0});
        assert!(cbor_map! {cbor_array![] => 0} < cbor_map! {cbor_map!{} => 0});
        assert!(cbor_map! {cbor_map!{} => 0} < cbor_map! {false => 0});
        assert!(cbor_map! {false => 0} < cbor_map! {0 => 0, 0 => 0});
        assert!(cbor_map! {0 => 0} < cbor_tagged!(2, cbor_int!(0)));
        assert!(cbor_map! {0 => 0, 0 => 0} < cbor_bool!(false));
        assert!(cbor_bool!(false) < cbor_bool!(true));
        assert!(cbor_bool!(true) < Value::Simple(SimpleValue::NullValue));
        assert!(Value::Simple(SimpleValue::NullValue) < Value::Simple(SimpleValue::Undefined));
        assert!(cbor_tagged!(1, cbor_text!("s")) < cbor_tagged!(2, cbor_int!(0)));
        assert!(cbor_int!(1) < cbor_int!(-1));
        assert!(cbor_int!(1) < cbor_bytes!(vec![0x00]));
        assert!(cbor_int!(1) < cbor_text!("s"));
        assert!(cbor_int!(1) < cbor_array![]);
        assert!(cbor_int!(1) < cbor_map! {});
        assert!(cbor_int!(1) < cbor_tagged!(1, cbor_text!("s")));
        assert!(cbor_int!(1) < cbor_bool!(false));
        assert!(cbor_int!(-1) < cbor_bytes!(vec![0x00]));
        assert!(cbor_int!(-1) < cbor_text!("s"));
        assert!(cbor_int!(-1) < cbor_array![]);
        assert!(cbor_int!(-1) < cbor_map! {});
        assert!(cbor_int!(-1) < cbor_tagged!(1, cbor_text!("s")));
        assert!(cbor_int!(-1) < cbor_bool!(false));
        assert!(cbor_bytes!(vec![0x00]) < cbor_text!("s"));
        assert!(cbor_bytes!(vec![0x00]) < cbor_array![]);
        assert!(cbor_bytes!(vec![0x00]) < cbor_map! {});
        assert!(cbor_bytes!(vec![0x00]) < cbor_tagged!(1, cbor_text!("s")));
        assert!(cbor_bytes!(vec![0x00]) < cbor_bool!(false));
        assert!(cbor_text!("s") < cbor_array![]);
        assert!(cbor_text!("s") < cbor_map! {});
        assert!(cbor_text!("s") < cbor_tagged!(1, cbor_text!("s")));
        assert!(cbor_text!("s") < cbor_bool!(false));
        assert!(cbor_array![] < cbor_map!(0 => 1));
        assert!(cbor_array![] < cbor_tagged!(2, cbor_int!(0)));
        assert!(cbor_array![] < cbor_bool!(false));
        assert!(cbor_tagged!(1, cbor_text!("s")) < cbor_bool!(false));
    }
}
