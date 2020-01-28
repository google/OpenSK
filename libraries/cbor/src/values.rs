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

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    KeyValue(KeyType),
    Array(Vec<Value>),
    Map(BTreeMap<KeyType, Value>),
    // TAG is omitted
    Simple(SimpleValue),
}

// The specification recommends to limit the available keys.
// Currently supported are both integer and string types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyType {
    Unsigned(u64),
    // We only use 63 bits of information here.
    Negative(i64),
    ByteString(Vec<u8>),
    TextString(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum SimpleValue {
    FalseValue = 20,
    TrueValue = 21,
    NullValue = 22,
    Undefined = 23,
}

pub struct Constants {}

impl Constants {
    pub const MAJOR_TYPE_BIT_SHIFT: u8 = 5;
    pub const ADDITIONAL_INFORMATION_MASK: u8 = 0x1F;
    pub const ADDITIONAL_INFORMATION_MAX_INT: u8 = 23;
    pub const ADDITIONAL_INFORMATION_1_BYTE: u8 = 24;
    pub const ADDITIONAL_INFORMATION_2_BYTES: u8 = 25;
    pub const ADDITIONAL_INFORMATION_4_BYTES: u8 = 26;
    pub const ADDITIONAL_INFORMATION_8_BYTES: u8 = 27;
}

impl Value {
    pub fn bool_value(b: bool) -> Value {
        if b {
            Value::Simple(SimpleValue::TrueValue)
        } else {
            Value::Simple(SimpleValue::FalseValue)
        }
    }

    pub fn type_label(&self) -> u8 {
        match self {
            Value::KeyValue(key) => key.type_label(),
            Value::Array(_) => 4,
            Value::Map(_) => 5,
            Value::Simple(_) => 7,
        }
    }
}

impl KeyType {
    // For simplicity, this only takes i64. Construct directly for the last bit.
    pub fn integer(int: i64) -> KeyType {
        if int >= 0 {
            KeyType::Unsigned(int as u64)
        } else {
            KeyType::Negative(int)
        }
    }

    pub fn type_label(&self) -> u8 {
        match self {
            KeyType::Unsigned(_) => 0,
            KeyType::Negative(_) => 1,
            KeyType::ByteString(_) => 2,
            KeyType::TextString(_) => 3,
        }
    }
}

impl Ord for KeyType {
    fn cmp(&self, other: &KeyType) -> Ordering {
        use super::values::KeyType::{ByteString, Negative, TextString, Unsigned};
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
            _ => unreachable!(),
        }
    }
}

impl PartialOrd for KeyType {
    fn partial_cmp(&self, other: &KeyType) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl SimpleValue {
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

impl From<u64> for KeyType {
    fn from(unsigned: u64) -> Self {
        KeyType::Unsigned(unsigned)
    }
}

impl From<i64> for KeyType {
    fn from(i: i64) -> Self {
        KeyType::integer(i)
    }
}

impl From<i32> for KeyType {
    fn from(i: i32) -> Self {
        KeyType::integer(i as i64)
    }
}

impl From<Vec<u8>> for KeyType {
    fn from(bytes: Vec<u8>) -> Self {
        KeyType::ByteString(bytes)
    }
}

impl From<&[u8]> for KeyType {
    fn from(bytes: &[u8]) -> Self {
        KeyType::ByteString(bytes.to_vec())
    }
}

impl From<String> for KeyType {
    fn from(text: String) -> Self {
        KeyType::TextString(text)
    }
}

impl From<&str> for KeyType {
    fn from(text: &str) -> Self {
        KeyType::TextString(text.to_string())
    }
}

impl<T> From<T> for Value
where
    KeyType: From<T>,
{
    fn from(t: T) -> Self {
        Value::KeyValue(KeyType::from(t))
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::bool_value(b)
    }
}

pub trait IntoCborKey {
    fn into_cbor_key(self) -> KeyType;
}

impl<T> IntoCborKey for T
where
    KeyType: From<T>,
{
    fn into_cbor_key(self) -> KeyType {
        KeyType::from(self)
    }
}

pub trait IntoCborValue {
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

pub trait IntoCborValueOption {
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
    #[test]
    fn test_key_type_ordering() {
        assert!(cbor_key_int!(0) < cbor_key_int!(23));
        assert!(cbor_key_int!(23) < cbor_key_int!(24));
        assert!(cbor_key_int!(24) < cbor_key_int!(1000));
        assert!(cbor_key_int!(1000) < cbor_key_int!(1000000));
        assert!(cbor_key_int!(1000000) < cbor_key_int!(std::i64::MAX));
        assert!(cbor_key_int!(std::i64::MAX) < cbor_key_int!(-1));
        assert!(cbor_key_int!(-1) < cbor_key_int!(-23));
        assert!(cbor_key_int!(-23) < cbor_key_int!(-24));
        assert!(cbor_key_int!(-24) < cbor_key_int!(-1000));
        assert!(cbor_key_int!(-1000) < cbor_key_int!(-1000000));
        assert!(cbor_key_int!(-1000000) < cbor_key_int!(std::i64::MIN));
        assert!(cbor_key_int!(std::i64::MIN) < cbor_key_bytes!(vec![]));
        assert!(cbor_key_bytes!(vec![]) < cbor_key_bytes!(vec![0x00]));
        assert!(cbor_key_bytes!(vec![0x00]) < cbor_key_bytes!(vec![0x01]));
        assert!(cbor_key_bytes!(vec![0x01]) < cbor_key_bytes!(vec![0xFF]));
        assert!(cbor_key_bytes!(vec![0xFF]) < cbor_key_bytes!(vec![0x00, 0x00]));
        assert!(cbor_key_bytes!(vec![0x00, 0x00]) < cbor_key_text!(""));
        assert!(cbor_key_text!("") < cbor_key_text!("a"));
        assert!(cbor_key_text!("a") < cbor_key_text!("b"));
        assert!(cbor_key_text!("b") < cbor_key_text!("aa"));
        assert!(cbor_key_int!(1) < cbor_key_bytes!(vec![0x00]));
        assert!(cbor_key_int!(1) < cbor_key_text!("s"));
        assert!(cbor_key_int!(-1) < cbor_key_text!("s"));
    }
}
