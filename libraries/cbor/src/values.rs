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

use super::writer::write;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;

#[derive(Clone, Debug)]
pub enum Value {
    Unsigned(u64),
    // We only use 63 bits of information here.
    Negative(i64),
    ByteString(Vec<u8>),
    TextString(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    // TAG is omitted
    Simple(SimpleValue),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
    // For simplicity, this only takes i64. Construct directly for the last bit.
    pub fn integer(int: i64) -> Value {
        if int >= 0 {
            Value::Unsigned(int as u64)
        } else {
            Value::Negative(int)
        }
    }

    pub fn bool_value(b: bool) -> Value {
        if b {
            Value::Simple(SimpleValue::TrueValue)
        } else {
            Value::Simple(SimpleValue::FalseValue)
        }
    }

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
            Value::Simple(_) => 7,
        }
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Value) -> Ordering {
        use super::values::Value::{
            Array, ByteString, Map, Negative, Simple, TextString, Unsigned,
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
            (Map(m1), Map(m2)) if m1.len() != m2.len() => m1.len().cmp(&m2.len()),
            (Simple(s1), Simple(s2)) => s1.cmp(s2),
            (v1, v2) => {
                // This case could handle all of the above as well. Checking individually is faster.
                let mut encoding1 = Vec::new();
                write(v1.clone(), &mut encoding1);
                let mut encoding2 = Vec::new();
                write(v2.clone(), &mut encoding2);
                encoding1.cmp(&encoding2)
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
    use super::*;
    use crate::{cbor_array, cbor_bool, cbor_bytes, cbor_int, cbor_map, cbor_text};

    #[test]
    fn test_value_ordering() {
        assert!(cbor_int!(0) < cbor_int!(23));
        assert!(cbor_int!(23) < cbor_int!(24));
        assert!(cbor_int!(24) < cbor_int!(1000));
        assert!(cbor_int!(1000) < cbor_int!(1000000));
        assert!(cbor_int!(1000000) < cbor_int!(std::i64::MAX));
        assert!(cbor_int!(std::i64::MAX) < cbor_int!(-1));
        assert!(cbor_int!(-1) < cbor_int!(-23));
        assert!(cbor_int!(-23) < cbor_int!(-24));
        assert!(cbor_int!(-24) < cbor_int!(-1000));
        assert!(cbor_int!(-1000) < cbor_int!(-1000000));
        assert!(cbor_int!(-1000000) < cbor_int!(std::i64::MIN));
        assert!(cbor_int!(std::i64::MIN) < cbor_bytes!(vec![]));
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
        assert!(cbor_map! {0 => 0, 0 => 0} < cbor_bool!(false));
        assert!(cbor_bool!(false) < cbor_bool!(true));
        assert!(cbor_bool!(true) < Value::Simple(SimpleValue::NullValue));
        assert!(Value::Simple(SimpleValue::NullValue) < Value::Simple(SimpleValue::Undefined));
        assert!(cbor_int!(1) < cbor_bytes!(vec![0x00]));
        assert!(cbor_int!(1) < cbor_text!("s"));
        assert!(cbor_int!(1) < cbor_array![]);
        assert!(cbor_int!(1) < cbor_map! {});
        assert!(cbor_int!(1) < cbor_bool!(false));
        assert!(cbor_int!(-1) < cbor_text!("s"));
        assert!(cbor_int!(-1) < cbor_array![]);
        assert!(cbor_int!(-1) < cbor_map! {});
        assert!(cbor_int!(-1) < cbor_bool!(false));
        assert!(cbor_bytes!(vec![0x00]) < cbor_array![]);
        assert!(cbor_bytes!(vec![0x00]) < cbor_map! {});
        assert!(cbor_bytes!(vec![0x00]) < cbor_bool!(false));
        assert!(cbor_text!("s") < cbor_map! {});
        assert!(cbor_text!("s") < cbor_bool!(false));
        assert!(cbor_array![] < cbor_bool!(false));
    }
}
