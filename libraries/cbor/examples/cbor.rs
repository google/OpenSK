// Copyright 2021 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

//! Example program demonstrating cbor usage.

extern crate alloc;

use sk_cbor::values::Value;
use sk_cbor::{cbor_array, cbor_bytes, cbor_map, cbor_null, cbor_true};

fn hexify(data: &[u8]) -> String {
    let mut s = String::new();
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn main() {
    // Build a CBOR object with various different types included. Note that this
    // object is not built in canonical order.
    let manual_object = Value::map(vec![
        (
            Value::from(1),
            Value::array(vec![Value::from(2), Value::from(3)]),
        ),
        (Value::from("tstr".to_owned()), Value::from(vec![1, 2, 3])),
        (Value::from(-2), Value::null_value()),
        (Value::from(3), Value::bool_value(true)),
    ]);

    // Build the same object using the crate's convenience macros.
    let macro_object = cbor_map! {
        1 => cbor_array![2, 3],
        "tstr" => cbor_bytes!(vec![1, 2, 3]),
        -2 => cbor_null!(),
        3 => cbor_true!(),
    };

    assert_eq!(manual_object, macro_object);
    println!("Object {:?}", manual_object);

    // Serialize to bytes.
    let mut manual_data = vec![];
    sk_cbor::writer::write(manual_object, &mut manual_data).unwrap();
    let hex_manual_data = hexify(&manual_data);
    let mut macro_data = vec![];
    sk_cbor::writer::write(macro_object, &mut macro_data).unwrap();
    let hex_macro_data = hexify(&macro_data);

    assert_eq!(hex_manual_data, hex_macro_data);

    // Serialized version is in canonical order.
    println!("Serializes to {}", hex_manual_data);
    assert_eq!(
        hex_manual_data,
        concat!(
            "a4",         // 4-map
            "01",         // int(1) =>
            "820203",     // 2-array [2, 3],
            "03",         // int(3) =>
            "f5",         // true,
            "21",         // nint(-2) =>
            "f6",         // null,
            "6474737472", // 4-tstr "tstr" =>
            "43010203"    // 3-bstr
        )
    );

    // Convert back to an object.  This is different than the original object,
    // because the map is now in canonical order.
    let recovered_object = sk_cbor::reader::read(&manual_data).unwrap();
    println!("Deserializes to {:?}", recovered_object);
}
