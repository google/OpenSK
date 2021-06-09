# CBOR Parsing Library

This crate implements Concise Binary Object Representation (CBOR) from [RFC
8949](https://datatracker.ietf.org/doc/html/rfc8949).

## Usage

```rust
fn main() {
    // Build a CBOR object with various different types included. Note that this
    // object is not built in canonical order.
    let manual_object = Value::Map(vec![
        (
            Value::Unsigned(1),
            Value::Array(vec![Value::Unsigned(2), Value::Unsigned(3)]),
        ),
        (
            Value::TextString("tstr".to_owned()),
            Value::ByteString(vec![1, 2, 3]),
        ),
        (Value::Negative(-2), Value::Simple(SimpleValue::NullValue)),
        (Value::Unsigned(3), Value::Simple(SimpleValue::TrueValue)),
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
    sk_cbor::writer::write(manual_object, &mut manual_data);
    let hex_manual_data = hexify(&manual_data);

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
```
