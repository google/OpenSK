# CBOR Parsing Library

[![crates.io](https://img.shields.io/crates/d/sk-cbor.svg)](https://crates.io/crates/sk-cbor)
[![crates.io](https://img.shields.io/crates/v/sk-cbor.svg)](https://crates.io/crates/sk-cbor)
[![docs.rs](https://docs.rs/sk-cbor/badge.svg)](https://docs.rs/sk-cbor)
[![License](https://img.shields.io/crates/l/sk-cbor.svg)](https://crates.io/crates/sk-cbor)
[![Maintenance](https://img.shields.io/maintenance/yes/2021)](https://crates.io/crates/sk-cbor)

This crate implements Concise Binary Object Representation (CBOR) from [RFC
8949](https://datatracker.ietf.org/doc/html/rfc8949).

## Usage

```rust
fn main() {
    // Build a CBOR object with the crate's convenience macros. Note that this
    // object is not built in canonical order.
    let map_object = cbor_map! {
        1 => cbor_array![2, 3],
        "tstr" => cbor_bytes!(vec![1, 2, 3]),
        -2 => cbor_null!(),
        3 => cbor_true!(),
    };

    println!("Object {:?}", map_object);

    // Serialize to bytes.
    let mut map_data = vec![];
    sk_cbor::writer::write(map_object, &mut map_data).unwrap();
    let hex_map_data = hex::encode(&map_data);

    // Serialized version is in canonical order.
    println!("Serializes to {}", hex_map_data);
    assert_eq!(
        hex_map_data,
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
    let recovered_object = sk_cbor::reader::read(&map_data).unwrap();
    println!("Deserializes to {:?}", recovered_object);
}
```
