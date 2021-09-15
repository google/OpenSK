// Copyright 2019-2021 Google LLC
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

extern crate alloc;

use sk_cbor::cbor_map;
use std::env;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use uuid::Uuid;
use x509_parser::pem::Pem;

fn main() {
    println!("cargo:rerun-if-changed=crypto_data/aaguid.txt");
    println!("cargo:rerun-if-changed=crypto_data/opensk_upgrade_pub.pem");
    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rerun-if-changed=nrf52840_layout.ld");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let aaguid_bin_path = Path::new(&out_dir).join("opensk_aaguid.bin");

    let mut aaguid_bin_file = File::create(&aaguid_bin_path).unwrap();
    let mut aaguid_txt_file = File::open("crypto_data/aaguid.txt").unwrap();
    let mut content = String::new();
    aaguid_txt_file.read_to_string(&mut content).unwrap();
    content.truncate(36);
    let aaguid = Uuid::parse_str(&content).unwrap();
    aaguid_bin_file.write_all(aaguid.as_bytes()).unwrap();

    // COSE encoding the public key, then write it out.
    let file = File::open("crypto_data/opensk_upgrade_pub.pem").unwrap();
    let (pem, _bytes_read) = Pem::read(std::io::BufReader::new(file)).unwrap();
    // Check if the contents are uncompressed.
    assert_eq!(pem.contents[pem.contents.len() - 65], 0x04);
    let x_index = pem.contents.len() - 64;
    let y_index = pem.contents.len() - 32;
    let x_bytes = &pem.contents[x_index..][..32];
    let y_bytes = &pem.contents[y_index..][..32];
    const EC2_KEY_TYPE: i64 = 2;
    const P_256_CURVE: i64 = 1;
    const ES256_ALGORITHM: i64 = -7;
    let pub_key_cbor = sk_cbor::cbor_map! {
        1 => EC2_KEY_TYPE,
        3 => ES256_ALGORITHM,
        -1 => P_256_CURVE,
        -2 => x_bytes,
        -3 => y_bytes,
    };
    let mut cbor_bytes = vec![];
    sk_cbor::writer::write(pub_key_cbor, &mut cbor_bytes).unwrap();
    let upgrade_pubkey_path = Path::new(&out_dir).join("opensk_upgrade_pubkey_cbor.bin");
    let mut upgrade_pub_bin_file = File::create(&upgrade_pubkey_path).unwrap();
    upgrade_pub_bin_file.write_all(&cbor_bytes).unwrap();
}
