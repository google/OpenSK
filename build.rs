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

use openssl::{bn, ec, nid};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::{env, fs};
use uuid::Uuid;

fn main() {
    const UPGRADE_FILE: &str = "crypto_data/opensk_upgrade_pub.pem";
    println!("cargo:rerun-if-changed=crypto_data/aaguid.txt");
    println!("cargo:rerun-if-changed={UPGRADE_FILE}");
    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rerun-if-changed=nrf52840_layout.ld");
    println!("cargo:rerun-if-changed=nrf52840_layout_a.ld");
    println!("cargo:rerun-if-changed=nrf52840_layout_b.ld");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let aaguid_bin_path = Path::new(&out_dir).join("opensk_aaguid.bin");

    let mut aaguid_bin_file = File::create(aaguid_bin_path).unwrap();
    let mut aaguid_txt_file = File::open("crypto_data/aaguid.txt").unwrap();
    let mut content = String::new();
    aaguid_txt_file.read_to_string(&mut content).unwrap();
    content.truncate(36);
    let aaguid = Uuid::parse_str(&content).unwrap();
    aaguid_bin_file.write_all(aaguid.as_bytes()).unwrap();

    // COSE encoding the public key, then write it out.
    let pem_bytes = fs::read(UPGRADE_FILE).unwrap();
    let ec_key = ec::EcKey::public_key_from_pem(&pem_bytes).ok().unwrap();
    let group = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1).unwrap();
    let conversion_form = ec::PointConversionForm::UNCOMPRESSED;
    let mut ctx = bn::BigNumContext::new().unwrap();
    let raw_bytes = ec_key
        .public_key()
        .to_bytes(&group, conversion_form, &mut ctx)
        .unwrap();
    let upgrade_pubkey_path = Path::new(&out_dir).join("opensk_upgrade_pubkey.bin");
    let mut upgrade_pub_bin_file = File::create(upgrade_pubkey_path).unwrap();
    upgrade_pub_bin_file.write_all(&raw_bytes).unwrap();
}
