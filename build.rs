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

extern crate openssl;

use openssl::asn1;
use openssl::ec;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=crypto_data/opensk.key");
    println!("cargo:rerun-if-changed=crypto_data/opensk_cert.pem");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let priv_key_bin_path = Path::new(&out_dir).join("opensk_pkey.bin");
    let cert_bin_path = Path::new(&out_dir).join("opensk_cert.bin");
    let aaguid_bin_path = Path::new(&out_dir).join("opensk_aaguid.bin");

    // Load the OpenSSL PEM ECC key
    let ecc_data = include_bytes!("crypto_data/opensk.key");
    let pkey = ec::EcKey::private_key_from_pem(ecc_data)
        .ok()
        .expect("Failed to load OpenSK private key file");

    // Check key validity
    pkey.check_key().unwrap();
    assert_eq!(pkey.group().curve_name(), Some(Nid::X9_62_PRIME256V1));

    let mut priv_key = pkey.private_key().to_vec();
    if priv_key.len() == 33 && priv_key[0] == 0 {
        priv_key.remove(0);
    }
    assert_eq!(priv_key.len(), 32);

    // Create the raw private key out of the OpenSSL data
    let mut priv_key_bin_file = File::create(&priv_key_bin_path).unwrap();
    priv_key_bin_file.write_all(&priv_key).unwrap();

    // Convert the PEM certificate to DER and extract the serial for AAGUID
    let input_pem_cert = include_bytes!("crypto_data/opensk_cert.pem");
    let cert = x509::X509::from_pem(input_pem_cert)
        .ok()
        .expect("Failed to load OpenSK certificate");

    // Do some sanity check on the certificate
    assert!(cert
        .public_key()
        .unwrap()
        .public_eq(&PKey::from_ec_key(pkey).unwrap()));
    let today = asn1::Asn1Time::days_from_now(0).unwrap();
    assert!(cert.not_after() > today);
    assert!(cert.not_before() <= today);

    let mut cert_bin_file = File::create(&cert_bin_path).unwrap();
    cert_bin_file.write_all(&cert.to_der().unwrap()).unwrap();

    let mut aaguid_bin_file = File::create(&aaguid_bin_path).unwrap();
    let mut serial = cert.serial_number().to_bn().unwrap().to_vec();
    serial.resize(16, 0);
    aaguid_bin_file.write_all(&serial).unwrap();
}
