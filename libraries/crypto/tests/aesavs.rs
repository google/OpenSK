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

/// Test vectors for AES-ECB from NIST's validation suite.
///
/// See also https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
#[macro_use]
extern crate arrayref;
extern crate hex;
extern crate regex;

use crypto::{aes256, Decrypt16BytesBlock, Encrypt16BytesBlock};
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[test]
fn aesavs() {
    // These data files are taken from https://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip.
    test_aesavs_file("tests/data/ECBVarKey256.rsp");
    test_aesavs_file("tests/data/ECBVarTxt256.rsp");
}

fn test_aesavs_file<P: AsRef<Path>>(path: P) {
    // Implements some custom parsing for NIST's test vectors.
    let re_count = Regex::new("^COUNT = ([0-9]+)$").unwrap();
    let re_key = Regex::new("^KEY = ([0-9a-f]{64})$").unwrap();
    let re_plaintext = Regex::new("^PLAINTEXT = ([0-9a-f]{32})$").unwrap();
    let re_ciphertext = Regex::new("^CIPHERTEXT = ([0-9a-f]{32})$").unwrap();

    let file = BufReader::new(File::open(path).unwrap());
    let mut lines = file.lines();

    loop {
        let line = lines.next().unwrap().unwrap();
        if line == "[ENCRYPT]" {
            break;
        }
    }

    for i in 0.. {
        // empty line
        let line = lines.next().unwrap().unwrap();
        assert_eq!(line, "");

        let line = lines.next().unwrap().unwrap();
        if line == "[DECRYPT]" {
            // Skip the decryption tests, they are the same as the encryption tests.
            break;
        }
        // "COUNT = "
        let captures = re_count.captures(&line).unwrap();
        let count = captures.get(1).unwrap().as_str().parse::<usize>().unwrap();
        assert_eq!(count, i);

        // "KEY = "
        let line = lines.next().unwrap().unwrap();
        let captures = re_key.captures(&line).unwrap();
        let key = hex::decode(captures.get(1).unwrap().as_str()).unwrap();
        assert_eq!(key.len(), 32);

        // "PLAINTEXT = "
        let line = lines.next().unwrap().unwrap();
        let captures = re_plaintext.captures(&line).unwrap();
        let plaintext = hex::decode(captures.get(1).unwrap().as_str()).unwrap();
        assert_eq!(plaintext.len(), 16);

        // "CIPHERTEXT = "
        let line = lines.next().unwrap().unwrap();
        let captures = re_ciphertext.captures(&line).unwrap();
        let ciphertext = hex::decode(captures.get(1).unwrap().as_str()).unwrap();
        assert_eq!(ciphertext.len(), 16);

        {
            let encryption_key = aes256::EncryptionKey::new(array_ref![key, 0, 32]);
            let mut block: [u8; 16] = [Default::default(); 16];
            block.copy_from_slice(&plaintext);
            encryption_key.encrypt_block(&mut block);
            assert_eq!(&block, ciphertext.as_slice());
        }

        {
            let encryption_key = aes256::EncryptionKey::new(array_ref![key, 0, 32]);
            let decryption_key = aes256::DecryptionKey::new(&encryption_key);
            let mut block: [u8; 16] = [Default::default(); 16];
            block.copy_from_slice(&ciphertext);
            decryption_key.decrypt_block(&mut block);
            assert_eq!(&block, plaintext.as_slice());
        }
    }
}
