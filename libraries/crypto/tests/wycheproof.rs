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

use crypto::ecdsa;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

mod asn1;

#[test]
fn wycheproof() {
    let wycheproof = load_tests("tests/data/ecdsa_secp256r1_sha256_test.json").unwrap();
    wycheproof.type_check();
    assert!(wycheproof.run_tests());
}

fn load_tests<P: AsRef<Path>>(path: P) -> Result<Wycheproof, Box<dyn Error>> {
    let file = File::open(path)?;
    let wycheproof = serde_json::from_reader(BufReader::new(file))?;
    Ok(wycheproof)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct Wycheproof {
    algorithm: String,
    #[allow(dead_code)]
    generatorVersion: String,
    #[allow(dead_code)]
    numberOfTests: u32,
    #[allow(dead_code)]
    header: Vec<String>,
    notes: HashMap<String, String>,
    schema: String,
    testGroups: Vec<TestGroup>,
}

impl Wycheproof {
    fn type_check(&self) {
        assert_eq!(self.algorithm, "ECDSA");
        assert_eq!(self.schema, "ecdsa_verify_schema.json");
        for group in &self.testGroups {
            group.type_check();
        }
    }

    fn run_tests(&self) -> bool {
        let mut result = true;
        for group in &self.testGroups {
            result &= group.run_tests(&self.notes);
        }
        result
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct TestGroup {
    key: Key,
    #[allow(dead_code)]
    keyDer: String,
    #[allow(dead_code)]
    keyPem: String,
    sha: String,
    r#type: String,
    tests: Vec<TestCase>,
}

impl TestGroup {
    fn type_check(&self) {
        self.key.type_check();
        assert_eq!(self.sha, "SHA-256");
        assert_eq!(self.r#type, "EcdsaVerify");
        for test in &self.tests {
            test.type_check();
        }
    }

    fn run_tests(&self, notes: &HashMap<String, String>) -> bool {
        let key = self.key.get_key();
        let mut result = true;
        for test in &self.tests {
            result &= test.run_test(&key, notes);
        }
        result
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct Key {
    curve: String,
    keySize: u32,
    r#type: String,
    uncompressed: String,
    #[allow(dead_code)]
    wx: String,
    #[allow(dead_code)]
    wy: String,
}

impl Key {
    fn type_check(&self) {
        assert_eq!(self.curve, "secp256r1");
        assert_eq!(self.keySize, 256);
        assert_eq!(self.r#type, "EcPublicKey");
        assert_eq!(self.uncompressed.len(), 130);
    }

    fn get_key(&self) -> Option<ecdsa::PubKey> {
        let bytes = hex::decode(&self.uncompressed).unwrap();
        ecdsa::PubKey::from_bytes_uncompressed(&bytes)
    }
}

#[derive(Deserialize, Debug)]
#[allow(non_camel_case_types)]
enum TestResult {
    valid,
    invalid,
    acceptable,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct TestCase {
    tcId: u32,
    comment: String,
    msg: String,
    sig: String,
    result: TestResult,
    flags: Vec<String>,
}

impl TestCase {
    fn type_check(&self) {
        // Nothing to do.
    }

    fn print(&self, notes: &HashMap<String, String>, error_msg: &str) {
        println!("Test case #{} => {}", self.tcId, error_msg);
        println!("    {}", self.comment);
        println!("    result = {:?}", self.result);
        for f in &self.flags {
            println!(
                "    flag {} = {}",
                f,
                notes.get(f).map_or("unknown flag", |x| &x)
            );
        }
    }

    fn run_test(&self, key: &Option<ecdsa::PubKey>, notes: &HashMap<String, String>) -> bool {
        match key {
            None => {
                let pass = match self.result {
                    TestResult::invalid | TestResult::acceptable => true,
                    TestResult::valid => false,
                };
                if !pass {
                    self.print(notes, "Invalid public key");
                }
                pass
            }
            Some(k) => {
                let msg = hex::decode(&self.msg).unwrap();
                let sig = hex::decode(&self.sig).unwrap();
                match asn1::parse_signature(sig.as_slice()) {
                    Err(e) => {
                        let pass = match self.result {
                            TestResult::invalid | TestResult::acceptable => true,
                            TestResult::valid => false,
                        };
                        if !pass {
                            self.print(notes, "Invalid ASN.1 encoding for the signature");
                            println!("    {:?}", e);
                        }
                        pass
                    }
                    Ok(signature) => {
                        let verified = k.verify_vartime::<crypto::sha256::Sha256>(&msg, &signature);
                        let pass = match self.result {
                            TestResult::acceptable => true,
                            TestResult::valid => verified,
                            TestResult::invalid => !verified,
                        };
                        if !pass {
                            self.print(
                                notes,
                                &format!(
                                    "Expected {:?} result, but the signature verification was {}",
                                    self.result, verified
                                ),
                            );
                        }
                        pass
                    }
                }
            }
        }
    }
}
