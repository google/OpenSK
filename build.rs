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

use std::env;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

fn main() {
    println!("cargo:rerun-if-changed=crypto_data/aaguid.txt");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let aaguid_bin_path = Path::new(&out_dir).join("opensk_aaguid.bin");

    let mut aaguid_bin_file = File::create(&aaguid_bin_path).unwrap();
    let mut aaguid_txt_file = File::open("crypto_data/aaguid.txt").unwrap();
    let mut content = String::new();
    aaguid_txt_file.read_to_string(&mut content).unwrap();
    content.truncate(36);
    let aaguid = Uuid::parse_str(&content).unwrap();
    aaguid_bin_file.write_all(aaguid.as_bytes()).unwrap();
}
