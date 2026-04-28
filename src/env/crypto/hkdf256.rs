// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use opensk::api::crypto::HASH_SIZE;
use opensk::api::crypto::hkdf256::Hkdf256;
use wasefire::crypto::hash::Algorithm;

use crate::env::WasefireEnv;

impl Hkdf256 for WasefireEnv {
    fn hkdf_256(ikm: &[u8], salt: &[u8; HASH_SIZE], info: &[u8], okm: &mut [u8; HASH_SIZE]) {
        wasefire::crypto::hash::hkdf(Algorithm::Sha256, Some(salt), ikm, info, okm).unwrap();
    }
}
