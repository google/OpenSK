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

use opensk::api::crypto::hmac256::Hmac256;
use opensk::api::crypto::{HASH_SIZE, HMAC_KEY_SIZE, TRUNCATED_HMAC_SIZE};
use wasefire::crypto::hash::hmac_sha256;

use crate::env::WasefireEnv;

impl Hmac256 for WasefireEnv {
    fn mac(key: &[u8; HMAC_KEY_SIZE], data: &[u8], output: &mut [u8; HASH_SIZE]) {
        *output = hmac_sha256(key, data).unwrap();
    }

    fn verify(key: &[u8; HMAC_KEY_SIZE], data: &[u8], mac: &[u8; HASH_SIZE]) -> bool {
        *mac == hmac_sha256(key, data).unwrap()
    }

    fn verify_truncated_left(
        key: &[u8; HMAC_KEY_SIZE],
        data: &[u8],
        mac: &[u8; TRUNCATED_HMAC_SIZE],
    ) -> bool {
        *mac == hmac_sha256(key, data).unwrap()[..TRUNCATED_HMAC_SIZE]
    }
}
