// Copyright 2023 Google LLC
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

use super::{HASH_SIZE, HMAC_KEY_SIZE, TRUNCATED_HMAC_SIZE};

/// For a given hash function, computes and verifies the HMAC.
pub trait Hmac256 {
    /// Computes the HMAC.
    fn mac(key: &[u8; HMAC_KEY_SIZE], data: &[u8]) -> [u8; HASH_SIZE];

    /// Verifies the HMAC.
    ///
    /// When implementing, make sure that you don't leak side channel information about the key,
    /// i.e. by using constant time comparisons of the computed and given MAC.
    fn verify(key: &[u8; HMAC_KEY_SIZE], data: &[u8], mac: &[u8; HASH_SIZE]) -> bool;

    /// Verifies the first bytes of an HMAC.
    ///
    /// When implementing, make sure that you don't leak side channel information about the key,
    /// i.e. by using constant time comparisons of the computed and given truncated MAC.
    fn verify_truncated_left(
        key: &[u8; HMAC_KEY_SIZE],
        data: &[u8],
        mac: &[u8; TRUNCATED_HMAC_SIZE],
    ) -> bool;
}
