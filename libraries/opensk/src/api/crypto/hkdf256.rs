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

use super::HASH_SIZE;

/// HKDF using SHA256.
pub trait Hkdf256 {
    /// Computes the HKDF with 256 bit (one block) output.
    ///
    /// # Arguments
    ///
    /// * `ikm` - Input keying material
    /// * `salt` - Byte string that acts as a key
    /// * `info` - Optional context and application specific information
    ///
    /// This implementation is equivalent to a standard HKD, with `salt` fixed at a length of
    /// 32 byte and the output length l as 32.
    fn hkdf_256(ikm: &[u8], salt: &[u8; HASH_SIZE], info: &[u8], okm: &mut [u8; HASH_SIZE]);

    /// Computes the HKDF with empty salt and 256 bit (one block) output.
    ///
    /// # Arguments
    ///
    /// * `ikm` - Input keying material
    /// * `info` - Optional context and application specific information
    ///
    /// This implementation is equivalent to a standard HKDF, with `salt` set to the
    /// default block of zeros and the output length l as 32.
    fn hkdf_empty_salt_256(ikm: &[u8], info: &[u8], okm: &mut [u8; HASH_SIZE]) {
        Self::hkdf_256(ikm, &[0; HASH_SIZE], info, okm)
    }
}
