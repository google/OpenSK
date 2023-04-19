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

/// Hashes data using SHA256.
///
/// When you implement this trait, make sure to implement `digest_mut` first, because the default
/// implementations of `digest` relies on it.
pub trait Sha256: Sized {
    /// Computes the hash of a given message as an array.
    ///
    /// This function does not let you control the memory allocation. It should therefore not be
    /// used for secrets that need zeroization.
    fn digest(data: &[u8]) -> [u8; HASH_SIZE] {
        let mut output = [0; HASH_SIZE];
        Self::digest_mut(data, &mut output);
        output
    }

    /// Computes the hash of a given message directly.
    fn digest_mut(data: &[u8], output: &mut [u8; HASH_SIZE]) {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize(output)
    }

    /// Create a new object that can be incrementally updated for digesting.
    fn new() -> Self;

    /// Digest the next part of the message to hash.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hashing process, returns the hash value.
    fn finalize(self, output: &mut [u8; HASH_SIZE]);
}
