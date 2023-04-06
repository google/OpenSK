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

use super::{AES_BLOCK_SIZE, AES_KEY_SIZE};

/// Encrypts and decrypts data using AES256.
pub trait Aes256 {
    /// Creates a new key from its bytes.
    fn new(key: &[u8; AES_KEY_SIZE]) -> Self;

    /// Encrypts a block in place.
    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]);

    /// Decrypts a block in place.
    fn decrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]);

    /// Encrypts a message in place using CBC mode.
    ///
    /// # Panics
    ///
    /// Panics if the plaintext is not a multiple of the block size.
    fn encrypt_cbc(&self, iv: &[u8; AES_BLOCK_SIZE], plaintext: &mut [u8]);

    /// Decrypts a message in place using CBC mode.
    ///
    /// # Panics
    ///
    /// Panics if the ciphertext is not a multiple of the block size.
    fn decrypt_cbc(&self, iv: &[u8; AES_BLOCK_SIZE], ciphertext: &mut [u8]);
}
