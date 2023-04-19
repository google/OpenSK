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

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(wrapping_int_impl)]

extern crate alloc;

pub mod aes256;
pub mod cbc;
mod ec;
pub mod ecdh;
pub mod ecdsa;
pub mod hkdf;
pub mod hmac;
pub mod sha256;
pub mod util;

/// Trait for hash functions that returns a 256-bit hash.
///
/// When you implement this trait, make sure to implement `hash_mut` and `hmac_mut` first, because
/// the default implementations of `hash` and `hmac` rely on it.
pub trait Hash256: Sized {
    fn new() -> Self;
    fn update(&mut self, contents: &[u8]);
    fn finalize(self, output: &mut [u8; 32]);

    fn hash(contents: &[u8]) -> [u8; 32] {
        let mut output = [0; 32];
        Self::hash_mut(contents, &mut output);
        output
    }

    fn hash_mut(contents: &[u8], output: &mut [u8; 32]) {
        let mut h = Self::new();
        h.update(contents);
        h.finalize(output)
    }

    fn hmac(key: &[u8; 32], contents: &[u8]) -> [u8; 32] {
        let mut output = [0; 32];
        Self::hmac_mut(key, contents, &mut output);
        output
    }

    fn hmac_mut(key: &[u8; 32], contents: &[u8], output: &mut [u8; 32]) {
        hmac::software_hmac_256::<Self>(key, contents, output);
    }
}

/// Trait for hash functions that operate on 64-byte input blocks.
pub trait HashBlockSize64Bytes {
    type State;

    fn hash_block(state: &mut Self::State, block: &[u8; 64]);
}
