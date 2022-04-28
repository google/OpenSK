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

// Trait for hash functions that returns a 256-bit hash.
// The type must be Sized (size known at compile time) so that we can instanciate one on the stack
// in the hash() method.
pub trait Hash256: Sized {
    fn new() -> Self;
    fn update(&mut self, contents: &[u8]);
    fn finalize(self) -> [u8; 32];

    fn hash(contents: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(contents);
        h.finalize()
    }

    fn hmac(key: &[u8; 32], contents: &[u8]) -> [u8; 32] {
        hmac::software_hmac_256::<Self>(key, contents)
    }
}

// Trait for hash functions that operate on 64-byte input blocks.
pub trait HashBlockSize64Bytes {
    type State;

    fn hash_block(state: &mut Self::State, block: &[u8; 64]);
}
