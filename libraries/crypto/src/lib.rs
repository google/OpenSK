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

#[macro_use]
extern crate alloc;
extern crate subtle;
#[macro_use]
extern crate arrayref;
extern crate byteorder;
#[macro_use]
extern crate cbor;

pub mod aes256;
pub mod cbc;
mod ec;
pub mod ecdh;
pub mod ecdsa;
pub mod hmac;
pub mod rng256;
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
}

// Traits for block ciphers that operate on 16-byte blocks.
pub trait Encrypt16BytesBlock {
    fn encrypt_block(&self, block: &mut [u8; 16]);
}

pub trait Decrypt16BytesBlock {
    fn decrypt_block(&self, block: &mut [u8; 16]);
}

// Trait for hash functions that operate on 64-byte input blocks.
pub trait HashBlockSize64Bytes {
    type State;

    fn hash_block(state: &mut Self::State, block: &[u8; 64]);
}
