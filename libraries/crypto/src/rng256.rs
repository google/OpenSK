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

use libtock_drivers::rng;

// Lightweight RNG trait to generate uniformly distributed 256 bits.
pub trait Rng256 {
    fn gen_uniform_u8x32(&mut self) -> [u8; 32];

    fn gen_uniform_u32x8(&mut self) -> [u32; 8] {
        bytes_to_u32(self.gen_uniform_u8x32())
    }
}

// The TockOS rng driver fills a buffer of bytes, but we need 32-bit words for ECDSA.
// This function does the conversion in safe Rust, using the native endianness to avoid unnecessary
// instructions.
// An unsafe one-line equivalent could be implemented with mem::transmute, but let's use safe Rust
// when possible.
fn bytes_to_u32(bytes: [u8; 32]) -> [u32; 8] {
    let mut result: [u32; 8] = [Default::default(); 8];
    for (i, r) in result.iter_mut().enumerate() {
        *r = u32::from_ne_bytes(*array_ref![bytes, 4 * i, 4]);
    }
    result
}

// RNG backed by the TockOS rng driver.
pub struct TockRng256 {}

impl Rng256 for TockRng256 {
    fn gen_uniform_u8x32(&mut self) -> [u8; 32] {
        let mut buf: [u8; 32] = [Default::default(); 32];
        rng::fill_buffer(&mut buf);
        buf
    }
}

// For tests on the desktop, we use the cryptographically secure thread rng as entropy source.
#[cfg(feature = "std")]
pub struct ThreadRng256 {}

#[cfg(feature = "std")]
impl Rng256 for ThreadRng256 {
    fn gen_uniform_u8x32(&mut self) -> [u8; 32] {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut result = [Default::default(); 32];
        rng.fill(&mut result);
        result
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn test_bytes_to_u32() {
        // This tests that all bytes of the input are indeed used in the output, once each.
        // Otherwise the result of gen_uniform_u32x8 wouldn't be uniformly distributed.
        let bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\
                      \x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
                      \x10\x11\x12\x13\x14\x15\x16\x17\
                      \x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
        #[cfg(target_endian = "big")]
        let expected = [
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
            0x1c1d1e1f,
        ];
        #[cfg(target_endian = "little")]
        let expected = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
            0x1f1e1d1c,
        ];

        assert_eq!(bytes_to_u32(*bytes), expected);
    }
}
