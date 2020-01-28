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

use super::util::{xor_block_16, Block16};
use super::{Decrypt16BytesBlock, Encrypt16BytesBlock};

/** A portable and naive textbook implementation of AES-256 **/
type Word = [u8; 4];

/** This structure caches the round keys, to avoid re-computing the key schedule for each block. **/
pub struct EncryptionKey {
    enc_round_keys: [Block16; 15],
}

pub struct DecryptionKey {
    dec_round_keys: [Block16; 15],
}

impl EncryptionKey {
    // Computes the round keys.
    pub fn new(key: &[u8; 32]) -> EncryptionKey {
        let mut enc_round_keys = [Default::default(); 15];

        enc_round_keys[0] = *array_ref![key, 0, 16];
        enc_round_keys[1] = *array_ref![key, 16, 16];

        let mut word: Word = *array_ref![enc_round_keys[1], 12, 4];
        for i in 2..15 {
            if i & 1 == 0 {
                rotword(&mut word);
                subword(&mut word);
                word[0] ^= RCON[(i >> 1) - 1];
            } else {
                subword(&mut word);
            }

            for j in 0..4 {
                xorword(&mut word, *array_ref![enc_round_keys[i - 2], 4 * j, 4]);
                *array_mut_ref![enc_round_keys[i], 4 * j, 4] = word;
            }
        }

        EncryptionKey { enc_round_keys }
    }
}

impl Encrypt16BytesBlock for EncryptionKey {
    // Encrypt an AES block in place.
    fn encrypt_block(&self, block: &mut Block16) {
        add_round_key(block, &self.enc_round_keys[0]);
        for i in 1..14 {
            aes_enc(block, &self.enc_round_keys[i]);
        }
        aes_enc_last(block, &self.enc_round_keys[14]);
    }
}

impl DecryptionKey {
    // Computes the round keys.
    pub fn new(key: &EncryptionKey) -> DecryptionKey {
        let mut dec_round_keys = [Default::default(); 15];
        dec_round_keys[0] = key.enc_round_keys[14];
        #[allow(clippy::needless_range_loop)]
        for i in 1..14 {
            let rk = &mut dec_round_keys[i];
            *rk = key.enc_round_keys[14 - i];
            inv_mix_columns(rk);
        }
        dec_round_keys[14] = key.enc_round_keys[0];

        DecryptionKey { dec_round_keys }
    }
}

impl Decrypt16BytesBlock for DecryptionKey {
    // Decrypt an AES block in place.
    fn decrypt_block(&self, block: &mut Block16) {
        add_round_key(block, &self.dec_round_keys[0]);
        for i in 1..14 {
            aes_dec(block, &self.dec_round_keys[i]);
        }
        aes_dec_last(block, &self.dec_round_keys[14]);
    }
}

/** Helper functions for the key schedule **/
fn rotword(word: &mut Word) {
    let tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

fn subword(word: &mut Word) {
    for byte in word.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

fn xorword(word: &mut Word, src: Word) {
    for i in 0..4 {
        word[i] ^= src[i];
    }
}

/** Helper functions for the encryption **/
fn aes_enc(block: &mut Block16, rkey: &Block16) {
    sub_bytes(block);
    shift_rows(block);
    mix_columns(block);
    add_round_key(block, rkey);
}

fn aes_dec(block: &mut Block16, rkey: &Block16) {
    inv_shift_rows(block);
    inv_sub_bytes(block);
    inv_mix_columns(block);
    add_round_key(block, rkey);
}

fn aes_enc_last(block: &mut Block16, rkey: &Block16) {
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, rkey);
}

fn aes_dec_last(block: &mut Block16, rkey: &Block16) {
    inv_shift_rows(block);
    inv_sub_bytes(block);
    add_round_key(block, rkey);
}

#[inline(always)]
fn add_round_key(block: &mut Block16, rkey: &Block16) {
    xor_block_16(block, rkey);
}

fn sub_bytes(block: &mut Block16) {
    for byte in block.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

fn inv_sub_bytes(block: &mut Block16) {
    for byte in block.iter_mut() {
        *byte = SBOX_INV[*byte as usize];
    }
}

fn shift_rows(block: &mut Block16) {
    let tmp = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = tmp;

    block.swap(2, 10);
    block.swap(6, 14);

    let tmp = block[3];
    block[3] = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = tmp;
}

fn inv_shift_rows(block: &mut Block16) {
    let tmp = block[7];
    block[7] = block[11];
    block[11] = block[15];
    block[15] = block[3];
    block[3] = tmp;

    block.swap(2, 10);
    block.swap(6, 14);

    let tmp = block[13];
    block[13] = block[9];
    block[9] = block[5];
    block[5] = block[1];
    block[1] = tmp;
}

// multiplication by 2 in GF(2^256)
fn mul2(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

// multiplication by 3 in GF(2^256)
fn mul3(x: u8) -> u8 {
    mul2(x) ^ x
}

fn mix_columns(block: &mut Block16) {
    for i in 0..4 {
        let x0 = block[4 * i];
        let x1 = block[4 * i + 1];
        let x2 = block[4 * i + 2];
        let x3 = block[4 * i + 3];
        block[4 * i] = mul2(x0) ^ mul3(x1) ^ x2 ^ x3;
        block[4 * i + 1] = x0 ^ mul2(x1) ^ mul3(x2) ^ x3;
        block[4 * i + 2] = x0 ^ x1 ^ mul2(x2) ^ mul3(x3);
        block[4 * i + 3] = mul3(x0) ^ x1 ^ x2 ^ mul2(x3);
    }
}

// multiplication by 9 in GF(2^256)
fn mul9(x: u8) -> u8 {
    mul2(mul2(mul2(x))) ^ x
}

// multiplication by 11 in GF(2^256)
fn mul11(x: u8) -> u8 {
    mul2(mul2(mul2(x)) ^ x) ^ x
}

// multiplication by 13 in GF(2^256)
fn mul13(x: u8) -> u8 {
    mul2(mul2(mul2(x) ^ x)) ^ x
}

// multiplication by 14 in GF(2^256)
fn mul14(x: u8) -> u8 {
    mul2(mul2(mul2(x) ^ x) ^ x)
}

fn inv_mix_columns(block: &mut Block16) {
    for i in 0..4 {
        let x0 = block[4 * i];
        let x1 = block[4 * i + 1];
        let x2 = block[4 * i + 2];
        let x3 = block[4 * i + 3];
        block[4 * i] = mul14(x0) ^ mul11(x1) ^ mul13(x2) ^ mul9(x3);
        block[4 * i + 1] = mul9(x0) ^ mul14(x1) ^ mul11(x2) ^ mul13(x3);
        block[4 * i + 2] = mul13(x0) ^ mul9(x1) ^ mul14(x2) ^ mul11(x3);
        block[4 * i + 3] = mul11(x0) ^ mul13(x1) ^ mul9(x2) ^ mul14(x3);
    }
}

/** Constants **/
// Constants used in the key schedule.
const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

// AES substitution box.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const SBOX_INV: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

#[cfg(test)]
mod test {
    use super::*;

    // Test vector from the NIST obtained at:
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf
    #[test]
    fn test_nist_aes256_ecb_encrypt() {
        let src = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\
                    \xe9\x3d\x7e\x11\x73\x93\x17\x2a";
        let key = b"\x60\x3d\xeb\x10\x15\xca\x71\xbe\
                    \x2b\x73\xae\xf0\x85\x7d\x77\x81\
                    \x1f\x35\x2c\x07\x3b\x61\x08\xd7\
                    \x2d\x98\x10\xa3\x09\x14\xdf\xf4";
        let expected = b"\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\
                         \x06\x4b\x5a\x7e\x3d\xb1\x81\xf8";

        let mut dst: Block16 = Default::default();
        dst.copy_from_slice(src);
        EncryptionKey::new(key).encrypt_block(&mut dst);
        assert_eq!(&dst, expected);
    }

    #[test]
    fn test_nist_aes256_ecb_decrypt() {
        let src = b"\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\
                    \x06\x4b\x5a\x7e\x3d\xb1\x81\xf8";
        let key = b"\x60\x3d\xeb\x10\x15\xca\x71\xbe\
                    \x2b\x73\xae\xf0\x85\x7d\x77\x81\
                    \x1f\x35\x2c\x07\x3b\x61\x08\xd7\
                    \x2d\x98\x10\xa3\x09\x14\xdf\xf4";
        let expected = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\
                         \xe9\x3d\x7e\x11\x73\x93\x17\x2a";

        let mut dst: Block16 = Default::default();
        dst.copy_from_slice(src);
        DecryptionKey::new(&EncryptionKey::new(key)).decrypt_block(&mut dst);
        assert_eq!(&dst, expected);
    }

    #[test]
    fn test_encrypt_decrypt() {
        // Test that decrypt_block is the inverse of encrypt_block for a bunch of block values.
        let key_bytes = b"\x60\x3d\xeb\x10\x15\xca\x71\xbe\
                          \x2b\x73\xae\xf0\x85\x7d\x77\x81\
                          \x1f\x35\x2c\x07\x3b\x61\x08\xd7\
                          \x2d\x98\x10\xa3\x09\x14\xdf\xf4";
        let enc_key = EncryptionKey::new(key_bytes);
        let dec_key = DecryptionKey::new(&enc_key);
        let mut block: Block16 = [0; 16];
        for i in 0..=255 {
            for j in 0..16 {
                block[j] = (i + j) as u8;
            }
            let expected = block;
            enc_key.encrypt_block(&mut block);
            dec_key.decrypt_block(&mut block);
            assert_eq!(block, expected);
        }
    }

    #[test]
    fn test_sbox_is_permutation() {
        let mut image = [false; 256];
        for &sboxed in SBOX.iter() {
            assert_eq!(image[sboxed as usize], false);
            image[sboxed as usize] = true;
        }
    }

    #[test]
    fn test_sbox_inv_is_permutation() {
        let mut image = [false; 256];
        for &sboxed in SBOX_INV.iter() {
            assert_eq!(image[sboxed as usize], false);
            image[sboxed as usize] = true;
        }
    }

    #[test]
    fn test_sbox_inverse() {
        for i in 0..=255 {
            assert_eq!(SBOX_INV[SBOX[i as usize] as usize], i);
        }
    }

    #[test]
    fn test_subbytes() {
        let mut block = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expected = [
            99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
        ];
        sub_bytes(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn test_subbytes_inv() {
        // Test that inv_sub_bytes is the inverse of sub_bytes for a bunch of block values.
        let mut block: Block16 = [0; 16];
        for i in 0..=255 {
            for j in 0..16 {
                block[j] = (i + j) as u8;
            }
            let expected = block;
            sub_bytes(&mut block);
            inv_sub_bytes(&mut block);
            assert_eq!(block, expected);
        }
    }

    #[test]
    fn test_shift_rows() {
        let mut block = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expected = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
        shift_rows(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn test_shift_rows_inv() {
        // Test that inv_shift_rows is the inverse of shift_rows for a bunch of block values.
        let mut block: Block16 = [0; 16];
        for i in 0..=255 {
            for j in 0..16 {
                block[j] = (i + j) as u8;
            }
            let expected = block;
            shift_rows(&mut block);
            inv_shift_rows(&mut block);
            assert_eq!(block, expected);
        }
    }

    #[test]
    fn test_mix_columns_inv() {
        // Test that inv_mix_columns is the inverse of mix_columns for a bunch of block values.
        let mut block: Block16 = [0; 16];
        for i in 0..=255 {
            for j in 0..16 {
                block[j] = (i + j) as u8;
            }
            let expected = block;
            mix_columns(&mut block);
            inv_mix_columns(&mut block);
            assert_eq!(block, expected);
        }
    }

    /** Comparison with AES-NI instructions for CPUs that support them **/
    #[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
    mod aesni {
        use super::super::*;

        fn aes_enc_ni(block: &mut Block16, rkey: &Block16) {
            use core::arch::x86_64::{__m128i, _mm_aesenc_si128};

            unsafe {
                let block_mm: __m128i = core::mem::transmute(*block);
                let rkey_mm: __m128i = core::mem::transmute(*rkey);
                let encrypted_mm: __m128i = _mm_aesenc_si128(block_mm, rkey_mm);
                *block = core::mem::transmute(encrypted_mm)
            }
        }

        fn aes_enc_last_ni(block: &mut Block16, rkey: &Block16) {
            use core::arch::x86_64::{__m128i, _mm_aesenclast_si128};

            unsafe {
                let block_mm: __m128i = core::mem::transmute(*block);
                let rkey_mm: __m128i = core::mem::transmute(*rkey);
                let encrypted_mm: __m128i = _mm_aesenclast_si128(block_mm, rkey_mm);
                *block = core::mem::transmute(encrypted_mm)
            }
        }

        fn aes_dec_ni(block: &mut Block16, rkey: &Block16) {
            use core::arch::x86_64::{__m128i, _mm_aesdec_si128};

            unsafe {
                let block_mm: __m128i = core::mem::transmute(*block);
                let rkey_mm: __m128i = core::mem::transmute(*rkey);
                let decrypted_mm: __m128i = _mm_aesdec_si128(block_mm, rkey_mm);
                *block = core::mem::transmute(decrypted_mm)
            }
        }

        fn aes_dec_last_ni(block: &mut Block16, rkey: &Block16) {
            use core::arch::x86_64::{__m128i, _mm_aesdeclast_si128};

            unsafe {
                let block_mm: __m128i = core::mem::transmute(*block);
                let rkey_mm: __m128i = core::mem::transmute(*rkey);
                let decrypted_mm: __m128i = _mm_aesdeclast_si128(block_mm, rkey_mm);
                *block = core::mem::transmute(decrypted_mm)
            }
        }

        #[test]
        fn test_aes_enc_ni() {
            let mut block = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            let mut block_ni = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            let rkey = [
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            aes_enc(&mut block, &rkey);
            aes_enc_ni(&mut block_ni, &rkey);
            assert_eq!(block, block_ni);
        }

        #[test]
        fn test_aes_enc_last_ni() {
            let mut block = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            let mut block_ni = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            let rkey = [
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            aes_enc_last(&mut block, &rkey);
            aes_enc_last_ni(&mut block_ni, &rkey);
            assert_eq!(block, block_ni);
        }

        #[test]
        fn test_aes_dec_ni() {
            let mut block = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            let mut block_ni = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            let rkey = [
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            aes_dec(&mut block, &rkey);
            aes_dec_ni(&mut block_ni, &rkey);
            assert_eq!(block, block_ni);
        }

        #[test]
        fn test_aes_dec_last_ni() {
            let mut block = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            let mut block_ni = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            let rkey = [
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            aes_dec_last(&mut block, &rkey);
            aes_dec_last_ni(&mut block_ni, &rkey);
            assert_eq!(block, block_ni);
        }
    }
}
