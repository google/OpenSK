// Copyright 2021-2023 Google LLC
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

use crate::api::crypto::aes256::Aes256;
use crate::ctap::secret::Secret;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::env::{AesKey, Env};
use alloc::vec::Vec;
use rand_core::RngCore;

/// Wraps the AES256-CBC encryption to match what we need in CTAP.
pub fn aes256_cbc_encrypt<E: Env>(
    rng: &mut E::Rng,
    aes_key: &AesKey<E>,
    plaintext: &[u8],
    embeds_iv: bool,
) -> Result<Vec<u8>, Ctap2StatusCode> {
    if plaintext.len() % 16 != 0 {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    let mut ciphertext = Vec::with_capacity(plaintext.len() + 16 * embeds_iv as usize);
    let iv = if embeds_iv {
        ciphertext.resize(16, 0);
        rng.fill_bytes(&mut ciphertext[..16]);
        *array_ref!(ciphertext, 0, 16)
    } else {
        [0u8; 16]
    };
    let start = ciphertext.len();
    ciphertext.extend_from_slice(plaintext);
    aes_key.encrypt_cbc(&iv, &mut ciphertext[start..]);
    Ok(ciphertext)
}

/// Wraps the AES256-CBC decryption to match what we need in CTAP.
pub fn aes256_cbc_decrypt<E: Env>(
    aes_key: &AesKey<E>,
    ciphertext: &[u8],
    embeds_iv: bool,
) -> Result<Secret<[u8]>, Ctap2StatusCode> {
    if ciphertext.len() % 16 != 0 || (embeds_iv && ciphertext.is_empty()) {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    let (iv, ciphertext) = if embeds_iv {
        let (iv, ciphertext) = ciphertext.split_at(16);
        (array_ref!(iv, 0, 16), ciphertext)
    } else {
        (&[0u8; 16], ciphertext)
    };
    let mut plaintext = Secret::new(ciphertext.len());
    plaintext.copy_from_slice(ciphertext);
    aes_key.decrypt_cbc(iv, &mut plaintext);
    Ok(plaintext)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;

    #[test]
    fn test_encrypt_decrypt_with_iv() {
        let mut env = TestEnv::default();
        let aes_key = AesKey::<TestEnv>::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let ciphertext =
            aes256_cbc_encrypt::<TestEnv>(env.rng(), &aes_key, &plaintext, true).unwrap();
        let decrypted = aes256_cbc_decrypt::<TestEnv>(&aes_key, &ciphertext, true).unwrap();
        assert_eq!(*decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_without_iv() {
        let mut env = TestEnv::default();
        let aes_key = AesKey::<TestEnv>::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let ciphertext =
            aes256_cbc_encrypt::<TestEnv>(env.rng(), &aes_key, &plaintext, false).unwrap();
        let decrypted = aes256_cbc_decrypt::<TestEnv>(&aes_key, &ciphertext, false).unwrap();
        assert_eq!(*decrypted, plaintext);
    }

    #[test]
    fn test_correct_iv_usage() {
        let mut env = TestEnv::default();
        let aes_key = AesKey::<TestEnv>::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let mut ciphertext_no_iv =
            aes256_cbc_encrypt::<TestEnv>(env.rng(), &aes_key, &plaintext, false).unwrap();
        let mut ciphertext_with_iv = vec![0u8; 16];
        ciphertext_with_iv.append(&mut ciphertext_no_iv);
        let decrypted = aes256_cbc_decrypt::<TestEnv>(&aes_key, &ciphertext_with_iv, true).unwrap();
        assert_eq!(*decrypted, plaintext);
    }

    #[test]
    fn test_iv_manipulation_property() {
        let mut env = TestEnv::default();
        let aes_key = AesKey::<TestEnv>::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let mut ciphertext =
            aes256_cbc_encrypt::<TestEnv>(env.rng(), &aes_key, &plaintext, true).unwrap();
        let mut expected_plaintext = plaintext;
        for i in 0..16 {
            ciphertext[i] ^= 0xBB;
            expected_plaintext[i] ^= 0xBB;
        }
        let decrypted = aes256_cbc_decrypt::<TestEnv>(&aes_key, &ciphertext, true).unwrap();
        assert_eq!(*decrypted, expected_plaintext);
    }

    #[test]
    fn test_chaining() {
        let mut env = TestEnv::default();
        let aes_key = AesKey::<TestEnv>::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let ciphertext1 =
            aes256_cbc_encrypt::<TestEnv>(env.rng(), &aes_key, &plaintext, true).unwrap();
        let ciphertext2 =
            aes256_cbc_encrypt::<TestEnv>(env.rng(), &aes_key, &plaintext, true).unwrap();
        assert_eq!(ciphertext1.len(), 80);
        assert_eq!(ciphertext2.len(), 80);
        // The ciphertext should mutate in all blocks with a different IV.
        let block_iter1 = ciphertext1.chunks_exact(16);
        let block_iter2 = ciphertext2.chunks_exact(16);
        for (block1, block2) in block_iter1.zip(block_iter2) {
            assert_ne!(block1, block2);
        }
    }
}
