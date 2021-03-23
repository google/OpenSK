// Copyright 2021 Google LLC
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

use crate::ctap::status_code::Ctap2StatusCode;
use alloc::vec;
use alloc::vec::Vec;
use crypto::cbc::{cbc_decrypt, cbc_encrypt};
use crypto::rng256::Rng256;

/// Wraps the AES256-CBC encryption to match what we need in CTAP.
pub fn aes256_cbc_encrypt(
    rng: &mut dyn Rng256,
    aes_enc_key: &crypto::aes256::EncryptionKey,
    plaintext: &[u8],
    has_iv: bool,
) -> Result<Vec<u8>, Ctap2StatusCode> {
    if plaintext.len() % 16 != 0 {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    let iv = if has_iv {
        let random_bytes = rng.gen_uniform_u8x32();
        *array_ref!(random_bytes, 0, 16)
    } else {
        [0u8; 16]
    };
    let mut blocks = Vec::with_capacity(plaintext.len() / 16);
    // TODO(https://github.com/rust-lang/rust/issues/74985) Use array_chunks when stable.
    for block in plaintext.chunks_exact(16) {
        blocks.push(*array_ref!(block, 0, 16));
    }
    cbc_encrypt(aes_enc_key, iv, &mut blocks);
    let mut ciphertext = if has_iv { iv.to_vec() } else { vec![] };
    ciphertext.extend(blocks.iter().flatten());
    Ok(ciphertext)
}

/// Wraps the AES256-CBC decryption to match what we need in CTAP.
pub fn aes256_cbc_decrypt(
    aes_enc_key: &crypto::aes256::EncryptionKey,
    ciphertext: &[u8],
    has_iv: bool,
) -> Result<Vec<u8>, Ctap2StatusCode> {
    if ciphertext.len() % 16 != 0 {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    let mut block_len = ciphertext.len() / 16;
    // TODO(https://github.com/rust-lang/rust/issues/74985) Use array_chunks when stable.
    let mut block_iter = ciphertext.chunks_exact(16);
    let iv = if has_iv {
        block_len -= 1;
        let iv_block = block_iter
            .next()
            .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
        *array_ref!(iv_block, 0, 16)
    } else {
        [0u8; 16]
    };
    let mut blocks = Vec::with_capacity(block_len);
    for block in block_iter {
        blocks.push(*array_ref!(block, 0, 16));
    }
    let aes_dec_key = crypto::aes256::DecryptionKey::new(aes_enc_key);
    cbc_decrypt(&aes_dec_key, iv, &mut blocks);
    Ok(blocks.iter().flatten().cloned().collect::<Vec<u8>>())
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto::rng256::ThreadRng256;

    #[test]
    fn test_encrypt_decrypt_with_iv() {
        let mut rng = ThreadRng256 {};
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let ciphertext = aes256_cbc_encrypt(&mut rng, &aes_enc_key, &plaintext, true).unwrap();
        let decrypted = aes256_cbc_decrypt(&aes_enc_key, &ciphertext, true).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_without_iv() {
        let mut rng = ThreadRng256 {};
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let ciphertext = aes256_cbc_encrypt(&mut rng, &aes_enc_key, &plaintext, false).unwrap();
        let decrypted = aes256_cbc_decrypt(&aes_enc_key, &ciphertext, false).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
