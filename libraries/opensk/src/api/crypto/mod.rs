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

pub mod aes256;
pub mod ecdh;
pub mod ecdsa;
#[cfg(feature = "rust_crypto")]
pub mod rust_crypto;
#[cfg(not(feature = "rust_crypto"))]
pub mod software_crypto;
#[cfg(feature = "rust_crypto")]
pub use rust_crypto as software_crypto;
pub mod hkdf256;
pub mod hmac256;
pub mod sha256;

use self::aes256::Aes256;
use self::ecdh::Ecdh;
use self::ecdsa::Ecdsa;
use self::hkdf256::Hkdf256;
use self::hmac256::Hmac256;
use self::sha256::Sha256;

/// The size of a serialized ECDSA signature.
pub const AES_BLOCK_SIZE: usize = 16;

/// The size of field elements in the elliptic curve P256.
pub const AES_KEY_SIZE: usize = 32;

/// The size of field elements in the elliptic curve P256.
pub const EC_FIELD_SIZE: usize = 32;

/// The size of a serialized ECDSA signature.
pub const EC_SIGNATURE_SIZE: usize = 2 * EC_FIELD_SIZE;

/// The size in bytes of a SHA256.
pub const HASH_SIZE: usize = 32;

/// The size in bytes of an HMAC.
pub const HMAC_KEY_SIZE: usize = 32;

/// The size in bytes of a truncated HMAC.
///
/// Truncated HMACs are used in PIN protocol V1 in CTAP2.
pub const TRUNCATED_HMAC_SIZE: usize = 16;

/// Necessary cryptographic primitives for CTAP.
pub trait Crypto {
    type Aes256: Aes256;
    type Ecdh: Ecdh;
    type Ecdsa: Ecdsa;
    type Sha256: Sha256;
    type Hmac256: Hmac256;
    type Hkdf256: Hkdf256;
}

#[cfg(test)]
mod test {
    use super::software_crypto::*;
    use super::*;
    use crate::api::crypto::ecdh::{PublicKey as _, SecretKey as _, SharedSecret};
    use crate::api::crypto::ecdsa::{PublicKey as _, SecretKey as _, Signature};
    use crate::env::test::TestEnv;
    use crate::env::Env;
    use core::convert::TryFrom;

    #[test]
    fn test_shared_secret_symmetric() {
        let mut env = TestEnv::default();
        let private1 = SoftwareEcdhSecretKey::random(env.rng());
        let private2 = SoftwareEcdhSecretKey::random(env.rng());
        let pub1 = private1.public_key();
        let pub2 = private2.public_key();
        let shared1 = private1.diffie_hellman(&pub2);
        let shared2 = private2.diffie_hellman(&pub1);
        let mut secret_bytes1 = [0; EC_FIELD_SIZE];
        let mut secret_bytes2 = [0; EC_FIELD_SIZE];
        shared1.raw_secret_bytes(&mut secret_bytes1);
        shared2.raw_secret_bytes(&mut secret_bytes2);
        assert_eq!(secret_bytes1, secret_bytes2);
    }

    #[test]
    fn test_ecdh_public_key_from_to_bytes() {
        let mut env = TestEnv::default();
        let first_key = SoftwareEcdhSecretKey::random(env.rng());
        let first_public = first_key.public_key();
        let mut x = [0; EC_FIELD_SIZE];
        let mut y = [0; EC_FIELD_SIZE];
        first_public.to_coordinates(&mut x, &mut y);
        let new_public = SoftwareEcdhPublicKey::from_coordinates(&x, &y).unwrap();
        let mut new_x = [0; EC_FIELD_SIZE];
        let mut new_y = [0; EC_FIELD_SIZE];
        new_public.to_coordinates(&mut new_x, &mut new_y);
        assert_eq!(x, new_x);
        assert_eq!(y, new_y);
    }

    #[test]
    fn test_sign_verify() {
        let mut env = TestEnv::default();
        let private_key = SoftwareEcdsaSecretKey::random(env.rng());
        let public_key = private_key.public_key();
        let message = [0x12, 0x34, 0x56, 0x78];
        let signature = private_key.sign(&message);
        assert!(public_key.verify(&message, &signature));
    }

    #[test]
    fn test_sign_verify_hash() {
        let mut env = TestEnv::default();
        let private_key = SoftwareEcdsaSecretKey::random(env.rng());
        let public_key = private_key.public_key();
        let message = [0x12, 0x34, 0x56, 0x78];
        let signature = private_key.sign(&message);
        let message_hash = SoftwareSha256::digest(&message);
        assert!(public_key.verify_prehash(&message_hash, &signature));
    }

    #[test]
    fn test_ecdsa_secret_key_from_to_slice() {
        let mut env = TestEnv::default();
        let first_key = SoftwareEcdsaSecretKey::random(env.rng());
        let mut key_bytes = [0; EC_FIELD_SIZE];
        first_key.to_slice(&mut key_bytes);
        let second_key = SoftwareEcdsaSecretKey::from_slice(&key_bytes).unwrap();
        let mut new_bytes = [0; EC_FIELD_SIZE];
        second_key.to_slice(&mut new_bytes);
        assert_eq!(key_bytes, new_bytes);
    }

    #[test]
    fn test_ecdsa_signature_from_to_slice() {
        let mut env = TestEnv::default();
        let private_key = SoftwareEcdsaSecretKey::random(env.rng());
        let message = [0x12, 0x34, 0x56, 0x78];
        let signature = private_key.sign(&message);
        let mut signature_bytes = [0; EC_SIGNATURE_SIZE];
        signature.to_slice(&mut signature_bytes);
        let new_signature = SoftwareEcdsaSignature::from_slice(&signature_bytes).unwrap();
        let mut new_bytes = [0; EC_SIGNATURE_SIZE];
        new_signature.to_slice(&mut new_bytes);
        assert_eq!(signature_bytes, new_bytes);
    }

    #[test]
    fn test_sha256_hash_matches() {
        let data = [0x55; 16];
        let mut hasher = SoftwareSha256::new();
        hasher.update(&data);
        let mut hash_from_finalize = [0; HASH_SIZE];
        hasher.finalize(&mut hash_from_finalize);
        assert_eq!(SoftwareSha256::digest(&data), hash_from_finalize);
        let mut hash_from_mut = [0; HASH_SIZE];
        SoftwareSha256::digest_mut(&data, &mut hash_from_mut);
        assert_eq!(SoftwareSha256::digest(&data), hash_from_mut);
    }

    #[test]
    fn test_hmac256_verifies() {
        let key = [0xAA; HMAC_KEY_SIZE];
        let data = [0x55; 16];
        let mut mac = [0; HASH_SIZE];
        SoftwareHmac256::mac(&key, &data, &mut mac);
        assert!(SoftwareHmac256::verify(&key, &data, &mac));
        let truncated_mac =
            <&[u8; TRUNCATED_HMAC_SIZE]>::try_from(&mac[..TRUNCATED_HMAC_SIZE]).unwrap();
        assert!(SoftwareHmac256::verify_truncated_left(
            &key,
            &data,
            truncated_mac
        ));
    }

    #[test]
    fn test_hkdf_empty_salt_256_vector() {
        let expected_okm = [
            0xf9, 0xbe, 0x72, 0x11, 0x6c, 0xb9, 0x7f, 0x41, 0x82, 0x82, 0x10, 0x28, 0x9c, 0xaa,
            0xfe, 0xab, 0xde, 0x1f, 0x3d, 0xfb, 0x97, 0x23, 0xbf, 0x43, 0x53, 0x8a, 0xb1, 0x8f,
            0x36, 0x66, 0x78, 0x3a,
        ];
        let mut okm = [0; HASH_SIZE];
        SoftwareHkdf256::hkdf_empty_salt_256(b"0", &[0], &mut okm);
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_hkdf_256_matches() {
        let ikm = [0x11; 16];
        let salt = [0; 32];
        let info = [0x22; 16];
        let mut empty_salt_output = [0; HASH_SIZE];
        let mut explicit_output = [0; HASH_SIZE];
        SoftwareHkdf256::hkdf_empty_salt_256(&ikm, &info, &mut empty_salt_output);
        SoftwareHkdf256::hkdf_256(&ikm, &salt, &info, &mut explicit_output);
        assert_eq!(empty_salt_output, explicit_output);
    }

    #[test]
    fn test_aes_encrypt_decrypt_block() {
        let mut block = [0x55; AES_BLOCK_SIZE];
        let aes = SoftwareAes256::new(&[0xAA; AES_KEY_SIZE]);
        aes.encrypt_block(&mut block);
        aes.decrypt_block(&mut block);
        assert_eq!(block, [0x55; AES_BLOCK_SIZE]);
    }

    #[test]
    fn test_aes_encrypt_decrypt_cbc() {
        let mut message = [0x55; 2 * AES_BLOCK_SIZE];
        let iv = [0x11; AES_BLOCK_SIZE];
        let aes = SoftwareAes256::new(&[0xAA; AES_KEY_SIZE]);
        aes.encrypt_cbc(&iv, &mut message);
        aes.decrypt_cbc(&iv, &mut message);
        assert_eq!(message, [0x55; 2 * AES_BLOCK_SIZE]);
    }

    #[test]
    #[should_panic]
    fn test_aes_encrypt_panics() {
        let mut message = [0x55; AES_BLOCK_SIZE + 1];
        let iv = [0x11; AES_BLOCK_SIZE];
        let aes = SoftwareAes256::new(&[0xAA; AES_KEY_SIZE]);
        aes.encrypt_cbc(&iv, &mut message);
    }

    #[test]
    #[should_panic]
    fn test_aes_decrypt_panics() {
        let mut message = [0x55; AES_BLOCK_SIZE + 1];
        let iv = [0x11; AES_BLOCK_SIZE];
        let aes = SoftwareAes256::new(&[0xAA; AES_KEY_SIZE]);
        aes.decrypt_cbc(&iv, &mut message);
    }
}
