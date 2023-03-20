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

use crate::api::crypto::hmac256::Hmac256;
use crate::api::crypto::sha256::Sha256;
use crate::api::crypto::{
    ecdh, ecdsa, Crypto, EC_FIELD_SIZE, EC_SIGNATURE_SIZE, HASH_SIZE, HMAC_KEY_SIZE,
    TRUNCATED_HMAC_SIZE,
};
use alloc::vec::Vec;
use crypto::Hash256;
use rng256::Rng256;

pub struct SoftwareCrypto;
pub struct SoftwareEcdh;
pub struct SoftwareEcdsa;

impl Crypto for SoftwareCrypto {
    type Ecdh = SoftwareEcdh;
    type Ecdsa = SoftwareEcdsa;
    type Sha256 = SoftwareSha256;
    type Hmac256 = SoftwareHmac256;
}

impl ecdh::Ecdh for SoftwareEcdh {
    type SecretKey = SoftwareEcdhSecretKey;
    type PublicKey = SoftwareEcdhPublicKey;
    type SharedSecret = SoftwareEcdhSharedSecret;
}

pub struct SoftwareEcdhSecretKey {
    sec_key: crypto::ecdh::SecKey,
}

impl ecdh::SecretKey for SoftwareEcdhSecretKey {
    type PublicKey = SoftwareEcdhPublicKey;
    type SharedSecret = SoftwareEcdhSharedSecret;

    fn random(rng: &mut impl Rng256) -> Self {
        let sec_key = crypto::ecdh::SecKey::gensk(rng);
        Self { sec_key }
    }

    fn public_key(&self) -> Self::PublicKey {
        let pub_key = self.sec_key.genpk();
        SoftwareEcdhPublicKey { pub_key }
    }

    fn diffie_hellman(&self, public_key: &SoftwareEcdhPublicKey) -> Self::SharedSecret {
        let shared_secret = self.sec_key.exchange_x(&public_key.pub_key);
        SoftwareEcdhSharedSecret { shared_secret }
    }
}

pub struct SoftwareEcdhPublicKey {
    pub_key: crypto::ecdh::PubKey,
}

impl ecdh::PublicKey for SoftwareEcdhPublicKey {
    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], y: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        crypto::ecdh::PubKey::from_coordinates(x, y).map(|k| Self { pub_key: k })
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        self.pub_key.to_coordinates(x, y);
    }
}

pub struct SoftwareEcdhSharedSecret {
    shared_secret: [u8; EC_FIELD_SIZE],
}

impl ecdh::SharedSecret for SoftwareEcdhSharedSecret {
    fn raw_secret_bytes(&self) -> [u8; EC_FIELD_SIZE] {
        self.shared_secret
    }
}

impl ecdsa::Ecdsa for SoftwareEcdsa {
    type SecretKey = SoftwareEcdsaSecretKey;
    type PublicKey = SoftwareEcdsaPublicKey;
    type Signature = SoftwareEcdsaSignature;
}

pub struct SoftwareEcdsaSecretKey {
    sec_key: crypto::ecdsa::SecKey,
}

impl ecdsa::SecretKey for SoftwareEcdsaSecretKey {
    type PublicKey = SoftwareEcdsaPublicKey;
    type Signature = SoftwareEcdsaSignature;

    fn random(rng: &mut impl Rng256) -> Self {
        let sec_key = crypto::ecdsa::SecKey::gensk(rng);
        Self { sec_key }
    }

    fn from_slice(bytes: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        crypto::ecdsa::SecKey::from_bytes(bytes).map(|k| Self { sec_key: k })
    }

    fn public_key(&self) -> Self::PublicKey {
        let pub_key = self.sec_key.genpk();
        SoftwareEcdsaPublicKey { pub_key }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = self.sec_key.sign_rfc6979::<crypto::sha256::Sha256>(message);
        SoftwareEcdsaSignature { signature }
    }

    fn to_slice(&self, bytes: &mut [u8; EC_FIELD_SIZE]) {
        self.sec_key.to_bytes(bytes);
    }
}

pub struct SoftwareEcdsaPublicKey {
    pub_key: crypto::ecdsa::PubKey,
}

impl ecdsa::PublicKey for SoftwareEcdsaPublicKey {
    type Signature = SoftwareEcdsaSignature;

    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], y: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        crypto::ecdsa::PubKey::from_coordinates(x, y).map(|k| Self { pub_key: k })
    }

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.pub_key
            .verify_vartime::<crypto::sha256::Sha256>(message, &signature.signature)
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        self.pub_key.to_coordinates(x, y);
    }
}

pub struct SoftwareEcdsaSignature {
    signature: crypto::ecdsa::Signature,
}

impl ecdsa::Signature for SoftwareEcdsaSignature {
    fn from_slice(bytes: &[u8; EC_SIGNATURE_SIZE]) -> Option<Self> {
        crypto::ecdsa::Signature::from_bytes(bytes).map(|s| SoftwareEcdsaSignature { signature: s })
    }

    fn to_der(&self) -> Vec<u8> {
        self.signature.to_asn1_der()
    }
}

pub struct SoftwareSha256 {
    hasher: crypto::sha256::Sha256,
}

impl Sha256 for SoftwareSha256 {
    fn new() -> Self {
        let hasher = crypto::sha256::Sha256::new();
        Self { hasher }
    }

    /// Digest the next part of the message to hash.
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalizes the hashing process, returns the hash value.
    fn finalize(self) -> [u8; HASH_SIZE] {
        self.hasher.finalize()
    }
}

pub struct SoftwareHmac256;

impl Hmac256 for SoftwareHmac256 {
    fn mac(key: &[u8; HMAC_KEY_SIZE], data: &[u8]) -> [u8; HASH_SIZE] {
        crypto::hmac::hmac_256::<crypto::sha256::Sha256>(key, data)
    }

    fn verify(key: &[u8; HMAC_KEY_SIZE], data: &[u8], mac: &[u8; HASH_SIZE]) -> bool {
        crypto::hmac::verify_hmac_256::<crypto::sha256::Sha256>(key, data, mac)
    }

    fn verify_truncated_left(
        key: &[u8; HMAC_KEY_SIZE],
        data: &[u8],
        mac: &[u8; TRUNCATED_HMAC_SIZE],
    ) -> bool {
        crypto::hmac::verify_hmac_256_first_128bits::<crypto::sha256::Sha256>(key, data, mac)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::crypto::ecdh::{
        PublicKey as EcdhPublicKey, SecretKey as EcdhSecretKey, SharedSecret,
    };
    use crate::api::crypto::ecdsa::{PublicKey as EcdsaPublicKey, SecretKey as EcdsaSecretKey};
    use crate::env::test::TestEnv;
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
        assert_eq!(shared1.raw_secret_bytes(), shared2.raw_secret_bytes());
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
    fn test_ecdsa_secret_key_from_to_bytes() {
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
    fn test_sha256_hash_matches() {
        let data = [0x55; 16];
        let mut hasher = SoftwareSha256::new();
        hasher.update(&data);
        assert_eq!(SoftwareSha256::digest(&data), hasher.finalize());
    }

    #[test]
    fn test_hmac256_verifies() {
        let key = [0xAA; HMAC_KEY_SIZE];
        let data = [0x55; 16];
        let mac = SoftwareHmac256::mac(&key, &data);
        assert!(SoftwareHmac256::verify(&key, &data, &mac));
        let truncated_mac =
            <&[u8; TRUNCATED_HMAC_SIZE]>::try_from(&mac[..TRUNCATED_HMAC_SIZE]).unwrap();
        assert!(SoftwareHmac256::verify_truncated_left(
            &key,
            &data,
            truncated_mac
        ));
    }
}
