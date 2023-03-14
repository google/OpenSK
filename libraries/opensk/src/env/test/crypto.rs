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

use crate::api::crypto::{ecdh, ecdsa, Crypto, EC_FIELD_BYTE_SIZE, EC_SIGNATURE_SIZE};
use alloc::vec::Vec;
use rng256::Rng256;

pub struct TestCrypto;
pub struct TestEcdh;
pub struct TestEcdsa;

impl Crypto for TestCrypto {
    type Ecdh = TestEcdh;
    type Ecdsa = TestEcdsa;
}

impl ecdh::Ecdh for TestEcdh {
    type SecretKey = TestEcdhSecretKey;
    type PublicKey = TestEcdhPublicKey;
    type SharedSecret = TestEcdhSharedSecret;
}

pub struct TestEcdhSecretKey {
    sec_key: crypto::ecdh::SecKey,
}

impl ecdh::SecretKey for TestEcdhSecretKey {
    type PublicKey = TestEcdhPublicKey;
    type SharedSecret = TestEcdhSharedSecret;

    fn random(rng: &mut impl Rng256) -> Self {
        let sec_key = crypto::ecdh::SecKey::gensk(rng);
        Self { sec_key }
    }

    fn public_key(&self) -> Self::PublicKey {
        let pub_key = self.sec_key.genpk();
        TestEcdhPublicKey { pub_key }
    }

    fn diffie_hellman(&self, public_key: &TestEcdhPublicKey) -> Self::SharedSecret {
        let shared_secret = self.sec_key.exchange_x(&public_key.pub_key);
        TestEcdhSharedSecret { shared_secret }
    }
}

pub struct TestEcdhPublicKey {
    pub_key: crypto::ecdh::PubKey,
}

impl ecdh::PublicKey for TestEcdhPublicKey {
    fn from_coordinates(
        x: &[u8; EC_FIELD_BYTE_SIZE],
        y: &[u8; EC_FIELD_BYTE_SIZE],
    ) -> Option<Self> {
        crypto::ecdh::PubKey::from_coordinates(x, y).map(|k| Self { pub_key: k })
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_BYTE_SIZE], y: &mut [u8; EC_FIELD_BYTE_SIZE]) {
        self.pub_key.to_coordinates(x, y);
    }
}

pub struct TestEcdhSharedSecret {
    shared_secret: [u8; EC_FIELD_BYTE_SIZE],
}

impl ecdh::SharedSecret for TestEcdhSharedSecret {
    fn raw_secret_bytes(&self) -> [u8; EC_FIELD_BYTE_SIZE] {
        self.shared_secret
    }
}

impl ecdsa::Ecdsa for TestEcdsa {
    type SecretKey = TestEcdsaSecretKey;
    type PublicKey = TestEcdsaPublicKey;
    type Signature = TestEcdsaSignature;
}

pub struct TestEcdsaSecretKey {
    sec_key: crypto::ecdsa::SecKey,
}

impl ecdsa::SecretKey for TestEcdsaSecretKey {
    type PublicKey = TestEcdsaPublicKey;
    type Signature = TestEcdsaSignature;

    fn random(rng: &mut impl Rng256) -> Self {
        let sec_key = crypto::ecdsa::SecKey::gensk(rng);
        Self { sec_key }
    }

    fn from_slice(bytes: &[u8; EC_FIELD_BYTE_SIZE]) -> Option<Self> {
        crypto::ecdsa::SecKey::from_bytes(bytes).map(|k| Self { sec_key: k })
    }

    fn public_key(&self) -> Self::PublicKey {
        let pub_key = self.sec_key.genpk();
        TestEcdsaPublicKey { pub_key }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = self.sec_key.sign_rfc6979::<crypto::sha256::Sha256>(message);
        TestEcdsaSignature { signature }
    }

    fn to_slice(&self, bytes: &mut [u8; EC_FIELD_BYTE_SIZE]) {
        self.sec_key.to_bytes(bytes);
    }
}

pub struct TestEcdsaPublicKey {
    pub_key: crypto::ecdsa::PubKey,
}

impl ecdsa::PublicKey for TestEcdsaPublicKey {
    type Signature = TestEcdsaSignature;

    fn from_coordinates(
        x: &[u8; EC_FIELD_BYTE_SIZE],
        y: &[u8; EC_FIELD_BYTE_SIZE],
    ) -> Option<Self> {
        crypto::ecdsa::PubKey::from_coordinates(x, y).map(|k| Self { pub_key: k })
    }

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.pub_key
            .verify_vartime::<crypto::sha256::Sha256>(message, &signature.signature)
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_BYTE_SIZE], y: &mut [u8; EC_FIELD_BYTE_SIZE]) {
        self.pub_key.to_coordinates(x, y);
    }
}

pub struct TestEcdsaSignature {
    signature: crypto::ecdsa::Signature,
}

impl ecdsa::Signature for TestEcdsaSignature {
    fn from_slice(bytes: &[u8; EC_SIGNATURE_SIZE]) -> Option<Self> {
        crypto::ecdsa::Signature::from_bytes(bytes).map(|s| TestEcdsaSignature { signature: s })
    }

    fn to_der(&self) -> Vec<u8> {
        self.signature.to_asn1_der()
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

    #[test]
    fn test_shared_secret_symmetric() {
        let mut env = TestEnv::default();
        let private1 = TestEcdhSecretKey::random(env.rng());
        let private2 = TestEcdhSecretKey::random(env.rng());
        let pub1 = private1.public_key();
        let pub2 = private2.public_key();
        let shared1 = private1.diffie_hellman(&pub2);
        let shared2 = private2.diffie_hellman(&pub1);
        assert_eq!(shared1.raw_secret_bytes(), shared2.raw_secret_bytes());
    }

    #[test]
    fn test_ecdh_public_key_from_to_bytes() {
        let mut env = TestEnv::default();
        let first_key = TestEcdhSecretKey::random(env.rng());
        let first_public = first_key.public_key();
        let mut x = [0; EC_FIELD_BYTE_SIZE];
        let mut y = [0; EC_FIELD_BYTE_SIZE];
        first_public.to_coordinates(&mut x, &mut y);
        let new_public = TestEcdhPublicKey::from_coordinates(&x, &y).unwrap();
        let mut new_x = [0; EC_FIELD_BYTE_SIZE];
        let mut new_y = [0; EC_FIELD_BYTE_SIZE];
        new_public.to_coordinates(&mut new_x, &mut new_y);
        assert_eq!(x, new_x);
        assert_eq!(y, new_y);
    }

    #[test]
    fn test_sign_verify() {
        let mut env = TestEnv::default();
        let private_key = TestEcdsaSecretKey::random(env.rng());
        let public_key = private_key.public_key();
        let message = [0x12, 0x34, 0x56, 0x78];
        let signature = private_key.sign(&message);
        assert!(public_key.verify(&message, &signature));
    }

    #[test]
    fn test_ecdsa_secret_key_from_to_bytes() {
        let mut env = TestEnv::default();
        let first_key = TestEcdsaSecretKey::random(env.rng());
        let mut key_bytes = [0; EC_FIELD_BYTE_SIZE];
        first_key.to_slice(&mut key_bytes);
        let second_key = TestEcdsaSecretKey::from_slice(&key_bytes).unwrap();
        let mut new_bytes = [0; EC_FIELD_BYTE_SIZE];
        second_key.to_slice(&mut new_bytes);
        assert_eq!(key_bytes, new_bytes);
    }
}
