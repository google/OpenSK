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

//! This cryptography implementation is an alternative for our own library.
//!
//! You can use it with the `rust_crypto` feature. An example call to cargo test is in
//! `run_desktop_tests.sh`. It is currently impossible to use it with our version of TockOS due to
//! a compiler version imcompatibility.
//!
//! If you want to use OpenSK outside of Tock v1, maybe this is useful for you though!

use crate::api::crypto::{ecdh, ecdsa, Crypto, EC_FIELD_BYTE_SIZE, EC_SIGNATURE_SIZE};
use core::convert::TryFrom;
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::signature::{SignatureEncoding, Signer, Verifier};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
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
    ephemeral_secret: EphemeralSecret,
}

impl ecdh::SecretKey for TestEcdhSecretKey {
    type PublicKey = TestEcdhPublicKey;
    type SharedSecret = TestEcdhSharedSecret;

    fn random(_rng: &mut impl Rng256) -> Self {
        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        Self { ephemeral_secret }
    }

    fn public_key(&self) -> Self::PublicKey {
        let public_key = self.ephemeral_secret.public_key();
        TestEcdhPublicKey { public_key }
    }

    fn diffie_hellman(&self, public_key: &TestEcdhPublicKey) -> Self::SharedSecret {
        let shared_secret = self.ephemeral_secret.diffie_hellman(&public_key.public_key);
        TestEcdhSharedSecret { shared_secret }
    }
}

pub struct TestEcdhPublicKey {
    public_key: p256::PublicKey,
}

impl ecdh::PublicKey for TestEcdhPublicKey {
    fn from_coordinates(
        x: &[u8; EC_FIELD_BYTE_SIZE],
        y: &[u8; EC_FIELD_BYTE_SIZE],
    ) -> Option<Self> {
        let encoded_point: p256::EncodedPoint =
            p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let public_key = p256::PublicKey::from_sec1_bytes(encoded_point.as_bytes()).ok()?;
        Some(Self { public_key })
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_BYTE_SIZE], y: &mut [u8; EC_FIELD_BYTE_SIZE]) {
        let point = self.public_key.to_encoded_point(false);
        x.copy_from_slice(point.x().unwrap());
        y.copy_from_slice(point.y().unwrap());
    }
}

pub struct TestEcdhSharedSecret {
    shared_secret: p256::ecdh::SharedSecret,
}

impl ecdh::SharedSecret for TestEcdhSharedSecret {
    fn raw_secret_bytes(&self) -> [u8; EC_FIELD_BYTE_SIZE] {
        let mut bytes = [0; EC_FIELD_BYTE_SIZE];
        bytes.copy_from_slice(self.shared_secret.raw_secret_bytes().as_slice());
        bytes
    }
}

impl ecdsa::Ecdsa for TestEcdsa {
    type SecretKey = TestEcdsaSecretKey;
    type PublicKey = TestEcdsaPublicKey;
    type Signature = TestEcdsaSignature;
}

pub struct TestEcdsaSecretKey {
    signing_key: SigningKey,
}

impl ecdsa::SecretKey for TestEcdsaSecretKey {
    type PublicKey = TestEcdsaPublicKey;
    type Signature = TestEcdsaSignature;

    fn random(_rng: &mut impl Rng256) -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        TestEcdsaSecretKey { signing_key }
    }

    fn from_slice(bytes: &[u8; EC_FIELD_BYTE_SIZE]) -> Option<Self> {
        let signing_key = SigningKey::from_slice(bytes).ok()?;
        Some(TestEcdsaSecretKey { signing_key })
    }

    fn public_key(&self) -> Self::PublicKey {
        let verifying_key = VerifyingKey::from(&self.signing_key);
        TestEcdsaPublicKey { verifying_key }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = self.signing_key.sign(message);
        TestEcdsaSignature { signature }
    }

    fn to_slice(&self, bytes: &mut [u8; EC_FIELD_BYTE_SIZE]) {
        bytes.copy_from_slice(&self.signing_key.to_bytes());
    }
}

pub struct TestEcdsaPublicKey {
    verifying_key: VerifyingKey,
}

impl ecdsa::PublicKey for TestEcdsaPublicKey {
    type Signature = TestEcdsaSignature;

    fn from_coordinates(
        x: &[u8; EC_FIELD_BYTE_SIZE],
        y: &[u8; EC_FIELD_BYTE_SIZE],
    ) -> Option<Self> {
        let encoded_point: p256::EncodedPoint =
            p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let verifying_key = VerifyingKey::from_encoded_point(&encoded_point).ok()?;
        Some(TestEcdsaPublicKey { verifying_key })
    }

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.verifying_key
            .verify(message, &signature.signature)
            .is_ok()
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_BYTE_SIZE], y: &mut [u8; EC_FIELD_BYTE_SIZE]) {
        let point = self.verifying_key.to_encoded_point(false);
        x.copy_from_slice(point.x().unwrap());
        y.copy_from_slice(point.y().unwrap());
    }
}

pub struct TestEcdsaSignature {
    signature: p256::ecdsa::Signature,
}

impl ecdsa::Signature for TestEcdsaSignature {
    fn from_slice(bytes: &[u8; EC_SIGNATURE_SIZE]) -> Option<Self> {
        // Assumes EC_SIGNATURE_SIZE == 2 * EC_FIELD_BYTE_SIZE
        let r = &bytes[..EC_FIELD_BYTE_SIZE];
        let s = &bytes[EC_FIELD_BYTE_SIZE..];
        let r = p256::NonZeroScalar::try_from(r).ok()?;
        let s = p256::NonZeroScalar::try_from(s).ok()?;
        let r = p256::FieldBytes::from(r);
        let s = p256::FieldBytes::from(s);
        let signature = p256::ecdsa::Signature::from_scalars(r, s).ok()?;
        Some(TestEcdsaSignature { signature })
    }

    fn to_der(&self) -> Vec<u8> {
        self.signature.to_der().to_vec()
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
