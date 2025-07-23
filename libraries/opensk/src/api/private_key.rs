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

use crate::api::crypto::ec_signing::{EcSecretKey, EcSignature};
#[cfg(feature = "ed25519")]
use crate::api::crypto::ec_signing::{EdSecretKey, EdSignature};
use crate::ctap::data_formats::{extract_array, extract_byte_string, CoseKey, SignatureAlgorithm};
use crate::ctap::status_code::{Ctap2StatusCode, CtapResult};
#[cfg(feature = "ed25519")]
use crate::env::Ed25519Sk;
use crate::env::{EcdsaSk, Env};
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use sk_cbor as cbor;
use sk_cbor::{cbor_array, cbor_bytes, cbor_int};

/// An asymmetric private key that can sign messages.
pub enum PrivateKey<E: Env> {
    Ecdsa(EcdsaSk<E>),
    #[cfg(feature = "ed25519")]
    Ed25519(Ed25519Sk<E>),
}

// We shouldn't compare private keys in prod without constant-time operations.
#[cfg(test)]
impl<E: Env> PartialEq for PrivateKey<E> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PrivateKey::Ecdsa(key1), PrivateKey::Ecdsa(key2)) => key1.export() == key2.export(),
            #[cfg(feature = "ed25519")]
            (PrivateKey::Ed25519(key1), PrivateKey::Ed25519(key2)) => {
                key1.export() == key2.export()
            }
            #[cfg(feature = "ed25519")]
            _ => false,
        }
    }
}

impl<E: Env> PrivateKey<E> {
    /// Creates a new private key for the given algorithm.
    ///
    /// # Panics
    ///
    /// Panics if the algorithm is [`SignatureAlgorithm::Unknown`].
    pub fn new(env: &mut E, alg: SignatureAlgorithm) -> Self {
        match alg {
            SignatureAlgorithm::Es256 => Self::Ecdsa(EcdsaSk::<E>::random(env.rng())),
            #[cfg(feature = "ed25519")]
            SignatureAlgorithm::Eddsa => Self::Ed25519(Ed25519Sk::<E>::random(env.rng())),
            SignatureAlgorithm::Unknown => unreachable!(),
        }
    }

    /// Creates a new ecdsa private key.
    pub fn new_ecdsa(env: &mut E) -> PrivateKey<E> {
        Self::new(env, SignatureAlgorithm::Es256)
    }

    /// Returns the corresponding public key.
    pub fn get_pub_key(&self) -> CtapResult<CoseKey> {
        Ok(match self {
            PrivateKey::Ecdsa(key) => CoseKey::from_ecdsa_public_key::<E>(key.public_key()),
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(key) => CoseKey::from_ed25519_public_key::<E>(key.public_key()),
        })
    }

    /// Returns the encoded signature for a given message.
    pub fn sign_and_encode(&self, message: &[u8]) -> CtapResult<Vec<u8>> {
        Ok(match self {
            PrivateKey::Ecdsa(key) => key.sign(message).to_der(),
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(key) => key.sign(message).to_bytes(),
        })
    }

    /// The associated COSE signature algorithm identifier.
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            PrivateKey::Ecdsa(_) => SignatureAlgorithm::Es256,
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(_) => SignatureAlgorithm::Eddsa,
        }
    }

    /// Writes the key bytes.
    pub fn export(&self) -> Vec<u8> {
        match self {
            PrivateKey::Ecdsa(key) => key.export(),
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(key) => key.export(),
        }
    }

    /// Encodes the private key into a CBOR array with type information.
    pub fn to_cbor(&self) -> cbor::Value {
        cbor_array![
            cbor_int!(self.signature_algorithm() as i64),
            cbor_bytes!(self.export()),
        ]
    }

    pub fn from_cbor(cbor_value: cbor::Value) -> CtapResult<Self> {
        let mut array = extract_array(cbor_value)?;
        if array.len() != 2 {
            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR);
        }
        let wrapped_bytes = extract_byte_string(array.pop().unwrap())?;
        match SignatureAlgorithm::try_from(array.pop().unwrap())? {
            SignatureAlgorithm::Es256 => EcdsaSk::<E>::import(&wrapped_bytes)
                .map(|k| PrivateKey::Ecdsa(k))
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            #[cfg(feature = "ed25519")]
            SignatureAlgorithm::Eddsa => Ed25519Sk::<E>::import(&wrapped_bytes)
                .map(|k| PrivateKey::Ed25519(k))
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;

    #[test]
    fn test_new_ecdsa_export_import() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::<TestEnv>::new_ecdsa(&mut env);
        let key_bytes = private_key.export();
        let ecdsa_key = EcdsaSk::<TestEnv>::import(&key_bytes).unwrap();
        let reconstructed = PrivateKey::<TestEnv>::Ecdsa(ecdsa_key);
        assert!(private_key == reconstructed);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_new_ed25519_export_import() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::<TestEnv>::new(&mut env, SignatureAlgorithm::Eddsa);
        let key_bytes = private_key.export();
        let ed25519_key = Ed25519Sk::<TestEnv>::import(&key_bytes).unwrap();
        let reconstructed = PrivateKey::<TestEnv>::Ed25519(ed25519_key);
        assert!(private_key == reconstructed);
    }

    #[test]
    fn test_private_key_get_pub_key() {
        let mut env = TestEnv::default();
        let ecdsa_key = EcdsaSk::<TestEnv>::random(env.rng());
        let public_key = ecdsa_key.public_key();
        let private_key = PrivateKey::<TestEnv>::Ecdsa(ecdsa_key);
        assert_eq!(
            private_key.get_pub_key(),
            Ok(CoseKey::from_ecdsa_public_key::<TestEnv>(public_key))
        );
    }

    #[test]
    fn test_private_key_sign_and_encode() {
        let mut env = TestEnv::default();
        let message = [0x5A; 32];
        let ecdsa_key = EcdsaSk::<TestEnv>::random(env.rng());
        let signature = ecdsa_key.sign(&message).to_der();
        let private_key = PrivateKey::<TestEnv>::Ecdsa(ecdsa_key);
        assert_eq!(private_key.sign_and_encode(&message), Ok(signature));
    }

    fn test_private_key_signature_algorithm(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::<TestEnv>::new(&mut env, signature_algorithm);
        assert_eq!(private_key.signature_algorithm(), signature_algorithm);
    }

    #[test]
    fn test_ecdsa_private_key_signature_algorithm() {
        test_private_key_signature_algorithm(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_private_key_signature_algorithm() {
        test_private_key_signature_algorithm(SignatureAlgorithm::Eddsa);
    }

    fn test_private_key_from_to_cbor(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::<TestEnv>::new(&mut env, signature_algorithm);
        let cbor = private_key.to_cbor();
        assert!(PrivateKey::<TestEnv>::from_cbor(cbor) == Ok(private_key));
    }

    #[test]
    fn test_ecdsa_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::Eddsa);
    }

    fn test_private_key_from_bad_cbor(signature_algorithm: SignatureAlgorithm) {
        let cbor = cbor_array![
            cbor_int!(signature_algorithm as i64),
            cbor_bytes!(vec![0x88; 32]),
            // The array is too long.
            cbor_int!(0),
        ];
        assert!(
            PrivateKey::<TestEnv>::from_cbor(cbor) == Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
        );
    }

    #[test]
    fn test_ecdsa_private_key_from_bad_cbor() {
        test_private_key_from_bad_cbor(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_private_key_from_bad_cbor() {
        test_private_key_from_bad_cbor(SignatureAlgorithm::Eddsa);
    }

    #[test]
    fn test_private_key_from_bad_cbor_unsupported_algo() {
        let cbor = cbor_array![
            // This algorithms doesn't exist.
            cbor_int!(-1),
            cbor_bytes!(vec![0x88; 32]),
        ];
        assert!(
            PrivateKey::<TestEnv>::from_cbor(cbor) == Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
        );
    }
}
