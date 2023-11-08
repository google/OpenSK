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

use crate::api::crypto::ecdsa::{SecretKey as _, Signature};
use crate::ctap::crypto_wrapper::{aes256_cbc_decrypt, aes256_cbc_encrypt};
use crate::ctap::data_formats::{extract_array, extract_byte_string, CoseKey, SignatureAlgorithm};
use crate::ctap::secret::Secret;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::env::{AesKey, EcdsaSk, Env};
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::ops::Deref;
#[cfg(feature = "ed25519")]
use core::ops::DerefMut;
#[cfg(feature = "ed25519")]
use rand_core::RngCore;
use sk_cbor as cbor;
use sk_cbor::{cbor_array, cbor_bytes, cbor_int};

/// An asymmetric private key that can sign messages.
#[derive(Clone, Debug)]
// We shouldn't compare private keys in prod without constant-time operations.
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum PrivateKey {
    // We store the key bytes instead of the env type. They can be converted into each other.
    Ecdsa(Secret<[u8; 32]>),
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519_compact::SecretKey),
}

impl PrivateKey {
    /// Creates a new private key for the given algorithm.
    ///
    /// # Panics
    ///
    /// Panics if the algorithm is [`SignatureAlgorithm::Unknown`].
    pub fn new<E: Env>(env: &mut E, alg: SignatureAlgorithm) -> Self {
        match alg {
            SignatureAlgorithm::Es256 => {
                let mut bytes: Secret<[u8; 32]> = Secret::default();
                EcdsaSk::<E>::random(env.rng()).to_slice(&mut bytes);
                PrivateKey::Ecdsa(bytes)
            }
            #[cfg(feature = "ed25519")]
            SignatureAlgorithm::Eddsa => {
                let mut bytes: Secret<[u8; 32]> = Secret::default();
                env.rng().fill_bytes(bytes.deref_mut());
                Self::new_ed25519_from_bytes(&*bytes).unwrap()
            }
            SignatureAlgorithm::Unknown => unreachable!(),
        }
    }

    /// Creates a new ecdsa private key.
    pub fn new_ecdsa(env: &mut impl Env) -> PrivateKey {
        Self::new(env, SignatureAlgorithm::Es256)
    }

    /// Helper function that creates a private key of type ECDSA.
    pub fn new_ecdsa_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut seed: Secret<[u8; 32]> = Secret::default();
        seed.copy_from_slice(bytes);
        Some(PrivateKey::Ecdsa(seed))
    }

    /// Helper function that creates a private key of type Ed25519.
    #[cfg(feature = "ed25519")]
    pub fn new_ed25519_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let seed = ed25519_compact::Seed::from_slice(bytes).unwrap();
        Some(Self::Ed25519(ed25519_compact::KeyPair::from_seed(seed).sk))
    }

    /// Returns the ECDSA private key.
    pub fn ecdsa_key<E: Env>(&self) -> Result<EcdsaSk<E>, Ctap2StatusCode> {
        match self {
            PrivateKey::Ecdsa(bytes) => ecdsa_key_from_bytes::<E>(bytes),
            #[allow(unreachable_patterns)]
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Returns the corresponding public key.
    pub fn get_pub_key<E: Env>(&self) -> Result<CoseKey, Ctap2StatusCode> {
        Ok(match self {
            PrivateKey::Ecdsa(bytes) => {
                CoseKey::from_ecdsa_public_key(ecdsa_key_from_bytes::<E>(bytes)?.public_key())
            }
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(ed25519_key) => CoseKey::from(ed25519_key.public_key()),
        })
    }

    /// Returns the encoded signature for a given message.
    pub fn sign_and_encode<E: Env>(&self, message: &[u8]) -> Result<Vec<u8>, Ctap2StatusCode> {
        Ok(match self {
            PrivateKey::Ecdsa(bytes) => ecdsa_key_from_bytes::<E>(bytes)?.sign(message).to_der(),
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(ed25519_key) => ed25519_key.sign(message, None).to_vec(),
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
    pub fn to_bytes(&self) -> Secret<[u8]> {
        let mut bytes = Secret::new(32);
        match self {
            PrivateKey::Ecdsa(key_bytes) => bytes.copy_from_slice(key_bytes.deref()),
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(ed25519_key) => bytes.copy_from_slice(ed25519_key.seed().deref()),
        }
        bytes
    }

    pub fn to_cbor<E: Env>(
        &self,
        rng: &mut E::Rng,
        wrap_key: &AesKey<E>,
    ) -> Result<cbor::Value, Ctap2StatusCode> {
        let bytes = self.to_bytes();
        let wrapped_bytes = aes256_cbc_encrypt::<E>(rng, wrap_key, &bytes, true)?;
        Ok(cbor_array![
            cbor_int!(self.signature_algorithm() as i64),
            cbor_bytes!(wrapped_bytes),
        ])
    }

    pub fn from_cbor<E: Env>(
        wrap_key: &AesKey<E>,
        cbor_value: cbor::Value,
    ) -> Result<Self, Ctap2StatusCode> {
        let mut array = extract_array(cbor_value)?;
        if array.len() != 2 {
            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR);
        }
        let wrapped_bytes = extract_byte_string(array.pop().unwrap())?;
        let key_bytes = aes256_cbc_decrypt::<E>(wrap_key, &wrapped_bytes, true)?;
        match SignatureAlgorithm::try_from(array.pop().unwrap())? {
            SignatureAlgorithm::Es256 => PrivateKey::new_ecdsa_from_bytes(&key_bytes)
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            #[cfg(feature = "ed25519")]
            SignatureAlgorithm::Eddsa => PrivateKey::new_ed25519_from_bytes(&key_bytes)
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
        }
    }
}

fn ecdsa_key_from_bytes<E: Env>(bytes: &[u8; 32]) -> Result<EcdsaSk<E>, Ctap2StatusCode> {
    EcdsaSk::<E>::from_slice(bytes).ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::key_store::KeyStore;
    use crate::env::test::TestEnv;

    #[test]
    fn test_new_ecdsa_from_bytes() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::Es256);
        let key_bytes = private_key.to_bytes();
        assert_eq!(
            PrivateKey::new_ecdsa_from_bytes(&key_bytes),
            Some(private_key)
        );
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_new_ed25519_from_bytes() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::Eddsa);
        let key_bytes = private_key.to_bytes();
        assert_eq!(
            PrivateKey::new_ed25519_from_bytes(&key_bytes),
            Some(private_key)
        );
    }

    #[test]
    fn test_new_ecdsa_from_bytes_wrong_length() {
        assert_eq!(PrivateKey::new_ecdsa_from_bytes(&[0x55; 16]), None);
        assert_eq!(PrivateKey::new_ecdsa_from_bytes(&[0x55; 31]), None);
        assert_eq!(PrivateKey::new_ecdsa_from_bytes(&[0x55; 33]), None);
        assert_eq!(PrivateKey::new_ecdsa_from_bytes(&[0x55; 64]), None);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_new_ed25519_from_bytes_wrong_length() {
        assert_eq!(PrivateKey::new_ed25519_from_bytes(&[0x55; 16]), None);
        assert_eq!(PrivateKey::new_ed25519_from_bytes(&[0x55; 31]), None);
        assert_eq!(PrivateKey::new_ed25519_from_bytes(&[0x55; 33]), None);
        assert_eq!(PrivateKey::new_ed25519_from_bytes(&[0x55; 64]), None);
    }

    #[test]
    fn test_private_key_get_pub_key() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let ecdsa_key = private_key.ecdsa_key::<TestEnv>().unwrap();
        let public_key = ecdsa_key.public_key();
        assert_eq!(
            private_key.get_pub_key::<TestEnv>(),
            Ok(CoseKey::from_ecdsa_public_key(public_key))
        );
    }

    #[test]
    fn test_private_key_sign_and_encode() {
        let mut env = TestEnv::default();
        let message = [0x5A; 32];
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let ecdsa_key = private_key.ecdsa_key::<TestEnv>().unwrap();
        let signature = ecdsa_key.sign(&message).to_der();
        assert_eq!(
            private_key.sign_and_encode::<TestEnv>(&message),
            Ok(signature)
        );
    }

    fn test_private_key_signature_algorithm(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);
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
        let wrap_key = env.key_store().wrap_key::<TestEnv>().unwrap();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);
        let cbor = private_key
            .to_cbor::<TestEnv>(env.rng(), &wrap_key)
            .unwrap();
        assert_eq!(
            PrivateKey::from_cbor::<TestEnv>(&wrap_key, cbor),
            Ok(private_key)
        );
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
        let mut env = TestEnv::default();
        let wrap_key = env.key_store().wrap_key::<TestEnv>().unwrap();
        let cbor = cbor_array![
            cbor_int!(signature_algorithm as i64),
            cbor_bytes!(vec![0x88; 32]),
            // The array is too long.
            cbor_int!(0),
        ];
        assert_eq!(
            PrivateKey::from_cbor::<TestEnv>(&wrap_key, cbor),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
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
        let mut env = TestEnv::default();
        let wrap_key = env.key_store().wrap_key::<TestEnv>().unwrap();
        let cbor = cbor_array![
            // This algorithms doesn't exist.
            cbor_int!(-1),
            cbor_bytes!(vec![0x88; 32]),
        ];
        assert_eq!(
            PrivateKey::from_cbor::<TestEnv>(&wrap_key, cbor),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
        );
    }
}
