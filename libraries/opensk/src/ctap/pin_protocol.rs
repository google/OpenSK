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

use crate::api::crypto::aes256::Aes256;
use crate::api::crypto::ecdh::{PublicKey as _, SecretKey as _, SharedSecret as _};
use crate::api::crypto::hkdf256::Hkdf256;
use crate::api::crypto::hmac256::Hmac256;
use crate::api::crypto::sha256::Sha256;
use crate::ctap::client_pin::PIN_TOKEN_LENGTH;
use crate::ctap::crypto_wrapper::{aes256_cbc_decrypt, aes256_cbc_encrypt};
use crate::ctap::data_formats::{CoseKey, PinUvAuthProtocol};
use crate::ctap::secret::Secret;
use crate::ctap::status_code::Ctap2StatusCode;
#[cfg(test)]
use crate::env::test::TestEnv;
use crate::env::{AesKey, EcdhPk, EcdhSk, Env, Hkdf, Hmac, Sha};
use alloc::vec::Vec;
use core::ops::DerefMut;
use rand_core::RngCore;

/// Implements common functions between existing PIN protocols for handshakes.
pub struct PinProtocol<E: Env> {
    key_agreement_key: EcdhSk<E>,
    pin_uv_auth_token: Secret<[u8; PIN_TOKEN_LENGTH]>,
}

impl<E: Env> PinProtocol<E> {
    /// This process is run by the authenticator at power-on.
    ///
    /// This function implements "initialize" from the specification.
    pub fn new(env: &mut E) -> Self {
        let key_agreement_key = EcdhSk::<E>::random(env.rng());
        let mut pin_uv_auth_token: Secret<[u8; 32]> = Secret::default();
        env.rng().fill_bytes(pin_uv_auth_token.deref_mut());
        PinProtocol {
            key_agreement_key,
            pin_uv_auth_token,
        }
    }

    /// Generates a fresh public key.
    pub fn regenerate(&mut self, env: &mut E) {
        self.key_agreement_key = EcdhSk::<E>::random(env.rng());
    }

    /// Generates a fresh pinUvAuthToken.
    pub fn reset_pin_uv_auth_token(&mut self, env: &mut E) {
        env.rng().fill_bytes(self.pin_uv_auth_token.deref_mut());
    }

    /// Returns the authenticator’s public key as a CoseKey structure.
    pub fn get_public_key(&self) -> CoseKey {
        CoseKey::from_ecdh_public_key(self.key_agreement_key.public_key())
    }

    /// Processes the peer's encapsulated CoseKey and returns the shared secret.
    pub fn decapsulate(
        &self,
        peer_cose_key: CoseKey,
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) -> Result<SharedSecret<E>, Ctap2StatusCode> {
        let (x_bytes, y_bytes) = peer_cose_key.try_into_ecdh_coordinates()?;
        let pk = EcdhPk::<E>::from_coordinates(&x_bytes, &y_bytes)
            .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
        let mut handshake = Secret::default();
        self.key_agreement_key
            .diffie_hellman(&pk)
            .raw_secret_bytes(&mut handshake);
        Ok(SharedSecret::new(pin_uv_auth_protocol, handshake))
    }

    /// Getter for pinUvAuthToken.
    pub fn get_pin_uv_auth_token(&self) -> &[u8; PIN_TOKEN_LENGTH] {
        &self.pin_uv_auth_token
    }

    /// This is used for debugging to inject key material.
    #[cfg(test)]
    pub fn new_test(
        key_agreement_key: EcdhSk<E>,
        pin_uv_auth_token: [u8; PIN_TOKEN_LENGTH],
    ) -> Self {
        PinProtocol {
            key_agreement_key,
            pin_uv_auth_token: Secret::from_exposed_secret(pin_uv_auth_token),
        }
    }
}

/// Authenticates the pinUvAuthToken for the given PIN protocol.
#[cfg(test)]
pub fn authenticate_pin_uv_auth_token(
    token: &[u8; PIN_TOKEN_LENGTH],
    message: &[u8],
    pin_uv_auth_protocol: PinUvAuthProtocol,
) -> Vec<u8> {
    let mut mac = [0; 32];
    Hmac::<TestEnv>::mac(token, message, &mut mac);
    match pin_uv_auth_protocol {
        PinUvAuthProtocol::V1 => mac[..16].to_vec(),
        PinUvAuthProtocol::V2 => mac.to_vec(),
    }
}

/// Verifies the pinUvAuthToken for the given PIN protocol.
pub fn verify_pin_uv_auth_token<E: Env>(
    token: &[u8; PIN_TOKEN_LENGTH],
    message: &[u8],
    signature: &[u8],
    pin_uv_auth_protocol: PinUvAuthProtocol,
) -> Result<(), Ctap2StatusCode> {
    match pin_uv_auth_protocol {
        PinUvAuthProtocol::V1 => verify_v1::<E>(token, message, signature),
        PinUvAuthProtocol::V2 => verify_v2::<E>(token, message, signature),
    }
}

pub enum SharedSecret<E: Env> {
    V1(SharedSecretV1<E>),
    V2(SharedSecretV2<E>),
}

impl<E: Env> SharedSecret<E> {
    /// Creates a new shared secret for the respective PIN protocol.
    ///
    /// This enum wraps all types of shared secrets.
    fn new(pin_uv_auth_protocol: PinUvAuthProtocol, handshake: Secret<[u8; 32]>) -> Self {
        match pin_uv_auth_protocol {
            PinUvAuthProtocol::V1 => SharedSecret::V1(SharedSecretV1::new(handshake)),
            PinUvAuthProtocol::V2 => SharedSecret::V2(SharedSecretV2::new(handshake)),
        }
    }

    /// Returns the encrypted plaintext.
    pub fn encrypt(&self, env: &mut E, plaintext: &[u8]) -> Result<Vec<u8>, Ctap2StatusCode> {
        match self {
            SharedSecret::V1(s) => s.encrypt(env, plaintext),
            SharedSecret::V2(s) => s.encrypt(env, plaintext),
        }
    }

    /// Returns the decrypted ciphertext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Secret<[u8]>, Ctap2StatusCode> {
        match self {
            SharedSecret::V1(s) => s.decrypt(ciphertext),
            SharedSecret::V2(s) => s.decrypt(ciphertext),
        }
    }

    /// Verifies that the signature is a valid MAC for the given message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Ctap2StatusCode> {
        match self {
            SharedSecret::V1(s) => s.verify(message, signature),
            SharedSecret::V2(s) => s.verify(message, signature),
        }
    }

    /// Creates a signature that matches verify.
    #[cfg(test)]
    // Does not return a Secret as it is only used in tests.
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        match self {
            SharedSecret::V1(s) => s.authenticate(message),
            SharedSecret::V2(s) => s.authenticate(message),
        }
    }
}

fn verify_v1<E: Env>(
    key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Ctap2StatusCode> {
    if signature.len() != 16 {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    if Hmac::<E>::verify_truncated_left(key, message, array_ref![signature, 0, 16]) {
        Ok(())
    } else {
        Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
    }
}

fn verify_v2<E: Env>(
    key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Ctap2StatusCode> {
    if signature.len() != 32 {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    if Hmac::<E>::verify(key, message, array_ref![signature, 0, 32]) {
        Ok(())
    } else {
        Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
    }
}

pub struct SharedSecretV1<E: Env> {
    common_secret: Secret<[u8; 32]>,
    aes_key: AesKey<E>,
}

impl<E: Env> SharedSecretV1<E> {
    /// Creates a new shared secret from the handshake result.
    fn new(handshake: Secret<[u8; 32]>) -> Self {
        let mut common_secret = Secret::default();
        Sha::<E>::digest_mut(&*handshake, &mut common_secret);
        let aes_key = AesKey::<E>::new(&common_secret);
        SharedSecretV1 {
            common_secret,
            aes_key,
        }
    }

    fn encrypt(&self, env: &mut E, plaintext: &[u8]) -> Result<Vec<u8>, Ctap2StatusCode> {
        aes256_cbc_encrypt::<E>(env.rng(), &self.aes_key, plaintext, false)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Secret<[u8]>, Ctap2StatusCode> {
        aes256_cbc_decrypt::<E>(&self.aes_key, ciphertext, false)
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Ctap2StatusCode> {
        verify_v1::<E>(&self.common_secret, message, signature)
    }

    #[cfg(test)]
    fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        let mut output = [0; 32];
        Hmac::<E>::mac(&self.common_secret, message, &mut output);
        output[..16].to_vec()
    }
}

pub struct SharedSecretV2<E: Env> {
    aes_key: AesKey<E>,
    hmac_key: Secret<[u8; 32]>,
}

impl<E: Env> SharedSecretV2<E> {
    /// Creates a new shared secret from the handshake result.
    fn new(handshake: Secret<[u8; 32]>) -> Self {
        let mut aes_key_bytes = Secret::default();
        Hkdf::<E>::hkdf_empty_salt_256(&*handshake, b"CTAP2 AES key", &mut aes_key_bytes);
        let mut hmac_key = Secret::default();
        Hkdf::<E>::hkdf_empty_salt_256(&*handshake, b"CTAP2 HMAC key", &mut hmac_key);
        SharedSecretV2 {
            aes_key: AesKey::<E>::new(&aes_key_bytes),
            hmac_key,
        }
    }

    fn encrypt(&self, env: &mut E, plaintext: &[u8]) -> Result<Vec<u8>, Ctap2StatusCode> {
        aes256_cbc_encrypt::<E>(env.rng(), &self.aes_key, plaintext, true)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Secret<[u8]>, Ctap2StatusCode> {
        aes256_cbc_decrypt::<E>(&self.aes_key, ciphertext, true)
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Ctap2StatusCode> {
        verify_v2::<E>(&self.hmac_key, message, signature)
    }

    #[cfg(test)]
    fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        let mut output = [0; 32];
        Hmac::<E>::mac(&self.hmac_key, message, &mut output);
        output.to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;

    #[test]
    fn test_pin_protocol_public_key() {
        let mut env = TestEnv::default();
        let mut pin_protocol = PinProtocol::<TestEnv>::new(&mut env);
        let public_key = pin_protocol.get_public_key();
        pin_protocol.regenerate(&mut env);
        let new_public_key = pin_protocol.get_public_key();
        assert_ne!(public_key, new_public_key);
    }

    #[test]
    fn test_pin_protocol_pin_uv_auth_token() {
        let mut env = TestEnv::default();
        let mut pin_protocol = PinProtocol::<TestEnv>::new(&mut env);
        let token = *pin_protocol.get_pin_uv_auth_token();
        pin_protocol.reset_pin_uv_auth_token(&mut env);
        let new_token = pin_protocol.get_pin_uv_auth_token();
        assert_ne!(&token, new_token);
    }

    #[test]
    fn test_shared_secret_v1_encrypt_decrypt() {
        let mut env = TestEnv::default();
        let shared_secret = SharedSecretV1::<TestEnv>::new(Secret::from_exposed_secret([0x55; 32]));
        let mut plaintext = Secret::new(64);
        plaintext.fill(0xAA);
        let ciphertext = shared_secret.encrypt(&mut env, &plaintext).unwrap();
        assert_eq!(shared_secret.decrypt(&ciphertext), Ok(plaintext));
    }

    #[test]
    fn test_shared_secret_v1_authenticate_verify() {
        let shared_secret = SharedSecretV1::<TestEnv>::new(Secret::from_exposed_secret([0x55; 32]));
        let message = [0xAA; 32];
        let signature = shared_secret.authenticate(&message);
        assert_eq!(shared_secret.verify(&message, &signature), Ok(()));
    }

    #[test]
    fn test_shared_secret_v1_verify() {
        let shared_secret = SharedSecretV1::<TestEnv>::new(Secret::from_exposed_secret([0x55; 32]));
        let message = [0xAA];
        let signature = [
            0x8B, 0x60, 0x15, 0x7D, 0xF3, 0x44, 0x82, 0x2E, 0x54, 0x34, 0x7A, 0x01, 0xFB, 0x02,
            0x48, 0xA6,
        ];
        assert_eq!(shared_secret.verify(&message, &signature), Ok(()));
        assert_eq!(
            shared_secret.verify(&[0xBB], &signature),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            shared_secret.verify(&message, &[0x12; 16]),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_shared_secret_v2_encrypt_decrypt() {
        let mut env = TestEnv::default();
        let shared_secret = SharedSecretV2::<TestEnv>::new(Secret::from_exposed_secret([0x55; 32]));
        let mut plaintext = Secret::new(64);
        plaintext.fill(0xAA);
        let ciphertext = shared_secret.encrypt(&mut env, &plaintext).unwrap();
        assert_eq!(shared_secret.decrypt(&ciphertext), Ok(plaintext));
    }

    #[test]
    fn test_shared_secret_v2_authenticate_verify() {
        let shared_secret = SharedSecretV2::<TestEnv>::new(Secret::from_exposed_secret([0x55; 32]));
        let message = [0xAA; 32];
        let signature = shared_secret.authenticate(&message);
        assert_eq!(shared_secret.verify(&message, &signature), Ok(()));
    }

    #[test]
    fn test_shared_secret_v2_verify() {
        let shared_secret = SharedSecretV2::<TestEnv>::new(Secret::from_exposed_secret([0x55; 32]));
        let message = [0xAA];
        let signature = [
            0xC0, 0x3F, 0x2A, 0x22, 0x5C, 0xC3, 0x4E, 0x05, 0xC1, 0x0E, 0x72, 0x9C, 0x8D, 0xD5,
            0x7D, 0xE5, 0x98, 0x9C, 0x68, 0x15, 0xEC, 0xE2, 0x3A, 0x95, 0xD5, 0x90, 0xE1, 0xE9,
            0x3F, 0xF0, 0x1A, 0xAF,
        ];
        assert_eq!(shared_secret.verify(&message, &signature), Ok(()));
        assert_eq!(
            shared_secret.verify(&[0xBB], &signature),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            shared_secret.verify(&message, &[0x12; 32]),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_decapsulate_symmetric() {
        let mut env = TestEnv::default();
        let pin_protocol1 = PinProtocol::<TestEnv>::new(&mut env);
        let pin_protocol2 = PinProtocol::<TestEnv>::new(&mut env);
        for &protocol in &[PinUvAuthProtocol::V1, PinUvAuthProtocol::V2] {
            let shared_secret1 = pin_protocol1
                .decapsulate(pin_protocol2.get_public_key(), protocol)
                .unwrap();
            let shared_secret2 = pin_protocol2
                .decapsulate(pin_protocol1.get_public_key(), protocol)
                .unwrap();
            let mut plaintext = Secret::new(64);
            plaintext.fill(0xAA);
            let ciphertext = shared_secret1.encrypt(&mut env, &plaintext).unwrap();
            assert_eq!(plaintext, shared_secret2.decrypt(&ciphertext).unwrap());
        }
    }

    #[test]
    fn test_verify_pin_uv_auth_token_v1() {
        let token = [0x91; PIN_TOKEN_LENGTH];
        let message = [0xAA];
        let signature = [
            0x9C, 0x1C, 0xFE, 0x9D, 0xD7, 0x64, 0x6A, 0x06, 0xB9, 0xA8, 0x0F, 0x96, 0xAD, 0x50,
            0x49, 0x68,
        ];
        assert_eq!(
            verify_pin_uv_auth_token::<TestEnv>(
                &token,
                &message,
                &signature,
                PinUvAuthProtocol::V1
            ),
            Ok(())
        );
        assert_eq!(
            verify_pin_uv_auth_token::<TestEnv>(
                &[0x12; PIN_TOKEN_LENGTH],
                &message,
                &signature,
                PinUvAuthProtocol::V1
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            verify_pin_uv_auth_token::<TestEnv>(&token, &[0xBB], &signature, PinUvAuthProtocol::V1),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            verify_pin_uv_auth_token::<TestEnv>(
                &token,
                &message,
                &[0x12; 16],
                PinUvAuthProtocol::V1
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_verify_pin_uv_auth_token_v2() {
        let token = [0x91; PIN_TOKEN_LENGTH];
        let message = [0xAA];
        let signature = [
            0x9C, 0x1C, 0xFE, 0x9D, 0xD7, 0x64, 0x6A, 0x06, 0xB9, 0xA8, 0x0F, 0x96, 0xAD, 0x50,
            0x49, 0x68, 0x94, 0x90, 0x20, 0x53, 0x0F, 0xA3, 0xD2, 0x7A, 0x9F, 0xFD, 0xFA, 0x62,
            0x36, 0x93, 0xF7, 0x84,
        ];
        assert_eq!(
            verify_pin_uv_auth_token::<TestEnv>(
                &token,
                &message,
                &signature,
                PinUvAuthProtocol::V2
            ),
            Ok(())
        );
        assert_eq!(
            verify_pin_uv_auth_token::<TestEnv>(
                &[0x12; PIN_TOKEN_LENGTH],
                &message,
                &signature,
                PinUvAuthProtocol::V2
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            verify_pin_uv_auth_token::<TestEnv>(&token, &[0xBB], &signature, PinUvAuthProtocol::V2),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            verify_pin_uv_auth_token::<TestEnv>(
                &token,
                &message,
                &[0x12; 32],
                PinUvAuthProtocol::V2
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}
