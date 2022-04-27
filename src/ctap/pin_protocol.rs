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

use crate::ctap::client_pin::PIN_TOKEN_LENGTH;
use crate::ctap::crypto_wrapper::{aes256_cbc_decrypt, aes256_cbc_encrypt};
use crate::ctap::data_formats::{CoseKey, PinUvAuthProtocol};
use crate::ctap::status_code::Ctap2StatusCode;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::TryInto;
use crypto::hkdf::hkdf_empty_salt_256;
#[cfg(test)]
use crypto::hmac::hmac_256;
use crypto::hmac::{verify_hmac_256, verify_hmac_256_first_128bits};
use crypto::sha256::Sha256;
use crypto::Hash256;
use rng256::Rng256;

/// Implements common functions between existing PIN protocols for handshakes.
pub struct PinProtocol {
    key_agreement_key: crypto::ecdh::SecKey,
    pin_uv_auth_token: [u8; PIN_TOKEN_LENGTH],
}

impl PinProtocol {
    /// This process is run by the authenticator at power-on.
    ///
    /// This function implements "initialize" from the specification.
    pub fn new(rng: &mut impl Rng256) -> PinProtocol {
        let key_agreement_key = crypto::ecdh::SecKey::gensk(rng);
        let pin_uv_auth_token = rng.gen_uniform_u8x32();
        PinProtocol {
            key_agreement_key,
            pin_uv_auth_token,
        }
    }

    /// Generates a fresh public key.
    pub fn regenerate(&mut self, rng: &mut impl Rng256) {
        self.key_agreement_key = crypto::ecdh::SecKey::gensk(rng);
    }

    /// Generates a fresh pinUvAuthToken.
    pub fn reset_pin_uv_auth_token(&mut self, rng: &mut impl Rng256) {
        self.pin_uv_auth_token = rng.gen_uniform_u8x32();
    }

    /// Returns the authenticator’s public key as a CoseKey structure.
    pub fn get_public_key(&self) -> CoseKey {
        CoseKey::from(self.key_agreement_key.genpk())
    }

    /// Processes the peer's encapsulated CoseKey and returns the shared secret.
    pub fn decapsulate(
        &self,
        peer_cose_key: CoseKey,
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) -> Result<Box<dyn SharedSecret>, Ctap2StatusCode> {
        let pk: crypto::ecdh::PubKey = CoseKey::try_into(peer_cose_key)?;
        let handshake = self.key_agreement_key.exchange_x(&pk);
        match pin_uv_auth_protocol {
            PinUvAuthProtocol::V1 => Ok(Box::new(SharedSecretV1::new(handshake))),
            PinUvAuthProtocol::V2 => Ok(Box::new(SharedSecretV2::new(handshake))),
        }
    }

    /// Getter for pinUvAuthToken.
    pub fn get_pin_uv_auth_token(&self) -> &[u8; PIN_TOKEN_LENGTH] {
        &self.pin_uv_auth_token
    }

    /// This is used for debugging to inject key material.
    #[cfg(test)]
    pub fn new_test(
        key_agreement_key: crypto::ecdh::SecKey,
        pin_uv_auth_token: [u8; PIN_TOKEN_LENGTH],
    ) -> PinProtocol {
        PinProtocol {
            key_agreement_key,
            pin_uv_auth_token,
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
    match pin_uv_auth_protocol {
        PinUvAuthProtocol::V1 => hmac_256::<Sha256>(token, message)[..16].to_vec(),
        PinUvAuthProtocol::V2 => hmac_256::<Sha256>(token, message).to_vec(),
    }
}

/// Verifies the pinUvAuthToken for the given PIN protocol.
pub fn verify_pin_uv_auth_token(
    token: &[u8; PIN_TOKEN_LENGTH],
    message: &[u8],
    signature: &[u8],
    pin_uv_auth_protocol: PinUvAuthProtocol,
) -> Result<(), Ctap2StatusCode> {
    match pin_uv_auth_protocol {
        PinUvAuthProtocol::V1 => verify_v1(token, message, signature),
        PinUvAuthProtocol::V2 => verify_v2(token, message, signature),
    }
}

pub trait SharedSecret {
    /// Returns the encrypted plaintext.
    fn encrypt(&self, rng: &mut dyn Rng256, plaintext: &[u8]) -> Result<Vec<u8>, Ctap2StatusCode>;

    /// Returns the decrypted ciphertext.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Ctap2StatusCode>;

    /// Verifies that the signature is a valid MAC for the given message.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Ctap2StatusCode>;

    /// Creates a signature that matches verify.
    #[cfg(test)]
    fn authenticate(&self, message: &[u8]) -> Vec<u8>;
}

fn verify_v1(key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<(), Ctap2StatusCode> {
    if signature.len() != 16 {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    if verify_hmac_256_first_128bits::<Sha256>(key, message, array_ref![signature, 0, 16]) {
        Ok(())
    } else {
        Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
    }
}

fn verify_v2(key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<(), Ctap2StatusCode> {
    if signature.len() != 32 {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    if verify_hmac_256::<Sha256>(key, message, array_ref![signature, 0, 32]) {
        Ok(())
    } else {
        Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
    }
}

pub struct SharedSecretV1 {
    common_secret: [u8; 32],
    aes_enc_key: crypto::aes256::EncryptionKey,
}

impl SharedSecretV1 {
    /// Creates a new shared secret from the handshake result.
    fn new(handshake: [u8; 32]) -> SharedSecretV1 {
        let common_secret = Sha256::hash(&handshake);
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&common_secret);
        SharedSecretV1 {
            common_secret,
            aes_enc_key,
        }
    }
}

impl SharedSecret for SharedSecretV1 {
    fn encrypt(&self, rng: &mut dyn Rng256, plaintext: &[u8]) -> Result<Vec<u8>, Ctap2StatusCode> {
        aes256_cbc_encrypt(rng, &self.aes_enc_key, plaintext, false)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Ctap2StatusCode> {
        aes256_cbc_decrypt(&self.aes_enc_key, ciphertext, false)
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Ctap2StatusCode> {
        verify_v1(&self.common_secret, message, signature)
    }

    #[cfg(test)]
    fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        hmac_256::<Sha256>(&self.common_secret, message)[..16].to_vec()
    }
}

pub struct SharedSecretV2 {
    aes_enc_key: crypto::aes256::EncryptionKey,
    hmac_key: [u8; 32],
}

impl SharedSecretV2 {
    /// Creates a new shared secret from the handshake result.
    fn new(handshake: [u8; 32]) -> SharedSecretV2 {
        let aes_key = hkdf_empty_salt_256::<Sha256>(&handshake, b"CTAP2 AES key");
        SharedSecretV2 {
            aes_enc_key: crypto::aes256::EncryptionKey::new(&aes_key),
            hmac_key: hkdf_empty_salt_256::<Sha256>(&handshake, b"CTAP2 HMAC key"),
        }
    }
}

impl SharedSecret for SharedSecretV2 {
    fn encrypt(&self, rng: &mut dyn Rng256, plaintext: &[u8]) -> Result<Vec<u8>, Ctap2StatusCode> {
        aes256_cbc_encrypt(rng, &self.aes_enc_key, plaintext, true)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Ctap2StatusCode> {
        aes256_cbc_decrypt(&self.aes_enc_key, ciphertext, true)
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Ctap2StatusCode> {
        verify_v2(&self.hmac_key, message, signature)
    }

    #[cfg(test)]
    fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        hmac_256::<Sha256>(&self.hmac_key, message).to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;

    #[test]
    fn test_pin_protocol_public_key() {
        let mut env = TestEnv::new();
        let mut pin_protocol = PinProtocol::new(env.rng());
        let public_key = pin_protocol.get_public_key();
        pin_protocol.regenerate(env.rng());
        let new_public_key = pin_protocol.get_public_key();
        assert_ne!(public_key, new_public_key);
    }

    #[test]
    fn test_pin_protocol_pin_uv_auth_token() {
        let mut env = TestEnv::new();
        let mut pin_protocol = PinProtocol::new(env.rng());
        let token = *pin_protocol.get_pin_uv_auth_token();
        pin_protocol.reset_pin_uv_auth_token(env.rng());
        let new_token = pin_protocol.get_pin_uv_auth_token();
        assert_ne!(&token, new_token);
    }

    #[test]
    fn test_shared_secret_v1_encrypt_decrypt() {
        let mut env = TestEnv::new();
        let shared_secret = SharedSecretV1::new([0x55; 32]);
        let plaintext = vec![0xAA; 64];
        let ciphertext = shared_secret.encrypt(env.rng(), &plaintext).unwrap();
        assert_eq!(shared_secret.decrypt(&ciphertext), Ok(plaintext));
    }

    #[test]
    fn test_shared_secret_v1_authenticate_verify() {
        let shared_secret = SharedSecretV1::new([0x55; 32]);
        let message = [0xAA; 32];
        let signature = shared_secret.authenticate(&message);
        assert_eq!(shared_secret.verify(&message, &signature), Ok(()));
    }

    #[test]
    fn test_shared_secret_v1_verify() {
        let shared_secret = SharedSecretV1::new([0x55; 32]);
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
        let mut env = TestEnv::new();
        let shared_secret = SharedSecretV2::new([0x55; 32]);
        let plaintext = vec![0xAA; 64];
        let ciphertext = shared_secret.encrypt(env.rng(), &plaintext).unwrap();
        assert_eq!(shared_secret.decrypt(&ciphertext), Ok(plaintext));
    }

    #[test]
    fn test_shared_secret_v2_authenticate_verify() {
        let shared_secret = SharedSecretV2::new([0x55; 32]);
        let message = [0xAA; 32];
        let signature = shared_secret.authenticate(&message);
        assert_eq!(shared_secret.verify(&message, &signature), Ok(()));
    }

    #[test]
    fn test_shared_secret_v2_verify() {
        let shared_secret = SharedSecretV2::new([0x55; 32]);
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
        let mut env = TestEnv::new();
        let pin_protocol1 = PinProtocol::new(env.rng());
        let pin_protocol2 = PinProtocol::new(env.rng());
        for &protocol in &[PinUvAuthProtocol::V1, PinUvAuthProtocol::V2] {
            let shared_secret1 = pin_protocol1
                .decapsulate(pin_protocol2.get_public_key(), protocol)
                .unwrap();
            let shared_secret2 = pin_protocol2
                .decapsulate(pin_protocol1.get_public_key(), protocol)
                .unwrap();
            let plaintext = vec![0xAA; 64];
            let ciphertext = shared_secret1.encrypt(env.rng(), &plaintext).unwrap();
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
            verify_pin_uv_auth_token(&token, &message, &signature, PinUvAuthProtocol::V1),
            Ok(())
        );
        assert_eq!(
            verify_pin_uv_auth_token(
                &[0x12; PIN_TOKEN_LENGTH],
                &message,
                &signature,
                PinUvAuthProtocol::V1
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            verify_pin_uv_auth_token(&token, &[0xBB], &signature, PinUvAuthProtocol::V1),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            verify_pin_uv_auth_token(&token, &message, &[0x12; 16], PinUvAuthProtocol::V1),
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
            verify_pin_uv_auth_token(&token, &message, &signature, PinUvAuthProtocol::V2),
            Ok(())
        );
        assert_eq!(
            verify_pin_uv_auth_token(
                &[0x12; PIN_TOKEN_LENGTH],
                &message,
                &signature,
                PinUvAuthProtocol::V2
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            verify_pin_uv_auth_token(&token, &[0xBB], &signature, PinUvAuthProtocol::V2),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            verify_pin_uv_auth_token(&token, &message, &[0x12; 32], PinUvAuthProtocol::V2),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}
