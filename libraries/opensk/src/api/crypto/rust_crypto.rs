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

use crate::api::crypto::aes256::Aes256;
use crate::api::crypto::hkdf256::Hkdf256;
use crate::api::crypto::hmac256::Hmac256;
use crate::api::crypto::sha256::Sha256;
use crate::api::crypto::{
    ec_signing, ecdh, Crypto, AES_BLOCK_SIZE, AES_KEY_SIZE, EC_FIELD_SIZE, EC_SIGNATURE_SIZE,
    HASH_SIZE, HMAC_KEY_SIZE, TRUNCATED_HMAC_SIZE,
};
use crate::api::rng::Rng;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{
    BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit,
};
use alloc::vec::Vec;
#[cfg(test)]
use core::cell::RefCell;
#[cfg(feature = "ed25519")]
use der::{Any, Encode};
use hmac::digest::FixedOutput;
use hmac::Mac;
use p256::ecdh::EphemeralSecret;
#[cfg(test)]
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::signature::{SignatureEncoding, Signer as _};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Digest;
#[cfg(test)]
use std::sync::{Mutex, MutexGuard};

// To be able to support hardware cryptography, we want to make sure we never compute multiple
// sha256 in parallel. Note that calling `digest` or `digest_mut` is statically correct.
// These variables track whether `new` was called but `finalize` wasn't called yet.
#[cfg(test)]
static BUSY: Mutex<()> = Mutex::new(());
#[cfg(test)]
thread_local! {
    static BUSY_GUARD: RefCell<Option<MutexGuard<'static, ()>>> = RefCell::new(None);
}

pub struct SoftwareCrypto;
pub struct SoftwareEcdh;
pub struct SoftwareEcdsa;
#[cfg(feature = "ed25519")]
pub struct SoftwareEd25519;

impl Crypto for SoftwareCrypto {
    type Aes256 = SoftwareAes256;
    type Ecdh = SoftwareEcdh;
    type Ecdsa = SoftwareEcdsa;
    #[cfg(feature = "ed25519")]
    type Ed25519 = SoftwareEd25519;
    type Sha256 = SoftwareSha256;
    type Hmac256 = SoftwareHmac256;
    type Hkdf256 = SoftwareHkdf256;
}

impl ecdh::Ecdh for SoftwareEcdh {
    type SecretKey = SoftwareEcdhSecretKey;
    type PublicKey = SoftwareEcdhPublicKey;
    type SharedSecret = SoftwareEcdhSharedSecret;
}

pub struct SoftwareEcdhSecretKey {
    ephemeral_secret: EphemeralSecret,
}

impl ecdh::SecretKey for SoftwareEcdhSecretKey {
    type PublicKey = SoftwareEcdhPublicKey;
    type SharedSecret = SoftwareEcdhSharedSecret;

    fn random(rng: &mut impl Rng) -> Self {
        let ephemeral_secret = EphemeralSecret::random(rng);
        Self { ephemeral_secret }
    }

    fn public_key(&self) -> Self::PublicKey {
        let public_key = self.ephemeral_secret.public_key();
        SoftwareEcdhPublicKey { public_key }
    }

    fn diffie_hellman(&self, public_key: &SoftwareEcdhPublicKey) -> Self::SharedSecret {
        let shared_secret = self.ephemeral_secret.diffie_hellman(&public_key.public_key);
        SoftwareEcdhSharedSecret { shared_secret }
    }
}

pub struct SoftwareEcdhPublicKey {
    public_key: p256::PublicKey,
}

impl ecdh::PublicKey for SoftwareEcdhPublicKey {
    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], y: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        let encoded_point: p256::EncodedPoint =
            p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let public_key = p256::PublicKey::from_sec1_bytes(encoded_point.as_bytes()).ok()?;
        Some(Self { public_key })
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        let point = self.public_key.to_encoded_point(false);
        x.copy_from_slice(point.x().unwrap());
        y.copy_from_slice(point.y().unwrap());
    }
}

pub struct SoftwareEcdhSharedSecret {
    shared_secret: p256::ecdh::SharedSecret,
}

impl ecdh::SharedSecret for SoftwareEcdhSharedSecret {
    fn raw_secret_bytes(&self, secret: &mut [u8; EC_FIELD_SIZE]) {
        secret.copy_from_slice(self.shared_secret.raw_secret_bytes().as_slice());
    }
}

impl ec_signing::EcSigning for SoftwareEcdsa {
    type SecretKey = SoftwareEcdsaSecretKey;
    type PublicKey = SoftwareEcdsaPublicKey;
    type Signature = SoftwareEcdsaSignature;
}

pub struct SoftwareEcdsaSecretKey {
    signing_key: p256::ecdsa::SigningKey,
}

impl ec_signing::SecretKey for SoftwareEcdsaSecretKey {
    type PublicKey = SoftwareEcdsaPublicKey;
    type Signature = SoftwareEcdsaSignature;

    fn random(rng: &mut impl Rng) -> Self {
        let signing_key = p256::ecdsa::SigningKey::random(rng);
        SoftwareEcdsaSecretKey { signing_key }
    }

    fn public_key(&self) -> Self::PublicKey {
        let verifying_key = p256::ecdsa::VerifyingKey::from(&self.signing_key);
        SoftwareEcdsaPublicKey { verifying_key }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = self.signing_key.sign(message);
        SoftwareEcdsaSignature { signature }
    }

    fn export(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    fn import(bytes: &[u8]) -> Option<Self> {
        let signing_key = p256::ecdsa::SigningKey::from_slice(bytes).ok()?;
        Some(SoftwareEcdsaSecretKey { signing_key })
    }
}

pub struct SoftwareEcdsaPublicKey {
    verifying_key: p256::ecdsa::VerifyingKey,
}

impl ec_signing::PublicKey for SoftwareEcdsaPublicKey {
    type Signature = SoftwareEcdsaSignature;

    #[cfg(test)]
    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], y: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        let encoded_point: p256::EncodedPoint =
            p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point).ok()?;
        Some(SoftwareEcdsaPublicKey { verifying_key })
    }

    #[cfg(test)]
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.verifying_key
            .verify(message, &signature.signature)
            .is_ok()
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        let point = self.verifying_key.to_encoded_point(false);
        x.copy_from_slice(point.x().unwrap());
        y.copy_from_slice(point.y().unwrap());
    }
}

pub struct SoftwareEcdsaSignature {
    signature: p256::ecdsa::Signature,
}

impl ec_signing::Signature for SoftwareEcdsaSignature {
    #[cfg(test)]
    fn from_slice(bytes: &[u8; EC_SIGNATURE_SIZE]) -> Option<Self> {
        // Assumes EC_SIGNATURE_SIZE == 2 * EC_FIELD_SIZE
        let signature = p256::ecdsa::Signature::from_slice(bytes).ok()?;
        Some(SoftwareEcdsaSignature { signature })
    }

    fn to_slice(&self, bytes: &mut [u8; EC_SIGNATURE_SIZE]) {
        bytes.copy_from_slice(&self.signature.to_bytes());
    }

    fn to_der(&self) -> Vec<u8> {
        self.signature.to_der().to_vec()
    }
}

#[cfg(feature = "ed25519")]
impl ec_signing::EcSigning for SoftwareEd25519 {
    type SecretKey = SoftwareEd25519SecretKey;
    type PublicKey = SoftwareEd25519PublicKey;
    type Signature = SoftwareEd25519Signature;
}

#[cfg(feature = "ed25519")]
pub struct SoftwareEd25519SecretKey {
    signing_key: ed25519_compact::SecretKey,
}

#[cfg(feature = "ed25519")]
impl ec_signing::SecretKey for SoftwareEd25519SecretKey {
    type PublicKey = SoftwareEd25519PublicKey;
    type Signature = SoftwareEd25519Signature;

    fn random(rng: &mut impl Rng) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes[..]);
        let seed = ed25519_compact::Seed::from_slice(&bytes).unwrap();
        let signing_key = ed25519_compact::KeyPair::from_seed(seed).sk;
        SoftwareEd25519SecretKey { signing_key }
    }

    fn public_key(&self) -> Self::PublicKey {
        SoftwareEd25519PublicKey {
            verifying_key: self.signing_key.public_key(),
        }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = self.signing_key.sign(message, None);
        SoftwareEd25519Signature { signature }
    }

    fn export(&self) -> Vec<u8> {
        self.signing_key[..].to_vec()
    }

    fn import(bytes: &[u8]) -> Option<Self> {
        let signing_key = ed25519_compact::SecretKey::from_slice(bytes).ok()?;
        Some(SoftwareEd25519SecretKey { signing_key })
    }
}

#[cfg(feature = "ed25519")]
pub struct SoftwareEd25519PublicKey {
    verifying_key: ed25519_compact::PublicKey,
}

#[cfg(feature = "ed25519")]
impl ec_signing::PublicKey for SoftwareEd25519PublicKey {
    type Signature = SoftwareEd25519Signature;

    #[cfg(test)]
    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], _y: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        let verifying_key = ed25519_compact::PublicKey::from_slice(x).ok()?;
        // The y coordinate is unused when exporting and importing.
        Some(SoftwareEd25519PublicKey { verifying_key })
    }

    #[cfg(test)]
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.verifying_key
            .verify(message, &signature.signature)
            .is_ok()
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        x.copy_from_slice(&self.verifying_key[..]);
        // The public key can be reconstructed from the x slice only.
        y.copy_from_slice(&[0u8; 32]);
    }
}

#[cfg(feature = "ed25519")]
pub struct SoftwareEd25519Signature {
    signature: ed25519_compact::Signature,
}

#[cfg(feature = "ed25519")]
impl ec_signing::Signature for SoftwareEd25519Signature {
    #[cfg(test)]
    fn from_slice(bytes: &[u8; EC_SIGNATURE_SIZE]) -> Option<Self> {
        // Assumes EC_SIGNATURE_SIZE == 64
        let signature = ed25519_compact::Signature::from_slice(bytes).ok()?;
        Some(SoftwareEd25519Signature { signature })
    }

    fn to_slice(&self, bytes: &mut [u8; EC_SIGNATURE_SIZE]) {
        bytes.copy_from_slice(&self.signature[..]);
    }

    fn to_der(&self) -> Vec<u8> {
        // The ECDSA implementation has implicit unwraps, too.
        let signature_any = Any::new(der::Tag::OctetString, &self.signature[..]).unwrap();
        signature_any.to_der().unwrap()
    }
}

pub struct SoftwareSha256 {
    hasher: sha2::Sha256,
}

impl Sha256 for SoftwareSha256 {
    fn digest(data: &[u8]) -> [u8; HASH_SIZE] {
        sha2::Sha256::digest(data).into()
    }

    fn new() -> Self {
        #[cfg(test)]
        BUSY_GUARD.with_borrow_mut(|guard| {
            assert!(guard.is_none());
            *guard = Some(BUSY.lock().unwrap());
        });
        let hasher = sha2::Sha256::new();
        Self { hasher }
    }

    /// Digest the next part of the message to hash.
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalizes the hashing process, returns the hash value.
    fn finalize(self, output: &mut [u8; HASH_SIZE]) {
        FixedOutput::finalize_into(self.hasher, output.into());
        #[cfg(test)]
        BUSY_GUARD.with_borrow_mut(|guard| {
            assert!(guard.is_some());
            *guard = None;
        });
    }
}

pub struct SoftwareHmac256;

impl Hmac256 for SoftwareHmac256 {
    fn mac(key: &[u8; HMAC_KEY_SIZE], data: &[u8], output: &mut [u8; HASH_SIZE]) {
        let mut hmac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key).unwrap();
        hmac.update(data);
        hmac.finalize_into(output.into());
    }

    fn verify(key: &[u8; HMAC_KEY_SIZE], data: &[u8], mac: &[u8; HASH_SIZE]) -> bool {
        let mut hmac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key).unwrap();
        hmac.update(data);
        hmac.verify_slice(mac).is_ok()
    }

    fn verify_truncated_left(
        key: &[u8; HMAC_KEY_SIZE],
        data: &[u8],
        mac: &[u8; TRUNCATED_HMAC_SIZE],
    ) -> bool {
        let mut hmac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key).unwrap();
        hmac.update(data);
        hmac.verify_truncated_left(mac).is_ok()
    }
}

pub struct SoftwareHkdf256;

impl Hkdf256 for SoftwareHkdf256 {
    fn hkdf_256(ikm: &[u8], salt: &[u8; HASH_SIZE], info: &[u8], okm: &mut [u8; HASH_SIZE]) {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
        hk.expand(info, okm).unwrap();
    }
}

pub struct SoftwareAes256 {
    key: [u8; AES_KEY_SIZE],
}

impl Aes256 for SoftwareAes256 {
    fn new(key: &[u8; AES_KEY_SIZE]) -> Self {
        SoftwareAes256 { key: *key }
    }

    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        let cipher = aes::Aes256::new_from_slice(&self.key).unwrap();
        cipher.encrypt_block(block.into());
    }

    fn decrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        let cipher = aes::Aes256::new_from_slice(&self.key).unwrap();
        cipher.decrypt_block(block.into());
    }

    fn encrypt_cbc(&self, iv: &[u8; AES_BLOCK_SIZE], plaintext: &mut [u8]) {
        let mut encryptor = cbc::Encryptor::<aes::Aes256>::new_from_slices(&self.key, iv).unwrap();
        for block in plaintext.chunks_mut(AES_BLOCK_SIZE) {
            encryptor.encrypt_block_mut(GenericArray::from_mut_slice(block));
        }
    }

    fn decrypt_cbc(&self, iv: &[u8; AES_BLOCK_SIZE], ciphertext: &mut [u8]) {
        let mut decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(&self.key, iv).unwrap();
        for block in ciphertext.chunks_mut(AES_BLOCK_SIZE) {
            decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
        }
    }
}
