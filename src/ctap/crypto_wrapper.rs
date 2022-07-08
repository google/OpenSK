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

use super::credential_id::CredentialId;
use super::data_formats::CredentialProtectionPolicy;
use crate::api::key_store::KeyStore;
use crate::ctap::data_formats::{
    extract_array, extract_byte_string, CoseKey, PublicKeyCredentialSource,
    PublicKeyCredentialType, SignatureAlgorithm,
};
use crate::ctap::status_code::Ctap2StatusCode;
use crate::env::Env;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use crypto::cbc::{cbc_decrypt, cbc_encrypt};
use crypto::ecdsa;
use crypto::sha256::Sha256;
use rng256::Rng256;
use sk_cbor as cbor;
use sk_cbor::{cbor_array, cbor_bytes, cbor_int};

/// Wraps the AES256-CBC encryption to match what we need in CTAP.
pub fn aes256_cbc_encrypt(
    rng: &mut dyn Rng256,
    aes_enc_key: &crypto::aes256::EncryptionKey,
    plaintext: &[u8],
    embeds_iv: bool,
) -> Result<Vec<u8>, Ctap2StatusCode> {
    if plaintext.len() % 16 != 0 {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    // The extra 1 capacity is because encrypt_key_handle adds a version number.
    let mut ciphertext = Vec::with_capacity(plaintext.len() + 16 * embeds_iv as usize + 1);
    let iv = if embeds_iv {
        let random_bytes = rng.gen_uniform_u8x32();
        ciphertext.extend_from_slice(&random_bytes[..16]);
        *array_ref!(ciphertext, 0, 16)
    } else {
        [0u8; 16]
    };
    let start = ciphertext.len();
    ciphertext.extend_from_slice(plaintext);
    cbc_encrypt(aes_enc_key, iv, &mut ciphertext[start..]);
    Ok(ciphertext)
}

/// Wraps the AES256-CBC decryption to match what we need in CTAP.
pub fn aes256_cbc_decrypt(
    aes_enc_key: &crypto::aes256::EncryptionKey,
    ciphertext: &[u8],
    embeds_iv: bool,
) -> Result<Vec<u8>, Ctap2StatusCode> {
    if ciphertext.len() % 16 != 0 || (embeds_iv && ciphertext.is_empty()) {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    let (iv, ciphertext) = if embeds_iv {
        let (iv, ciphertext) = ciphertext.split_at(16);
        (*array_ref!(iv, 0, 16), ciphertext)
    } else {
        ([0u8; 16], ciphertext)
    };
    let mut plaintext = ciphertext.to_vec();
    let aes_dec_key = crypto::aes256::DecryptionKey::new(aes_enc_key);
    cbc_decrypt(&aes_dec_key, iv, &mut plaintext);
    Ok(plaintext)
}

/// An asymmetric private key that can sign messages.
#[derive(Clone, Debug)]
// We shouldn't compare private keys in prod without constant-time operations.
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum PrivateKey {
    // We store the seed instead of the key since we can't get the seed back from the key. We could
    // store both if we believe deriving the key is done more than once and costly.
    Ecdsa([u8; 32]),
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519_compact::SecretKey),
}

impl PrivateKey {
    /// Creates a new private key for the given algorithm.
    ///
    /// # Panics
    ///
    /// Panics if the algorithm is [`SignatureAlgorithm::Unknown`].
    pub fn new(env: &mut impl Env, alg: SignatureAlgorithm) -> Self {
        match alg {
            SignatureAlgorithm::ES256 => {
                PrivateKey::Ecdsa(env.key_store().generate_ecdsa_seed().unwrap())
            }
            #[cfg(feature = "ed25519")]
            SignatureAlgorithm::EDDSA => {
                let bytes = env.rng().gen_uniform_u8x32();
                Self::new_ed25519_from_bytes(&bytes).unwrap()
            }
            SignatureAlgorithm::Unknown => unreachable!(),
        }
    }

    /// Creates a new ecdsa private key.
    pub fn new_ecdsa(env: &mut impl Env) -> PrivateKey {
        Self::new(env, SignatureAlgorithm::ES256)
    }

    /// Helper function that creates a private key of type ECDSA.
    ///
    /// This function is public for legacy credential source parsing only.
    pub fn new_ecdsa_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        Some(PrivateKey::Ecdsa(*array_ref!(bytes, 0, 32)))
    }

    #[cfg(feature = "ed25519")]
    pub fn new_ed25519_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let seed = ed25519_compact::Seed::from_slice(bytes).unwrap();
        Some(Self::Ed25519(ed25519_compact::KeyPair::from_seed(seed).sk))
    }

    /// Returns the ECDSA private key.
    pub fn ecdsa_key(&self, env: &mut impl Env) -> Result<ecdsa::SecKey, Ctap2StatusCode> {
        match self {
            PrivateKey::Ecdsa(seed) => ecdsa_key_from_seed(env, seed),
            #[allow(unreachable_patterns)]
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Returns the corresponding public key.
    pub fn get_pub_key(&self, env: &mut impl Env) -> Result<CoseKey, Ctap2StatusCode> {
        Ok(match self {
            PrivateKey::Ecdsa(ecdsa_seed) => {
                CoseKey::from(ecdsa_key_from_seed(env, ecdsa_seed)?.genpk())
            }
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(ed25519_key) => CoseKey::from(ed25519_key.public_key()),
        })
    }

    /// Returns the encoded signature for a given message.
    pub fn sign_and_encode(
        &self,
        env: &mut impl Env,
        message: &[u8],
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        Ok(match self {
            PrivateKey::Ecdsa(ecdsa_seed) => ecdsa_key_from_seed(env, ecdsa_seed)?
                .sign_rfc6979::<Sha256>(message)
                .to_asn1_der(),
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(ed25519_key) => ed25519_key.sign(message, None).to_vec(),
        })
    }

    /// The associated COSE signature algorithm identifier.
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            PrivateKey::Ecdsa(_) => SignatureAlgorithm::ES256,
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(_) => SignatureAlgorithm::EDDSA,
        }
    }

    /// Writes the key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PrivateKey::Ecdsa(ecdsa_seed) => ecdsa_seed.to_vec(),
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(ed25519_key) => ed25519_key.seed().to_vec(),
        }
    }
}

fn ecdsa_key_from_seed(
    env: &mut impl Env,
    seed: &[u8; 32],
) -> Result<ecdsa::SecKey, Ctap2StatusCode> {
    let ecdsa_bytes = env.key_store().derive_ecdsa(seed)?;
    Ok(ecdsa::SecKey::from_bytes(&ecdsa_bytes).unwrap())
}

impl From<&PrivateKey> for cbor::Value {
    fn from(private_key: &PrivateKey) -> Self {
        cbor_array![
            cbor_int!(private_key.signature_algorithm() as i64),
            cbor_bytes!(private_key.to_bytes()),
        ]
    }
}

impl From<PrivateKey> for cbor::Value {
    fn from(private_key: PrivateKey) -> Self {
        cbor_array![
            cbor_int!(private_key.signature_algorithm() as i64),
            cbor_bytes!(private_key.to_bytes()),
        ]
    }
}

impl TryFrom<cbor::Value> for PrivateKey {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        let mut array = extract_array(cbor_value)?;
        if array.len() != 2 {
            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR);
        }
        let key_bytes = extract_byte_string(array.pop().unwrap())?;
        match SignatureAlgorithm::try_from(array.pop().unwrap())? {
            SignatureAlgorithm::ES256 => PrivateKey::new_ecdsa_from_bytes(&key_bytes)
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            #[cfg(feature = "ed25519")]
            SignatureAlgorithm::EDDSA => PrivateKey::new_ed25519_from_bytes(&key_bytes)
                .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
        }
    }
}

/// Encrypts the given data into a credential ID, see CredentialId::encrypt_to_bytes.
pub fn encrypt_key_handle(
    env: &mut impl Env,
    private_key: &PrivateKey,
    rp_id_hash: &[u8; 32],
    cred_protect_policy: Option<CredentialProtectionPolicy>,
) -> Result<Vec<u8>, Ctap2StatusCode> {
    CredentialId::encrypt_to_bytes(env, private_key, rp_id_hash, cred_protect_policy)
}

/// Decrypts a credential ID and writes the private key into a PublicKeyCredentialSource.
///
/// Returns None if
/// - the format does not match any known versions,
/// - the HMAC test fails or
/// - the relying party does not match the decrypted relying party ID hash.
pub fn decrypt_credential_source(
    env: &mut impl Env,
    credential_id_bytes: Vec<u8>,
    rp_id_hash: &[u8],
) -> Result<Option<PublicKeyCredentialSource>, Ctap2StatusCode> {
    CredentialId::decrypt_from_bytes(env, credential_id_bytes.clone()).map(|cred_id| {
        cred_id.and_then(|cred_id| {
            if rp_id_hash != cred_id.rp_id_hash {
                return None;
            }
            Some(PublicKeyCredentialSource {
                key_type: PublicKeyCredentialType::PublicKey,
                credential_id: credential_id_bytes,
                private_key: cred_id.private_key,
                rp_id: String::new(),
                user_handle: Vec::new(),
                user_display_name: None,
                cred_protect_policy: cred_id.cred_protect_policy,
                creation_order: 0,
                user_name: None,
                user_icon: None,
                cred_blob: None,
                large_blob_key: None,
            })
        })
    })
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "ed25519")]
    use crate::ctap::credential_id::ED25519_CREDENTIAL_ID_VERSION;
    use crate::ctap::credential_id::{CBOR_CREDENTIAL_ID_SIZE, ECDSA_CREDENTIAL_ID_VERSION};
    use crate::env::test::TestEnv;
    use crypto::hmac::hmac_256;

    const UNSUPPORTED_CREDENTIAL_ID_VERSION: u8 = 0x80;

    #[test]
    fn test_encrypt_decrypt_with_iv() {
        let mut env = TestEnv::new();
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let ciphertext = aes256_cbc_encrypt(env.rng(), &aes_enc_key, &plaintext, true).unwrap();
        let decrypted = aes256_cbc_decrypt(&aes_enc_key, &ciphertext, true).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_without_iv() {
        let mut env = TestEnv::new();
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let ciphertext = aes256_cbc_encrypt(env.rng(), &aes_enc_key, &plaintext, false).unwrap();
        let decrypted = aes256_cbc_decrypt(&aes_enc_key, &ciphertext, false).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_correct_iv_usage() {
        let mut env = TestEnv::new();
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let mut ciphertext_no_iv =
            aes256_cbc_encrypt(env.rng(), &aes_enc_key, &plaintext, false).unwrap();
        let mut ciphertext_with_iv = vec![0u8; 16];
        ciphertext_with_iv.append(&mut ciphertext_no_iv);
        let decrypted = aes256_cbc_decrypt(&aes_enc_key, &ciphertext_with_iv, true).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_iv_manipulation_property() {
        let mut env = TestEnv::new();
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let mut ciphertext = aes256_cbc_encrypt(env.rng(), &aes_enc_key, &plaintext, true).unwrap();
        let mut expected_plaintext = plaintext;
        for i in 0..16 {
            ciphertext[i] ^= 0xBB;
            expected_plaintext[i] ^= 0xBB;
        }
        let decrypted = aes256_cbc_decrypt(&aes_enc_key, &ciphertext, true).unwrap();
        assert_eq!(decrypted, expected_plaintext);
    }

    #[test]
    fn test_chaining() {
        let mut env = TestEnv::new();
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&[0xC2; 32]);
        let plaintext = vec![0xAA; 64];
        let ciphertext1 = aes256_cbc_encrypt(env.rng(), &aes_enc_key, &plaintext, true).unwrap();
        let ciphertext2 = aes256_cbc_encrypt(env.rng(), &aes_enc_key, &plaintext, true).unwrap();
        assert_eq!(ciphertext1.len(), 80);
        assert_eq!(ciphertext2.len(), 80);
        // The ciphertext should mutate in all blocks with a different IV.
        let block_iter1 = ciphertext1.chunks_exact(16);
        let block_iter2 = ciphertext2.chunks_exact(16);
        for (block1, block2) in block_iter1.zip(block_iter2) {
            assert_ne!(block1, block2);
        }
    }

    #[test]
    fn test_new_ecdsa_from_bytes() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::ES256);
        let key_bytes = private_key.to_bytes();
        assert_eq!(
            PrivateKey::new_ecdsa_from_bytes(&key_bytes),
            Some(private_key)
        );
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_new_ed25519_from_bytes() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::EDDSA);
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
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let ecdsa_key = private_key.ecdsa_key(&mut env).unwrap();
        let public_key = ecdsa_key.genpk();
        assert_eq!(
            private_key.get_pub_key(&mut env),
            Ok(CoseKey::from(public_key))
        );
    }

    #[test]
    fn test_private_key_sign_and_encode() {
        let mut env = TestEnv::new();
        let message = [0x5A; 32];
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let ecdsa_key = private_key.ecdsa_key(&mut env).unwrap();
        let signature = ecdsa_key.sign_rfc6979::<Sha256>(&message).to_asn1_der();
        assert_eq!(
            private_key.sign_and_encode(&mut env, &message),
            Ok(signature)
        );
    }

    fn test_private_key_signature_algorithm(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);
        assert_eq!(private_key.signature_algorithm(), signature_algorithm);
    }

    #[test]
    fn test_ecdsa_private_key_signature_algorithm() {
        test_private_key_signature_algorithm(SignatureAlgorithm::ES256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_private_key_signature_algorithm() {
        test_private_key_signature_algorithm(SignatureAlgorithm::EDDSA);
    }

    fn test_private_key_from_to_cbor(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);
        let cbor = cbor::Value::from(private_key.clone());
        assert_eq!(PrivateKey::try_from(cbor), Ok(private_key),);
    }

    #[test]
    fn test_ecdsa_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::ES256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_private_key_from_to_cbor() {
        test_private_key_from_to_cbor(SignatureAlgorithm::EDDSA);
    }

    fn test_private_key_from_bad_cbor(signature_algorithm: SignatureAlgorithm) {
        let cbor = cbor_array![
            cbor_int!(signature_algorithm as i64),
            cbor_bytes!(vec![0x88; 32]),
            // The array is too long.
            cbor_int!(0),
        ];
        assert_eq!(
            PrivateKey::try_from(cbor),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
        );
    }

    #[test]
    fn test_ecdsa_private_key_from_bad_cbor() {
        test_private_key_from_bad_cbor(SignatureAlgorithm::ES256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_private_key_from_bad_cbor() {
        test_private_key_from_bad_cbor(SignatureAlgorithm::EDDSA);
    }

    #[test]
    fn test_private_key_from_bad_cbor_unsupported_algo() {
        let cbor = cbor_array![
            // This algorithms doesn't exist.
            cbor_int!(-1),
            cbor_bytes!(vec![0x88; 32]),
        ];
        assert_eq!(
            PrivateKey::try_from(cbor),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
        );
    }

    fn test_encrypt_decrypt_credential(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);

        let rp_id_hash = [0x55; 32];
        let encrypted_id = encrypt_key_handle(&mut env, &private_key, &rp_id_hash, None).unwrap();
        let decrypted_source = decrypt_credential_source(&mut env, encrypted_id, &rp_id_hash)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, decrypted_source.private_key);
    }

    #[test]
    fn test_encrypt_decrypt_ecdsa_credential() {
        test_encrypt_decrypt_credential(SignatureAlgorithm::ES256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_encrypt_decrypt_ed25519_credential() {
        test_encrypt_decrypt_credential(SignatureAlgorithm::EDDSA);
    }

    #[test]
    fn test_encrypt_decrypt_bad_version() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::ES256);

        let rp_id_hash = [0x55; 32];
        let mut encrypted_id =
            encrypt_key_handle(&mut env, &private_key, &rp_id_hash, None).unwrap();
        encrypted_id[0] = UNSUPPORTED_CREDENTIAL_ID_VERSION;
        // Override the HMAC to pass the check.
        encrypted_id.truncate(&encrypted_id.len() - 32);
        let hmac_key = env.key_store().key_handle_authentication().unwrap();
        let id_hmac = hmac_256::<Sha256>(&hmac_key, &encrypted_id[..]);
        encrypted_id.extend(&id_hmac);

        assert_eq!(
            decrypt_credential_source(&mut env, encrypted_id, &rp_id_hash),
            Ok(None)
        );
    }

    fn test_encrypt_decrypt_bad_hmac(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);

        let rp_id_hash = [0x55; 32];
        let encrypted_id = encrypt_key_handle(&mut env, &private_key, &rp_id_hash, None).unwrap();
        for i in 0..encrypted_id.len() {
            let mut modified_id = encrypted_id.clone();
            modified_id[i] ^= 0x01;
            assert_eq!(
                decrypt_credential_source(&mut env, modified_id, &rp_id_hash),
                Ok(None)
            );
        }
    }

    #[test]
    fn test_ecdsa_encrypt_decrypt_bad_hmac() {
        test_encrypt_decrypt_bad_hmac(SignatureAlgorithm::ES256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_encrypt_decrypt_bad_hmac() {
        test_encrypt_decrypt_bad_hmac(SignatureAlgorithm::EDDSA);
    }

    fn test_decrypt_credential_missing_blocks(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);

        let rp_id_hash = [0x55; 32];
        let encrypted_id = encrypt_key_handle(&mut env, &private_key, &rp_id_hash, None).unwrap();

        for length in (1..CBOR_CREDENTIAL_ID_SIZE).step_by(16) {
            assert_eq!(
                decrypt_credential_source(&mut env, encrypted_id[..length].to_vec(), &rp_id_hash),
                Ok(None)
            );
        }
    }

    #[test]
    fn test_ecdsa_decrypt_credential_missing_blocks() {
        test_decrypt_credential_missing_blocks(SignatureAlgorithm::ES256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_decrypt_credential_missing_blocks() {
        test_decrypt_credential_missing_blocks(SignatureAlgorithm::EDDSA);
    }

    /// This is a copy of the function that genereated deprecated v1 and v2 key handles.
    pub fn legacy_encrypt_versioned_key_handle(
        env: &mut impl Env,
        private_key: &PrivateKey,
        application: &[u8; 32],
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let aes_enc_key =
            crypto::aes256::EncryptionKey::new(&env.key_store().key_handle_encryption()?);

        let mut plaintext = [0; 64];
        let version = match private_key {
            PrivateKey::Ecdsa(ecdsa_seed) => {
                plaintext[..32].copy_from_slice(ecdsa_seed);
                ECDSA_CREDENTIAL_ID_VERSION
            }
            #[cfg(feature = "ed25519")]
            PrivateKey::Ed25519(ed25519_key) => {
                let sk_bytes = *ed25519_key.seed();
                plaintext[0..32].copy_from_slice(&sk_bytes);
                ED25519_CREDENTIAL_ID_VERSION
            }
        };
        plaintext[32..64].copy_from_slice(application);
        let mut encrypted_id = aes256_cbc_encrypt(env.rng(), &aes_enc_key, &plaintext, true)?;
        encrypted_id.insert(0, version);

        let id_hmac = hmac_256::<Sha256>(
            &env.key_store().key_handle_authentication()?,
            &encrypted_id[..],
        );
        encrypted_id.extend(&id_hmac);
        Ok(encrypted_id)
    }

    /// This is a copy of the function that genereated deprecated key handles.
    fn legacy_encrypt_key_handle(
        env: &mut impl Env,
        private_key: crypto::ecdsa::SecKey,
        application: &[u8; 32],
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let aes_enc_key =
            crypto::aes256::EncryptionKey::new(&env.key_store().key_handle_encryption()?);
        let mut plaintext = [0; 64];
        private_key.to_bytes(array_mut_ref!(plaintext, 0, 32));
        plaintext[32..64].copy_from_slice(application);

        let mut encrypted_id = aes256_cbc_encrypt(env.rng(), &aes_enc_key, &plaintext, true)?;
        let id_hmac = hmac_256::<Sha256>(
            &env.key_store().key_handle_authentication()?,
            &encrypted_id[..],
        );
        encrypted_id.extend(&id_hmac);
        Ok(encrypted_id)
    }

    #[test]
    fn test_encrypt_decrypt_credential_legacy() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let ecdsa_key = private_key.ecdsa_key(&mut env).unwrap();

        let rp_id_hash = [0x55; 32];
        let encrypted_id = legacy_encrypt_key_handle(&mut env, ecdsa_key, &rp_id_hash).unwrap();
        let decrypted_source = decrypt_credential_source(&mut env, encrypted_id, &rp_id_hash)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, decrypted_source.private_key);
    }

    fn test_encrypt_decrypt_credential_legacy_versioned(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);

        let rp_id_hash = [0x55; 32];
        let encrypted_id =
            legacy_encrypt_versioned_key_handle(&mut env, &private_key, &rp_id_hash).unwrap();
        let decrypted_source = decrypt_credential_source(&mut env, encrypted_id, &rp_id_hash)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, decrypted_source.private_key);
    }

    #[test]
    fn test_ecdsa_encrypt_decrypt_credential_legacy_versioned() {
        test_encrypt_decrypt_credential_legacy_versioned(SignatureAlgorithm::ES256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_encrypt_decrypt_credential_legacy_versioned() {
        test_encrypt_decrypt_credential_legacy_versioned(SignatureAlgorithm::EDDSA);
    }

    #[test]
    fn test_encrypt_credential_size() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::ES256);

        let rp_id_hash = [0x55; 32];
        let encrypted_id = encrypt_key_handle(&mut env, &private_key, &rp_id_hash, None).unwrap();
        assert_eq!(encrypted_id.len(), CBOR_CREDENTIAL_ID_SIZE);
    }
}
