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

use crate::ctap::data_formats::{
    extract_array, extract_byte_string, CoseKey, PublicKeyCredentialSource,
    PublicKeyCredentialType, SignatureAlgorithm,
};
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::storage;
use crate::env::Env;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::convert::TryFrom;
use crypto::cbc::{cbc_decrypt, cbc_encrypt};
use crypto::ecdsa;
use crypto::hmac::{hmac_256, verify_hmac_256};
use crypto::sha256::Sha256;
use rng256::Rng256;
use sk_cbor as cbor;
use sk_cbor::{cbor_array, cbor_bytes, cbor_int};

// Legacy credential IDs consist of
// - 16 bytes: initialization vector for AES-256,
// - 32 bytes: ECDSA private key for the credential,
// - 32 bytes: relying party ID hashed with SHA256,
// - 32 bytes: HMAC-SHA256 over everything else.
pub const LEGACY_CREDENTIAL_ID_SIZE: usize = 112;
#[cfg(test)]
pub const ECDSA_CREDENTIAL_ID_SIZE: usize = 129;
// See encrypt_key_handle v1 documentation.
pub const MAX_CREDENTIAL_ID_SIZE: usize = 129;

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateKey {
    Ecdsa(ecdsa::SecKey),
}

impl PrivateKey {
    /// Creates a new private key for the given algorithm.
    ///
    /// # Panics
    ///
    /// Panics if the algorithm is [`SignatureAlgorithm::Unknown`].
    pub fn new(rng: &mut impl Rng256, alg: SignatureAlgorithm) -> Self {
        match alg {
            SignatureAlgorithm::ES256 => PrivateKey::Ecdsa(crypto::ecdsa::SecKey::gensk(rng)),
            SignatureAlgorithm::Unknown => unreachable!(),
        }
    }

    /// Helper function that creates a private key of type ECDSA.
    ///
    /// This function is public for legacy credential source parsing only.
    pub fn new_ecdsa_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        ecdsa::SecKey::from_bytes(array_ref!(bytes, 0, 32)).map(PrivateKey::from)
    }

    /// Returns the corresponding public key.
    pub fn get_pub_key(&self) -> CoseKey {
        match self {
            PrivateKey::Ecdsa(ecdsa_key) => CoseKey::from(ecdsa_key.genpk()),
        }
    }

    /// Returns the encoded signature for a given message.
    pub fn sign_and_encode(&self, message: &[u8]) -> Vec<u8> {
        match self {
            PrivateKey::Ecdsa(ecdsa_key) => ecdsa_key.sign_rfc6979::<Sha256>(message).to_asn1_der(),
        }
    }

    /// The associated COSE signature algorithm identifier.
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            PrivateKey::Ecdsa(_) => SignatureAlgorithm::ES256,
        }
    }

    /// Writes the key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PrivateKey::Ecdsa(ecdsa_key) => {
                let mut key_bytes = vec![0u8; 32];
                ecdsa_key.to_bytes(array_mut_ref!(key_bytes, 0, 32));
                key_bytes
            }
        }
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
            _ => Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
        }
    }
}

impl From<ecdsa::SecKey> for PrivateKey {
    fn from(ecdsa_key: ecdsa::SecKey) -> Self {
        PrivateKey::Ecdsa(ecdsa_key)
    }
}

/// Encrypts the given private key and relying party ID hash into a credential ID.
///
/// Other information, such as a user name, are not stored. Since encrypted credential IDs are
/// stored server-side, this information is already available (unencrypted).
///
/// Also, by limiting ourselves to private key and RP ID hash, we are compatible with U2F for
/// ECDSA private keys.
///
/// This is v1, and we write the following data for ECDSA (algorithm -7):
/// -  1 byte : version number
/// - 16 bytes: initialization vector for AES-256,
/// -  4 bytes: algorithm in big endian encoding,
/// - 12 bytes: reserved,
/// - 32 bytes: ECDSA private key for the credential,
/// - 32 bytes: relying party ID hashed with SHA256,
/// - 32 bytes: HMAC-SHA256 over everything else.
pub fn encrypt_key_handle(
    env: &mut impl Env,
    private_key: &PrivateKey,
    application: &[u8; 32],
) -> Result<Vec<u8>, Ctap2StatusCode> {
    let master_keys = storage::master_keys(env)?;
    let aes_enc_key = crypto::aes256::EncryptionKey::new(&master_keys.encryption);

    let mut encrypted_id = match private_key {
        PrivateKey::Ecdsa(ecdsa_key) => {
            let mut plaintext = [0; 80];
            // Algorithm
            BigEndian::write_i32(&mut plaintext, SignatureAlgorithm::ES256 as i32);
            ecdsa_key.to_bytes(array_mut_ref!(plaintext, 16, 32));
            plaintext[48..80].copy_from_slice(application);
            aes256_cbc_encrypt(env.rng(), &aes_enc_key, &plaintext, true)?
        }
    };

    // Version number
    encrypted_id.insert(0, 0x01);
    let id_hmac = hmac_256::<Sha256>(&master_keys.hmac, &encrypted_id[..]);
    encrypted_id.extend(&id_hmac);
    Ok(encrypted_id)
}

/// Decrypts a credential ID and writes the private key into a PublicKeyCredentialSource.
///
/// Returns None if
/// - the HMAC test fails or
/// - the relying party does not match the decrypted relying party ID hash.
///
/// This functions reads:
/// - legacy credentials (no algorithm identifier or version number),
/// - ECDSA v1
///
/// It opportunistically accepts all version numbers >= 1.
pub fn decrypt_credential_source(
    env: &mut impl Env,
    credential_id: Vec<u8>,
    rp_id_hash: &[u8],
) -> Result<Option<PublicKeyCredentialSource>, Ctap2StatusCode> {
    if credential_id.len() < LEGACY_CREDENTIAL_ID_SIZE {
        return Ok(None);
    }
    let master_keys = storage::master_keys(env)?;
    let hmac_message_size = credential_id.len() - 32;
    if !verify_hmac_256::<Sha256>(
        &master_keys.hmac,
        &credential_id[..hmac_message_size],
        array_ref![credential_id, hmac_message_size, 32],
    ) {
        return Ok(None);
    }

    let is_legacy = credential_id.len() == LEGACY_CREDENTIAL_ID_SIZE;
    let payload = if is_legacy {
        &credential_id[..hmac_message_size]
    } else {
        // Version number check
        if credential_id[0] != 1 {
            return Ok(None);
        }
        &credential_id[1..hmac_message_size]
    };

    let aes_enc_key = crypto::aes256::EncryptionKey::new(&master_keys.encryption);
    let decrypted_id = aes256_cbc_decrypt(&aes_enc_key, payload, true)?;

    if rp_id_hash != &decrypted_id[decrypted_id.len() - 32..] {
        return Ok(None);
    }
    let sk_option = if is_legacy {
        PrivateKey::new_ecdsa_from_bytes(&decrypted_id[..32])
    } else {
        let algorithm_int = BigEndian::read_i32(&decrypted_id[..4]);
        match SignatureAlgorithm::from(algorithm_int as i64) {
            SignatureAlgorithm::ES256 => PrivateKey::new_ecdsa_from_bytes(&decrypted_id[16..48]),
            // This credential was created with our master keys, but uses an unknown algorithm.
            SignatureAlgorithm::Unknown => return Ok(None),
        }
    };

    Ok(sk_option.map(|sk| PublicKeyCredentialSource {
        key_type: PublicKeyCredentialType::PublicKey,
        credential_id,
        private_key: sk,
        rp_id: String::from(""),
        user_handle: vec![],
        user_display_name: None,
        cred_protect_policy: None,
        creation_order: 0,
        user_name: None,
        user_icon: None,
        cred_blob: None,
        large_blob_key: None,
    }))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;

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
        let private_key = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);
        let key_bytes = private_key.to_bytes();
        assert_eq!(
            PrivateKey::new_ecdsa_from_bytes(&key_bytes),
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
    fn test_private_key_get_pub_key() {
        let mut env = TestEnv::new();
        let ecdsa_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let public_key = ecdsa_key.genpk();
        let private_key = PrivateKey::from(ecdsa_key);
        assert_eq!(private_key.get_pub_key(), CoseKey::from(public_key));
    }

    #[test]
    fn test_private_key_sign_and_encode() {
        let mut env = TestEnv::new();
        let message = [0x5A; 32];
        let ecdsa_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let signature = ecdsa_key.sign_rfc6979::<Sha256>(&message).to_asn1_der();
        let private_key = PrivateKey::from(ecdsa_key);
        assert_eq!(private_key.sign_and_encode(&message), signature);
    }

    #[test]
    fn test_private_key_signature_algorithm() {
        let mut env = TestEnv::new();
        let algorithm = SignatureAlgorithm::ES256;
        let private_key = PrivateKey::new(env.rng(), algorithm);
        assert_eq!(private_key.signature_algorithm(), algorithm);
    }

    #[test]
    fn test_private_key_from_to_cbor() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);
        let cbor = cbor::Value::from(private_key.clone());
        assert_eq!(PrivateKey::try_from(cbor), Ok(private_key),);
    }

    #[test]
    fn test_private_key_from_bad_cbor() {
        let cbor = cbor_array![
            cbor_int!(SignatureAlgorithm::ES256 as i64),
            cbor_bytes!(vec![0x88; 32]),
            // The array is too long.
            cbor_int!(0),
        ];
        assert_eq!(
            PrivateKey::try_from(cbor),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR),
        );

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

    #[test]
    fn test_encrypt_decrypt_credential() {
        let mut env = TestEnv::new();
        storage::init(&mut env).ok().unwrap();
        let private_key = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);

        let rp_id_hash = [0x55; 32];
        let encrypted_id = encrypt_key_handle(&mut env, &private_key, &rp_id_hash).unwrap();
        let decrypted_source = decrypt_credential_source(&mut env, encrypted_id, &rp_id_hash)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, decrypted_source.private_key);
    }

    #[test]
    fn test_encrypt_decrypt_bad_hmac() {
        let mut env = TestEnv::new();
        storage::init(&mut env).ok().unwrap();
        let private_key = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);

        let rp_id_hash = [0x55; 32];
        let encrypted_id = encrypt_key_handle(&mut env, &private_key, &rp_id_hash).unwrap();
        for i in 0..encrypted_id.len() {
            let mut modified_id = encrypted_id.clone();
            modified_id[i] ^= 0x01;
            assert!(
                decrypt_credential_source(&mut env, modified_id, &rp_id_hash)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn test_decrypt_credential_missing_blocks() {
        let mut env = TestEnv::new();
        storage::init(&mut env).ok().unwrap();
        let private_key = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);

        let rp_id_hash = [0x55; 32];
        let encrypted_id = encrypt_key_handle(&mut env, &private_key, &rp_id_hash).unwrap();

        for length in (0..ECDSA_CREDENTIAL_ID_SIZE).step_by(16) {
            assert_eq!(
                decrypt_credential_source(&mut env, encrypted_id[..length].to_vec(), &rp_id_hash),
                Ok(None)
            );
        }
    }

    /// This is a copy of the function that genereated deprecated key handles.
    fn legacy_encrypt_key_handle(
        env: &mut impl Env,
        private_key: crypto::ecdsa::SecKey,
        application: &[u8; 32],
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let master_keys = storage::master_keys(env)?;
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&master_keys.encryption);
        let mut plaintext = [0; 64];
        private_key.to_bytes(array_mut_ref!(plaintext, 0, 32));
        plaintext[32..64].copy_from_slice(application);

        let mut encrypted_id = aes256_cbc_encrypt(env.rng(), &aes_enc_key, &plaintext, true)?;
        let id_hmac = hmac_256::<Sha256>(&master_keys.hmac, &encrypted_id[..]);
        encrypted_id.extend(&id_hmac);
        Ok(encrypted_id)
    }

    #[test]
    fn test_encrypt_decrypt_credential_legacy() {
        let mut env = TestEnv::new();
        storage::init(&mut env).ok().unwrap();
        let ecdsa_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let private_key = PrivateKey::from(ecdsa_key.clone());

        let rp_id_hash = [0x55; 32];
        let encrypted_id = legacy_encrypt_key_handle(&mut env, ecdsa_key, &rp_id_hash).unwrap();
        let decrypted_source = decrypt_credential_source(&mut env, encrypted_id, &rp_id_hash)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, decrypted_source.private_key);
    }
}
