// Copyright 2022 Google LLC
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

use super::crypto_wrapper::{aes256_cbc_decrypt, aes256_cbc_encrypt, PrivateKey};
use super::data_formats::{
    CredentialProtectionPolicy, PublicKeyCredentialSource, PublicKeyCredentialType,
};
use super::status_code::Ctap2StatusCode;
use super::{cbor_read, cbor_write};
use crate::api::key_store::KeyStore;
use crate::ctap::data_formats::{extract_byte_string, extract_map};
use crate::env::Env;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use crypto::hmac::{hmac_256, verify_hmac_256};
use crypto::sha256::Sha256;
use sk_cbor::{cbor_map_options, destructure_cbor_map};

pub const LEGACY_CREDENTIAL_ID_SIZE: usize = 112;
// CBOR credential IDs consist of
// - 1   byte : version number
// - 16  bytes: initialization vector for AES-256,
// - 192 bytes: encrypted block of the key handle cbor,
// - 32  bytes: HMAC-SHA256 over everything else.
pub const CBOR_CREDENTIAL_ID_SIZE: usize = 241;
pub const MIN_CREDENTIAL_ID_SIZE: usize = LEGACY_CREDENTIAL_ID_SIZE;
pub const MAX_CREDENTIAL_ID_SIZE: usize = CBOR_CREDENTIAL_ID_SIZE;

pub const CBOR_CREDENTIAL_ID_VERSION: u8 = 0x01;

pub const MAX_PADDING_LENGTH: u8 = 0xBF;

// Data fields that are contained in the credential ID of non-discoverable credentials.
struct CredentialSource {
    private_key: PrivateKey,
    rp_id_hash: [u8; 32],
    cred_protect_policy: Option<CredentialProtectionPolicy>,
    cred_blob: Option<Vec<u8>>,
}

// The data fields contained in the credential ID are serialized using CBOR maps.
// Each field is associated with a unique tag, implemented with a CBOR unsigned key.
enum CredentialSourceField {
    PrivateKey = 0,
    RpIdHash = 1,
    CredProtectPolicy = 2,
    CredBlob = 3,
}

impl From<CredentialSourceField> for sk_cbor::Value {
    fn from(field: CredentialSourceField) -> sk_cbor::Value {
        (field as u64).into()
    }
}

fn decrypt_legacy_credential_id(
    env: &mut impl Env,
    bytes: &[u8],
) -> Result<Option<CredentialSource>, Ctap2StatusCode> {
    let aes_enc_key = crypto::aes256::EncryptionKey::new(&env.key_store().key_handle_encryption()?);
    let plaintext = aes256_cbc_decrypt(&aes_enc_key, bytes, true)?;
    if plaintext.len() != 64 {
        return Ok(None);
    }
    let private_key = if let Some(key) = PrivateKey::new_ecdsa_from_bytes(&plaintext[..32]) {
        key
    } else {
        return Ok(None);
    };
    Ok(Some(CredentialSource {
        private_key,
        rp_id_hash: plaintext[32..64].try_into().unwrap(),
        cred_protect_policy: None,
        cred_blob: None,
    }))
}

fn decrypt_cbor_credential_id(
    env: &mut impl Env,
    bytes: &[u8],
) -> Result<Option<CredentialSource>, Ctap2StatusCode> {
    let aes_enc_key = crypto::aes256::EncryptionKey::new(&env.key_store().key_handle_encryption()?);
    let mut plaintext = aes256_cbc_decrypt(&aes_enc_key, bytes, true)?;
    remove_padding(&mut plaintext)?;

    let cbor_credential_source = cbor_read(plaintext.as_slice())?;
    destructure_cbor_map! {
      let {
          CredentialSourceField::PrivateKey => private_key,
          CredentialSourceField::RpIdHash=> rp_id_hash,
          CredentialSourceField::CredProtectPolicy => cred_protect_policy,
          CredentialSourceField::CredBlob => cred_blob,
      } = extract_map(cbor_credential_source)?;
    }
    Ok(match (private_key, rp_id_hash) {
        (Some(private_key), Some(rp_id_hash)) => {
            let private_key = PrivateKey::try_from(private_key)?;
            let rp_id_hash = extract_byte_string(rp_id_hash)?;
            if rp_id_hash.len() != 32 {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
            }
            let cred_protect_policy = cred_protect_policy
                .map(CredentialProtectionPolicy::try_from)
                .transpose()?;
            let cred_blob = cred_blob.map(extract_byte_string).transpose()?;
            Some(CredentialSource {
                private_key,
                rp_id_hash: rp_id_hash.try_into().unwrap(),
                cred_protect_policy,
                cred_blob,
            })
        }
        _ => None,
    })
}

/// Pad data to MAX_PADDING_LENGTH+1 (192) bytes using PKCS padding scheme.
/// Let N = 192 - data.len(), the PKCS padding scheme would pad N bytes of N after the data.
fn add_padding(data: &mut Vec<u8>) -> Result<(), Ctap2StatusCode> {
    // The data should be between 1 to MAX_PADDING_LENGTH bytes for the padding scheme to be valid.
    if data.is_empty() || data.len() > MAX_PADDING_LENGTH as usize {
        return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
    }
    let pad_length = MAX_PADDING_LENGTH - (data.len() as u8 - 1);
    data.extend(core::iter::repeat(pad_length).take(pad_length as usize));
    Ok(())
}

fn remove_padding(data: &mut Vec<u8>) -> Result<(), Ctap2StatusCode> {
    if data.len() != MAX_PADDING_LENGTH as usize + 1 {
        // This is an internal error instead of corrupted credential ID which we should just ignore because
        // we've already checked that the HMAC matched.
        return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
    }
    let pad_length = *data.last().unwrap();
    if pad_length == 0 || pad_length > MAX_PADDING_LENGTH {
        return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
    }
    if !data
        .drain((data.len() - pad_length as usize)..)
        .all(|x| x == pad_length)
    {
        return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
    }
    Ok(())
}

/// Encrypts the given private key, relying party ID hash, and some other metadata into a credential ID.
///
/// Other information, such as a user name, are not stored. Since encrypted credential IDs are
/// stored server-side, this information is already available (unencrypted).
pub fn encrypt_to_credential_id(
    env: &mut impl Env,
    private_key: &PrivateKey,
    rp_id_hash: &[u8; 32],
    cred_protect_policy: Option<CredentialProtectionPolicy>,
    cred_blob: Option<Vec<u8>>,
) -> Result<Vec<u8>, Ctap2StatusCode> {
    let mut payload = Vec::new();
    let cbor = cbor_map_options! {
      CredentialSourceField::PrivateKey => private_key,
      CredentialSourceField::RpIdHash=> rp_id_hash,
      CredentialSourceField::CredProtectPolicy => cred_protect_policy,
      CredentialSourceField::CredBlob => cred_blob,
    };
    cbor_write(cbor, &mut payload)?;
    add_padding(&mut payload)?;

    let aes_enc_key = crypto::aes256::EncryptionKey::new(&env.key_store().key_handle_encryption()?);
    let encrypted_payload = aes256_cbc_encrypt(env.rng(), &aes_enc_key, &payload, true)?;
    let mut credential_id = encrypted_payload;
    credential_id.insert(0, CBOR_CREDENTIAL_ID_VERSION);

    let id_hmac = hmac_256::<Sha256>(
        &env.key_store().key_handle_authentication()?,
        &credential_id[..],
    );
    credential_id.extend(id_hmac);
    Ok(credential_id)
}

/// Decrypts the given credential ID into a PublicKeyCredentialSource, populating only the recorded fields.
///
/// Returns None if
/// - the format does not match any known versions, or
/// - the HMAC test fails.
///
/// For v0 (legacy U2F) the credential ID consists of:
/// - 16 bytes: initialization vector for AES-256,
/// - 32 bytes: encrypted ECDSA private key for the credential,
/// - 32 bytes: encrypted relying party ID hashed with SHA256,
/// - 32 bytes: HMAC-SHA256 over everything else.
///
/// For v1 (CBOR) the credential ID consists of:
/// -   1 byte : version number,
/// -  16 bytes: initialization vector for AES-256,
/// - 192 bytes: encrypted CBOR-encoded credential source fields,
/// -  32 bytes: HMAC-SHA256 over everything else.
pub fn decrypt_credential_id(
    env: &mut impl Env,
    credential_id: Vec<u8>,
    rp_id_hash: &[u8],
) -> Result<Option<PublicKeyCredentialSource>, Ctap2StatusCode> {
    if credential_id.len() < MIN_CREDENTIAL_ID_SIZE {
        return Ok(None);
    }
    let hmac_message_size = credential_id.len() - 32;
    if !verify_hmac_256::<Sha256>(
        &env.key_store().key_handle_authentication()?,
        &credential_id[..hmac_message_size],
        array_ref![credential_id, hmac_message_size, 32],
    ) {
        return Ok(None);
    }

    let credential_source = if credential_id.len() == LEGACY_CREDENTIAL_ID_SIZE {
        decrypt_legacy_credential_id(env, &credential_id[..hmac_message_size])?
    } else {
        match credential_id[0] {
            CBOR_CREDENTIAL_ID_VERSION => {
                if credential_id.len() != CBOR_CREDENTIAL_ID_SIZE {
                    return Ok(None);
                }
                decrypt_cbor_credential_id(env, &credential_id[1..hmac_message_size])?
            }
            _ => return Ok(None),
        }
    };

    let credential_source = if let Some(credential_source) = credential_source {
        credential_source
    } else {
        return Ok(None);
    };

    if rp_id_hash != credential_source.rp_id_hash {
        return Ok(None);
    }

    Ok(Some(PublicKeyCredentialSource {
        key_type: PublicKeyCredentialType::PublicKey,
        credential_id,
        private_key: credential_source.private_key,
        rp_id: String::new(),
        user_handle: Vec::new(),
        user_display_name: None,
        cred_protect_policy: credential_source.cred_protect_policy,
        creation_order: 0,
        user_name: None,
        user_icon: None,
        cred_blob: credential_source.cred_blob,
        large_blob_key: None,
    }))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::customization::Customization;
    use crate::ctap::credential_id::CBOR_CREDENTIAL_ID_SIZE;
    use crate::ctap::SignatureAlgorithm;
    use crate::env::test::TestEnv;
    use crypto::hmac::hmac_256;

    const UNSUPPORTED_CREDENTIAL_ID_VERSION: u8 = 0x80;

    fn test_encrypt_decrypt_credential(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);

        let rp_id_hash = [0x55; 32];
        let encrypted_id =
            encrypt_to_credential_id(&mut env, &private_key, &rp_id_hash, None, None).unwrap();
        let decrypted_source = decrypt_credential_id(&mut env, encrypted_id, &rp_id_hash)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, decrypted_source.private_key);
    }

    #[test]
    fn test_encrypt_decrypt_ecdsa_credential() {
        test_encrypt_decrypt_credential(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_encrypt_decrypt_ed25519_credential() {
        test_encrypt_decrypt_credential(SignatureAlgorithm::Eddsa);
    }

    #[test]
    fn test_encrypt_decrypt_bad_version() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::Es256);

        let rp_id_hash = [0x55; 32];
        let mut encrypted_id =
            encrypt_to_credential_id(&mut env, &private_key, &rp_id_hash, None, None).unwrap();
        encrypted_id[0] = UNSUPPORTED_CREDENTIAL_ID_VERSION;
        // Override the HMAC to pass the check.
        encrypted_id.truncate(&encrypted_id.len() - 32);
        let hmac_key = env.key_store().key_handle_authentication().unwrap();
        let id_hmac = hmac_256::<Sha256>(&hmac_key, &encrypted_id[..]);
        encrypted_id.extend(id_hmac);

        assert_eq!(
            decrypt_credential_id(&mut env, encrypted_id, &rp_id_hash),
            Ok(None)
        );
    }

    fn test_encrypt_decrypt_bad_hmac(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);

        let rp_id_hash = [0x55; 32];
        let encrypted_id =
            encrypt_to_credential_id(&mut env, &private_key, &rp_id_hash, None, None).unwrap();
        for i in 0..encrypted_id.len() {
            let mut modified_id = encrypted_id.clone();
            modified_id[i] ^= 0x01;
            assert_eq!(
                decrypt_credential_id(&mut env, modified_id, &rp_id_hash),
                Ok(None)
            );
        }
    }

    #[test]
    fn test_ecdsa_encrypt_decrypt_bad_hmac() {
        test_encrypt_decrypt_bad_hmac(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_encrypt_decrypt_bad_hmac() {
        test_encrypt_decrypt_bad_hmac(SignatureAlgorithm::Eddsa);
    }

    fn test_decrypt_credential_missing_blocks(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);

        let rp_id_hash = [0x55; 32];
        let encrypted_id =
            encrypt_to_credential_id(&mut env, &private_key, &rp_id_hash, None, None).unwrap();

        for length in (1..CBOR_CREDENTIAL_ID_SIZE).step_by(16) {
            assert_eq!(
                decrypt_credential_id(&mut env, encrypted_id[..length].to_vec(), &rp_id_hash),
                Ok(None)
            );
        }
    }

    #[test]
    fn test_ecdsa_decrypt_credential_missing_blocks() {
        test_decrypt_credential_missing_blocks(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_decrypt_credential_missing_blocks() {
        test_decrypt_credential_missing_blocks(SignatureAlgorithm::Eddsa);
    }

    /// This is a copy of the function that genereated deprecated key handles.
    fn legacy_encrypt_to_credential_id(
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
        encrypted_id.extend(id_hmac);
        Ok(encrypted_id)
    }

    #[test]
    fn test_encrypt_decrypt_credential_legacy() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let ecdsa_key = private_key.ecdsa_key(&mut env).unwrap();

        let rp_id_hash = [0x55; 32];
        let encrypted_id =
            legacy_encrypt_to_credential_id(&mut env, ecdsa_key, &rp_id_hash).unwrap();
        let decrypted_source = decrypt_credential_id(&mut env, encrypted_id, &rp_id_hash)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, decrypted_source.private_key);
        // Legacy credentials didn't persist credProtectPolicy info, so it should be treated as None.
        assert!(decrypted_source.cred_protect_policy.is_none());
    }

    #[test]
    fn test_encrypt_credential_size() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::Es256);

        let rp_id_hash = [0x55; 32];
        let encrypted_id =
            encrypt_to_credential_id(&mut env, &private_key, &rp_id_hash, None, None).unwrap();
        assert_eq!(encrypted_id.len(), CBOR_CREDENTIAL_ID_SIZE);
    }

    #[test]
    fn test_encrypt_credential_max_cbor_size() {
        // The cbor encoding length is variadic and depends on size of fields. Try to put maximum length
        // for each encoded field and ensure that it doesn't go over the padding size.
        let mut env = TestEnv::new();
        // Currently all private key types have same length when transformed to bytes.
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::Es256);
        let rp_id_hash = [0x55; 32];
        let cred_protect_policy = Some(CredentialProtectionPolicy::UserVerificationOptional);
        let cred_blob = Some(vec![0x55; env.customization().max_cred_blob_length()]);

        let encrypted_id = encrypt_to_credential_id(
            &mut env,
            &private_key,
            &rp_id_hash,
            cred_protect_policy,
            cred_blob,
        );

        assert!(encrypted_id.is_ok());
    }

    #[test]
    fn test_cred_protect_persisted() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::Es256);

        let rp_id_hash = [0x55; 32];
        let encrypted_id = encrypt_to_credential_id(
            &mut env,
            &private_key,
            &rp_id_hash,
            Some(CredentialProtectionPolicy::UserVerificationRequired),
            None,
        )
        .unwrap();

        let decrypted_source = decrypt_credential_id(&mut env, encrypted_id, &rp_id_hash)
            .unwrap()
            .unwrap();
        assert_eq!(decrypted_source.private_key, private_key);
        assert_eq!(
            decrypted_source.cred_protect_policy,
            Some(CredentialProtectionPolicy::UserVerificationRequired)
        );
    }

    #[test]
    fn test_cred_blob_persisted() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::Es256);

        let rp_id_hash = [0x55; 32];
        let cred_blob = Some(vec![0x55; env.customization().max_cred_blob_length()]);
        let encrypted_id =
            encrypt_to_credential_id(&mut env, &private_key, &rp_id_hash, None, cred_blob.clone())
                .unwrap();

        let decrypted_source = decrypt_credential_id(&mut env, encrypted_id, &rp_id_hash)
            .unwrap()
            .unwrap();
        assert_eq!(decrypted_source.private_key, private_key);
        assert_eq!(decrypted_source.cred_blob, cred_blob);
    }
}
