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
use super::data_formats::CredentialProtectionPolicy;
use super::status_code::Ctap2StatusCode;
use super::{cbor_read, cbor_write};
use crate::api::key_store::KeyStore;
#[cfg(feature = "ed25519")]
use crate::ctap::data_formats::EDDSA_ALGORITHM;
use crate::ctap::data_formats::{extract_byte_string, extract_map, ES256_ALGORITHM};
use crate::env::Env;
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use crypto::hmac::{hmac_256, verify_hmac_256};
use crypto::sha256::Sha256;
use sk_cbor::{cbor_map_options, destructure_cbor_map};

pub const LEGACY_CREDENTIAL_ID_SIZE: usize = 112;
// CBOR credential IDs consist of
// - 1   byte : version number
// - 16  bytes: initialization vector for AES-256,
// - 240 bytes: encrypted block of the key handle cbor,
// - 32  bytes: HMAC-SHA256 over everything else.
#[cfg(test)]
pub const CBOR_CREDENTIAL_ID_SIZE: usize = 241;
pub const MAX_CREDENTIAL_ID_SIZE: usize = 241;
pub const MIN_CREDENTIAL_ID_SIZE: usize = 112;

pub const ECDSA_CREDENTIAL_ID_VERSION: u8 = 0x01;
#[cfg(feature = "ed25519")]
pub const ED25519_CREDENTIAL_ID_VERSION: u8 = 0x02;
pub const CBOR_CREDENTIAL_ID_VERSION: u8 = 0x03;

pub const MAX_PADDING_LENGTH: u8 = 0xBF;

pub(crate) struct CredentialId {
    pub private_key: PrivateKey,
    pub rp_id_hash: [u8; 32],
    pub cred_protect_policy: Option<CredentialProtectionPolicy>,
}

fn decrypt_legacy_key_handle(
    env: &mut impl Env,
    bytes: &[u8],
    algorithm: i64,
) -> Result<Option<CredentialId>, Ctap2StatusCode> {
    let aes_enc_key = crypto::aes256::EncryptionKey::new(&env.key_store().key_handle_encryption()?);
    let plaintext = aes256_cbc_decrypt(&aes_enc_key, bytes, true)?;
    if plaintext.len() != 64 {
        return Ok(None);
    }
    let private_key = if let Some(key) = match algorithm {
        ES256_ALGORITHM => PrivateKey::new_ecdsa_from_bytes(&plaintext[..32]),
        #[cfg(feature = "ed25519")]
        EDDSA_ALGORITHM => PrivateKey::new_ed25519_from_bytes(&plaintext[..32]),
        _ => None,
    } {
        key
    } else {
        return Ok(None);
    };
    Ok(Some(CredentialId {
        private_key,
        rp_id_hash: plaintext[32..64].try_into().unwrap(),
        cred_protect_policy: None,
    }))
}

// We serialize key handles using CBOR maps. Each field of a key handle
// is associated with a unique tag, implemented with a CBOR unsigned key.
enum CborKeyHandleField {
    PrivateKey = 0,
    RpIdHash = 1,
    CredProtectPolicy = 2,
}

impl From<CborKeyHandleField> for sk_cbor::Value {
    fn from(field: CborKeyHandleField) -> sk_cbor::Value {
        (field as u64).into()
    }
}

fn decrypt_cbor_key_handle(
    env: &mut impl Env,
    bytes: &[u8],
) -> Result<Option<CredentialId>, Ctap2StatusCode> {
    let aes_enc_key = crypto::aes256::EncryptionKey::new(&env.key_store().key_handle_encryption()?);
    let mut plaintext = aes256_cbc_decrypt(&aes_enc_key, bytes, true)?;
    remove_padding(&mut plaintext)?;

    let decoded_cbor = cbor_read(plaintext.as_slice())?;
    destructure_cbor_map! {
      let {
          CborKeyHandleField::PrivateKey => private_key,
          CborKeyHandleField::RpIdHash=> rp_id_hash,
          CborKeyHandleField::CredProtectPolicy => cred_protect_policy,
      } = extract_map(decoded_cbor)?;
    }
    Ok(match (private_key, rp_id_hash, cred_protect_policy) {
        (Some(private_key), Some(rp_id_hash), cred_protect_policy) => {
            let private_key = PrivateKey::try_from(private_key)?;
            let rp_id_hash = extract_byte_string(rp_id_hash)?;
            if rp_id_hash.len() != 32 {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
            }
            let cred_protect_policy = if let Some(policy) = cred_protect_policy {
                Some(CredentialProtectionPolicy::try_from(policy)?)
            } else {
                None
            };
            Some(CredentialId {
                private_key,
                rp_id_hash: rp_id_hash.try_into().unwrap(),
                cred_protect_policy,
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

impl CredentialId {
    /// Encrypts the given private key, relying party ID hash, and cred protect policy into a credential ID.
    ///
    /// Other information, such as a user name, are not stored. Since encrypted credential IDs are
    /// stored server-side, this information is already available (unencrypted).
    pub(super) fn encrypt_to_bytes(
        env: &mut impl Env,
        private_key: &PrivateKey,
        rp_id_hash: &[u8; 32],
        cred_protect_policy: Option<CredentialProtectionPolicy>,
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let mut payload = Vec::new();
        let cbor = cbor_map_options! {
          CborKeyHandleField::PrivateKey => private_key,
          CborKeyHandleField::RpIdHash=> rp_id_hash,
          CborKeyHandleField::CredProtectPolicy => cred_protect_policy,
        };
        cbor_write(cbor, &mut payload)?;
        add_padding(&mut payload)?;

        let aes_enc_key =
            crypto::aes256::EncryptionKey::new(&env.key_store().key_handle_encryption()?);
        let encrypted_payload = aes256_cbc_encrypt(env.rng(), &aes_enc_key, &payload, true)?;
        let mut credential_id = encrypted_payload;
        credential_id.insert(0, CBOR_CREDENTIAL_ID_VERSION);

        let id_hmac = hmac_256::<Sha256>(
            &env.key_store().key_handle_authentication()?,
            &credential_id[..],
        );
        credential_id.extend(&id_hmac);
        Ok(credential_id)
    }

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
    /// For v1 (ECDSA (algorithm -7)) the credential ID consists of:
    /// -  1 byte : version number
    /// - 16 bytes: initialization vector for AES-256,
    /// - 32 bytes: encrypted ECDSA private key for the credential,
    /// - 32 bytes: encrypted relying party ID hashed with SHA256,
    /// - 32 bytes: HMAC-SHA256 over everything else.
    ///
    /// For v2 (EdDSA over curve Ed25519 (algorithm -8, curve 6)) the credential ID consists of:
    /// -  1 byte : version number
    /// - 16 bytes: initialization vector for AES-256,
    /// - 32 bytes: encrypted Ed25519 private key for the credential,
    /// - 32 bytes: encrypted relying party ID hashed with SHA256,
    /// - 32 bytes: HMAC-SHA256 over everything else.
    ///
    /// For v3 (CBOR key handle) the credential ID consists of:
    /// -  1 byte : version number
    /// - 16 bytes: initialization vector for AES-256,
    /// - 64 bytes * N: encrypted CBOR key handle
    /// - 32 bytes: HMAC-SHA256 over everything else.
    pub(super) fn decrypt_from_bytes(
        env: &mut impl Env,
        credential_id: Vec<u8>,
    ) -> Result<Option<Self>, Ctap2StatusCode> {
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

        if credential_id.len() == LEGACY_CREDENTIAL_ID_SIZE {
            return decrypt_legacy_key_handle(
                env,
                &credential_id[..hmac_message_size],
                ES256_ALGORITHM,
            );
        }
        match credential_id[0] {
            ECDSA_CREDENTIAL_ID_VERSION => decrypt_legacy_key_handle(
                env,
                &credential_id[1..hmac_message_size],
                ES256_ALGORITHM,
            ),
            #[cfg(feature = "ed25519")]
            ED25519_CREDENTIAL_ID_VERSION => decrypt_legacy_key_handle(
                env,
                &credential_id[1..hmac_message_size],
                EDDSA_ALGORITHM,
            ),
            CBOR_CREDENTIAL_ID_VERSION => {
                decrypt_cbor_key_handle(env, &credential_id[1..hmac_message_size])
            }
            _ => Ok(None),
        }
    }
}
