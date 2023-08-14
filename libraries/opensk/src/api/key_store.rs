// Copyright 2022-2023 Google LLC
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
use crate::api::crypto::hmac256::Hmac256;
use crate::api::crypto::HASH_SIZE;
use crate::api::private_key::PrivateKey;
use crate::ctap::crypto_wrapper::{aes256_cbc_decrypt, aes256_cbc_encrypt};
use crate::ctap::data_formats::CredentialProtectionPolicy;
use crate::ctap::secret::Secret;
use crate::ctap::{cbor_read, cbor_write};
use crate::env::{AesKey, Env, Hmac};
use alloc::vec;
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use persistent_store::StoreError;
use rand_core::RngCore;
use sk_cbor as cbor;
use sk_cbor::{cbor_map_options, destructure_cbor_map};

// CBOR credential IDs consist of
// - 1   byte : version number
// - 16  bytes: initialization vector for AES-256,
// - 192 bytes: encrypted block of the key handle cbor,
// - 32  bytes: HMAC-SHA256 over everything else.
pub const CBOR_CREDENTIAL_ID_SIZE: usize = 241;
const MIN_CREDENTIAL_ID_SIZE: usize = CBOR_CREDENTIAL_ID_SIZE;
pub(crate) const MAX_CREDENTIAL_ID_SIZE: usize = CBOR_CREDENTIAL_ID_SIZE;

pub const CBOR_CREDENTIAL_ID_VERSION: u8 = 0x01;
const MAX_PADDING_LENGTH: u8 = 0xBF;

/// Stored data for credentials.
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct CredentialSource {
    pub private_key: PrivateKey,
    pub rp_id_hash: [u8; 32],
    pub cred_protect_policy: Option<CredentialProtectionPolicy>,
    pub cred_blob: Option<Vec<u8>>,
}

/// CBOR map keys for serialized credential IDs.
enum CredentialSourceField {
    PrivateKey = 0,
    RpIdHash = 1,
    CredProtectPolicy = 2,
    CredBlob = 3,
}

impl From<CredentialSourceField> for cbor::Value {
    fn from(field: CredentialSourceField) -> cbor::Value {
        (field as u64).into()
    }
}

/// Provides storage for secret keys.
///
/// Implementations may use the environment store: [`STORAGE_KEY`] is reserved for this usage.
pub trait KeyStore {
    /// Initializes the key store (if needed).
    ///
    /// This function should be a no-op if the key store is already initialized.
    fn init(&mut self) -> Result<(), Error>;

    /// Key to wrap (secret) data.
    ///
    /// Useful for encrypting data before
    /// - writing it to persistent storage,
    /// - CBOR encoding it,
    /// - doing anything that does not support [`Secret`].
    fn wrap_key<E: Env>(&mut self) -> Result<AesKey<E>, Error>;

    /// Encodes a credential as a binary strings.
    ///
    /// The output is encrypted and authenticated. Since the wrapped credentials are passed to the
    /// relying party, the choice for credential wrapping impacts privacy. Looking at their size and
    /// structure, a relying party can guess the authenticator model that produced it.
    ///
    /// A credential ID that imitates the default needs the following structure:
    /// - The length is [`CBOR_CREDENTIAL_ID_SIZE`].
    /// - The first byte is the version. The latest version is [`CBOR_CREDENTIAL_ID_VERSION`].
    /// - All other bytes appear to be drawn from a uniform random distribution.
    ///
    /// Without attestation, a relying party can't distinguish such credentials from other OpenSK
    /// implementations.
    fn wrap_credential(&mut self, credential: CredentialSource) -> Result<Vec<u8>, Error>;

    /// Decodes the credential.
    ///
    /// Returns None if the data was not created by this authenticator.
    fn unwrap_credential(
        &mut self,
        bytes: &[u8],
        rp_id_hash: &[u8],
    ) -> Result<Option<CredentialSource>, Error>;

    /// Returns the key for the CredRandom feature.
    fn cred_random(&mut self, has_uv: bool) -> Result<Secret<[u8; 32]>, Error>;

    /// Encrypts a PIN hash.
    fn encrypt_pin_hash(&mut self, plain: &[u8; 16]) -> Result<[u8; 16], Error>;

    /// Decrypts a PIN hash.
    fn decrypt_pin_hash(&mut self, cipher: &[u8; 16]) -> Result<Secret<[u8; 16]>, Error>;

    /// Resets the key store.
    fn reset(&mut self) -> Result<(), Error>;
}

/// Key store errors.
///
/// They are deliberately indistinguishable to avoid leaking information.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Error;

/// Key of the environment store reserved for the key store.
pub const STORAGE_KEY: usize = 2046;

/// Implements a default key store using the environment rng and store.
pub trait Helper: Env {}

impl<T: Helper> KeyStore for T {
    fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn wrap_key<E: Env>(&mut self) -> Result<AesKey<E>, Error> {
        Ok(AesKey::<E>::new(&get_master_keys(self)?.encryption))
    }

    /// Encrypts the given credential source data into a credential ID.
    ///
    /// Other information, such as a user name, are not stored. Since encrypted credential IDs are
    /// stored server-side, this information is already available (unencrypted).
    fn wrap_credential(&mut self, credential: CredentialSource) -> Result<Vec<u8>, Error> {
        let mut payload = Vec::new();
        let wrap_key = self.wrap_key::<T>()?;
        let private_key_cbor = credential
            .private_key
            .to_cbor::<T>(self.rng(), &wrap_key)
            .map_err(|_| Error)?;
        let cbor = cbor_map_options! {
          CredentialSourceField::PrivateKey => private_key_cbor,
          CredentialSourceField::RpIdHash => credential.rp_id_hash,
          CredentialSourceField::CredProtectPolicy => credential.cred_protect_policy,
          CredentialSourceField::CredBlob => credential.cred_blob,
        };
        cbor_write(cbor, &mut payload).map_err(|_| Error)?;
        add_padding(&mut payload)?;
        let master_keys = get_master_keys(self)?;
        let aes_key = AesKey::<T>::new(&master_keys.encryption);
        let encrypted_payload =
            aes256_cbc_encrypt::<T>(self.rng(), &aes_key, &payload, true).map_err(|_| Error)?;
        let mut credential_id = encrypted_payload;
        credential_id.insert(0, CBOR_CREDENTIAL_ID_VERSION);

        let mut id_hmac = [0; HASH_SIZE];
        Hmac::<T>::mac(
            &master_keys.authentication,
            &credential_id[..],
            &mut id_hmac,
        );
        credential_id.extend(&id_hmac);
        Ok(credential_id)
    }

    /// Decrypts the given credential ID, populating only the recorded fields.
    ///
    /// Returns None if
    /// - the format does not match any known versions, or
    /// - the HMAC test fails.
    ///
    /// For v1 (CBOR) the credential ID consists of:
    /// -   1 byte : version number,
    /// -  16 bytes: initialization vector for AES-256,
    /// - 192 bytes: encrypted CBOR-encoded credential source fields,
    /// -  32 bytes: HMAC-SHA256 over everything else.
    fn unwrap_credential(
        &mut self,
        bytes: &[u8],
        rp_id_hash: &[u8],
    ) -> Result<Option<CredentialSource>, Error> {
        if bytes.len() < MIN_CREDENTIAL_ID_SIZE {
            return Ok(None);
        }
        let hmac_message_size = bytes.len() - 32;
        let master_keys = get_master_keys(self)?;
        if !Hmac::<T>::verify(
            &master_keys.authentication,
            &bytes[..hmac_message_size],
            array_ref![bytes, hmac_message_size, 32],
        ) {
            return Ok(None);
        }

        let credential_source = match bytes[0] {
            CBOR_CREDENTIAL_ID_VERSION => {
                if bytes.len() != CBOR_CREDENTIAL_ID_SIZE {
                    return Ok(None);
                }
                decrypt_cbor_credential_id::<T>(
                    self,
                    &master_keys.encryption,
                    &bytes[1..hmac_message_size],
                )?
            }
            _ => return Ok(None),
        };

        if let Some(credential_source) = &credential_source {
            if rp_id_hash != credential_source.rp_id_hash {
                return Ok(None);
            }
        }
        Ok(credential_source)
    }

    fn cred_random(&mut self, has_uv: bool) -> Result<Secret<[u8; 32]>, Error> {
        Ok(get_master_keys(self)?.cred_random[has_uv as usize].clone())
    }

    fn encrypt_pin_hash(&mut self, plain: &[u8; 16]) -> Result<[u8; 16], Error> {
        Ok(*plain)
    }

    fn decrypt_pin_hash(&mut self, cipher: &[u8; 16]) -> Result<Secret<[u8; 16]>, Error> {
        Ok(Secret::from_exposed_secret(*cipher))
    }

    fn reset(&mut self) -> Result<(), Error> {
        // The storage also removes `STORAGE_KEY`, but this makes KeyStore more self-sufficient.
        Ok(self.store().remove(STORAGE_KEY)?)
    }
}

/// Wrapper for master keys.
struct MasterKeys {
    /// Master encryption key.
    encryption: Secret<[u8; 32]>,

    /// Master authentication key.
    authentication: Secret<[u8; 32]>,

    /// Cred random keys (without and with UV in that order).
    cred_random: [Secret<[u8; 32]>; 2],
}

fn get_master_keys(env: &mut impl Env) -> Result<MasterKeys, Error> {
    let master_keys = match env.store().find(STORAGE_KEY)? {
        Some(x) if x.len() == 128 => x,
        Some(_) => return Err(Error),
        None => {
            let mut master_keys = vec![0; 128];
            env.rng().fill_bytes(&mut master_keys);
            env.store().insert(STORAGE_KEY, &master_keys)?;
            master_keys
        }
    };
    let mut encryption: Secret<[u8; 32]> = Secret::default();
    encryption.copy_from_slice(array_ref![master_keys, 0, 32]);
    let mut authentication: Secret<[u8; 32]> = Secret::default();
    authentication.copy_from_slice(array_ref![master_keys, 32, 32]);
    let mut cred_random_no_uv: Secret<[u8; 32]> = Secret::default();
    cred_random_no_uv.copy_from_slice(array_ref![master_keys, 64, 32]);
    let mut cred_random_with_uv: Secret<[u8; 32]> = Secret::default();
    cred_random_with_uv.copy_from_slice(array_ref![master_keys, 96, 32]);
    Ok(MasterKeys {
        encryption,
        authentication,
        cred_random: [cred_random_no_uv, cred_random_with_uv],
    })
}

/// Pad data to MAX_PADDING_LENGTH+1 (192) bytes using PKCS padding scheme.
///
/// Let N = 192 - data.len(), the PKCS padding scheme would pad N bytes of N after the data.
fn add_padding(data: &mut Vec<u8>) -> Result<(), Error> {
    // The data should be between 1 to MAX_PADDING_LENGTH bytes for the padding scheme to be valid.
    if data.is_empty() || data.len() > MAX_PADDING_LENGTH as usize {
        return Err(Error);
    }
    let pad_length = MAX_PADDING_LENGTH - (data.len() as u8 - 1);
    data.extend(core::iter::repeat(pad_length).take(pad_length as usize));
    Ok(())
}

fn remove_padding(data: &[u8]) -> Result<&[u8], Error> {
    if data.len() != MAX_PADDING_LENGTH as usize + 1 {
        // This is an internal error instead of corrupted credential ID which we should just ignore because
        // we've already checked that the HMAC matched.
        return Err(Error);
    }
    let pad_length = *data.last().unwrap();
    if pad_length == 0 || pad_length > MAX_PADDING_LENGTH {
        return Err(Error);
    }
    if !data[(data.len() - pad_length as usize)..]
        .iter()
        .all(|x| *x == pad_length)
    {
        return Err(Error);
    }
    Ok(&data[..data.len() - pad_length as usize])
}

fn decrypt_cbor_credential_id<E: Env>(
    env: &mut E,
    encryption_key_bytes: &[u8; 32],
    bytes: &[u8],
) -> Result<Option<CredentialSource>, Error> {
    let aes_key = AesKey::<E>::new(encryption_key_bytes);
    let plaintext = aes256_cbc_decrypt::<E>(&aes_key, bytes, true).map_err(|_| Error)?;
    let unpadded = remove_padding(&plaintext)?;

    let cbor_credential_source = cbor_read(unpadded).map_err(|_| Error)?;
    destructure_cbor_map! {
      let {
          CredentialSourceField::PrivateKey => private_key,
          CredentialSourceField::RpIdHash => rp_id_hash,
          CredentialSourceField::CredProtectPolicy => cred_protect_policy,
          CredentialSourceField::CredBlob => cred_blob,
      } = extract_map(cbor_credential_source)?;
    }
    Ok(match (private_key, rp_id_hash) {
        (Some(private_key), Some(rp_id_hash)) => {
            let wrap_key = env.key_store().wrap_key::<E>()?;
            let private_key =
                PrivateKey::from_cbor::<E>(&wrap_key, private_key).map_err(|_| Error)?;
            let rp_id_hash = extract_byte_string(rp_id_hash)?;
            if rp_id_hash.len() != 32 {
                return Err(Error);
            }
            let cred_protect_policy = cred_protect_policy
                .map(CredentialProtectionPolicy::try_from)
                .transpose()
                .map_err(|_| Error)?;
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

impl From<StoreError> for Error {
    fn from(_: StoreError) -> Self {
        Error
    }
}

fn extract_byte_string(cbor_value: cbor::Value) -> Result<Vec<u8>, Error> {
    cbor_value.extract_byte_string().ok_or(Error)
}

fn extract_map(cbor_value: cbor::Value) -> Result<Vec<(cbor::Value, cbor::Value)>, Error> {
    cbor_value.extract_map().ok_or(Error)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::customization::Customization;
    use crate::ctap::data_formats::SignatureAlgorithm;
    use crate::env::test::TestEnv;

    const UNSUPPORTED_CREDENTIAL_ID_VERSION: u8 = 0x80;

    #[test]
    fn test_key_store() {
        let mut env = TestEnv::default();
        let key_store = env.key_store();

        // Master keys are well-defined and stable.
        let cred_random_no_uv = key_store.cred_random(false).unwrap();
        let cred_random_with_uv = key_store.cred_random(true).unwrap();
        assert_eq!(&key_store.cred_random(false).unwrap(), &cred_random_no_uv);
        assert_eq!(&key_store.cred_random(true).unwrap(), &cred_random_with_uv);

        // Same for wrap key.
        let wrap_key = key_store.wrap_key::<TestEnv>().unwrap();
        let mut test_block = [0x33; 16];
        wrap_key.encrypt_block(&mut test_block);
        let new_wrap_key = key_store.wrap_key::<TestEnv>().unwrap();
        let mut new_test_block = [0x33; 16];
        new_wrap_key.encrypt_block(&mut new_test_block);
        assert_eq!(&new_test_block, &test_block);

        // Master keys change after reset. We don't require this for ECDSA seeds because it's not
        // the case, but it might be better.
        key_store.reset().unwrap();
        assert_ne!(&key_store.cred_random(false).unwrap(), &cred_random_no_uv);
        assert_ne!(&key_store.cred_random(true).unwrap(), &cred_random_with_uv);
        let new_wrap_key = key_store.wrap_key::<TestEnv>().unwrap();
        let mut new_test_block = [0x33; 16];
        new_wrap_key.encrypt_block(&mut new_test_block);
        assert_ne!(&new_test_block, &test_block);
    }

    #[test]
    fn test_pin_hash_encrypt_decrypt() {
        let mut env = TestEnv::default();
        let key_store = env.key_store();
        assert_eq!(key_store.init(), Ok(()));

        let pin_hash = [0x55; 16];
        let encrypted = key_store.encrypt_pin_hash(&pin_hash).unwrap();
        let decrypted = key_store.decrypt_pin_hash(&encrypted).unwrap();
        assert_eq!(pin_hash, *decrypted);
    }

    fn test_wrap_unwrap_credential(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);
        let credential_source = CredentialSource {
            private_key,
            rp_id_hash: [0x55; 32],
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationOptional),
            cred_blob: Some(vec![0xAA; 32]),
        };
        let credential_id = env
            .key_store()
            .wrap_credential(credential_source.clone())
            .unwrap();
        let unwrapped = env
            .key_store()
            .unwrap_credential(&credential_id, &[0x55; 32])
            .unwrap()
            .unwrap();
        assert_eq!(credential_source, unwrapped);
    }

    #[test]
    fn test_wrap_unwrap_credential_ecdsa() {
        test_wrap_unwrap_credential(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_wrap_unwrap_credential_ed25519() {
        test_wrap_unwrap_credential(SignatureAlgorithm::Eddsa);
    }

    fn test_wrap_unwrap_credential_bad_version(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);
        let credential_source = CredentialSource {
            private_key,
            rp_id_hash: [0x55; 32],
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationOptional),
            cred_blob: Some(vec![0xAA; 32]),
        };
        let mut credential_id = env.key_store().wrap_credential(credential_source).unwrap();
        credential_id[0] = UNSUPPORTED_CREDENTIAL_ID_VERSION;
        // Override the HMAC to pass the check.
        credential_id.truncate(&credential_id.len() - 32);
        let hmac_key = get_master_keys(&mut env).unwrap().authentication;
        let mut id_hmac = [0; HASH_SIZE];
        Hmac::<TestEnv>::mac(&hmac_key, &credential_id[..], &mut id_hmac);
        credential_id.extend(&id_hmac);
        let unwrapped = env
            .key_store()
            .unwrap_credential(&credential_id, &[0x55; 32]);
        assert_eq!(unwrapped, Ok(None));
    }

    #[test]
    fn test_wrap_unwrap_credential_bad_version_ecdsa() {
        test_wrap_unwrap_credential_bad_version(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_wrap_unwrap_credential_bad_version_ed25519() {
        test_wrap_unwrap_credential_bad_version(SignatureAlgorithm::Eddsa);
    }

    fn test_wrap_unwrap_credential_bad_hmac(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);
        let credential_source = CredentialSource {
            private_key,
            rp_id_hash: [0x55; 32],
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationOptional),
            cred_blob: Some(vec![0xAA; 32]),
        };
        let mut credential_id = env.key_store().wrap_credential(credential_source).unwrap();
        let hmac_byte_index = credential_id.len() - 1;
        credential_id[hmac_byte_index] ^= 0x01;
        let unwrapped = env
            .key_store()
            .unwrap_credential(&credential_id, &[0x55; 32]);
        assert_eq!(unwrapped, Ok(None));
    }

    #[test]
    fn test_wrap_unwrap_credential_bad_hmac_ecdsa() {
        test_wrap_unwrap_credential_bad_hmac(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_wrap_unwrap_credential_bad_hmac_ed25519() {
        test_wrap_unwrap_credential_bad_hmac(SignatureAlgorithm::Eddsa);
    }

    fn test_wrap_unwrap_credential_missing_blocks(signature_algorithm: SignatureAlgorithm) {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new(&mut env, signature_algorithm);
        let credential_source = CredentialSource {
            private_key,
            rp_id_hash: [0x55; 32],
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationOptional),
            cred_blob: Some(vec![0xAA; 32]),
        };
        let credential_id = env.key_store().wrap_credential(credential_source).unwrap();
        for length in (1..CBOR_CREDENTIAL_ID_SIZE).step_by(16) {
            let unwrapped = env
                .key_store()
                .unwrap_credential(&credential_id[..length], &[0x55; 32]);
            assert_eq!(unwrapped, Ok(None));
        }
    }

    #[test]
    fn test_wrap_unwrap_credential_missing_blocks_ecdsa() {
        test_wrap_unwrap_credential_missing_blocks(SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_wrap_unwrap_credential_missing_blocks_ed25519() {
        test_wrap_unwrap_credential_missing_blocks(SignatureAlgorithm::Eddsa);
    }

    #[test]
    fn test_wrap_credential_size() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::Es256);
        let credential_source = CredentialSource {
            private_key,
            rp_id_hash: [0x55; 32],
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationOptional),
            cred_blob: Some(vec![0xAA; 32]),
        };
        let credential_id = env.key_store().wrap_credential(credential_source).unwrap();
        assert_eq!(credential_id.len(), CBOR_CREDENTIAL_ID_SIZE);
    }

    #[test]
    fn test_wrap_credential_max_size() {
        // The CBOR encoding length is variadic and depends on size of fields. Ensure that contents
        // still fit into the padded size when we use maximum length entries.
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new(&mut env, SignatureAlgorithm::Es256);
        let credential_source = CredentialSource {
            private_key,
            rp_id_hash: [0x55; 32],
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationOptional),
            cred_blob: Some(vec![0xAA; env.customization().max_cred_blob_length()]),
        };
        let credential_id = env.key_store().wrap_credential(credential_source);
        assert!(credential_id.is_ok());
    }
}
