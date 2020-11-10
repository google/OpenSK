// Copyright 2019 Google LLC
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

#[cfg(feature = "with_ctap2_1")]
use crate::ctap::data_formats::{extract_array, extract_text_string};
use crate::ctap::data_formats::{CredentialProtectionPolicy, PublicKeyCredentialSource};
use crate::ctap::pin_protocol_v1::PIN_AUTH_LENGTH;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::{key_material, USE_BATCH_ATTESTATION};
use crate::embedded_flash::{self, StoreConfig, StoreEntry, StoreError};
use alloc::string::String;
#[cfg(any(test, feature = "ram_storage", feature = "with_ctap2_1"))]
use alloc::vec;
use alloc::vec::Vec;
use arrayref::array_ref;
#[cfg(feature = "with_ctap2_1")]
use cbor::cbor_array_vec;
use core::convert::TryInto;
use crypto::rng256::Rng256;

#[cfg(any(test, feature = "ram_storage"))]
type Storage = embedded_flash::BufferStorage;
#[cfg(not(any(test, feature = "ram_storage")))]
type Storage = embedded_flash::SyscallStorage;

// Those constants may be modified before compilation to tune the behavior of the key.
//
// The number of pages should be at least 2 and at most what the flash can hold. There should be no
// reason to put a small number here, except that the latency of flash operations depends on the
// number of pages. This will improve in the future. Currently, using 20 pages gives 65ms per
// operation. The rule of thumb is 3.5ms per additional page.
//
// Limiting the number of residential keys permits to ensure a minimum number of counter increments.
// Let:
// - P the number of pages (NUM_PAGES)
// - K the maximum number of residential keys (MAX_SUPPORTED_RESIDENTIAL_KEYS)
// - S the maximum size of a residential key (about 500)
// - C the number of erase cycles (10000)
// - I the minimum number of counter increments
//
// We have: I = ((P - 1) * 4092 - K * S) / 12 * C
//
// With P=20 and K=150, we have I > 2M which is enough for 500 increments per day for 10 years.
#[cfg(feature = "ram_storage")]
const NUM_PAGES: usize = 2;
#[cfg(not(feature = "ram_storage"))]
const NUM_PAGES: usize = 20;
const MAX_SUPPORTED_RESIDENTIAL_KEYS: usize = 150;

// List of tags. They should all be unique. And there should be less than NUM_TAGS.
const TAG_CREDENTIAL: usize = 0;
const GLOBAL_SIGNATURE_COUNTER: usize = 1;
const MASTER_KEYS: usize = 2;
const PIN_HASH: usize = 3;
const PIN_RETRIES: usize = 4;
const ATTESTATION_PRIVATE_KEY: usize = 5;
const ATTESTATION_CERTIFICATE: usize = 6;
const AAGUID: usize = 7;
#[cfg(feature = "with_ctap2_1")]
const MIN_PIN_LENGTH: usize = 8;
#[cfg(feature = "with_ctap2_1")]
const MIN_PIN_LENGTH_RP_IDS: usize = 9;
// Different NUM_TAGS depending on the CTAP version make the storage incompatible,
// so we use the maximum.
const NUM_TAGS: usize = 10;

const MAX_PIN_RETRIES: u8 = 8;
const ATTESTATION_PRIVATE_KEY_LENGTH: usize = 32;
const AAGUID_LENGTH: usize = 16;
#[cfg(feature = "with_ctap2_1")]
const DEFAULT_MIN_PIN_LENGTH: u8 = 4;
// TODO(kaczmarczyck) use this for the minPinLength extension
// https://github.com/google/OpenSK/issues/129
#[cfg(feature = "with_ctap2_1")]
const _DEFAULT_MIN_PIN_LENGTH_RP_IDS: Vec<String> = Vec::new();
// TODO(kaczmarczyck) Check whether this constant is necessary, or replace it accordingly.
#[cfg(feature = "with_ctap2_1")]
const _MAX_RP_IDS_LENGTH: usize = 8;

#[allow(clippy::enum_variant_names)]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    // TODO(cretin): Test whether this doesn't consume too much memory. Otherwise, we can use less
    // keys. Either only a simple enum value for all credentials, or group by rp_id.
    Credential {
        rp_id: Option<String>,
        credential_id: Option<Vec<u8>>,
        user_handle: Option<Vec<u8>>,
    },
    GlobalSignatureCounter,
    MasterKeys,
    PinHash,
    PinRetries,
    AttestationPrivateKey,
    AttestationCertificate,
    Aaguid,
    #[cfg(feature = "with_ctap2_1")]
    MinPinLength,
    #[cfg(feature = "with_ctap2_1")]
    MinPinLengthRpIds,
}

pub struct MasterKeys {
    pub encryption: [u8; 32],
    pub hmac: [u8; 32],
}

struct Config;

impl StoreConfig for Config {
    type Key = Key;

    fn num_tags(&self) -> usize {
        NUM_TAGS
    }

    fn keys(&self, entry: StoreEntry, mut add: impl FnMut(Key)) {
        match entry.tag {
            TAG_CREDENTIAL => {
                let credential = match deserialize_credential(entry.data) {
                    None => {
                        debug_assert!(false);
                        return;
                    }
                    Some(credential) => credential,
                };
                add(Key::Credential {
                    rp_id: Some(credential.rp_id.clone()),
                    credential_id: Some(credential.credential_id),
                    user_handle: None,
                });
                add(Key::Credential {
                    rp_id: Some(credential.rp_id.clone()),
                    credential_id: None,
                    user_handle: None,
                });
                add(Key::Credential {
                    rp_id: Some(credential.rp_id),
                    credential_id: None,
                    user_handle: Some(credential.user_handle),
                });
                add(Key::Credential {
                    rp_id: None,
                    credential_id: None,
                    user_handle: None,
                });
            }
            GLOBAL_SIGNATURE_COUNTER => add(Key::GlobalSignatureCounter),
            MASTER_KEYS => add(Key::MasterKeys),
            PIN_HASH => add(Key::PinHash),
            PIN_RETRIES => add(Key::PinRetries),
            ATTESTATION_PRIVATE_KEY => add(Key::AttestationPrivateKey),
            ATTESTATION_CERTIFICATE => add(Key::AttestationCertificate),
            AAGUID => add(Key::Aaguid),
            #[cfg(feature = "with_ctap2_1")]
            MIN_PIN_LENGTH => add(Key::MinPinLength),
            #[cfg(feature = "with_ctap2_1")]
            MIN_PIN_LENGTH_RP_IDS => add(Key::MinPinLengthRpIds),
            _ => debug_assert!(false),
        }
    }
}

pub struct PersistentStore {
    store: embedded_flash::Store<Storage, Config>,
}

impl PersistentStore {
    /// Gives access to the persistent store.
    ///
    /// # Safety
    ///
    /// This should be at most one instance of persistent store per program lifetime.
    pub fn new(rng: &mut impl Rng256) -> PersistentStore {
        #[cfg(not(any(test, feature = "ram_storage")))]
        let storage = PersistentStore::new_prod_storage();
        #[cfg(any(test, feature = "ram_storage"))]
        let storage = PersistentStore::new_test_storage();
        let mut store = PersistentStore {
            store: embedded_flash::Store::new(storage, Config).unwrap(),
        };
        store.init(rng);
        store
    }

    #[cfg(not(any(test, feature = "ram_storage")))]
    fn new_prod_storage() -> Storage {
        Storage::new(NUM_PAGES).unwrap()
    }

    #[cfg(any(test, feature = "ram_storage"))]
    fn new_test_storage() -> Storage {
        #[cfg(not(test))]
        const PAGE_SIZE: usize = 0x100;
        #[cfg(test)]
        const PAGE_SIZE: usize = 0x1000;
        let store = vec![0xff; NUM_PAGES * PAGE_SIZE].into_boxed_slice();
        let options = embedded_flash::BufferOptions {
            word_size: 4,
            page_size: PAGE_SIZE,
            max_word_writes: 2,
            max_page_erases: 10000,
            strict_write: true,
        };
        Storage::new(store, options)
    }

    fn init(&mut self, rng: &mut impl Rng256) {
        if self.store.find_one(&Key::MasterKeys).is_none() {
            let master_encryption_key = rng.gen_uniform_u8x32();
            let master_hmac_key = rng.gen_uniform_u8x32();
            let mut master_keys = Vec::with_capacity(64);
            master_keys.extend_from_slice(&master_encryption_key);
            master_keys.extend_from_slice(&master_hmac_key);
            self.store
                .insert(StoreEntry {
                    tag: MASTER_KEYS,
                    data: &master_keys,
                    sensitive: true,
                })
                .unwrap();
        }
        // The following 3 entries are meant to be written by vendor-specific commands.
        if USE_BATCH_ATTESTATION {
            if self.store.find_one(&Key::AttestationPrivateKey).is_none() {
                self.set_attestation_private_key(key_material::ATTESTATION_PRIVATE_KEY)
                    .unwrap();
            }
            if self.store.find_one(&Key::AttestationCertificate).is_none() {
                self.set_attestation_certificate(key_material::ATTESTATION_CERTIFICATE)
                    .unwrap();
            }
        }
        if self.store.find_one(&Key::Aaguid).is_none() {
            self.set_aaguid(key_material::AAGUID).unwrap();
        }
    }

    pub fn find_credential(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        check_cred_protect: bool,
    ) -> Result<Option<PublicKeyCredentialSource>, Ctap2StatusCode> {
        let key = Key::Credential {
            rp_id: Some(rp_id.into()),
            credential_id: Some(credential_id.into()),
            user_handle: None,
        };
        let entry = match self.store.find_one(&key) {
            None => return Ok(None),
            Some((_, entry)) => entry,
        };
        debug_assert_eq!(entry.tag, TAG_CREDENTIAL);
        let result = deserialize_credential(entry.data);
        debug_assert!(result.is_some());
        let user_verification_required = result.as_ref().map_or(false, |cred| {
            cred.cred_protect_policy == Some(CredentialProtectionPolicy::UserVerificationRequired)
        });
        if check_cred_protect && user_verification_required {
            Ok(None)
        } else {
            Ok(result)
        }
    }

    pub fn store_credential(
        &mut self,
        credential: PublicKeyCredentialSource,
    ) -> Result<(), Ctap2StatusCode> {
        let key = Key::Credential {
            rp_id: Some(credential.rp_id.clone()),
            credential_id: None,
            user_handle: Some(credential.user_handle.clone()),
        };
        let old_entry = self.store.find_one(&key);
        if old_entry.is_none() && self.count_credentials()? >= MAX_SUPPORTED_RESIDENTIAL_KEYS {
            return Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL);
        }
        let credential = serialize_credential(credential)?;
        let new_entry = StoreEntry {
            tag: TAG_CREDENTIAL,
            data: &credential,
            sensitive: true,
        };
        match old_entry {
            None => self.store.insert(new_entry)?,
            Some((index, old_entry)) => {
                debug_assert_eq!(old_entry.tag, TAG_CREDENTIAL);
                self.store.replace(index, new_entry)?
            }
        };
        Ok(())
    }

    pub fn filter_credential(
        &self,
        rp_id: &str,
        check_cred_protect: bool,
    ) -> Result<Vec<PublicKeyCredentialSource>, Ctap2StatusCode> {
        Ok(self
            .store
            .find_all(&Key::Credential {
                rp_id: Some(rp_id.into()),
                credential_id: None,
                user_handle: None,
            })
            .filter_map(|(_, entry)| {
                debug_assert_eq!(entry.tag, TAG_CREDENTIAL);
                let credential = deserialize_credential(entry.data);
                debug_assert!(credential.is_some());
                credential
            })
            .filter(|cred| !check_cred_protect || cred.is_discoverable())
            .collect())
    }

    pub fn count_credentials(&self) -> Result<usize, Ctap2StatusCode> {
        Ok(self
            .store
            .find_all(&Key::Credential {
                rp_id: None,
                credential_id: None,
                user_handle: None,
            })
            .count())
    }

    pub fn global_signature_counter(&self) -> Result<u32, Ctap2StatusCode> {
        Ok(self
            .store
            .find_one(&Key::GlobalSignatureCounter)
            .map_or(0, |(_, entry)| {
                u32::from_ne_bytes(*array_ref!(entry.data, 0, 4))
            }))
    }

    pub fn incr_global_signature_counter(&mut self) -> Result<(), Ctap2StatusCode> {
        let mut buffer = [0; core::mem::size_of::<u32>()];
        match self.store.find_one(&Key::GlobalSignatureCounter) {
            None => {
                buffer.copy_from_slice(&1u32.to_ne_bytes());
                self.store.insert(StoreEntry {
                    tag: GLOBAL_SIGNATURE_COUNTER,
                    data: &buffer,
                    sensitive: false,
                })?;
            }
            Some((index, entry)) => {
                let value = u32::from_ne_bytes(*array_ref!(entry.data, 0, 4));
                // In hopes that servers handle the wrapping gracefully.
                buffer.copy_from_slice(&value.wrapping_add(1).to_ne_bytes());
                self.store.replace(
                    index,
                    StoreEntry {
                        tag: GLOBAL_SIGNATURE_COUNTER,
                        data: &buffer,
                        sensitive: false,
                    },
                )?;
            }
        }
        Ok(())
    }

    pub fn master_keys(&self) -> Result<MasterKeys, Ctap2StatusCode> {
        let (_, entry) = self.store.find_one(&Key::MasterKeys).unwrap();
        if entry.data.len() != 64 {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        Ok(MasterKeys {
            encryption: *array_ref![entry.data, 0, 32],
            hmac: *array_ref![entry.data, 32, 32],
        })
    }

    pub fn pin_hash(&self) -> Result<Option<[u8; PIN_AUTH_LENGTH]>, Ctap2StatusCode> {
        let data = match self.store.find_one(&Key::PinHash) {
            None => return Ok(None),
            Some((_, entry)) => entry.data,
        };
        if data.len() != PIN_AUTH_LENGTH {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        Ok(Some(*array_ref![data, 0, PIN_AUTH_LENGTH]))
    }

    pub fn set_pin_hash(
        &mut self,
        pin_hash: &[u8; PIN_AUTH_LENGTH],
    ) -> Result<(), Ctap2StatusCode> {
        let entry = StoreEntry {
            tag: PIN_HASH,
            data: pin_hash,
            sensitive: true,
        };
        match self.store.find_one(&Key::PinHash) {
            None => self.store.insert(entry)?,
            Some((index, _)) => self.store.replace(index, entry)?,
        }
        Ok(())
    }

    pub fn pin_retries(&self) -> Result<u8, Ctap2StatusCode> {
        Ok(self
            .store
            .find_one(&Key::PinRetries)
            .map_or(MAX_PIN_RETRIES, |(_, entry)| {
                debug_assert_eq!(entry.data.len(), 1);
                entry.data[0]
            }))
    }

    pub fn decr_pin_retries(&mut self) -> Result<(), Ctap2StatusCode> {
        match self.store.find_one(&Key::PinRetries) {
            None => {
                self.store.insert(StoreEntry {
                    tag: PIN_RETRIES,
                    data: &[MAX_PIN_RETRIES.saturating_sub(1)],
                    sensitive: false,
                })?;
            }
            Some((index, entry)) => {
                debug_assert_eq!(entry.data.len(), 1);
                if entry.data[0] == 0 {
                    return Ok(());
                }
                let new_value = entry.data[0].saturating_sub(1);
                self.store.replace(
                    index,
                    StoreEntry {
                        tag: PIN_RETRIES,
                        data: &[new_value],
                        sensitive: false,
                    },
                )?;
            }
        }
        Ok(())
    }

    pub fn reset_pin_retries(&mut self) -> Result<(), Ctap2StatusCode> {
        if let Some((index, _)) = self.store.find_one(&Key::PinRetries) {
            self.store.delete(index)?;
        }
        Ok(())
    }

    #[cfg(feature = "with_ctap2_1")]
    pub fn min_pin_length(&self) -> Result<u8, Ctap2StatusCode> {
        Ok(self
            .store
            .find_one(&Key::MinPinLength)
            .map_or(DEFAULT_MIN_PIN_LENGTH, |(_, entry)| {
                debug_assert_eq!(entry.data.len(), 1);
                entry.data[0]
            }))
    }

    #[cfg(feature = "with_ctap2_1")]
    pub fn set_min_pin_length(&mut self, min_pin_length: u8) -> Result<(), Ctap2StatusCode> {
        let entry = StoreEntry {
            tag: MIN_PIN_LENGTH,
            data: &[min_pin_length],
            sensitive: false,
        };
        Ok(match self.store.find_one(&Key::MinPinLength) {
            None => self.store.insert(entry)?,
            Some((index, _)) => self.store.replace(index, entry)?,
        })
    }

    #[cfg(feature = "with_ctap2_1")]
    pub fn _min_pin_length_rp_ids(&self) -> Result<Vec<String>, Ctap2StatusCode> {
        let rp_ids = self
            .store
            .find_one(&Key::MinPinLengthRpIds)
            .map_or(Some(_DEFAULT_MIN_PIN_LENGTH_RP_IDS), |(_, entry)| {
                _deserialize_min_pin_length_rp_ids(entry.data)
            });
        debug_assert!(rp_ids.is_some());
        Ok(rp_ids.unwrap_or(vec![]))
    }

    #[cfg(feature = "with_ctap2_1")]
    pub fn _set_min_pin_length_rp_ids(
        &mut self,
        min_pin_length_rp_ids: Vec<String>,
    ) -> Result<(), Ctap2StatusCode> {
        let mut min_pin_length_rp_ids = min_pin_length_rp_ids;
        for rp_id in _DEFAULT_MIN_PIN_LENGTH_RP_IDS {
            if !min_pin_length_rp_ids.contains(&rp_id) {
                min_pin_length_rp_ids.push(rp_id);
            }
        }
        if min_pin_length_rp_ids.len() > _MAX_RP_IDS_LENGTH {
            return Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL);
        }
        let entry = StoreEntry {
            tag: MIN_PIN_LENGTH_RP_IDS,
            data: &_serialize_min_pin_length_rp_ids(min_pin_length_rp_ids)?,
            sensitive: false,
        };
        match self.store.find_one(&Key::MinPinLengthRpIds) {
            None => {
                self.store.insert(entry).unwrap();
            }
            Some((index, _)) => {
                self.store.replace(index, entry).unwrap();
            }
        }
        Ok(())
    }

    pub fn attestation_private_key(
        &self,
    ) -> Result<Option<&[u8; ATTESTATION_PRIVATE_KEY_LENGTH]>, Ctap2StatusCode> {
        let data = match self.store.find_one(&Key::AttestationPrivateKey) {
            None => return Ok(None),
            Some((_, entry)) => entry.data,
        };
        if data.len() != ATTESTATION_PRIVATE_KEY_LENGTH {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        Ok(Some(array_ref!(data, 0, ATTESTATION_PRIVATE_KEY_LENGTH)))
    }

    pub fn set_attestation_private_key(
        &mut self,
        attestation_private_key: &[u8; ATTESTATION_PRIVATE_KEY_LENGTH],
    ) -> Result<(), Ctap2StatusCode> {
        let entry = StoreEntry {
            tag: ATTESTATION_PRIVATE_KEY,
            data: attestation_private_key,
            sensitive: false,
        };
        match self.store.find_one(&Key::AttestationPrivateKey) {
            None => self.store.insert(entry)?,
            Some((index, _)) => self.store.replace(index, entry)?,
        }
        Ok(())
    }

    pub fn attestation_certificate(&self) -> Result<Option<Vec<u8>>, Ctap2StatusCode> {
        let data = match self.store.find_one(&Key::AttestationCertificate) {
            None => return Ok(None),
            Some((_, entry)) => entry.data,
        };
        Ok(Some(data.to_vec()))
    }

    pub fn set_attestation_certificate(
        &mut self,
        attestation_certificate: &[u8],
    ) -> Result<(), Ctap2StatusCode> {
        let entry = StoreEntry {
            tag: ATTESTATION_CERTIFICATE,
            data: attestation_certificate,
            sensitive: false,
        };
        match self.store.find_one(&Key::AttestationCertificate) {
            None => self.store.insert(entry)?,
            Some((index, _)) => self.store.replace(index, entry)?,
        }
        Ok(())
    }

    pub fn aaguid(&self) -> Result<[u8; AAGUID_LENGTH], Ctap2StatusCode> {
        let (_, entry) = self
            .store
            .find_one(&Key::Aaguid)
            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
        let data = entry.data;
        if data.len() != AAGUID_LENGTH {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        Ok(*array_ref![data, 0, AAGUID_LENGTH])
    }

    pub fn set_aaguid(&mut self, aaguid: &[u8; AAGUID_LENGTH]) -> Result<(), Ctap2StatusCode> {
        let entry = StoreEntry {
            tag: AAGUID,
            data: aaguid,
            sensitive: false,
        };
        match self.store.find_one(&Key::Aaguid) {
            None => self.store.insert(entry)?,
            Some((index, _)) => self.store.replace(index, entry)?,
        }
        Ok(())
    }

    pub fn reset(&mut self, rng: &mut impl Rng256) -> Result<(), Ctap2StatusCode> {
        loop {
            let index = {
                let mut iter = self.store.iter().filter(|(_, entry)| should_reset(entry));
                match iter.next() {
                    None => break,
                    Some((index, _)) => index,
                }
            };
            self.store.delete(index)?;
        }
        self.init(rng);
        Ok(())
    }
}

impl From<StoreError> for Ctap2StatusCode {
    fn from(error: StoreError) -> Ctap2StatusCode {
        match error {
            StoreError::StoreFull => Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL,
            StoreError::InvalidTag => unreachable!(),
            StoreError::InvalidPrecondition => unreachable!(),
        }
    }
}

fn should_reset(entry: &StoreEntry<'_>) -> bool {
    match entry.tag {
        ATTESTATION_PRIVATE_KEY | ATTESTATION_CERTIFICATE | AAGUID => false,
        _ => true,
    }
}

fn deserialize_credential(data: &[u8]) -> Option<PublicKeyCredentialSource> {
    let cbor = cbor::read(data).ok()?;
    cbor.try_into().ok()
}

fn serialize_credential(credential: PublicKeyCredentialSource) -> Result<Vec<u8>, Ctap2StatusCode> {
    let mut data = Vec::new();
    if cbor::write(credential.into(), &mut data) {
        Ok(data)
    } else {
        Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_RESPONSE_CANNOT_WRITE_CBOR)
    }
}

#[cfg(feature = "with_ctap2_1")]
fn _deserialize_min_pin_length_rp_ids(data: &[u8]) -> Option<Vec<String>> {
    let cbor = cbor::read(data).ok()?;
    extract_array(cbor)
        .ok()?
        .into_iter()
        .map(extract_text_string)
        .collect::<Result<Vec<String>, Ctap2StatusCode>>()
        .ok()
}

#[cfg(feature = "with_ctap2_1")]
fn _serialize_min_pin_length_rp_ids(rp_ids: Vec<String>) -> Result<Vec<u8>, Ctap2StatusCode> {
    let mut data = Vec::new();
    if cbor::write(cbor_array_vec!(rp_ids), &mut data) {
        Ok(data)
    } else {
        Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_RESPONSE_CANNOT_WRITE_CBOR)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ctap::data_formats::{PublicKeyCredentialSource, PublicKeyCredentialType};
    use crypto::rng256::{Rng256, ThreadRng256};

    fn create_credential_source(
        rng: &mut ThreadRng256,
        rp_id: &str,
        user_handle: Vec<u8>,
    ) -> PublicKeyCredentialSource {
        let private_key = crypto::ecdsa::SecKey::gensk(rng);
        PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: rng.gen_uniform_u8x32().to_vec(),
            private_key,
            rp_id: String::from(rp_id),
            user_handle,
            other_ui: None,
            cred_random: None,
            cred_protect_policy: None,
        }
    }

    #[test]
    fn format_overhead() {
        // nRF52840 NVMC
        const WORD_SIZE: usize = 4;
        const PAGE_SIZE: usize = 0x1000;
        const NUM_PAGES: usize = 100;
        let store = vec![0xff; NUM_PAGES * PAGE_SIZE].into_boxed_slice();
        let options = embedded_flash::BufferOptions {
            word_size: WORD_SIZE,
            page_size: PAGE_SIZE,
            max_word_writes: 2,
            max_page_erases: 10000,
            strict_write: true,
        };
        let storage = Storage::new(store, options);
        let store = embedded_flash::Store::new(storage, Config).unwrap();
        // We can replace 3 bytes with minimal overhead.
        assert_eq!(store.replace_len(false, 0), 2 * WORD_SIZE);
        assert_eq!(store.replace_len(false, 3), 3 * WORD_SIZE);
        assert_eq!(store.replace_len(false, 4), 3 * WORD_SIZE);
    }

    #[test]
    fn test_store() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials().unwrap(), 0);
        let credential_source = create_credential_source(&mut rng, "example.com", vec![]);
        assert!(persistent_store.store_credential(credential_source).is_ok());
        assert!(persistent_store.count_credentials().unwrap() > 0);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_fill_store() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials().unwrap(), 0);

        // To make this test work for bigger storages, implement better int -> Vec conversion.
        assert!(MAX_SUPPORTED_RESIDENTIAL_KEYS < 256);
        for i in 0..MAX_SUPPORTED_RESIDENTIAL_KEYS {
            let credential_source =
                create_credential_source(&mut rng, "example.com", vec![i as u8]);
            assert!(persistent_store.store_credential(credential_source).is_ok());
            assert_eq!(persistent_store.count_credentials().unwrap(), i + 1);
        }
        let credential_source = create_credential_source(
            &mut rng,
            "example.com",
            vec![MAX_SUPPORTED_RESIDENTIAL_KEYS as u8],
        );
        assert_eq!(
            persistent_store.store_credential(credential_source),
            Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL)
        );
        assert_eq!(
            persistent_store.count_credentials().unwrap(),
            MAX_SUPPORTED_RESIDENTIAL_KEYS
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_overwrite() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials().unwrap(), 0);
        // These should have different IDs.
        let credential_source0 = create_credential_source(&mut rng, "example.com", vec![0x00]);
        let credential_source1 = create_credential_source(&mut rng, "example.com", vec![0x00]);
        let expected_credential = credential_source1.clone();

        assert!(persistent_store
            .store_credential(credential_source0)
            .is_ok());
        assert!(persistent_store
            .store_credential(credential_source1)
            .is_ok());
        assert_eq!(persistent_store.count_credentials().unwrap(), 1);
        assert_eq!(
            &persistent_store
                .filter_credential("example.com", false)
                .unwrap(),
            &[expected_credential]
        );

        // To make this test work for bigger storages, implement better int -> Vec conversion.
        assert!(MAX_SUPPORTED_RESIDENTIAL_KEYS < 256);
        for i in 0..MAX_SUPPORTED_RESIDENTIAL_KEYS {
            let credential_source =
                create_credential_source(&mut rng, "example.com", vec![i as u8]);
            assert!(persistent_store.store_credential(credential_source).is_ok());
            assert_eq!(persistent_store.count_credentials().unwrap(), i + 1);
        }
        let credential_source = create_credential_source(
            &mut rng,
            "example.com",
            vec![MAX_SUPPORTED_RESIDENTIAL_KEYS as u8],
        );
        assert_eq!(
            persistent_store.store_credential(credential_source),
            Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL)
        );
        assert_eq!(
            persistent_store.count_credentials().unwrap(),
            MAX_SUPPORTED_RESIDENTIAL_KEYS
        );
    }

    #[test]
    fn test_filter() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials().unwrap(), 0);
        let credential_source0 = create_credential_source(&mut rng, "example.com", vec![0x00]);
        let credential_source1 = create_credential_source(&mut rng, "example.com", vec![0x01]);
        let credential_source2 =
            create_credential_source(&mut rng, "another.example.com", vec![0x02]);
        let id0 = credential_source0.credential_id.clone();
        let id1 = credential_source1.credential_id.clone();
        assert!(persistent_store
            .store_credential(credential_source0)
            .is_ok());
        assert!(persistent_store
            .store_credential(credential_source1)
            .is_ok());
        assert!(persistent_store
            .store_credential(credential_source2)
            .is_ok());

        let filtered_credentials = persistent_store
            .filter_credential("example.com", false)
            .unwrap();
        assert_eq!(filtered_credentials.len(), 2);
        assert!(
            (filtered_credentials[0].credential_id == id0
                && filtered_credentials[1].credential_id == id1)
                || (filtered_credentials[1].credential_id == id0
                    && filtered_credentials[0].credential_id == id1)
        );
    }

    #[test]
    fn test_filter_with_cred_protect() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials().unwrap(), 0);
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: rng.gen_uniform_u8x32().to_vec(),
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x00],
            other_ui: None,
            cred_random: None,
            cred_protect_policy: Some(
                CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
            ),
        };
        assert!(persistent_store.store_credential(credential).is_ok());

        let no_credential = persistent_store
            .filter_credential("example.com", true)
            .unwrap();
        assert_eq!(no_credential, vec![]);
    }

    #[test]
    fn test_find() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials().unwrap(), 0);
        let credential_source0 = create_credential_source(&mut rng, "example.com", vec![0x00]);
        let credential_source1 = create_credential_source(&mut rng, "example.com", vec![0x01]);
        let id0 = credential_source0.credential_id.clone();
        let key0 = credential_source0.private_key.clone();
        assert!(persistent_store
            .store_credential(credential_source0)
            .is_ok());
        assert!(persistent_store
            .store_credential(credential_source1)
            .is_ok());

        let no_credential = persistent_store
            .find_credential("another.example.com", &id0, false)
            .unwrap();
        assert_eq!(no_credential, None);
        let found_credential = persistent_store
            .find_credential("example.com", &id0, false)
            .unwrap();
        let expected_credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: id0,
            private_key: key0,
            rp_id: String::from("example.com"),
            user_handle: vec![0x00],
            other_ui: None,
            cred_random: None,
            cred_protect_policy: None,
        };
        assert_eq!(found_credential, Some(expected_credential));
    }

    #[test]
    fn test_find_with_cred_protect() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials().unwrap(), 0);
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: rng.gen_uniform_u8x32().to_vec(),
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x00],
            other_ui: None,
            cred_random: None,
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationRequired),
        };
        assert!(persistent_store.store_credential(credential).is_ok());

        let no_credential = persistent_store
            .find_credential("example.com", &[0x00], true)
            .unwrap();
        assert_eq!(no_credential, None);
    }

    #[test]
    fn test_master_keys() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // Master keys stay the same between resets.
        let master_keys_1 = persistent_store.master_keys().unwrap();
        let master_keys_2 = persistent_store.master_keys().unwrap();
        assert_eq!(master_keys_2.encryption, master_keys_1.encryption);
        assert_eq!(master_keys_2.hmac, master_keys_1.hmac);

        // Master keys change after reset. This test may fail if the random generator produces the
        // same keys.
        let master_encryption_key = master_keys_1.encryption.to_vec();
        let master_hmac_key = master_keys_1.hmac.to_vec();
        persistent_store.reset(&mut rng).unwrap();
        let master_keys_3 = persistent_store.master_keys().unwrap();
        assert!(master_keys_3.encryption != master_encryption_key.as_slice());
        assert!(master_keys_3.hmac != master_hmac_key.as_slice());
    }

    #[test]
    fn test_pin_hash() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // Pin hash is initially not set.
        assert!(persistent_store.pin_hash().unwrap().is_none());

        // Setting the pin hash sets the pin hash.
        let random_data = rng.gen_uniform_u8x32();
        assert_eq!(random_data.len(), 2 * PIN_AUTH_LENGTH);
        let pin_hash_1 = *array_ref!(random_data, 0, PIN_AUTH_LENGTH);
        let pin_hash_2 = *array_ref!(random_data, PIN_AUTH_LENGTH, PIN_AUTH_LENGTH);
        persistent_store.set_pin_hash(&pin_hash_1).unwrap();
        assert_eq!(persistent_store.pin_hash().unwrap(), Some(pin_hash_1));
        assert_eq!(persistent_store.pin_hash().unwrap(), Some(pin_hash_1));
        persistent_store.set_pin_hash(&pin_hash_2).unwrap();
        assert_eq!(persistent_store.pin_hash().unwrap(), Some(pin_hash_2));
        assert_eq!(persistent_store.pin_hash().unwrap(), Some(pin_hash_2));

        // Resetting the storage resets the pin hash.
        persistent_store.reset(&mut rng).unwrap();
        assert!(persistent_store.pin_hash().unwrap().is_none());
    }

    #[test]
    fn test_pin_retries() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // The pin retries is initially at the maximum.
        assert_eq!(persistent_store.pin_retries().unwrap(), MAX_PIN_RETRIES);

        // Decrementing the pin retries decrements the pin retries.
        for pin_retries in (0..MAX_PIN_RETRIES).rev() {
            persistent_store.decr_pin_retries().unwrap();
            assert_eq!(persistent_store.pin_retries().unwrap(), pin_retries);
        }

        // Decrementing the pin retries after zero does not modify the pin retries.
        persistent_store.decr_pin_retries().unwrap();
        assert_eq!(persistent_store.pin_retries().unwrap(), 0);

        // Resetting the pin retries resets the pin retries.
        persistent_store.reset_pin_retries().unwrap();
        assert_eq!(persistent_store.pin_retries().unwrap(), MAX_PIN_RETRIES);
    }

    #[test]
    fn test_persistent_keys() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // Make sure the attestation are absent. There is no batch attestation in tests.
        assert!(persistent_store
            .attestation_private_key()
            .unwrap()
            .is_none());
        assert!(persistent_store
            .attestation_certificate()
            .unwrap()
            .is_none());

        // Make sure the persistent keys are initialized.
        persistent_store
            .set_attestation_private_key(key_material::ATTESTATION_PRIVATE_KEY)
            .unwrap();
        persistent_store
            .set_attestation_certificate(key_material::ATTESTATION_CERTIFICATE)
            .unwrap();
        assert_eq!(&persistent_store.aaguid().unwrap(), key_material::AAGUID);

        // The persistent keys stay initialized and preserve their value after a reset.
        persistent_store.reset(&mut rng).unwrap();
        assert_eq!(
            persistent_store.attestation_private_key().unwrap().unwrap(),
            key_material::ATTESTATION_PRIVATE_KEY
        );
        assert_eq!(
            persistent_store.attestation_certificate().unwrap().unwrap(),
            key_material::ATTESTATION_CERTIFICATE
        );
        assert_eq!(&persistent_store.aaguid().unwrap(), key_material::AAGUID);
    }

    #[cfg(feature = "with_ctap2_1")]
    #[test]
    fn test_min_pin_length() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // The minimum PIN length is initially at the default.
        assert_eq!(
            persistent_store.min_pin_length().unwrap(),
            DEFAULT_MIN_PIN_LENGTH
        );

        // Changes by the setter are reflected by the getter..
        let new_min_pin_length = 8;
        persistent_store
            .set_min_pin_length(new_min_pin_length)
            .unwrap();
        assert_eq!(
            persistent_store.min_pin_length().unwrap(),
            new_min_pin_length
        );
    }

    #[cfg(feature = "with_ctap2_1")]
    #[test]
    fn test_min_pin_length_rp_ids() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // The minimum PIN length RP IDs are initially at the default.
        assert_eq!(
            persistent_store._min_pin_length_rp_ids().unwrap(),
            _DEFAULT_MIN_PIN_LENGTH_RP_IDS
        );

        // Changes by the setter are reflected by the getter.
        let mut rp_ids = vec![String::from("example.com")];
        assert_eq!(
            persistent_store._set_min_pin_length_rp_ids(rp_ids.clone()),
            Ok(())
        );
        for rp_id in _DEFAULT_MIN_PIN_LENGTH_RP_IDS {
            if !rp_ids.contains(&rp_id) {
                rp_ids.push(rp_id);
            }
        }
        assert_eq!(persistent_store._min_pin_length_rp_ids().unwrap(), rp_ids);
    }

    #[test]
    fn test_serialize_deserialize_credential() {
        let mut rng = ThreadRng256 {};
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: rng.gen_uniform_u8x32().to_vec(),
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x00],
            other_ui: None,
            cred_random: None,
            cred_protect_policy: None,
        };
        let serialized = serialize_credential(credential.clone()).unwrap();
        let reconstructed = deserialize_credential(&serialized).unwrap();
        assert_eq!(credential, reconstructed);
    }

    #[cfg(feature = "with_ctap2_1")]
    #[test]
    fn test_serialize_deserialize_min_pin_length_rp_ids() {
        let rp_ids = vec![String::from("example.com")];
        let serialized = _serialize_min_pin_length_rp_ids(rp_ids.clone()).unwrap();
        let reconstructed = _deserialize_min_pin_length_rp_ids(&serialized).unwrap();
        assert_eq!(rp_ids, reconstructed);
    }
}
