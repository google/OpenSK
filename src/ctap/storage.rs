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

use crate::crypto::rng256::Rng256;
use crate::ctap::data_formats::PublicKeyCredentialSource;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::PIN_AUTH_LENGTH;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryInto;
use ctap2::embedded_flash::{self, StoreConfig, StoreEntry, StoreError, StoreIndex};

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
const NUM_TAGS: usize = 5;

const MAX_PIN_RETRIES: u8 = 6;

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
}

pub struct MasterKeys<'a> {
    pub encryption: &'a [u8; 32],
    pub hmac: &'a [u8; 32],
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
            _ => debug_assert!(false),
        }
    }
}

pub struct PersistentStore {
    store: embedded_flash::Store<Storage, Config>,
}

#[cfg(feature = "ram_storage")]
const PAGE_SIZE: usize = 0x100;
#[cfg(not(feature = "ram_storage"))]
const PAGE_SIZE: usize = 0x1000;

const STORE_SIZE: usize = NUM_PAGES * PAGE_SIZE;

#[cfg(not(any(test, feature = "ram_storage")))]
#[link_section = ".app_state"]
static STORE: [u8; STORE_SIZE] = [0xff; STORE_SIZE];

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
        let store = unsafe {
            // Safety: The store cannot alias because this function is called only once.
            core::slice::from_raw_parts_mut(STORE.as_ptr() as *mut u8, STORE_SIZE)
        };
        unsafe {
            // Safety: The store is in a writeable flash region.
            Storage::new(store).unwrap()
        }
    }

    #[cfg(any(test, feature = "ram_storage"))]
    fn new_test_storage() -> Storage {
        let store = vec![0xff; STORE_SIZE].into_boxed_slice();
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
                })
                .unwrap();
        }
        if self.store.find_one(&Key::PinRetries).is_none() {
            self.store
                .insert(StoreEntry {
                    tag: PIN_RETRIES,
                    data: &[MAX_PIN_RETRIES],
                })
                .unwrap();
        }
    }

    pub fn find_credential(
        &self,
        rp_id: &str,
        credential_id: &[u8],
    ) -> Option<PublicKeyCredentialSource> {
        let key = Key::Credential {
            rp_id: Some(rp_id.into()),
            credential_id: Some(credential_id.into()),
            user_handle: None,
        };
        let (_, entry) = self.store.find_one(&key)?;
        debug_assert_eq!(entry.tag, TAG_CREDENTIAL);
        let result = deserialize_credential(entry.data);
        debug_assert!(result.is_some());
        result
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
        if old_entry.is_none() && self.count_credentials() >= MAX_SUPPORTED_RESIDENTIAL_KEYS {
            return Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL);
        }
        let credential = serialize_credential(credential)?;
        let new_entry = StoreEntry {
            tag: TAG_CREDENTIAL,
            data: &credential,
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

    pub fn filter_credential(&self, rp_id: &str) -> Vec<PublicKeyCredentialSource> {
        self.store
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
            .collect()
    }

    pub fn count_credentials(&self) -> usize {
        self.store
            .find_all(&Key::Credential {
                rp_id: None,
                credential_id: None,
                user_handle: None,
            })
            .count()
    }

    pub fn global_signature_counter(&self) -> u32 {
        self.store
            .find_one(&Key::GlobalSignatureCounter)
            .map_or(0, |(_, entry)| {
                u32::from_ne_bytes(*array_ref!(entry.data, 0, 4))
            })
    }

    pub fn incr_global_signature_counter(&mut self) {
        let mut buffer = [0; core::mem::size_of::<u32>()];
        match self.store.find_one(&Key::GlobalSignatureCounter) {
            None => {
                buffer.copy_from_slice(&1u32.to_ne_bytes());
                self.store
                    .insert(StoreEntry {
                        tag: GLOBAL_SIGNATURE_COUNTER,
                        data: &buffer,
                    })
                    .unwrap();
            }
            Some((index, entry)) => {
                let value = u32::from_ne_bytes(*array_ref!(entry.data, 0, 4));
                // In hopes that servers handle the wrapping gracefully.
                buffer.copy_from_slice(&value.wrapping_add(1).to_ne_bytes());
                self.store
                    .replace(
                        index,
                        StoreEntry {
                            tag: GLOBAL_SIGNATURE_COUNTER,
                            data: &buffer,
                        },
                    )
                    .unwrap();
            }
        }
    }

    pub fn master_keys(&self) -> MasterKeys {
        // We have as invariant that there is always exactly one MasterKeys entry in the store.
        let (_, entry) = self.store.find_one(&Key::MasterKeys).unwrap();
        let data = entry.data;
        // And this entry is well formed: the encryption key followed by the hmac key.
        let encryption = array_ref!(data, 0, 32);
        let hmac = array_ref!(data, 32, 32);
        MasterKeys { encryption, hmac }
    }

    pub fn pin_hash(&self) -> Option<&[u8; PIN_AUTH_LENGTH]> {
        self.store
            .find_one(&Key::PinHash)
            .map(|(_, entry)| array_ref!(entry.data, 0, PIN_AUTH_LENGTH))
    }

    pub fn set_pin_hash(&mut self, pin_hash: &[u8; PIN_AUTH_LENGTH]) {
        let entry = StoreEntry {
            tag: PIN_HASH,
            data: pin_hash,
        };
        match self.store.find_one(&Key::PinHash) {
            None => self.store.insert(entry).unwrap(),
            Some((index, _)) => {
                self.store.replace(index, entry).unwrap();
            }
        }
    }

    fn pin_retries_entry(&self) -> (StoreIndex, u8) {
        let (index, entry) = self.store.find_one(&Key::PinRetries).unwrap();
        let data = entry.data;
        debug_assert_eq!(data.len(), 1);
        (index, data[0])
    }

    pub fn pin_retries(&self) -> u8 {
        self.pin_retries_entry().1
    }

    pub fn decr_pin_retries(&mut self) {
        let (index, old_value) = self.pin_retries_entry();
        let new_value = old_value.saturating_sub(1);
        self.store
            .replace(
                index,
                StoreEntry {
                    tag: PIN_RETRIES,
                    data: &[new_value],
                },
            )
            .unwrap();
    }

    pub fn reset_pin_retries(&mut self) {
        let (index, _) = self.pin_retries_entry();
        self.store
            .replace(
                index,
                StoreEntry {
                    tag: PIN_RETRIES,
                    data: &[MAX_PIN_RETRIES],
                },
            )
            .unwrap();
    }

    pub fn reset(&mut self, rng: &mut impl Rng256) {
        loop {
            let index = {
                let mut iter = self.store.iter();
                match iter.next() {
                    None => break,
                    Some((index, _)) => index,
                }
            };
            self.store.delete(index).unwrap();
        }
        self.init(rng);
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

fn deserialize_credential(data: &[u8]) -> Option<PublicKeyCredentialSource> {
    let cbor = cbor::read(data).ok()?;
    cbor.try_into().ok()
}

fn serialize_credential(credential: PublicKeyCredentialSource) -> Result<Vec<u8>, Ctap2StatusCode> {
    let mut data = Vec::new();
    if cbor::write(credential.into(), &mut data) {
        Ok(data)
    } else {
        Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CREDENTIAL)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto;
    use crate::crypto::rng256::{Rng256, ThreadRng256};
    use crate::ctap::data_formats::{PublicKeyCredentialSource, PublicKeyCredentialType};

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
        assert_eq!(store.replace_len(0), 2 * WORD_SIZE);
        assert_eq!(store.replace_len(3), 2 * WORD_SIZE);
        assert_eq!(store.replace_len(4), 3 * WORD_SIZE);
    }

    #[test]
    fn test_store() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials(), 0);
        let credential_source = create_credential_source(&mut rng, "example.com", vec![]);
        assert!(persistent_store.store_credential(credential_source).is_ok());
        assert!(persistent_store.count_credentials() > 0);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_fill_store() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials(), 0);

        // To make this test work for bigger storages, implement better int -> Vec conversion.
        assert!(MAX_SUPPORTED_RESIDENTIAL_KEYS < 256);
        for i in 0..MAX_SUPPORTED_RESIDENTIAL_KEYS {
            let credential_source =
                create_credential_source(&mut rng, "example.com", vec![i as u8]);
            assert!(persistent_store.store_credential(credential_source).is_ok());
            assert_eq!(persistent_store.count_credentials(), i + 1);
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
            persistent_store.count_credentials(),
            MAX_SUPPORTED_RESIDENTIAL_KEYS
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_overwrite() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials(), 0);
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
        assert_eq!(persistent_store.count_credentials(), 1);
        assert_eq!(
            &persistent_store.filter_credential("example.com"),
            &[expected_credential]
        );

        // To make this test work for bigger storages, implement better int -> Vec conversion.
        assert!(MAX_SUPPORTED_RESIDENTIAL_KEYS < 256);
        for i in 0..MAX_SUPPORTED_RESIDENTIAL_KEYS {
            let credential_source =
                create_credential_source(&mut rng, "example.com", vec![i as u8]);
            assert!(persistent_store.store_credential(credential_source).is_ok());
            assert_eq!(persistent_store.count_credentials(), i + 1);
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
            persistent_store.count_credentials(),
            MAX_SUPPORTED_RESIDENTIAL_KEYS
        );
    }

    #[test]
    fn test_filter() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials(), 0);
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

        let filtered_credentials = persistent_store.filter_credential("example.com");
        assert_eq!(filtered_credentials.len(), 2);
        assert!(
            (filtered_credentials[0].credential_id == id0
                && filtered_credentials[1].credential_id == id1)
                || (filtered_credentials[1].credential_id == id0
                    && filtered_credentials[0].credential_id == id1)
        );
    }

    #[test]
    fn test_find() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials(), 0);
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

        let no_credential = persistent_store.find_credential("another.example.com", &id0);
        assert_eq!(no_credential, None);
        let found_credential = persistent_store.find_credential("example.com", &id0);
        let expected_credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: id0,
            private_key: key0,
            rp_id: String::from("example.com"),
            user_handle: vec![0x00],
            other_ui: None,
            cred_random: None,
        };
        assert_eq!(found_credential, Some(expected_credential));
    }

    #[test]
    fn test_master_keys() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // Master keys stay the same between resets.
        let master_keys_1 = persistent_store.master_keys();
        let master_keys_2 = persistent_store.master_keys();
        assert_eq!(master_keys_2.encryption, master_keys_1.encryption);
        assert_eq!(master_keys_2.hmac, master_keys_1.hmac);

        // Master keys change after reset. This test may fail if the random generator produces the
        // same keys.
        let master_encryption_key = master_keys_1.encryption.to_vec();
        let master_hmac_key = master_keys_1.hmac.to_vec();
        persistent_store.reset(&mut rng);
        let master_keys_3 = persistent_store.master_keys();
        assert!(master_keys_3.encryption as &[u8] != &master_encryption_key[..]);
        assert!(master_keys_3.hmac as &[u8] != &master_hmac_key[..]);
    }

    #[test]
    fn test_pin_hash() {
        use crate::ctap::PIN_AUTH_LENGTH;
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // Pin hash is initially not set.
        assert!(persistent_store.pin_hash().is_none());

        // Setting the pin hash sets the pin hash.
        let random_data = rng.gen_uniform_u8x32();
        assert_eq!(random_data.len(), 2 * PIN_AUTH_LENGTH);
        let pin_hash_1 = array_ref!(random_data, 0, PIN_AUTH_LENGTH);
        let pin_hash_2 = array_ref!(random_data, PIN_AUTH_LENGTH, PIN_AUTH_LENGTH);
        persistent_store.set_pin_hash(&pin_hash_1);
        assert_eq!(persistent_store.pin_hash(), Some(pin_hash_1));
        assert_eq!(persistent_store.pin_hash(), Some(pin_hash_1));
        persistent_store.set_pin_hash(&pin_hash_2);
        assert_eq!(persistent_store.pin_hash(), Some(pin_hash_2));
        assert_eq!(persistent_store.pin_hash(), Some(pin_hash_2));

        // Resetting the storage resets the pin hash.
        persistent_store.reset(&mut rng);
        assert!(persistent_store.pin_hash().is_none());
    }

    #[test]
    fn test_pin_retries() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // The pin retries is initially at the maximum.
        assert_eq!(persistent_store.pin_retries(), MAX_PIN_RETRIES);

        // Decrementing the pin retries decrements the pin retries.
        for pin_retries in (0..MAX_PIN_RETRIES).rev() {
            persistent_store.decr_pin_retries();
            assert_eq!(persistent_store.pin_retries(), pin_retries);
        }

        // Decrementing the pin retries after zero does not modify the pin retries.
        persistent_store.decr_pin_retries();
        assert_eq!(persistent_store.pin_retries(), 0);

        // Resetting the pin retries resets the pin retries.
        persistent_store.reset_pin_retries();
        assert_eq!(persistent_store.pin_retries(), MAX_PIN_RETRIES);
    }
}
