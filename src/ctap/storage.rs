// Copyright 2019-2021 Google LLC
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

mod key;

use crate::ctap::data_formats::{
    extract_array, extract_text_string, CredentialProtectionPolicy, PublicKeyCredentialSource,
    PublicKeyCredentialUserEntity,
};
use crate::ctap::key_material;
use crate::ctap::pin_protocol_v1::PIN_AUTH_LENGTH;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::INITIAL_SIGNATURE_COUNTER;
use crate::embedded_flash::{new_storage, Storage};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use arrayref::array_ref;
use cbor::cbor_array_vec;
use core::cmp;
use core::convert::TryInto;
use crypto::rng256::Rng256;
use persistent_store::{fragment, StoreUpdate};

// Those constants may be modified before compilation to tune the behavior of the key.
//
// The number of pages should be at least 3 and at most what the flash can hold. There should be no
// reason to put a small number here, except that the latency of flash operations is linear in the
// number of pages. This may improve in the future. Currently, using 20 pages gives between 20ms and
// 240ms per operation. The rule of thumb is between 1ms and 12ms per additional page.
//
// Limiting the number of resident keys permits to ensure a minimum number of counter increments.
// Let:
// - P the number of pages (NUM_PAGES)
// - K the maximum number of resident keys (MAX_SUPPORTED_RESIDENT_KEYS)
// - S the maximum size of a resident key (about 500)
// - C the number of erase cycles (10000)
// - I the minimum number of counter increments
//
// We have: I = (P * 4084 - 5107 - K * S) / 8 * C
//
// With P=20 and K=150, we have I=2M which is enough for 500 increments per day for 10 years.
const NUM_PAGES: usize = 20;
const MAX_SUPPORTED_RESIDENT_KEYS: usize = 150;

const MAX_PIN_RETRIES: u8 = 8;
const DEFAULT_MIN_PIN_LENGTH: u8 = 4;
const DEFAULT_MIN_PIN_LENGTH_RP_IDS: Vec<String> = Vec::new();
// This constant is an attempt to limit storage requirements. If you don't set it to 0,
// the stored strings can still be unbounded, but that is true for all RP IDs.
pub const MAX_RP_IDS_LENGTH: usize = 8;
pub const MAX_LARGE_BLOB_ARRAY_SIZE: usize = 2048;

/// Wrapper for master keys.
pub struct MasterKeys {
    /// Master encryption key.
    pub encryption: [u8; 32],

    /// Master hmac key.
    pub hmac: [u8; 32],
}

/// Wrapper for PIN properties.
struct PinProperties {
    /// 16 byte prefix of SHA256 of the currently set PIN.
    hash: [u8; PIN_AUTH_LENGTH],

    /// Length of the current PIN in code points.
    code_point_length: u8,
}

/// CTAP persistent storage.
pub struct PersistentStore {
    store: persistent_store::Store<Storage>,
}

impl PersistentStore {
    /// Gives access to the persistent store.
    ///
    /// # Safety
    ///
    /// This should be at most one instance of persistent store per program lifetime.
    pub fn new(rng: &mut impl Rng256) -> PersistentStore {
        let storage = new_storage(NUM_PAGES);
        let mut store = PersistentStore {
            store: persistent_store::Store::new(storage).ok().unwrap(),
        };
        store.init(rng).unwrap();
        store
    }

    /// Initializes the store by creating missing objects.
    fn init(&mut self, rng: &mut impl Rng256) -> Result<(), Ctap2StatusCode> {
        // Generate and store the master keys if they are missing.
        if self.store.find_handle(key::MASTER_KEYS)?.is_none() {
            let master_encryption_key = rng.gen_uniform_u8x32();
            let master_hmac_key = rng.gen_uniform_u8x32();
            let mut master_keys = Vec::with_capacity(64);
            master_keys.extend_from_slice(&master_encryption_key);
            master_keys.extend_from_slice(&master_hmac_key);
            self.store.insert(key::MASTER_KEYS, &master_keys)?;
        }

        // Generate and store the CredRandom secrets if they are missing.
        if self.store.find_handle(key::CRED_RANDOM_SECRET)?.is_none() {
            let cred_random_with_uv = rng.gen_uniform_u8x32();
            let cred_random_without_uv = rng.gen_uniform_u8x32();
            let mut cred_random = Vec::with_capacity(64);
            cred_random.extend_from_slice(&cred_random_without_uv);
            cred_random.extend_from_slice(&cred_random_with_uv);
            self.store.insert(key::CRED_RANDOM_SECRET, &cred_random)?;
        }

        if self.store.find_handle(key::AAGUID)?.is_none() {
            self.set_aaguid(key_material::AAGUID)?;
        }
        Ok(())
    }

    /// Returns the credential at the given key.
    ///
    /// # Errors
    ///
    /// Returns `CTAP2_ERR_VENDOR_INTERNAL_ERROR` if the key does not hold a valid credential.
    pub fn get_credential(&self, key: usize) -> Result<PublicKeyCredentialSource, Ctap2StatusCode> {
        let min_key = key::CREDENTIALS.start;
        if key < min_key || key >= min_key + MAX_SUPPORTED_RESIDENT_KEYS {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        let credential_entry = self
            .store
            .find(key)?
            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
        deserialize_credential(&credential_entry)
            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }

    /// Finds the key and value for a given credential ID.
    ///
    /// # Errors
    ///
    /// Returns `CTAP2_ERR_NO_CREDENTIALS` if the credential is not found.
    fn find_credential_item(
        &self,
        credential_id: &[u8],
    ) -> Result<(usize, PublicKeyCredentialSource), Ctap2StatusCode> {
        let mut iter_result = Ok(());
        let iter = self.iter_credentials(&mut iter_result)?;
        let mut credentials: Vec<(usize, PublicKeyCredentialSource)> = iter
            .filter(|(_, credential)| credential.credential_id == credential_id)
            .collect();
        iter_result?;
        if credentials.len() > 1 {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        credentials
            .pop()
            .ok_or(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)
    }

    /// Returns the first matching credential.
    ///
    /// Returns `None` if no credentials are matched or if `check_cred_protect` is set and the first
    /// matched credential requires user verification.
    pub fn find_credential(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        check_cred_protect: bool,
    ) -> Result<Option<PublicKeyCredentialSource>, Ctap2StatusCode> {
        let credential = match self.find_credential_item(credential_id) {
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS) => return Ok(None),
            Err(e) => return Err(e),
            Ok((_key, credential)) => credential,
        };
        let is_protected = credential.cred_protect_policy
            == Some(CredentialProtectionPolicy::UserVerificationRequired);
        if credential.rp_id != rp_id || (check_cred_protect && is_protected) {
            return Ok(None);
        }
        Ok(Some(credential))
    }

    /// Stores or updates a credential.
    ///
    /// If a credential with the same RP id and user handle already exists, it is replaced.
    pub fn store_credential(
        &mut self,
        new_credential: PublicKeyCredentialSource,
    ) -> Result<(), Ctap2StatusCode> {
        // Holds the key of the existing credential if this is an update.
        let mut old_key = None;
        let min_key = key::CREDENTIALS.start;
        // Holds whether a key is used (indices are shifted by min_key).
        let mut keys = vec![false; MAX_SUPPORTED_RESIDENT_KEYS];
        let mut iter_result = Ok(());
        let iter = self.iter_credentials(&mut iter_result)?;
        for (key, credential) in iter {
            if key < min_key || key - min_key >= MAX_SUPPORTED_RESIDENT_KEYS || keys[key - min_key]
            {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
            }
            keys[key - min_key] = true;
            if credential.rp_id == new_credential.rp_id
                && credential.user_handle == new_credential.user_handle
            {
                if old_key.is_some() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
                }
                old_key = Some(key);
            }
        }
        iter_result?;
        if old_key.is_none() && keys.iter().filter(|&&x| x).count() >= MAX_SUPPORTED_RESIDENT_KEYS {
            return Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL);
        }
        let key = match old_key {
            // This is a new credential being added, we need to allocate a free key. We choose the
            // first available key.
            None => key::CREDENTIALS
                .take(MAX_SUPPORTED_RESIDENT_KEYS)
                .find(|key| !keys[key - min_key])
                .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?,
            // This is an existing credential being updated, we reuse its key.
            Some(x) => x,
        };
        let value = serialize_credential(new_credential)?;
        self.store.insert(key, &value)?;
        Ok(())
    }

    /// Deletes a credential.
    ///
    /// # Errors
    ///
    /// Returns `CTAP2_ERR_NO_CREDENTIALS` if the credential is not found.
    pub fn delete_credential(&mut self, credential_id: &[u8]) -> Result<(), Ctap2StatusCode> {
        let (key, _) = self.find_credential_item(credential_id)?;
        Ok(self.store.remove(key)?)
    }

    /// Updates a credential's user information.
    ///
    /// # Errors
    ///
    /// Returns `CTAP2_ERR_NO_CREDENTIALS` if the credential is not found.
    pub fn update_credential(
        &mut self,
        credential_id: &[u8],
        user: PublicKeyCredentialUserEntity,
    ) -> Result<(), Ctap2StatusCode> {
        let (key, mut credential) = self.find_credential_item(credential_id)?;
        credential.user_name = user.user_name;
        credential.user_display_name = user.user_display_name;
        credential.user_icon = user.user_icon;
        let value = serialize_credential(credential)?;
        Ok(self.store.insert(key, &value)?)
    }

    /// Returns the number of credentials.
    pub fn count_credentials(&self) -> Result<usize, Ctap2StatusCode> {
        let mut count = 0;
        for handle in self.store.iter()? {
            count += key::CREDENTIALS.contains(&handle?.get_key()) as usize;
        }
        Ok(count)
    }

    /// Returns the estimated number of credentials that can still be stored.
    pub fn remaining_credentials(&self) -> Result<usize, Ctap2StatusCode> {
        MAX_SUPPORTED_RESIDENT_KEYS
            .checked_sub(self.count_credentials()?)
            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }

    /// Iterates through the credentials.
    ///
    /// If an error is encountered during iteration, it is written to `result`.
    pub fn iter_credentials<'a>(
        &'a self,
        result: &'a mut Result<(), Ctap2StatusCode>,
    ) -> Result<IterCredentials<'a>, Ctap2StatusCode> {
        IterCredentials::new(&self.store, result)
    }

    /// Returns the next creation order.
    pub fn new_creation_order(&self) -> Result<u64, Ctap2StatusCode> {
        let mut iter_result = Ok(());
        let iter = self.iter_credentials(&mut iter_result)?;
        let max = iter.map(|(_, credential)| credential.creation_order).max();
        iter_result?;
        Ok(max.unwrap_or(0).wrapping_add(1))
    }

    /// Returns the global signature counter.
    pub fn global_signature_counter(&self) -> Result<u32, Ctap2StatusCode> {
        match self.store.find(key::GLOBAL_SIGNATURE_COUNTER)? {
            None => Ok(INITIAL_SIGNATURE_COUNTER),
            Some(value) if value.len() == 4 => Ok(u32::from_ne_bytes(*array_ref!(&value, 0, 4))),
            Some(_) => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Increments the global signature counter.
    pub fn incr_global_signature_counter(&mut self, increment: u32) -> Result<(), Ctap2StatusCode> {
        let old_value = self.global_signature_counter()?;
        // In hopes that servers handle the wrapping gracefully.
        let new_value = old_value.wrapping_add(increment);
        self.store
            .insert(key::GLOBAL_SIGNATURE_COUNTER, &new_value.to_ne_bytes())?;
        Ok(())
    }

    /// Returns the master keys.
    pub fn master_keys(&self) -> Result<MasterKeys, Ctap2StatusCode> {
        let master_keys = self
            .store
            .find(key::MASTER_KEYS)?
            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
        if master_keys.len() != 64 {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        Ok(MasterKeys {
            encryption: *array_ref![master_keys, 0, 32],
            hmac: *array_ref![master_keys, 32, 32],
        })
    }

    /// Returns the CredRandom secret.
    pub fn cred_random_secret(&self, has_uv: bool) -> Result<[u8; 32], Ctap2StatusCode> {
        let cred_random_secret = self
            .store
            .find(key::CRED_RANDOM_SECRET)?
            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
        if cred_random_secret.len() != 64 {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        let offset = if has_uv { 32 } else { 0 };
        Ok(*array_ref![cred_random_secret, offset, 32])
    }

    /// Reads the PIN properties and wraps them into PinProperties.
    fn pin_properties(&self) -> Result<Option<PinProperties>, Ctap2StatusCode> {
        let pin_properties = match self.store.find(key::PIN_PROPERTIES)? {
            None => return Ok(None),
            Some(pin_properties) => pin_properties,
        };
        const PROPERTIES_LENGTH: usize = PIN_AUTH_LENGTH + 1;
        match pin_properties.len() {
            PROPERTIES_LENGTH => Ok(Some(PinProperties {
                hash: *array_ref![pin_properties, 1, PIN_AUTH_LENGTH],
                code_point_length: pin_properties[0],
            })),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Returns the PIN hash if defined.
    pub fn pin_hash(&self) -> Result<Option<[u8; PIN_AUTH_LENGTH]>, Ctap2StatusCode> {
        Ok(self.pin_properties()?.map(|p| p.hash))
    }

    /// Returns the length of the currently set PIN if defined.
    pub fn pin_code_point_length(&self) -> Result<Option<u8>, Ctap2StatusCode> {
        Ok(self.pin_properties()?.map(|p| p.code_point_length))
    }

    /// Sets the PIN hash and length.
    ///
    /// If it was already defined, it is updated.
    pub fn set_pin(
        &mut self,
        pin_hash: &[u8; PIN_AUTH_LENGTH],
        pin_code_point_length: u8,
    ) -> Result<(), Ctap2StatusCode> {
        let mut pin_properties = [0; 1 + PIN_AUTH_LENGTH];
        pin_properties[0] = pin_code_point_length;
        pin_properties[1..].clone_from_slice(pin_hash);
        Ok(self.store.transaction(&[
            StoreUpdate::Insert {
                key: key::PIN_PROPERTIES,
                value: &pin_properties[..],
            },
            StoreUpdate::Remove {
                key: key::FORCE_PIN_CHANGE,
            },
        ])?)
    }

    /// Returns the number of remaining PIN retries.
    pub fn pin_retries(&self) -> Result<u8, Ctap2StatusCode> {
        match self.store.find(key::PIN_RETRIES)? {
            None => Ok(MAX_PIN_RETRIES),
            Some(value) if value.len() == 1 => Ok(value[0]),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Decrements the number of remaining PIN retries.
    pub fn decr_pin_retries(&mut self) -> Result<(), Ctap2StatusCode> {
        let old_value = self.pin_retries()?;
        let new_value = old_value.saturating_sub(1);
        if new_value != old_value {
            self.store.insert(key::PIN_RETRIES, &[new_value])?;
        }
        Ok(())
    }

    /// Resets the number of remaining PIN retries.
    pub fn reset_pin_retries(&mut self) -> Result<(), Ctap2StatusCode> {
        Ok(self.store.remove(key::PIN_RETRIES)?)
    }

    /// Returns the minimum PIN length.
    pub fn min_pin_length(&self) -> Result<u8, Ctap2StatusCode> {
        match self.store.find(key::MIN_PIN_LENGTH)? {
            None => Ok(DEFAULT_MIN_PIN_LENGTH),
            Some(value) if value.len() == 1 => Ok(value[0]),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Sets the minimum PIN length.
    pub fn set_min_pin_length(&mut self, min_pin_length: u8) -> Result<(), Ctap2StatusCode> {
        Ok(self.store.insert(key::MIN_PIN_LENGTH, &[min_pin_length])?)
    }

    /// Returns the list of RP IDs that are used to check if reading the minimum PIN length is
    /// allowed.
    pub fn min_pin_length_rp_ids(&self) -> Result<Vec<String>, Ctap2StatusCode> {
        let rp_ids = self
            .store
            .find(key::MIN_PIN_LENGTH_RP_IDS)?
            .map_or(Some(DEFAULT_MIN_PIN_LENGTH_RP_IDS), |value| {
                deserialize_min_pin_length_rp_ids(&value)
            });
        debug_assert!(rp_ids.is_some());
        Ok(rp_ids.unwrap_or_default())
    }

    /// Sets the list of RP IDs that are used to check if reading the minimum PIN length is allowed.
    pub fn set_min_pin_length_rp_ids(
        &mut self,
        min_pin_length_rp_ids: Vec<String>,
    ) -> Result<(), Ctap2StatusCode> {
        let mut min_pin_length_rp_ids = min_pin_length_rp_ids;
        for rp_id in DEFAULT_MIN_PIN_LENGTH_RP_IDS {
            if !min_pin_length_rp_ids.contains(&rp_id) {
                min_pin_length_rp_ids.push(rp_id);
            }
        }
        if min_pin_length_rp_ids.len() > MAX_RP_IDS_LENGTH {
            return Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL);
        }
        Ok(self.store.insert(
            key::MIN_PIN_LENGTH_RP_IDS,
            &serialize_min_pin_length_rp_ids(min_pin_length_rp_ids)?,
        )?)
    }

    /// Reads the byte vector stored as the serialized large blobs array.
    ///
    /// If too few bytes exist at that offset, return the maximum number
    /// available. This includes cases of offset being beyond the stored array.
    ///
    /// If no large blob is committed to the store, get responds as if an empty
    /// CBOR array (0x80) was written, together with the 16 byte prefix of its
    /// SHA256, to a total length of 17 byte (which is the shortest legitimate
    /// large blob entry possible).
    pub fn get_large_blob_array(
        &self,
        offset: usize,
        byte_count: usize,
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let byte_range = offset..offset + byte_count;
        let output = fragment::read_range(&self.store, &key::LARGE_BLOB_SHARDS, byte_range)?;
        Ok(output.unwrap_or_else(|| {
            const EMPTY_LARGE_BLOB: [u8; 17] = [
                0x80, 0x76, 0xBE, 0x8B, 0x52, 0x8D, 0x00, 0x75, 0xF7, 0xAA, 0xE9, 0x8D, 0x6F, 0xA5,
                0x7A, 0x6D, 0x3C,
            ];
            let last_index = cmp::min(EMPTY_LARGE_BLOB.len(), offset + byte_count);
            EMPTY_LARGE_BLOB
                .get(offset..last_index)
                .unwrap_or_default()
                .to_vec()
        }))
    }

    /// Sets a byte vector as the serialized large blobs array.
    pub fn commit_large_blob_array(
        &mut self,
        large_blob_array: &[u8],
    ) -> Result<(), Ctap2StatusCode> {
        // This input should have been caught at caller level.
        if large_blob_array.len() > MAX_LARGE_BLOB_ARRAY_SIZE {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        Ok(fragment::write(
            &mut self.store,
            &key::LARGE_BLOB_SHARDS,
            large_blob_array,
        )?)
    }

    /// Returns the attestation private key if defined.
    pub fn attestation_private_key(
        &self,
    ) -> Result<Option<[u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH]>, Ctap2StatusCode> {
        match self.store.find(key::ATTESTATION_PRIVATE_KEY)? {
            None => Ok(None),
            Some(key) if key.len() == key_material::ATTESTATION_PRIVATE_KEY_LENGTH => {
                Ok(Some(*array_ref![
                    key,
                    0,
                    key_material::ATTESTATION_PRIVATE_KEY_LENGTH
                ]))
            }
            Some(_) => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Sets the attestation private key.
    ///
    /// If it is already defined, it is overwritten.
    pub fn set_attestation_private_key(
        &mut self,
        attestation_private_key: &[u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH],
    ) -> Result<(), Ctap2StatusCode> {
        match self.store.find(key::ATTESTATION_PRIVATE_KEY)? {
            None => Ok(self
                .store
                .insert(key::ATTESTATION_PRIVATE_KEY, attestation_private_key)?),
            Some(_) => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Returns the attestation certificate if defined.
    pub fn attestation_certificate(&self) -> Result<Option<Vec<u8>>, Ctap2StatusCode> {
        Ok(self.store.find(key::ATTESTATION_CERTIFICATE)?)
    }

    /// Sets the attestation certificate.
    ///
    /// If it is already defined, it is overwritten.
    pub fn set_attestation_certificate(
        &mut self,
        attestation_certificate: &[u8],
    ) -> Result<(), Ctap2StatusCode> {
        match self.store.find(key::ATTESTATION_CERTIFICATE)? {
            None => Ok(self
                .store
                .insert(key::ATTESTATION_CERTIFICATE, attestation_certificate)?),
            Some(_) => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Returns the AAGUID.
    pub fn aaguid(&self) -> Result<[u8; key_material::AAGUID_LENGTH], Ctap2StatusCode> {
        let aaguid = self
            .store
            .find(key::AAGUID)?
            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
        if aaguid.len() != key_material::AAGUID_LENGTH {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        Ok(*array_ref![aaguid, 0, key_material::AAGUID_LENGTH])
    }

    /// Sets the AAGUID.
    ///
    /// If it is already defined, it is overwritten.
    pub fn set_aaguid(
        &mut self,
        aaguid: &[u8; key_material::AAGUID_LENGTH],
    ) -> Result<(), Ctap2StatusCode> {
        Ok(self.store.insert(key::AAGUID, aaguid)?)
    }

    /// Resets the store as for a CTAP reset.
    ///
    /// In particular persistent entries are not reset.
    pub fn reset(&mut self, rng: &mut impl Rng256) -> Result<(), Ctap2StatusCode> {
        self.store.clear(key::NUM_PERSISTENT_KEYS)?;
        self.init(rng)?;
        Ok(())
    }

    /// Returns whether the PIN needs to be changed before its next usage.
    pub fn has_force_pin_change(&self) -> Result<bool, Ctap2StatusCode> {
        match self.store.find(key::FORCE_PIN_CHANGE)? {
            None => Ok(false),
            Some(value) if value.is_empty() => Ok(true),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Marks the PIN as outdated with respect to the new PIN policy.
    pub fn force_pin_change(&mut self) -> Result<(), Ctap2StatusCode> {
        Ok(self.store.insert(key::FORCE_PIN_CHANGE, &[])?)
    }

    /// Returns whether alwaysUv is enabled.
    pub fn has_always_uv(&self) -> Result<bool, Ctap2StatusCode> {
        match self.store.find(key::ALWAYS_UV)? {
            None => Ok(false),
            Some(value) if value.is_empty() => Ok(true),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Enables alwaysUv, when disabled, and vice versa.
    pub fn toggle_always_uv(&mut self) -> Result<(), Ctap2StatusCode> {
        if self.has_always_uv()? {
            Ok(self.store.remove(key::ALWAYS_UV)?)
        } else {
            Ok(self.store.insert(key::ALWAYS_UV, &[])?)
        }
    }
}

impl From<persistent_store::StoreError> for Ctap2StatusCode {
    fn from(error: persistent_store::StoreError) -> Ctap2StatusCode {
        use persistent_store::StoreError;
        match error {
            // This error is expected. The store is full.
            StoreError::NoCapacity => Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL,
            // This error is expected. The flash is out of life.
            StoreError::NoLifetime => Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL,
            // This error is expected if we don't satisfy the store preconditions. For example we
            // try to store a credential which is too long.
            StoreError::InvalidArgument => Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR,
            // This error is not expected. The storage has been tempered with. We could erase the
            // storage.
            StoreError::InvalidStorage => Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE,
            // This error is not expected. The kernel is failing our syscalls.
            StoreError::StorageError => Ctap2StatusCode::CTAP1_ERR_OTHER,
        }
    }
}

/// Iterator for credentials.
pub struct IterCredentials<'a> {
    /// The store being iterated.
    store: &'a persistent_store::Store<Storage>,

    /// The store iterator.
    iter: persistent_store::StoreIter<'a>,

    /// The iteration result.
    ///
    /// It starts as success and gets written at most once with an error if something fails. The
    /// iteration stops as soon as an error is encountered.
    result: &'a mut Result<(), Ctap2StatusCode>,
}

impl<'a> IterCredentials<'a> {
    /// Creates a credential iterator.
    fn new(
        store: &'a persistent_store::Store<Storage>,
        result: &'a mut Result<(), Ctap2StatusCode>,
    ) -> Result<IterCredentials<'a>, Ctap2StatusCode> {
        let iter = store.iter()?;
        Ok(IterCredentials {
            store,
            iter,
            result,
        })
    }

    /// Marks the iteration as failed if the content is absent.
    ///
    /// For convenience, the function takes and returns ownership instead of taking a shared
    /// reference and returning nothing. This permits to use it in both expressions and statements
    /// instead of statements only.
    fn unwrap<T>(&mut self, x: Option<T>) -> Option<T> {
        if x.is_none() {
            *self.result = Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        x
    }
}

impl<'a> Iterator for IterCredentials<'a> {
    type Item = (usize, PublicKeyCredentialSource);

    fn next(&mut self) -> Option<(usize, PublicKeyCredentialSource)> {
        if self.result.is_err() {
            return None;
        }
        while let Some(next) = self.iter.next() {
            let handle = self.unwrap(next.ok())?;
            let key = handle.get_key();
            if !key::CREDENTIALS.contains(&key) {
                continue;
            }
            let value = self.unwrap(handle.get_value(&self.store).ok())?;
            let credential = self.unwrap(deserialize_credential(&value))?;
            return Some((key, credential));
        }
        None
    }
}

/// Deserializes a credential from storage representation.
fn deserialize_credential(data: &[u8]) -> Option<PublicKeyCredentialSource> {
    let cbor = cbor::read(data).ok()?;
    cbor.try_into().ok()
}

/// Serializes a credential to storage representation.
fn serialize_credential(credential: PublicKeyCredentialSource) -> Result<Vec<u8>, Ctap2StatusCode> {
    let mut data = Vec::new();
    if cbor::write(credential.into(), &mut data) {
        Ok(data)
    } else {
        Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }
}

/// Deserializes a list of RP IDs from storage representation.
fn deserialize_min_pin_length_rp_ids(data: &[u8]) -> Option<Vec<String>> {
    let cbor = cbor::read(data).ok()?;
    extract_array(cbor)
        .ok()?
        .into_iter()
        .map(extract_text_string)
        .collect::<Result<Vec<String>, Ctap2StatusCode>>()
        .ok()
}

/// Serializes a list of RP IDs to storage representation.
fn serialize_min_pin_length_rp_ids(rp_ids: Vec<String>) -> Result<Vec<u8>, Ctap2StatusCode> {
    let mut data = Vec::new();
    if cbor::write(cbor_array_vec!(rp_ids), &mut data) {
        Ok(data)
    } else {
        Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
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
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        }
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
    fn test_delete_credential() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials().unwrap(), 0);

        let mut credential_ids = vec![];
        for i in 0..MAX_SUPPORTED_RESIDENT_KEYS {
            let user_handle = i.to_ne_bytes().to_vec();
            let credential_source = create_credential_source(&mut rng, "example.com", user_handle);
            credential_ids.push(credential_source.credential_id.clone());
            assert!(persistent_store.store_credential(credential_source).is_ok());
            assert_eq!(persistent_store.count_credentials().unwrap(), i + 1);
        }
        let mut count = persistent_store.count_credentials().unwrap();
        for credential_id in credential_ids {
            assert!(persistent_store.delete_credential(&credential_id).is_ok());
            count -= 1;
            assert_eq!(persistent_store.count_credentials().unwrap(), count);
        }
    }

    #[test]
    fn test_update_credential() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let user = PublicKeyCredentialUserEntity {
            // User ID is ignored.
            user_id: vec![0x00],
            user_name: Some("name".to_string()),
            user_display_name: Some("display_name".to_string()),
            user_icon: Some("icon".to_string()),
        };
        assert_eq!(
            persistent_store.update_credential(&[0x1D], user.clone()),
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)
        );

        let credential_source = create_credential_source(&mut rng, "example.com", vec![0x1D]);
        let credential_id = credential_source.credential_id.clone();
        assert!(persistent_store.store_credential(credential_source).is_ok());
        let stored_credential = persistent_store
            .find_credential("example.com", &credential_id, false)
            .unwrap()
            .unwrap();
        assert_eq!(stored_credential.user_name, None);
        assert_eq!(stored_credential.user_display_name, None);
        assert_eq!(stored_credential.user_icon, None);
        assert!(persistent_store
            .update_credential(&credential_id, user.clone())
            .is_ok());
        let stored_credential = persistent_store
            .find_credential("example.com", &credential_id, false)
            .unwrap()
            .unwrap();
        assert_eq!(stored_credential.user_name, user.user_name);
        assert_eq!(stored_credential.user_display_name, user.user_display_name);
        assert_eq!(stored_credential.user_icon, user.user_icon);
    }

    #[test]
    fn test_credential_order() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let credential_source = create_credential_source(&mut rng, "example.com", vec![]);
        let current_latest_creation = credential_source.creation_order;
        assert!(persistent_store.store_credential(credential_source).is_ok());
        let mut credential_source = create_credential_source(&mut rng, "example.com", vec![]);
        credential_source.creation_order = persistent_store.new_creation_order().unwrap();
        assert!(credential_source.creation_order > current_latest_creation);
        let current_latest_creation = credential_source.creation_order;
        assert!(persistent_store.store_credential(credential_source).is_ok());
        assert!(persistent_store.new_creation_order().unwrap() > current_latest_creation);
    }

    #[test]
    fn test_fill_store() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials().unwrap(), 0);

        for i in 0..MAX_SUPPORTED_RESIDENT_KEYS {
            let user_handle = i.to_ne_bytes().to_vec();
            let credential_source = create_credential_source(&mut rng, "example.com", user_handle);
            assert!(persistent_store.store_credential(credential_source).is_ok());
            assert_eq!(persistent_store.count_credentials().unwrap(), i + 1);
        }
        let credential_source = create_credential_source(
            &mut rng,
            "example.com",
            vec![MAX_SUPPORTED_RESIDENT_KEYS as u8],
        );
        assert_eq!(
            persistent_store.store_credential(credential_source),
            Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL)
        );
        assert_eq!(
            persistent_store.count_credentials().unwrap(),
            MAX_SUPPORTED_RESIDENT_KEYS
        );
    }

    #[test]
    fn test_overwrite() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        assert_eq!(persistent_store.count_credentials().unwrap(), 0);
        // These should have different IDs.
        let credential_source0 = create_credential_source(&mut rng, "example.com", vec![0x00]);
        let credential_source1 = create_credential_source(&mut rng, "example.com", vec![0x00]);
        let credential_id0 = credential_source0.credential_id.clone();
        let credential_id1 = credential_source1.credential_id.clone();

        assert!(persistent_store
            .store_credential(credential_source0)
            .is_ok());
        assert!(persistent_store
            .store_credential(credential_source1)
            .is_ok());
        assert_eq!(persistent_store.count_credentials().unwrap(), 1);
        assert!(persistent_store
            .find_credential("example.com", &credential_id0, false)
            .unwrap()
            .is_none());
        assert!(persistent_store
            .find_credential("example.com", &credential_id1, false)
            .unwrap()
            .is_some());

        let mut persistent_store = PersistentStore::new(&mut rng);
        for i in 0..MAX_SUPPORTED_RESIDENT_KEYS {
            let user_handle = i.to_ne_bytes().to_vec();
            let credential_source = create_credential_source(&mut rng, "example.com", user_handle);
            assert!(persistent_store.store_credential(credential_source).is_ok());
            assert_eq!(persistent_store.count_credentials().unwrap(), i + 1);
        }
        let credential_source = create_credential_source(
            &mut rng,
            "example.com",
            vec![MAX_SUPPORTED_RESIDENT_KEYS as u8],
        );
        assert_eq!(
            persistent_store.store_credential(credential_source),
            Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL)
        );
        assert_eq!(
            persistent_store.count_credentials().unwrap(),
            MAX_SUPPORTED_RESIDENT_KEYS
        );
    }

    #[test]
    fn test_get_credential() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let credential_source0 = create_credential_source(&mut rng, "example.com", vec![0x00]);
        let credential_source1 = create_credential_source(&mut rng, "example.com", vec![0x01]);
        let credential_source2 =
            create_credential_source(&mut rng, "another.example.com", vec![0x02]);
        let credential_sources = vec![credential_source0, credential_source1, credential_source2];
        for credential_source in credential_sources.into_iter() {
            let cred_id = credential_source.credential_id.clone();
            assert!(persistent_store.store_credential(credential_source).is_ok());
            let (key, _) = persistent_store.find_credential_item(&cred_id).unwrap();
            let cred = persistent_store.get_credential(key).unwrap();
            assert_eq!(&cred_id, &cred.credential_id);
        }
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
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
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
            user_display_name: None,
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationRequired),
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
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

        // Master keys stay the same within the same CTAP reset cycle.
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
    fn test_cred_random_secret() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // CredRandom secrets stay the same within the same CTAP reset cycle.
        let cred_random_with_uv_1 = persistent_store.cred_random_secret(true).unwrap();
        let cred_random_without_uv_1 = persistent_store.cred_random_secret(false).unwrap();
        let cred_random_with_uv_2 = persistent_store.cred_random_secret(true).unwrap();
        let cred_random_without_uv_2 = persistent_store.cred_random_secret(false).unwrap();
        assert_eq!(cred_random_with_uv_1, cred_random_with_uv_2);
        assert_eq!(cred_random_without_uv_1, cred_random_without_uv_2);

        // CredRandom secrets change after reset. This test may fail if the random generator produces the
        // same keys.
        persistent_store.reset(&mut rng).unwrap();
        let cred_random_with_uv_3 = persistent_store.cred_random_secret(true).unwrap();
        let cred_random_without_uv_3 = persistent_store.cred_random_secret(false).unwrap();
        assert!(cred_random_with_uv_1 != cred_random_with_uv_3);
        assert!(cred_random_without_uv_1 != cred_random_without_uv_3);
    }

    #[test]
    fn test_pin_hash_and_length() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // Pin hash is initially not set.
        assert!(persistent_store.pin_hash().unwrap().is_none());
        assert!(persistent_store.pin_code_point_length().unwrap().is_none());

        // Setting the pin sets the pin hash.
        let random_data = rng.gen_uniform_u8x32();
        assert_eq!(random_data.len(), 2 * PIN_AUTH_LENGTH);
        let pin_hash_1 = *array_ref!(random_data, 0, PIN_AUTH_LENGTH);
        let pin_hash_2 = *array_ref!(random_data, PIN_AUTH_LENGTH, PIN_AUTH_LENGTH);
        let pin_length_1 = 4;
        let pin_length_2 = 63;
        persistent_store.set_pin(&pin_hash_1, pin_length_1).unwrap();
        assert_eq!(persistent_store.pin_hash().unwrap(), Some(pin_hash_1));
        assert_eq!(
            persistent_store.pin_code_point_length().unwrap(),
            Some(pin_length_1)
        );
        persistent_store.set_pin(&pin_hash_2, pin_length_2).unwrap();
        assert_eq!(persistent_store.pin_hash().unwrap(), Some(pin_hash_2));
        assert_eq!(
            persistent_store.pin_code_point_length().unwrap(),
            Some(pin_length_2)
        );

        // Resetting the storage resets the pin hash.
        persistent_store.reset(&mut rng).unwrap();
        assert!(persistent_store.pin_hash().unwrap().is_none());
        assert!(persistent_store.pin_code_point_length().unwrap().is_none());
    }

    #[test]
    fn test_pin_retries() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // The pin retries is initially at the maximum.
        assert_eq!(persistent_store.pin_retries(), Ok(MAX_PIN_RETRIES));

        // Decrementing the pin retries decrements the pin retries.
        for pin_retries in (0..MAX_PIN_RETRIES).rev() {
            persistent_store.decr_pin_retries().unwrap();
            assert_eq!(persistent_store.pin_retries(), Ok(pin_retries));
        }

        // Decrementing the pin retries after zero does not modify the pin retries.
        persistent_store.decr_pin_retries().unwrap();
        assert_eq!(persistent_store.pin_retries(), Ok(0));

        // Resetting the pin retries resets the pin retries.
        persistent_store.reset_pin_retries().unwrap();
        assert_eq!(persistent_store.pin_retries(), Ok(MAX_PIN_RETRIES));
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

        // Make sure the persistent keys are initialized to dummy values.
        let dummy_key = [0x41u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH];
        let dummy_cert = [0xddu8; 20];
        persistent_store
            .set_attestation_private_key(&dummy_key)
            .unwrap();
        persistent_store
            .set_attestation_certificate(&dummy_cert)
            .unwrap();
        assert_eq!(&persistent_store.aaguid().unwrap(), key_material::AAGUID);

        // The persistent keys stay initialized and preserve their value after a reset.
        persistent_store.reset(&mut rng).unwrap();
        assert_eq!(
            &persistent_store.attestation_private_key().unwrap().unwrap(),
            &dummy_key
        );
        assert_eq!(
            persistent_store.attestation_certificate().unwrap().unwrap(),
            &dummy_cert
        );
        assert_eq!(&persistent_store.aaguid().unwrap(), key_material::AAGUID);
    }

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

    #[test]
    fn test_min_pin_length_rp_ids() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        // The minimum PIN length RP IDs are initially at the default.
        assert_eq!(
            persistent_store.min_pin_length_rp_ids().unwrap(),
            DEFAULT_MIN_PIN_LENGTH_RP_IDS
        );

        // Changes by the setter are reflected by the getter.
        let mut rp_ids = vec![String::from("example.com")];
        assert_eq!(
            persistent_store.set_min_pin_length_rp_ids(rp_ids.clone()),
            Ok(())
        );
        for rp_id in DEFAULT_MIN_PIN_LENGTH_RP_IDS {
            if !rp_ids.contains(&rp_id) {
                rp_ids.push(rp_id);
            }
        }
        assert_eq!(persistent_store.min_pin_length_rp_ids().unwrap(), rp_ids);
    }

    #[test]
    fn test_max_large_blob_array_size() {
        let mut rng = ThreadRng256 {};
        let persistent_store = PersistentStore::new(&mut rng);

        #[allow(clippy::assertions_on_constants)]
        {
            assert!(MAX_LARGE_BLOB_ARRAY_SIZE >= 1024);
        }
        assert!(
            MAX_LARGE_BLOB_ARRAY_SIZE
                <= persistent_store.store.max_value_length()
                    * (key::LARGE_BLOB_SHARDS.end - key::LARGE_BLOB_SHARDS.start)
        );
    }

    #[test]
    fn test_commit_get_large_blob_array() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        let large_blob_array = vec![0x01, 0x02, 0x03];
        assert!(persistent_store
            .commit_large_blob_array(&large_blob_array)
            .is_ok());
        let restored_large_blob_array = persistent_store.get_large_blob_array(0, 1).unwrap();
        assert_eq!(vec![0x01], restored_large_blob_array);
        let restored_large_blob_array = persistent_store.get_large_blob_array(1, 1).unwrap();
        assert_eq!(vec![0x02], restored_large_blob_array);
        let restored_large_blob_array = persistent_store.get_large_blob_array(2, 1).unwrap();
        assert_eq!(vec![0x03], restored_large_blob_array);
        let restored_large_blob_array = persistent_store.get_large_blob_array(2, 2).unwrap();
        assert_eq!(vec![0x03], restored_large_blob_array);
        let restored_large_blob_array = persistent_store.get_large_blob_array(3, 1).unwrap();
        assert_eq!(Vec::<u8>::new(), restored_large_blob_array);
        let restored_large_blob_array = persistent_store.get_large_blob_array(4, 1).unwrap();
        assert_eq!(Vec::<u8>::new(), restored_large_blob_array);
    }

    #[test]
    fn test_commit_get_large_blob_array_overwrite() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        let large_blob_array = vec![0x11; 5];
        assert!(persistent_store
            .commit_large_blob_array(&large_blob_array)
            .is_ok());
        let large_blob_array = vec![0x22; 4];
        assert!(persistent_store
            .commit_large_blob_array(&large_blob_array)
            .is_ok());
        let restored_large_blob_array = persistent_store.get_large_blob_array(0, 5).unwrap();
        assert_eq!(large_blob_array, restored_large_blob_array);
        let restored_large_blob_array = persistent_store.get_large_blob_array(4, 1).unwrap();
        assert_eq!(Vec::<u8>::new(), restored_large_blob_array);

        assert!(persistent_store.commit_large_blob_array(&[]).is_ok());
        let restored_large_blob_array = persistent_store.get_large_blob_array(0, 20).unwrap();
        // Committing an empty array resets to the default blob of 17 byte.
        assert_eq!(restored_large_blob_array.len(), 17);
    }

    #[test]
    fn test_commit_get_large_blob_array_no_commit() {
        let mut rng = ThreadRng256 {};
        let persistent_store = PersistentStore::new(&mut rng);

        let empty_blob_array = vec![
            0x80, 0x76, 0xBE, 0x8B, 0x52, 0x8D, 0x00, 0x75, 0xF7, 0xAA, 0xE9, 0x8D, 0x6F, 0xA5,
            0x7A, 0x6D, 0x3C,
        ];
        let restored_large_blob_array = persistent_store.get_large_blob_array(0, 17).unwrap();
        assert_eq!(empty_blob_array, restored_large_blob_array);
        let restored_large_blob_array = persistent_store.get_large_blob_array(0, 1).unwrap();
        assert_eq!(vec![0x80], restored_large_blob_array);
        let restored_large_blob_array = persistent_store.get_large_blob_array(16, 1).unwrap();
        assert_eq!(vec![0x3C], restored_large_blob_array);
    }

    #[test]
    fn test_global_signature_counter() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        let mut counter_value = 1;
        assert_eq!(
            persistent_store.global_signature_counter().unwrap(),
            counter_value
        );
        for increment in 1..10 {
            assert!(persistent_store
                .incr_global_signature_counter(increment)
                .is_ok());
            counter_value += increment;
            assert_eq!(
                persistent_store.global_signature_counter().unwrap(),
                counter_value
            );
        }
    }

    #[test]
    fn test_force_pin_change() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        assert!(!persistent_store.has_force_pin_change().unwrap());
        assert_eq!(persistent_store.force_pin_change(), Ok(()));
        assert!(persistent_store.has_force_pin_change().unwrap());
        assert_eq!(persistent_store.set_pin(&[0x88; 16], 8), Ok(()));
        assert!(!persistent_store.has_force_pin_change().unwrap());
    }

    #[test]
    fn test_always_uv() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);

        assert!(!persistent_store.has_always_uv().unwrap());
        assert_eq!(persistent_store.toggle_always_uv(), Ok(()));
        assert!(persistent_store.has_always_uv().unwrap());
        assert_eq!(persistent_store.toggle_always_uv(), Ok(()));
        assert!(!persistent_store.has_always_uv().unwrap());
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
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        };
        let serialized = serialize_credential(credential.clone()).unwrap();
        let reconstructed = deserialize_credential(&serialized).unwrap();
        assert_eq!(credential, reconstructed);
    }

    #[test]
    fn test_serialize_deserialize_min_pin_length_rp_ids() {
        let rp_ids = vec![String::from("example.com")];
        let serialized = serialize_min_pin_length_rp_ids(rp_ids.clone()).unwrap();
        let reconstructed = deserialize_min_pin_length_rp_ids(&serialized).unwrap();
        assert_eq!(rp_ids, reconstructed);
    }
}
