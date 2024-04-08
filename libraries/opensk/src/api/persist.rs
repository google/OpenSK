// Copyright 2024 Google LLC
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

mod keys;

use crate::api::crypto::EC_FIELD_SIZE;
use crate::ctap::secret::Secret;
use crate::ctap::status_code::{Ctap2StatusCode, CtapResult};
use crate::ctap::PIN_AUTH_LENGTH;
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp;
use core::convert::TryFrom;
#[cfg(test)]
use enum_iterator::IntoEnumIterator;

pub type PersistIter<'a> = Box<dyn Iterator<Item = CtapResult<usize>> + 'a>;
pub type PersistCredentialIter<'a> = Box<dyn Iterator<Item = CtapResult<(usize, Vec<u8>)>> + 'a>;
pub type LargeBlobBuffer = Vec<u8>;

/// Stores data that persists across reboots.
///
/// This trait might get appended to with new versions of CTAP.
///
/// The default implementations using the key-value store have assumptions on the ranges for key
/// and value, if you decide to use them:
/// - Keys within 0 and 4095 are supported.
/// - Values of at most 1023 bytes are supported.
///
/// To implement this trait, you have 2 options:
/// - Implement all high level functions with default implementations,
///   calling `unimplemented!` in the key-value accessors.
///   When we update this trait in a new version, OpenSK will panic when calling any new functions.
///   If you need special implementation for new functions, you need to manually add them.
/// - Implement the key-value accessors, and special case as many default implemented high level
///   functions as desired.
///   When the trait gets extended, new features will silently work.
///   Credentials still need keys to be identified by.
pub trait Persist {
    /// Retrieves the value for a given key.
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>>;

    /// Inserts the value at the given key.
    fn insert(&mut self, key: usize, value: &[u8]) -> CtapResult<()>;

    /// Removes a key, if present.
    fn remove(&mut self, key: usize) -> CtapResult<()>;

    /// Iterator for all present keys.
    fn iter(&self) -> CtapResult<PersistIter<'_>>;

    /// Checks consistency on boot, and if necessary fixes problems or initializes.
    ///
    /// Calling this function after successful init should be a NO-OP.
    fn init(&mut self) -> CtapResult<()> {
        if self.find(keys::RESET_COMPLETION)?.is_some() {
            self.reset()?;
        }
        Ok(())
    }

    /// Returns the byte array representation of a stored credential.
    fn credential_bytes(&self, key: usize) -> CtapResult<Vec<u8>> {
        if !keys::CREDENTIALS.contains(&key) {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        self.find(key)?
            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }

    /// Writes a credential at the given key.
    fn write_credential_bytes(&mut self, key: usize, value: &[u8]) -> CtapResult<()> {
        if !keys::CREDENTIALS.contains(&key) {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        self.insert(key, value)
    }

    /// Removes a credential at the given key.
    fn remove_credential(&mut self, key: usize) -> CtapResult<()> {
        if !keys::CREDENTIALS.contains(&key) {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        self.remove(key)
    }

    /// Iterates all stored credentials.
    fn iter_credentials(&self) -> CtapResult<PersistCredentialIter<'_>> {
        Ok(Box::new(self.iter()?.filter_map(move |key| match key {
            Ok(k) => {
                if keys::CREDENTIALS.contains(&k) {
                    match self.find(k) {
                        Ok(Some(v)) => Some(Ok((k, v))),
                        Ok(None) => None,
                        Err(e) => Some(Err(e)),
                    }
                } else {
                    None
                }
            }
            Err(e) => Some(Err(e)),
        })))
    }

    /// Returns a key where a new credential can be inserted.
    fn free_credential_key(&self) -> CtapResult<usize> {
        for key in keys::CREDENTIALS {
            if self.find(key)?.is_none() {
                return Ok(key);
            }
        }
        Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL)
    }

    /// Returns the global signature counter.
    fn global_signature_counter(&self) -> CtapResult<u32> {
        const INITIAL_SIGNATURE_COUNTER: u32 = 1;
        match self.find(keys::GLOBAL_SIGNATURE_COUNTER)? {
            None => Ok(INITIAL_SIGNATURE_COUNTER),
            Some(value) if value.len() == 4 => Ok(u32::from_ne_bytes(*array_ref!(&value, 0, 4))),
            Some(_) => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Increments the global signature counter.
    fn incr_global_signature_counter(&mut self, increment: u32) -> CtapResult<()> {
        let old_value = self.global_signature_counter()?;
        // In hopes that servers handle the wrapping gracefully.
        let new_value = old_value.wrapping_add(increment);
        self.insert(keys::GLOBAL_SIGNATURE_COUNTER, &new_value.to_ne_bytes())
    }

    /// Returns the PIN hash if defined.
    fn pin_hash(&self) -> CtapResult<Option<[u8; PIN_AUTH_LENGTH]>> {
        let pin_properties = match self.find(keys::PIN_PROPERTIES)? {
            None => return Ok(None),
            Some(pin_properties) => pin_properties,
        };
        if pin_properties.len() != 1 + PIN_AUTH_LENGTH {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        Ok(Some(*array_ref![pin_properties, 1, PIN_AUTH_LENGTH]))
    }

    /// Returns the length of the currently set PIN if defined.
    #[cfg(feature = "config_command")]
    fn pin_code_point_length(&self) -> CtapResult<Option<u8>> {
        let pin_properties = match self.find(keys::PIN_PROPERTIES)? {
            None => return Ok(None),
            Some(pin_properties) => pin_properties,
        };
        if pin_properties.is_empty() {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        Ok(Some(pin_properties[0]))
    }

    /// Sets the PIN hash and length.
    ///
    /// If it was already defined, it is updated.
    fn set_pin(
        &mut self,
        pin_hash: &[u8; PIN_AUTH_LENGTH],
        pin_code_point_length: u8,
    ) -> CtapResult<()> {
        let mut pin_properties = [0; 1 + PIN_AUTH_LENGTH];
        pin_properties[0] = pin_code_point_length;
        pin_properties[1..].clone_from_slice(pin_hash);
        self.insert(keys::PIN_PROPERTIES, &pin_properties[..])?;
        // If power fails between these 2 transactions, PIN has to be set again.
        self.remove(keys::FORCE_PIN_CHANGE)
    }

    /// Returns the number of failed PIN attempts.
    fn pin_fails(&self) -> CtapResult<u8> {
        match self.find(keys::PIN_RETRIES)? {
            None => Ok(0),
            Some(value) if value.len() == 1 => Ok(value[0]),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Decrements the number of remaining PIN retries.
    fn incr_pin_fails(&mut self) -> CtapResult<()> {
        let old_value = self.pin_fails()?;
        let new_value = old_value.saturating_add(1);
        self.insert(keys::PIN_RETRIES, &[new_value])
    }

    /// Resets the number of remaining PIN retries.
    fn reset_pin_retries(&mut self) -> CtapResult<()> {
        self.remove(keys::PIN_RETRIES)
    }

    /// Returns the minimum PIN length, if stored.
    fn min_pin_length(&self) -> CtapResult<Option<u8>> {
        match self.find(keys::MIN_PIN_LENGTH)? {
            None => Ok(None),
            Some(value) if value.len() == 1 => Ok(Some(value[0])),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Sets the minimum PIN length.
    #[cfg(feature = "config_command")]
    fn set_min_pin_length(&mut self, min_pin_length: u8) -> CtapResult<()> {
        self.insert(keys::MIN_PIN_LENGTH, &[min_pin_length])
    }

    /// Returns the list of RP IDs that may read the minimum PIN length.
    ///
    /// Defaults to an empty vector if not found.
    fn min_pin_length_rp_ids_bytes(&self) -> CtapResult<Vec<u8>> {
        Ok(self
            .find(keys::MIN_PIN_LENGTH_RP_IDS)?
            .unwrap_or(Vec::new()))
    }

    /// Sets the list of RP IDs that may read the minimum PIN length.
    #[cfg(feature = "config_command")]
    fn set_min_pin_length_rp_ids(&mut self, min_pin_length_rp_ids_bytes: &[u8]) -> CtapResult<()> {
        self.insert(keys::MIN_PIN_LENGTH_RP_IDS, min_pin_length_rp_ids_bytes)
    }

    /// Prepares writing a new large blob.
    ///
    /// Returns a buffer that is returned to other API calls for potential usage.
    fn init_large_blob(&mut self, expected_length: usize) -> CtapResult<LargeBlobBuffer> {
        Ok(Vec::with_capacity(expected_length))
    }

    /// Writes a large blob chunk to the buffer.
    ///
    /// This can be the passed in buffer, or a custom solution.
    fn write_large_blob_chunk(
        &mut self,
        offset: usize,
        chunk: &[u8],
        buffer: &mut LargeBlobBuffer,
    ) -> CtapResult<()> {
        if buffer.len() != offset {
            // This should be caught on CTAP level.
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        buffer.extend_from_slice(chunk);
        Ok(())
    }

    /// Reads the byte vector stored as the serialized large blobs array.
    ///
    /// If too few bytes exist at that offset, return the maximum number
    /// available. This includes cases of offset being beyond the stored array.
    ///
    /// The buffer is passed in when writing is in process.
    fn get_large_blob<'a>(
        &self,
        mut offset: usize,
        byte_count: usize,
        buffer: Option<&'a LargeBlobBuffer>,
    ) -> CtapResult<Option<Cow<'a, [u8]>>> {
        if let Some(buffer) = buffer {
            let start = cmp::min(offset, buffer.len());
            let end = offset.saturating_add(byte_count);
            let end = cmp::min(end, buffer.len());
            return Ok(Some(Cow::from(&buffer[start..end])));
        }
        let mut result = Vec::with_capacity(byte_count);
        for key in keys::LARGE_BLOB_SHARDS {
            if offset >= VALUE_LENGTH {
                offset = offset.saturating_sub(VALUE_LENGTH);
                continue;
            }
            let end = offset.saturating_add(byte_count - result.len());
            let end = cmp::min(end, VALUE_LENGTH);
            let value = self.find(key)?.unwrap_or(Vec::new());
            if key == keys::LARGE_BLOB_SHARDS.start && value.is_empty() {
                return Ok(None);
            }
            let end = cmp::min(end, value.len());
            if end < offset {
                return Ok(Some(Cow::from(result)));
            }
            result.extend(&value[offset..end]);
            offset = offset.saturating_sub(VALUE_LENGTH);
        }
        Ok(Some(Cow::from(result)))
    }

    /// Sets a byte vector as the serialized large blobs array.
    fn commit_large_blob_array(&mut self, buffer: &LargeBlobBuffer) -> CtapResult<()> {
        debug_assert!(buffer.len() <= keys::LARGE_BLOB_SHARDS.len() * VALUE_LENGTH);
        let mut offset = 0;
        for key in keys::LARGE_BLOB_SHARDS {
            let cur_len = cmp::min(buffer.len().saturating_sub(offset), VALUE_LENGTH);
            let slice = &buffer[offset..][..cur_len];
            if slice.is_empty() {
                self.remove(key)?;
            } else {
                self.insert(key, slice)?;
            }
            offset += cur_len;
        }
        Ok(())
    }

    /// Resets persistent data, consistent with a CTAP reset.
    ///
    /// In particular, entries that are persistent across factory reset are not removed.
    fn reset(&mut self) -> CtapResult<()> {
        self.insert(keys::RESET_COMPLETION, &[])?;
        let mut removed_keys = Vec::new();
        for key in self.iter()? {
            let key = key?;
            if key >= keys::NUM_PERSISTENT_KEYS && key != keys::RESET_COMPLETION {
                removed_keys.push(key);
            }
        }
        for key in removed_keys {
            self.remove(key)?;
        }
        self.remove(keys::RESET_COMPLETION)
    }

    /// Returns whether the PIN needs to be changed before its next usage.
    fn has_force_pin_change(&self) -> CtapResult<bool> {
        match self.find(keys::FORCE_PIN_CHANGE)? {
            None => Ok(false),
            Some(value) if value.is_empty() => Ok(true),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Marks the PIN as outdated with respect to the new PIN policy.
    #[cfg(feature = "config_command")]
    fn force_pin_change(&mut self) -> CtapResult<()> {
        self.insert(keys::FORCE_PIN_CHANGE, &[])
    }

    /// Returns whether enterprise attestation is enabled.
    #[cfg(feature = "config_command")]
    fn enterprise_attestation(&self) -> CtapResult<bool> {
        match self.find(keys::ENTERPRISE_ATTESTATION)? {
            None => Ok(false),
            Some(value) if value.is_empty() => Ok(true),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Marks enterprise attestation as enabled.
    #[cfg(feature = "config_command")]
    fn enable_enterprise_attestation(&mut self) -> CtapResult<()> {
        if self.get_attestation(AttestationId::Enterprise)?.is_none() {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        self.insert(keys::ENTERPRISE_ATTESTATION, &[])
    }

    /// Returns whether alwaysUv is enabled.
    fn has_always_uv(&self) -> CtapResult<bool> {
        match self.find(keys::ALWAYS_UV)? {
            None => Ok(false),
            Some(value) if value.is_empty() => Ok(true),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    /// Enables alwaysUv, when disabled, and vice versa.
    #[cfg(feature = "config_command")]
    fn toggle_always_uv(&mut self) -> CtapResult<()> {
        if self.has_always_uv()? {
            Ok(self.remove(keys::ALWAYS_UV)?)
        } else {
            Ok(self.insert(keys::ALWAYS_UV, &[])?)
        }
    }

    fn get_attestation(&self, id: AttestationId) -> CtapResult<Option<Attestation>> {
        let stored_id_bytes = self.find(keys::ATTESTATION_ID)?;
        if let Some(bytes) = stored_id_bytes {
            if bytes.len() != 1 {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
            }
            if id != AttestationId::try_from(bytes[0])? {
                return Ok(None);
            }
        } else {
            // This is for backwards compatibility. No ID stored implies batch.
            if id != AttestationId::Batch {
                return Ok(None);
            }
        }
        let private_key = self.find(keys::ATTESTATION_PRIVATE_KEY)?;
        let certificate = self.find(keys::ATTESTATION_CERTIFICATE)?;
        let (private_key, certificate) = match (private_key, certificate) {
            (Some(x), Some(y)) => (x, y),
            (None, None) => return Ok(None),
            _ => return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        };
        if private_key.len() != EC_FIELD_SIZE {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        Ok(Some(Attestation {
            private_key: Secret::from_exposed_secret(*array_ref![private_key, 0, EC_FIELD_SIZE]),
            certificate,
        }))
    }

    fn set_attestation(
        &mut self,
        id: AttestationId,
        attestation: Option<&Attestation>,
    ) -> CtapResult<()> {
        // To overwrite, first call with None, then call again, to avoid mistakes.
        if self.find(keys::ATTESTATION_ID)?.is_some() {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        // We set attestation storage in 3 transactions. If that gets interrupted halfway,
        // Register and MakeCredential will error when being called. Needs to be redone then.
        // ID is set last to allow idempotent rewrites.
        match attestation {
            None => {
                self.remove(keys::ATTESTATION_PRIVATE_KEY)?;
                self.remove(keys::ATTESTATION_CERTIFICATE)?;
                self.remove(keys::ATTESTATION_ID)?;
            }
            Some(attestation) => {
                self.insert(keys::ATTESTATION_PRIVATE_KEY, &attestation.private_key[..])?;
                self.insert(keys::ATTESTATION_CERTIFICATE, &attestation.certificate[..])?;
                self.insert(keys::ATTESTATION_ID, &[id as u8])?;
            }
        }
        Ok(())
    }

    fn key_store_bytes(&self) -> CtapResult<Option<Secret<[u8]>>> {
        let bytes = self.find(keys::KEY_STORE)?;
        Ok(bytes.map(|b| {
            let mut secret = Secret::new(b.len());
            secret.copy_from_slice(&b);
            secret
        }))
    }

    fn write_key_store_bytes(&mut self, bytes: &[u8]) -> CtapResult<()> {
        self.insert(keys::KEY_STORE, bytes)
    }
}

const VALUE_LENGTH: usize = 1023;

/// Identifies an attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(IntoEnumIterator))]
pub enum AttestationId {
    Batch = 0x01,
    Enterprise = 0x02,
}

impl TryFrom<u8> for AttestationId {
    type Error = Ctap2StatusCode;

    fn try_from(byte: u8) -> CtapResult<Self> {
        match byte {
            0x01 => Ok(Self::Batch),
            0x02 => Ok(Self::Enterprise),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }
}

#[cfg_attr(feature = "std", derive(Debug, PartialEq, Eq))]
pub struct Attestation {
    /// ECDSA private key (big-endian).
    pub private_key: Secret<[u8; EC_FIELD_SIZE]>,
    pub certificate: Vec<u8>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::customization::Customization;
    use crate::api::rng::Rng;
    use crate::env::test::TestEnv;
    use crate::env::Env;

    #[test]
    fn test_max_large_blob_array_size() {
        let env = TestEnv::default();

        assert!(
            env.customization().max_large_blob_array_size()
                <= VALUE_LENGTH * keys::LARGE_BLOB_SHARDS.len()
        );
    }

    #[test]
    fn test_from_into_attestation_id() {
        for id in AttestationId::into_enum_iter() {
            assert_eq!(id, AttestationId::try_from(id as u8).unwrap());
        }
        assert_eq!(
            AttestationId::try_from(0x03),
            Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
        );
    }

    #[test]
    fn test_global_signature_counter() {
        let mut env = TestEnv::default();
        let persist = env.persist();

        let mut counter_value = 1;
        assert_eq!(persist.global_signature_counter().unwrap(), counter_value);
        for increment in 1..10 {
            assert!(persist.incr_global_signature_counter(increment).is_ok());
            counter_value += increment;
            assert_eq!(persist.global_signature_counter().unwrap(), counter_value);
        }
    }

    #[test]
    fn test_force_pin_change() {
        let mut env = TestEnv::default();
        let persist = env.persist();

        assert!(!persist.has_force_pin_change().unwrap());
        assert_eq!(persist.force_pin_change(), Ok(()));
        assert!(persist.has_force_pin_change().unwrap());
        assert_eq!(persist.set_pin(&[0x88; 16], 8), Ok(()));
        assert!(!persist.has_force_pin_change().unwrap());
    }

    #[test]
    fn test_pin_hash_and_length() {
        let mut env = TestEnv::default();
        let random_data = env.rng().gen_uniform_u8x32();
        let persist = env.persist();

        // Pin hash is initially not set.
        assert!(persist.pin_hash().unwrap().is_none());
        assert!(persist.pin_code_point_length().unwrap().is_none());

        // Setting the pin sets the pin hash.
        assert_eq!(random_data.len(), 2 * PIN_AUTH_LENGTH);
        let pin_hash_1 = *array_ref!(random_data, 0, PIN_AUTH_LENGTH);
        let pin_hash_2 = *array_ref!(random_data, PIN_AUTH_LENGTH, PIN_AUTH_LENGTH);
        let pin_length_1 = 4;
        let pin_length_2 = 63;
        assert_eq!(persist.set_pin(&pin_hash_1, pin_length_1), Ok(()));
        assert_eq!(persist.pin_hash().unwrap(), Some(pin_hash_1));
        assert_eq!(persist.pin_code_point_length().unwrap(), Some(pin_length_1));
        assert_eq!(persist.set_pin(&pin_hash_2, pin_length_2), Ok(()));
        assert_eq!(persist.pin_hash().unwrap(), Some(pin_hash_2));
        assert_eq!(persist.pin_code_point_length().unwrap(), Some(pin_length_2));

        // Resetting the storage resets the pin hash.
        assert_eq!(persist.reset(), Ok(()));
        assert!(persist.pin_hash().unwrap().is_none());
        assert!(persist.pin_code_point_length().unwrap().is_none());
    }
}
