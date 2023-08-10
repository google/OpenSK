// Copyright 2019-2023 Google LLC
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

#[cfg(feature = "config_command")]
use crate::api::attestation_store::{self, AttestationStore};
use crate::api::customization::Customization;
use crate::api::key_store::KeyStore;
use crate::ctap::client_pin::PIN_AUTH_LENGTH;
use crate::ctap::data_formats::{
    extract_array, extract_text_string, PublicKeyCredentialSource, PublicKeyCredentialUserEntity,
};
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::INITIAL_SIGNATURE_COUNTER;
use crate::env::{AesKey, Env};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use arrayref::array_ref;
use core::cmp;
use persistent_store::{fragment, StoreUpdate};
#[cfg(feature = "config_command")]
use sk_cbor::cbor_array_vec;

/// Wrapper for PIN properties.
struct PinProperties {
    /// 16 byte prefix of SHA256 of the currently set PIN.
    hash: [u8; PIN_AUTH_LENGTH],

    /// Length of the current PIN in code points.
    #[cfg_attr(not(feature = "config_command"), allow(dead_code))]
    code_point_length: u8,
}

/// Initializes the store by creating missing objects.
pub fn init(env: &mut impl Env) -> Result<(), Ctap2StatusCode> {
    env.key_store().init()?;
    Ok(())
}

/// Returns the credential at the given key.
///
/// # Errors
///
/// Returns `CTAP2_ERR_VENDOR_INTERNAL_ERROR` if the key does not hold a valid credential.
pub fn get_credential<E: Env>(
    env: &mut E,
    key: usize,
) -> Result<PublicKeyCredentialSource, Ctap2StatusCode> {
    let min_key = key::CREDENTIALS.start;
    if key < min_key || key >= min_key + env.customization().max_supported_resident_keys() {
        return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
    }
    let credential_entry = env
        .store()
        .find(key)?
        .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
    let wrap_key = env.key_store().wrap_key::<E>()?;
    deserialize_credential::<E>(&wrap_key, &credential_entry)
        .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
}

/// Finds the key and value for a given credential ID.
///
/// # Errors
///
/// Returns `CTAP2_ERR_NO_CREDENTIALS` if the credential is not found.
pub fn find_credential_item(
    env: &mut impl Env,
    credential_id: &[u8],
) -> Result<(usize, PublicKeyCredentialSource), Ctap2StatusCode> {
    let mut iter_result = Ok(());
    let iter = iter_credentials(env, &mut iter_result)?;
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
    env: &mut impl Env,
    rp_id: &str,
    credential_id: &[u8],
) -> Result<Option<PublicKeyCredentialSource>, Ctap2StatusCode> {
    let credential = match find_credential_item(env, credential_id) {
        Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS) => return Ok(None),
        Err(e) => return Err(e),
        Ok((_key, credential)) => credential,
    };
    if credential.rp_id != rp_id {
        return Ok(None);
    }
    Ok(Some(credential))
}

/// Stores or updates a credential.
///
/// If a credential with the same RP id and user handle already exists, it is replaced.
pub fn store_credential<E: Env>(
    env: &mut E,
    new_credential: PublicKeyCredentialSource,
) -> Result<(), Ctap2StatusCode> {
    let max_supported_resident_keys = env.customization().max_supported_resident_keys();
    // Holds the key of the existing credential if this is an update.
    let mut old_key = None;
    let min_key = key::CREDENTIALS.start;
    // Holds whether a key is used (indices are shifted by min_key).
    let mut keys = vec![false; max_supported_resident_keys];
    let mut iter_result = Ok(());
    let iter = iter_credentials(env, &mut iter_result)?;
    for (key, credential) in iter {
        if key < min_key || key - min_key >= max_supported_resident_keys || keys[key - min_key] {
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
    if old_key.is_none() && keys.iter().filter(|&&x| x).count() >= max_supported_resident_keys {
        return Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL);
    }
    let key = match old_key {
        // This is a new credential being added, we need to allocate a free key. We choose the
        // first available key.
        None => key::CREDENTIALS
            .take(max_supported_resident_keys)
            .find(|key| !keys[key - min_key])
            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?,
        // This is an existing credential being updated, we reuse its key.
        Some(x) => x,
    };
    let wrap_key = env.key_store().wrap_key::<E>()?;
    let value = serialize_credential::<E>(env, &wrap_key, new_credential)?;
    env.store().insert(key, &value)?;
    Ok(())
}

/// Deletes a credential.
///
/// # Errors
///
/// Returns `CTAP2_ERR_NO_CREDENTIALS` if the credential is not found.
pub fn delete_credential(env: &mut impl Env, credential_id: &[u8]) -> Result<(), Ctap2StatusCode> {
    let (key, _) = find_credential_item(env, credential_id)?;
    Ok(env.store().remove(key)?)
}

/// Updates a credential's user information.
///
/// # Errors
///
/// Returns `CTAP2_ERR_NO_CREDENTIALS` if the credential is not found.
pub fn update_credential<E: Env>(
    env: &mut E,
    credential_id: &[u8],
    user: PublicKeyCredentialUserEntity,
) -> Result<(), Ctap2StatusCode> {
    let (key, mut credential) = find_credential_item(env, credential_id)?;
    credential.user_name = user.user_name;
    credential.user_display_name = user.user_display_name;
    credential.user_icon = user.user_icon;
    let wrap_key = env.key_store().wrap_key::<E>()?;
    let value = serialize_credential::<E>(env, &wrap_key, credential)?;
    Ok(env.store().insert(key, &value)?)
}

/// Returns the number of credentials.
pub fn count_credentials(env: &mut impl Env) -> Result<usize, Ctap2StatusCode> {
    let mut count = 0;
    for handle in env.store().iter()? {
        count += key::CREDENTIALS.contains(&handle?.get_key()) as usize;
    }
    Ok(count)
}

/// Returns the estimated number of credentials that can still be stored.
pub fn remaining_credentials(env: &mut impl Env) -> Result<usize, Ctap2StatusCode> {
    env.customization()
        .max_supported_resident_keys()
        .checked_sub(count_credentials(env)?)
        .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
}

/// Iterates through the credentials.
///
/// If an error is encountered during iteration, it is written to `result`.
pub fn iter_credentials<'a, E: Env>(
    env: &'a mut E,
    result: &'a mut Result<(), Ctap2StatusCode>,
) -> Result<IterCredentials<'a, E>, Ctap2StatusCode> {
    IterCredentials::new(env, result)
}

/// Returns the next creation order.
pub fn new_creation_order(env: &mut impl Env) -> Result<u64, Ctap2StatusCode> {
    let mut iter_result = Ok(());
    let iter = iter_credentials(env, &mut iter_result)?;
    let max = iter.map(|(_, credential)| credential.creation_order).max();
    iter_result?;
    Ok(max.unwrap_or(0).wrapping_add(1))
}

/// Returns the global signature counter.
pub fn global_signature_counter(env: &mut impl Env) -> Result<u32, Ctap2StatusCode> {
    match env.store().find(key::GLOBAL_SIGNATURE_COUNTER)? {
        None => Ok(INITIAL_SIGNATURE_COUNTER),
        Some(value) if value.len() == 4 => Ok(u32::from_ne_bytes(*array_ref!(&value, 0, 4))),
        Some(_) => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
    }
}

/// Increments the global signature counter.
pub fn incr_global_signature_counter(
    env: &mut impl Env,
    increment: u32,
) -> Result<(), Ctap2StatusCode> {
    let old_value = global_signature_counter(env)?;
    // In hopes that servers handle the wrapping gracefully.
    let new_value = old_value.wrapping_add(increment);
    env.store()
        .insert(key::GLOBAL_SIGNATURE_COUNTER, &new_value.to_ne_bytes())?;
    Ok(())
}

/// Reads the PIN properties and wraps them into PinProperties.
fn pin_properties(env: &mut impl Env) -> Result<Option<PinProperties>, Ctap2StatusCode> {
    let pin_properties = match env.store().find(key::PIN_PROPERTIES)? {
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
pub fn pin_hash(env: &mut impl Env) -> Result<Option<[u8; PIN_AUTH_LENGTH]>, Ctap2StatusCode> {
    Ok(pin_properties(env)?.map(|p| p.hash))
}

/// Returns the length of the currently set PIN if defined.
#[cfg(feature = "config_command")]
pub fn pin_code_point_length(env: &mut impl Env) -> Result<Option<u8>, Ctap2StatusCode> {
    Ok(pin_properties(env)?.map(|p| p.code_point_length))
}

/// Sets the PIN hash and length.
///
/// If it was already defined, it is updated.
pub fn set_pin(
    env: &mut impl Env,
    pin_hash: &[u8; PIN_AUTH_LENGTH],
    pin_code_point_length: u8,
) -> Result<(), Ctap2StatusCode> {
    let mut pin_properties = [0; 1 + PIN_AUTH_LENGTH];
    pin_properties[0] = pin_code_point_length;
    pin_properties[1..].clone_from_slice(pin_hash);
    Ok(env.store().transaction(&[
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
pub fn pin_retries(env: &mut impl Env) -> Result<u8, Ctap2StatusCode> {
    match env.store().find(key::PIN_RETRIES)? {
        None => Ok(env.customization().max_pin_retries()),
        Some(value) if value.len() == 1 => Ok(value[0]),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
    }
}

/// Decrements the number of remaining PIN retries.
pub fn decr_pin_retries(env: &mut impl Env) -> Result<(), Ctap2StatusCode> {
    let old_value = pin_retries(env)?;
    let new_value = old_value.saturating_sub(1);
    if new_value != old_value {
        env.store().insert(key::PIN_RETRIES, &[new_value])?;
    }
    Ok(())
}

/// Resets the number of remaining PIN retries.
pub fn reset_pin_retries(env: &mut impl Env) -> Result<(), Ctap2StatusCode> {
    Ok(env.store().remove(key::PIN_RETRIES)?)
}

/// Returns the minimum PIN length.
pub fn min_pin_length(env: &mut impl Env) -> Result<u8, Ctap2StatusCode> {
    match env.store().find(key::MIN_PIN_LENGTH)? {
        None => Ok(env.customization().default_min_pin_length()),
        Some(value) if value.len() == 1 => Ok(value[0]),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
    }
}

/// Sets the minimum PIN length.
#[cfg(feature = "config_command")]
pub fn set_min_pin_length(env: &mut impl Env, min_pin_length: u8) -> Result<(), Ctap2StatusCode> {
    Ok(env.store().insert(key::MIN_PIN_LENGTH, &[min_pin_length])?)
}

/// Returns the list of RP IDs that are used to check if reading the minimum PIN length is
/// allowed.
pub fn min_pin_length_rp_ids(env: &mut impl Env) -> Result<Vec<String>, Ctap2StatusCode> {
    let rp_ids = env.store().find(key::MIN_PIN_LENGTH_RP_IDS)?.map_or_else(
        || Some(env.customization().default_min_pin_length_rp_ids()),
        |value| deserialize_min_pin_length_rp_ids(&value),
    );
    debug_assert!(rp_ids.is_some());
    Ok(rp_ids.unwrap_or_default())
}

/// Sets the list of RP IDs that are used to check if reading the minimum PIN length is allowed.
#[cfg(feature = "config_command")]
pub fn set_min_pin_length_rp_ids(
    env: &mut impl Env,
    min_pin_length_rp_ids: Vec<String>,
) -> Result<(), Ctap2StatusCode> {
    let mut min_pin_length_rp_ids = min_pin_length_rp_ids;
    for rp_id in env.customization().default_min_pin_length_rp_ids() {
        if !min_pin_length_rp_ids.contains(&rp_id) {
            min_pin_length_rp_ids.push(rp_id);
        }
    }
    if min_pin_length_rp_ids.len() > env.customization().max_rp_ids_length() {
        return Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL);
    }
    Ok(env.store().insert(
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
    env: &mut impl Env,
    offset: usize,
    byte_count: usize,
) -> Result<Vec<u8>, Ctap2StatusCode> {
    let byte_range = offset..offset + byte_count;
    let output = fragment::read_range(env.store(), &key::LARGE_BLOB_SHARDS, byte_range)?;
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
    env: &mut impl Env,
    large_blob_array: &[u8],
) -> Result<(), Ctap2StatusCode> {
    // This input should have been caught at caller level.
    if large_blob_array.len() > env.customization().max_large_blob_array_size() {
        return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
    }
    Ok(fragment::write(
        env.store(),
        &key::LARGE_BLOB_SHARDS,
        large_blob_array,
    )?)
}

/// Resets the store as for a CTAP reset.
///
/// In particular persistent entries are not reset.
pub fn reset(env: &mut impl Env) -> Result<(), Ctap2StatusCode> {
    env.store().clear(key::NUM_PERSISTENT_KEYS)?;
    env.key_store().reset()?;
    init(env)?;
    Ok(())
}

/// Returns whether the PIN needs to be changed before its next usage.
pub fn has_force_pin_change(env: &mut impl Env) -> Result<bool, Ctap2StatusCode> {
    match env.store().find(key::FORCE_PIN_CHANGE)? {
        None => Ok(false),
        Some(value) if value.is_empty() => Ok(true),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
    }
}

/// Marks the PIN as outdated with respect to the new PIN policy.
#[cfg(feature = "config_command")]
pub fn force_pin_change(env: &mut impl Env) -> Result<(), Ctap2StatusCode> {
    Ok(env.store().insert(key::FORCE_PIN_CHANGE, &[])?)
}

/// Returns whether enterprise attestation is enabled.
///
/// Without the AuthenticatorConfig command, customization determines the result.
#[cfg(not(feature = "config_command"))]
pub fn enterprise_attestation(env: &mut impl Env) -> Result<bool, Ctap2StatusCode> {
    Ok(env.customization().enterprise_attestation_mode().is_some())
}

/// Returns whether enterprise attestation is enabled.
///
/// Use the AuthenticatorConfig command to turn it on.
#[cfg(feature = "config_command")]
pub fn enterprise_attestation(env: &mut impl Env) -> Result<bool, Ctap2StatusCode> {
    match env.store().find(key::ENTERPRISE_ATTESTATION)? {
        None => Ok(false),
        Some(value) if value.is_empty() => Ok(true),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
    }
}

/// Marks enterprise attestation as enabled.
#[cfg(feature = "config_command")]
pub fn enable_enterprise_attestation(env: &mut impl Env) -> Result<(), Ctap2StatusCode> {
    if env
        .attestation_store()
        .get(&attestation_store::Id::Enterprise)?
        .is_none()
    {
        return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
    }
    if !enterprise_attestation(env)? {
        env.store().insert(key::ENTERPRISE_ATTESTATION, &[])?;
    }
    Ok(())
}

/// Returns whether alwaysUv is enabled.
pub fn has_always_uv(env: &mut impl Env) -> Result<bool, Ctap2StatusCode> {
    if env.customization().enforce_always_uv() {
        return Ok(true);
    }
    match env.store().find(key::ALWAYS_UV)? {
        None => Ok(false),
        Some(value) if value.is_empty() => Ok(true),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
    }
}

/// Enables alwaysUv, when disabled, and vice versa.
#[cfg(feature = "config_command")]
pub fn toggle_always_uv(env: &mut impl Env) -> Result<(), Ctap2StatusCode> {
    if env.customization().enforce_always_uv() {
        return Err(Ctap2StatusCode::CTAP2_ERR_OPERATION_DENIED);
    }
    if has_always_uv(env)? {
        Ok(env.store().remove(key::ALWAYS_UV)?)
    } else {
        Ok(env.store().insert(key::ALWAYS_UV, &[])?)
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
pub struct IterCredentials<'a, E: Env> {
    /// The store being iterated.
    store: &'a persistent_store::Store<E::Storage>,

    /// The key store for credential unwrapping.
    wrap_key: AesKey<E>,

    /// The store iterator.
    iter: persistent_store::StoreIter<'a>,

    /// The iteration result.
    ///
    /// It starts as success and gets written at most once with an error if something fails. The
    /// iteration stops as soon as an error is encountered.
    result: &'a mut Result<(), Ctap2StatusCode>,
}

impl<'a, E: Env> IterCredentials<'a, E> {
    /// Creates a credential iterator.
    fn new(
        env: &'a mut E,
        result: &'a mut Result<(), Ctap2StatusCode>,
    ) -> Result<Self, Ctap2StatusCode> {
        let wrap_key = env.key_store().wrap_key::<E>()?;
        let store = env.store();
        let iter = store.iter()?;
        Ok(IterCredentials {
            store,
            wrap_key,
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

impl<'a, E: Env> Iterator for IterCredentials<'a, E> {
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
            let value = self.unwrap(handle.get_value(self.store).ok())?;
            let deserialized = deserialize_credential::<E>(&self.wrap_key, &value);
            let credential = self.unwrap(deserialized)?;
            return Some((key, credential));
        }
        None
    }
}

/// Deserializes a credential from storage representation.
fn deserialize_credential<E: Env>(
    wrap_key: &AesKey<E>,
    data: &[u8],
) -> Option<PublicKeyCredentialSource> {
    let cbor = super::cbor_read(data).ok()?;
    PublicKeyCredentialSource::from_cbor::<E>(wrap_key, cbor).ok()
}

/// Serializes a credential to storage representation.
fn serialize_credential<E: Env>(
    env: &mut E,
    wrap_key: &AesKey<E>,
    credential: PublicKeyCredentialSource,
) -> Result<Vec<u8>, Ctap2StatusCode> {
    let mut data = Vec::new();
    super::cbor_write(credential.to_cbor::<E>(env.rng(), wrap_key)?, &mut data)?;
    Ok(data)
}

/// Deserializes a list of RP IDs from storage representation.
fn deserialize_min_pin_length_rp_ids(data: &[u8]) -> Option<Vec<String>> {
    let cbor = super::cbor_read(data).ok()?;
    extract_array(cbor)
        .ok()?
        .into_iter()
        .map(extract_text_string)
        .collect::<Result<Vec<String>, Ctap2StatusCode>>()
        .ok()
}

/// Serializes a list of RP IDs to storage representation.
#[cfg(feature = "config_command")]
fn serialize_min_pin_length_rp_ids(rp_ids: Vec<String>) -> Result<Vec<u8>, Ctap2StatusCode> {
    let mut data = Vec::new();
    super::cbor_write(cbor_array_vec!(rp_ids), &mut data)?;
    Ok(data)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::attestation_store::{self, Attestation, AttestationStore};
    use crate::api::private_key::PrivateKey;
    use crate::api::rng::Rng;
    use crate::ctap::data_formats::{
        CredentialProtectionPolicy, PublicKeyCredentialSource, PublicKeyCredentialType,
    };
    use crate::ctap::secret::Secret;
    use crate::env::test::TestEnv;

    fn create_credential_source(
        env: &mut TestEnv,
        rp_id: &str,
        user_handle: Vec<u8>,
    ) -> PublicKeyCredentialSource {
        let private_key = PrivateKey::new_ecdsa(env);
        PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: env.rng().gen_uniform_u8x32().to_vec(),
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
        let mut env = TestEnv::default();
        assert_eq!(count_credentials(&mut env).unwrap(), 0);
        let credential_source = create_credential_source(&mut env, "example.com", vec![]);
        assert!(store_credential(&mut env, credential_source).is_ok());
        assert!(count_credentials(&mut env).unwrap() > 0);
    }

    #[test]
    fn test_delete_credential() {
        let mut env = TestEnv::default();
        assert_eq!(count_credentials(&mut env).unwrap(), 0);

        let mut credential_ids = vec![];
        for i in 0..env.customization().max_supported_resident_keys() {
            let user_handle = (i as u32).to_ne_bytes().to_vec();
            let credential_source = create_credential_source(&mut env, "example.com", user_handle);
            credential_ids.push(credential_source.credential_id.clone());
            assert!(store_credential(&mut env, credential_source).is_ok());
            assert_eq!(count_credentials(&mut env).unwrap(), i + 1);
        }
        let mut count = count_credentials(&mut env).unwrap();
        for credential_id in credential_ids {
            assert!(delete_credential(&mut env, &credential_id).is_ok());
            count -= 1;
            assert_eq!(count_credentials(&mut env).unwrap(), count);
        }
    }

    #[test]
    fn test_update_credential() {
        let mut env = TestEnv::default();
        let user = PublicKeyCredentialUserEntity {
            // User ID is ignored.
            user_id: vec![0x00],
            user_name: Some("name".to_string()),
            user_display_name: Some("display_name".to_string()),
            user_icon: Some("icon".to_string()),
        };
        assert_eq!(
            update_credential(&mut env, &[0x1D], user.clone()),
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)
        );

        let credential_source = create_credential_source(&mut env, "example.com", vec![0x1D]);
        let credential_id = credential_source.credential_id.clone();
        assert!(store_credential(&mut env, credential_source).is_ok());
        let stored_credential = find_credential(&mut env, "example.com", &credential_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored_credential.user_name, None);
        assert_eq!(stored_credential.user_display_name, None);
        assert_eq!(stored_credential.user_icon, None);
        assert!(update_credential(&mut env, &credential_id, user.clone()).is_ok());
        let stored_credential = find_credential(&mut env, "example.com", &credential_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored_credential.user_name, user.user_name);
        assert_eq!(stored_credential.user_display_name, user.user_display_name);
        assert_eq!(stored_credential.user_icon, user.user_icon);
    }

    #[test]
    fn test_credential_order() {
        let mut env = TestEnv::default();
        let credential_source = create_credential_source(&mut env, "example.com", vec![]);
        let current_latest_creation = credential_source.creation_order;
        assert!(store_credential(&mut env, credential_source).is_ok());
        let mut credential_source = create_credential_source(&mut env, "example.com", vec![]);
        credential_source.creation_order = new_creation_order(&mut env).unwrap();
        assert!(credential_source.creation_order > current_latest_creation);
        let current_latest_creation = credential_source.creation_order;
        assert!(store_credential(&mut env, credential_source).is_ok());
        assert!(new_creation_order(&mut env).unwrap() > current_latest_creation);
    }

    #[test]
    fn test_fill_store() {
        let mut env = TestEnv::default();
        assert_eq!(count_credentials(&mut env).unwrap(), 0);

        let max_supported_resident_keys = env.customization().max_supported_resident_keys();
        for i in 0..max_supported_resident_keys {
            let user_handle = (i as u32).to_ne_bytes().to_vec();
            let credential_source = create_credential_source(&mut env, "example.com", user_handle);
            assert!(store_credential(&mut env, credential_source).is_ok());
            assert_eq!(count_credentials(&mut env).unwrap(), i + 1);
        }
        let credential_source = create_credential_source(
            &mut env,
            "example.com",
            vec![max_supported_resident_keys as u8],
        );
        assert_eq!(
            store_credential(&mut env, credential_source),
            Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL)
        );
        assert_eq!(
            count_credentials(&mut env).unwrap(),
            max_supported_resident_keys
        );
    }

    #[test]
    fn test_overwrite() {
        let mut env = TestEnv::default();
        init(&mut env).unwrap();

        assert_eq!(count_credentials(&mut env).unwrap(), 0);
        // These should have different IDs.
        let credential_source0 = create_credential_source(&mut env, "example.com", vec![0x00]);
        let credential_source1 = create_credential_source(&mut env, "example.com", vec![0x00]);
        let credential_id0 = credential_source0.credential_id.clone();
        let credential_id1 = credential_source1.credential_id.clone();

        assert!(store_credential(&mut env, credential_source0).is_ok());
        assert!(store_credential(&mut env, credential_source1).is_ok());
        assert_eq!(count_credentials(&mut env).unwrap(), 1);
        assert!(find_credential(&mut env, "example.com", &credential_id0)
            .unwrap()
            .is_none());
        assert!(find_credential(&mut env, "example.com", &credential_id1)
            .unwrap()
            .is_some());

        reset(&mut env).unwrap();
        let max_supported_resident_keys = env.customization().max_supported_resident_keys();
        for i in 0..max_supported_resident_keys {
            let user_handle = (i as u32).to_ne_bytes().to_vec();
            let credential_source = create_credential_source(&mut env, "example.com", user_handle);
            assert!(store_credential(&mut env, credential_source).is_ok());
            assert_eq!(count_credentials(&mut env).unwrap(), i + 1);
        }
        let credential_source = create_credential_source(
            &mut env,
            "example.com",
            vec![max_supported_resident_keys as u8],
        );
        assert_eq!(
            store_credential(&mut env, credential_source),
            Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL)
        );
        assert_eq!(
            count_credentials(&mut env).unwrap(),
            max_supported_resident_keys
        );
    }

    #[test]
    fn test_get_credential() {
        let mut env = TestEnv::default();
        let credential_source0 = create_credential_source(&mut env, "example.com", vec![0x00]);
        let credential_source1 = create_credential_source(&mut env, "example.com", vec![0x01]);
        let credential_source2 =
            create_credential_source(&mut env, "another.example.com", vec![0x02]);
        let credential_sources = vec![credential_source0, credential_source1, credential_source2];
        for credential_source in credential_sources.into_iter() {
            let cred_id = credential_source.credential_id.clone();
            assert!(store_credential(&mut env, credential_source).is_ok());
            let (key, _) = find_credential_item(&mut env, &cred_id).unwrap();
            let cred = get_credential(&mut env, key).unwrap();
            assert_eq!(&cred_id, &cred.credential_id);
        }
    }

    #[test]
    fn test_find() {
        let mut env = TestEnv::default();
        assert_eq!(count_credentials(&mut env).unwrap(), 0);
        let credential_source0 = create_credential_source(&mut env, "example.com", vec![0x00]);
        let credential_source1 = create_credential_source(&mut env, "example.com", vec![0x01]);
        let id0 = credential_source0.credential_id.clone();
        let key0 = credential_source0.private_key.clone();
        assert!(store_credential(&mut env, credential_source0).is_ok());
        assert!(store_credential(&mut env, credential_source1).is_ok());

        let no_credential = find_credential(&mut env, "another.example.com", &id0).unwrap();
        assert_eq!(no_credential, None);
        let found_credential = find_credential(&mut env, "example.com", &id0).unwrap();
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
    fn test_pin_hash_and_length() {
        let mut env = TestEnv::default();

        // Pin hash is initially not set.
        assert!(pin_hash(&mut env).unwrap().is_none());
        assert!(pin_code_point_length(&mut env).unwrap().is_none());

        // Setting the pin sets the pin hash.
        let random_data = env.rng().gen_uniform_u8x32();
        assert_eq!(random_data.len(), 2 * PIN_AUTH_LENGTH);
        let pin_hash_1 = *array_ref!(random_data, 0, PIN_AUTH_LENGTH);
        let pin_hash_2 = *array_ref!(random_data, PIN_AUTH_LENGTH, PIN_AUTH_LENGTH);
        let pin_length_1 = 4;
        let pin_length_2 = 63;
        set_pin(&mut env, &pin_hash_1, pin_length_1).unwrap();
        assert_eq!(pin_hash(&mut env).unwrap(), Some(pin_hash_1));
        assert_eq!(pin_code_point_length(&mut env).unwrap(), Some(pin_length_1));
        set_pin(&mut env, &pin_hash_2, pin_length_2).unwrap();
        assert_eq!(pin_hash(&mut env).unwrap(), Some(pin_hash_2));
        assert_eq!(pin_code_point_length(&mut env).unwrap(), Some(pin_length_2));

        // Resetting the storage resets the pin hash.
        reset(&mut env).unwrap();
        assert!(pin_hash(&mut env).unwrap().is_none());
        assert!(pin_code_point_length(&mut env).unwrap().is_none());
    }

    #[test]
    fn test_pin_retries() {
        let mut env = TestEnv::default();

        // The pin retries is initially at the maximum.
        assert_eq!(
            pin_retries(&mut env),
            Ok(env.customization().max_pin_retries())
        );

        // Decrementing the pin retries decrements the pin retries.
        for retries in (0..env.customization().max_pin_retries()).rev() {
            decr_pin_retries(&mut env).unwrap();
            assert_eq!(pin_retries(&mut env), Ok(retries));
        }

        // Decrementing the pin retries after zero does not modify the pin retries.
        decr_pin_retries(&mut env).unwrap();
        assert_eq!(pin_retries(&mut env), Ok(0));

        // Resetting the pin retries resets the pin retries.
        reset_pin_retries(&mut env).unwrap();
        assert_eq!(
            pin_retries(&mut env),
            Ok(env.customization().max_pin_retries())
        );
    }

    #[test]
    fn test_persistent_keys() {
        let mut env = TestEnv::default();
        init(&mut env).unwrap();

        // Make sure the attestation are absent. There is no batch attestation in tests.
        assert_eq!(
            env.attestation_store().get(&attestation_store::Id::Batch),
            Ok(None)
        );

        // Make sure the persistent keys are initialized to dummy values.
        let dummy_attestation = Attestation {
            private_key: Secret::from_exposed_secret([0x41; 32]),
            certificate: vec![0xdd; 20],
        };
        env.attestation_store()
            .set(&attestation_store::Id::Batch, Some(&dummy_attestation))
            .unwrap();

        // The persistent keys stay initialized and preserve their value after a reset.
        reset(&mut env).unwrap();
        assert_eq!(
            env.attestation_store().get(&attestation_store::Id::Batch),
            Ok(Some(dummy_attestation))
        );
    }

    #[test]
    fn test_min_pin_length() {
        let mut env = TestEnv::default();

        // The minimum PIN length is initially at the default.
        assert_eq!(
            min_pin_length(&mut env).unwrap(),
            env.customization().default_min_pin_length()
        );

        // Changes by the setter are reflected by the getter..
        let new_min_pin_length = 8;
        set_min_pin_length(&mut env, new_min_pin_length).unwrap();
        assert_eq!(min_pin_length(&mut env).unwrap(), new_min_pin_length);
    }

    #[test]
    fn test_min_pin_length_rp_ids() {
        let mut env = TestEnv::default();

        // The minimum PIN length RP IDs are initially at the default.
        assert_eq!(
            min_pin_length_rp_ids(&mut env).unwrap(),
            env.customization().default_min_pin_length_rp_ids()
        );

        // Changes by the setter are reflected by the getter.
        let mut rp_ids = vec![String::from("example.com")];
        assert_eq!(set_min_pin_length_rp_ids(&mut env, rp_ids.clone()), Ok(()));
        for rp_id in env.customization().default_min_pin_length_rp_ids() {
            if !rp_ids.contains(&rp_id) {
                rp_ids.push(rp_id);
            }
        }
        assert_eq!(min_pin_length_rp_ids(&mut env).unwrap(), rp_ids);
    }

    #[test]
    fn test_max_large_blob_array_size() {
        let mut env = TestEnv::default();

        assert!(
            env.customization().max_large_blob_array_size()
                <= env.store().max_value_length()
                    * (key::LARGE_BLOB_SHARDS.end - key::LARGE_BLOB_SHARDS.start)
        );
    }

    #[test]
    fn test_commit_get_large_blob_array() {
        let mut env = TestEnv::default();

        let large_blob_array = vec![0x01, 0x02, 0x03];
        assert!(commit_large_blob_array(&mut env, &large_blob_array).is_ok());
        let restored_large_blob_array = get_large_blob_array(&mut env, 0, 1).unwrap();
        assert_eq!(vec![0x01], restored_large_blob_array);
        let restored_large_blob_array = get_large_blob_array(&mut env, 1, 1).unwrap();
        assert_eq!(vec![0x02], restored_large_blob_array);
        let restored_large_blob_array = get_large_blob_array(&mut env, 2, 1).unwrap();
        assert_eq!(vec![0x03], restored_large_blob_array);
        let restored_large_blob_array = get_large_blob_array(&mut env, 2, 2).unwrap();
        assert_eq!(vec![0x03], restored_large_blob_array);
        let restored_large_blob_array = get_large_blob_array(&mut env, 3, 1).unwrap();
        assert_eq!(Vec::<u8>::new(), restored_large_blob_array);
        let restored_large_blob_array = get_large_blob_array(&mut env, 4, 1).unwrap();
        assert_eq!(Vec::<u8>::new(), restored_large_blob_array);
    }

    #[test]
    fn test_commit_get_large_blob_array_overwrite() {
        let mut env = TestEnv::default();

        let large_blob_array = vec![0x11; 5];
        assert!(commit_large_blob_array(&mut env, &large_blob_array).is_ok());
        let large_blob_array = vec![0x22; 4];
        assert!(commit_large_blob_array(&mut env, &large_blob_array).is_ok());
        let restored_large_blob_array = get_large_blob_array(&mut env, 0, 5).unwrap();
        assert_eq!(large_blob_array, restored_large_blob_array);
        let restored_large_blob_array = get_large_blob_array(&mut env, 4, 1).unwrap();
        assert_eq!(Vec::<u8>::new(), restored_large_blob_array);

        assert!(commit_large_blob_array(&mut env, &[]).is_ok());
        let restored_large_blob_array = get_large_blob_array(&mut env, 0, 20).unwrap();
        // Committing an empty array resets to the default blob of 17 byte.
        assert_eq!(restored_large_blob_array.len(), 17);
    }

    #[test]
    fn test_commit_get_large_blob_array_no_commit() {
        let mut env = TestEnv::default();

        let empty_blob_array = vec![
            0x80, 0x76, 0xBE, 0x8B, 0x52, 0x8D, 0x00, 0x75, 0xF7, 0xAA, 0xE9, 0x8D, 0x6F, 0xA5,
            0x7A, 0x6D, 0x3C,
        ];
        let restored_large_blob_array = get_large_blob_array(&mut env, 0, 17).unwrap();
        assert_eq!(empty_blob_array, restored_large_blob_array);
        let restored_large_blob_array = get_large_blob_array(&mut env, 0, 1).unwrap();
        assert_eq!(vec![0x80], restored_large_blob_array);
        let restored_large_blob_array = get_large_blob_array(&mut env, 16, 1).unwrap();
        assert_eq!(vec![0x3C], restored_large_blob_array);
    }

    #[test]
    fn test_global_signature_counter() {
        let mut env = TestEnv::default();

        let mut counter_value = 1;
        assert_eq!(global_signature_counter(&mut env).unwrap(), counter_value);
        for increment in 1..10 {
            assert!(incr_global_signature_counter(&mut env, increment).is_ok());
            counter_value += increment;
            assert_eq!(global_signature_counter(&mut env).unwrap(), counter_value);
        }
    }

    #[test]
    fn test_force_pin_change() {
        let mut env = TestEnv::default();

        assert!(!has_force_pin_change(&mut env).unwrap());
        assert_eq!(force_pin_change(&mut env), Ok(()));
        assert!(has_force_pin_change(&mut env).unwrap());
        assert_eq!(set_pin(&mut env, &[0x88; 16], 8), Ok(()));
        assert!(!has_force_pin_change(&mut env).unwrap());
    }

    #[test]
    fn test_enterprise_attestation() {
        let mut env = TestEnv::default();

        let dummy_attestation = Attestation {
            private_key: Secret::from_exposed_secret([0x41; 32]),
            certificate: vec![0xdd; 20],
        };
        env.attestation_store()
            .set(&attestation_store::Id::Enterprise, Some(&dummy_attestation))
            .unwrap();

        assert!(!enterprise_attestation(&mut env).unwrap());
        assert_eq!(enable_enterprise_attestation(&mut env), Ok(()));
        assert!(enterprise_attestation(&mut env).unwrap());
        reset(&mut env).unwrap();
        assert!(!enterprise_attestation(&mut env).unwrap());
    }

    #[test]
    fn test_always_uv() {
        let mut env = TestEnv::default();

        if env.customization().enforce_always_uv() {
            assert!(has_always_uv(&mut env).unwrap());
            assert_eq!(
                toggle_always_uv(&mut env),
                Err(Ctap2StatusCode::CTAP2_ERR_OPERATION_DENIED)
            );
        } else {
            assert!(!has_always_uv(&mut env).unwrap());
            assert_eq!(toggle_always_uv(&mut env), Ok(()));
            assert!(has_always_uv(&mut env).unwrap());
            assert_eq!(toggle_always_uv(&mut env), Ok(()));
            assert!(!has_always_uv(&mut env).unwrap());
        }
    }

    #[test]
    fn test_serialize_deserialize_credential() {
        let mut env = TestEnv::default();
        let wrap_key = env.key_store().wrap_key::<TestEnv>().unwrap();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: env.rng().gen_uniform_u8x32().to_vec(),
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x00],
            user_display_name: Some(String::from("Display Name")),
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationOptional),
            creation_order: 0,
            user_name: Some(String::from("name")),
            user_icon: Some(String::from("icon")),
            cred_blob: Some(vec![0xCB]),
            large_blob_key: Some(vec![0x1B]),
        };
        let serialized =
            serialize_credential::<TestEnv>(&mut env, &wrap_key, credential.clone()).unwrap();
        let reconstructed = deserialize_credential::<TestEnv>(&wrap_key, &serialized).unwrap();
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
