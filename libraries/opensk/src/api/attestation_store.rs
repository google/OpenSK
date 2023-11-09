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

use crate::api::crypto::EC_FIELD_SIZE;
use crate::ctap::secret::Secret;
use crate::env::Env;
use alloc::vec::Vec;
use persistent_store::{StoreError, StoreUpdate};

/// Identifies an attestation.
#[derive(Clone, PartialEq, Eq)]
pub enum Id {
    Batch,
    Enterprise,
}

#[cfg_attr(feature = "std", derive(Debug, PartialEq, Eq))]
pub struct Attestation {
    /// ECDSA private key (big-endian).
    pub private_key: Secret<[u8; EC_FIELD_SIZE]>,
    pub certificate: Vec<u8>,
}

/// Stores enterprise or batch attestations.
pub trait AttestationStore {
    /// Returns an attestation given its id, if it exists.
    ///
    /// This should always return the attestation. Checking whether it is ok to use the attestation
    /// is done in the CTAP library.
    fn get(&mut self, id: &Id) -> Result<Option<Attestation>, Error>;

    /// Sets the attestation for a given id.
    ///
    /// This function may not be supported.
    fn set(&mut self, id: &Id, attestation: Option<&Attestation>) -> Result<(), Error>;
}

/// Attestation store errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Storage,
    Internal,
    NoSupport,
}

/// Keys of the environment store reserved for the attestation store.
pub const STORAGE_KEYS: &[usize] = &[1, 2];

pub fn helper_get(env: &mut impl Env) -> Result<Option<Attestation>, Error> {
    let private_key = env.store().find(PRIVATE_KEY_STORAGE_KEY)?;
    let certificate = env.store().find(CERTIFICATE_STORAGE_KEY)?;
    let (private_key, certificate) = match (private_key, certificate) {
        (Some(x), Some(y)) => (x, y),
        (None, None) => return Ok(None),
        _ => return Err(Error::Internal),
    };
    if private_key.len() != EC_FIELD_SIZE {
        return Err(Error::Internal);
    }
    Ok(Some(Attestation {
        private_key: Secret::from_exposed_secret(*array_ref![private_key, 0, EC_FIELD_SIZE]),
        certificate,
    }))
}

pub fn helper_set(env: &mut impl Env, attestation: Option<&Attestation>) -> Result<(), Error> {
    let updates = match attestation {
        None => [
            StoreUpdate::Remove {
                key: PRIVATE_KEY_STORAGE_KEY,
            },
            StoreUpdate::Remove {
                key: CERTIFICATE_STORAGE_KEY,
            },
        ],
        Some(attestation) => [
            StoreUpdate::Insert {
                key: PRIVATE_KEY_STORAGE_KEY,
                value: &attestation.private_key[..],
            },
            StoreUpdate::Insert {
                key: CERTIFICATE_STORAGE_KEY,
                value: &attestation.certificate[..],
            },
        ],
    };
    Ok(env.store().transaction(&updates)?)
}

const PRIVATE_KEY_STORAGE_KEY: usize = STORAGE_KEYS[0];
const CERTIFICATE_STORAGE_KEY: usize = STORAGE_KEYS[1];

impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::InvalidArgument
            | StoreError::NoCapacity
            | StoreError::NoLifetime
            | StoreError::InvalidStorage => Error::Internal,
            StoreError::StorageError => Error::Storage,
        }
    }
}
