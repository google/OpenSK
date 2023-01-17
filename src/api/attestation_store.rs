use alloc::vec::Vec;
use persistent_store::{StoreError, StoreUpdate};

use crate::env::Env;

/// Identifies an attestation.
#[derive(Clone, PartialEq, Eq)]
pub enum Id {
    Batch,
    Enterprise,
}

#[cfg_attr(feature = "std", derive(Debug, PartialEq, Eq))]
pub struct Attestation {
    /// ECDSA private key (big-endian).
    pub private_key: [u8; 32],
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
    if private_key.len() != 32 {
        return Err(Error::Internal);
    }
    Ok(Some(Attestation {
        private_key: *array_ref![private_key, 0, 32],
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
            | StoreError::StorageImplError(_)
            | StoreError::InvalidStorage => Error::Internal,
            StoreError::StorageError => Error::Storage,
        }
    }
}
