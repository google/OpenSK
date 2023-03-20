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

use crate::api::crypto::ecdsa::SecretKey as _;
use crate::env::{EcdsaSk, Env};
use alloc::vec::Vec;
use persistent_store::StoreError;
use rng256::Rng256;

/// Provides storage for secret keys.
///
/// Implementations may use the environment store: [`STORAGE_KEY`] is reserved for this usage.
pub trait KeyStore {
    /// Returns the AES key for key handles encryption.
    fn key_handle_encryption(&mut self) -> Result<[u8; 32], Error>;

    /// Returns the key for key handles authentication.
    fn key_handle_authentication(&mut self) -> Result<[u8; 32], Error>;

    /// Derives an ECDSA private key from a seed.
    ///
    /// The result is big-endian.
    fn derive_ecdsa(&mut self, seed: &[u8; 32]) -> Result<[u8; 32], Error>;

    /// Generates a seed to derive an ECDSA private key.
    fn generate_ecdsa_seed(&mut self) -> Result<[u8; 32], Error>;

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
    fn key_handle_encryption(&mut self) -> Result<[u8; 32], Error> {
        Ok(get_master_keys(self)?.encryption)
    }

    fn key_handle_authentication(&mut self) -> Result<[u8; 32], Error> {
        Ok(get_master_keys(self)?.authentication)
    }

    fn derive_ecdsa(&mut self, seed: &[u8; 32]) -> Result<[u8; 32], Error> {
        match EcdsaSk::<T>::from_slice(seed) {
            None => Err(Error),
            Some(_) => Ok(*seed),
        }
    }

    fn generate_ecdsa_seed(&mut self) -> Result<[u8; 32], Error> {
        let mut seed = [0; 32];
        EcdsaSk::<T>::random(self.rng()).to_slice(&mut seed);
        Ok(seed)
    }

    fn reset(&mut self) -> Result<(), Error> {
        Ok(self.store().remove(STORAGE_KEY)?)
    }
}

/// Wrapper for master keys.
struct MasterKeys {
    /// Master encryption key.
    encryption: [u8; 32],

    /// Master authentication key.
    authentication: [u8; 32],
}

fn get_master_keys(env: &mut impl Env) -> Result<MasterKeys, Error> {
    let master_keys = match env.store().find(STORAGE_KEY)? {
        Some(x) => x,
        None => {
            let master_encryption_key = env.rng().gen_uniform_u8x32();
            let master_authentication_key = env.rng().gen_uniform_u8x32();
            let mut master_keys = Vec::with_capacity(64);
            master_keys.extend_from_slice(&master_encryption_key);
            master_keys.extend_from_slice(&master_authentication_key);
            env.store().insert(STORAGE_KEY, &master_keys)?;
            master_keys
        }
    };
    if master_keys.len() != 64 {
        return Err(Error);
    }
    Ok(MasterKeys {
        encryption: *array_ref![master_keys, 0, 32],
        authentication: *array_ref![master_keys, 32, 32],
    })
}

impl From<StoreError> for Error {
    fn from(_: StoreError) -> Self {
        Error
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_key_store() {
        let mut env = crate::env::test::TestEnv::default();
        let key_store = env.key_store();

        // Master keys are well-defined and stable.
        let encryption_key = key_store.key_handle_encryption().unwrap();
        let authentication_key = key_store.key_handle_authentication().unwrap();
        assert_eq!(key_store.key_handle_encryption(), Ok(encryption_key));
        assert_eq!(
            key_store.key_handle_authentication(),
            Ok(authentication_key)
        );

        // ECDSA seeds are well-defined and stable.
        let ecdsa_seed = key_store.generate_ecdsa_seed().unwrap();
        let ecdsa_key = key_store.derive_ecdsa(&ecdsa_seed).unwrap();
        assert_eq!(key_store.derive_ecdsa(&ecdsa_seed), Ok(ecdsa_key));

        // Master keys change after reset. We don't require this for ECDSA seeds because it's not
        // the case, but it might be better.
        key_store.reset().unwrap();
        assert!(key_store.key_handle_encryption().unwrap() != encryption_key);
        assert!(key_store.key_handle_authentication().unwrap() != authentication_key);
    }
}
