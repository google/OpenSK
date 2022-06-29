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

use alloc::vec::Vec;
use crypto::ecdsa::SecKey;
use persistent_store::StoreError;
use rng256::Rng256;

use crate::env::Env;

/// Provides storage for secret keys.
///
/// Implementations may use the environment store: [`STORE_KEY`] is reserved for this usage.
pub trait KeyStore {
    /// Returns the AES key for key handles encryption.
    fn kh_encryption(&mut self) -> Result<[u8; 32], Error>;

    /// Returns the key for key handles authentication.
    fn kh_authentication(&mut self) -> Result<[u8; 32], Error>;

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
/// They are deliberately indistinguishable from each other to avoid leaking information.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Error;

/// Key of the environment store reserved for the key store.
pub const STORE_KEY: usize = 2046;

impl<T: Env> KeyStore for T {
    fn kh_encryption(&mut self) -> Result<[u8; 32], Error> {
        Ok(get_master_keys(self)?.encryption)
    }

    fn kh_authentication(&mut self) -> Result<[u8; 32], Error> {
        Ok(get_master_keys(self)?.authentication)
    }

    fn derive_ecdsa(&mut self, seed: &[u8; 32]) -> Result<[u8; 32], Error> {
        match SecKey::from_bytes(seed) {
            None => Err(Error),
            Some(_) => Ok(*seed),
        }
    }

    fn generate_ecdsa_seed(&mut self) -> Result<[u8; 32], Error> {
        let mut seed = [0; 32];
        SecKey::gensk(self.rng()).to_bytes(&mut seed);
        Ok(seed)
    }

    fn reset(&mut self) -> Result<(), Error> {
        Ok(self.store().remove(STORE_KEY)?)
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
    let master_keys = match env.store().find(STORE_KEY)? {
        Some(x) => x,
        None => {
            let master_encryption_key = env.rng().gen_uniform_u8x32();
            let master_authentication_key = env.rng().gen_uniform_u8x32();
            let mut master_keys = Vec::with_capacity(64);
            master_keys.extend_from_slice(&master_encryption_key);
            master_keys.extend_from_slice(&master_authentication_key);
            env.store().insert(STORE_KEY, &master_keys)?;
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

#[test]
fn test_key_store() {
    let mut env = crate::env::test::TestEnv::new();
    let key_store = env.key_store();

    // Master keys are well-defined and stable.
    let encryption_key = key_store.kh_encryption().unwrap();
    let authentication_key = key_store.kh_authentication().unwrap();
    assert_eq!(key_store.kh_encryption(), Ok(encryption_key));
    assert_eq!(key_store.kh_authentication(), Ok(authentication_key));

    // ECDSA seeds are well-defined and stable.
    let ecdsa_seed = key_store.generate_ecdsa_seed().unwrap();
    let ecdsa_key = key_store.derive_ecdsa(&ecdsa_seed).unwrap();
    assert_eq!(key_store.derive_ecdsa(&ecdsa_seed), Ok(ecdsa_key));

    // Master keys change after reset. We don't require this for ECDSA seeds because it's not the
    // case, but it might be better.
    key_store.reset().unwrap();
    assert!(key_store.kh_encryption().unwrap() != encryption_key);
    assert!(key_store.kh_authentication().unwrap() != authentication_key);
}
