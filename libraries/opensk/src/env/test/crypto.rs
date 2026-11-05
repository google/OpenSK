// Copyright 2026 Google LLC
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

//! Test-only crypto that can simulate signing and key generation failures.

use crate::api::crypto::Crypto;
#[cfg(feature = "ed25519")]
use crate::api::crypto::ec_signing::EdSecretKey;
use crate::api::crypto::ec_signing::{self, EcSecretKey};
use crate::api::crypto::software_crypto::{self, SoftwareCrypto};
use crate::api::rng::Rng;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::marker::PhantomData;

// The signing traits provide no environment or context when signing. Thread-local
// controls isolate parallel tests; they affect every TestCrypto key on this thread.
thread_local! {
    static FAIL_KEY_GENERATION: Cell<bool> = const { Cell::new(false) };
    static FAIL_SIGNING: Cell<bool> = const { Cell::new(false) };
}

/// Restores the previous setting even if the test panics. It cannot move threads.
pub(crate) struct FailureGuard {
    flag: &'static std::thread::LocalKey<Cell<bool>>,
    previous: bool,
    _not_send: PhantomData<Rc<()>>,
}

impl Drop for FailureGuard {
    fn drop(&mut self) {
        self.flag.with(|flag| flag.set(self.previous));
    }
}

fn fail(flag: &'static std::thread::LocalKey<Cell<bool>>) -> FailureGuard {
    let previous = flag.with(|flag| flag.replace(true));
    FailureGuard {
        flag,
        previous,
        _not_send: PhantomData,
    }
}

pub(crate) fn fail_key_generation() -> FailureGuard {
    fail(&FAIL_KEY_GENERATION)
}

pub(crate) fn fail_signing() -> FailureGuard {
    fail(&FAIL_SIGNING)
}

pub struct TestCrypto;
pub struct TestEcdsa;
pub struct TestEcdsaSecretKey(software_crypto::SoftwareEcdsaSecretKey);

impl Crypto for TestCrypto {
    type Aes256 = <SoftwareCrypto as Crypto>::Aes256;
    type Ecdh = <SoftwareCrypto as Crypto>::Ecdh;
    type Ecdsa = TestEcdsa;
    #[cfg(feature = "ed25519")]
    type Ed25519 = TestEd25519;
    type Sha256 = <SoftwareCrypto as Crypto>::Sha256;
    type Hmac256 = <SoftwareCrypto as Crypto>::Hmac256;
    type Hkdf256 = <SoftwareCrypto as Crypto>::Hkdf256;
}

impl ec_signing::Ecdsa for TestEcdsa {
    type SecretKey = TestEcdsaSecretKey;
    type PublicKey = software_crypto::SoftwareEcdsaPublicKey;
    type Signature = software_crypto::SoftwareEcdsaSignature;
}

impl EcSecretKey for TestEcdsaSecretKey {
    type PublicKey = software_crypto::SoftwareEcdsaPublicKey;
    type Signature = software_crypto::SoftwareEcdsaSignature;

    fn random(rng: &mut impl Rng) -> Result<Self, ec_signing::Error> {
        if FAIL_KEY_GENERATION.with(Cell::get) {
            return Err(ec_signing::Error);
        }
        software_crypto::SoftwareEcdsaSecretKey::random(rng).map(Self)
    }
    fn public_key(&self) -> Self::PublicKey {
        self.0.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, ec_signing::Error> {
        if FAIL_SIGNING.with(Cell::get) {
            return Err(ec_signing::Error);
        }
        self.0.sign(message)
    }
    fn export(&self) -> Vec<u8> {
        self.0.export()
    }
    fn import(bytes: &[u8]) -> Option<Self> {
        software_crypto::SoftwareEcdsaSecretKey::import(bytes).map(Self)
    }
}

#[cfg(feature = "ed25519")]
pub struct TestEd25519;
#[cfg(feature = "ed25519")]
pub struct TestEd25519SecretKey(software_crypto::SoftwareEd25519SecretKey);

#[cfg(feature = "ed25519")]
impl ec_signing::Ed25519 for TestEd25519 {
    type SecretKey = TestEd25519SecretKey;
    type PublicKey = software_crypto::SoftwareEd25519PublicKey;
    type Signature = software_crypto::SoftwareEd25519Signature;
}

#[cfg(feature = "ed25519")]
impl EdSecretKey for TestEd25519SecretKey {
    type PublicKey = software_crypto::SoftwareEd25519PublicKey;
    type Signature = software_crypto::SoftwareEd25519Signature;

    fn random(rng: &mut impl Rng) -> Result<Self, ec_signing::Error> {
        if FAIL_KEY_GENERATION.with(Cell::get) {
            return Err(ec_signing::Error);
        }
        software_crypto::SoftwareEd25519SecretKey::random(rng).map(Self)
    }
    fn public_key(&self) -> Self::PublicKey {
        self.0.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, ec_signing::Error> {
        if FAIL_SIGNING.with(Cell::get) {
            return Err(ec_signing::Error);
        }
        self.0.sign(message)
    }
    fn export(&self) -> Vec<u8> {
        self.0.export()
    }
    fn import(bytes: &[u8]) -> Option<Self> {
        software_crypto::SoftwareEd25519SecretKey::import(bytes).map(Self)
    }
}

#[test]
fn failure_guard_restores_nested_settings_and_after_unwind() {
    assert!(!FAIL_SIGNING.with(Cell::get));
    {
        let _outer = fail_signing();
        {
            let _inner = fail_signing();
            assert!(FAIL_SIGNING.with(Cell::get));
        }
        assert!(FAIL_SIGNING.with(Cell::get));
    }
    assert!(!FAIL_SIGNING.with(Cell::get));
    let _ = std::panic::catch_unwind(|| {
        let _failure = fail_signing();
        panic!("simulated test failure");
    });
    assert!(!FAIL_SIGNING.with(Cell::get));
}

#[test]
fn failure_setting_is_local_to_thread() {
    let _failure = fail_signing();
    assert!(FAIL_SIGNING.with(Cell::get));
    std::thread::spawn(|| assert!(!FAIL_SIGNING.with(Cell::get)))
        .join()
        .unwrap();
}
