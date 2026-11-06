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

// The signing traits provide no environment or context when signing. Counts allow
// nested guards to be dropped in any order without leaving failures enabled.
thread_local! {
    static FAIL_KEY_GENERATION: Cell<usize> = const { Cell::new(0) };
    static FAIL_SIGNING: Cell<usize> = const { Cell::new(0) };
}

/// Keeps a failure enabled on this thread until dropped, including during unwinding.
///
/// Guards for the same failure may be nested or dropped in any order. A guard
/// cannot be sent to another thread. Deliberately leaking it leaves the failure
/// enabled for the rest of the thread's lifetime.
#[must_use = "the failure is only enabled while the guard is alive"]
pub(crate) struct FailureGuard {
    count: &'static std::thread::LocalKey<Cell<usize>>,
    _not_send: PhantomData<Rc<()>>,
}

impl Drop for FailureGuard {
    fn drop(&mut self) {
        self.count.with(|count| count.set(count.get() - 1));
    }
}

fn fail(count: &'static std::thread::LocalKey<Cell<usize>>) -> FailureGuard {
    count.with(|count| count.set(count.get().checked_add(1).unwrap()));
    FailureGuard {
        count,
        _not_send: PhantomData,
    }
}

/// Makes all `TestCrypto` key generation fail on the current thread while the
/// returned guard is alive. Other threads, including parallel Cargo tests, are
/// unaffected; a spawned thread must enable the failure itself. All environments
/// on this thread share the setting, including interleaved tasks. Does not affect
/// signing, key import, or production crypto implementations.
pub(crate) fn fail_key_generation() -> FailureGuard {
    fail(&FAIL_KEY_GENERATION)
}

/// Makes all `TestCrypto` signing fail on the current thread while the returned
/// guard is alive. The thread and environment scope is the same as for
/// [`fail_key_generation`]; key generation remains unaffected.
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
        if FAIL_KEY_GENERATION.with(Cell::get) != 0 {
            return Err(ec_signing::Error);
        }
        software_crypto::SoftwareEcdsaSecretKey::random(rng).map(Self)
    }
    fn public_key(&self) -> Self::PublicKey {
        self.0.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, ec_signing::Error> {
        if FAIL_SIGNING.with(Cell::get) != 0 {
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
        if FAIL_KEY_GENERATION.with(Cell::get) != 0 {
            return Err(ec_signing::Error);
        }
        software_crypto::SoftwareEd25519SecretKey::random(rng).map(Self)
    }
    fn public_key(&self) -> Self::PublicKey {
        self.0.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, ec_signing::Error> {
        if FAIL_SIGNING.with(Cell::get) != 0 {
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
fn failure_remains_enabled_until_all_guards_are_dropped() {
    let first = fail_signing();
    let second = fail_signing();
    drop(first);
    assert_ne!(FAIL_SIGNING.with(Cell::get), 0);
    drop(second);
    assert_eq!(FAIL_SIGNING.with(Cell::get), 0);
}

#[test]
fn failure_guard_clears_setting_on_unwind() {
    let _ = std::panic::catch_unwind(|| {
        let _failure = fail_signing();
        panic!("simulated test failure");
    });
    assert_eq!(FAIL_SIGNING.with(Cell::get), 0);
}

#[test]
fn key_generation_failure_is_local_to_thread() {
    use rand::SeedableRng;

    let _failure = fail_key_generation();
    let other_thread = std::thread::spawn(|| {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        TestEcdsaSecretKey::random(&mut rng).is_ok()
    });
    assert!(other_thread.join().unwrap());
}

#[test]
fn signing_failure_is_local_to_thread() {
    use rand::SeedableRng;

    let _failure = fail_signing();
    let other_thread = std::thread::spawn(|| {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        TestEcdsaSecretKey::random(&mut rng)
            .unwrap()
            .sign(b"test")
            .is_ok()
    });
    assert!(other_thread.join().unwrap());
}
