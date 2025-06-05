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

use crate::api::clock::Clock;
use crate::api::connection::{HidConnection, RecvStatus, UsbEndpoint};
use crate::api::crypto::software_crypto::SoftwareCrypto;
use crate::api::customization::DEFAULT_CUSTOMIZATION;
#[cfg(feature = "fingerprint")]
use crate::api::fingerprint::{
    Ctap2EnrollFeedback, Fingerprint, FingerprintCheckError, FingerprintKind,
};
use crate::api::key_store;
use crate::api::persist::{Persist, PersistIter};
use crate::api::rng::Rng;
use crate::api::user_presence::{UserPresence, UserPresenceResult, UserPresenceWaitResult};
use crate::ctap::status_code::CtapResult;
use crate::env::Env;
use customization::TestCustomization;
use persistent_store::{BufferOptions, BufferStorage, Store};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::{Arc, Mutex};

pub mod customization;

pub struct TestEnv {
    rng: TestRng,
    user_presence: TestUserPresence,
    store: Store<BufferStorage>,
    customization: TestCustomization,
    clock: TestClock,
    soft_reset: bool,
    #[cfg(feature = "fingerprint")]
    fingerprint: TestFingerprint,
}

pub type TestRng = StdRng;

impl Rng for TestRng {}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TestTimer {
    end_ms: usize,
}

#[derive(Clone, Debug, Default)]
pub struct TestClock {
    /// The current time, as advanced, in milliseconds.
    now_ms: Arc<Mutex<usize>>,
}

impl TestClock {
    pub fn now(&self) -> usize {
        *self.now_ms.lock().unwrap()
    }

    pub fn advance(&self, milliseconds: usize) {
        let mut locked_now_ms = self.now_ms.lock().unwrap();
        *locked_now_ms += milliseconds;
    }
}

impl Clock for TestClock {
    type Timer = TestTimer;

    fn make_timer(&mut self, milliseconds: usize) -> Self::Timer {
        TestTimer {
            end_ms: self.now() + milliseconds,
        }
    }

    fn is_elapsed(&mut self, timer: &Self::Timer) -> bool {
        self.now() >= timer.end_ms
    }

    #[cfg(feature = "debug_ctap")]
    fn timestamp_us(&mut self) -> usize {
        // Unused, but let's implement something because it's easy.
        self.now() * 1000
    }
}

pub struct TestUserPresence {
    check: Box<dyn Fn() -> UserPresenceResult>,
}

#[cfg(feature = "fingerprint")]
#[derive(Debug, Default)]
pub struct TestFingerprint {
    // TODO more complete fake
    template_ids: Vec<Vec<u8>>,
    template_counter: usize,
}

pub struct TestWrite;

impl core::fmt::Write for TestWrite {
    fn write_str(&mut self, _: &str) -> core::fmt::Result {
        Ok(())
    }
}

fn new_storage() -> BufferStorage {
    // Use the Nordic configuration.
    const PAGE_SIZE: usize = 0x1000;
    const NUM_PAGES: usize = 20;
    let store = vec![0xff; NUM_PAGES * PAGE_SIZE].into_boxed_slice();
    let options = BufferOptions {
        word_size: 4,
        page_size: PAGE_SIZE,
        max_word_writes: 2,
        max_page_erases: 10000,
        strict_mode: true,
    };
    BufferStorage::new(store, options)
}

impl Persist for TestEnv {
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        Ok(self.store.find(key)?)
    }

    fn insert(&mut self, key: usize, value: &[u8]) -> CtapResult<()> {
        Ok(self.store.insert(key, value)?)
    }

    fn remove(&mut self, key: usize) -> CtapResult<()> {
        Ok(self.store.remove(key)?)
    }

    fn iter(&self) -> CtapResult<PersistIter<'_>> {
        Ok(Box::new(self.store.iter()?.map(|handle| match handle {
            Ok(handle) => Ok(handle.get_key()),
            Err(error) => Err(error.into()),
        })))
    }
}

impl HidConnection for TestEnv {
    // TODO: Implement I/O from canned requests/responses for integration testing.

    fn send(&mut self, _buf: &[u8; 64], _endpoint: UsbEndpoint) -> CtapResult<()> {
        Ok(())
    }

    fn recv(&mut self, _buf: &mut [u8; 64], _timeout_ms: usize) -> CtapResult<RecvStatus> {
        Ok(RecvStatus::Received(UsbEndpoint::MainHid))
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        let rng = StdRng::seed_from_u64(0);
        let user_presence = TestUserPresence {
            check: Box::new(|| Ok(())),
        };
        let storage = new_storage();
        let store = Store::new(storage).ok().unwrap();
        let customization = DEFAULT_CUSTOMIZATION.into();
        let clock = TestClock::default();
        #[cfg(feature = "fingerprint")]
        let fingerprint = TestFingerprint::default();
        TestEnv {
            rng,
            user_presence,
            store,
            customization,
            clock,
            soft_reset: false,
            #[cfg(feature = "fingerprint")]
            fingerprint,
        }
    }
}

impl TestEnv {
    pub fn customization_mut(&mut self) -> &mut TestCustomization {
        &mut self.customization
    }

    pub fn seed_rng_from_u64(&mut self, seed: u64) {
        self.rng = StdRng::seed_from_u64(seed);
    }

    pub fn set_boots_after_soft_reset(&mut self, value: bool) {
        self.soft_reset = value;
    }
}

impl TestUserPresence {
    pub fn set(&mut self, check: impl Fn() -> UserPresenceResult + 'static) {
        self.check = Box::new(check);
    }
}

impl UserPresence for TestUserPresence {
    fn check_init(&mut self) {}
    fn wait_with_timeout(
        &mut self,
        _buf: &mut [u8; 64],
        _timeout_ms: usize,
    ) -> UserPresenceWaitResult {
        Ok(((self.check)(), RecvStatus::Timeout))
    }
    fn check_complete(&mut self) {}
}

#[cfg(feature = "fingerprint")]
impl Fingerprint for TestFingerprint {
    fn prepare_enrollment(&mut self) -> CtapResult<Vec<u8>> {
        self.template_counter += 1;
        let template_id = Vec::from(&self.template_counter.to_be_bytes());
        self.template_ids.push(template_id.clone());
        Ok(template_id)
    }

    fn capture_sample(
        &mut self,
        _template_id: &[u8],
        _timeout_ms: Option<usize>,
    ) -> CtapResult<(Ctap2EnrollFeedback, usize)> {
        Ok((Ctap2EnrollFeedback::FpGood, 0))
    }

    fn cancel_enrollment(&mut self) -> CtapResult<()> {
        Ok(())
    }

    fn remove_enrollment(&mut self, template_id: &[u8]) -> CtapResult<()> {
        let index = self.template_ids.iter().position(|x| x == template_id);
        if let Some(index) = index {
            self.template_ids.remove(index);
        }
        Ok(())
    }

    fn check_fingerprint_init(&mut self) {}

    fn check_fingerprint(&mut self, _timeout_ms: usize) -> Result<(), FingerprintCheckError> {
        if self.template_ids.is_empty() {
            return Err(FingerprintCheckError::NoMatch);
        }
        Ok(())
    }

    fn check_fingerprint_complete(&mut self) {}

    fn fingerprint_kind(&self) -> FingerprintKind {
        FingerprintKind::Touch
    }

    fn max_capture_samples_required_for_enroll(&self) -> usize {
        1
    }
}

impl key_store::Helper for TestEnv {}

impl Env for TestEnv {
    type Rng = TestRng;
    type UserPresence = TestUserPresence;
    type Persist = Self;
    type KeyStore = Self;
    type Clock = TestClock;
    type Write = TestWrite;
    type Customization = TestCustomization;
    type HidConnection = Self;
    type Crypto = SoftwareCrypto;
    #[cfg(feature = "fingerprint")]
    type Fingerprint = TestFingerprint;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        &mut self.user_presence
    }

    #[cfg(feature = "fingerprint")]
    fn fingerprint(&mut self) -> &mut Self::Fingerprint {
        &mut self.fingerprint
    }

    fn persist(&mut self) -> &mut Self {
        self
    }

    fn key_store(&mut self) -> &mut Self {
        self
    }

    fn clock(&mut self) -> &mut Self::Clock {
        &mut self.clock
    }

    fn write(&mut self) -> Self::Write {
        TestWrite
    }

    fn customization(&self) -> &Self::Customization {
        &self.customization
    }

    fn hid_connection(&mut self) -> &mut Self {
        self
    }

    fn boots_after_soft_reset(&self) -> bool {
        self.soft_reset
    }

    fn firmware_version(&self) -> Option<u64> {
        Some(0)
    }
}

#[cfg(test)]
#[allow(clippy::module_inception)]
mod test {
    use super::*;

    #[test]
    fn test_clock() {
        let mut clock = TestClock::default();
        let timer = clock.make_timer(3);
        assert!(!clock.is_elapsed(&timer));
        clock.advance(2);
        assert!(!clock.is_elapsed(&timer));
        clock.advance(1);
        assert!(clock.is_elapsed(&timer));
    }

    #[test]
    fn test_soft_reset() {
        let mut env = TestEnv::default();
        assert!(!env.boots_after_soft_reset());
        env.set_boots_after_soft_reset(true);
        assert!(env.boots_after_soft_reset());
        env.set_boots_after_soft_reset(false);
        assert!(!env.boots_after_soft_reset());
    }
}
