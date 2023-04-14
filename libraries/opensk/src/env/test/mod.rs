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

use crate::api::attestation_store::AttestationStore;
use crate::api::clock::Clock;
use crate::api::connection::{HidConnection, SendOrRecvResult, SendOrRecvStatus};
use crate::api::crypto::software_crypto::SoftwareCrypto;
use crate::api::customization::DEFAULT_CUSTOMIZATION;
use crate::api::rng::Rng;
use crate::api::user_presence::{UserPresence, UserPresenceResult};
use crate::api::{attestation_store, key_store};
use crate::env::Env;
use customization::TestCustomization;
use persistent_store::{BufferOptions, BufferStorage, Store};
use rand::rngs::StdRng;
use rand::SeedableRng;

pub mod customization;

pub struct TestEnv {
    rng: TestRng,
    user_presence: TestUserPresence,
    store: Store<BufferStorage>,
    customization: TestCustomization,
    clock: TestClock,
}

pub type TestRng = StdRng;

impl Rng for TestRng {}

#[derive(Debug, Default, PartialEq)]
pub struct TestTimer {
    end_ms: usize,
}

#[derive(Debug, Default)]
pub struct TestClock {
    /// The current time, as advanced, in milliseconds.
    now_ms: usize,
}

impl TestClock {
    pub fn advance(&mut self, milliseconds: usize) {
        self.now_ms += milliseconds;
    }
}

impl Clock for TestClock {
    type Timer = TestTimer;

    fn make_timer(&mut self, milliseconds: usize) -> Self::Timer {
        TestTimer {
            end_ms: self.now_ms + milliseconds,
        }
    }

    fn is_elapsed(&mut self, timer: &Self::Timer) -> bool {
        self.now_ms >= timer.end_ms
    }

    #[cfg(feature = "debug_ctap")]
    fn timestamp_us(&mut self) -> usize {
        // Unused, but let's implement something because it's easy.
        self.now_ms * 1000
    }
}

pub struct TestUserPresence {
    check: Box<dyn Fn() -> UserPresenceResult>,
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

impl HidConnection for TestEnv {
    fn send_and_maybe_recv(&mut self, _buf: &mut [u8; 64], _timeout_ms: usize) -> SendOrRecvResult {
        // TODO: Implement I/O from canned requests/responses for integration testing.
        Ok(SendOrRecvStatus::Sent)
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
        TestEnv {
            rng,
            user_presence,
            store,
            customization,
            clock,
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
}

impl TestUserPresence {
    pub fn set(&mut self, check: impl Fn() -> UserPresenceResult + 'static) {
        self.check = Box::new(check);
    }
}

impl UserPresence for TestUserPresence {
    fn check_init(&mut self) {}
    fn wait_with_timeout(&mut self, _timeout_ms: usize) -> UserPresenceResult {
        (self.check)()
    }
    fn check_complete(&mut self) {}
}

impl key_store::Helper for TestEnv {}

impl AttestationStore for TestEnv {
    fn get(
        &mut self,
        _id: &attestation_store::Id,
    ) -> Result<Option<attestation_store::Attestation>, attestation_store::Error> {
        attestation_store::helper_get(self)
    }

    fn set(
        &mut self,
        _id: &attestation_store::Id,
        attestation: Option<&attestation_store::Attestation>,
    ) -> Result<(), attestation_store::Error> {
        attestation_store::helper_set(self, attestation)
    }
}

impl Env for TestEnv {
    type Rng = TestRng;
    type UserPresence = TestUserPresence;
    type Storage = BufferStorage;
    type KeyStore = Self;
    type AttestationStore = Self;
    type Clock = TestClock;
    type Write = TestWrite;
    type Customization = TestCustomization;
    type HidConnection = Self;
    type Crypto = SoftwareCrypto;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        &mut self.user_presence
    }

    fn store(&mut self) -> &mut Store<Self::Storage> {
        &mut self.store
    }

    fn key_store(&mut self) -> &mut Self {
        self
    }

    fn attestation_store(&mut self) -> &mut Self {
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

    fn main_hid_connection(&mut self) -> &mut Self::HidConnection {
        self
    }

    #[cfg(feature = "vendor_hid")]
    fn vendor_hid_connection(&mut self) -> &mut Self::HidConnection {
        self
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
}
