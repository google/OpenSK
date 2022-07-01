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

use self::upgrade_storage::BufferUpgradeStorage;
use crate::api::connection::{HidConnection, SendOrRecvResult, SendOrRecvStatus};
use crate::api::customization::DEFAULT_CUSTOMIZATION;
use crate::api::firmware_protection::FirmwareProtection;
use crate::api::key_store;
use crate::api::user_presence::{UserPresence, UserPresenceResult};
use crate::clock::ClockInt;
use crate::env::Env;
use customization::TestCustomization;
use embedded_time::duration::Milliseconds;
use persistent_store::{BufferOptions, BufferStorage, Store};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rng256::Rng256;

pub mod customization;
mod upgrade_storage;

pub struct TestEnv {
    rng: TestRng256,
    user_presence: TestUserPresence,
    store: Store<BufferStorage>,
    upgrade_storage: Option<BufferUpgradeStorage>,
    customization: TestCustomization,
}

pub struct TestRng256 {
    rng: StdRng,
}

impl TestRng256 {
    pub fn seed_from_u64(&mut self, state: u64) {
        self.rng = StdRng::seed_from_u64(state);
    }
}

impl Rng256 for TestRng256 {
    fn gen_uniform_u8x32(&mut self) -> [u8; 32] {
        let mut result = [Default::default(); 32];
        self.rng.fill(&mut result);
        result
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
    fn send_or_recv_with_timeout(
        &mut self,
        _buf: &mut [u8; 64],
        _timeout: Milliseconds<ClockInt>,
    ) -> SendOrRecvResult {
        // TODO: Implement I/O from canned requests/responses for integration testing.
        Ok(SendOrRecvStatus::Sent)
    }
}

impl TestEnv {
    pub fn new() -> Self {
        let rng = TestRng256 {
            rng: StdRng::seed_from_u64(0),
        };
        let user_presence = TestUserPresence {
            check: Box::new(|| Ok(())),
        };
        let storage = new_storage();
        let store = Store::new(storage).ok().unwrap();
        let upgrade_storage = Some(BufferUpgradeStorage::new().unwrap());
        let customization = DEFAULT_CUSTOMIZATION.into();
        TestEnv {
            rng,
            user_presence,
            store,
            upgrade_storage,
            customization,
        }
    }

    pub fn disable_upgrade_storage(&mut self) {
        self.upgrade_storage = None;
    }

    pub fn customization_mut(&mut self) -> &mut TestCustomization {
        &mut self.customization
    }

    pub fn rng(&mut self) -> &mut TestRng256 {
        &mut self.rng
    }
}

impl TestUserPresence {
    pub fn set(&mut self, check: impl Fn() -> UserPresenceResult + 'static) {
        self.check = Box::new(check);
    }
}

impl UserPresence for TestUserPresence {
    fn check_init(&mut self) {}
    fn wait_with_timeout(&mut self, _timeout: Milliseconds<ClockInt>) -> UserPresenceResult {
        (self.check)()
    }
    fn check_complete(&mut self) {}
}

impl FirmwareProtection for TestEnv {
    fn lock(&mut self) -> bool {
        true
    }
}

impl key_store::Helper for TestEnv {}

impl Env for TestEnv {
    type Rng = TestRng256;
    type UserPresence = TestUserPresence;
    type Storage = BufferStorage;
    type KeyStore = Self;
    type UpgradeStorage = BufferUpgradeStorage;
    type FirmwareProtection = Self;
    type Write = TestWrite;
    type Customization = TestCustomization;
    type HidConnection = Self;

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

    fn upgrade_storage(&mut self) -> Option<&mut Self::UpgradeStorage> {
        self.upgrade_storage.as_mut()
    }

    fn firmware_protection(&mut self) -> &mut Self::FirmwareProtection {
        self
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
}
