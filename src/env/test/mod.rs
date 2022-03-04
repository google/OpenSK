use self::upgrade_storage::BufferUpgradeStorage;
use crate::api::firmware_protection::FirmwareProtection;
use crate::ctap::hid::ChannelID;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::env::{Env, UserPresence};
use crypto::rng256::ThreadRng256;
use persistent_store::{BufferOptions, BufferStorage, StorageResult};

mod upgrade_storage;

pub struct TestEnv {
    rng: ThreadRng256,
    user_presence: TestUserPresence,
}

pub struct TestUserPresence {
    check: Box<dyn Fn(ChannelID) -> Result<(), Ctap2StatusCode>>,
}

impl TestEnv {
    pub fn new() -> Self {
        let rng = ThreadRng256 {};
        let user_presence = TestUserPresence {
            check: Box::new(|_| Ok(())),
        };
        TestEnv { rng, user_presence }
    }
}

impl TestUserPresence {
    pub fn set(&mut self, check: impl Fn(ChannelID) -> Result<(), Ctap2StatusCode> + 'static) {
        self.check = Box::new(check);
    }
}

impl UserPresence for TestUserPresence {
    fn check(&self, cid: ChannelID) -> Result<(), Ctap2StatusCode> {
        (self.check)(cid)
    }
}

impl FirmwareProtection for TestEnv {
    fn lock(&mut self) -> bool {
        true
    }
}

impl Env for TestEnv {
    type Rng = ThreadRng256;
    type UserPresence = TestUserPresence;
    type Storage = BufferStorage;
    type UpgradeStorage = BufferUpgradeStorage;
    type FirmwareProtection = Self;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        &mut self.user_presence
    }

    fn storage(&mut self) -> StorageResult<Self::Storage> {
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
        Ok(BufferStorage::new(store, options))
    }

    fn upgrade_storage(&mut self) -> StorageResult<Self::UpgradeStorage> {
        BufferUpgradeStorage::new()
    }

    fn firmware_protection(&mut self) -> &mut Self::FirmwareProtection {
        self
    }
}
