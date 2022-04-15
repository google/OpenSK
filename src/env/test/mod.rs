use self::upgrade_storage::BufferUpgradeStorage;
use crate::api::customization::{CustomizationImpl, DEFAULT_CUSTOMIZATION};
use crate::api::firmware_protection::FirmwareProtection;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::Channel;
use crate::env::{Env, UserPresence};
use crypto::rng256::Rng256;
use persistent_store::{BufferOptions, BufferStorage, Store};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

mod upgrade_storage;

pub struct TestEnv {
    rng: TestRng256,
    user_presence: TestUserPresence,
    store: Store<BufferStorage>,
    upgrade_storage: Option<BufferUpgradeStorage>,
    customization: CustomizationImpl,
}

pub struct TestRng256 {
    rng: StdRng,
}

impl Rng256 for TestRng256 {
    fn gen_uniform_u8x32(&mut self) -> [u8; 32] {
        let mut result = [Default::default(); 32];
        self.rng.fill(&mut result);
        result
    }
}

pub struct TestUserPresence {
    check: Box<dyn Fn(Channel) -> Result<(), Ctap2StatusCode>>,
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

impl TestEnv {
    pub fn new() -> Self {
        let rng = TestRng256 {
            rng: StdRng::seed_from_u64(0),
        };
        let user_presence = TestUserPresence {
            check: Box::new(|_| Ok(())),
        };
        let storage = new_storage();
        let store = Store::new(storage).ok().unwrap();
        let upgrade_storage = Some(BufferUpgradeStorage::new().unwrap());
        let customization = DEFAULT_CUSTOMIZATION.clone();
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

    pub fn customization_mut(&mut self) -> &mut CustomizationImpl {
        &mut self.customization
    }

    pub fn seed_rng_from_u64(&mut self, state: u64) {
        self.rng = TestRng256 {
            rng: StdRng::seed_from_u64(state),
        };
    }
}

impl TestUserPresence {
    pub fn set(&mut self, check: impl Fn(Channel) -> Result<(), Ctap2StatusCode> + 'static) {
        self.check = Box::new(check);
    }
}

impl UserPresence for TestUserPresence {
    fn check(&mut self, channel: Channel) -> Result<(), Ctap2StatusCode> {
        (self.check)(channel)
    }
}

impl FirmwareProtection for TestEnv {
    fn lock(&mut self) -> bool {
        true
    }
}

impl Env for TestEnv {
    type Rng = TestRng256;
    type UserPresence = TestUserPresence;
    type Storage = BufferStorage;
    type UpgradeStorage = BufferUpgradeStorage;
    type FirmwareProtection = Self;
    type Write = TestWrite;
    type Customization = CustomizationImpl;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        &mut self.user_presence
    }

    fn store(&mut self) -> &mut Store<Self::Storage> {
        &mut self.store
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
}
