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

pub use self::storage::{TockStorage, TockUpgradeStorage};
use clock::TockClock;
use core::cell::Cell;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicBool, Ordering};
use libtock_core::result::{CommandError, EALREADY};
use libtock_drivers::buttons::{self, ButtonState};
use libtock_drivers::console::Console;
use libtock_drivers::result::{FlexUnwrap, TockError};
use libtock_drivers::timer::Duration;
use libtock_drivers::{crp, led, rng, timer, usb_ctap_hid};
use opensk::api::attestation_store::AttestationStore;
use opensk::api::connection::{
    HidConnection, SendOrRecvError, SendOrRecvResult, SendOrRecvStatus, UsbEndpoint,
};
use opensk::api::customization::{CustomizationImpl, AAGUID_LENGTH, DEFAULT_CUSTOMIZATION};
use opensk::api::firmware_protection::FirmwareProtection;
use opensk::api::user_presence::{UserPresence, UserPresenceError, UserPresenceResult};
use opensk::api::{attestation_store, key_store};
use opensk::env::Env;
use persistent_store::{StorageResult, Store};
use rng256::Rng256;

mod clock;
mod storage;

pub const AAGUID: &[u8; AAGUID_LENGTH] =
    include_bytes!(concat!(env!("OUT_DIR"), "/opensk_aaguid.bin"));

const TOCK_CUSTOMIZATION: CustomizationImpl = CustomizationImpl {
    aaguid: AAGUID,
    ..DEFAULT_CUSTOMIZATION
};

/// RNG backed by the TockOS rng driver.
pub struct TockRng256 {}

impl Rng256 for TockRng256 {
    fn gen_uniform_u8x32(&mut self) -> [u8; 32] {
        let mut buf: [u8; 32] = [Default::default(); 32];
        rng::fill_buffer(&mut buf);
        buf
    }
}

pub struct TockHidConnection {
    endpoint: UsbEndpoint,
}

impl HidConnection for TockHidConnection {
    fn send_and_maybe_recv(&mut self, buf: &mut [u8; 64], timeout_ms: usize) -> SendOrRecvResult {
        match usb_ctap_hid::send_or_recv_with_timeout(
            buf,
            Duration::from_ms(timeout_ms as isize),
            self.endpoint as usize,
        ) {
            Ok(usb_ctap_hid::SendOrRecvStatus::Timeout) => Ok(SendOrRecvStatus::Timeout),
            Ok(usb_ctap_hid::SendOrRecvStatus::Sent) => Ok(SendOrRecvStatus::Sent),
            Ok(usb_ctap_hid::SendOrRecvStatus::Received(recv_endpoint)) => {
                UsbEndpoint::try_from(recv_endpoint).map(SendOrRecvStatus::Received)
            }
            _ => Err(SendOrRecvError),
        }
    }
}

pub struct TockEnv {
    rng: TockRng256,
    store: Store<TockStorage>,
    upgrade_storage: Option<TockUpgradeStorage>,
    main_connection: TockHidConnection,
    #[cfg(feature = "vendor_hid")]
    vendor_connection: TockHidConnection,
    blink_pattern: usize,
    clock: TockClock,
}

impl Default for TockEnv {
    /// Returns the unique instance of the Tock environment.
    ///
    /// # Panics
    ///
    /// - If called a second time.
    fn default() -> Self {
        // We rely on `take_storage` to ensure that this function is called only once.
        let storage = take_storage().unwrap();
        let store = Store::new(storage).ok().unwrap();
        let upgrade_storage = TockUpgradeStorage::new().ok();
        TockEnv {
            rng: TockRng256 {},
            store,
            upgrade_storage,
            main_connection: TockHidConnection {
                endpoint: UsbEndpoint::MainHid,
            },
            #[cfg(feature = "vendor_hid")]
            vendor_connection: TockHidConnection {
                endpoint: UsbEndpoint::VendorHid,
            },
            blink_pattern: 0,
            clock: TockClock::default(),
        }
    }
}

/// Returns the unique storage instance.
///
/// # Panics
///
/// - If called a second time.
pub fn take_storage() -> StorageResult<TockStorage> {
    // Make sure the storage was not already taken.
    static TAKEN: AtomicBool = AtomicBool::new(false);
    assert!(!TAKEN.fetch_or(true, Ordering::SeqCst));
    TockStorage::new()
}

impl UserPresence for TockEnv {
    fn check_init(&mut self) {
        self.blink_pattern = 0;
    }

    fn wait_with_timeout(&mut self, timeout_ms: usize) -> UserPresenceResult {
        if timeout_ms == 0 {
            return Err(UserPresenceError::Timeout);
        }
        blink_leds(self.blink_pattern);
        self.blink_pattern += 1;

        let button_touched = Cell::new(false);
        let mut buttons_callback = buttons::with_callback(|_button_num, state| {
            match state {
                ButtonState::Pressed => button_touched.set(true),
                ButtonState::Released => (),
            };
        });
        let mut buttons = buttons_callback.init().flex_unwrap();
        for mut button in &mut buttons {
            button.enable().flex_unwrap();
        }

        // Setup a keep-alive callback.
        let keepalive_expired = Cell::new(false);
        let mut keepalive_callback = timer::with_callback(|_, _| {
            keepalive_expired.set(true);
        });
        let mut keepalive = keepalive_callback.init().flex_unwrap();
        let keepalive_alarm = keepalive
            .set_alarm(Duration::from_ms(timeout_ms as isize))
            .flex_unwrap();

        // Wait for a button touch or an alarm.
        libtock_drivers::util::yieldk_for(|| button_touched.get() || keepalive_expired.get());

        // Cleanup alarm callback.
        match keepalive.stop_alarm(keepalive_alarm) {
            Ok(()) => (),
            Err(TockError::Command(CommandError {
                return_code: EALREADY,
                ..
            })) => assert!(keepalive_expired.get()),
            Err(_e) => {
                #[cfg(feature = "debug_ctap")]
                panic!("Unexpected error when stopping alarm: {:?}", _e);
                #[cfg(not(feature = "debug_ctap"))]
                panic!("Unexpected error when stopping alarm: <error is only visible with the debug_ctap feature>");
            }
        }

        for mut button in &mut buttons {
            button.disable().flex_unwrap();
        }

        if button_touched.get() {
            Ok(())
        } else if keepalive_expired.get() {
            Err(UserPresenceError::Timeout)
        } else {
            panic!("Unexpected exit condition");
        }
    }

    fn check_complete(&mut self) {
        switch_off_leds();
    }
}

impl FirmwareProtection for TockEnv {
    fn lock(&mut self) -> bool {
        matches!(
            crp::set_protection(crp::ProtectionLevel::FullyLocked),
            Ok(())
                | Err(TockError::Command(CommandError {
                    return_code: EALREADY,
                    ..
                }))
        )
    }
}

impl key_store::Helper for TockEnv {}

impl AttestationStore for TockEnv {
    fn get(
        &mut self,
        id: &attestation_store::Id,
    ) -> Result<Option<attestation_store::Attestation>, attestation_store::Error> {
        if !matches!(id, attestation_store::Id::Batch) {
            return Err(attestation_store::Error::NoSupport);
        }
        attestation_store::helper_get(self)
    }

    fn set(
        &mut self,
        id: &attestation_store::Id,
        attestation: Option<&attestation_store::Attestation>,
    ) -> Result<(), attestation_store::Error> {
        if !matches!(id, attestation_store::Id::Batch) {
            return Err(attestation_store::Error::NoSupport);
        }
        attestation_store::helper_set(self, attestation)
    }
}

impl Env for TockEnv {
    type Rng = TockRng256;
    type UserPresence = Self;
    type Storage = TockStorage;
    type KeyStore = Self;
    type AttestationStore = Self;
    type Clock = TockClock;
    type UpgradeStorage = TockUpgradeStorage;
    type FirmwareProtection = Self;
    type Write = Console;
    type Customization = CustomizationImpl;
    type HidConnection = TockHidConnection;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        self
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

    fn upgrade_storage(&mut self) -> Option<&mut Self::UpgradeStorage> {
        self.upgrade_storage.as_mut()
    }

    fn firmware_protection(&mut self) -> &mut Self::FirmwareProtection {
        self
    }

    fn write(&mut self) -> Self::Write {
        Console::new()
    }

    fn customization(&self) -> &Self::Customization {
        &TOCK_CUSTOMIZATION
    }

    fn main_hid_connection(&mut self) -> &mut Self::HidConnection {
        &mut self.main_connection
    }

    #[cfg(feature = "vendor_hid")]
    fn vendor_hid_connection(&mut self) -> &mut Self::HidConnection {
        &mut self.vendor_connection
    }
}

pub fn blink_leds(pattern_seed: usize) {
    for l in 0..led::count().flex_unwrap() {
        if (pattern_seed ^ l).count_ones() & 1 != 0 {
            led::get(l).flex_unwrap().on().flex_unwrap();
        } else {
            led::get(l).flex_unwrap().off().flex_unwrap();
        }
    }
}

pub fn wink_leds(pattern_seed: usize) {
    // This generates a "snake" pattern circling through the LEDs.
    // Fox example with 4 LEDs the sequence of lit LEDs will be the following.
    // 0 1 2 3
    // * *
    // * * *
    //   * *
    //   * * *
    //     * *
    // *   * *
    // *     *
    // * *   *
    // * *
    let count = led::count().flex_unwrap();
    let a = (pattern_seed / 2) % count;
    let b = ((pattern_seed + 1) / 2) % count;
    let c = ((pattern_seed + 3) / 2) % count;

    for l in 0..count {
        // On nRF52840-DK, logically swap LEDs 3 and 4 so that the order of LEDs form a circle.
        let k = match l {
            2 => 3,
            3 => 2,
            _ => l,
        };
        if k == a || k == b || k == c {
            led::get(l).flex_unwrap().on().flex_unwrap();
        } else {
            led::get(l).flex_unwrap().off().flex_unwrap();
        }
    }
}

pub fn switch_off_leds() {
    for l in 0..led::count().flex_unwrap() {
        led::get(l).flex_unwrap().off().flex_unwrap();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use opensk::api::customization::is_valid;

    #[test]
    fn test_invariants() {
        assert!(is_valid(&TOCK_CUSTOMIZATION));
    }
}
