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

pub use self::storage::{TockStorage, TockUpgradeStorage};
use crate::api::attestation_store::AttestationStore;
use crate::api::connection::{HidConnection, SendOrRecvError, SendOrRecvResult, SendOrRecvStatus};
use crate::api::customization::{CustomizationImpl, DEFAULT_CUSTOMIZATION};
use crate::api::firmware_protection::FirmwareProtection;
use crate::api::user_presence::{UserPresence, UserPresenceError, UserPresenceResult};
use crate::api::{attestation_store, key_store};
use crate::clock::{ClockInt, KEEPALIVE_DELAY_MS};
use crate::env::Env;
use core::cell::Cell;
use core::marker::PhantomData;
use embedded_time::duration::Milliseconds;
use embedded_time::fixed_point::FixedPoint;
use libtock_buttons::{ButtonListener, ButtonState, Buttons};
use libtock_console::{Console, ConsoleWriter};
use libtock_drivers::result::{FlexUnwrap, TockError};
use libtock_drivers::timer::Duration;
use libtock_drivers::usb_ctap_hid::{self, UsbCtapHid, UsbEndpoint};
use libtock_drivers::{crp, timer};
use libtock_leds::Leds;
use libtock_platform as platform;
use libtock_platform::{ErrorCode, Syscalls};
use persistent_store::{StorageResult, Store};
use platform::{share, DefaultConfig, Subscribe};
use rng256::TockRng256;

mod storage;

pub struct TockHidConnection<S: Syscalls> {
    endpoint: UsbEndpoint,
    s: PhantomData<S>,
}

impl<S: Syscalls> HidConnection for TockHidConnection<S> {
    fn send_and_maybe_recv(
        &mut self,
        buf: &mut [u8; 64],
        timeout: Milliseconds<ClockInt>,
    ) -> SendOrRecvResult {
        match UsbCtapHid::<S>::send_or_recv_with_timeout(
            buf,
            Duration::from_ms(timeout.integer() as isize),
            self.endpoint,
        ) {
            Ok(usb_ctap_hid::SendOrRecvStatus::Timeout) => Ok(SendOrRecvStatus::Timeout),
            Ok(usb_ctap_hid::SendOrRecvStatus::Sent) => Ok(SendOrRecvStatus::Sent),
            Ok(usb_ctap_hid::SendOrRecvStatus::Received(recv_endpoint)) => {
                Ok(SendOrRecvStatus::Received(recv_endpoint))
            }
            _ => Err(SendOrRecvError),
        }
    }
}

pub struct TockEnv<
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config = DefaultConfig,
> {
    rng: TockRng256<S>,
    store: Store<TockStorage<S, C>>,
    upgrade_storage: Option<TockUpgradeStorage<S, C>>,
    main_connection: TockHidConnection<S>,
    #[cfg(feature = "vendor_hid")]
    vendor_connection: TockHidConnection<S>,
    blink_pattern: usize,
}

impl<S: Syscalls> TockEnv<S> {
    /// Returns the unique instance of the Tock environment.
    ///
    /// # Panics
    ///
    /// - If called a second time.
    pub fn new() -> Self {
        // We rely on `take_storage` to ensure that this function is called only once.
        let storage = take_storage().unwrap();
        let store = match Store::new(storage) {
            Ok(s) => s,
            Err((e, _)) => panic!("StoreError: {:?}", e),
        };
        let upgrade_storage = TockUpgradeStorage::new().ok();
        TockEnv {
            rng: TockRng256::new(),
            store,
            upgrade_storage,
            main_connection: TockHidConnection {
                endpoint: UsbEndpoint::MainHid,
                s: PhantomData,
            },
            #[cfg(feature = "vendor_hid")]
            vendor_connection: TockHidConnection {
                endpoint: UsbEndpoint::VendorHid,
                s: PhantomData,
            },
            blink_pattern: 0,
        }
    }
}

impl<S: Syscalls> Default for TockEnv<S> {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the unique storage instance.
///
/// # Panics
///
/// - If called a second time.
pub fn take_storage<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config>(
) -> StorageResult<TockStorage<S, C>> {
    // Make sure the storage was not already taken.
    #[cfg(target_has_atomic = "8")]
    {
        use core::sync::atomic::{AtomicBool, Ordering};
        static TAKEN: AtomicBool = AtomicBool::new(false);
        assert!(!TAKEN.fetch_or(true, Ordering::SeqCst));
    }
    #[cfg(not(target_has_atomic = "8"))]
    {
        static mut TAKEN: bool = false;
        // Safety
        //
        // We can not use an AtomicBool on platforms that do not support atomics,
        // such as the whole `riscv32i[mc]` family like OpenTitan.
        // Thus, we need to use a mutable static variable which are unsafe
        // cause they could cause a data race when two threads access it
        // at the same time.
        //
        // However, as we are running an application on TockOS and because
        // of its [architecture](https://www.tockos.org/documentation/design)
        // we are running in a single-threaded event loop which means the
        // aforementioned data race is impossible. Thus, in this case, the
        // usage of a static mut is safe.
        unsafe {
            assert!(!TAKEN);
            TAKEN = true;
        }
    }
    TockStorage::new()
}

impl<S, C> UserPresence for TockEnv<S, C>
where
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
{
    fn check_init(&mut self) {
        self.blink_pattern = 0;
    }
    fn wait_with_timeout(&mut self, timeout: Milliseconds<ClockInt>) -> UserPresenceResult {
        if timeout.integer() == 0 {
            return Err(UserPresenceError::Timeout);
        }
        blink_leds::<S>(self.blink_pattern);
        self.blink_pattern += 1;

        // enable interrupts for all buttons
        let num_buttons = Buttons::<S>::count()?;
        (0..num_buttons)
            .into_iter()
            .try_for_each(|n| Buttons::<S>::enable_interrupts(n))?;

        let button_touched = Cell::new(false);
        let button_listener = ButtonListener(|_button_num, state| {
            match state {
                ButtonState::Pressed => button_touched.set(true),
                ButtonState::Released => (),
            };
        });

        // Setup a keep-alive callback but don't enable it yet
        let keepalive_expired = Cell::new(false);
        let mut keepalive_callback =
            timer::with_callback::<S, C, _>(|_| keepalive_expired.set(true));
        share::scope::<
            (
                Subscribe<_, { libtock_buttons::DRIVER_NUM }, 0>,
                Subscribe<
                    S,
                    { libtock_drivers::timer::DRIVER_NUM },
                    { libtock_drivers::timer::subscribe::CALLBACK },
                >,
            ),
            _,
            _,
        >(|handle| {
            let (sub_button, sub_timer) = handle.split();
            Buttons::<S>::register_listener(&button_listener, sub_button)?;

            let mut keepalive = keepalive_callback.init().flex_unwrap();
            keepalive_callback.enable(sub_timer)?;
            keepalive
                .set_alarm(timer::Duration::from_ms(timeout.integer() as isize))
                .flex_unwrap();

            // Wait for a button touch or an alarm.
            libtock_drivers::util::Util::<S>::yieldk_for(|| {
                button_touched.get() || keepalive_expired.get()
            });

            Buttons::<S>::unregister_listener();

            // disable event interrupts for all buttons
            (0..num_buttons)
                .into_iter()
                .try_for_each(|n| Buttons::<S>::disable_interrupts(n))?;

            // Cleanup alarm callback.
            match keepalive.stop_alarm() {
                Ok(()) => (),
                Err(TockError::Command(ErrorCode::Already)) => assert!(keepalive_expired.get()),
                Err(_e) => {
                    #[cfg(feature = "debug_ctap")]
                    panic!("Unexpected error when stopping alarm: {:?}", _e);
                    #[cfg(not(feature = "debug_ctap"))]
                    panic!("Unexpected error when stopping alarm: <error is only visible with the debug_ctap feature>");
                }
            }

            Ok::<(), UserPresenceError>(())
        })?;

        if button_touched.get() {
            Ok(())
        } else if keepalive_expired.get() {
            Err(UserPresenceError::Timeout)
        } else {
            panic!("Unexpected exit condition");
        }
    }

    fn check_complete(&mut self) {
        switch_off_leds::<S>();
    }
}

impl<S, C> FirmwareProtection for TockEnv<S, C>
where
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
{
    fn lock(&mut self) -> bool {
        matches!(
            crp::Crp::<S>::set_protection(crp::ProtectionLevel::FullyLocked),
            Ok(()) | Err(TockError::Command(ErrorCode::Already))
        )
    }
}

impl<S, C> key_store::Helper for TockEnv<S, C>
where
    S: Syscalls,
    C: platform::allow_ro::Config + platform::subscribe::Config,
{
}

impl<S, C> AttestationStore for TockEnv<S, C>
where
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
{
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

impl<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config> Env
    for TockEnv<S, C>
{
    type Rng = TockRng256<S>;
    type UserPresence = Self;
    type Storage = TockStorage<S, C>;
    type KeyStore = Self;
    type AttestationStore = Self;
    type UpgradeStorage = TockUpgradeStorage<S, C>;
    type FirmwareProtection = Self;
    type Write = ConsoleWriter<S>;
    type Customization = CustomizationImpl;
    type HidConnection = TockHidConnection<S>;

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

    fn upgrade_storage(&mut self) -> Option<&mut Self::UpgradeStorage> {
        self.upgrade_storage.as_mut()
    }

    fn firmware_protection(&mut self) -> &mut Self::FirmwareProtection {
        self
    }

    fn write(&mut self) -> Self::Write {
        Console::<S>::writer()
    }

    fn customization(&self) -> &Self::Customization {
        &DEFAULT_CUSTOMIZATION
    }

    fn main_hid_connection(&mut self) -> &mut Self::HidConnection {
        &mut self.main_connection
    }

    #[cfg(feature = "vendor_hid")]
    fn vendor_hid_connection(&mut self) -> &mut Self::HidConnection {
        &mut self.vendor_connection
    }
}

pub fn blink_leds<S: Syscalls>(pattern_seed: usize) {
    for l in 0..Leds::<S>::count().unwrap() {
        if (pattern_seed ^ l as usize).count_ones() & 1 != 0 {
            Leds::<S>::on(l).unwrap();
        } else {
            Leds::<S>::off(l).unwrap();
        }
    }
}

pub fn wink_leds<S: Syscalls>(pattern_seed: usize) {
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
    let count = Leds::<S>::count().unwrap() as usize;
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
            Leds::<S>::on(l as u32).unwrap();
        } else {
            Leds::<S>::off(l as u32).unwrap();
        }
    }
}

pub fn switch_off_leds<S: Syscalls>() {
    let count = Leds::<S>::count().unwrap();
    for l in 0..count {
        Leds::<S>::off(l).unwrap();
    }
}

pub const KEEPALIVE_DELAY_TOCK: Duration<isize> = Duration::from_ms(KEEPALIVE_DELAY_MS as isize);
