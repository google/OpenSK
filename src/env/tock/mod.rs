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

use alloc::vec::Vec;
use clock::TockClock;
use core::cell::Cell;
use core::convert::TryFrom;
use core::marker::PhantomData;
#[cfg(all(target_has_atomic = "8", not(feature = "std")))]
use core::sync::atomic::{AtomicBool, Ordering};
use libtock_buttons::{ButtonListener, ButtonState, Buttons};
use libtock_console::{Console, ConsoleWriter};
use libtock_drivers::result::{FlexUnwrap, TockError};
use libtock_drivers::timer::Duration;
use libtock_drivers::usb_ctap_hid::UsbCtapHid;
use libtock_drivers::{rng, timer, usb_ctap_hid};
use libtock_leds::Leds;
use libtock_platform as platform;
use libtock_platform::{ErrorCode, Syscalls};
use opensk::api::attestation_store::AttestationStore;
use opensk::api::connection::{
    HidConnection, SendOrRecvError, SendOrRecvResult, SendOrRecvStatus, UsbEndpoint,
};
use opensk::api::crypto::software_crypto::SoftwareCrypto;
use opensk::api::customization::{CustomizationImpl, AAGUID_LENGTH, DEFAULT_CUSTOMIZATION};
use opensk::api::rng::Rng;
use opensk::api::user_presence::{UserPresence, UserPresenceError, UserPresenceResult};
use opensk::api::{attestation_store, key_store};
use opensk::ctap::Channel;
use opensk::env::Env;
#[cfg(feature = "std")]
use persistent_store::BufferOptions;
use persistent_store::{StorageResult, Store};
use platform::{share, DefaultConfig, Subscribe};
use rand_core::{impls, CryptoRng, Error, RngCore};

#[cfg(feature = "std")]
mod buffer_upgrade_storage;
mod clock;
mod commands;
#[cfg(feature = "std")]
mod phantom_buffer_storage;
#[cfg(not(feature = "std"))]
mod storage;
mod storage_helper;
mod upgrade_helper;

#[cfg(not(feature = "std"))]
pub type Storage<S, C> = storage::TockStorage<S, C>;
#[cfg(feature = "std")]
pub type Storage<S, C> = phantom_buffer_storage::PhantomBufferStorage<S, C>;

#[cfg(not(feature = "std"))]
type UpgradeStorage<S, C> = storage::TockUpgradeStorage<S, C>;
#[cfg(feature = "std")]
type UpgradeStorage<S, C> = buffer_upgrade_storage::BufferUpgradeStorage<S, C>;

pub const AAGUID: &[u8; AAGUID_LENGTH] =
    include_bytes!(concat!(env!("OUT_DIR"), "/opensk_aaguid.bin"));

const TOCK_CUSTOMIZATION: CustomizationImpl = CustomizationImpl {
    aaguid: AAGUID,
    ..DEFAULT_CUSTOMIZATION
};

/// RNG backed by the TockOS rng driver.
pub struct TockRng<S: Syscalls> {
    _syscalls: PhantomData<S>,
}

impl<S: Syscalls> Default for TockRng<S> {
    fn default() -> Self {
        Self {
            _syscalls: PhantomData,
        }
    }
}

impl<S: Syscalls> CryptoRng for TockRng<S> {}

impl<S: Syscalls> RngCore for TockRng<S> {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rng::Rng::<S>::fill_buffer(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<S: Syscalls> Rng for TockRng<S> {}

pub struct TockHidConnection<S: Syscalls> {
    endpoint: UsbEndpoint,
    s: PhantomData<S>,
}

impl<S: Syscalls> HidConnection for TockHidConnection<S> {
    fn send_and_maybe_recv(&mut self, buf: &mut [u8; 64], timeout_ms: usize) -> SendOrRecvResult {
        match UsbCtapHid::<S>::send_or_recv_with_timeout(
            buf,
            Duration::from_ms(timeout_ms as isize),
            self.endpoint as u32,
        ) {
            Ok(usb_ctap_hid::SendOrRecvStatus::Timeout) => Ok(SendOrRecvStatus::Timeout),
            Ok(usb_ctap_hid::SendOrRecvStatus::Sent) => Ok(SendOrRecvStatus::Sent),
            Ok(usb_ctap_hid::SendOrRecvStatus::Received(recv_endpoint)) => {
                UsbEndpoint::try_from(recv_endpoint as usize).map(SendOrRecvStatus::Received)
            }
            _ => Err(SendOrRecvError),
        }
    }
}

pub struct TockEnv<
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config = DefaultConfig,
> {
    rng: TockRng<S>,
    store: Store<Storage<S, C>>,
    upgrade_storage: Option<UpgradeStorage<S, C>>,
    main_connection: TockHidConnection<S>,
    #[cfg(feature = "vendor_hid")]
    vendor_connection: TockHidConnection<S>,
    blink_pattern: usize,
    clock: TockClock<S>,
    c: PhantomData<C>,
}

impl<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config> Default
    for TockEnv<S, C>
{
    /// Returns the unique instance of the Tock environment.
    ///
    /// # Panics
    ///
    /// - If called a second time.
    fn default() -> Self {
        let rng = TockRng::default();
        // We rely on `take_storage` to ensure that this function is called only once.
        let storage = take_storage::<S, C>().unwrap();
        let store = Store::new(storage).ok().unwrap();
        let upgrade_storage = UpgradeStorage::new().ok();
        TockEnv {
            rng,
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
            clock: TockClock::default(),
            c: PhantomData,
        }
    }
}

impl<S, C> TockEnv<S, C>
where
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
{
    /// Returns the upgrade storage instance.
    ///
    /// Upgrade storage is optional, so implementations may return `None`. However, implementations
    /// should either always return `None` or always return `Some`.
    pub fn upgrade_storage(&mut self) -> Option<&mut UpgradeStorage<S, C>> {
        self.upgrade_storage.as_mut()
    }

    pub fn disable_upgrade_storage(&mut self) {
        self.upgrade_storage = None;
    }

    pub fn lock_firmware_protection(&mut self) -> bool {
        false
    }
}

#[cfg(feature = "std")]
pub fn take_storage<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config>(
) -> StorageResult<Storage<S, C>> {
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
    Ok(phantom_buffer_storage::PhantomBufferStorage::new(
        store, options,
    ))
}

/// Returns the unique storage instance.
///
/// # Panics
///
/// - If called a second time.
#[cfg(not(feature = "std"))]
pub fn take_storage<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config>(
) -> StorageResult<Storage<S, C>> {
    // Make sure the storage was not already taken.
    #[cfg(target_has_atomic = "8")]
    {
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
    Storage::new()
}

impl<S, C> UserPresence for TockEnv<S, C>
where
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
{
    fn check_init(&mut self) {
        self.blink_pattern = 0;
    }

    fn wait_with_timeout(&mut self, timeout_ms: usize) -> UserPresenceResult {
        if timeout_ms == 0 {
            return Err(UserPresenceError::Timeout);
        }
        blink_leds::<S>(self.blink_pattern);
        self.blink_pattern += 1;

        // enable interrupts for all buttons
        let num_buttons = Buttons::<S>::count().map_err(|_| UserPresenceError::Fail)?;
        (0..num_buttons)
            .try_for_each(|n| Buttons::<S>::enable_interrupts(n))
            .map_err(|_| UserPresenceError::Fail)?;

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
            Buttons::<S>::register_listener(&button_listener, sub_button)
                .map_err(|_| UserPresenceError::Fail)?;

            let mut keepalive = keepalive_callback.init().flex_unwrap();
            keepalive_callback
                .enable(sub_timer)
                .map_err(|_| UserPresenceError::Fail)?;
            keepalive
                .set_alarm(timer::Duration::from_ms(timeout_ms as isize))
                .flex_unwrap();

            // Wait for a button touch or an alarm.
            libtock_drivers::util::Util::<S>::yieldk_for(|| {
                button_touched.get() || keepalive_expired.get()
            });

            Buttons::<S>::unregister_listener();

            // disable event interrupts for all buttons
            (0..num_buttons)
                .try_for_each(|n| Buttons::<S>::disable_interrupts(n))
                .map_err(|_| UserPresenceError::Fail)?;

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
    type Rng = TockRng<S>;
    type UserPresence = Self;
    type Storage = Storage<S, C>;
    type KeyStore = Self;
    type AttestationStore = Self;
    type Clock = TockClock<S>;
    type Write = ConsoleWriter<S>;
    type Customization = CustomizationImpl;
    type HidConnection = TockHidConnection<S>;
    type Crypto = SoftwareCrypto;

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

    fn write(&mut self) -> Self::Write {
        Console::<S>::writer()
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

    fn process_vendor_command(&mut self, bytes: &[u8], channel: Channel) -> Option<Vec<u8>> {
        commands::process_vendor_command(self, bytes, channel)
    }

    fn firmware_version(&self) -> Option<u64> {
        self.upgrade_storage
            .as_ref()
            .map(|u| u.running_firmware_version())
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

#[cfg(test)]
mod test {
    use super::*;
    use opensk::api::customization::is_valid;

    #[test]
    fn test_invariants() {
        assert!(is_valid(&TOCK_CUSTOMIZATION));
    }
}
