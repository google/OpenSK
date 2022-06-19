pub use self::storage::{TockStorage, TockUpgradeStorage};
use crate::api::customization::{CustomizationImpl, DEFAULT_CUSTOMIZATION};
use crate::api::firmware_protection::FirmwareProtection;
use crate::clock::{CtapDuration, KEEPALIVE_DELAY_MS};
use crate::ctap::{Channel, Transport};
use crate::env::{
    CtapHidChannel, Env, SendOrRecvError, SendOrRecvResult, SendOrRecvStatus, UserPresence,
    UserPresenceResult, UserPresenceStatus,
};
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, Ordering};
use embedded_time::fixed_point::FixedPoint;
use libtock_core::result::{CommandError, EALREADY};
use libtock_drivers::buttons::{self, ButtonState};
use libtock_drivers::console::Console;
use libtock_drivers::result::{FlexUnwrap, TockError};
use libtock_drivers::timer::Duration;
use libtock_drivers::{crp, led, timer, usb_ctap_hid};
use persistent_store::{StorageResult, Store};
use rng256::TockRng256;

mod storage;

pub struct TockCtapHidChannel {
    transport: Transport,
}

impl CtapHidChannel for TockCtapHidChannel {
    fn send_or_recv_with_timeout(
        &mut self,
        buf: &mut [u8; 64],
        timeout: CtapDuration,
    ) -> SendOrRecvResult {
        let endpoint = match self.transport {
            Transport::MainHid => usb_ctap_hid::UsbEndpoint::MainHid,
            #[cfg(feature = "vendor_hid")]
            Transport::VendorHid => usb_ctap_hid::UsbEndpoint::VendorHid,
        };
        match usb_ctap_hid::send_or_recv_with_timeout(
            buf,
            timer::Duration::from_ms(timeout.integer() as isize),
            endpoint,
        ) {
            Ok(usb_ctap_hid::SendOrRecvStatus::Timeout) => Ok(SendOrRecvStatus::Timeout),
            Ok(usb_ctap_hid::SendOrRecvStatus::Sent) => Ok(SendOrRecvStatus::Sent),
            Ok(usb_ctap_hid::SendOrRecvStatus::Received(recv_endpoint))
                if endpoint == recv_endpoint =>
            {
                Ok(SendOrRecvStatus::Received)
            }
            _ => Err(SendOrRecvError),
        }
    }
}

pub struct TockEnv {
    rng: TockRng256,
    store: Store<TockStorage>,
    upgrade_storage: Option<TockUpgradeStorage>,
    main_channel: TockCtapHidChannel,
    #[cfg(feature = "vendor_hid")]
    vendor_channel: TockCtapHidChannel,
    blink_pattern: usize,
}

impl TockEnv {
    /// Returns the unique instance of the Tock environment.
    ///
    /// # Panics
    ///
    /// - If called a second time.
    pub fn new() -> Self {
        // We rely on `take_storage` to ensure that this function is called only once.
        let storage = take_storage().unwrap();
        let store = Store::new(storage).ok().unwrap();
        let upgrade_storage = TockUpgradeStorage::new().ok();
        TockEnv {
            rng: TockRng256 {},
            store,
            upgrade_storage,
            main_channel: TockCtapHidChannel {
                transport: Transport::MainHid,
            },
            #[cfg(feature = "vendor_hid")]
            vendor_channel: TockCtapHidChannel {
                transport: Transport::VendorHid,
            },
            blink_pattern: 0,
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
    fn user_presence_check_init(&mut self, _channel: Channel) {
        self.blink_pattern = 0;
    }
    fn wait_for_user_presence_with_timeout(
        &mut self,
        _channel: Channel,
        timeout: CtapDuration,
    ) -> UserPresenceResult {
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
            .set_alarm(timer::Duration::from_ms(timeout.integer() as isize))
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
            Ok(UserPresenceStatus::Confirmed)
        } else if keepalive_expired.get() {
            Ok(UserPresenceStatus::Timeout)
        } else {
            panic!("Unexpected exit condition");
        }
    }

    fn user_presence_check_complete(&mut self, _result: &UserPresenceResult) {
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

impl Env for TockEnv {
    type Rng = TockRng256;
    type UserPresence = Self;
    type Storage = TockStorage;
    type UpgradeStorage = TockUpgradeStorage;
    type FirmwareProtection = Self;
    type Write = Console;
    type Customization = CustomizationImpl;
    type CtapHidChannel = TockCtapHidChannel;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        self
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
        Console::new()
    }

    fn customization(&self) -> &Self::Customization {
        &DEFAULT_CUSTOMIZATION
    }

    fn main_hid_channel(&mut self) -> &mut Self::CtapHidChannel {
        &mut self.main_channel
    }

    #[cfg(feature = "vendor_hid")]
    fn vendor_hid_channel(&mut self) -> &mut Self::CtapHidChannel {
        &mut self.vendor_channel
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

pub const KEEPALIVE_DELAY_TOCK: Duration<isize> = Duration::from_ms(KEEPALIVE_DELAY_MS as isize);
