pub use self::storage::{TockStorage, TockUpgradeStorage};
use crate::api::firmware_protection::FirmwareProtection;
use crate::ctap::hid::{ChannelID, CtapHid, CtapHidCommand, KeepaliveStatus, ProcessedPacket};
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::Channel;
use crate::env::{Env, UserPresence};
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, Ordering};
use crypto::rng256::TockRng256;
use libtock_core::result::{CommandError, EALREADY};
use libtock_drivers::buttons::{self, ButtonState};
use libtock_drivers::console::Console;
use libtock_drivers::result::{FlexUnwrap, TockError};
use libtock_drivers::timer::Duration;
use libtock_drivers::{crp, led, timer, usb_ctap_hid};
use persistent_store::{StorageResult, Store};

mod storage;

pub struct TockEnv {
    rng: TockRng256,
    store: Store<TockStorage>,
    upgrade_storage: Option<TockUpgradeStorage>,
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
    fn check(&mut self, channel: Channel) -> Result<(), Ctap2StatusCode> {
        match channel {
            Channel::MainHid(cid) => check_user_presence(self, cid),
            #[cfg(feature = "vendor_hid")]
            Channel::VendorHid(cid) => check_user_presence(self, cid),
        }
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
}

// Returns whether the keepalive was sent, or false if cancelled.
fn send_keepalive_up_needed(
    env: &mut TockEnv,
    cid: ChannelID,
    timeout: Duration<isize>,
) -> Result<(), Ctap2StatusCode> {
    let keepalive_msg = CtapHid::keepalive(cid, KeepaliveStatus::UpNeeded);
    for mut pkt in keepalive_msg {
        let status = usb_ctap_hid::send_or_recv_with_timeout(&mut pkt, timeout);
        match status {
            None => {
                debug_ctap!(env, "Sending a KEEPALIVE packet timed out");
                // TODO: abort user presence test?
            }
            Some(usb_ctap_hid::SendOrRecvStatus::Error) => panic!("Error sending KEEPALIVE packet"),
            Some(usb_ctap_hid::SendOrRecvStatus::Sent) => {
                debug_ctap!(env, "Sent KEEPALIVE packet");
            }
            Some(usb_ctap_hid::SendOrRecvStatus::Received) => {
                // We only parse one packet, because we only care about CANCEL.
                let (received_cid, processed_packet) = CtapHid::process_single_packet(&pkt);
                if received_cid != &cid {
                    debug_ctap!(
                        env,
                        "Received a packet on channel ID {:?} while sending a KEEPALIVE packet",
                        received_cid,
                    );
                    return Ok(());
                }
                match processed_packet {
                    ProcessedPacket::InitPacket { cmd, .. } => {
                        if cmd == CtapHidCommand::Cancel as u8 {
                            // We ignore the payload, we can't answer with an error code anyway.
                            debug_ctap!(env, "User presence check cancelled");
                            return Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL);
                        } else {
                            debug_ctap!(
                                env,
                                "Discarded packet with command {} received while sending a KEEPALIVE packet",
                                cmd,
                            );
                        }
                    }
                    ProcessedPacket::ContinuationPacket { .. } => {
                        debug_ctap!(
                            env,
                            "Discarded continuation packet received while sending a KEEPALIVE packet",
                        );
                    }
                }
            }
        }
    }
    Ok(())
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

const KEEPALIVE_DELAY_MS: isize = 100;
pub const KEEPALIVE_DELAY_TOCK: Duration<isize> = Duration::from_ms(KEEPALIVE_DELAY_MS);

fn check_user_presence(env: &mut TockEnv, cid: ChannelID) -> Result<(), Ctap2StatusCode> {
    // The timeout is N times the keepalive delay.
    const TIMEOUT_ITERATIONS: usize =
        crate::ctap::TOUCH_TIMEOUT_MS as usize / KEEPALIVE_DELAY_MS as usize;

    // First, send a keep-alive packet to notify that the keep-alive status has changed.
    send_keepalive_up_needed(env, cid, KEEPALIVE_DELAY_TOCK)?;

    // Listen to the button presses.
    let button_touched = Cell::new(false);
    let mut buttons_callback = buttons::with_callback(|_button_num, state| {
        match state {
            ButtonState::Pressed => button_touched.set(true),
            ButtonState::Released => (),
        };
    });
    let mut buttons = buttons_callback.init().flex_unwrap();
    // At the moment, all buttons are accepted. You can customize your setup here.
    for mut button in &mut buttons {
        button.enable().flex_unwrap();
    }

    let mut keepalive_response = Ok(());
    for i in 0..TIMEOUT_ITERATIONS {
        blink_leds(i);

        // Setup a keep-alive callback.
        let keepalive_expired = Cell::new(false);
        let mut keepalive_callback = timer::with_callback(|_, _| {
            keepalive_expired.set(true);
        });
        let mut keepalive = keepalive_callback.init().flex_unwrap();
        let keepalive_alarm = keepalive.set_alarm(KEEPALIVE_DELAY_TOCK).flex_unwrap();

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

        // TODO: this may take arbitrary time. The keepalive_delay should be adjusted accordingly,
        // so that LEDs blink with a consistent pattern.
        if keepalive_expired.get() {
            // Do not return immediately, because we must clean up still.
            keepalive_response = send_keepalive_up_needed(env, cid, KEEPALIVE_DELAY_TOCK);
        }

        if button_touched.get() || keepalive_response.is_err() {
            break;
        }
    }

    switch_off_leds();

    // Cleanup button callbacks.
    for mut button in &mut buttons {
        button.disable().flex_unwrap();
    }

    // Returns whether the user was present.
    if keepalive_response.is_err() {
        keepalive_response
    } else if button_touched.get() {
        Ok(())
    } else {
        Err(Ctap2StatusCode::CTAP2_ERR_USER_ACTION_TIMEOUT)
    }
}
