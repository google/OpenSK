use self::storage::{SyscallStorage, SyscallUpgradeStorage};
use crate::ctap::hid::{ChannelID, CtapHid, CtapHidCommand, KeepaliveStatus, ProcessedPacket};
use crate::ctap::status_code::Ctap2StatusCode;
use crate::env::{Env, UserPresence};
use core::cell::Cell;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};
use crypto::rng256::TockRng256;
use libtock_core::result::{CommandError, EALREADY};
use libtock_drivers::buttons::{self, ButtonState};
#[cfg(feature = "debug_ctap")]
use libtock_drivers::console::Console;
use libtock_drivers::result::{FlexUnwrap, TockError};
use libtock_drivers::timer::Duration;
use libtock_drivers::{led, timer, usb_ctap_hid};
use persistent_store::{StorageResult, Store};

mod storage;

pub struct TockEnv {
    rng: TockRng256,
    store: Store<SyscallStorage>,
    upgrade_storage: Option<SyscallUpgradeStorage>,
}

impl TockEnv {
    /// Returns the unique instance of the Tock environment.
    ///
    /// # Panics
    ///
    /// - If called a second time.
    pub fn new() -> Self {
        // Make sure the environment was not already taken.
        static TAKEN: AtomicBool = AtomicBool::new(false);
        assert!(!TAKEN.fetch_or(true, Ordering::SeqCst));
        let storage = unsafe { steal_storage() }.unwrap();
        let store = Store::new(storage).ok().unwrap();
        let upgrade_storage = SyscallUpgradeStorage::new().ok();
        TockEnv {
            rng: TockRng256 {},
            store,
            upgrade_storage,
        }
    }
}

/// Creates a new storage instance.
///
/// # Safety
///
/// It is probably technically memory-safe to have multiple storage instances at the same time, but
/// for extra precaution we mark the function as unsafe. To ensure correct usage, this function
/// should only be called if the previous storage instance was dropped.
// This function is exposed to example binaries testing the hardware. This could probably be cleaned
// up by having the persistent store return its storage.
pub unsafe fn steal_storage() -> StorageResult<SyscallStorage> {
    SyscallStorage::new()
}

impl UserPresence for TockEnv {
    fn check(&self, cid: ChannelID) -> Result<(), Ctap2StatusCode> {
        check_user_presence(cid)
    }
}

impl Env for TockEnv {
    type Rng = TockRng256;
    type UserPresence = Self;
    type Storage = SyscallStorage;
    type UpgradeStorage = SyscallUpgradeStorage;

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
}

// Returns whether the keepalive was sent, or false if cancelled.
fn send_keepalive_up_needed(
    cid: ChannelID,
    timeout: Duration<isize>,
) -> Result<(), Ctap2StatusCode> {
    let keepalive_msg = CtapHid::keepalive(cid, KeepaliveStatus::UpNeeded);
    for mut pkt in keepalive_msg {
        let status = usb_ctap_hid::send_or_recv_with_timeout(&mut pkt, timeout);
        match status {
            None => {
                #[cfg(feature = "debug_ctap")]
                writeln!(Console::new(), "Sending a KEEPALIVE packet timed out").unwrap();
                // TODO: abort user presence test?
            }
            Some(usb_ctap_hid::SendOrRecvStatus::Error) => panic!("Error sending KEEPALIVE packet"),
            Some(usb_ctap_hid::SendOrRecvStatus::Sent) => {
                #[cfg(feature = "debug_ctap")]
                writeln!(Console::new(), "Sent KEEPALIVE packet").unwrap();
            }
            Some(usb_ctap_hid::SendOrRecvStatus::Received) => {
                // We only parse one packet, because we only care about CANCEL.
                let (received_cid, processed_packet) = CtapHid::process_single_packet(&pkt);
                if received_cid != &cid {
                    #[cfg(feature = "debug_ctap")]
                    writeln!(
                        Console::new(),
                        "Received a packet on channel ID {:?} while sending a KEEPALIVE packet",
                        received_cid,
                    )
                    .unwrap();
                    return Ok(());
                }
                match processed_packet {
                    ProcessedPacket::InitPacket { cmd, .. } => {
                        if cmd == CtapHidCommand::Cancel as u8 {
                            // We ignore the payload, we can't answer with an error code anyway.
                            #[cfg(feature = "debug_ctap")]
                            writeln!(Console::new(), "User presence check cancelled").unwrap();
                            return Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL);
                        } else {
                            #[cfg(feature = "debug_ctap")]
                            writeln!(
                                Console::new(),
                                "Discarded packet with command {} received while sending a KEEPALIVE packet",
                                cmd,
                            )
                            .unwrap();
                        }
                    }
                    ProcessedPacket::ContinuationPacket { .. } => {
                        #[cfg(feature = "debug_ctap")]
                        writeln!(
                            Console::new(),
                            "Discarded continuation packet received while sending a KEEPALIVE packet",
                        )
                        .unwrap();
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
pub const KEEPALIVE_DELAY: Duration<isize> = Duration::from_ms(KEEPALIVE_DELAY_MS);

fn check_user_presence(cid: ChannelID) -> Result<(), Ctap2StatusCode> {
    // The timeout is N times the keepalive delay.
    const TIMEOUT_ITERATIONS: usize =
        crate::ctap::TOUCH_TIMEOUT_MS as usize / KEEPALIVE_DELAY_MS as usize;

    // First, send a keep-alive packet to notify that the keep-alive status has changed.
    send_keepalive_up_needed(cid, KEEPALIVE_DELAY)?;

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
        let keepalive_alarm = keepalive.set_alarm(KEEPALIVE_DELAY).flex_unwrap();

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
            keepalive_response = send_keepalive_up_needed(cid, KEEPALIVE_DELAY);
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
