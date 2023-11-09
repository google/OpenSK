use libtock_alarm::{Alarm, Milliseconds};
use libtock_leds::Leds;
use libtock_low_level_debug::{AlertCode, LowLevelDebug};
use libtock_platform as platform;
use libtock_platform::Syscalls;
use platform::DefaultConfig;

pub struct Util<S: Syscalls, C: platform::subscribe::Config = DefaultConfig>(S, C);

impl<S: Syscalls, C: platform::subscribe::Config> Util<S, C> {
    /// Signal a panic using the LowLevelDebug capsule (if available).
    pub fn signal_panic() {
        LowLevelDebug::<S>::print_alert_code(AlertCode::Panic);
    }

    /// Signal an out-of-memory error using the LowLevelDebug capsule (if available).
    pub fn signal_oom() {
        LowLevelDebug::<S>::print_alert_code(AlertCode::WrongLocation);
    }

    #[allow(dead_code)]
    pub fn flash_all_leds() -> ! {
        // Flash all LEDs (if available). All errors from syscalls are ignored: we are already inside a
        // panic handler so there is nothing much to do if simple drivers (timer, LEDs) don't work.
        loop {
            if let Ok(led_count) = Leds::<S>::count() {
                for led in 0..led_count {
                    let _ = Leds::<S>::on(led);
                }
            }
            let _ = Alarm::<S, C>::sleep_for(Milliseconds(100));
            if let Ok(led_count) = Leds::<S>::count() {
                for led in 0..led_count {
                    let _ = Leds::<S>::off(led);
                }
            }
            let _ = Alarm::<S, C>::sleep_for(Milliseconds(100));
        }
    }

    #[allow(dead_code)]
    pub fn cycle_leds() -> ! {
        // Cycle though all LEDs (if available). All errors from syscalls are ignored: we are already
        // inside an error handler so there is nothing much to do if simple drivers (timer, LEDs) don't
        // work.
        loop {
            if let Ok(leds) = Leds::<S>::count() {
                for led in 0..leds {
                    let _ = Leds::<S>::on(led);
                    let _ = Alarm::<S, C>::sleep_for(Milliseconds(100));
                    let _ = Leds::<S>::off(led);
                }
            }
        }
    }
}
