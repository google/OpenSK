use libtock_drivers::led;
use libtock_drivers::timer::{self, Duration};

// Signal a panic using the LowLevelDebug capsule (if available).
pub fn signal_panic() {
    let _ = libtock_core::syscalls::command1_insecure(8, 1, 1);
}

// Signal an out-of-memory error using the LowLevelDebug capsule (if available).
pub fn signal_oom() {
    let _ = libtock_core::syscalls::command1_insecure(8, 2, 1);
}

pub fn flash_all_leds() -> ! {
    // Flash all LEDs (if available). All errors from syscalls are ignored: we are already inside a
    // panic handler so there is nothing much to do if simple drivers (timer, LEDs) don't work.
    loop {
        if let Ok(leds) = led::all() {
            for led in leds {
                let _ = led.on();
            }
        }
        let _ = timer::sleep(Duration::from_ms(100));
        if let Ok(leds) = led::all() {
            for led in leds {
                let _ = led.off();
            }
        }
        let _ = timer::sleep(Duration::from_ms(100));
    }
}

pub fn cycle_leds() -> ! {
    // Cycle though all LEDs (if available). All errors from syscalls are ignored: we are already
    // inside an error handler so there is nothing much to do if simple drivers (timer, LEDs) don't
    // work.
    loop {
        if let Ok(leds) = led::all() {
            for led in leds {
                let _ = led.on();
                let _ = timer::sleep(Duration::from_ms(100));
                let _ = led.off();
            }
        }
    }
}
