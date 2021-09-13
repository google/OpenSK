use core::fmt::Write;
use core::panic::PanicInfo;
use cortexm4;
use kernel::debug;
use kernel::debug::IoWrite;
use kernel::hil::led;
use kernel::hil::uart::{self, Configure};
use nrf52840::gpio::Pin;

use crate::CHIP;
use crate::PROCESSES;

struct Writer {
    initialized: bool,
}

static mut WRITER: Writer = Writer { initialized: false };

impl Write for Writer {
    fn write_str(&mut self, s: &str) -> ::core::fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}

impl IoWrite for Writer {
    fn write(&mut self, buf: &[u8]) {
        // Here, we create a second instance of the Uarte struct.
        // This is okay because we only call this during a panic, and
        // we will never actually process the interrupts
        let uart = nrf52840::uart::Uarte::new();
        if !self.initialized {
            self.initialized = true;
            uart.configure(uart::Parameters {
                baud_rate: 115200,
                stop_bits: uart::StopBits::One,
                parity: uart::Parity::None,
                hw_flow_control: false,
                width: uart::Width::Eight,
            });
        }
        for &c in buf {
            unsafe {
                uart.send_byte(c);
            }
            while !uart.tx_ready() {}
        }
    }
}

#[cfg(not(test))]
#[no_mangle]
#[panic_handler]
/// Panic handler
pub unsafe extern "C" fn panic_fmt(pi: &PanicInfo) -> ! {
    // The nRF52840 Dongle LEDs (see back of board)
    let led_kernel_pin = &nrf52840::gpio::GPIOPin::new(Pin::P0_06);
    let led = &mut led::LedLow::new(led_kernel_pin);
    let writer = &mut WRITER;
    debug::panic(
        &mut [led],
        writer,
        pi,
        &cortexm4::support::nop,
        &PROCESSES,
        &CHIP,
    )
}
