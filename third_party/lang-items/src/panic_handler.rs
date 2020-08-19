use crate::util;
#[cfg(feature = "panic_console")]
use core::fmt::Write;
use core::panic::PanicInfo;
#[cfg(feature = "panic_console")]
use libtock_drivers::console::Console;

#[panic_handler]
fn panic_handler(_info: &PanicInfo) -> ! {
    util::signal_panic();

    #[cfg(feature = "panic_console")]
    {
        let mut console = Console::new();
        writeln!(console, "{}", _info).ok();
        console.flush();
        // Force the kernel to report the panic cause, by reading an invalid address.
        // The memory protection unit should be setup by the Tock kernel to prevent apps from accessing
        // address zero.
        unsafe {
            core::ptr::read_volatile(0 as *const usize);
        }
    }

    util::flash_all_leds();
}
