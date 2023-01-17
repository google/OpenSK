//! Custom panic handler for OpenSK

use crate::util;
#[cfg(feature = "panic_console")]
use core::fmt::Write;
#[cfg(feature = "panic_console")]
use libtock_console::Console;
#[allow(unused_imports)]
use libtock_platform::{ErrorCode, Syscalls};
use libtock_runtime::TockSyscalls;

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    util::Util::<TockSyscalls>::signal_panic();

    #[cfg(feature = "panic_console")]
    {
        let mut writer = Console::<TockSyscalls>::writer();
        writeln!(writer, "{}", _info).ok();
        // Exit with a non-zero exit code to indicate failure.
        TockSyscalls::exit_terminate(ErrorCode::Fail as u32);
    }
    #[cfg(not(feature = "panic_console"))]
    util::Util::<TockSyscalls>::flash_all_leds();
}
