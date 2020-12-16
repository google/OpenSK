#![no_std]

extern crate alloc;
extern crate lang_items;
extern crate libtock_drivers;

use core::fmt::Write;
use libtock_drivers::console::Console;

mod example {
    use super::Console;
    use libtock_drivers::nfc::nfc_helper;

    #[cfg(not(feature = "with_nfc"))]
    pub fn nfc(console: &mut Console) {
        writeln!(console, "NFC feature flag is missing!").unwrap();
    }

    #[cfg(feature = "with_nfc")]
    pub fn nfc(console: &mut Console) {
        loop {
            nfc_helper::nfc_receive(console, |_, _| {});
        }
    }
}

fn main() {
    let mut console = Console::new();
    writeln!(console, "****************************************").unwrap();
    writeln!(console, "nfct_test application is installed").unwrap();
    example::nfc(&mut console);
}
