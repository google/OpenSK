extern crate alloc;
extern crate lang_items;

use core::fmt::Write;
use libtock_drivers::console::Console;
// use libtock_drivers::nfc;

fn main() {
    let mut console = Console::new();

    writeln!(console, "****************************************").unwrap();
    writeln!(console, "nfct_test application is installed").unwrap();
    writeln!(console, "****************************************").unwrap();

    // 1. Subscribe to a SELECTED CALLBACK
    // 2. Configure Type 4 tag
    // [_.] Enable Tag emulation (currently the tag is always activated)
    // loop {
    // 1. Allow Receive Buffer
    // 2. Subscribe to RECEIVE CALLBACK
    // 3. Allow TX buffer
    // 4. Subscribe to TX CALLBACK
    // }
}
