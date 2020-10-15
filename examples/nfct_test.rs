#![no_std]

extern crate alloc;
extern crate lang_items;

use core::fmt::Write;
use libtock_drivers::console::Console;
use libtock_drivers::nfc::NfcTag;

#[allow(dead_code)]
/// Helper function to write a slice into a fixed
/// length transmission buffer.
fn write_tx_buffer(buf: &mut [u8], slice: &[u8]) {
    for (i, &byte) in slice.iter().enumerate() {
        buf[i] = byte;
    }
}

fn main() {
    let mut console = Console::new();

    writeln!(console, "****************************************").unwrap();
    writeln!(console, "nfct_test application is installed").unwrap();

    // 1. Configure Type 4 tag
    if NfcTag::configure(4) {
        writeln!(console, " -- TAG CONFIGURED").unwrap();
    }
    // 2. Subscribe to a SELECTED CALLBACK
    if NfcTag::selected() {
        writeln!(console, " -- TAG SELECTED").unwrap();
        // 0xfffff results in 1048575 / 13.56e6 = 77ms
        NfcTag::set_framedelaymax(0xfffff);
    }
    /*
    [_.] TODO: Enable Tag emulation (currently the tag is always activated)
    needs field detection support in the driver level.
    */
    let mut rx_buf = [0; 64];
    let mut unknown_cmd_cntr = 0;
    loop {
        NfcTag::receive(&mut rx_buf);
        match rx_buf[0] {
            0xe0 /* RATS */=> {
                let mut answer_to_select = [0x05, 0x78, 0x80, 0xB1, 0x00];
                let amount = answer_to_select.len();
                NfcTag::transmit(&mut answer_to_select, amount);
            }
            0xc2 /* DESELECT */ => {
                // Ignore the request
                let mut command_error = [0x6A, 0x81];
                let amount = command_error.len();
                NfcTag::transmit(&mut command_error, amount);
            }
            0x02 | 0x03 /* APDU Prefix */ => {
                let mut reply = [rx_buf[0], 0x90, 0x00];
                let amount = reply.len();
                NfcTag::transmit(&mut reply, amount);
            }
            _ => {
                unknown_cmd_cntr += 1;
            }
        }
        if unknown_cmd_cntr > 50 {
            break;
        }
    }
    writeln!(console, "****************************************").unwrap();
}
