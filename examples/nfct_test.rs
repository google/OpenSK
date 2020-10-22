#![no_std]

extern crate alloc;
extern crate lang_items;

use core::fmt::Write;
use libtock_drivers::console::Console;
use libtock_drivers::nfc::NfcTag;
use libtock_drivers::nfc::RecvOp;

#[allow(dead_code)]
/// Helper function to write a slice into a fixed
/// length transmission buffer.
fn write_tx_buffer(buf: &mut [u8], slice: &[u8]) {
    for (i, &byte) in slice.iter().enumerate() {
        buf[i] = byte;
    }
}

#[derive(PartialEq, Eq)]
enum State {
    Enabled,
    Disabled,
}

fn main() {
    let mut console = Console::new();

    writeln!(console, "****************************************").unwrap();
    writeln!(console, "nfct_test application is installed").unwrap();

    let mut state = State::Disabled;
    let mut state_change_cntr = 0;
    loop {
        match state {
            State::Enabled => {
                let mut rx_buf = [0; 256];
                loop {
                    match NfcTag::receive(&mut rx_buf) {
                        Ok(RecvOp {
                            recv_amount: amount,
                            ..
                        }) => match amount {
                            1 => writeln!(console, " -- RX Packet: {:02x?}", rx_buf[0],).unwrap(),
                            2 => writeln!(
                                console,
                                " -- RX Packet: {:02x?} {:02x?}",
                                rx_buf[0], rx_buf[1],
                            )
                            .unwrap(),
                            3 => writeln!(
                                console,
                                " -- RX Packet: {:02x?} {:02x?} {:02x?}",
                                rx_buf[0], rx_buf[1], rx_buf[2],
                            )
                            .unwrap(),
                            _ => writeln!(
                                console,
                                " -- RX Packet: {:02x?} {:02x?} {:02x?} {:02x?}",
                                rx_buf[0], rx_buf[1], rx_buf[2], rx_buf[3],
                            )
                            .unwrap(),
                        },
                        Err(_) => writeln!(console, " -- rx error!").unwrap(),
                    }

                    match rx_buf[0] {
                        0xe0 /* RATS */=> {
                            let mut answer_to_select = [0x05, 0x78, 0x80, 0xB1, 0x00];
                            let amount = answer_to_select.len();
                            match NfcTag::transmit(&mut answer_to_select, amount) {
                                Ok(_) => (),
                                Err(_) => writeln!(console, " -- tx error!").unwrap(),
                            }
                        }
                        0xc2 /* DESELECT */ => {
                            // Ignore the request
                            let mut command_error = [0x6A, 0x81];
                            let amount = command_error.len();
                            match NfcTag::transmit(&mut command_error, amount) {
                                Ok(_) => (),
                                Err(_) => writeln!(console, " -- tx error!").unwrap(),
                            }
                        }
                        0x02 | 0x03 /* APDU Prefix */ => {
                            let mut reply = [rx_buf[0], 0x90, 0x00];
                            let amount = reply.len();
                            match NfcTag::transmit(&mut reply, amount) {
                                Ok(_) => (),
                                Err(_) => writeln!(console, " -- tx error!").unwrap(),
                            }
                        }
                        0x52 | 0x50 /* WUPA | Halt */ => {
                            if NfcTag::disable_emulation() {
                                writeln!(console, " -- TAG DISABLED").unwrap();
                            }
                            state = State::Disabled;
                            break;
                        }
                        _ => {
                        }
                    }
                }
            }
            State::Disabled => {
                if NfcTag::enable_emulation() {
                    writeln!(console, " -- TAG ENABLED").unwrap();
                }
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
                state = State::Enabled;
            }
        }
        state_change_cntr += 1;
        if state_change_cntr > 10 && state == State::Disabled {
            break;
        }
    }
    writeln!(console, "****************************************").unwrap();
}
