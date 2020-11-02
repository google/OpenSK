#![no_std]
#![allow(unused_imports)]

extern crate alloc;
extern crate lang_items;
extern crate libtock_drivers;

use core::fmt::Write;
use libtock_core::result::CommandError;
use libtock_drivers::console::Console;
#[cfg(feature = "with_nfc")]
use libtock_drivers::nfc::NfcTag;
#[cfg(feature = "with_nfc")]
use libtock_drivers::nfc::RecvOp;
use libtock_drivers::result::TockError;

#[allow(dead_code)]
/// Helper function to write a slice into a transmission buffer.
fn write_tx_buffer(buf: &mut [u8], slice: &[u8]) {
    for (i, &byte) in slice.iter().enumerate() {
        buf[i] = byte;
    }
}

#[allow(dead_code)]
/// Helper function to write on console the received packet.
fn print_rx_buffer(buf: &mut [u8], amount: usize) {
    if amount < 1 || amount > buf.len() {
        return;
    }
    let mut console = Console::new();
    write!(console, " -- RX Packet:").unwrap();
    for byte in buf.iter().take(amount - 1) {
        write!(console, " {:02x?}", byte).unwrap();
    }
    writeln!(console, " {:02x?}", buf[amount - 1]).unwrap();
}

#[allow(dead_code)]
/// Helper function to write on console the received packet.
fn transmit_slice(buf: &mut [u8] {
    let amount = buf.len();
    match NfcTag::transmit(&mut buf, amount) {
        Ok(_) => (),
        Err(_) => writeln!(console, " -- tx error!").unwrap(),
    }
}

#[cfg(feature = "with_nfc")]
#[derive(PartialEq, Eq)]
/// enum for reserving the NFC tag state.
enum State {
    Enabled,
    Disabled,
}

fn main() {
    let mut console = Console::new();

    writeln!(console, "****************************************").unwrap();
    writeln!(console, "nfct_test application is installed").unwrap();

    #[cfg(feature = "with_nfc")]
    let mut state = State::Disabled;
    #[cfg(feature = "with_nfc")]
    let mut state_change_cntr = 0;
    #[cfg(feature = "with_nfc")]
    loop {
        match state {
            State::Enabled => {
                let mut rx_buf = [0; 256];
                loop {
                    match NfcTag::receive(&mut rx_buf) {
                        Ok(RecvOp {
                            recv_amount: amount,
                            ..
                        }) => print_rx_buffer(&mut rx_buf, amount),
                        Err(TockError::Command(CommandError {
                            return_code: -4, /* EOFF: Not Ready */
                            ..
                        })) => (),
                        Err(TockError::Command(CommandError {
                            return_code: value, ..
                        })) => writeln!(console, " -- Err({})!", value).unwrap(),
                        Err(_) => writeln!(console, " -- RX Err").unwrap(),
                    }

                    match rx_buf[0] {
                        0xe0 /* RATS */=> {
                            let mut answer_to_select = [0x05, 0x78, 0x80, 0xB1, 0x00];
                            transmit_slice(&mut answer_to_select);
                        }
                        0xc2 /* DESELECT */ => {
                            // Ignore the request
                            let mut command_error = [0x6A, 0x81];
                            transmit_slice(&mut command_error);
                        }
                        0x02 | 0x03 /* APDU Prefix */ => {
                            // If the received packet is applet selection command (FIDO 2)
                            if rx_buf[1] == 0x00 && rx_buf[2] == 0xa4 && rx_buf[3] == 0x04 {
                                /// Vesion: "U2F_V2"
                                // let mut reply = [rx_buf[0], 0x55, 0x32, 0x46, 0x5f, 0x56, 0x32, 0x90, 0x00,];
                                /// Vesion: "FIDO_2_0"
                                let mut reply = [rx_buf[0], 0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30, 0x90, 0x00,];
                                transmit_slice(&mut reply);
                            } else {
                                let mut reply = [rx_buf[0], 0x90, 0x00];
                                transmit_slice(&mut reply);
                            }
                        }
                        0x52 | 0x50 /* WUPA | Halt */ => {
                            if NfcTag::disable_emulation() {
                                writeln!(console, " -- TAG DISABLED").unwrap();
                            }
                            state = State::Disabled;
                            break;
                        }
                        _ => (),
                    }
                }
            }
            State::Disabled => {
                NfcTag::enable_emulation();
                // Configure Type 4 tag
                if NfcTag::configure(4) {
                    state = State::Enabled;
                }
            }
        }
        state_change_cntr += 1;
        if state_change_cntr > 100 && state == State::Disabled {
            break;
        }
    }
    writeln!(console, "****************************************").unwrap();
}
