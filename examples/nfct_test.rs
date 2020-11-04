#![no_std]

extern crate alloc;
extern crate lang_items;
extern crate libtock_drivers;

use core::fmt::Write;
use libtock_core::result::CommandError;
use libtock_drivers::console::Console;
use libtock_drivers::nfc::NfcTag;
use libtock_drivers::nfc::RecvOp;
use libtock_drivers::result::FlexUnwrap;
use libtock_drivers::result::TockError;
use libtock_drivers::timer;
use libtock_drivers::timer::Timer;
use libtock_drivers::timer::Timestamp;

#[allow(dead_code)]
/// Helper function to write on console the received packet.
fn print_rx_buffer(buf: &mut [u8], amount: usize) {
    if amount < 1 || amount > buf.len() {
        return;
    }
    let mut console = Console::new();
    write!(console, "RX:").unwrap();
    for byte in buf.iter().take(amount - 1) {
        write!(console, " {:02x?}", byte).unwrap();
    }
    writeln!(console, " {:02x?}", buf[amount - 1]).unwrap();
    console.flush();
}

#[allow(dead_code)]
/// Function to identify the time elapsed for a transmission request.
fn bench_transmit(console: &mut Console, timer: &Timer, title: &str, mut buf: &mut [u8]) {
    let amount = buf.len();
    let start = Timestamp::<f64>::from_clock_value(timer.get_current_clock().flex_unwrap());
    match NfcTag::transmit(&mut buf, amount) {
        Ok(_) => (),
        Err(_) => writeln!(Console::new(), " -- tx error!").unwrap(),
    }
    let end = Timestamp::<f64>::from_clock_value(timer.get_current_clock().flex_unwrap());
    let elapsed = (end - start).ms();
    writeln!(
        console,
        "{}\n{:.2} ms elapsed for {} bytes ({:.2} kbit/s)",
        title,
        elapsed,
        amount,
        (amount as f64) / elapsed * 8.
    )
    .unwrap();
    console.flush();
}

#[derive(PartialEq, Eq)]
/// enum for reserving the NFC tag state.
enum State {
    Enabled,
    Disabled,
}

fn main() {
    let mut console = Console::new();
    // Setup the timer with a dummy callback (we only care about reading the current time, but the
    // API forces us to set an alarm callback too).
    let mut with_callback = timer::with_callback(|_, _| {});
    let timer = with_callback.init().flex_unwrap();

    writeln!(console, "****************************************").unwrap();
    writeln!(console, "nfct_test application is installed").unwrap();
    writeln!(
        console,
        "Clock frequency: {} Hz",
        timer.clock_frequency().hz()
    )
    .unwrap();

    let mut state = State::Disabled;
    // Variable to count the change in the tag's state
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
                            bench_transmit(&mut console, &timer, "TX: ATS", &mut answer_to_select);
                        }
                        0xc2 /* DESELECT */ => {
                            // Ignore the request
                            let mut command_error = [0x6A, 0x81];
                            bench_transmit(&mut console, &timer, "TX: DESELECT", &mut command_error);
                        }
                        0x02 | 0x03 /* APDU Prefix */ => match rx_buf[2] {
                            // If the received packet is applet selection command (FIDO 2)
                            0xa4 /* SELECT */ => if rx_buf[3] == 0x04 && rx_buf[5] == 0x08 && rx_buf[6] == 0xa0 {
                                    // Vesion: "FIDO_2_0"
                                    let mut reply = [rx_buf[0], 0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30, 0x90, 0x00,];
                                    bench_transmit(&mut console, &timer, "TX: Version Str", &mut reply);
                                } else {
                                    let mut reply = [rx_buf[0], 0x90, 0x00];
                                    bench_transmit(&mut console, &timer, "TX: 0x9000", &mut reply);
                                }
                            0xb0 /* READ */ =>  match rx_buf[5] {
                                    0x02 => {
                                    let mut reply = [rx_buf[0], 0x12, 0x90, 0x00,];
                                    bench_transmit(&mut console, &timer, "TX: File Size", &mut reply);
                                }
                                0x12 => {
                                    let mut reply = [rx_buf[0], 0xd1, 0x01, 0x0e, 0x55, 0x77, 0x77, 0x77, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x6b, 0x2e, 0x64, 0x65, 0x76, 0x90, 0x00,];
                                    bench_transmit(&mut console, &timer, "TX: NDEF", &mut reply);
                                }
                                0x0f => {
                                    let mut reply = [rx_buf[0], 0x00, 0x0f, 0x20, 0x00, 0x7f, 0x00, 0x7f, 0x04, 0x06, 0xe1, 0x04, 0x00, 0x7f, 0x00, 0x00, 0x90, 0x00,];
                                    bench_transmit(&mut console, &timer, "TX: CC", &mut reply);
                                }
                                _ => {
                                    let mut reply = [rx_buf[0], 0x90, 0x00];
                                    bench_transmit(&mut console, &timer, "TX: 0x9000", &mut reply);
                                }
                            }
                            _ => {
                                let mut reply = [rx_buf[0], 0x90, 0x00];
                                bench_transmit(&mut console, &timer, "TX: 0x9000", &mut reply);
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
