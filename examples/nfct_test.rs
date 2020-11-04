#![no_std]

extern crate alloc;
extern crate lang_items;
extern crate libtock_drivers;

use core::fmt::Write;
use libtock_drivers::console::Console;

#[cfg(not(feature = "with_nfc"))]
mod example {
    use super::Console;
    use super::Write;

    pub fn nfc(console: &mut Console) {
        writeln!(console, "NFC feature flag is missing!").unwrap();
    }
}

#[cfg(feature = "with_nfc")]
mod example {

    use super::Console;
    use super::Write;
    use libtock_core::result::CommandError;
    use libtock_drivers::nfc::NfcTag;
    use libtock_drivers::nfc::RecvOp;
    use libtock_drivers::result::FlexUnwrap;
    use libtock_drivers::result::TockError;
    use libtock_drivers::timer;
    use libtock_drivers::timer::Timer;
    use libtock_drivers::timer::Timestamp;

    /// Helper function to write on console the received packet.
    fn print_rx_buffer(buf: &mut [u8]) {
        let mut console = Console::new();
        write!(console, "RX:").unwrap();
        if let Some((last, bytes)) = buf.split_last() {
            for byte in bytes {
                write!(console, " {:02x?}", byte).unwrap();
            }
            writeln!(console, " {:02x?}", last).unwrap();
        }
        console.flush();
    }

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

    fn receive_packet(console: &mut Console, mut buf: &mut [u8; 256]) {
        match NfcTag::receive(&mut buf) {
            Ok(RecvOp {
                recv_amount: amount,
                ..
            }) => {
                if amount > 0 && amount <= buf.len() {
                    print_rx_buffer(&mut buf[..amount]);
                }
            }
            Err(TockError::Command(CommandError {
                return_code: -4, /* EOFF: Not Ready */
                ..
            })) => (),
            Err(TockError::Command(CommandError {
                return_code: value, ..
            })) => writeln!(console, " -- Err({})!", value).unwrap(),
            Err(_) => writeln!(console, " -- RX Err").unwrap(),
        }
    }

    fn transmit_reply(mut console: &mut Console, timer: &Timer, buf: &[u8]) -> bool {
        match buf[0] {
            0xe0 /* RATS */=> {
                let mut answer_to_select = [0x05, 0x78, 0x80, 0xB1, 0x00];
                bench_transmit(&mut console, &timer, "TX: ATS", &mut answer_to_select);
            }
            0xc2 /* DESELECT */ => {
                // Ignore the request
                let mut command_error = [0x6A, 0x81];
                bench_transmit(&mut console, &timer, "TX: DESELECT", &mut command_error);
            }
            0x02 | 0x03 /* APDU Prefix */ => match buf[2] {
                // If the received packet is applet selection command (FIDO 2)
                0xa4 /* SELECT */ => if buf[3] == 0x04 && buf[5] == 0x08 && buf[6] == 0xa0 {
                        // Vesion: "FIDO_2_0"
                        let mut reply = [buf[0], 0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30, 0x90, 0x00,];
                        bench_transmit(&mut console, &timer, "TX: Version Str", &mut reply);
                    } else {
                        let mut reply = [buf[0], 0x90, 0x00];
                        bench_transmit(&mut console, &timer, "TX: 0x9000", &mut reply);
                    }
                0xb0 /* READ */ =>  match buf[5] {
                        0x02 => {
                        let mut reply = [buf[0], 0x12, 0x90, 0x00,];
                        bench_transmit(&mut console, &timer, "TX: File Size", &mut reply);
                    }
                    0x12 => {
                        let mut reply = [buf[0], 0xd1, 0x01, 0x0e, 0x55, 0x77, 0x77, 0x77, 0x2e, 0x6f, 0x70, 0x65,
                        0x6e, 0x73, 0x6b, 0x2e, 0x64, 0x65, 0x76, 0x90, 0x00,];
                        bench_transmit(&mut console, &timer, "TX: NDEF", &mut reply);
                    }
                    0x0f => {
                        let mut reply = [buf[0], 0x00, 0x0f, 0x20, 0x00, 0x7f, 0x00, 0x7f, 0x04, 0x06, 0xe1, 0x04,
                        0x00, 0x7f, 0x00, 0x00, 0x90, 0x00,];
                        bench_transmit(&mut console, &timer, "TX: CC", &mut reply);
                    }
                    _ => {
                        let mut reply = [buf[0], 0x90, 0x00];
                        bench_transmit(&mut console, &timer, "TX: 0x9000", &mut reply);
                    }
                }
                _ => {
                    let mut reply = [buf[0], 0x90, 0x00];
                    bench_transmit(&mut console, &timer, "TX: 0x9000", &mut reply);
                }
            }
            0x26 | 0x52 | 0x50 /* REQA | WUPA | Halt */ => {
                if NfcTag::disable_emulation() {
                    writeln!(console, " -- TAG DISABLED").unwrap();
                }
                return false;
            }
            _ => (),
        }
        true
    }

    pub fn nfc(mut console: &mut Console) {
        // Setup the timer with a dummy callback (we only care about reading the current time, but the
        // API forces us to set an alarm callback too).
        let mut with_callback = timer::with_callback(|_, _| {});
        let timer = with_callback.init().flex_unwrap();

        writeln!(
            console,
            "Clock frequency: {} Hz",
            timer.clock_frequency().hz()
        )
        .unwrap();

        let mut is_enabled = false;
        let mut state_change_counter = 0;
        loop {
            match is_enabled {
                true => {
                    let mut rx_buf = [0; 256];
                    loop {
                        receive_packet(&mut console, &mut rx_buf);
                        // If the reader restarts the communication and we can't
                        // reply to the received packet, then disable the tag.
                        if !transmit_reply(&mut console, &timer, &rx_buf) {
                            is_enabled = false;
                            break;
                        }
                    }
                }
                false => {
                    NfcTag::enable_emulation();
                    // Configure Type 4 tag
                    if NfcTag::configure(4) {
                        is_enabled = true;
                    }
                }
            }
            state_change_counter += 1;
            if state_change_counter > 100 && is_enabled == false {
                break;
            }
        }
    }
}

fn main() {
    let mut console = Console::new();
    writeln!(console, "****************************************").unwrap();
    writeln!(console, "nfct_test application is installed").unwrap();
    example::nfc(&mut console);
    writeln!(console, "****************************************").unwrap();
}
