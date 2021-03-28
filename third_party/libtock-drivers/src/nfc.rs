extern crate alloc;

use crate::console::Console;
use crate::ctap_transport::{SendOrRecvStatus, Transport};
use crate::result::TockResult;
use crate::util;
use core::cell::Cell;
use core::cmp;
use core::fmt::Write;
use core::mem;
use libtock_core::{callback, syscalls};

const CHAINING_FRAME_SIZE: usize = 40;

macro_rules! print_to_console {
    ($x:ident, $($tts:tt)*) => {
        writeln!($x, $($tts)*).unwrap();
        $x.flush();
    }
}

const DRIVER_NUMBER: usize = 0x30004;
pub const MAX_LENGTH: usize = 256;

mod command_nr {
    pub const CHECK: usize = 0;
    pub const TRANSMIT: usize = 1;
    pub const RECEIVE: usize = 2;
    pub const EMULATE: usize = 3;
    pub const CONFIGURE: usize = 4;
}

mod subscribe_nr {
    pub const TRANSMIT: usize = 1;
    pub const RECEIVE: usize = 2;
}

mod allow_nr {
    pub const TRANSMIT: usize = 1;
    pub const RECEIVE: usize = 2;
}

pub mod nfc_helper {
    use super::MAX_LENGTH;
    use crate::console::Console;
    use crate::nfc::NfcTag;
    use crate::nfc::RecvOp;
    use crate::result::FlexUnwrap;
    use crate::result::TockError;
    use crate::timer;
    use core::fmt::Write;
    use libtock_core::result::CommandError;

    #[derive(Copy, Clone, Debug, PartialEq)]
    pub enum ReturnCode {
        /// Operation completed successfully
        SUCCESS,
        /// Generic failure condition
        FAIL,
        /// Underlying system is busy; retry
        EBUSY,
        /// The component is powered down
        EOFF,
        /// An invalid parameter was passed
        EINVAL,
        /// Operation canceled by a call
        ECANCEL,
        /// Memory required not available
        ENOMEM,
        /// Operation or command is unsupported
        ENOSUPPORT,
    }

    impl From<isize> for ReturnCode {
        fn from(original: isize) -> ReturnCode {
            match original {
                0 => ReturnCode::SUCCESS,
                -1 => ReturnCode::FAIL,
                -2 => ReturnCode::EBUSY,
                -4 => ReturnCode::EOFF,
                -6 => ReturnCode::EINVAL,
                -8 => ReturnCode::ECANCEL,
                -9 => ReturnCode::ENOMEM,
                _ => ReturnCode::ENOSUPPORT,
            }
        }
    }

    fn transmit_packet(console: &mut Console, buffer: &mut [u8], chaining: bool) -> ReturnCode {
        console.flush();
        let len = if buffer.len() < MAX_LENGTH {
            buffer.len()
        } else {
            MAX_LENGTH
        };
        match NfcTag::transmit(&mut buffer[..len], chaining) {
            Ok(_) => {
                writeln!(
                    console,
                    "[NFC_T4APP] TX DONE ({} bytes): {:02x?}",
                    len,
                    &buffer[..len]
                )
                .unwrap();
                return ReturnCode::SUCCESS;
            }
            Err(TockError::Command(CommandError { return_code, .. })) => return return_code.into(),
            Err(_) => {
                return ReturnCode::ECANCEL;
            }
        }
    }

    fn receive_packet(
        console: &mut Console,
        mut buf: &mut [u8; MAX_LENGTH],
    ) -> (ReturnCode, usize) {
        match NfcTag::receive(&mut buf) {
            Ok(RecvOp {
                recv_amount: amount,
                ..
            }) => {
                writeln!(console, "[NFC_T4APP] RX DONE: {:02x?}", &buf[..amount]).unwrap();
                console.flush();
                return (ReturnCode::SUCCESS, amount);
            }
            Err(TockError::Command(CommandError { return_code, .. })) => {
                return (return_code.into(), 0)
            }
            Err(_) => {
                return (ReturnCode::ECANCEL, 0);
            }
        }
    }

    pub fn nfc_receive<F>(mut console: &mut Console, mut cb: F) -> usize
    where
        F: FnMut(&[u8; MAX_LENGTH], usize),
    {
        // Setup the timer with a dummy callback (we only care about reading the current time, but the
        // API forces us to set an alarm callback too).
        let mut with_callback = timer::with_callback(|_, _| {});
        let timer = with_callback.init().flex_unwrap();

        timer.clock_frequency().hz();

        writeln!(console, "[NFC_T4APP] WAITING FOR RX").unwrap();
        console.flush();

        loop {
            let mut rx_buf = [0; MAX_LENGTH];
            let (retcode, amount) = receive_packet(&mut console, &mut rx_buf);

            match retcode {
                ReturnCode::EOFF | ReturnCode::ECANCEL | ReturnCode::EBUSY => {
                    while !NfcTag::enable_emulation() {}
                    while !NfcTag::configure(4) {}
                }
                ReturnCode::ENOMEM
                | ReturnCode::FAIL
                | ReturnCode::EINVAL
                | ReturnCode::ENOSUPPORT => {}
                ReturnCode::SUCCESS => {
                    writeln!(
                        console,
                        "[NFC_T4APP] RX RETCODE: {:?}, AMOUNT: {}",
                        retcode, amount
                    )
                    .unwrap();
                    console.flush();
                    cb(&rx_buf, amount);
                    return amount;
                }
            }
        }
    }

    pub fn nfc_transmit<F>(
        mut console: &mut Console,
        buffer: &mut [u8],
        chaining: bool,
        mut cb: F,
    ) -> bool
    where
        F: FnMut(ReturnCode),
    {
        // Setup the timer with a dummy callback (we only care about reading the current time, but the
        // API forces us to set an alarm callback too).
        let mut with_callback = timer::with_callback(|_, _| {});
        let timer = with_callback.init().flex_unwrap();
        timer.clock_frequency().hz();

        writeln!(console, "[NFC_T4APP] TX: {:02x?}", buffer).unwrap();
        console.flush();

        loop {
            let retcode = transmit_packet(&mut console, buffer, chaining);

            match retcode {
                ReturnCode::EOFF | ReturnCode::ECANCEL | ReturnCode::EBUSY => {}
                ReturnCode::ENOMEM
                | ReturnCode::FAIL
                | ReturnCode::EINVAL
                | ReturnCode::ENOSUPPORT => {}
                ReturnCode::SUCCESS => {
                    writeln!(console, "[NFC_T4APP] TX RETCODE: {:?}", retcode).unwrap();
                    console.flush();
                    cb(retcode);
                    return true;
                }
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct RecvOp {
    pub result_code: usize,
    pub recv_amount: usize,
}

#[derive(Clone, Copy)]
pub struct NfcTag {}

impl NfcTag {
    /// Check the existence of an NFC driver.
    pub fn setup() -> bool {
        syscalls::command(DRIVER_NUMBER, command_nr::CHECK, 0, 0).is_ok()
    }

    pub fn enable_emulation() -> bool {
        NfcTag::emulate(true)
    }

    pub fn disable_emulation() -> bool {
        NfcTag::emulate(false)
    }

    fn emulate(enabled: bool) -> bool {
        syscalls::command(DRIVER_NUMBER, command_nr::EMULATE, enabled as usize, 0).is_ok()
    }

    /// Configure the tag type command.
    pub fn configure(tag_type: u8) -> bool {
        syscalls::command(DRIVER_NUMBER, command_nr::CONFIGURE, tag_type as usize, 0).is_ok()
    }

    /// 1. Share with the driver a buffer.
    /// 2. Subscribe to having a successful receive callback.
    /// 3. Issue the request for reception.
    pub fn receive(buf: &mut [u8; MAX_LENGTH]) -> TockResult<RecvOp> {
        let result = syscalls::allow(DRIVER_NUMBER, allow_nr::RECEIVE, buf)?;
        // set callback with 2 arguments, to receive ReturnCode and RX Amount
        let recv_data = Cell::new(None);
        let mut callback = |result, amount| {
            recv_data.set(Some(RecvOp {
                result_code: result,
                recv_amount: amount,
            }))
        };
        let subscription = syscalls::subscribe::<callback::Identity2Consumer, _>(
            DRIVER_NUMBER,
            subscribe_nr::RECEIVE,
            &mut callback,
        )?;
        syscalls::command(DRIVER_NUMBER, command_nr::RECEIVE, 0, 0)?;
        util::yieldk_for(|| recv_data.get().is_some());
        mem::drop(subscription);
        mem::drop(result);
        Ok(recv_data.get().unwrap())
    }

    /// 1. Share with the driver a buffer containing the app's reply.
    /// 2. Subscribe to having a successful transmission callback.
    /// 3. Issue the request for transmitting.
    pub fn transmit(buf: &mut [u8], chaining: bool) -> TockResult<usize> {
        let amount = buf.len();
        let result = syscalls::allow(DRIVER_NUMBER, allow_nr::TRANSMIT, buf)?;
        // set callback with 1 argument, to receive ReturnCode
        let result_code = Cell::new(None);
        let mut callback = |result| result_code.set(Some(result));
        let subscription = syscalls::subscribe::<callback::Identity1Consumer, _>(
            DRIVER_NUMBER,
            subscribe_nr::TRANSMIT,
            &mut callback,
        )?;
        syscalls::command(
            DRIVER_NUMBER,
            command_nr::TRANSMIT,
            amount,
            chaining as usize,
        )?;
        util::yieldk_for(|| result_code.get().is_some());
        mem::drop(subscription);
        mem::drop(result);
        Ok(result_code.get().unwrap())
    }

    pub fn receive_bytes(buf: &mut [u8]) -> usize {
        let mut rx_amount = 0;
        nfc_helper::nfc_receive(&mut Console::new(), |rx_buf, amount| {
            rx_amount = amount;
            buf[..amount].copy_from_slice(&rx_buf[..amount]);
        });
        rx_amount
    }

    pub fn transmit_bytes(buf: &mut [u8], chaining: bool) {
        nfc_helper::nfc_transmit(&mut Console::new(), buf, chaining, |_| {});
    }

    pub fn transmit_as_type4_frame(buf: &mut [u8]) {
        let mut console = Console::new();
        print_to_console!(console, "[NFC_T4APP] Type 4 Response: {:02x?}", buf);

        let mut chaining;
        let mut current_start = 0;
        let mut current_end = cmp::min(current_start + CHAINING_FRAME_SIZE, buf.len());
        loop {
            chaining = current_end < buf.len();

            print_to_console!(
                console,
                "[NFC_T4APP] Transmitting {}..{} bytes, chaining: {}",
                current_start,
                current_end,
                chaining
            );

            NfcTag::transmit_bytes(&mut buf[current_start..current_end], chaining);

            if !chaining {
                return;
            }

            current_start = current_end;
            current_end = cmp::min(current_end + CHAINING_FRAME_SIZE, buf.len());
        }
    }
}

impl Transport for NfcTag {
    fn setup(&self) -> bool {
        true
    }

    fn recv(&self, buf: &mut [u8]) -> usize {
        nfc_helper::nfc_receive(&mut Console::new(), |rx_buf, amount| {
            buf[..amount].copy_from_slice(&rx_buf[..amount]);
        })
    }

    fn send(&self, buf: &mut [u8]) -> bool {
        match NfcTag::transmit(buf, false) {
            Ok(bytes_sent) => {
                return bytes_sent == MAX_LENGTH;
            }
            Err(_) => {
                return false;
            }
        }
    }

    fn send_or_recv(&self, buf: &mut [u8]) -> SendOrRecvStatus {
        // Todo: Handle receive as well
        if self.send(buf) {
            return SendOrRecvStatus::Sent;
        }
        return SendOrRecvStatus::Error;
    }

    fn recv_with_timeout(
        &self,
        buf: &mut [u8],
        _timeout_delay: crate::timer::Duration<isize>,
    ) -> Option<SendOrRecvStatus> {
        // Todo: use an alarm to set timeout
        let bytes_received = self.recv(buf);
        if bytes_received > 0 {
            return Some(SendOrRecvStatus::ReceivedBytes(bytes_received));
        } else {
            return None;
        }
    }

    fn send_or_recv_with_timeout(
        &self,
        buf: &mut [u8],
        _timeout_delay: crate::timer::Duration<isize>,
    ) -> Option<SendOrRecvStatus> {
        // Todo: use an alarm to set timeout
        if self.send(buf) {
            return Some(SendOrRecvStatus::Sent);
        } else {
            return None;
        }
    }

    fn recv_with_timeout_detail(
        &self,
        buf: &mut [u8],
        timeout_delay: crate::timer::Duration<isize>,
    ) -> Option<SendOrRecvStatus> {
        self.recv_with_timeout(buf, timeout_delay)
    }

    fn send_or_recv_with_timeout_detail(
        &self,
        buf: &mut [u8],
        timeout_delay: crate::timer::Duration<isize>,
    ) -> Option<SendOrRecvStatus> {
        self.send_or_recv_with_timeout(buf, timeout_delay)
    }
}
