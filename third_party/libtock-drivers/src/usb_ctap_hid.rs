// Copyright 2019-2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(feature = "debug_ctap")]
use crate::console::Console;
use crate::result::{OutOfRangeError, TockError, TockResult};
use crate::timer::Duration;
use crate::{timer, util};
use core::cell::Cell;
use core::convert::TryFrom;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
use libtock_core::result::{CommandError, EALREADY, EBUSY, SUCCESS};
use libtock_core::{callback, syscalls};

const DRIVER_NUMBER: usize = 0x20009;

mod command_nr {
    pub const CHECK: usize = 0;
    pub const CONNECT: usize = 1;
    pub const _TRANSMIT: usize = 2;
    pub const RECEIVE: usize = 3;
    pub const TRANSMIT_OR_RECEIVE: usize = 4;
    pub const CANCEL: usize = 5;
}

mod subscribe_nr {
    pub const _TRANSMIT: usize = 1;
    pub const RECEIVE: usize = 2;
    pub const TRANSMIT_OR_RECEIVE: usize = 3;
    pub mod callback_status {
        pub const TRANSMITTED: usize = 1;
        pub const RECEIVED: usize = 2;
    }
}

mod allow_nr {
    pub const _TRANSMIT: usize = 1;
    pub const RECEIVE: usize = 2;
    pub const TRANSMIT_OR_RECEIVE: usize = 3;
}

pub fn setup() -> bool {
    let result = syscalls::command(DRIVER_NUMBER, command_nr::CHECK, 0, 0);
    if result.is_err() {
        return false;
    }

    let result = syscalls::command(DRIVER_NUMBER, command_nr::CONNECT, 0, 0);
    if result.is_err() {
        return false;
    }

    true
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UsbEndpoint {
    MainHid = 1,
    #[cfg(feature = "vendor_hid")]
    VendorHid = 2,
}

impl TryFrom<usize> for UsbEndpoint {
    type Error = TockError;

    fn try_from(endpoint_num: usize) -> Result<Self, TockError> {
        match endpoint_num {
            1 => Ok(UsbEndpoint::MainHid),
            #[cfg(feature = "vendor_hid")]
            2 => Ok(UsbEndpoint::VendorHid),
            _ => Err(OutOfRangeError.into()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SendOrRecvStatus {
    Timeout,
    Sent,
    Received(UsbEndpoint),
}

/// Waits to receive a packet.
///
/// Returns None if the transaction timed out, else its status.
#[allow(clippy::let_and_return)]
pub fn recv_with_timeout(
    buf: &mut [u8; 64],
    timeout_delay: Duration<isize>,
) -> TockResult<SendOrRecvStatus> {
    #[cfg(feature = "verbose_usb")]
    writeln!(
        Console::new(),
        "Receiving packet with timeout of {}ms",
        timeout_delay.ms(),
    )
    .unwrap();

    let result = recv_with_timeout_detail(buf, timeout_delay);

    #[cfg(feature = "verbose_usb")]
    if let Ok(SendOrRecvStatus::Received(endpoint)) = result {
        writeln!(
            Console::new(),
            "Received packet = {:02x?} on endpoint {}",
            buf as &[u8],
            endpoint as u8,
        )
        .unwrap();
    }

    result
}

/// Either sends or receives a packet within a given time.
///
/// Because USB transactions are initiated by the host, we don't decide whether an IN transaction
/// (send for us), an OUT transaction (receive for us), or no transaction at all will happen next.
///
/// - If an IN transaction happens first, the initial content of buf is sent to the host and the
/// Sent status is returned.
/// - If an OUT transaction happens first, the content of buf is replaced by the packet received
/// from the host and Received status is returned. In that case, the original content of buf is not
/// sent to the host, and it's up to the caller to retry sending or to handle the packet received
/// from the host.
/// If the timeout elapses, return None.
#[allow(clippy::let_and_return)]
pub fn send_or_recv_with_timeout(
    buf: &mut [u8; 64],
    timeout_delay: Duration<isize>,
    endpoint: UsbEndpoint,
) -> TockResult<SendOrRecvStatus> {
    #[cfg(feature = "verbose_usb")]
    writeln!(
        Console::new(),
        "Sending packet with timeout of {}ms = {:02x?}",
        timeout_delay.ms(),
        buf as &[u8]
    )
    .unwrap();

    let result = send_or_recv_with_timeout_detail(buf, timeout_delay, endpoint);

    #[cfg(feature = "verbose_usb")]
    if let Ok(SendOrRecvStatus::Received(received_endpoint)) = result {
        writeln!(
            Console::new(),
            "Received packet = {:02x?} on endpoint {}",
            buf as &[u8],
            received_endpoint as u8,
        )
        .unwrap();
    }

    result
}

fn recv_with_timeout_detail(
    buf: &mut [u8; 64],
    timeout_delay: Duration<isize>,
) -> TockResult<SendOrRecvStatus> {
    let result = syscalls::allow(DRIVER_NUMBER, allow_nr::RECEIVE, buf)?;

    let status = Cell::new(None);
    let mut alarm = |direction, endpoint| {
        status.set(Some(match direction {
            subscribe_nr::callback_status::RECEIVED => {
                UsbEndpoint::try_from(endpoint).map(|i| SendOrRecvStatus::Received(i))
            }
            // Unknown direction or "transmitted" sent by the kernel.
            _ => Err(OutOfRangeError.into()),
        }));
    };

    let subscription = syscalls::subscribe::<callback::Identity2Consumer, _>(
        DRIVER_NUMBER,
        subscribe_nr::RECEIVE,
        &mut alarm,
    )?;

    // Setup a time-out callback.
    let mut timeout_callback = timer::with_callback(|_, _| {
        status.set(Some(Ok(SendOrRecvStatus::Timeout)));
    });
    let mut timeout = timeout_callback.init()?;
    let timeout_alarm = timeout.set_alarm(timeout_delay)?;

    // Trigger USB reception.
    let result_code = syscalls::command(DRIVER_NUMBER, command_nr::RECEIVE, 0, 0)?;

    util::yieldk_for(|| status.get().is_some());
    let status = status.get().unwrap();

    // Cleanup alarm callback.
    match timeout.stop_alarm(timeout_alarm) {
        Ok(()) => (),
        Err(TockError::Command(CommandError {
            return_code: EALREADY,
            ..
        })) => {
            if matches!(status, Ok(SendOrRecvStatus::Timeout)) {
                #[cfg(feature = "debug_ctap")]
                writeln!(
                    Console::new(),
                    "The receive timeout already expired, but the callback wasn't executed."
                )
                .unwrap();
            }
        }
        Err(_e) => {
            #[cfg(feature = "debug_ctap")]
            panic!("Unexpected error when stopping alarm: {:?}", _e);
            #[cfg(not(feature = "debug_ctap"))]
            panic!("Unexpected error when stopping alarm: <error is only visible with the debug_ctap feature>");
        }
    }

    // Cancel USB transaction if necessary.
    if matches!(status, Ok(SendOrRecvStatus::Timeout)) {
        #[cfg(feature = "verbose_usb")]
        writeln!(Console::new(), "Cancelling USB receive due to timeout").unwrap();
        let result_code =
            unsafe { syscalls::raw::command(DRIVER_NUMBER, command_nr::CANCEL, 0, 0) };
        match result_code {
            // - SUCCESS means that we successfully cancelled the transaction.
            // - EALREADY means that the transaction was already completed.
            SUCCESS | EALREADY => (),
            // - EBUSY means that the transaction is in progress.
            EBUSY => {
                // The app should wait for it, but it may never happen if the remote app crashes.
                // We just return to avoid a deadlock.
                #[cfg(feature = "debug_ctap")]
                writeln!(Console::new(), "Couldn't cancel the USB receive").unwrap();
            }
            _ => panic!(
                "Unexpected error when cancelling USB receive: {:?}",
                result_code
            ),
        }
    }

    core::mem::drop(result);
    core::mem::drop(subscription);
    core::mem::drop(result_code);
    status
}

fn send_or_recv_with_timeout_detail(
    buf: &mut [u8; 64],
    timeout_delay: Duration<isize>,
    endpoint: UsbEndpoint,
) -> TockResult<SendOrRecvStatus> {
    let result = syscalls::allow(DRIVER_NUMBER, allow_nr::TRANSMIT_OR_RECEIVE, buf)?;

    let status = Cell::new(None);
    let mut alarm = |direction, endpoint| {
        status.set(Some(match direction {
            subscribe_nr::callback_status::TRANSMITTED => Ok(SendOrRecvStatus::Sent),
            subscribe_nr::callback_status::RECEIVED => {
                UsbEndpoint::try_from(endpoint).map(|i| SendOrRecvStatus::Received(i))
            }
            // Unknown direction sent by the kernel.
            _ => Err(OutOfRangeError.into()),
        }));
    };

    let subscription = syscalls::subscribe::<callback::Identity2Consumer, _>(
        DRIVER_NUMBER,
        subscribe_nr::TRANSMIT_OR_RECEIVE,
        &mut alarm,
    )?;

    // Setup a time-out callback.
    let mut timeout_callback = timer::with_callback(|_, _| {
        status.set(Some(Ok(SendOrRecvStatus::Timeout)));
    });
    let mut timeout = timeout_callback.init()?;
    let timeout_alarm = timeout.set_alarm(timeout_delay)?;

    // Trigger USB transmission.
    let result_code = syscalls::command(
        DRIVER_NUMBER,
        command_nr::TRANSMIT_OR_RECEIVE,
        endpoint as usize,
        0,
    )?;

    util::yieldk_for(|| status.get().is_some());
    let status = status.get().unwrap();

    // Cleanup alarm callback.
    match timeout.stop_alarm(timeout_alarm) {
        Ok(()) => (),
        Err(TockError::Command(CommandError {
            return_code: EALREADY,
            ..
        })) => {
            if matches!(status, Ok(SendOrRecvStatus::Timeout)) {
                #[cfg(feature = "debug_ctap")]
                writeln!(
                    Console::new(),
                    "The send/receive timeout already expired, but the callback wasn't executed."
                )
                .unwrap();
            }
        }
        Err(_e) => {
            #[cfg(feature = "debug_ctap")]
            panic!("Unexpected error when stopping alarm: {:?}", _e);
            #[cfg(not(feature = "debug_ctap"))]
            panic!("Unexpected error when stopping alarm: <error is only visible with the debug_ctap feature>");
        }
    }

    // Cancel USB transaction if necessary.
    if matches!(status, Ok(SendOrRecvStatus::Timeout)) {
        #[cfg(feature = "verbose_usb")]
        writeln!(Console::new(), "Cancelling USB transaction due to timeout").unwrap();
        let result_code =
            unsafe { syscalls::raw::command(DRIVER_NUMBER, command_nr::CANCEL, endpoint as usize, 0) };
        match result_code {
            // - SUCCESS means that we successfully cancelled the transaction.
            // - EALREADY means that the transaction was already completed.
            SUCCESS | EALREADY => (),
            // - EBUSY means that the transaction is in progress.
            EBUSY => {
                // The app should wait for it, but it may never happen if the remote app crashes.
                // We just return to avoid a deadlock.
                #[cfg(feature = "debug_ctap")]
                writeln!(Console::new(), "Couldn't cancel the transaction").unwrap();
            }
            _ => panic!(
                "Unexpected error when cancelling USB transaction: {:?}",
                result_code
            ),
        }
        #[cfg(feature = "debug_ctap")]
        writeln!(Console::new(), "Cancelled USB transaction!").unwrap();
    }

    core::mem::drop(result);
    core::mem::drop(subscription);
    core::mem::drop(result_code);
    status
}
