// Copyright 2019 Google LLC
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
use crate::result::TockError;
use crate::timer;
use crate::timer::Duration;
use crate::util;
use core::cell::Cell;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
use libtock_core::result::{CommandError, EALREADY, EBUSY, SUCCESS};
use libtock_core::{callback, syscalls};

const DRIVER_NUMBER: usize = 0x20009;

mod command_nr {
    pub const CHECK: usize = 0;
    pub const CONNECT: usize = 1;
    pub const TRANSMIT: usize = 2;
    pub const RECEIVE: usize = 3;
    pub const TRANSMIT_OR_RECEIVE: usize = 4;
    pub const CANCEL: usize = 5;
}

mod subscribe_nr {
    pub const TRANSMIT: usize = 1;
    pub const RECEIVE: usize = 2;
    pub const TRANSMIT_OR_RECEIVE: usize = 3;
    pub mod callback_status {
        pub const TRANSMITTED: usize = 1;
        pub const RECEIVED: usize = 2;
    }
}

mod allow_nr {
    pub const TRANSMIT: usize = 1;
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

#[allow(dead_code)]
pub fn recv(buf: &mut [u8; 64]) -> bool {
    let result = syscalls::allow(DRIVER_NUMBER, allow_nr::RECEIVE, buf);
    if result.is_err() {
        return false;
    }

    let done = Cell::new(false);
    let mut alarm = || done.set(true);
    let subscription = syscalls::subscribe::<callback::Identity0Consumer, _>(
        DRIVER_NUMBER,
        subscribe_nr::RECEIVE,
        &mut alarm,
    );
    if subscription.is_err() {
        return false;
    }

    let result_code = syscalls::command(DRIVER_NUMBER, command_nr::RECEIVE, 0, 0);
    if result_code.is_err() {
        return false;
    }

    util::yieldk_for(|| done.get());
    true
}

#[allow(dead_code)]
pub fn send(buf: &mut [u8; 64]) -> bool {
    let result = syscalls::allow(DRIVER_NUMBER, allow_nr::TRANSMIT, buf);
    if result.is_err() {
        return false;
    }

    let done = Cell::new(false);
    let mut alarm = || done.set(true);
    let subscription = syscalls::subscribe::<callback::Identity0Consumer, _>(
        DRIVER_NUMBER,
        subscribe_nr::TRANSMIT,
        &mut alarm,
    );
    if subscription.is_err() {
        return false;
    }

    let result_code = syscalls::command(DRIVER_NUMBER, command_nr::TRANSMIT, 0, 0);
    if result_code.is_err() {
        return false;
    }

    util::yieldk_for(|| done.get());
    true
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SendOrRecvStatus {
    Error,
    Sent,
    Received,
}

// Either sends or receive a packet.
// Because USB transactions are initiated by the host, we don't decide whether an IN transaction
// (send for us), an OUT transaction (receive for us), or no transaction at all will happen next.
//
// - If an IN transaction happens first, the initial content of buf is sent to the host and the
// Sent status is returned.
// - If an OUT transaction happens first, the content of buf is replaced by the packet received
// from the host and Received status is returned. In that case, the original content of buf is not
// sent to the host, and it's up to the caller to retry sending or to handle the packet received
// from the host.
#[allow(dead_code)]
pub fn send_or_recv(buf: &mut [u8; 64]) -> SendOrRecvStatus {
    let result = syscalls::allow(DRIVER_NUMBER, allow_nr::TRANSMIT_OR_RECEIVE, buf);
    if result.is_err() {
        return SendOrRecvStatus::Error;
    }

    let status = Cell::new(None);
    let mut alarm = |direction| {
        status.set(Some(match direction {
            subscribe_nr::callback_status::TRANSMITTED => SendOrRecvStatus::Sent,
            subscribe_nr::callback_status::RECEIVED => SendOrRecvStatus::Received,
            // Unknown direction sent by the kernel.
            _ => SendOrRecvStatus::Error,
        }));
    };

    let subscription = syscalls::subscribe::<callback::Identity1Consumer, _>(
        DRIVER_NUMBER,
        subscribe_nr::TRANSMIT_OR_RECEIVE,
        &mut alarm,
    );
    if subscription.is_err() {
        return SendOrRecvStatus::Error;
    }

    let result_code = syscalls::command(DRIVER_NUMBER, command_nr::TRANSMIT_OR_RECEIVE, 0, 0);
    if result_code.is_err() {
        return SendOrRecvStatus::Error;
    }

    util::yieldk_for(|| status.get().is_some());
    status.get().unwrap()
}

// Same as recv, but with a timeout.
// If the timeout elapses, return None.
#[allow(clippy::let_and_return)]
pub fn recv_with_timeout(
    buf: &mut [u8; 64],
    timeout_delay: Duration<isize>,
) -> Option<SendOrRecvStatus> {
    #[cfg(feature = "verbose_usb")]
    writeln!(
        Console::new(),
        "Receiving packet with timeout of {}ms",
        timeout_delay.ms(),
    )
    .unwrap();

    let result = recv_with_timeout_detail(buf, timeout_delay);

    #[cfg(feature = "verbose_usb")]
    {
        if let Some(SendOrRecvStatus::Received) = result {
            writeln!(Console::new(), "Received packet = {:02x?}", buf as &[u8]).unwrap();
        }
    }

    result
}

// Same as send_or_recv, but with a timeout.
// If the timeout elapses, return None.
#[allow(clippy::let_and_return)]
pub fn send_or_recv_with_timeout(
    buf: &mut [u8; 64],
    timeout_delay: Duration<isize>,
) -> Option<SendOrRecvStatus> {
    #[cfg(feature = "verbose_usb")]
    writeln!(
        Console::new(),
        "Sending packet with timeout of {}ms = {:02x?}",
        timeout_delay.ms(),
        buf as &[u8]
    )
    .unwrap();

    let result = send_or_recv_with_timeout_detail(buf, timeout_delay);

    #[cfg(feature = "verbose_usb")]
    {
        if let Some(SendOrRecvStatus::Received) = result {
            writeln!(Console::new(), "Received packet = {:02x?}", buf as &[u8]).unwrap();
        }
    }

    result
}

fn recv_with_timeout_detail(
    buf: &mut [u8; 64],
    timeout_delay: Duration<isize>,
) -> Option<SendOrRecvStatus> {
    let result = syscalls::allow(DRIVER_NUMBER, allow_nr::RECEIVE, buf);
    if result.is_err() {
        return Some(SendOrRecvStatus::Error);
    }

    let status = Cell::new(None);
    let mut alarm = |direction| {
        status.set(Some(match direction {
            subscribe_nr::callback_status::RECEIVED => SendOrRecvStatus::Received,
            // Unknown direction or "transmitted" sent by the kernel.
            _ => SendOrRecvStatus::Error,
        }));
    };

    let subscription = syscalls::subscribe::<callback::Identity1Consumer, _>(
        DRIVER_NUMBER,
        subscribe_nr::RECEIVE,
        &mut alarm,
    );
    if subscription.is_err() {
        return Some(SendOrRecvStatus::Error);
    }

    // Setup a time-out callback.
    let timeout_expired = Cell::new(false);
    let mut timeout_callback = timer::with_callback(|_, _| {
        timeout_expired.set(true);
    });
    let mut timeout = match timeout_callback.init() {
        Ok(x) => x,
        Err(_) => return Some(SendOrRecvStatus::Error),
    };
    let timeout_alarm = match timeout.set_alarm(timeout_delay) {
        Ok(x) => x,
        Err(_) => return Some(SendOrRecvStatus::Error),
    };

    // Trigger USB reception.
    let result_code = syscalls::command(DRIVER_NUMBER, command_nr::RECEIVE, 0, 0);
    if result_code.is_err() {
        return Some(SendOrRecvStatus::Error);
    }

    util::yieldk_for(|| status.get().is_some() || timeout_expired.get());

    // Cleanup alarm callback.
    match timeout.stop_alarm(timeout_alarm) {
        Ok(()) => (),
        Err(TockError::Command(CommandError {
            return_code: EALREADY,
            ..
        })) => {
            if !timeout_expired.get() {
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
    if status.get().is_none() {
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

    status.get()
}

fn send_or_recv_with_timeout_detail(
    buf: &mut [u8; 64],
    timeout_delay: Duration<isize>,
) -> Option<SendOrRecvStatus> {
    let result = syscalls::allow(DRIVER_NUMBER, allow_nr::TRANSMIT_OR_RECEIVE, buf);
    if result.is_err() {
        return Some(SendOrRecvStatus::Error);
    }

    let status = Cell::new(None);
    let mut alarm = |direction| {
        status.set(Some(match direction {
            subscribe_nr::callback_status::TRANSMITTED => SendOrRecvStatus::Sent,
            subscribe_nr::callback_status::RECEIVED => SendOrRecvStatus::Received,
            // Unknown direction sent by the kernel.
            _ => SendOrRecvStatus::Error,
        }));
    };

    let subscription = syscalls::subscribe::<callback::Identity1Consumer, _>(
        DRIVER_NUMBER,
        subscribe_nr::TRANSMIT_OR_RECEIVE,
        &mut alarm,
    );
    if subscription.is_err() {
        return Some(SendOrRecvStatus::Error);
    }

    // Setup a time-out callback.
    let timeout_expired = Cell::new(false);
    let mut timeout_callback = timer::with_callback(|_, _| {
        timeout_expired.set(true);
    });
    let mut timeout = match timeout_callback.init() {
        Ok(x) => x,
        Err(_) => return Some(SendOrRecvStatus::Error),
    };
    let timeout_alarm = match timeout.set_alarm(timeout_delay) {
        Ok(x) => x,
        Err(_) => return Some(SendOrRecvStatus::Error),
    };

    // Trigger USB transmission.
    let result_code = syscalls::command(DRIVER_NUMBER, command_nr::TRANSMIT_OR_RECEIVE, 0, 0);
    if result_code.is_err() {
        return Some(SendOrRecvStatus::Error);
    }

    util::yieldk_for(|| status.get().is_some() || timeout_expired.get());

    // Cleanup alarm callback.
    match timeout.stop_alarm(timeout_alarm) {
        Ok(()) => (),
        Err(TockError::Command(CommandError {
            return_code: EALREADY,
            ..
        })) => {
            if !timeout_expired.get() {
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
    if status.get().is_none() {
        #[cfg(feature = "verbose_usb")]
        writeln!(Console::new(), "Cancelling USB transaction due to timeout").unwrap();
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

    status.get()
}
