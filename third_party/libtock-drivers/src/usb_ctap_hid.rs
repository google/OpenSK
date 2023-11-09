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

use crate::result::{OutOfRangeError, TockError, TockResult};
use crate::timer::Duration;
use crate::util::Util;
use crate::{timer, util};
use core::cell::Cell;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
#[cfg(feature = "debug_ctap")]
use libtock_console::Console;
use libtock_platform as platform;
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use platform::share::Handle;
use platform::subscribe::OneId;
use platform::{AllowRo, AllowRw, Subscribe, Upcall};

const DRIVER_NUMBER: u32 = 0x20009;

/// Ids for commands
mod command_nr {
    pub const CHECK: u32 = 0;
    pub const CONNECT: u32 = 1;
    pub const TRANSMIT: u32 = 2;
    pub const RECEIVE: u32 = 3;
    pub const TRANSMIT_OR_RECEIVE: u32 = 4;
    pub const CANCEL: u32 = 5;
}

/// Ids for subscribe numbers
mod subscribe_nr {
    pub const TRANSMIT: u32 = 0;
    pub const RECEIVE: u32 = 1;
}

mod ro_allow_nr {
    pub const TRANSMIT: u32 = 0;
}

mod rw_allow_nr {
    pub const RECEIVE: u32 = 0;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SendOrRecvStatus {
    Timeout,
    Sent,
    Received(u32),
}

pub trait Config:
    platform::allow_ro::Config + platform::allow_rw::Config + platform::subscribe::Config
{
}

impl<T: platform::allow_ro::Config + platform::allow_rw::Config + platform::subscribe::Config>
    Config for T
{
}

pub struct UsbCtapHidListener<F: Fn(u32, u32)>(pub F);

impl<const SUB_NUM: u32, F: Fn(u32, u32)> Upcall<OneId<DRIVER_NUMBER, SUB_NUM>>
    for UsbCtapHidListener<F>
{
    fn upcall(&self, direction: u32, endpoint: u32, _: u32) {
        self.0(direction, endpoint)
    }
}
pub struct UsbCtapHid<S: Syscalls, C: Config = DefaultConfig>(S, C);

impl<S: Syscalls, C: Config> UsbCtapHid<S, C> {
    /// Register an listener to call with the arguments.
    ///
    /// Only one listener can be registered at a time.
    fn register_listener<'share, const SUB_NUM: u32, F: Fn(u32, u32)>(
        listener: &'share UsbCtapHidListener<F>,
        subscribe: Handle<Subscribe<'share, S, DRIVER_NUMBER, SUB_NUM>>,
    ) -> Result<(), ErrorCode> {
        S::subscribe::<_, _, C, DRIVER_NUMBER, SUB_NUM>(subscribe, listener)
    }

    /// Unregisters the listener.
    ///
    /// Can be called even if there was no previously registered listener.
    fn unregister_listener(subscribe_num: u32) {
        S::unsubscribe(DRIVER_NUMBER, subscribe_num);
    }

    /// Checks whether the driver is available and tries to setup the connection.
    pub fn setup() -> bool {
        let result =
            S::command(DRIVER_NUMBER, command_nr::CHECK, 0, 0).to_result::<(), ErrorCode>();
        if result.is_err() {
            return false;
        }

        let result =
            S::command(DRIVER_NUMBER, command_nr::CONNECT, 0, 0).to_result::<(), ErrorCode>();
        if result.is_err() {
            return false;
        }

        true
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
            Console::<S>::writer(),
            "Receiving packet with timeout of {} ms",
            timeout_delay.ms(),
        )
        .unwrap();

        let result = Self::recv_with_timeout_detail(buf, timeout_delay);

        #[cfg(feature = "verbose_usb")]
        if let Ok(SendOrRecvStatus::Received(endpoint)) = result {
            writeln!(
                Console::<S>::writer(),
                "Received packet = {:02x?} on endpoint {}",
                buf as &[u8],
                endpoint as u8,
            )
            .unwrap();
        }

        result
    }

    /// Sends a packet to a given endpoint.
    ///
    /// Returns the transmission status.
    pub fn send(
        buf: &[u8; 64],
        timeout_delay: Duration<isize>,
        endpoint: u32,
    ) -> TockResult<SendOrRecvStatus> {
        #[cfg(feature = "verbose_usb")]
        writeln!(
            Console::<S>::writer(),
            "Sending packet on endpoint {} with timeout of {} ms = {:02x?}",
            endpoint,
            timeout_delay.ms(),
            buf as &[u8],
        )
        .unwrap();

        Self::send_detail(buf, timeout_delay, endpoint)
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
        endpoint: u32,
    ) -> TockResult<SendOrRecvStatus> {
        #[cfg(feature = "verbose_usb")]
        writeln!(
            Console::<S>::writer(),
            "Sending packet with timeout of {} ms = {:02x?}",
            timeout_delay.ms(),
            buf as &[u8]
        )
        .unwrap();

        let result = Self::send_or_recv_with_timeout_detail(buf, timeout_delay, endpoint);

        #[cfg(feature = "verbose_usb")]
        if let Ok(SendOrRecvStatus::Received(received_endpoint)) = result {
            writeln!(
                Console::<S>::writer(),
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
        let status: Cell<Option<SendOrRecvStatus>> = Cell::new(None);

        let alarm = UsbCtapHidListener(|direction, endpoint| match direction {
            subscribe_nr::RECEIVE => status.set(Some(SendOrRecvStatus::Received(endpoint))),
            // Unknown direction or "transmitted" sent by the kernel
            _ => status.set(None),
        });

        let mut timeout_callback =
            timer::with_callback::<S, C, _>(|_| status.set(Some(SendOrRecvStatus::Timeout)));
        let status = share::scope::<
            (
                AllowRw<_, DRIVER_NUMBER, { rw_allow_nr::RECEIVE }>,
                Subscribe<_, DRIVER_NUMBER, { subscribe_nr::RECEIVE }>,
                Subscribe<S, { timer::DRIVER_NUM }, { timer::subscribe::CALLBACK }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow, subscribe_recv, subscribe_timer) = handle.split();
            S::allow_rw::<C, DRIVER_NUMBER, { rw_allow_nr::RECEIVE }>(allow, buf)?;

            Self::register_listener::<{ subscribe_nr::RECEIVE }, _>(&alarm, subscribe_recv)?;

            let mut timeout = timeout_callback.init()?;
            timeout_callback.enable(subscribe_timer)?;
            timeout
                .set_alarm(timeout_delay)
                .map_err(|_| ErrorCode::Fail)?;

            S::command(DRIVER_NUMBER, command_nr::RECEIVE, 0, 0).to_result::<(), ErrorCode>()?;

            Util::<S>::yieldk_for(|| status.get().is_some());
            Self::unregister_listener(subscribe_nr::RECEIVE);

            let status = match status.get() {
                Some(status) => Ok::<SendOrRecvStatus, TockError>(status),
                None => Err(OutOfRangeError.into()),
            }?;

            // Cleanup alarm callback.
            match timeout.stop_alarm() {
                Ok(()) => (),
                Err(TockError::Command(ErrorCode::Already)) => {
                    if matches!(status, SendOrRecvStatus::Timeout) {
                        #[cfg(feature = "debug_ctap")]
                        write!(Console::<S>::writer(), ".").unwrap();
                    }
                }
                Err(_e) => {
                    #[cfg(feature = "debug_ctap")]
                    panic!("Unexpected error when stopping alarm: {:?}", _e);
                    #[cfg(not(feature = "debug_ctap"))]
                    panic!("Unexpected error when stopping alarm: <error is only visible with the debug_ctap feature>");
                }
            }
            Ok::<SendOrRecvStatus, TockError>(status)
        });

        // Cancel USB transaction if necessary.
        if matches!(status, Ok(SendOrRecvStatus::Timeout)) {
            #[cfg(feature = "verbose_usb")]
            writeln!(
                Console::<S>::writer(),
                "Cancelling USB receive due to timeout"
            )
            .unwrap();
            let result =
                S::command(DRIVER_NUMBER, command_nr::CANCEL, 0, 0).to_result::<(), ErrorCode>();
            match result {
                // - SUCCESS means that we successfully cancelled the transaction.
                // - EALREADY means that the transaction was already completed.
                Ok(_) | Err(ErrorCode::Already) => (),
                // - EBUSY means that the transaction is in progress.
                Err(ErrorCode::Busy) => {
                    // The app should wait for it, but it may never happen if the remote app crashes.
                    // We just return to avoid a deadlock.
                    #[cfg(feature = "debug_ctap")]
                    writeln!(Console::<S>::writer(), "Couldn't cancel the USB receive").unwrap();
                }
                Err(e) => panic!("Unexpected error when cancelling USB receive: {:?}", e),
            }
        }

        status
    }

    fn send_detail(
        buf: &[u8; 64],
        timeout_delay: Duration<isize>,
        endpoint: u32,
    ) -> TockResult<SendOrRecvStatus> {
        let status: Cell<Option<SendOrRecvStatus>> = Cell::new(None);
        let alarm = UsbCtapHidListener(|direction, _| {
            let option = match direction {
                subscribe_nr::TRANSMIT => Some(SendOrRecvStatus::Sent),
                _ => None,
            };
            status.set(option);
        });

        let mut timeout_callback =
            timer::with_callback::<S, C, _>(|_| status.set(Some(SendOrRecvStatus::Timeout)));
        let status = share::scope::<
            (
                AllowRo<_, DRIVER_NUMBER, { ro_allow_nr::TRANSMIT }>,
                Subscribe<_, DRIVER_NUMBER, { subscribe_nr::TRANSMIT }>,
                Subscribe<S, { timer::DRIVER_NUM }, { timer::subscribe::CALLBACK }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow, subscribe_send, subscribe_timer) = handle.split();

            S::allow_ro::<C, DRIVER_NUMBER, { ro_allow_nr::TRANSMIT }>(allow, buf)?;

            Self::register_listener::<{ subscribe_nr::TRANSMIT }, _>(&alarm, subscribe_send)?;

            let mut timeout = timeout_callback.init()?;
            timeout_callback.enable(subscribe_timer)?;
            timeout
                .set_alarm(timeout_delay)
                .map_err(|_| ErrorCode::Fail)?;

            S::command(DRIVER_NUMBER, command_nr::TRANSMIT, endpoint as u32, 0)
                .to_result::<(), ErrorCode>()?;

            util::Util::<S>::yieldk_for(|| status.get().is_some());
            Self::unregister_listener(subscribe_nr::TRANSMIT);

            let status = match status.get() {
                Some(status) => Ok::<SendOrRecvStatus, TockError>(status),
                None => Err(OutOfRangeError.into()),
            }?;

            // Cleanup alarm callback.
            match timeout.stop_alarm() {
                Ok(()) => (),
                Err(TockError::Command(ErrorCode::Already)) => {
                    if matches!(status, SendOrRecvStatus::Timeout) {
                        #[cfg(feature = "debug_ctap")]
                        writeln!(
                            Console::<S>::writer(),
                            "The send timeout already expired, but the callback wasn't executed."
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
            Ok::<SendOrRecvStatus, TockError>(status)
        });

        // Cancel USB transaction if necessary.
        if matches!(status, Ok(SendOrRecvStatus::Timeout)) {
            #[cfg(feature = "verbose_usb")]
            writeln!(
                Console::<S>::writer(),
                "Cancelling USB transmit due to timeout"
            )
            .unwrap();
            let result = S::command(DRIVER_NUMBER, command_nr::CANCEL, endpoint as u32, 0)
                .to_result::<(), ErrorCode>();
            match result {
                // - SUCCESS means that we successfully cancelled the transaction.
                // - EALREADY means that the transaction was already completed.
                Ok(_) | Err(ErrorCode::Already) => (),
                // - EBUSY means that the transaction is in progress.
                Err(ErrorCode::Busy) => {
                    // The app should wait for it, but it may never happen if the remote app crashes.
                    // We just return to avoid a deadlock.
                    #[cfg(feature = "debug_ctap")]
                    writeln!(Console::<S>::writer(), "Couldn't cancel the USB receive").unwrap();
                }
                Err(e) => panic!("Unexpected error when cancelling USB receive: {:?}", e),
            }
        }

        status
    }

    fn send_or_recv_with_timeout_detail(
        buf: &mut [u8; 64],
        timeout_delay: Duration<isize>,
        endpoint: u32,
    ) -> TockResult<SendOrRecvStatus> {
        let status: Cell<Option<SendOrRecvStatus>> = Cell::new(None);
        let alarm = UsbCtapHidListener(|direction, endpoint| {
            let option = match direction {
                subscribe_nr::TRANSMIT => Some(SendOrRecvStatus::Sent),
                subscribe_nr::RECEIVE => Some(SendOrRecvStatus::Received(endpoint)),
                _ => None,
            };
            status.set(option);
        });
        let mut recv_buf = [0; 64];

        // init the time-out callback but don't enable it yet
        let mut timeout_callback = timer::with_callback::<S, C, _>(|_| {
            status.set(Some(SendOrRecvStatus::Timeout));
        });
        let status = share::scope::<
            (
                AllowRo<_, DRIVER_NUMBER, { ro_allow_nr::TRANSMIT }>,
                AllowRw<_, DRIVER_NUMBER, { rw_allow_nr::RECEIVE }>,
                Subscribe<_, DRIVER_NUMBER, { subscribe_nr::TRANSMIT }>,
                Subscribe<_, DRIVER_NUMBER, { subscribe_nr::RECEIVE }>,
                Subscribe<_, { timer::DRIVER_NUM }, { timer::subscribe::CALLBACK }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow_ro, allow_rw, sub_send, sub_recv, sub_timer) = handle.split();

            S::allow_ro::<C, DRIVER_NUMBER, { ro_allow_nr::TRANSMIT }>(allow_ro, buf)?;
            S::allow_rw::<C, DRIVER_NUMBER, { rw_allow_nr::RECEIVE }>(allow_rw, &mut recv_buf)?;

            Self::register_listener::<{ subscribe_nr::TRANSMIT }, _>(&alarm, sub_send)?;
            Self::register_listener::<{ subscribe_nr::RECEIVE }, _>(&alarm, sub_recv)?;

            let mut timeout = timeout_callback.init()?;
            timeout_callback.enable(sub_timer)?;
            timeout.set_alarm(timeout_delay)?;

            // Trigger USB transmission.
            S::command(
                DRIVER_NUMBER,
                command_nr::TRANSMIT_OR_RECEIVE,
                endpoint as u32,
                0,
            )
            .to_result::<(), ErrorCode>()?;

            util::Util::<S>::yieldk_for(|| status.get().is_some());
            Self::unregister_listener(subscribe_nr::TRANSMIT);
            Self::unregister_listener(subscribe_nr::RECEIVE);

            let status = match status.get() {
                Some(status) => Ok::<SendOrRecvStatus, TockError>(status),
                None => Err(OutOfRangeError.into()),
            }?;

            // Cleanup alarm callback.
            match timeout.stop_alarm() {
                Ok(_) => (),
                Err(TockError::Command(ErrorCode::Already)) => {
                    if matches!(status, SendOrRecvStatus::Timeout) {
                        #[cfg(feature = "debug_ctap")]
                        writeln!(
                            Console::<S>::writer(),
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
            Ok::<SendOrRecvStatus, TockError>(status)
        });

        // Cancel USB transaction if necessary.
        if matches!(status, Ok(SendOrRecvStatus::Timeout)) {
            #[cfg(feature = "verbose_usb")]
            writeln!(
                Console::<S>::writer(),
                "Cancelling USB transaction due to timeout"
            )
            .unwrap();
            let result =
                S::command(DRIVER_NUMBER, command_nr::CANCEL, 0, 0).to_result::<(), ErrorCode>();
            match result {
                // - SUCCESS means that we successfully cancelled the transaction.
                // - EALREADY means that the transaction was already completed.
                Ok(_) | Err(ErrorCode::Already) => (),
                // - EBUSY means that the transaction is in progress.
                Err(ErrorCode::Busy) => {
                    // The app should wait for it, but it may never happen if the remote app crashes.
                    // We just return to avoid a deadlock.
                    #[cfg(feature = "debug_ctap")]
                    writeln!(Console::<S>::writer(), "Couldn't cancel the transaction").unwrap();
                }
                Err(e) => panic!("Unexpected error when cancelling USB transaction: {:?}", e),
            }
            #[cfg(feature = "debug_ctap")]
            writeln!(Console::<S>::writer(), "Cancelled USB transaction!").unwrap();
        }

        if matches!(status, Ok(SendOrRecvStatus::Received(_))) {
            buf.copy_from_slice(&recv_buf);
        }
        status
    }
}
