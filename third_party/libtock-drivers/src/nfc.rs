use crate::result::TockResult;
use crate::util;
use core::cell::Cell;
use libtock_platform as platform;
use platform::{share, AllowRo, AllowRw, DefaultConfig, ErrorCode, Subscribe, Syscalls};

const DRIVER_NUMBER: u32 = 0x30003;

mod command_nr {
    pub const CHECK: u32 = 0;
    pub const TRANSMIT: u32 = 1;
    pub const RECEIVE: u32 = 2;
    pub const EMULATE: u32 = 3;
    pub const CONFIGURE: u32 = 4;
}

mod subscribe_nr {
    pub const TRANSMIT: u32 = 1;
    pub const RECEIVE: u32 = 2;
}

mod allow_nr {
    pub const TRANSMIT: u32 = 1;
    pub const RECEIVE: u32 = 2;
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct RecvOp {
    pub result_code: u32,
    pub recv_amount: u32,
}

pub trait Config:
    platform::allow_rw::Config + platform::allow_ro::Config + platform::subscribe::Config
{
}
impl<T: platform::allow_rw::Config + platform::allow_ro::Config + platform::subscribe::Config>
    Config for T
{
}

pub struct NfcTag<S: Syscalls, C: Config = DefaultConfig>(S, C);

impl<S: Syscalls, C: Config> NfcTag<S, C> {
    /// Check the existence of an NFC driver.
    pub fn setup() -> bool {
        S::command(DRIVER_NUMBER, command_nr::CHECK, 0, 0).is_success()
    }

    pub fn enable_emulation() -> bool {
        NfcTag::<S, C>::emulate(true)
    }

    pub fn disable_emulation() -> bool {
        NfcTag::<S, C>::emulate(false)
    }

    fn emulate(enabled: bool) -> bool {
        S::command(DRIVER_NUMBER, command_nr::EMULATE, enabled as u32, 0).is_success()
    }

    /// Configure the tag type command.
    pub fn configure(tag_type: u8) -> bool {
        S::command(DRIVER_NUMBER, command_nr::CONFIGURE, tag_type as u32, 0).is_success()
    }

    /// 1. Share with the driver a buffer.
    /// 2. Subscribe to having a successful receive callback.
    /// 3. Issue the request for reception.
    pub fn receive(buf: &mut [u8; 256]) -> TockResult<RecvOp> {
        // set callback with 2 arguments, to receive ReturnCode and RX Amount
        let recv: Cell<Option<(u32, u32)>> = Cell::new(None);
        share::scope::<
            (
                AllowRw<_, DRIVER_NUMBER, { allow_nr::RECEIVE }>,
                Subscribe<_, DRIVER_NUMBER, { subscribe_nr::RECEIVE }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow_rw, subscribe) = handle.split();
            S::allow_rw::<C, DRIVER_NUMBER, { allow_nr::RECEIVE }>(allow_rw, buf)?;
            S::subscribe::<_, _, C, DRIVER_NUMBER, { subscribe_nr::RECEIVE }>(subscribe, &recv)?;
            S::command(DRIVER_NUMBER, command_nr::RECEIVE, 0, 0).to_result::<(), ErrorCode>()?;

            util::Util::<S>::yieldk_for(|| recv.get().is_some());

            let (result_code, recv_amount) = recv.get().unwrap();
            let recv_op = RecvOp {
                result_code,
                recv_amount,
            };
            Ok(recv_op)
        })
    }

    /// 1. Share with the driver a buffer containing the app's reply.
    /// 2. Subscribe to having a successful transmission callback.
    /// 3. Issue the request for transmitting.
    pub fn transmit(buf: &mut [u8], amount: u32) -> TockResult<u32> {
        // set callback with 1 argument, to receive ReturnCode
        let result: Cell<Option<(u32,)>> = Cell::new(None);
        share::scope::<
            (
                AllowRo<_, DRIVER_NUMBER, { allow_nr::TRANSMIT }>,
                Subscribe<_, DRIVER_NUMBER, { subscribe_nr::TRANSMIT }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow_ro, subscribe) = handle.split();
            S::allow_ro::<C, DRIVER_NUMBER, { allow_nr::TRANSMIT }>(allow_ro, buf)?;

            S::subscribe::<_, _, C, DRIVER_NUMBER, { subscribe_nr::TRANSMIT }>(subscribe, &result)?;
            S::command(DRIVER_NUMBER, command_nr::TRANSMIT, amount, 0)
                .to_result::<(), ErrorCode>()?;

            util::Util::<S>::yieldk_for(|| result.get().is_some());

            Ok(result.get().unwrap().0)
        })
    }
}
