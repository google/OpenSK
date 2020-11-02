use crate::result::TockResult;
use crate::util;
use core::cell::Cell;
use core::mem;
use libtock_core::{callback, syscalls};

const DRIVER_NUMBER: usize = 0x30003;

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

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct RecvOp {
    pub result_code: usize,
    pub recv_amount: usize,
}

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
    pub fn receive(buf: &mut [u8; 256]) -> TockResult<RecvOp> {
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
    pub fn transmit(buf: &mut [u8], amount: usize) -> TockResult<usize> {
        let result = syscalls::allow(DRIVER_NUMBER, allow_nr::TRANSMIT, buf)?;
        // set callback with 1 argument, to receive ReturnCode
        let result_code = Cell::new(None);
        let mut callback = |result| result_code.set(Some(result));
        let subscription = syscalls::subscribe::<callback::Identity1Consumer, _>(
            DRIVER_NUMBER,
            subscribe_nr::TRANSMIT,
            &mut callback,
        )?;
        syscalls::command(DRIVER_NUMBER, command_nr::TRANSMIT, amount, 0)?;
        util::yieldk_for(|| result_code.get().is_some());
        mem::drop(subscription);
        mem::drop(result);
        Ok(result_code.get().unwrap())
    }
}
