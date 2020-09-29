use crate::util;
use core::cell::Cell;
use libtock_core::{callback, syscalls};

const DRIVER_NUMBER: usize = 0x40001;

mod command_nr {
    pub const REQUEST_RNG: usize = 1;
}

mod subscribe_nr {
    pub const BUFFER_FILLED: usize = 0;
}

mod allow_nr {
    pub const SHARE_BUFFER: usize = 0;
}

pub fn fill_buffer(buf: &mut [u8]) -> bool {
    let buf_len = buf.len();

    let result = syscalls::allow(DRIVER_NUMBER, allow_nr::SHARE_BUFFER, buf);
    if result.is_err() {
        return false;
    }

    let is_filled = Cell::new(false);
    let mut is_filled_alarm = || is_filled.set(true);
    let subscription = syscalls::subscribe::<callback::Identity0Consumer, _>(
        DRIVER_NUMBER,
        subscribe_nr::BUFFER_FILLED,
        &mut is_filled_alarm,
    );
    if subscription.is_err() {
        return false;
    }

    let result_code = syscalls::command(DRIVER_NUMBER, command_nr::REQUEST_RNG, buf_len, 0);
    if result_code.is_err() {
        return false;
    }

    util::yieldk_for(|| is_filled.get());
    true
}
