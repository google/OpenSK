use crate::util;
use core::cell::Cell;
use libtock_core::{callback, syscalls};

const DRIVER_NUMBER: usize = 0x30003;

mod command_nr {
    pub const TRANSMIT: usize = 1;
    pub const RECEIVE: usize = 2;
    pub const EMULATE: usize = 3;
    pub const CONFIGURE: usize = 4;
}

mod subscribe_nr {
    pub const TRANSMIT: usize = 1;
    pub const RECEIVE: usize = 2;
    pub const SELECT: usize = 3;
}

mod allow_nr {
    pub const TRANSMIT: usize = 1;
    pub const RECEIVE: usize = 2;
}

pub fn enable_emulation() {
    emulate(true);
}

pub fn disable_emulation() {
    emulate(false);
}

pub fn emulate(enabled: bool) -> bool {
    let result_code = syscalls::command(DRIVER_NUMBER, command_nr::EMULATE, enabled as usize, 0);
    if result_code.is_err() {
        return false;
    }

    true
}

pub fn selected() -> bool {
    let is_selected = Cell::new(false);
    let mut is_selected_alarm = || is_selected.set(true);
    let subscription = syscalls::subscribe::<callback::Identity0Consumer, _>(
        DRIVER_NUMBER,
        subscribe_nr::SELECT,
        &mut is_selected_alarm,
    );
    if subscription.is_err() {
        return false;
    }

    util::yieldk_for(|| is_selected.get());
    true
}

pub fn configure(tag_type: u8) -> bool {
    let result_code = syscalls::command(DRIVER_NUMBER, command_nr::CONFIGURE, tag_type as usize, 0);
    if result_code.is_err() {
        return false;
    }

    true
}

pub fn receive(buf: &mut [u8]) -> bool {
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

pub fn transmit(buf: &mut [u8]) -> bool {
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
