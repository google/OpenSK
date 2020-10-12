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

pub const TX_BUFFER_SIZE: usize = 256;
pub const RX_BUFFER_SIZE: usize = 256;

pub struct NfcTag {
    tx_buffer: [u8; BUFFER_SIZE],
    rx_buffer: [u8; BUFFER_SIZE],
    tag_type: u8,
}

impl NfcTag {
    pub fn new() -> Console {
        Console {
            tx_buffer: [0; TX_BUFFER_SIZE],
            tx_buffer: [0; RX_BUFFER_SIZE],
            tag_type: 0,
        }
    }

    pub fn set_tag_type(&mut self, type: u8) {
        self.tag_type = type;
    }

    pub fn selected(&self) -> bool {
        let is_selected = Cell::new(false);
        let mut is_selected_alarm = || is_selected.set(true);
        let subscription = syscalls::subscribe::<callback::Identity0Consumer, _>(
            DRIVER_NUMBER,
            subscribe_nr::SELECT,
            &mut is_selected_alarm,
        );
        if subscription.is_err() {
            return;
        }

        util::yieldk_for(|| is_selected.get());
        true
    }

    pub fn receive(&self) {

    }
}
