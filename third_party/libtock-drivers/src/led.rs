use crate::result::{OtherError, TockError, TockResult};
use libtock_core::syscalls;

const DRIVER_NUMBER: usize = 0x00002;

mod command_nr {
    pub const COUNT: usize = 0;
    pub const ON: usize = 1;
    pub const OFF: usize = 2;
    pub const TOGGLE: usize = 3;
}

pub struct Led {
    led_num: usize,
}

pub fn count() -> TockResult<usize> {
    let count = syscalls::command(DRIVER_NUMBER, command_nr::COUNT, 0, 0)?;
    Ok(count)
}

pub fn get(led_num: usize) -> TockResult<Led> {
    let led_count = count()?;
    if led_num < led_count {
        Ok(Led { led_num })
    } else {
        Err(TockError::Other(OtherError::OutOfRange))
    }
}

pub fn all() -> TockResult<LedIter> {
    let led_count = count()?;
    Ok(LedIter {
        curr_led: 0,
        led_count,
    })
}

impl Led {
    pub fn set_state(&self, state: bool) -> TockResult<()> {
        if state {
            self.on()
        } else {
            self.off()
        }
    }

    pub fn on(&self) -> TockResult<()> {
        syscalls::command(DRIVER_NUMBER, command_nr::ON, self.led_num, 0)?;
        Ok(())
    }

    pub fn off(&self) -> TockResult<()> {
        syscalls::command(DRIVER_NUMBER, command_nr::OFF, self.led_num, 0)?;
        Ok(())
    }

    pub fn toggle(&self) -> TockResult<()> {
        syscalls::command(DRIVER_NUMBER, command_nr::TOGGLE, self.led_num, 0)?;
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct LedIter {
    curr_led: usize,
    led_count: usize,
}

impl Iterator for LedIter {
    type Item = Led;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr_led < self.led_count {
            let item = Led {
                led_num: self.curr_led,
            };
            self.curr_led += 1;
            Some(item)
        } else {
            None
        }
    }
}
