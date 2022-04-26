trait Timer {
    fn start(milliseconds: u32) -> Self;
    fn has_elapsed(self) -> Option<Self>
    where
        Self: Sized;
}

use libtock_core::syscalls;

// see: https://github.com/tock/tock/blob/master/doc/syscalls/00000_alarm.md
mod command_nr {
    pub const _IS_DRIVER_AVAILABLE: usize = 0;
    pub const GET_CLOCK_FREQUENCY: usize = 1;
    pub const GET_CLOCK_VALUE: usize = 2;
    pub const _STOP_ALARM: usize = 3;
    pub const _SET_ALARM: usize = 4;
}
const DRIVER_NUMBER: usize = 0x00000;

lazy_static! {
    static ref CLOCK_FREQUENCY: usize =
        syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_FREQUENCY, 0, 0).unwrap_or(0);
}

struct LibtockAlarmTimer {
    start_tick: usize,
    milliseconds: u32,
}

fn wrapping_sub_u24(lhs: usize, rhs: usize) -> usize {
    lhs.wrapping_sub(rhs) & 0xffffff
}

impl Timer for LibtockAlarmTimer {
    fn start(milliseconds: u32) -> Self {
        let start_tick =
            syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_VALUE, 0, 0).unwrap_or(0);
        Self {
            start_tick,
            milliseconds,
        }
    }

    fn has_elapsed(self) -> Option<Self> {
        let cur_tick =
            syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_VALUE, 0, 0).unwrap_or(0);

        // TODO: handle 24 bits magic
        let delta_tick = wrapping_sub_u24(cur_tick, self.start_tick);
        if (delta_tick * 1000) / *CLOCK_FREQUENCY > self.milliseconds as usize {
            None
        } else {
            Some(self)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_wrapping_sub_u24() {
        // non-wrapping cases
        assert_eq!(wrapping_sub_u24(0, 0), 0);
        assert_eq!(wrapping_sub_u24(0xffffff, 0), 0xffffff);
        assert_eq!(wrapping_sub_u24(0xffffff, 0xffffff), 0);
        // wrapping cases
        assert_eq!(wrapping_sub_u24(0, 0xffffff), 1);
        assert_eq!(wrapping_sub_u24(0, 1), 0xffffff);
    }
}
