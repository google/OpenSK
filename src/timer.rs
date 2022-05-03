trait Timer: Sized {
    fn start(milliseconds: u32) -> Self;
    fn has_elapsed(self) -> Option<Self>;
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

struct LibtockAlarmTimer {
    end_tick: usize,
}

fn wrapping_add_u24(lhs: usize, rhs: usize) -> usize {
    lhs.wrapping_add(rhs) & 0xffffff
}
fn wrapping_sub_u24(lhs: usize, rhs: usize) -> usize {
    lhs.wrapping_sub(rhs) & 0xffffff
}

impl Timer for LibtockAlarmTimer {
    fn start(milliseconds: u32) -> Self {
        let clock_frequency =
            syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_FREQUENCY, 0, 0).unwrap_or(0);
        let start_tick =
            syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_VALUE, 0, 0).unwrap_or(0);
        // 32 bits inverted divisor for 1/1000 ( ceil((2^32) / 1000) ), so that (x * INV_DIV) >> 32 ≈ x / 1000
        const INV_DIV: u64 = 4294968;
        let delta_tick = ((clock_frequency as u64 * milliseconds as u64 * INV_DIV) >> 32) as usize;
        // this invariant is necessary for the test in has_elapsed to be correct
        assert!(delta_tick < 0x800000);
        let end_tick = wrapping_add_u24(start_tick, delta_tick);
        Self { end_tick }
    }

    fn has_elapsed(self) -> Option<Self> {
        let cur_tick =
            syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_VALUE, 0, 0).unwrap_or(0);

        if wrapping_sub_u24(self.end_tick, cur_tick) < 0x800000 {
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
