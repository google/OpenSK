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

use libtock_core::syscalls;

trait Timer: Sized {
    // start instantiate a Timer with a given length of time.
    fn start(milliseconds: u32) -> Self;
    // has_elapsed returns whether the Timer is elapsed or not. If it has elapsed, return None.
    fn has_elapsed(self) -> Option<Self>;
}

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
            syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_FREQUENCY, 0, 0).ok().unwrap();
        let start_tick =
            syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_VALUE, 0, 0).ok().unwrap();
        let delta_tick = (clock_frequency / 2).checked_mul(milliseconds as usize).unwrap() / 500;
        // this invariant is necessary for the test in has_elapsed to be correct
        assert!(delta_tick < 0x800000);
        let end_tick = wrapping_add_u24(start_tick, delta_tick);
        Self { end_tick }
    }

    fn has_elapsed(self) -> Option<Self> {
        let cur_tick =
            syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_VALUE, 0, 0).ok().unwrap();

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
