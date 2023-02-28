// Copyright 2022-2023 Google LLC
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

use crate::api::clock::Clock;
use libtock_core::syscalls;

mod command_nr {
    pub const GET_CLOCK_FREQUENCY: usize = 1;
    pub const GET_CLOCK_VALUE: usize = 2;
}

const DRIVER_NUMBER: usize = 0x00000;

#[derive(Default)]
pub struct TockTimer {
    end_epoch: usize,
    end_tick: usize,
}

/// Returns a tupel of u24 sum and how many times the sum wraps.
fn add_to_u24_with_wraps(lhs: usize, rhs: usize) -> (usize, usize) {
    // Saturating should never happen, but it fails gracefully.
    let sum = lhs.saturating_add(rhs);
    (sum & 0xffffff, sum >> 24)
}

/// Clock that produces timers through Tock syscalls.
///
/// To guarantee correctness, you have to call any of its functions at least once per full tick
/// counter wrap. In our case, 24 bit ticks with a 32 kHz frequency wrap after 512 seconds. If you
/// can't guarantee to regularly create or check timers, call tickle at least every 8 minutes.
#[derive(Default)]
pub struct TockClock {
    epoch: usize,
    tick: usize,
}

impl TockClock {
    /// Elapses timers before the clock wraps.
    ///
    /// Call this regularly to timeout reliably despite wrapping clock ticks.
    pub fn tickle(&mut self) {
        let cur_tick = syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_VALUE, 0, 0)
            .ok()
            .unwrap();
        if cur_tick < self.tick {
            self.epoch += 1;
        }
        self.tick = cur_tick;
    }
}

impl Clock for TockClock {
    type Timer = TockTimer;

    fn make_timer(&mut self, milliseconds: usize) -> Self::Timer {
        self.tickle();
        let clock_frequency =
            syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_FREQUENCY, 0, 0)
                .ok()
                .unwrap();
        let delta_tick = match milliseconds.checked_mul(clock_frequency) {
            Some(x) => x / 1000,
            // All CTAP timeouts are multiples of 100 so far. Worst case we timeout too early.
            None => (milliseconds / 100).saturating_mul(clock_frequency / 10),
        };
        let (end_tick, passed_epochs) = add_to_u24_with_wraps(self.tick, delta_tick);
        // Epoch wraps after thousands of years, so we don't mind.
        let end_epoch = self.epoch + passed_epochs;
        Self::Timer {
            end_epoch,
            end_tick,
        }
    }

    fn is_elapsed(&mut self, timer: &Self::Timer) -> bool {
        self.tickle();
        (self.epoch, self.tick) >= (timer.end_epoch, timer.end_tick)
    }

    #[cfg(feature = "debug_ctap")]
    fn timestamp_us(&mut self) -> usize {
        let clock_frequency =
            syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_FREQUENCY, 0, 0)
                .ok()
                .unwrap();
        let total_ticks = 0x100_0000 * self.epoch + self.tick;
        total_ticks * 1_000_000 / clock_frequency
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_add_to_u24_with_wraps() {
        // non-wrapping cases
        assert_eq!(add_to_u24_with_wraps(0, 0), (0, 0));
        assert_eq!(add_to_u24_with_wraps(0xffffff, 0), (0xffffff, 0));
        assert_eq!(add_to_u24_with_wraps(0, 0xffffff), (0xffffff, 0));
        // wrapping cases
        assert_eq!(add_to_u24_with_wraps(1, 0xffffff), (0, 1));
        assert_eq!(add_to_u24_with_wraps(0xffffff, 0xffffff), (0xfffffe, 1));
        assert_eq!(add_to_u24_with_wraps(0, 0x1000000), (0, 1));
        assert_eq!(add_to_u24_with_wraps(0, 0x2000000), (0, 2));
        assert_eq!(add_to_u24_with_wraps(0xffffff, 0x2ffffff), (0xfffffe, 3));
    }
}
