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

use core::marker::PhantomData;
use libtock_alarm::Alarm;
use libtock_drivers::result::FlexUnwrap;
use libtock_drivers::timer::Timer;
use libtock_platform::Syscalls;
use opensk::api::clock::Clock;

/// 56-bits timestamp (valid for 70k+ years)
#[derive(Clone, Copy, Debug, Default, PartialOrd, Ord, PartialEq, Eq)]
struct Timestamp {
    epoch: u32,
    tick: u32, // 24-bits (32kHz)
}

impl Timestamp {
    /// Adds (potentially more than 24 bit of) ticks to this timestamp.
    pub fn add_ticks(&mut self, ticks: u32) {
        // Saturating should never happen, but it fails gracefully.
        let sum = self.tick.saturating_add(ticks);
        self.epoch += sum >> 24;
        self.tick = sum & 0xff_ffff;
    }
}

#[derive(Default)]
pub struct TockTimer {
    deadline: Timestamp,
}

/// Clock that produces timers through Tock syscalls.
///
/// To guarantee correctness, you have to call any of its functions at least once per full tick
/// counter wrap. In our case, 24 bit ticks with a 32 kHz frequency wrap after 512 seconds. If you
/// can't guarantee to regularly create or check timers, call tickle at least every 8 minutes.
pub struct TockClock<S: Syscalls> {
    now: Timestamp,
    s: PhantomData<S>,
}

impl<S: Syscalls> Default for TockClock<S> {
    fn default() -> Self {
        TockClock {
            now: Timestamp::default(),
            s: PhantomData,
        }
    }
}

impl<S: Syscalls> TockClock<S> {
    /// Elapses timers before the clock wraps.
    ///
    /// Call this regularly to timeout reliably despite wrapping clock ticks.
    pub fn tickle(&mut self) {
        let cur_tick = Timer::<S>::get_ticks().flex_unwrap();
        if cur_tick < self.now.tick {
            self.now.epoch += 1;
        }
        self.now.tick = cur_tick;
    }
}

impl<S: Syscalls> Clock for TockClock<S> {
    type Timer = TockTimer;

    fn make_timer(&mut self, milliseconds: usize) -> Self::Timer {
        let milliseconds = milliseconds as u32;
        self.tickle();
        let clock_frequency = Alarm::<S>::get_frequency().ok().unwrap().0;
        let delta_tick = match milliseconds.checked_mul(clock_frequency) {
            Some(x) => x / 1000,
            // All CTAP timeouts are multiples of 100 so far. Worst case we timeout too early.
            None => (milliseconds / 100).saturating_mul(clock_frequency / 10),
        };
        let mut deadline = self.now;
        deadline.add_ticks(delta_tick);
        Self::Timer { deadline }
    }

    fn is_elapsed(&mut self, timer: &Self::Timer) -> bool {
        self.tickle();
        self.now >= timer.deadline
    }

    #[cfg(feature = "debug_ctap")]
    fn timestamp_us(&mut self) -> usize {
        let clock_frequency = Alarm::<S>::get_frequency().ok().unwrap().0;
        let total_ticks = 0x100_0000u64 * self.now.epoch as u64 + self.now.tick as u64;
        (total_ticks.wrapping_mul(1_000_000u64) / clock_frequency as u64) as usize
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_timestamp_add_ticks() {
        let mut timestamp = Timestamp::default();
        timestamp.add_ticks(1);
        let expected = Timestamp { epoch: 0, tick: 1 };
        assert_eq!(timestamp, expected);
        timestamp.add_ticks(0xff_ffff);
        let expected = Timestamp { epoch: 1, tick: 0 };
        assert_eq!(timestamp, expected);
        timestamp.add_ticks(0x100_0000);
        let expected = Timestamp { epoch: 2, tick: 0 };
        assert_eq!(timestamp, expected);
        timestamp.add_ticks(0x1ff_ffff);
        let expected = Timestamp {
            epoch: 3,
            tick: 0xff_ffff,
        };
        assert_eq!(timestamp, expected);
        timestamp.add_ticks(1);
        let expected = Timestamp { epoch: 4, tick: 0 };
        assert_eq!(timestamp, expected);
    }
}
