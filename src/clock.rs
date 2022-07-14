// Copyright 2022 Google LLC
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

#[cfg(not(feature = "std"))]
use alloc::fmt;
use embedded_time::duration::Milliseconds;
pub use embedded_time::Clock;
#[cfg(not(feature = "std"))]
use libtock_drivers::result::FlexUnwrap;

#[cfg(not(feature = "std"))]
pub struct LibtockClock<const CLOCK_FREQUENCY: u32>(libtock_drivers::timer::Timer<'static>);
#[cfg(not(feature = "std"))]
impl<const CLOCK_FREQUENCY: u32> LibtockClock<CLOCK_FREQUENCY> {
    pub fn new() -> Self {
        let boxed_cb = alloc::boxed::Box::new(libtock_drivers::timer::with_callback(|_, _| {}));
        let timer = alloc::boxed::Box::leak(boxed_cb).init().flex_unwrap();
        Self(timer)
    }
}
#[cfg(not(feature = "std"))]
impl<const CLOCK_FREQUENCY: u32> fmt::Debug for LibtockClock<CLOCK_FREQUENCY> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LibtockClock")
            .field("CLOCK_FREQUENCY", &CLOCK_FREQUENCY)
            .finish()
    }
}

pub const KEEPALIVE_DELAY_MS: ClockInt = 100;
pub const KEEPALIVE_DELAY: Milliseconds<ClockInt> = Milliseconds(KEEPALIVE_DELAY_MS);

#[cfg(target_pointer_width = "32")]
pub type ClockInt = u32;
#[cfg(target_pointer_width = "64")]
pub type ClockInt = u64;

#[cfg(not(feature = "std"))]
impl<const CLOCK_FREQUENCY: u32> embedded_time::Clock for LibtockClock<CLOCK_FREQUENCY> {
    // TODO: Implement and use a 24-bits TimeInt for Nordic
    type T = ClockInt;

    const SCALING_FACTOR: embedded_time::fraction::Fraction =
        <embedded_time::fraction::Fraction>::new(1, CLOCK_FREQUENCY);

    fn try_now(&self) -> Result<embedded_time::Instant<Self>, embedded_time::clock::Error> {
        let timer = &self.0;
        let now = timer.get_current_clock().flex_unwrap();
        Ok(embedded_time::Instant::new(now.num_ticks() as Self::T))
    }
}

#[cfg(not(feature = "std"))]
pub type CtapClock = LibtockClock<32768>;
#[cfg(feature = "std")]
pub type CtapClock = TestClock;

pub fn new_clock() -> CtapClock {
    CtapClock::new()
}

pub type CtapInstant = embedded_time::Instant<CtapClock>;

#[cfg(feature = "std")]
pub const TEST_CLOCK_FREQUENCY_HZ: u32 = 32768;

#[cfg(feature = "std")]
#[derive(Default, Clone, Copy, Debug)]
pub struct TestClock;
#[cfg(feature = "std")]
impl TestClock {
    pub fn new() -> Self {
        TestClock
    }
}

#[cfg(feature = "std")]
impl embedded_time::Clock for TestClock {
    type T = u64;
    const SCALING_FACTOR: embedded_time::fraction::Fraction =
        <embedded_time::fraction::Fraction>::new(1, TEST_CLOCK_FREQUENCY_HZ);

    fn try_now(&self) -> Result<embedded_time::Instant<Self>, embedded_time::clock::Error> {
        Ok(embedded_time::Instant::new(0))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use embedded_time::duration::{Milliseconds, Seconds};

    #[test]
    fn test_checked_add() {
        let now = CtapInstant::new(0);
        assert_eq!(
            now.checked_add(Seconds::new(1 as ClockInt)),
            Some(CtapInstant::new(TEST_CLOCK_FREQUENCY_HZ as ClockInt))
        );
        assert_eq!(
            now.checked_add(Seconds::new(1 as ClockInt)),
            now.checked_add(Milliseconds::new(1000 as ClockInt))
        );
    }

    #[test]
    fn test_checked_add_overflow() {
        assert_eq!(
            CtapInstant::new(u64::MAX).checked_add(Seconds::new(1 as ClockInt)),
            Some(CtapInstant::new(TEST_CLOCK_FREQUENCY_HZ as u64 - 1))
        );
    }

    #[test]
    fn test_checked_add_error() {
        assert!(CtapInstant::new(0)
            .checked_add(Seconds::new(u64::MAX / TEST_CLOCK_FREQUENCY_HZ as ClockInt))
            .is_none());
        assert!(CtapInstant::new(0)
            .checked_add(Seconds::new(
                u64::MAX / TEST_CLOCK_FREQUENCY_HZ as ClockInt / 2
            ))
            .is_some());
        assert!(CtapInstant::new(0)
            .checked_add(Seconds::new(
                u64::MAX / TEST_CLOCK_FREQUENCY_HZ as ClockInt / 2 + 1
            ))
            .is_none());
    }

    #[test]
    fn test_duration_since() {
        let early = CtapInstant::new(0);
        let later = CtapInstant::new(1000);
        assert_eq!(
            later.checked_duration_since(&early).unwrap().integer(),
            1000
        );
        assert_eq!(early.checked_duration_since(&later), None);
    }

    #[test]
    fn test_duration_since_overflow() {
        let early = CtapInstant::new(u64::MAX);
        let later = CtapInstant::new(1000);
        assert_eq!(
            later.checked_duration_since(&early).unwrap().integer(),
            1001
        );
        assert_eq!(early.checked_duration_since(&later), None);
    }

    #[test]
    #[should_panic]
    fn add_panic() {
        let _ =
            CtapInstant::new(0) + Seconds(u64::MAX / TEST_CLOCK_FREQUENCY_HZ as ClockInt / 2 + 1);
    }
}
