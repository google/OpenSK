// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use libtock_drivers::timer::{ClockValue, Duration};

#[derive(Clone, Copy, Debug)]
pub enum TimedPermission {
    Waiting,
    Granted(ClockValue),
}

impl TimedPermission {
    pub fn waiting() -> TimedPermission {
        TimedPermission::Waiting
    }

    pub fn granted(now: ClockValue, grant_duration: Duration<isize>) -> TimedPermission {
        TimedPermission::Granted(now.wrapping_add(grant_duration))
    }

    // Checks if the timeout is not reached, false for differing ClockValue frequencies.
    pub fn is_granted(&self, now: ClockValue) -> bool {
        if let TimedPermission::Granted(timeout) = self {
            if let Some(remaining_duration) = timeout.wrapping_sub(now) {
                return remaining_duration > Duration::from_ms(0);
            }
        }
        false
    }

    // Consumes the state and returns the current new permission state at time "now".
    // Returns a new state for differing ClockValue frequencies.
    pub fn check_expiration(self, now: ClockValue) -> TimedPermission {
        if let TimedPermission::Granted(timeout) = self {
            if let Some(remaining_duration) = timeout.wrapping_sub(now) {
                if remaining_duration > Duration::from_ms(0) {
                    return TimedPermission::Granted(timeout);
                }
            }
        }
        TimedPermission::Waiting
    }
}

#[cfg(feature = "with_ctap1")]
#[derive(Debug)]
pub struct U2fUserPresenceState {
    // If user presence was recently requested, its timeout is saved here.
    needs_up: TimedPermission,
    // Button touch timeouts, while user presence is requested, are saved here.
    has_up: TimedPermission,
    // This is the timeout duration of user presence requests.
    request_duration: Duration<isize>,
    // This is the timeout duration of button touches.
    presence_duration: Duration<isize>,
}

#[cfg(feature = "with_ctap1")]
impl U2fUserPresenceState {
    pub fn new(
        request_duration: Duration<isize>,
        presence_duration: Duration<isize>,
    ) -> U2fUserPresenceState {
        U2fUserPresenceState {
            needs_up: TimedPermission::Waiting,
            has_up: TimedPermission::Waiting,
            request_duration,
            presence_duration,
        }
    }

    // Granting user presence is ignored if it needs activation, but waits. Also cleans up.
    pub fn grant_up(&mut self, now: ClockValue) {
        self.check_expiration(now);
        if self.needs_up.is_granted(now) {
            self.needs_up = TimedPermission::Waiting;
            self.has_up = TimedPermission::granted(now, self.presence_duration);
        }
    }

    // This marks user presence as needed or uses it up if already granted. Also cleans up.
    pub fn consume_up(&mut self, now: ClockValue) -> bool {
        self.check_expiration(now);
        if self.has_up.is_granted(now) {
            self.has_up = TimedPermission::Waiting;
            true
        } else {
            self.needs_up = TimedPermission::granted(now, self.request_duration);
            false
        }
    }

    // Returns if user presence was requested. Also cleans up.
    pub fn is_up_needed(&mut self, now: ClockValue) -> bool {
        self.check_expiration(now);
        self.needs_up.is_granted(now)
    }

    // If you don't regularly call any other function, not cleaning up leads to overflow problems.
    pub fn check_expiration(&mut self, now: ClockValue) {
        self.needs_up = self.needs_up.check_expiration(now);
        self.has_up = self.has_up.check_expiration(now);
    }
}

#[cfg(feature = "with_ctap1")]
#[cfg(test)]
mod test {
    use super::*;
    use core::isize;

    const CLOCK_FREQUENCY_HZ: usize = 32768;
    const ZERO: ClockValue = ClockValue::new(0, CLOCK_FREQUENCY_HZ);
    const BIG_POSITIVE: ClockValue = ClockValue::new(isize::MAX / 1000 - 1, CLOCK_FREQUENCY_HZ);
    const NEGATIVE: ClockValue = ClockValue::new(-1, CLOCK_FREQUENCY_HZ);
    const SMALL_NEGATIVE: ClockValue = ClockValue::new(isize::MIN / 1000 + 1, CLOCK_FREQUENCY_HZ);
    const REQUEST_DURATION: Duration<isize> = Duration::from_ms(1000);
    const PRESENCE_DURATION: Duration<isize> = Duration::from_ms(1000);

    fn grant_up_when_needed(start_time: ClockValue) {
        let mut u2f_state = U2fUserPresenceState::new(REQUEST_DURATION, PRESENCE_DURATION);
        assert!(!u2f_state.consume_up(start_time));
        assert!(u2f_state.is_up_needed(start_time));
        u2f_state.grant_up(start_time);
        assert!(u2f_state.consume_up(start_time));
        assert!(!u2f_state.consume_up(start_time));
    }

    fn need_up_timeout(start_time: ClockValue) {
        let mut u2f_state = U2fUserPresenceState::new(REQUEST_DURATION, PRESENCE_DURATION);
        assert!(!u2f_state.consume_up(start_time));
        assert!(u2f_state.is_up_needed(start_time));
        // The timeout excludes equality, so it should be over at this instant.
        assert!(!u2f_state.is_up_needed(start_time.wrapping_add(REQUEST_DURATION)));
    }

    fn grant_up_timeout(start_time: ClockValue) {
        let mut u2f_state = U2fUserPresenceState::new(REQUEST_DURATION, PRESENCE_DURATION);
        assert!(!u2f_state.consume_up(start_time));
        assert!(u2f_state.is_up_needed(start_time));
        u2f_state.grant_up(start_time);
        // The timeout excludes equality, so it should be over at this instant.
        assert!(!u2f_state.consume_up(start_time.wrapping_add(PRESENCE_DURATION)));
    }

    #[test]
    fn test_grant_up_timeout() {
        grant_up_timeout(ZERO);
        grant_up_timeout(BIG_POSITIVE);
        grant_up_timeout(NEGATIVE);
        grant_up_timeout(SMALL_NEGATIVE);
    }

    #[test]
    fn test_need_up_timeout() {
        need_up_timeout(ZERO);
        need_up_timeout(BIG_POSITIVE);
        need_up_timeout(NEGATIVE);
        need_up_timeout(SMALL_NEGATIVE);
    }

    #[test]
    fn test_grant_up_when_needed() {
        grant_up_when_needed(ZERO);
        grant_up_when_needed(BIG_POSITIVE);
        grant_up_when_needed(NEGATIVE);
        grant_up_when_needed(SMALL_NEGATIVE);
    }

    #[test]
    fn test_grant_up_without_need() {
        let mut u2f_state = U2fUserPresenceState::new(REQUEST_DURATION, PRESENCE_DURATION);
        u2f_state.grant_up(ZERO);
        assert!(!u2f_state.is_up_needed(ZERO));
        assert!(!u2f_state.consume_up(ZERO));
    }
}
