// Copyright 2019-2021 Google LLC
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

use super::super::clock::{ClockInt, CtapInstant};
use embedded_time::duration::Milliseconds;

#[derive(Debug)]
pub enum TimedPermission {
    Waiting,
    Granted(CtapInstant),
}

impl Clone for TimedPermission {
    fn clone(&self) -> Self {
        match self {
            Self::Waiting => Self::Waiting,
            Self::Granted(instant) => Self::Granted(*instant),
        }
    }
}

impl Copy for TimedPermission {}

impl TimedPermission {
    pub fn waiting() -> TimedPermission {
        TimedPermission::Waiting
    }

    pub fn granted(now: CtapInstant, grant_duration: Milliseconds<ClockInt>) -> TimedPermission {
        now.checked_add(grant_duration)
            .map_or(Self::Waiting, TimedPermission::Granted)
    }

    // Checks if the timeout is not reached, false for differing ClockValue frequencies.
    pub fn is_granted(&self, now: CtapInstant) -> bool {
        if let TimedPermission::Granted(timeout) = self {
            let remaining_duration = timeout.checked_duration_since(&now);
            return remaining_duration.map_or(false, |duration| duration.integer() > 0);
        }
        false
    }

    // Consumes the state and returns the current new permission state at time "now".
    // Returns a new state for differing ClockValue frequencies.
    pub fn check_expiration(self, now: CtapInstant) -> TimedPermission {
        if let TimedPermission::Granted(timeout) = self {
            let remaining_duration = timeout.checked_duration_since(&now);
            if remaining_duration.map_or(false, |duration| duration.integer() > 0) {
                return TimedPermission::Granted(timeout);
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
    request_duration: Milliseconds<ClockInt>,
    // This is the timeout duration of button touches.
    presence_duration: Milliseconds<ClockInt>,
}

#[cfg(feature = "with_ctap1")]
impl U2fUserPresenceState {
    pub fn new(
        request_duration: Milliseconds<ClockInt>,
        presence_duration: Milliseconds<ClockInt>,
    ) -> U2fUserPresenceState {
        U2fUserPresenceState {
            needs_up: TimedPermission::Waiting,
            has_up: TimedPermission::Waiting,
            request_duration,
            presence_duration,
        }
    }

    // Granting user presence is ignored if it needs activation, but waits. Also cleans up.
    pub fn grant_up(&mut self, now: CtapInstant) {
        self.check_expiration(now);
        if self.needs_up.is_granted(now) {
            self.needs_up = TimedPermission::Waiting;
            self.has_up = TimedPermission::granted(now, self.presence_duration);
        }
    }

    // This marks user presence as needed or uses it up if already granted. Also cleans up.
    pub fn consume_up(&mut self, now: CtapInstant) -> bool {
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
    pub fn is_up_needed(&mut self, now: CtapInstant) -> bool {
        self.check_expiration(now);
        self.needs_up.is_granted(now)
    }

    // If you don't regularly call any other function, not cleaning up leads to overflow problems.
    pub fn check_expiration(&mut self, now: CtapInstant) {
        self.needs_up = self.needs_up.check_expiration(now);
        self.has_up = self.has_up.check_expiration(now);
    }
}

#[cfg(feature = "with_ctap1")]
#[cfg(test)]
mod test {
    use super::*;

    fn zero() -> CtapInstant {
        CtapInstant::new(0)
    }

    fn big_positive() -> CtapInstant {
        CtapInstant::new(u64::MAX / 1000 - 1)
    }

    fn small_negative() -> CtapInstant {
        CtapInstant::new(u64::MIN / 1000 + 1)
    }

    fn request_duration() -> Milliseconds<u64> {
        Milliseconds::new(1000_u64)
    }

    fn presence_duration() -> Milliseconds<u64> {
        Milliseconds::new(1000_u64)
    }

    fn grant_up_when_needed(start_time: CtapInstant) {
        let mut u2f_state = U2fUserPresenceState::new(request_duration(), presence_duration());
        assert!(!u2f_state.consume_up(start_time));
        assert!(u2f_state.is_up_needed(start_time));
        u2f_state.grant_up(start_time);
        assert!(u2f_state.consume_up(start_time));
        assert!(!u2f_state.consume_up(start_time));
    }

    fn need_up_timeout(start_time: CtapInstant) {
        let mut u2f_state = U2fUserPresenceState::new(request_duration(), presence_duration());
        assert!(!u2f_state.consume_up(start_time));
        assert!(u2f_state.is_up_needed(start_time));
        // The timeout excludes equality, so it should be over at this instant.
        assert!(!u2f_state.is_up_needed(start_time.checked_add(request_duration()).unwrap()));
    }

    fn grant_up_timeout(start_time: CtapInstant) {
        let mut u2f_state = U2fUserPresenceState::new(request_duration(), presence_duration());
        assert!(!u2f_state.consume_up(start_time));
        assert!(u2f_state.is_up_needed(start_time));
        u2f_state.grant_up(start_time);
        // The timeout excludes equality, so it should be over at this instant.
        assert!(!u2f_state.consume_up(start_time.checked_add(presence_duration()).unwrap()));
    }

    #[test]
    fn test_grant_up_timeout() {
        grant_up_timeout(zero());
        grant_up_timeout(big_positive());
        grant_up_timeout(small_negative());
    }

    #[test]
    fn test_need_up_timeout() {
        need_up_timeout(zero());
        need_up_timeout(big_positive());
        need_up_timeout(small_negative());
    }

    #[test]
    fn test_grant_up_when_needed() {
        grant_up_when_needed(zero());
        grant_up_when_needed(big_positive());
        grant_up_when_needed(small_negative());
    }

    #[test]
    fn test_grant_up_without_need() {
        let mut u2f_state = U2fUserPresenceState::new(request_duration(), presence_duration());
        u2f_state.grant_up(zero());
        assert!(!u2f_state.is_up_needed(zero()));
        assert!(!u2f_state.consume_up(zero()));
    }
}
