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

use super::TOUCH_TIMEOUT;
use crate::api::clock::Clock;
use crate::env::Env;

const U2F_UP_PROMPT_TIMEOUT: usize = 10000;

pub struct U2fUserPresenceState<E: Env> {
    /// If user presence was recently requested, its timeout is saved here.
    needs_up: Option<<<E as Env>::Clock as Clock>::Timer>,

    /// Button touch timeouts, while user presence is requested, are saved here.
    has_up: Option<<<E as Env>::Clock as Clock>::Timer>,
}

impl<E: Env> U2fUserPresenceState<E> {
    pub fn new() -> U2fUserPresenceState<E> {
        U2fUserPresenceState {
            needs_up: None,
            has_up: None,
        }
    }

    // Granting user presence is ignored if it needs activation, but waits. Also cleans up.
    pub fn grant_up(&mut self, env: &mut E) {
        self.check_expiration(env);
        if self.needs_up.is_some() {
            self.needs_up = None;
            self.has_up = Some(env.clock().make_timer(TOUCH_TIMEOUT));
        }
    }

    // This marks user presence as needed or uses it up if already granted. Also cleans up.
    pub fn consume_up(&mut self, env: &mut E) -> bool {
        self.check_expiration(env);
        if self.has_up.is_some() {
            self.has_up = None;
            true
        } else {
            self.needs_up = Some(env.clock().make_timer(U2F_UP_PROMPT_TIMEOUT));
            false
        }
    }

    // Returns if user presence was requested. Also cleans up.
    pub fn is_up_needed(&mut self, env: &mut E) -> bool {
        self.check_expiration(env);
        self.needs_up.is_some()
    }

    /// Checks and updates all timers.
    pub fn check_expiration(&mut self, env: &mut E) {
        env.clock().update_timer(&mut self.needs_up);
        env.clock().update_timer(&mut self.has_up);
    }
}

#[cfg(feature = "with_ctap1")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;

    fn big_positive() -> usize {
        1000000
    }

    fn grant_up_when_needed(env: &mut TestEnv) {
        let mut u2f_state = U2fUserPresenceState::new();
        assert!(!u2f_state.consume_up(env));
        assert!(u2f_state.is_up_needed(env));
        u2f_state.grant_up(env);
        assert!(u2f_state.consume_up(env));
        assert!(!u2f_state.consume_up(env));
    }

    fn need_up_timeout(env: &mut TestEnv) {
        let mut u2f_state = U2fUserPresenceState::new();
        assert!(!u2f_state.consume_up(env));
        assert!(u2f_state.is_up_needed(env));
        env.clock().advance(U2F_UP_PROMPT_TIMEOUT);
        // The timeout excludes equality, so it should be over at this instant.
        assert!(!u2f_state.is_up_needed(env));
    }

    fn grant_up_timeout(env: &mut TestEnv) {
        let mut u2f_state = U2fUserPresenceState::new();
        assert!(!u2f_state.consume_up(env));
        assert!(u2f_state.is_up_needed(env));
        u2f_state.grant_up(env);
        env.clock().advance(TOUCH_TIMEOUT);
        // The timeout excludes equality, so it should be over at this instant.
        assert!(!u2f_state.consume_up(env));
    }

    #[test]
    fn test_grant_up_timeout() {
        let mut env = TestEnv::new();
        grant_up_timeout(&mut env);
        env.clock().advance(big_positive());
        grant_up_timeout(&mut env);
    }

    #[test]
    fn test_need_up_timeout() {
        let mut env = TestEnv::new();
        need_up_timeout(&mut env);
        env.clock().advance(big_positive());
        need_up_timeout(&mut env);
    }

    #[test]
    fn test_grant_up_when_needed() {
        let mut env = TestEnv::new();
        grant_up_when_needed(&mut env);
        env.clock().advance(big_positive());
        grant_up_when_needed(&mut env);
    }

    #[test]
    fn test_grant_up_without_need() {
        let mut env = TestEnv::new();
        let mut u2f_state = U2fUserPresenceState::new();
        u2f_state.grant_up(&mut env);
        assert!(!u2f_state.is_up_needed(&mut env));
        assert!(!u2f_state.consume_up(&mut env));
    }
}
