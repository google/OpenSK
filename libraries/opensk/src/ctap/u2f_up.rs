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

use super::TOUCH_TIMEOUT_MS;
use crate::api::clock::Clock;
use crate::env::Env;

const U2F_UP_PROMPT_TIMEOUT_MS: usize = 10000;

pub struct U2fUserPresenceState<E: Env> {
    /// If user presence was recently requested, its timeout is saved here.
    needs_up: <E::Clock as Clock>::Timer,

    /// Button touch timeouts, while user presence is requested, are saved here.
    has_up: <E::Clock as Clock>::Timer,
}

impl<E: Env> U2fUserPresenceState<E> {
    pub fn new() -> U2fUserPresenceState<E> {
        U2fUserPresenceState {
            needs_up: <E::Clock as Clock>::Timer::default(),
            has_up: <E::Clock as Clock>::Timer::default(),
        }
    }

    /// Allows consuming user presence until timeout, if it was needed.
    ///
    /// If user presence was not requested, granting user presence does nothing.
    pub fn grant_up(&mut self, env: &mut E) {
        if !env.clock().is_elapsed(&self.needs_up) {
            self.needs_up = <E::Clock as Clock>::Timer::default();
            self.has_up = env.clock().make_timer(TOUCH_TIMEOUT_MS);
        }
    }

    /// Returns whether user presence was granted within the timeout and not yet consumed.
    pub fn consume_up(&mut self, env: &mut E) -> bool {
        if !env.clock().is_elapsed(&self.has_up) {
            self.has_up = <E::Clock as Clock>::Timer::default();
            true
        } else {
            self.needs_up = env.clock().make_timer(U2F_UP_PROMPT_TIMEOUT_MS);
            false
        }
    }

    /// Returns whether user presence was requested.
    ///
    /// This function doesn't represent interaction with the environment, and does not change the
    /// state, i.e. neither grants nor consumes user presence.
    pub fn is_up_needed(&mut self, env: &mut E) -> bool {
        !env.clock().is_elapsed(&self.needs_up)
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
        env.clock().advance(U2F_UP_PROMPT_TIMEOUT_MS);
        // The timeout excludes equality, so it should be over at this instant.
        assert!(!u2f_state.is_up_needed(env));
    }

    fn grant_up_timeout(env: &mut TestEnv) {
        let mut u2f_state = U2fUserPresenceState::new();
        assert!(!u2f_state.consume_up(env));
        assert!(u2f_state.is_up_needed(env));
        u2f_state.grant_up(env);
        env.clock().advance(TOUCH_TIMEOUT_MS);
        // The timeout excludes equality, so it should be over at this instant.
        assert!(!u2f_state.consume_up(env));
    }

    #[test]
    fn test_grant_up_timeout() {
        let mut env = TestEnv::default();
        grant_up_timeout(&mut env);
        env.clock().advance(big_positive());
        grant_up_timeout(&mut env);
    }

    #[test]
    fn test_need_up_timeout() {
        let mut env = TestEnv::default();
        need_up_timeout(&mut env);
        env.clock().advance(big_positive());
        need_up_timeout(&mut env);
    }

    #[test]
    fn test_grant_up_when_needed() {
        let mut env = TestEnv::default();
        grant_up_when_needed(&mut env);
        env.clock().advance(big_positive());
        grant_up_when_needed(&mut env);
    }

    #[test]
    fn test_grant_up_without_need() {
        let mut env = TestEnv::default();
        let mut u2f_state = U2fUserPresenceState::new();
        u2f_state.grant_up(&mut env);
        assert!(!u2f_state.is_up_needed(&mut env));
        assert!(!u2f_state.consume_up(&mut env));
    }
}
