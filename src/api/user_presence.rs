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

use crate::clock::ClockInt;
use crate::ctap::Channel;
use embedded_time::duration::Milliseconds;

pub enum UserPresenceError {
    Declined,
    Canceled,
    Timeout,
}

pub type UserPresenceResult = Result<(), UserPresenceError>;

pub trait UserPresence {
    /// Called at the beginning of user presence checking process.
    fn check_init(&mut self, channel: Channel);

    /// Implements a wait for user presence confirmation or rejection.
    fn wait_with_timeout(
        &mut self,
        channel: Channel,
        timeout: Milliseconds<ClockInt>,
    ) -> UserPresenceResult;

    /// Called at the end of user presence checking process.
    fn check_complete(&mut self, result: &UserPresenceResult);
}
