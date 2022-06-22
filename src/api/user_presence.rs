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
    // User explicitly declined user presence check.
    Declined,
    // User presence check was canceled by User Agent.
    Canceled,
    // User presence check timed out.
    Timeout,
}

pub type UserPresenceResult = Result<(), UserPresenceError>;

pub trait UserPresence {
    /// Initializes for a user presence check.
    ///
    /// Must eventually be followed by a call to [`Self::check_complete`].
    fn check_init(&mut self);

    /// Waits until user presence is confirmed, rejected, or the given timeout expires.
    ///
    /// Must be called between calls to [`Self::check_init`] and [`Self::check_complete`].
    ///
    /// # Errors
    ///
    /// Returns [`UserPresenceError::Timeout`] if no evidence of user interaction was provided by
    /// authenticator.
    /// Returns [`UserPresenceError::Declined`] if user presence was explicitly denied by user.
    /// Returns [`UserPresenceError::Canceled`] if authenticator receives CANCEL message from User
    /// Agent during wait for user presence.
    fn wait_with_timeout(
        &mut self,
        channel: Channel,
        timeout: Milliseconds<ClockInt>,
    ) -> UserPresenceResult;

    /// Finalizes a user presence check.
    ///
    /// Must be called after [`Self::check_init`].
    fn check_complete(&mut self);
}
