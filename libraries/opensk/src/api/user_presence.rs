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

#[derive(Debug)]
pub enum UserPresenceError {
    /// User explicitly declined user presence check.
    Declined,
    /// User presence check was canceled by User Agent.
    Canceled,
    /// User presence check timed out.
    Timeout,
    /// Unexpected (e.g., hardware) failures
    Fail,
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
    fn wait_with_timeout(&mut self, timeout_ms: usize) -> UserPresenceResult;

    /// Finalizes a user presence check.
    ///
    /// Must be called after [`Self::check_init`].
    fn check_complete(&mut self);
}
