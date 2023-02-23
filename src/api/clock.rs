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

pub trait Clock: Sized {
    type Timer;

    /// Creates a new timer that expires after the given time in ms.
    fn make_timer(&mut self, milliseconds: usize) -> Self::Timer;

    /// Consumes a timer, and returns it if not expired.
    fn check_timer(&mut self, timer: Self::Timer) -> Option<Self::Timer>;

    /// Checks the timer and takes it, if expired.
    fn update_timer(&mut self, timer: &mut Option<Self::Timer>) {
        *timer = timer.take().and_then(|t| Self::check_timer(self, t));
    }

    /// Tickles the clock and makes it check its timers. Often a NOOP.
    fn tickle(&mut self);

    /// Timestamp in microseconds.
    ///
    /// Normal operation only needs relative time, absolute timestamps are useful for debugging.
    #[cfg(feature = "debug_ctap")]
    fn timestamp_us(&mut self) -> usize;
}
