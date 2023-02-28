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

pub trait Clock {
    /// Stores data for the clock to recognize if this timer is elapsed or not.
    ///
    /// The Clock does not keep track of the timers it creates. Therefore, they should not wrap
    /// unexpectedly. A timer that is elapsed may never return to a non-elapsed state.
    ///
    /// A default Timer should return `true` when checked with `is_elapsed`.
    type Timer: Default;

    /// Creates a new timer that expires after the given time in ms.
    fn make_timer(&mut self, milliseconds: usize) -> Self::Timer;

    /// Checks whether a given timer is expired.
    ///
    /// Until a timer expires, this function consistently returns false. Once it expires, this
    /// function consistently returns true. In particular, it is valid to continue calling this
    /// function after the first time it returns true.
    fn is_elapsed(&mut self, timer: &Self::Timer) -> bool;

    /// Timestamp in microseconds.
    ///
    /// Normal operation only needs relative time, absolute timestamps are useful for debugging.
    #[cfg(feature = "debug_ctap")]
    fn timestamp_us(&mut self) -> usize;
}
