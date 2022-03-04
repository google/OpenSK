// Copyright 2019 Google LLC
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

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[macro_use]
extern crate arrayref;

use crate::ctap::hid::send::HidPacketIterator;
use crate::ctap::hid::{CtapHid, HidPacket};
use crate::ctap::CtapState;
use crate::env::Env;
use libtock_drivers::timer::ClockValue;

// Implementation details must be public for testing (in particular fuzzing).
#[cfg(feature = "std")]
pub mod ctap;
#[cfg(not(feature = "std"))]
mod ctap;
// Store example binaries use the flash directly. Eventually, they should access it from env::tock.
pub mod embedded_flash;
pub mod env;

/// CTAP implementation parameterized by its environment.
pub struct Ctap<E: Env> {
    env: E,
    state: CtapState,
    hid: CtapHid,
}

impl<E: Env> Ctap<E> {
    /// Instantiates a CTAP implementation given its environment.
    // This should only take the environment, but it temporarily takes the boot time until the
    // clock is part of the environment.
    pub fn new(mut env: E, now: ClockValue) -> Self {
        let state = CtapState::new(&mut env, now);
        let hid = CtapHid::new();
        Ctap { env, state, hid }
    }

    pub fn state(&mut self) -> &mut CtapState {
        &mut self.state
    }

    pub fn hid(&mut self) -> &mut CtapHid {
        &mut self.hid
    }

    pub fn process_hid_packet(&mut self, packet: &HidPacket, now: ClockValue) -> HidPacketIterator {
        self.hid
            .process_hid_packet(&mut self.env, packet, now, &mut self.state)
    }

    pub fn update_timeouts(&mut self, now: ClockValue) {
        self.state.update_timeouts(now);
        self.hid.wink_permission = self.hid.wink_permission.check_expiration(now);
    }
}
