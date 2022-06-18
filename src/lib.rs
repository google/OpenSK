// Copyright 2019-2022 Google LLC
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

use crate::ctap::hid::{HidPacket, HidPacketIterator};
use crate::ctap::main_hid::MainHid;
#[cfg(feature = "vendor_hid")]
use crate::ctap::vendor_hid::VendorHid;
use crate::ctap::CtapState;
pub use crate::ctap::Transport;
use crate::env::Env;
use clock::CtapInstant;

// Those macros should eventually be split into trace, debug, info, warn, and error macros when
// adding either the defmt or log feature and crate dependency.
#[cfg(feature = "debug_ctap")]
macro_rules! debug_ctap {
    ($env: expr, $($rest:tt)*) => {{
        use core::fmt::Write;
        writeln!($env.write(), $($rest)*).unwrap();
    }};
}
#[cfg(not(feature = "debug_ctap"))]
macro_rules! debug_ctap {
    ($env: expr, $($rest:tt)*) => {
        // To avoid unused variable warnings.
        let _ = $env;
    };
}

pub mod api;
pub mod clock;
// Implementation details must be public for testing (in particular fuzzing).
#[cfg(feature = "std")]
pub mod ctap;
#[cfg(not(feature = "std"))]
mod ctap;
pub mod env;
#[cfg(feature = "std")]
pub mod test_helpers;

/// CTAP implementation parameterized by its environment.
pub struct Ctap<E: Env> {
    env: E,
    state: CtapState,
    hid: MainHid,
    #[cfg(feature = "vendor_hid")]
    vendor_hid: VendorHid,
}

impl<E: Env> Ctap<E> {
    /// Instantiates a CTAP implementation given its environment.
    // This should only take the environment, but it temporarily takes the boot time until the
    // clock is part of the environment.
    pub fn new(mut env: E, now: CtapInstant) -> Self {
        let state = CtapState::new(&mut env, now);
        let hid = MainHid::new();
        #[cfg(feature = "vendor_hid")]
        let vendor_hid = VendorHid::new();
        Ctap {
            env,
            state,
            hid,
            #[cfg(feature = "vendor_hid")]
            vendor_hid,
        }
    }

    pub fn state(&mut self) -> &mut CtapState {
        &mut self.state
    }

    pub fn hid(&mut self) -> &mut MainHid {
        &mut self.hid
    }

    #[cfg(feature = "std")]
    pub fn env(&mut self) -> &mut E {
        &mut self.env
    }

    pub fn process_hid_packet(
        &mut self,
        packet: &HidPacket,
        transport: Transport,
        now: CtapInstant,
    ) -> HidPacketIterator {
        match transport {
            Transport::MainHid => {
                self.hid
                    .process_hid_packet(&mut self.env, packet, now, &mut self.state)
            }
            #[cfg(feature = "vendor_hid")]
            Transport::VendorHid => {
                self.vendor_hid
                    .process_hid_packet(&mut self.env, packet, now, &mut self.state)
            }
        }
    }

    pub fn update_timeouts(&mut self, now: CtapInstant) {
        self.state.update_timeouts(now);
        self.hid.update_wink_timeout(now);
    }

    pub fn main_hid_channel(&mut self) -> &mut E::CtapHidChannel {
        self.env.main_hid_channel()
    }

    #[cfg(feature = "vendor_hid")]
    pub fn vendor_hid_channel(&mut self) -> &mut E::CtapHidChannel {
        self.env.vendor_hid_channel()
    }
}
