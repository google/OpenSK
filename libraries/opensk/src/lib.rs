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
// TODO(kaczmarczyck): Refactor this so that ctap module isn't public.
pub mod ctap;
pub mod env;
#[cfg(feature = "std")]
pub mod test_helpers;

/// CTAP implementation parameterized by its environment.
pub struct Ctap<E: Env> {
    env: E,
    state: CtapState<E>,
    hid: MainHid<E>,
    #[cfg(feature = "vendor_hid")]
    vendor_hid: VendorHid<E>,
}

impl<E: Env> Ctap<E> {
    /// Instantiates a CTAP implementation given its environment.
    // This should only take the environment, but it temporarily takes the boot time until the
    // clock is part of the environment.
    pub fn new(mut env: E) -> Self {
        let state = CtapState::<E>::new(&mut env);
        let hid = MainHid::default();
        #[cfg(feature = "vendor_hid")]
        let vendor_hid = VendorHid::default();
        Ctap {
            env,
            state,
            hid,
            #[cfg(feature = "vendor_hid")]
            vendor_hid,
        }
    }

    pub fn state(&mut self) -> &mut CtapState<E> {
        &mut self.state
    }

    pub fn hid(&mut self) -> &mut MainHid<E> {
        &mut self.hid
    }

    pub fn env(&mut self) -> &mut E {
        &mut self.env
    }

    pub fn process_hid_packet(
        &mut self,
        packet: &HidPacket,
        transport: Transport,
    ) -> HidPacketIterator {
        match transport {
            Transport::MainHid => {
                #[cfg(not(feature = "vendor_hid"))]
                let is_disabled = false;
                #[cfg(feature = "vendor_hid")]
                let is_disabled = self.vendor_hid.has_channel_lock(&mut self.env);
                self.hid
                    .process_hid_packet(&mut self.env, packet, is_disabled, &mut self.state)
            }
            #[cfg(feature = "vendor_hid")]
            Transport::VendorHid => {
                let is_disabled = self.hid.has_channel_lock(&mut self.env);
                self.vendor_hid.process_hid_packet(
                    &mut self.env,
                    packet,
                    is_disabled,
                    &mut self.state,
                )
            }
        }
    }

    pub fn should_wink(&mut self) -> bool {
        self.hid.should_wink(&mut self.env)
    }

    #[cfg(feature = "with_ctap1")]
    pub fn u2f_grant_user_presence(&mut self) {
        self.state.u2f_grant_user_presence(&mut self.env)
    }

    #[cfg(feature = "with_ctap1")]
    pub fn u2f_needs_user_presence(&mut self) -> bool {
        self.state.u2f_needs_user_presence(&mut self.env)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;

    /// Assembles a packet for a payload that fits into one packet.
    fn assemble_packet(cid: &[u8; 4], cmd: u8, payload: &[u8]) -> HidPacket {
        assert!(payload.len() <= 57);
        let mut packet = [0x00; 64];
        packet[..4].copy_from_slice(cid);
        packet[4] = cmd | 0x80;
        packet[6] = payload.len() as u8;
        packet[7..][..payload.len()].copy_from_slice(payload);
        packet
    }

    fn init_packet() -> HidPacket {
        assemble_packet(&[0xFF; 4], 0x06, &[0x55; 8])
    }

    fn lock_packet(cid: &[u8; 4]) -> HidPacket {
        assemble_packet(cid, 0x04, &[0x01; 1])
    }

    fn wink_packet(cid: &[u8; 4]) -> HidPacket {
        assemble_packet(cid, 0x08, &[])
    }

    #[test]
    fn test_wink() {
        let env = TestEnv::default();
        let mut ctap = Ctap::<TestEnv>::new(env);

        // Send Init, receive Init response and check wink if disabled.
        let mut init_response = ctap.process_hid_packet(&init_packet(), Transport::MainHid);
        let response_packet = init_response.next().unwrap();
        assert_eq!(response_packet[4], 0x86);
        let cid = *array_ref!(response_packet, 15, 4);
        assert!(!ctap.should_wink());

        // Send Wink, receive Wink response and check wink is enabled.
        let mut lock_response = ctap.process_hid_packet(&wink_packet(&cid), Transport::MainHid);
        let response_packet = lock_response.next().unwrap();
        assert_eq!(response_packet[4], 0x88);
        assert!(ctap.should_wink());
    }

    #[test]
    fn test_locked_channel_id() {
        let env = TestEnv::default();
        let mut ctap = Ctap::<TestEnv>::new(env);

        // Send Init, receive Init response.
        let mut init_response = ctap.process_hid_packet(&init_packet(), Transport::MainHid);
        let response_packet = init_response.next().unwrap();
        assert_eq!(response_packet[4], 0x86);
        let cid = *array_ref!(response_packet, 15, 4);

        // Send Lock, receive Lock response.
        let mut lock_response = ctap.process_hid_packet(&lock_packet(&cid), Transport::MainHid);
        let response_packet = lock_response.next().unwrap();
        assert_eq!(response_packet[4], 0x84);

        // Send another Init, receive Error.
        let mut init_response = ctap.process_hid_packet(&init_packet(), Transport::MainHid);
        let response_packet = init_response.next().unwrap();
        assert_eq!(response_packet[4], 0xBF);
    }

    #[test]
    #[cfg(feature = "vendor_hid")]
    fn test_locked_transport() {
        let env = TestEnv::default();
        let mut ctap = Ctap::<TestEnv>::new(env);

        // Send Init, receive Init response.
        let mut init_response = ctap.process_hid_packet(&init_packet(), Transport::MainHid);
        let response_packet = init_response.next().unwrap();
        assert_eq!(response_packet[4], 0x86);
        let cid = *array_ref!(response_packet, 15, 4);

        // Send Lock, receive Lock response.
        let mut lock_response = ctap.process_hid_packet(&lock_packet(&cid), Transport::MainHid);
        let response_packet = lock_response.next().unwrap();
        assert_eq!(response_packet[4], 0x84);

        // Send Init on other transport, receive Error.
        let mut init_response = ctap.process_hid_packet(&init_packet(), Transport::VendorHid);
        let response_packet = init_response.next().unwrap();
        assert_eq!(response_packet[4], 0xBF);
    }
}
