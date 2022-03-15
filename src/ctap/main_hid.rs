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

use crate::clock::{ClockInt, CtapInstant};
#[cfg(feature = "with_ctap1")]
use crate::ctap::ctap1;
#[cfg(feature = "with_ctap1")]
use crate::ctap::hid::ChannelID;
use crate::ctap::hid::{
    CtapHid, CtapHidCommand, CtapHidError, HidPacket, HidPacketIterator, Message,
};
use crate::ctap::{Channel, CtapState, TimedPermission};
use crate::env::Env;
use embedded_time::duration::Milliseconds;

/// Implements the standard CTAP command processing for HID.
pub struct MainHid {
    hid: CtapHid,
    wink_permission: TimedPermission,
}

impl MainHid {
    const WINK_TIMEOUT_DURATION: Milliseconds<ClockInt> = Milliseconds(5000 as ClockInt);

    /// Instantiates a HID handler for CTAP1, CTAP2 and Wink.
    pub fn new() -> Self {
        let hid = CtapHid::new();
        let wink_permission = TimedPermission::waiting();
        MainHid {
            hid,
            wink_permission,
        }
    }

    /// Processes an incoming USB HID packet, and returns an iterator for all outgoing packets.
    pub fn process_hid_packet(
        &mut self,
        env: &mut impl Env,
        packet: &HidPacket,
        now: CtapInstant,
        ctap_state: &mut CtapState,
    ) -> HidPacketIterator {
        if let Some(message) = self.hid.parse_packet(env, packet, now) {
            let processed_message = self.process_message(env, message, now, ctap_state);
            debug_ctap!(env, "Sending message: {:02x?}", processed_message);
            CtapHid::split_message(processed_message)
        } else {
            HidPacketIterator::none()
        }
    }

    /// Processes a message's commands that affect the protocol outside HID.
    pub fn process_message(
        &mut self,
        env: &mut impl Env,
        message: Message,
        now: CtapInstant,
        ctap_state: &mut CtapState,
    ) -> Message {
        // If another command arrives, stop winking to prevent accidential button touches.
        self.wink_permission = TimedPermission::waiting();

        let cid = message.cid;
        match message.cmd {
            // CTAP 2.1 from 2021-06-15, section 11.2.9.1.1.
            CtapHidCommand::Msg => {
                // If we don't have CTAP1 backward compatibilty, this command is invalid.
                #[cfg(not(feature = "with_ctap1"))]
                return CtapHid::error_message(cid, CtapHidError::InvalidCmd);

                #[cfg(feature = "with_ctap1")]
                match ctap1::Ctap1Command::process_command(env, &message.payload, ctap_state, now) {
                    Ok(payload) => MainHid::ctap1_success_message(cid, &payload),
                    Err(ctap1_status_code) => MainHid::ctap1_error_message(cid, ctap1_status_code),
                }
            }
            // CTAP 2.1 from 2021-06-15, section 11.2.9.1.2.
            CtapHidCommand::Cbor => {
                // Each transaction is atomic, so we process the command directly here and
                // don't handle any other packet in the meantime.
                // TODO: Send "Processing" type keep-alive packets in the meantime.
                let response =
                    ctap_state.process_command(env, &message.payload, Channel::MainHid(cid), now);
                Message {
                    cid,
                    cmd: CtapHidCommand::Cbor,
                    payload: response,
                }
            }
            // CTAP 2.1 from 2021-06-15, section 11.2.9.2.1.
            CtapHidCommand::Wink => {
                if message.payload.is_empty() {
                    self.wink_permission =
                        TimedPermission::granted(now, Self::WINK_TIMEOUT_DURATION);
                    // The response is empty like the request.
                    message
                } else {
                    CtapHid::error_message(cid, CtapHidError::InvalidLen)
                }
            }
            // All other commands have already been processed, keep them as is.
            _ => message,
        }
    }

    /// Returns whether a wink permission is currently granted.
    pub fn should_wink(&self, now: CtapInstant) -> bool {
        self.wink_permission.is_granted(now)
    }

    /// Updates the timeout for the wink permission.
    pub fn update_wink_timeout(&mut self, now: CtapInstant) {
        self.wink_permission = self.wink_permission.check_expiration(now);
    }

    #[cfg(feature = "with_ctap1")]
    fn ctap1_error_message(cid: ChannelID, error_code: ctap1::Ctap1StatusCode) -> Message {
        let code: u16 = error_code.into();
        Message {
            cid,
            cmd: CtapHidCommand::Msg,
            payload: code.to_be_bytes().to_vec(),
        }
    }

    #[cfg(feature = "with_ctap1")]
    fn ctap1_success_message(cid: ChannelID, payload: &[u8]) -> Message {
        let mut response = payload.to_vec();
        let code: u16 = ctap1::Ctap1StatusCode::SW_SUCCESS.into();
        response.extend_from_slice(&code.to_be_bytes());
        Message {
            cid,
            cmd: CtapHidCommand::Msg,
            payload: response,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ctap::hid::ChannelID;
    use crate::env::test::TestEnv;

    fn new_initialized() -> (MainHid, ChannelID) {
        let (hid, cid) = CtapHid::new_initialized();
        let wink_permission = TimedPermission::waiting();
        (
            MainHid {
                hid,
                wink_permission,
            },
            cid,
        )
    }

    #[test]
    fn test_process_hid_packet() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        let (mut main_hid, cid) = new_initialized();

        let mut ping_packet = [0x00; 64];
        ping_packet[..4].copy_from_slice(&cid);
        ping_packet[4..9].copy_from_slice(&[0x81, 0x00, 0x02, 0x99, 0x99]);

        let mut response = main_hid.process_hid_packet(
            &mut env,
            &ping_packet,
            CtapInstant::new(0),
            &mut ctap_state,
        );
        assert_eq!(response.next(), Some(ping_packet));
        assert_eq!(response.next(), None);
    }

    #[test]
    fn test_process_hid_packet_empty() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        let (mut main_hid, cid) = new_initialized();

        let mut cancel_packet = [0x00; 64];
        cancel_packet[..4].copy_from_slice(&cid);
        cancel_packet[4..7].copy_from_slice(&[0x91, 0x00, 0x00]);

        let mut response = main_hid.process_hid_packet(
            &mut env,
            &cancel_packet,
            CtapInstant::new(0),
            &mut ctap_state,
        );
        assert_eq!(response.next(), None);
    }

    #[test]
    fn test_wink() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        let (mut main_hid, cid) = new_initialized();
        assert!(!main_hid.should_wink(CtapInstant::new(0)));

        let mut wink_packet = [0x00; 64];
        wink_packet[..4].copy_from_slice(&cid);
        wink_packet[4..7].copy_from_slice(&[0x88, 0x00, 0x00]);

        let mut response = main_hid.process_hid_packet(
            &mut env,
            &wink_packet,
            CtapInstant::new(0),
            &mut ctap_state,
        );
        assert_eq!(response.next(), Some(wink_packet));
        assert_eq!(response.next(), None);
        assert!(main_hid.should_wink(CtapInstant::new(0)));
        assert!(!main_hid.should_wink(CtapInstant::new(1) + MainHid::WINK_TIMEOUT_DURATION));
    }
}
