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

use crate::api::clock::Clock;
#[cfg(feature = "with_ctap1")]
use crate::ctap::ctap1;
#[cfg(feature = "with_ctap1")]
use crate::ctap::hid::ChannelID;
use crate::ctap::hid::{
    CtapHid, CtapHidCommand, CtapHidError, HidPacket, HidPacketIterator, Message,
};
use crate::ctap::{Channel, CtapState};
use crate::env::Env;

const WINK_TIMEOUT_DURATION_MS: usize = 5000;

/// Implements the standard CTAP command processing for HID.
pub struct MainHid<E: Env> {
    hid: CtapHid<E>,
    wink_permission: <E::Clock as Clock>::Timer,
}

impl<E: Env> Default for MainHid<E> {
    /// Instantiates a HID handler for CTAP1, CTAP2 and Wink.
    fn default() -> Self {
        #[cfg(feature = "with_ctap1")]
        let capabilities = CtapHid::<E>::CAPABILITY_WINK | CtapHid::<E>::CAPABILITY_CBOR;
        #[cfg(not(feature = "with_ctap1"))]
        let capabilities = CtapHid::<E>::CAPABILITY_WINK
            | CtapHid::<E>::CAPABILITY_CBOR
            | CtapHid::<E>::CAPABILITY_NMSG;

        let hid = CtapHid::new(capabilities);
        let wink_permission = <E::Clock as Clock>::Timer::default();
        MainHid {
            hid,
            wink_permission,
        }
    }
}

impl<E: Env> MainHid<E> {
    /// Processes an incoming USB HID packet, and returns an iterator for all outgoing packets.
    pub fn process_hid_packet(
        &mut self,
        env: &mut E,
        packet: &HidPacket,
        is_transport_disabled: bool,
        ctap_state: &mut CtapState<E>,
    ) -> HidPacketIterator {
        if let Some(message) = self.hid.parse_packet(env, packet, is_transport_disabled) {
            let processed_message = self.process_message(env, message, ctap_state);
            debug_ctap!(env, "Sending message: {:02x?}", processed_message);
            CtapHid::<E>::split_message(processed_message)
        } else {
            HidPacketIterator::none()
        }
    }

    /// Processes a message's commands that affect the protocol outside HID.
    pub fn process_message(
        &mut self,
        env: &mut E,
        message: Message,
        ctap_state: &mut CtapState<E>,
    ) -> Message {
        // If another command arrives, stop winking to prevent accidential button touches.
        self.wink_permission = <E::Clock as Clock>::Timer::default();

        let cid = message.cid;
        match message.cmd {
            // CTAP 2.1 from 2021-06-15, section 11.2.9.1.1.
            CtapHidCommand::Msg => {
                // If we don't have CTAP1 backward compatibilty, this command is invalid.
                #[cfg(not(feature = "with_ctap1"))]
                return CtapHid::<E>::error_message(cid, CtapHidError::InvalidCmd);

                #[cfg(feature = "with_ctap1")]
                match ctap1::Ctap1Command::process_command(env, &message.payload, ctap_state) {
                    Ok(payload) => Self::ctap1_success_message(cid, &payload),
                    Err(ctap1_status_code) => Self::ctap1_error_message(cid, ctap1_status_code),
                }
            }
            // CTAP 2.1 from 2021-06-15, section 11.2.9.1.2.
            CtapHidCommand::Cbor => {
                // Each transaction is atomic, so we process the command directly here and
                // don't handle any other packet in the meantime.
                // TODO: Send "Processing" type keep-alive packets in the meantime.
                let response =
                    ctap_state.process_command(env, &message.payload, Channel::MainHid(cid));
                Message {
                    cid,
                    cmd: CtapHidCommand::Cbor,
                    payload: response,
                }
            }
            // CTAP 2.1 from 2021-06-15, section 11.2.9.2.1.
            CtapHidCommand::Wink => {
                if message.payload.is_empty() {
                    self.wink_permission = env.clock().make_timer(WINK_TIMEOUT_DURATION_MS);
                    // The response is empty like the request.
                    message
                } else {
                    CtapHid::<E>::error_message(cid, CtapHidError::InvalidLen)
                }
            }
            // All other commands have already been processed, keep them as is.
            _ => message,
        }
    }

    /// Returns whether this transport claims a lock.
    pub fn has_channel_lock(&mut self, env: &mut E) -> bool {
        self.hid.has_channel_lock(env)
    }

    /// Returns whether a wink permission is currently granted.
    pub fn should_wink(&self, env: &mut E) -> bool {
        !env.clock().is_elapsed(&self.wink_permission)
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

    fn new_initialized() -> (MainHid<TestEnv>, ChannelID) {
        let (hid, cid) = CtapHid::new_initialized();
        let wink_permission = <<TestEnv as Env>::Clock as Clock>::Timer::default();
        (
            MainHid::<TestEnv> {
                hid,
                wink_permission,
            },
            cid,
        )
    }

    #[test]
    fn test_process_hid_packet() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        let (mut main_hid, cid) = new_initialized();

        let mut ping_packet = [0x00; 64];
        ping_packet[..4].copy_from_slice(&cid);
        ping_packet[4..9].copy_from_slice(&[0x81, 0x00, 0x02, 0x99, 0x99]);

        let mut response =
            main_hid.process_hid_packet(&mut env, &ping_packet, false, &mut ctap_state);
        assert_eq!(response.next(), Some(ping_packet));
        assert_eq!(response.next(), None);
    }

    #[test]
    fn test_process_hid_packet_empty() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        let (mut main_hid, cid) = new_initialized();

        let mut cancel_packet = [0x00; 64];
        cancel_packet[..4].copy_from_slice(&cid);
        cancel_packet[4..7].copy_from_slice(&[0x91, 0x00, 0x00]);

        let mut response =
            main_hid.process_hid_packet(&mut env, &cancel_packet, false, &mut ctap_state);
        assert_eq!(response.next(), None);
    }

    #[test]
    fn test_wink() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        let (mut main_hid, cid) = new_initialized();
        assert!(!main_hid.should_wink(&mut env));

        let mut wink_packet = [0x00; 64];
        wink_packet[..4].copy_from_slice(&cid);
        wink_packet[4..7].copy_from_slice(&[0x88, 0x00, 0x00]);

        let mut response =
            main_hid.process_hid_packet(&mut env, &wink_packet, false, &mut ctap_state);
        assert_eq!(response.next(), Some(wink_packet));
        assert_eq!(response.next(), None);
        assert!(main_hid.should_wink(&mut env));
        env.clock().advance(WINK_TIMEOUT_DURATION_MS);
        assert!(!main_hid.should_wink(&mut env));
    }

    #[test]
    fn test_locked_channels() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        let (mut main_hid, cid) = new_initialized();

        let mut ping_packet = [0x00; 64];
        ping_packet[..4].copy_from_slice(&cid);
        ping_packet[4..9].copy_from_slice(&[0x81, 0x00, 0x02, 0x99, 0x99]);

        let mut response =
            main_hid.process_hid_packet(&mut env, &ping_packet, true, &mut ctap_state);
        let mut error_packet = [0x00; 64];
        error_packet[..4].copy_from_slice(&cid);
        error_packet[4..8].copy_from_slice(&[0xBF, 0x00, 0x01, 0x06]);
        assert_eq!(response.next(), Some(error_packet));
        assert_eq!(response.next(), None);
    }
}
