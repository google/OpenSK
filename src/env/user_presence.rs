// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use opensk::api::connection::RecvStatus;
use opensk::api::user_presence::{UserPresence, UserPresenceError, UserPresenceWaitResult};
use opensk::ctap::status_code::Ctap2StatusCode;
use wasefire::{scheduling, timer, usb};

pub(crate) fn init() -> Impl {
    Impl(None)
}

pub(crate) struct Impl(Option<State>);

struct State {
    touch: crate::touch::Touch,
}

impl UserPresence for Impl {
    fn check_init(&mut self) {
        let touch = crate::touch::Touch::new();
        self.0 = Some(State { touch });
    }

    fn wait_with_timeout(
        &mut self,
        packet: &mut [u8; 64],
        timeout_ms: usize,
    ) -> UserPresenceWaitResult {
        let touch = match &self.0 {
            Some(x) => &x.touch,
            None => return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        };
        let timeout = timer::Timeout::new_ms(timeout_ms);
        let mut listener = usb::ctap::Listener::new(usb::ctap::Event::Read);
        while !usb::ctap::read(packet).unwrap() {
            scheduling::wait_until(|| {
                touch.is_present() || timeout.is_over() || listener.is_notified()
            });
            if touch.is_present() {
                return Ok((Ok(()), RecvStatus::Timeout));
            }
            if timeout.is_over() {
                return Ok((Err(UserPresenceError::Timeout), RecvStatus::Timeout));
            }
        }
        let endpoint = opensk::api::connection::UsbEndpoint::MainHid;
        Ok((
            Err(UserPresenceError::Timeout),
            RecvStatus::Received(endpoint),
        ))
    }

    fn check_complete(&mut self) {
        self.0 = None;
    }
}
