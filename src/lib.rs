// Copyright 2023 Google LLC
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

//! Example applet running OpenSK.
//!
//! See the [README] for more information.
//!
//! [README]: https://github.com/google/wasefire/blob/main/examples/rust/opensk/README.md

#![no_std]
wasefire::applet!();

use opensk::Transport;
use opensk::api::connection::{HidConnection as _, RecvStatus, UsbEndpoint};
use opensk::env::Env as _;

mod blink;
mod env;
mod touch;

fn main() -> ! {
    let mut opensk_ctap = opensk::Ctap::new(env::init());
    let mut wink: Option<blink::Blink> = None;
    #[cfg(feature = "ctap1")]
    let mut u2f: Option<touch::Touch> = None;
    debug!("OpenSK initialized");
    loop {
        match (wink.is_some(), opensk_ctap.should_wink()) {
            (true, true) | (false, false) => (),
            (false, true) => wink = Some(blink::Blink::new_ms(100)),
            (true, false) => wink = None,
        }
        let mut packet = [0; 64];
        let timeout = wink.is_some().then_some(500);
        match env::hid_connection::recv(&mut packet, timeout).unwrap() {
            RecvStatus::Timeout => continue,
            RecvStatus::Received(endpoint) => assert_eq!(endpoint, UsbEndpoint::MainHid),
        }
        #[cfg(feature = "ctap1")]
        if u2f.as_ref().is_some_and(|x| x.is_present()) {
            u2f = None;
            opensk_ctap.u2f_grant_user_presence();
        }
        for packet in opensk_ctap.process_hid_packet(&packet, Transport::MainHid) {
            opensk_ctap
                .env()
                .hid_connection()
                .send(&packet, UsbEndpoint::MainHid)
                .unwrap();
        }
        #[cfg(feature = "ctap1")]
        if opensk_ctap.u2f_needs_user_presence() && u2f.is_none() {
            u2f = Some(touch::Touch::new());
        }
    }
}
