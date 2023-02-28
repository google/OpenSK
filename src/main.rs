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
extern crate arrayref;
extern crate byteorder;
#[cfg(feature = "std")]
extern crate core;
extern crate lang_items;

#[cfg(feature = "with_ctap1")]
use core::cell::Cell;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
use ctap2::api::clock::Clock;
use ctap2::api::connection::{HidConnection, SendOrRecvStatus};
use ctap2::ctap::hid::HidPacketIterator;
use ctap2::ctap::KEEPALIVE_DELAY;
#[cfg(feature = "with_ctap1")]
use ctap2::env::tock::blink_leds;
use ctap2::env::tock::{switch_off_leds, wink_leds, TockEnv};
use ctap2::env::Env;
use ctap2::Transport;
#[cfg(feature = "with_ctap1")]
use libtock_drivers::buttons::{self, ButtonState};
#[cfg(feature = "debug_ctap")]
use libtock_drivers::console::Console;
use libtock_drivers::result::FlexUnwrap;
use libtock_drivers::timer::Duration;
use libtock_drivers::usb_ctap_hid;
use usb_ctap_hid::UsbEndpoint;

libtock_core::stack_size! {0x4000}

const SEND_TIMEOUT: usize = 1000;
const KEEPALIVE_DELAY_TOCK: Duration<isize> = Duration::from_ms(KEEPALIVE_DELAY as isize);

#[cfg(not(feature = "vendor_hid"))]
const NUM_ENDPOINTS: usize = 1;
#[cfg(feature = "vendor_hid")]
const NUM_ENDPOINTS: usize = 2;

// The reply/replies that are queued for each endpoint.
struct EndpointReply {
    endpoint: UsbEndpoint,
    transport: Transport,
    reply: HidPacketIterator,
}

impl EndpointReply {
    pub fn new(endpoint: UsbEndpoint) -> Self {
        EndpointReply {
            endpoint,
            transport: match endpoint {
                UsbEndpoint::MainHid => Transport::MainHid,
                #[cfg(feature = "vendor_hid")]
                UsbEndpoint::VendorHid => Transport::VendorHid,
            },
            reply: HidPacketIterator::none(),
        }
    }
}

// A single packet to send.
struct SendPacket {
    transport: Transport,
    packet: [u8; 64],
}

struct EndpointReplies {
    replies: [EndpointReply; NUM_ENDPOINTS],
}

impl EndpointReplies {
    pub fn new() -> Self {
        EndpointReplies {
            replies: [
                EndpointReply::new(UsbEndpoint::MainHid),
                #[cfg(feature = "vendor_hid")]
                EndpointReply::new(UsbEndpoint::VendorHid),
            ],
        }
    }

    pub fn next_packet(&mut self) -> Option<SendPacket> {
        for ep in self.replies.iter_mut() {
            if let Some(packet) = ep.reply.next() {
                return Some(SendPacket {
                    transport: ep.transport,
                    packet,
                });
            }
        }
        None
    }
}

fn main() {
    // Setup USB driver.
    if !usb_ctap_hid::setup() {
        panic!("Cannot setup USB driver");
    }

    let env = TockEnv::new();
    let mut ctap = ctap2::Ctap::new(env);

    let mut led_counter = 0;
    let mut led_blink_timer = <<TockEnv as Env>::Clock as Clock>::Timer::default();

    let mut replies = EndpointReplies::new();

    // Main loop. If CTAP1 is used, we register button presses for U2F while receiving and waiting.
    // The way TockOS and apps currently interact, callbacks need a yield syscall to execute,
    // making consistent blinking patterns and sending keepalives harder.
    loop {
        // Create the button callback, used for CTAP1.
        #[cfg(feature = "with_ctap1")]
        let button_touched = Cell::new(false);
        #[cfg(feature = "with_ctap1")]
        let mut buttons_callback = buttons::with_callback(|_button_num, state| {
            match state {
                ButtonState::Pressed => button_touched.set(true),
                ButtonState::Released => (),
            };
        });
        #[cfg(feature = "with_ctap1")]
        let mut buttons = buttons_callback.init().flex_unwrap();
        // At the moment, all buttons are accepted. You can customize your setup here.
        #[cfg(feature = "with_ctap1")]
        for mut button in &mut buttons {
            button.enable().flex_unwrap();
        }

        // Variable for use in both the send_and_maybe_recv and recv cases.
        let mut usb_endpoint: Option<UsbEndpoint> = None;
        let mut pkt_request = [0; 64];

        if let Some(mut packet) = replies.next_packet() {
            // send and receive.
            let hid_connection = packet.transport.hid_connection(ctap.env());
            match hid_connection.send_and_maybe_recv(&mut packet.packet, SEND_TIMEOUT) {
                Ok(SendOrRecvStatus::Timeout) => {
                    #[cfg(feature = "debug_ctap")]
                    print_packet_notice(
                        "Sending packet timed out",
                        ctap.env().clock().timestamp_us(),
                    );
                    // TODO: reset the ctap_hid state.
                    // Since sending the packet timed out, we cancel this reply.
                    break;
                }
                Ok(SendOrRecvStatus::Sent) => {
                    #[cfg(feature = "debug_ctap")]
                    print_packet_notice("Sent packet", ctap.env().clock().timestamp_us());
                }
                Ok(SendOrRecvStatus::Received(ep)) => {
                    #[cfg(feature = "debug_ctap")]
                    print_packet_notice(
                        "Received another packet",
                        ctap.env().clock().timestamp_us(),
                    );
                    usb_endpoint = Some(ep);

                    // Copy to incoming packet to local buffer to be consistent
                    // with the receive flow.
                    pkt_request = packet.packet;
                }
                Err(_) => panic!("Error sending packet"),
            }
        } else {
            // receive
            usb_endpoint =
                match usb_ctap_hid::recv_with_timeout(&mut pkt_request, KEEPALIVE_DELAY_TOCK)
                    .flex_unwrap()
                {
                    usb_ctap_hid::SendOrRecvStatus::Received(endpoint) => {
                        #[cfg(feature = "debug_ctap")]
                        print_packet_notice("Received packet", ctap.env().clock().timestamp_us());
                        Some(endpoint)
                    }
                    usb_ctap_hid::SendOrRecvStatus::Sent => {
                        panic!("Returned transmit status on receive")
                    }
                    usb_ctap_hid::SendOrRecvStatus::Timeout => None,
                };
        }

        #[cfg(feature = "with_ctap1")]
        {
            if button_touched.get() {
                ctap.u2f_grant_user_presence();
            }
            // Cleanup button callbacks. We miss button presses while processing though.
            // Heavy computation mostly follows a registered touch luckily. Unregistering
            // callbacks is important to not clash with those from check_user_presence.
            for mut button in &mut buttons {
                button.disable().flex_unwrap();
            }
            drop(buttons);
            drop(buttons_callback);
        }

        // These calls are making sure that even for long inactivity, wrapping clock values
        // don't cause problems with timers.
        ctap.update_timeouts();
        ctap.env().clock().tickle();

        if let Some(endpoint) = usb_endpoint {
            let transport = match endpoint {
                UsbEndpoint::MainHid => Transport::MainHid,
                #[cfg(feature = "vendor_hid")]
                UsbEndpoint::VendorHid => Transport::VendorHid,
            };
            let reply = ctap.process_hid_packet(&pkt_request, transport);
            if reply.has_data() {
                // Update endpoint with the reply.
                for ep in replies.replies.iter_mut() {
                    if ep.endpoint == endpoint {
                        if ep.reply.has_data() {
                            #[cfg(feature = "debug_ctap")]
                            writeln!(
                                Console::new(),
                                "Warning overwriting existing reply for endpoint {}",
                                endpoint as usize
                            )
                            .unwrap();
                        }
                        ep.reply = reply;
                        break;
                    }
                }
            }
        }

        if ctap.env().clock().is_elapsed(&led_blink_timer) {
            // Loops quickly when waiting for U2F user presence, so the next LED blink
            // state is only set if enough time has elapsed.
            led_counter += 1;
            led_blink_timer = ctap.env().clock().make_timer(KEEPALIVE_DELAY)
        }

        if ctap.should_wink() {
            wink_leds(led_counter);
        } else {
            #[cfg(not(feature = "with_ctap1"))]
            switch_off_leds();
            #[cfg(feature = "with_ctap1")]
            if ctap.u2f_needs_user_presence() {
                // Flash the LEDs with an almost regular pattern. The inaccuracy comes from
                // delay caused by processing and sending of packets.
                blink_leds(led_counter);
            } else {
                switch_off_leds();
            }
        }
    }
}

#[cfg(feature = "debug_ctap")]
fn print_packet_notice(notice_text: &str, now_us: usize) {
    writeln!(
        Console::new(),
        "{} at {}.{:06} s",
        notice_text,
        now_us / 1_000_000,
        now_us % 1_000_000
    )
    .unwrap();
}
