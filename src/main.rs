// Copyright 2019-2023 Google LLC
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
#![cfg_attr(not(feature = "std"), no_main)]

extern crate alloc;
extern crate arrayref;
extern crate byteorder;
#[cfg(feature = "std")]
extern crate core;
extern crate lang_items;

use core::convert::TryFrom;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
#[cfg(feature = "with_ctap1")]
use ctap2::env::tock::blink_leds;
use ctap2::env::tock::{switch_off_leds, wink_leds, TockEnv};
#[cfg(feature = "with_ctap1")]
use libtock_buttons::Buttons;
#[cfg(feature = "debug_ctap")]
use libtock_console::Console;
#[cfg(feature = "debug_ctap")]
use libtock_console::ConsoleWriter;
use libtock_drivers::result::FlexUnwrap;
use libtock_drivers::timer::Duration;
use libtock_drivers::usb_ctap_hid;
#[cfg(not(feature = "std"))]
use libtock_runtime::{set_main, stack_size, TockSyscalls};
#[cfg(feature = "std")]
use libtock_unittest::fake;
use opensk::api::clock::Clock;
use opensk::api::connection::UsbEndpoint;
use opensk::ctap::hid::HidPacketIterator;
use opensk::ctap::KEEPALIVE_DELAY_MS;
use opensk::env::Env;
use opensk::Transport;

#[cfg(not(feature = "std"))]
stack_size! {0x4000}
#[cfg(not(feature = "std"))]
set_main! {main}

const SEND_TIMEOUT_MS: Duration<isize> = Duration::from_ms(1000);
const KEEPALIVE_DELAY_MS_TOCK: Duration<isize> = Duration::from_ms(KEEPALIVE_DELAY_MS as isize);

#[cfg(not(feature = "vendor_hid"))]
const NUM_ENDPOINTS: usize = 1;
#[cfg(feature = "vendor_hid")]
const NUM_ENDPOINTS: usize = 2;

// The reply/replies that are queued for each endpoint.
struct EndpointReply {
    endpoint: UsbEndpoint,
    reply: HidPacketIterator,
}

#[cfg(feature = "std")]
type SyscallImplementation = fake::Syscalls;
#[cfg(not(feature = "std"))]
type SyscallImplementation = TockSyscalls;

impl EndpointReply {
    pub fn new(endpoint: UsbEndpoint) -> Self {
        EndpointReply {
            endpoint,
            reply: HidPacketIterator::none(),
        }
    }
}

// A single packet to send.
struct SendPacket {
    endpoint: UsbEndpoint,
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
                    endpoint: ep.endpoint,
                    packet,
                });
            }
        }
        None
    }

    pub fn clear(&mut self, endpoint: UsbEndpoint) {
        for ep in self.replies.iter_mut() {
            if ep.endpoint == endpoint {
                *ep = EndpointReply::new(endpoint);
                break;
            }
        }
    }
}

fn main() {
    #[cfg(feature = "debug_ctap")]
    let mut writer = Console::<SyscallImplementation>::writer();
    #[cfg(feature = "debug_ctap")]
    {
        writeln!(writer, "Hello world from OpenSK!").ok().unwrap();
    }
    // Setup USB driver.
    if !usb_ctap_hid::UsbCtapHid::<SyscallImplementation>::setup() {
        panic!("Cannot setup USB driver");
    }

    let env = TockEnv::<SyscallImplementation>::default();
    let mut ctap = opensk::Ctap::new(env);

    let mut led_counter = 0;
    let mut led_blink_timer =
        <<TockEnv<SyscallImplementation> as Env>::Clock as Clock>::Timer::default();

    let mut replies = EndpointReplies::new();

    // Main loop. If CTAP1 is used, we register button presses for U2F while receiving and waiting.
    // The way TockOS and apps currently interact, callbacks need a yield syscall to execute,
    // making consistent blinking patterns and sending keepalives harder.

    #[cfg(feature = "debug_ctap")]
    writeln!(writer, "Entering main ctap loop").unwrap();
    loop {
        #[cfg(feature = "with_ctap1")]
        let num_buttons = Buttons::<SyscallImplementation>::count().ok().unwrap();

        // Variable for use in both the send_and_maybe_recv and recv cases.
        let mut usb_endpoint: Option<UsbEndpoint> = None;
        let mut pkt_request = [0; 64];

        if let Some(packet) = replies.next_packet() {
            match usb_ctap_hid::UsbCtapHid::<SyscallImplementation>::send(
                &packet.packet,
                SEND_TIMEOUT_MS,
                packet.endpoint as u32,
            )
            .flex_unwrap()
            {
                usb_ctap_hid::SendOrRecvStatus::Sent => {
                    #[cfg(feature = "debug_ctap")]
                    print_packet_notice::<SyscallImplementation>(
                        "Sent packet",
                        ctap.env().clock().timestamp_us(),
                        &mut writer,
                    );
                }
                usb_ctap_hid::SendOrRecvStatus::Timeout => {
                    #[cfg(feature = "debug_ctap")]
                    print_packet_notice::<SyscallImplementation>(
                        "Timeout while sending packet",
                        ctap.env().clock().timestamp_us(),
                        &mut writer,
                    );
                    // The client is unresponsive, so we discard all pending packets.
                    replies.clear(packet.endpoint);
                }
                _ => panic!("Unexpected status on USB transmission"),
            };
        } else {
            usb_endpoint =
                match usb_ctap_hid::UsbCtapHid::<SyscallImplementation>::recv_with_timeout(
                    &mut pkt_request,
                    KEEPALIVE_DELAY_MS_TOCK,
                )
                .flex_unwrap()
                {
                    usb_ctap_hid::SendOrRecvStatus::Received(endpoint) => {
                        #[cfg(feature = "debug_ctap")]
                        print_packet_notice::<SyscallImplementation>(
                            "Received packet",
                            ctap.env().clock().timestamp_us(),
                            &mut writer,
                        );
                        UsbEndpoint::try_from(endpoint as usize).ok()
                    }
                    usb_ctap_hid::SendOrRecvStatus::Sent => {
                        panic!("Returned transmit status on receive")
                    }
                    usb_ctap_hid::SendOrRecvStatus::Timeout => None,
                };
        }

        #[cfg(feature = "with_ctap1")]
        {
            let button_touched = (0..num_buttons).any(Buttons::<SyscallImplementation>::is_pressed);
            if button_touched {
                ctap.u2f_grant_user_presence();
            }
        }

        // This call is making sure that even for long inactivity, wrapping clock values
        // don't cause problems with timers.
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
                                Console::<SyscallImplementation>::writer(),
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
            led_blink_timer = ctap.env().clock().make_timer(KEEPALIVE_DELAY_MS)
        }

        if ctap.should_wink() {
            wink_leds::<SyscallImplementation>(led_counter);
        } else {
            #[cfg(not(feature = "with_ctap1"))]
            switch_off_leds::<SyscallImplementation>();
            #[cfg(feature = "with_ctap1")]
            if ctap.u2f_needs_user_presence() {
                // Flash the LEDs with an almost regular pattern. The inaccuracy comes from
                // delay caused by processing and sending of packets.
                blink_leds::<SyscallImplementation>(led_counter);
            } else {
                switch_off_leds::<SyscallImplementation>();
            }
        }
    }
}

#[cfg(feature = "debug_ctap")]
fn print_packet_notice<S: libtock_platform::Syscalls>(
    notice_text: &str,
    now_us: usize,
    writer: &mut ConsoleWriter<S>,
) {
    writeln!(
        writer,
        "{} at {}.{:06} s",
        notice_text,
        now_us / 1_000_000,
        now_us % 1_000_000
    )
    .unwrap();
}
