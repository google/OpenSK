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
use core::convert::TryFrom;
use core::convert::TryInto;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
use ctap2::api::connection::{HidConnection, SendOrRecvStatus};
#[cfg(feature = "debug_ctap")]
use ctap2::clock::CtapClock;
use ctap2::clock::{new_clock, Clock, ClockInt, KEEPALIVE_DELAY, KEEPALIVE_DELAY_MS};
#[cfg(feature = "with_ctap1")]
use ctap2::env::tock::blink_leds;
use ctap2::env::tock::{switch_off_leds, wink_leds, TockEnv};
use ctap2::Transport;
#[cfg(feature = "debug_ctap")]
use embedded_time::duration::Microseconds;
use embedded_time::duration::Milliseconds;
#[cfg(feature = "with_ctap1")]
use libtock_drivers::buttons::{self, ButtonState};
#[cfg(feature = "debug_ctap")]
use libtock_drivers::console::Console;
use libtock_drivers::result::FlexUnwrap;
use libtock_drivers::timer::Duration;
use libtock_drivers::usb_ctap_hid;

libtock_core::stack_size! {0x4000}

const SEND_TIMEOUT: Milliseconds<ClockInt> = Milliseconds(1000);
const KEEPALIVE_DELAY_TOCK: Duration<isize> = Duration::from_ms(KEEPALIVE_DELAY_MS as isize);

fn main() {
    let clock = new_clock();

    // Setup USB driver.
    if !usb_ctap_hid::setup() {
        panic!("Cannot setup USB driver");
    }

    let boot_time = clock.try_now().unwrap();
    let env = TockEnv::new();
    let mut ctap = ctap2::Ctap::new(env, boot_time);

    let mut led_counter = 0;
    let mut last_led_increment = boot_time;

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

        let mut pkt_request = [0; 64];
        let usb_endpoint =
            match usb_ctap_hid::recv_with_timeout(&mut pkt_request, KEEPALIVE_DELAY_TOCK)
                .flex_unwrap()
            {
                usb_ctap_hid::SendOrRecvStatus::Received(endpoint) => {
                    #[cfg(feature = "debug_ctap")]
                    print_packet_notice("Received packet", &clock);
                    Some(endpoint)
                }
                usb_ctap_hid::SendOrRecvStatus::Sent => {
                    panic!("Returned transmit status on receive")
                }
                usb_ctap_hid::SendOrRecvStatus::Timeout => None,
            };

        let now = clock.try_now().unwrap();
        #[cfg(feature = "with_ctap1")]
        {
            if button_touched.get() {
                ctap.state().u2f_grant_user_presence(now);
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
        ctap.update_timeouts(now);

        if let Some(endpoint) = usb_endpoint {
            let transport = match endpoint {
                usb_ctap_hid::UsbEndpoint::MainHid => Transport::MainHid,
                #[cfg(feature = "vendor_hid")]
                usb_ctap_hid::UsbEndpoint::VendorHid => Transport::VendorHid,
            };
            let reply = ctap.process_hid_packet(&pkt_request, transport, now);
            // This block handles sending packets.
            for mut pkt_reply in reply {
                let hid_connection = transport.hid_connection(ctap.env());
                match hid_connection.send_or_recv_with_timeout(&mut pkt_reply, SEND_TIMEOUT) {
                    Ok(SendOrRecvStatus::Timeout) => {
                        #[cfg(feature = "debug_ctap")]
                        print_packet_notice("Sending packet timed out", &clock);
                        // TODO: reset the ctap_hid state.
                        // Since sending the packet timed out, we cancel this reply.
                        break;
                    }
                    Ok(SendOrRecvStatus::Sent) => {
                        #[cfg(feature = "debug_ctap")]
                        print_packet_notice("Sent packet", &clock);
                    }
                    Ok(SendOrRecvStatus::Received) => {
                        #[cfg(feature = "debug_ctap")]
                        print_packet_notice("Received an UNEXPECTED packet", &clock);
                        // TODO: handle this unexpected packet.
                    }
                    Err(_) => panic!("Error sending packet"),
                }
            }
        }

        let now = clock.try_now().unwrap();
        if let Some(wait_duration) = now.checked_duration_since(&last_led_increment) {
            let wait_duration: Milliseconds<ClockInt> = wait_duration.try_into().unwrap();
            if wait_duration > KEEPALIVE_DELAY {
                // Loops quickly when waiting for U2F user presence, so the next LED blink
                // state is only set if enough time has elapsed.
                led_counter += 1;
                last_led_increment = now;
            }
        } else {
            // This branch means the clock frequency changed. This should never happen.
            led_counter += 1;
            last_led_increment = now;
        }

        if ctap.hid().should_wink(now) {
            wink_leds(led_counter);
        } else {
            #[cfg(not(feature = "with_ctap1"))]
            switch_off_leds();
            #[cfg(feature = "with_ctap1")]
            if ctap.state().u2f_needs_user_presence(now) {
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
fn print_packet_notice(notice_text: &str, clock: &CtapClock) {
    let now = clock.try_now().unwrap();
    let now_us = Microseconds::<u64>::try_from(now.duration_since_epoch())
        .unwrap()
        .0;
    writeln!(
        Console::new(),
        "{} at {}.{:06} s",
        notice_text,
        now_us / 1_000_000,
        now_us % 1_000_000
    )
    .unwrap();
}
