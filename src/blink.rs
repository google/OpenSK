// Copyright 2025 Google LLC
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

use core::num::NonZero;

use wasefire::sync::Mutex;
use wasefire::{led, timer};

pub(crate) struct Blink {
    _private: (),
}

impl Blink {
    pub(crate) fn new_ms(period_ms: usize) -> Self {
        State::start_ms(&mut STATE.lock(), period_ms);
        Blink { _private: () }
    }
}

impl Drop for Blink {
    fn drop(&mut self) {
        State::stop(&mut STATE.lock());
    }
}

#[cfg(not(feature = "led-1"))]
const LED_ID: usize = 0;
#[cfg(feature = "led-1")]
const LED_ID: usize = 1;

static STATE: Mutex<Option<State>> = Mutex::new(None);

struct State {
    count: NonZero<usize>,
    timer: timer::Timer<Handler>,
}

impl State {
    fn start_ms(this: &mut Option<State>, period_ms: usize) {
        match this {
            None => {
                let timer = timer::Timer::new(Handler);
                led::set(LED_ID, led::On);
                timer.start_ms(timer::Mode::Periodic, period_ms);
                *this = Some(State {
                    count: NonZero::new(1).unwrap(),
                    timer,
                });
            }
            Some(state) => state.count = state.count.checked_add(1).unwrap(),
        }
    }

    fn stop(this: &mut Option<State>) {
        let Some(state) = this else { unreachable!() };
        if state.count.get() == 1 {
            state.timer.stop();
            led::set(LED_ID, led::Off);
            *this = None;
        } else {
            state.count = NonZero::new(state.count.get() - 1).unwrap();
        }
    }
}

struct Handler;

impl timer::Handler for Handler {
    fn event(&self) {
        led::set(LED_ID, !led::get(LED_ID));
    }
}
