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

use core::sync::atomic::Ordering::Relaxed;

use portable_atomic_util::Arc;
#[cfg(not(feature = "fingerprint"))]
use wasefire::button;
#[cfg(feature = "fingerprint")]
use wasefire::fingerprint as button;
use wasefire::sync::{AtomicBool, Mutex};

pub(crate) struct Touch {
    touched: Arc<AtomicBool>,
}

impl Touch {
    pub(crate) fn new() -> Self {
        Touch {
            touched: State::start(&mut STATE.lock()),
        }
    }

    pub(crate) fn is_present(&self) -> bool {
        self.touched.load(Relaxed)
    }
}

impl Drop for Touch {
    fn drop(&mut self) {
        if Arc::strong_count(&self.touched) == 2 {
            // We're the last object, so we can stop listening.
            *STATE.lock() = None;
        }
    }
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

struct State {
    button: button::Listener<Handler>,
    _blink: crate::blink::Blink,
    touched: Arc<AtomicBool>,
}

impl State {
    fn start(this: &mut Option<State>) -> Arc<AtomicBool> {
        match this {
            None => {
                #[cfg(not(feature = "fingerprint"))]
                let button = button::Listener::new(0, Handler).unwrap();
                #[cfg(feature = "fingerprint")]
                let button = button::Listener::new(Handler).unwrap();
                let blink = crate::blink::Blink::new_ms(500);
                let touched = Arc::new(AtomicBool::new(false));
                *this = Some(State {
                    button,
                    _blink: blink,
                    touched: touched.clone(),
                });
                touched
            }
            Some(state) => state.touched.clone(),
        }
    }

    fn touch(this: &mut Option<State>) {
        let Some(state) = this.take() else {
            unreachable!()
        };
        state.button.stop();
        state.touched.store(true, Relaxed);
    }
}

struct Handler;

impl button::Handler for Handler {
    #[cfg(not(feature = "fingerprint"))]
    fn event(&self, state: button::State) {
        if matches!(state, button::State::Pressed) {
            State::touch(&mut STATE.lock());
        }
    }
    #[cfg(feature = "fingerprint")]
    fn event(&self) {
        State::touch(&mut STATE.lock());
    }
}
