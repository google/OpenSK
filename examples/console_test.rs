// Copyright 2020 Google LLC
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

extern crate lang_items;

use libtock_console::Console;
use libtock_drivers::result::FlexUnwrap;
#[cfg(not(feature = "std"))]
use libtock_runtime::{set_main, stack_size, TockSyscalls};
#[cfg(feature = "std")]
use libtock_unittest::fake;

#[cfg(not(feature = "std"))]
stack_size! {0x800}
#[cfg(not(feature = "std"))]
set_main! {main}

#[cfg(feature = "std")]
type Syscalls = fake::Syscalls;
#[cfg(not(feature = "std"))]
type Syscalls = TockSyscalls;

fn main() {
    // Write messages of length up to the console driver's buffer size.
    let mut buf = [0; 1024];
    loop {
        for i in 1..buf.len() {
            for byte in buf.iter_mut().take(i) {
                *byte = b'0' + ((i % 10) as u8);
            }
            buf[i] = b'\n';
            Console::<Syscalls>::write(&buf[..(i + 1)])
                .map_err(|e| e.into())
                .flex_unwrap();
        }
    }
}
