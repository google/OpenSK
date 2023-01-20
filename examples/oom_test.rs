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

#![no_std]

extern crate alloc;
extern crate lang_items;

#[cfg(not(feature = "std"))]
use libtock_runtime::{set_main, stack_size, TockSyscalls};

use alloc::vec::Vec;
use core::fmt::Write;
use libtock_console::Console;
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
    let mut console = Console::<Syscalls>::writer();
    writeln!(console, "****************************************").unwrap();
    for i in 0.. {
        writeln!(console, "Allocating {} bytes...", 1 << i).unwrap();
        let x: Vec<u8> = Vec::with_capacity(1 << i);
        writeln!(console, "Allocated!").unwrap();
        drop(x);
        writeln!(console, "Dropped!").unwrap();
    }
}
