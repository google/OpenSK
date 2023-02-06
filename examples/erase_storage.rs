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

use core::fmt::Write;
use ctap2::env::tock::take_storage;
use libtock_console::Console;
use libtock_drivers::result::FlexUnwrap;
use libtock_leds::Leds;
use libtock_platform as platform;
#[cfg(not(feature = "std"))]
use libtock_runtime::{set_main, stack_size, TockSyscalls};
#[cfg(feature = "std")]
use libtock_unittest::fake;
use persistent_store::{Storage, StorageIndex};
use platform::DefaultConfig;

#[cfg(not(feature = "std"))]
stack_size! {0x800}
#[cfg(not(feature = "std"))]
set_main! {main}

#[cfg(feature = "std")]
type Syscalls = fake::Syscalls;
#[cfg(not(feature = "std"))]
type Syscalls = TockSyscalls;

fn is_page_erased(storage: &dyn Storage, page: usize) -> bool {
    let index = StorageIndex { page, byte: 0 };
    let length = storage.page_size();
    storage
        .read_slice(index, length)
        .unwrap()
        .iter()
        .all(|&x| x == 0xff)
}

fn main() {
    Leds::<Syscalls>::on(1).map_err(|e| e.into()).flex_unwrap(); // red on dongle
    let mut storage = take_storage::<Syscalls, DefaultConfig>().unwrap();
    let num_pages = storage.num_pages();
    let mut console = Console::<Syscalls>::writer();
    writeln!(console, "Erase {} pages of storage:", num_pages).unwrap();
    for page in 0..num_pages {
        write!(console, "- Page {} ", page).unwrap();
        if is_page_erased(&storage, page) {
            writeln!(console, "skipped (was already erased).").unwrap();
        } else {
            storage.erase_page(page).unwrap();
            writeln!(console, "erased.").unwrap();
        }
    }
    writeln!(console, "Done.").unwrap();
    Leds::<Syscalls>::on(1).map_err(|e| e.into()).flex_unwrap();
    Leds::<Syscalls>::off(0).map_err(|e| e.into()).flex_unwrap(); // green on dongle
}
