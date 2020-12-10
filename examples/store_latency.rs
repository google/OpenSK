// Copyright 2019-2020 Google LLC
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

use alloc::vec;
use core::fmt::Write;
use ctap2::embedded_flash::{new_storage, Storage};
use libtock_drivers::console::Console;
use libtock_drivers::timer::{self, Duration, Timer, Timestamp};
use persistent_store::Store;

fn timestamp(timer: &Timer) -> Timestamp<f64> {
    Timestamp::<f64>::from_clock_value(timer.get_current_clock().ok().unwrap())
}

fn measure<T>(timer: &Timer, operation: impl FnOnce() -> T) -> (T, Duration<f64>) {
    let before = timestamp(timer);
    let result = operation();
    let after = timestamp(timer);
    (result, after - before)
}

// Only use one store at a time.
unsafe fn boot_store(num_pages: usize, erase: bool) -> Store<Storage> {
    let mut storage = new_storage(num_pages);
    if erase {
        for page in 0..num_pages {
            use persistent_store::Storage;
            storage.erase_page(page).unwrap();
        }
    }
    Store::new(storage).ok().unwrap()
}

fn compute_latency(timer: &Timer, num_pages: usize, key_increment: usize, word_length: usize) {
    let mut console = Console::new();
    writeln!(
        console,
        "\nLatency for num_pages={} key_increment={} word_length={}.",
        num_pages, key_increment, word_length
    )
    .unwrap();

    let mut store = unsafe { boot_store(num_pages, true) };
    let total_capacity = store.capacity().unwrap().total();
    assert_eq!(store.capacity().unwrap().used(), 0);
    assert_eq!(store.lifetime().unwrap().used(), 0);

    // Burn N words to align the end of the user capacity with the virtual capacity.
    store.insert(0, &vec![0; 4 * (num_pages - 1)]).unwrap();
    store.remove(0).unwrap();
    assert_eq!(store.capacity().unwrap().used(), 0);
    assert_eq!(store.lifetime().unwrap().used(), num_pages);

    // Insert entries until there is space for one more.
    let count = total_capacity / (1 + word_length) - 1;
    let ((), time) = measure(timer, || {
        for i in 0..count {
            let key = 1 + key_increment * i;
            // For some reason the kernel sometimes fails.
            while store.insert(key, &vec![0; 4 * word_length]).is_err() {
                // We never enter this loop in practice, but we still need it for the kernel.
                writeln!(console, "Retry insert.").unwrap();
            }
        }
    });
    writeln!(console, "Setup: {:.1}ms for {} entries.", time.ms(), count).unwrap();

    // Measure latency of insert.
    let key = 1 + key_increment * count;
    let ((), time) = measure(&timer, || {
        store.insert(key, &vec![0; 4 * word_length]).unwrap()
    });
    writeln!(console, "Insert: {:.1}ms.", time.ms()).unwrap();
    assert_eq!(
        store.lifetime().unwrap().used(),
        num_pages + (1 + count) * (1 + word_length)
    );

    // Measure latency of boot.
    let (mut store, time) = measure(&timer, || unsafe { boot_store(num_pages, false) });
    writeln!(console, "Boot: {:.1}ms.", time.ms()).unwrap();

    // Measure latency of remove.
    let ((), time) = measure(&timer, || store.remove(key).unwrap());
    writeln!(console, "Remove: {:.1}ms.", time.ms()).unwrap();

    // Measure latency of compaction.
    let length = total_capacity + num_pages - store.lifetime().unwrap().used();
    if length > 0 {
        // Fill the store such that compaction is needed for one word.
        store.insert(0, &vec![0; 4 * (length - 1)]).unwrap();
        store.remove(0).unwrap();
    }
    assert!(store.capacity().unwrap().remaining() > 0);
    assert_eq!(store.lifetime().unwrap().used(), num_pages + total_capacity);
    let ((), time) = measure(timer, || store.prepare(1).unwrap());
    writeln!(console, "Compaction: {:.1}ms.", time.ms()).unwrap();
    assert!(store.lifetime().unwrap().used() > total_capacity + num_pages);
}

fn main() {
    let mut with_callback = timer::with_callback(|_, _| {});
    let timer = with_callback.init().ok().unwrap();

    writeln!(Console::new(), "\nRunning 4 tests...").unwrap();
    // Those non-overwritten 50 words entries simulate credentials.
    compute_latency(&timer, 3, 1, 50);
    compute_latency(&timer, 20, 1, 50);
    // Those overwritten 1 word entries simulate counters.
    compute_latency(&timer, 3, 0, 1);
    compute_latency(&timer, 6, 0, 1);
    writeln!(Console::new(), "\nDone.").unwrap();

    // Results on nrf52840dk:
    //
    // | Pages | Overwrite | Length    | Boot     | Compaction | Insert  | Remove  |
    // | ----- | --------- | --------- | -------  | ---------- | ------  | ------- |
    // | 3     | no        | 50 words  | 2.0 ms   | 132.5 ms   | 4.8 ms  | 1.2 ms  |
    // | 20    | no        | 50 words  | 7.4 ms   | 135.5 ms   | 10.2 ms | 3.9 ms  |
    // | 3     | yes       | 1 word    | 21.9 ms  | 94.5 ms    | 12.4 ms | 5.9 ms  |
    // | 6     | yes       | 1 word    | 55.2 ms  | 100.8 ms   | 24.8 ms | 12.1 ms |
}
