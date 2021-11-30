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

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::fmt::Write;
use ctap2::embedded_flash::{new_storage, Storage};
use libtock_drivers::console::Console;
use libtock_drivers::timer::{self, Duration, Timer, Timestamp};
use persistent_store::Store;

libtock_core::stack_size! {0x2000}

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
unsafe fn boot_store(erase: bool) -> Store<Storage> {
    use persistent_store::Storage;
    let mut storage = new_storage().unwrap();
    let num_pages = storage.num_pages();
    if erase {
        for page in 0..num_pages {
            storage.erase_page(page).unwrap();
        }
    }
    Store::new(storage).ok().unwrap()
}

#[derive(Debug)]
struct StorageConfig {
    _page_size: usize,
    num_pages: usize,
}

fn storage_config() -> StorageConfig {
    use persistent_store::Storage;
    let storage = new_storage().unwrap();
    StorageConfig {
        _page_size: storage.page_size(),
        num_pages: storage.num_pages(),
    }
}

#[derive(Default)]
struct Stat {
    key_increment: usize,
    entry_length: usize, // words
    boot_ms: f64,
    compaction_ms: f64,
    insert_ms: f64,
    remove_ms: f64,
}

fn compute_latency(
    timer: &Timer,
    num_pages: usize,
    key_increment: usize,
    word_length: usize,
) -> Stat {
    let mut stat = Stat {
        key_increment,
        entry_length: word_length,
        ..Default::default()
    };

    let mut console = Console::new();
    writeln!(
        console,
        "\nLatency for key_increment={} word_length={}.",
        key_increment, word_length
    )
    .unwrap();

    let mut store = unsafe { boot_store(true) };
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
            store.insert(key, &vec![0; 4 * word_length]).unwrap();
        }
    });
    writeln!(console, "Setup: {:.1}ms for {} entries.", time.ms(), count).unwrap();

    // Measure latency of insert.
    let key = 1 + key_increment * count;
    let ((), time) = measure(timer, || {
        store.insert(key, &vec![0; 4 * word_length]).unwrap()
    });
    writeln!(console, "Insert: {:.1}ms.", time.ms()).unwrap();
    stat.insert_ms = time.ms();
    assert_eq!(
        store.lifetime().unwrap().used(),
        num_pages + (1 + count) * (1 + word_length)
    );

    // Measure latency of boot.
    let (mut store, time) = measure(timer, || unsafe { boot_store(false) });
    writeln!(console, "Boot: {:.1}ms.", time.ms()).unwrap();
    stat.boot_ms = time.ms();

    // Measure latency of remove.
    let ((), time) = measure(timer, || store.remove(key).unwrap());
    writeln!(console, "Remove: {:.1}ms.", time.ms()).unwrap();
    stat.remove_ms = time.ms();

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
    stat.compaction_ms = time.ms();
    assert!(store.lifetime().unwrap().used() > total_capacity + num_pages);

    stat
}

fn main() {
    let mut with_callback = timer::with_callback(|_, _| {});
    let timer = with_callback.init().ok().unwrap();
    let config = storage_config();
    let mut stats = Vec::new();

    writeln!(Console::new(), "\nRunning 2 tests...").unwrap();
    // Simulate a store full of credentials (of 50 words).
    stats.push(compute_latency(&timer, config.num_pages, 1, 50));
    // Simulate a store full of increments of a single counter.
    stats.push(compute_latency(&timer, config.num_pages, 0, 1));
    writeln!(Console::new(), "\nDone.\n").unwrap();

    const HEADERS: &[&str] = &[
        "Overwrite",
        "Length",
        "Boot",
        "Compaction",
        "Insert",
        "Remove",
    ];
    let mut matrix = vec![HEADERS.iter().map(|x| x.to_string()).collect()];
    for stat in stats {
        matrix.push(vec![
            if stat.key_increment == 0 { "yes" } else { "no" }.to_string(),
            format!("{} words", stat.entry_length),
            format!("{:.1} ms", stat.boot_ms),
            format!("{:.1} ms", stat.compaction_ms),
            format!("{:.1} ms", stat.insert_ms),
            format!("{:.1} ms", stat.remove_ms),
        ]);
    }
    writeln!(Console::new(), "Copy to examples/store_latency.rs:\n").unwrap();
    writeln!(Console::new(), "{:?}", config).unwrap();
    write_matrix(matrix);

    // Results for nrf52840dk_opensk:
    // StorageConfig { page_size: 4096, num_pages: 20 }
    // Overwrite    Length      Boot  Compaction   Insert  Remove
    //        no  50 words   16.2 ms    143.8 ms  18.3 ms  8.4 ms
    //       yes   1 words  303.8 ms     97.9 ms   9.7 ms  4.7 ms
}

fn align(x: &str, n: usize) {
    for _ in 0..n.saturating_sub(x.len()) {
        write!(Console::new(), " ").unwrap();
    }
    write!(Console::new(), "{}", x).unwrap();
}

fn write_matrix(mut m: Vec<Vec<String>>) {
    if m.is_empty() {
        return;
    }
    let num_cols = m.iter().map(|r| r.len()).max().unwrap();
    let mut col_len = vec![0; num_cols];
    for row in &mut m {
        row.resize(num_cols, String::new());
        for col in 0..num_cols {
            col_len[col] = core::cmp::max(col_len[col], row[col].len());
        }
    }
    for row in m {
        for col in 0..num_cols {
            align(&row[col], col_len[col] + 2 * (col > 0) as usize);
        }
        writeln!(Console::new()).unwrap();
    }
}
