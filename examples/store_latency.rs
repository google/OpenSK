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

#![cfg_attr(any(target_arch = "arm", target_arch = "riscv32"), tock_syscalls)]
#![no_main]
#![no_std]

extern crate alloc;
extern crate lang_items;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::fmt::Write;
use ctap2::env::tock::{take_storage, TockStorage};
use libtock_console::Console;
use libtock_drivers::result::FlexUnwrap;
use libtock_drivers::timer::{self, Duration, Timer, Timestamp};
use libtock_platform::DefaultConfig;
#[cfg(feature = "tock_syscalls")]
use libtock_runtime::{set_main, stack_size, TockSyscalls};
#[cfg(not(feature = "tock_syscalls"))]
use libtock_unittest::fake;
use persistent_store::Store;

#[cfg(feature = "tock_syscalls")]
stack_size! {0x800}
#[cfg(feature = "tock_syscalls")]
set_main! {main}

#[cfg(feature = "tock_syscalls")]
type Syscalls = TockSyscalls;
#[cfg(not(feature = "tock_syscalls"))]
type Syscalls = fake::Syscalls;

fn timestamp(timer: &Timer<Syscalls>) -> Timestamp<f64> {
    Timestamp::<f64>::from_clock_value(timer.get_current_counter_ticks().ok().unwrap())
}

fn measure<T>(timer: &Timer<Syscalls>, operation: impl FnOnce() -> T) -> (T, Duration<f64>) {
    let before = timestamp(timer);
    let result = operation();
    let after = timestamp(timer);
    (result, after - before)
}

fn boot_store(
    mut storage: TockStorage<Syscalls, DefaultConfig>,
    erase: bool,
) -> Store<TockStorage<Syscalls, DefaultConfig>> {
    use persistent_store::Storage;
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
    num_pages: usize,
}

fn storage_config(storage: &TockStorage<Syscalls, DefaultConfig>) -> StorageConfig {
    use persistent_store::Storage;
    StorageConfig {
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
    storage: TockStorage<Syscalls, DefaultConfig>,
    timer: &Timer<Syscalls>,
    num_pages: usize,
    key_increment: usize,
    word_length: usize,
) -> (TockStorage<Syscalls, DefaultConfig>, Stat) {
    let mut stat = Stat {
        key_increment,
        entry_length: word_length,
        ..Default::default()
    };

    let mut console = Console::<Syscalls>::writer();
    writeln!(
        console,
        "\nLatency for key_increment={} word_length={}.",
        key_increment, word_length
    )
    .unwrap();

    let mut store = boot_store(storage, true);
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
    let storage = store.extract_storage();
    let (mut store, time) = measure(timer, || boot_store(storage, false));
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

    (store.extract_storage(), stat)
}

fn main() {
    let mut with_callback = timer::with_callback::<Syscalls, DefaultConfig, _>(|_| {});

    let timer = with_callback.init().flex_unwrap();
    let storage = take_storage::<Syscalls, DefaultConfig>().unwrap();
    let config = storage_config(&storage);
    let mut stats = Vec::new();
    let mut console = Console::<Syscalls>::writer();

    writeln!(console, "\nRunning 2 tests...").unwrap();
    // Simulate a store full of credentials (of 50 words).
    let (storage, stat) = compute_latency(storage, &timer, config.num_pages, 1, 50);
    stats.push(stat);
    // Simulate a store full of increments of a single counter.
    let (_storage, stat) = compute_latency(storage, &timer, config.num_pages, 0, 1);
    stats.push(stat);
    writeln!(console, "\nDone.\n").unwrap();

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
    writeln!(console, "Copy to examples/store_latency.rs:\n").unwrap();
    writeln!(console, "{:?}", config).unwrap();
    write_matrix(matrix);

    // Results for nrf52840dk_opensk:
    // StorageConfig { num_pages: 20 }
    // Overwrite    Length      Boot  Compaction   Insert  Removon
    //        no  50 words   18.6 ms    145.8 ms  21.0 ms  9.8 ms
    //       yes   1 words  335.8 ms    100.6 ms  11.7 ms  5.7 ms
}

fn align(x: &str, n: usize) {
    let mut console = Console::<Syscalls>::writer();
    for _ in 0..n.saturating_sub(x.len()) {
        write!(console, " ").unwrap();
    }
    write!(console, "{}", x).unwrap();
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
        writeln!(Console::<Syscalls>::writer()).unwrap();
    }
}
