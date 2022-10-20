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

#![no_std]

extern crate alloc;
extern crate lang_items;

use core::fmt::Write;
use crypto::sha256::Sha256;
use crypto::{ecdsa, hybrid};
use libtock_drivers::console::Console;
use libtock_drivers::result::FlexUnwrap;
use libtock_drivers::timer;
use libtock_drivers::timer::{Timer, Timestamp};
use rng256::Rng256;
// use ctap2::env::tock::{take_storage, TockStorage};
// use persistent_store::Store;

libtock_core::stack_size! {0x11800}

/*fn boot_store(mut storage: TockStorage, erase: bool) -> Store<TockStorage> {
    use persistent_store::Storage;
    let num_pages = storage.num_pages();
    if erase {
        for page in 0..num_pages {
            storage.erase_page(page).unwrap();
        }
    }
    Store::new(storage).ok().unwrap()
}*/

fn main() {
    // Fix to be faster.
    //let storage = take_storage().unwrap();
    //let mut _store = boot_store(storage, true);

    let mut console = Console::new();
    let mut rng = rng256::TockRng256 {};
    // Setup the timer with a dummy callback (we only care about reading the current time, but the
    // API forces us to set an alarm callback too).
    let mut with_callback = timer::with_callback(|_, _| {});
    let timer = with_callback.init().flex_unwrap();

    writeln!(console, "****************************************").unwrap();
    writeln!(
        console,
        "Clock frequency: {} Hz",
        timer.clock_frequency().hz()
    )
    .unwrap();

    custom_bench(
        &mut console,
        &timer,
        "ECDSA keygen",
        1000,
        || {},
        |()| {
            let k = ecdsa::SecKey::gensk(&mut rng);
            k.genpk();
        },
    );

    custom_bench(
        &mut console,
        &timer,
        "ECDSA sign",
        1000,
        || {
            let k = ecdsa::SecKey::gensk(&mut rng);
            let mut m = [0; 64];
            rng.fill_bytes(&mut m);
            (k, m)
        },
        |(k, m)| {
            k.sign_rfc6979::<Sha256>(&m);
        },
    );

    custom_bench(
        &mut console,
        &timer,
        "dilithium::SecKey::gensk_with_pk",
        1000,
        || {},
        |()| {
            dilithium::sign::SecKey::gensk_with_pk(&mut rng);
        },
    );

    custom_bench(
        &mut console,
        &timer,
        "dilithium::SecKey::sign",
        1000,
        || {
            let sk = dilithium::sign::SecKey::gensk(&mut rng);
            let mut m = [0; 64];
            rng.fill_bytes(&mut m);
            (sk, m)
        },
        |(sk, m)| {
            sk.sign(&m);
        },
    );

    custom_bench(
        &mut console,
        &timer,
        "hybrid::SecKey::gensk_with_pk",
        1000,
        || {},
        |()| {
            hybrid::SecKey::gensk_with_pk(&mut rng);
        },
    );

    custom_bench(
        &mut console,
        &timer,
        "hybrid::SecKey::sign",
        1000,
        || {
            let sk = hybrid::SecKey::gensk(&mut rng);
            let mut m = [0; 64];
            rng.fill_bytes(&mut m);
            (sk, m)
        },
        |(sk, m)| {
            sk.sign_rfc6979::<Sha256>(&m).to_asn1_der();
        },
    );
}

fn custom_bench<I, O, F, S>(
    console: &mut Console,
    timer: &Timer,
    title: &str,
    iter_count: usize,
    mut setup: S,
    mut f: F,
) where
    S: FnMut() -> I,
    F: FnMut(I) -> O,
{
    writeln!(console, "****************************************").unwrap();
    writeln!(console, "Benchmarking: {}", title).unwrap();
    writeln!(console, "----------------------------------------").unwrap();

    let mut elapsed = 0.0;

    for _ in 1..(iter_count + 1) {
        let inputs = setup();
        let start = Timestamp::<f64>::from_clock_value(timer.get_current_clock().flex_unwrap());
        f(inputs);
        let end = Timestamp::<f64>::from_clock_value(timer.get_current_clock().flex_unwrap());

        let mut run_duration = (end - start).ms();

        // After 512 seconds, we get a negative difference between the start
        // time and the end time.
        if run_duration < 0.0 {
            run_duration += 512.0 * 1000.0;
        }

        elapsed += run_duration;

        writeln!(console, "{},", run_duration).unwrap();
        console.flush();
    }

    writeln!(
        console,
        "Total: {} ms elapsed for {} iterations ({} ms/iter)",
        elapsed,
        iter_count,
        elapsed / (iter_count as f64)
    )
    .unwrap();
    console.flush();
}
