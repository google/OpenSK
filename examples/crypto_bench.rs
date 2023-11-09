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

#![no_main]
#![no_std]

extern crate alloc;
extern crate lang_items;

use alloc::format;
use alloc::vec::Vec;
use core::fmt::Write;
use core::hint::black_box;
use ctap2::env::tock::{TockEnv, TockRng};
use libtock_console::{Console, ConsoleWriter};
use libtock_drivers::result::FlexUnwrap;
use libtock_drivers::timer;
use libtock_drivers::timer::{Timer, Timestamp};
use libtock_runtime::{set_main, stack_size, TockSyscalls};
use opensk::api::crypto::aes256::Aes256;
use opensk::api::crypto::ecdsa::SecretKey as _;
use opensk::api::crypto::sha256::Sha256;
use opensk::env::{AesKey, EcdsaSk, Sha};

stack_size! {0x2000}
set_main! {main}

type Syscalls = TockSyscalls;

fn main() {
    let mut console = Console::<Syscalls>::writer();
    // Setup the timer with a dummy callback (we only care about reading the current time, but the
    // API forces us to set an alarm callback too).
    let mut with_callback = timer::with_callback(|_| {});
    let timer = with_callback.init().flex_unwrap();

    let mut rng = TockRng::<Syscalls>::default();

    writeln!(console, "****************************************").unwrap();
    writeln!(console, "Clock frequency: {:?} Hz", timer.clock_frequency()).unwrap();

    // AES
    bench(&mut console, &timer, "Aes256::new", || {
        black_box(AesKey::<TockEnv<Syscalls>>::new(&[0; 32]));
    });
    let aes_key = AesKey::<TockEnv<Syscalls>>::new(&[0; 32]);

    bench(&mut console, &timer, "Aes256::encrypt_block", || {
        aes_key.encrypt_block(&mut [0; 16]);
    });
    bench(&mut console, &timer, "Aes256::decrypt_block", || {
        aes_key.decrypt_block(&mut [0; 16]);
    });

    // CBC
    let mut blocks = Vec::new();
    for i in 0..6 {
        blocks.resize(1 << (i + 4), 0);
        bench(
            &mut console,
            &timer,
            &format!("Aes256::encrypt_cbc({} bytes)", blocks.len()),
            || {
                aes_key.encrypt_cbc(&[0; 16], &mut blocks);
            },
        );
    }
    drop(blocks);

    let mut blocks = Vec::new();
    for i in 0..6 {
        blocks.resize(1 << (i + 4), 0);
        bench(
            &mut console,
            &timer,
            &format!("Aes256::decrypt_cbc({} bytes)", blocks.len()),
            || {
                aes_key.decrypt_cbc(&[0; 16], &mut blocks);
            },
        );
    }
    drop(blocks);

    // SHA-256
    let mut contents = Vec::new();
    for i in 0..6 {
        contents.resize(16 << i, 0);
        bench(
            &mut console,
            &timer,
            &format!("Sha256::digest({} bytes)", contents.len()),
            || {
                Sha::<TockEnv<Syscalls>>::digest(&contents);
            },
        );
    }
    drop(contents);

    // ECDSA
    bench(&mut console, &timer, "Ecdsa::SecretKey::random", || {
        EcdsaSk::<TockEnv<Syscalls>>::random(&mut rng);
    });
    let sk = EcdsaSk::<TockEnv<Syscalls>>::random(&mut rng);
    bench(&mut console, &timer, "Ecdsa::SecretKey::public_key", || {
        black_box(sk.public_key());
    });
    bench(&mut console, &timer, "Ecdsa::SecretKey::sign", || {
        sk.sign(&[]);
    });

    writeln!(console, "****************************************").unwrap();
    writeln!(console, "All the benchmarks are done.\nHave a nice day!").unwrap();
    writeln!(console, "****************************************").unwrap();
}

fn bench<F>(console: &mut ConsoleWriter<Syscalls>, timer: &Timer<Syscalls>, title: &str, mut f: F)
where
    F: FnMut(),
{
    writeln!(console, "****************************************").unwrap();
    writeln!(console, "Benchmarking: {}", title).unwrap();
    writeln!(console, "----------------------------------------").unwrap();
    let mut count = 1;
    for _ in 0..30 {
        let start =
            Timestamp::<f64>::from_clock_value(timer.get_current_counter_ticks().flex_unwrap());
        for _ in 0..count {
            f();
        }
        let end =
            Timestamp::<f64>::from_clock_value(timer.get_current_counter_ticks().flex_unwrap());
        let elapsed = (end - start).ms();
        writeln!(
            console,
            "{} ms elapsed for {} iterations ({} ms/iter)",
            elapsed,
            count,
            elapsed / (count as f64)
        )
        .unwrap();
        if elapsed > 1000.0 {
            break;
        }
        count <<= 1;
    }
}
