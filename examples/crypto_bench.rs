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

use alloc::format;
use alloc::vec::Vec;
use core::fmt::Write;
use crypto::{
    aes256, cbc, ecdsa, rng256, sha256, Decrypt16BytesBlock, Encrypt16BytesBlock, Hash256,
};
use libtock_drivers::console::Console;
use libtock_drivers::result::FlexUnwrap;
use libtock_drivers::timer;
use libtock_drivers::timer::Timer;
use libtock_drivers::timer::Timestamp;

fn main() {
    let mut console = Console::new();
    // Setup the timer with a dummy callback (we only care about reading the current time, but the
    // API forces us to set an alarm callback too).
    let mut with_callback = timer::with_callback(|_, _| {});
    let timer = with_callback.init().flex_unwrap();

    let mut rng = rng256::TockRng256 {};

    writeln!(console, "****************************************").unwrap();
    writeln!(
        console,
        "Clock frequency: {} Hz",
        timer.clock_frequency().hz()
    )
    .unwrap();

    // AES
    bench(&mut console, &timer, "aes256::EncryptionKey::new", || {
        aes256::EncryptionKey::new(&[0; 32]);
    });
    let ek = aes256::EncryptionKey::new(&[0; 32]);
    bench(&mut console, &timer, "aes256::DecryptionKey::new", || {
        aes256::DecryptionKey::new(&ek);
    });
    let dk = aes256::DecryptionKey::new(&ek);

    bench(
        &mut console,
        &timer,
        "aes256::EncryptionKey::encrypt_block",
        || {
            ek.encrypt_block(&mut [0; 16]);
        },
    );
    bench(
        &mut console,
        &timer,
        "aes256::DecryptionKey::decrypt_block",
        || {
            dk.decrypt_block(&mut [0; 16]);
        },
    );

    // CBC
    let mut blocks = Vec::new();
    for i in 0..8 {
        blocks.resize(1 << i, [0; 16]);
        bench(
            &mut console,
            &timer,
            &format!("cbc::cbc_encrypt({} bytes)", blocks.len() * 16),
            || {
                cbc::cbc_encrypt(&ek, [0; 16], &mut blocks);
            },
        );
    }
    drop(blocks);

    let mut blocks = Vec::new();
    for i in 0..8 {
        blocks.resize(1 << i, [0; 16]);
        bench(
            &mut console,
            &timer,
            &format!("cbc::cbc_decrypt({} bytes)", blocks.len() * 16),
            || {
                cbc::cbc_decrypt(&dk, [0; 16], &mut blocks);
            },
        );
    }
    drop(blocks);

    // SHA-256
    let mut contents = Vec::new();
    for i in 0..8 {
        contents.resize(16 << i, 0);
        bench(
            &mut console,
            &timer,
            &format!("sha256::Sha256::update({} bytes)", contents.len()),
            || {
                let mut sha = sha256::Sha256::new();
                sha.update(&contents);
                sha.finalize();
            },
        );
    }
    drop(contents);

    // ECDSA
    bench(&mut console, &timer, "ecdsa::SecKey::gensk", || {
        ecdsa::SecKey::gensk(&mut rng);
    });
    let k = ecdsa::SecKey::gensk(&mut rng);
    bench(&mut console, &timer, "ecdsa::SecKey::genpk", || {
        k.genpk();
    });
    bench(
        &mut console,
        &timer,
        "ecdsa::SecKey::sign_rng::<sha256::Sha256, _>",
        || {
            k.sign_rng::<sha256::Sha256, _>(&[], &mut rng);
        },
    );
    bench(
        &mut console,
        &timer,
        "ecdsa::SecKey::sign_rfc6979::<sha256::Sha256>",
        || {
            k.sign_rfc6979::<sha256::Sha256>(&[]);
        },
    );

    writeln!(console, "****************************************").unwrap();
    writeln!(console, "All the benchmarks are done.\nHave a nice day!").unwrap();
    writeln!(console, "****************************************").unwrap();
}

fn bench<F>(console: &mut Console, timer: &Timer, title: &str, mut f: F)
where
    F: FnMut(),
{
    writeln!(console, "****************************************").unwrap();
    writeln!(console, "Benchmarking: {}", title).unwrap();
    writeln!(console, "----------------------------------------").unwrap();
    let mut count = 1;
    for _ in 0..30 {
        let start = Timestamp::<f64>::from_clock_value(timer.get_current_clock().flex_unwrap());
        for _ in 0..count {
            f();
        }
        let end = Timestamp::<f64>::from_clock_value(timer.get_current_clock().flex_unwrap());
        let elapsed = (end - start).ms();
        writeln!(
            console,
            "{} ms elapsed for {} iterations ({} ms/iter)",
            elapsed,
            count,
            elapsed / (count as f64)
        )
        .unwrap();
        console.flush();
        if elapsed > 1000.0 {
            break;
        }
        count <<= 1;
    }
}
