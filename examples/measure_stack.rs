// Copyright 2022 Google LLC
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
#![feature(asm)]
#![feature(llvm_asm)]
#![allow(dead_code)]

extern crate alloc;
extern crate lang_items;

use core::fmt::Write;
use core::ptr;
use crypto::sha256::Sha256;
use crypto::{ecdsa, hybrid, sha256};
use libtock_drivers::console::Console;

libtock_core::stack_size! {0x11800}

#[inline(never)]
fn read_stack_pointer() -> u32 {
    let x = 1u32;
    let address = &x as *const u32;
    address as u32
}

#[inline(never)]
fn print_stack_pointer(console: &mut Console) {
    let x = 1u32;
    writeln!(console, "Stack pointer: {:?}", &x as *const u32).unwrap();
}

/// Writes a byte pattern to a memory range.
///
/// Since the stack grows to lower addresses, end < start.
/// Addresses after start must be unused, i.e. start must be at least the current stack pointer.
/// Addresses until end should be within the stack area.
unsafe fn paint_memory(start: u32, end: u32) {
    for address in (end..start).step_by(4) {
        let p = address as *const u32;
        ptr::write(p as *mut u32, 0xCDCDCDCD);
    }
}

/// Find the lowest address that does not have the 0xCD pattern.
unsafe fn find_border(start: u32, end: u32) -> u32 {
    for address in (end..start).step_by(4) {
        let p = address as *const u32;
        if ptr::read(p) != 0xCDCDCDCD {
            return address;
        }
    }
    start
}

#[inline(never)]
pub fn black_box<T>(dummy: T) -> T {
    unsafe { llvm_asm!("" : : "r"(&dummy)) }
    dummy
}

#[inline(never)]
fn keygen_ecdsa(rng: &mut rng256::TockRng256) {
    let sk = ecdsa::SecKey::gensk(rng);
    black_box(sk);
}

#[inline(never)]
fn keygen_dilithium(rng: &mut rng256::TockRng256) {
    let sk = dilithium::sign::SecKey::gensk(rng);
    black_box(sk);
}

#[inline(never)]
fn keygen_hybrid(rng: &mut rng256::TockRng256) {
    let sk = hybrid::SecKey::gensk_with_pk(rng);
    black_box(sk);
}

#[inline(never)]
fn sign_ecdsa(rng: &mut rng256::TockRng256, sk: &ecdsa::SecKey) {
    let sig = sk.sign_rng::<sha256::Sha256, _>(&[], rng);
    black_box(sig);
}

fn sign_dilithium(sk: &dilithium::sign::SecKey) {
    let sig = sk.sign(&[]);
    black_box(sig);
}

#[inline(never)]
fn sign_hybrid(sk: &hybrid::SecKey) {
    let sig = sk.sign_rfc6979::<Sha256>(&[]);
    black_box(sig);
}

// Measure the stack usage of the method itself, plus a u32.
#[inline(never)]
fn dummy_test() {
    let x = 1u32;
    black_box(x);
}

// Tests whether input parameters are correctly ignored in the measurement.
#[inline(never)]
fn param_test(big_param: &mut [u8; 0x1000]) {
    let x = 0x01;
    big_param[0] = x;
    black_box(x);
}

fn write_result(console: &mut Console, text: &str, size: u32) {
    writeln!(console, "{} size: 0x{:08X}", text, size).unwrap();
}

fn main() {
    let mut console = Console::new();

    let x = 1u32;
    let sp = &x as *const u32;
    // Should be safe to write from here.
    let start = sp as u32 - 0x100u32;
    writeln!(console, "Search start address: 0x{:08X}", start).unwrap();
    print_stack_pointer(&mut console);

    let mut rng = rng256::TockRng256 {};

    unsafe { paint_memory(start, 0x20020000) };
    keygen_ecdsa(&mut rng);
    let min_address1 = unsafe { find_border(start, 0x20020000) };

    unsafe { paint_memory(start, 0x20020000) };
    keygen_dilithium(&mut rng);
    let min_address2 = unsafe { find_border(start, 0x20020000) };

    unsafe { paint_memory(start, 0x20020000) };
    keygen_hybrid(&mut rng);
    let min_address3 = unsafe { find_border(start, 0x20020000) };

    let sk = ecdsa::SecKey::gensk(&mut rng);
    unsafe { paint_memory(start, 0x20020000) };
    sign_ecdsa(&mut rng, &sk);
    let min_address4 = unsafe { find_border(start, 0x20020000) };

    let sk = dilithium::sign::SecKey::gensk(&mut rng);
    unsafe { paint_memory(start, 0x20020000) };
    sign_dilithium(&sk);
    let min_address5 = unsafe { find_border(start, 0x20020000) };

    let sk = hybrid::SecKey::gensk(&mut rng);
    unsafe { paint_memory(start, 0x20020000) };
    sign_hybrid(&sk);
    let min_address6 = unsafe { find_border(start, 0x20020000) };

    let mut param = [0; 0x1000];
    unsafe { paint_memory(start, 0x20020000) };
    param_test(&mut param);
    let min_address7 = unsafe { find_border(start, 0x20020000) };

    unsafe { paint_memory(start, 0x20020000) };
    dummy_test();
    let min_address8 = unsafe { find_border(start, 0x20020000) };

    let main_end = read_stack_pointer();
    write_result(&mut console, "    keygen_ecdsa", main_end - min_address1);
    write_result(&mut console, "keygen_dilithium", main_end - min_address2);
    write_result(&mut console, "   keygen_hybrid", main_end - min_address3);
    write_result(&mut console, "      sign_ecdsa", main_end - min_address4);
    write_result(&mut console, "  sign_dilithium", main_end - min_address5);
    write_result(&mut console, "     sign_hybrid", main_end - min_address6);
    write_result(&mut console, "      test dummy", main_end - min_address7);
    write_result(&mut console, "      test input", main_end - min_address8);
}
