// Copyright 2021-2022 Google LLC
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

mod bitfields;
mod crypto_cell;
mod registers;
mod static_ref;

extern crate cortex_m;
extern crate cortex_m_rt as rt;

use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryInto;
use core::ptr;
use cortex_m::asm;
use panic_abort as _;
use rt::entry;
#[cfg(debug_assertions)]
use rtt_target::{rprintln, rtt_init_print};

/// Size of a flash page in bytes.
const PAGE_SIZE: usize = 0x1000;
const METADATA_SIGN_OFFSET: usize = 0x800;

/// A flash page.
type Page = [u8; PAGE_SIZE];

/// Reads a page of memory.
unsafe fn read_page(address: usize) -> Page {
    debug_assert!(address % PAGE_SIZE == 0);
    let address_pointer = address as *const Page;
    ptr::read(address_pointer)
}

/// Parsed metadata for a firmware partition.
struct Metadata {
    checksum: [u8; 32],
    _signature: [u8; 64],
    version: u64,
    address: u32,
}

/// Reads the metadata from a flash page.
impl From<Page> for Metadata {
    fn from(page: Page) -> Self {
        Metadata {
            checksum: page[0..32].try_into().unwrap(),
            _signature: page[32..96].try_into().unwrap(),
            version: LittleEndian::read_u64(&page[METADATA_SIGN_OFFSET..][..8]),
            address: LittleEndian::read_u32(&page[METADATA_SIGN_OFFSET + 8..][..4]),
        }
    }
}

/// Location of a firmware partition's data.
struct BootPartition {
    firmware_address: usize,
    metadata_address: usize,
}

impl BootPartition {
    const FIRMWARE_LENGTH: usize = 0x00040000;

    /// Reads the metadata, returns the firmware version if all checks pass.
    pub fn read_version(&self) -> Result<u64, ()> {
        let metadata_page = unsafe { read_page(self.metadata_address) };
        let hash_value = self.compute_upgrade_hash(&metadata_page);
        let metadata = Metadata::from(metadata_page);
        if self.firmware_address != metadata.address as usize {
            #[cfg(debug_assertions)]
            rprintln!(
                "Partition address mismatch: expected 0x{:08X}, metadata 0x{:08X}",
                self.firmware_address,
                metadata.address as usize
            );
            return Err(());
        }
        if hash_value != metadata.checksum {
            #[cfg(debug_assertions)]
            rprintln!("Hash mismatch");
            return Err(());
        }
        Ok(metadata.version)
    }

    /// Computes the SHA256 of metadata information and partition data.
    ///
    /// Assumes that firmware address and length are divisible by the page size.
    /// This is the hardware implementation on the cryptocell.
    #[allow(clippy::assertions_on_constants)]
    fn compute_upgrade_hash(&self, metadata_page: &[u8]) -> [u8; 32] {
        debug_assert!(self.firmware_address % PAGE_SIZE == 0);
        debug_assert!(BootPartition::FIRMWARE_LENGTH % PAGE_SIZE == 0);
        let cc310 = crypto_cell::CryptoCell310::new();
        cc310.update(&metadata_page[METADATA_SIGN_OFFSET..], false);
        for page_offset in (0..BootPartition::FIRMWARE_LENGTH).step_by(PAGE_SIZE) {
            let page = unsafe { read_page(self.firmware_address + page_offset) };
            cc310.update(
                &page,
                page_offset + PAGE_SIZE == BootPartition::FIRMWARE_LENGTH,
            );
        }
        cc310.finalize_and_clear()
    }

    /// Jump to the firmware.
    pub fn boot(&self) -> ! {
        let address = self.firmware_address;

        // Clear any pending Cryptocell interrupt in NVIC
        let peripherals = cortex_m::Peripherals::take().unwrap();
        unsafe {
            // We could only clear cryptocell interrupts, but let's clean up before booting.
            // Example code to clear more specifically:
            // const CC310_IRQ: u16 = 42;
            // peripherals.NVIC.icpr[usize::from(CC310_IRQ / 32)].write(1 << (CC310_IRQ % 32));
            peripherals.NVIC.icer[0].write(0xffff_ffff);
            peripherals.NVIC.icpr[0].write(0xffff_ffff);
            peripherals.NVIC.icer[1].write(0xffff_ffff);
            peripherals.NVIC.icpr[1].write(0xffff_ffff);
        }

        #[cfg(debug_assertions)]
        rprintln!("Boot jump to {:08X}", address);
        let address_pointer = address as *const u32;
        // https://docs.rs/cortex-m/0.7.2/cortex_m/asm/fn.bootload.html
        unsafe { asm::bootload(address_pointer) };
    }
}

#[entry]
fn main() -> ! {
    #[cfg(debug_assertions)]
    rtt_init_print!();
    #[cfg(debug_assertions)]
    rprintln!("Starting bootloader");
    let partition_a = BootPartition {
        firmware_address: 0x20000,
        metadata_address: 0x4000,
    };
    let partition_b = BootPartition {
        firmware_address: 0x60000,
        metadata_address: 0x5000,
    };
    #[cfg(debug_assertions)]
    rprintln!("Reading partition A");
    let version_a = partition_a.read_version();
    #[cfg(debug_assertions)]
    rprintln!("Reading partition B");
    let version_b = partition_b.read_version();

    match (version_a, version_b) {
        (Ok(t1), Ok(t2)) => {
            if t1 >= t2 {
                partition_a.boot()
            } else {
                partition_b.boot()
            }
        }
        (Ok(_), Err(_)) => partition_a.boot(),
        (Err(_), Ok(_)) => partition_b.boot(),
        (Err(_), Err(_)) => panic!(),
    }
}
