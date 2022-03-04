// Copyright 2021 Google LLC
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
    timestamp: u32,
    address: u32,
}

impl Metadata {
    pub const DATA_LEN: usize = 40;
}

/// Reads the metadata from a flash page.
impl From<Page> for Metadata {
    fn from(page: Page) -> Self {
        Metadata {
            checksum: page[0..32].try_into().unwrap(),
            timestamp: LittleEndian::read_u32(&page[32..36]),
            address: LittleEndian::read_u32(&page[36..Metadata::DATA_LEN]),
        }
    }
}

/// Location of a firmware partition's data.
struct BootPartition {
    firmware_address: usize,
    metadata_address: usize,
}

impl BootPartition {
    const _FIRMWARE_LENGTH: usize = 0x00040000;

    /// Reads the metadata, returns the timestamp if all checks pass.
    pub fn read_timestamp(&self) -> Result<u32, ()> {
        let metadata_page = unsafe { read_page(self.metadata_address) };
        let hash_value = self.compute_upgrade_hash(&metadata_page);
        let metadata = Metadata::from(metadata_page);
        if self.firmware_address != metadata.address as usize {
            #[cfg(debug_assertions)]
            rprintln!(
                "Firmware address mismatch: expected 0x{:08X}, metadata 0x{:08X}",
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
        Ok(metadata.timestamp)
    }

    /// Placeholder for the SHA256 implementation.
    ///
    /// TODO implemented in next PR
    /// Without it, the bootloader will never boot anything.
    fn compute_upgrade_hash(&self, _metadata_page: &[u8]) -> [u8; 32] {
        [0; 32]
    }

    /// Jump to the firmware.
    pub fn boot(&self) -> ! {
        let address = self.firmware_address;

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
    let timestamp_a = partition_a.read_timestamp();
    #[cfg(debug_assertions)]
    rprintln!("Reading partition B");
    let timestamp_b = partition_b.read_timestamp();

    match (timestamp_a, timestamp_b) {
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
