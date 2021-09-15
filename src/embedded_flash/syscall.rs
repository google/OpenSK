// Copyright 2019-2021 Google LLC
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

use super::helper::{find_slice, is_aligned, ModRange};
use super::upgrade_storage::UpgradeStorage;
use alloc::vec::Vec;
use core::cell::Cell;
use libtock_core::{callback, syscalls};
use persistent_store::{Storage, StorageError, StorageIndex, StorageResult};

const DRIVER_NUMBER: usize = 0x50003;

mod subscribe_nr {
    pub const DONE: usize = 0;
}

mod command_nr {
    pub const GET_INFO: usize = 1;
    pub mod get_info_nr {
        pub const WORD_SIZE: usize = 0;
        pub const PAGE_SIZE: usize = 1;
        pub const MAX_WORD_WRITES: usize = 2;
        pub const MAX_PAGE_ERASES: usize = 3;
    }
    pub const WRITE_SLICE: usize = 2;
    pub const ERASE_PAGE: usize = 3;
}

mod allow_nr {
    pub const WRITE_SLICE: usize = 0;
}

mod memop_nr {
    pub const STORAGE_CNT: u32 = 12;
    pub const STORAGE_PTR: u32 = 13;
    pub const STORAGE_LEN: u32 = 14;
    pub const STORAGE_TYPE: u32 = 15;
}

mod storage_type {
    pub const STORE: usize = 1;
    pub const PARTITION: usize = 2;
    pub const METADATA: usize = 3;
}

fn get_info(nr: usize, arg: usize) -> StorageResult<usize> {
    let code = syscalls::command(DRIVER_NUMBER, command_nr::GET_INFO, nr, arg);
    code.map_err(|_| StorageError::CustomError)
}

fn memop(nr: u32, arg: usize) -> StorageResult<usize> {
    let code = unsafe { syscalls::raw::memop(nr, arg) };
    if code < 0 {
        Err(StorageError::CustomError)
    } else {
        Ok(code as usize)
    }
}

fn block_command(driver: usize, cmd: usize, arg1: usize, arg2: usize) -> StorageResult<()> {
    let done = Cell::new(None);
    let mut alarm = |status| done.set(Some(status));
    let subscription = syscalls::subscribe::<callback::Identity1Consumer, _>(
        DRIVER_NUMBER,
        subscribe_nr::DONE,
        &mut alarm,
    );
    if subscription.is_err() {
        return Err(StorageError::CustomError);
    }

    let code = syscalls::command(driver, cmd, arg1, arg2);
    if code.is_err() {
        return Err(StorageError::CustomError);
    }

    libtock_drivers::util::yieldk_for(|| done.get().is_some());
    if done.get().unwrap() == 0 {
        Ok(())
    } else {
        Err(StorageError::CustomError)
    }
}

fn write_slice(ptr: usize, value: &[u8]) -> StorageResult<()> {
    let code = unsafe {
        syscalls::raw::allow(
            DRIVER_NUMBER,
            allow_nr::WRITE_SLICE,
            // We rely on the driver not writing to the slice. This should use read-only allow
            // when available. See https://github.com/tock/tock/issues/1274.
            value.as_ptr() as *mut u8,
            value.len(),
        )
    };
    if code < 0 {
        return Err(StorageError::CustomError);
    }

    block_command(DRIVER_NUMBER, command_nr::WRITE_SLICE, ptr, value.len())
}

fn erase_page(ptr: usize, page_length: usize) -> StorageResult<()> {
    block_command(DRIVER_NUMBER, command_nr::ERASE_PAGE, ptr, page_length)
}

pub struct SyscallStorage {
    word_size: usize,
    page_size: usize,
    num_pages: usize,
    max_word_writes: usize,
    max_page_erases: usize,
    storage_locations: Vec<&'static [u8]>,
}

impl SyscallStorage {
    /// Provides access to the embedded flash if available.
    ///
    /// # Errors
    ///
    /// Returns `CustomError` if any of the following conditions do not hold:
    /// - The word size is a power of two.
    /// - The page size is a power of two.
    /// - The page size is a multiple of the word size.
    /// - The storage is page-aligned.
    pub fn new() -> StorageResult<SyscallStorage> {
        let mut syscall = SyscallStorage {
            word_size: get_info(command_nr::get_info_nr::WORD_SIZE, 0)?,
            page_size: get_info(command_nr::get_info_nr::PAGE_SIZE, 0)?,
            num_pages: 0,
            max_word_writes: get_info(command_nr::get_info_nr::MAX_WORD_WRITES, 0)?,
            max_page_erases: get_info(command_nr::get_info_nr::MAX_PAGE_ERASES, 0)?,
            storage_locations: Vec::new(),
        };
        if !syscall.word_size.is_power_of_two()
            || !syscall.page_size.is_power_of_two()
            || !syscall.is_word_aligned(syscall.page_size)
        {
            return Err(StorageError::CustomError);
        }
        for i in 0..memop(memop_nr::STORAGE_CNT, 0)? {
            if memop(memop_nr::STORAGE_TYPE, i)? != storage_type::STORE {
                continue;
            }
            let storage_ptr = memop(memop_nr::STORAGE_PTR, i)?;
            let storage_len = memop(memop_nr::STORAGE_LEN, i)?;
            if !syscall.is_page_aligned(storage_ptr) || !syscall.is_page_aligned(storage_len) {
                return Err(StorageError::CustomError);
            }
            syscall.num_pages += storage_len / syscall.page_size;
            syscall
                .storage_locations
                .push(unsafe { core::slice::from_raw_parts(storage_ptr as *mut u8, storage_len) });
        }
        Ok(syscall)
    }

    fn is_word_aligned(&self, x: usize) -> bool {
        is_aligned(self.word_size, x)
    }

    fn is_page_aligned(&self, x: usize) -> bool {
        is_aligned(self.page_size, x)
    }
}

impl Storage for SyscallStorage {
    fn word_size(&self) -> usize {
        self.word_size
    }

    fn page_size(&self) -> usize {
        self.page_size
    }

    fn num_pages(&self) -> usize {
        self.num_pages
    }

    fn max_word_writes(&self) -> usize {
        self.max_word_writes
    }

    fn max_page_erases(&self) -> usize {
        self.max_page_erases
    }

    fn read_slice(&self, index: StorageIndex, length: usize) -> StorageResult<&[u8]> {
        let start = index.range(length, self)?.start;
        find_slice(&self.storage_locations, start, length)
    }

    fn write_slice(&mut self, index: StorageIndex, value: &[u8]) -> StorageResult<()> {
        if !self.is_word_aligned(index.byte) || !self.is_word_aligned(value.len()) {
            return Err(StorageError::NotAligned);
        }
        let ptr = self.read_slice(index, value.len())?.as_ptr() as usize;
        write_slice(ptr, value)
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let index = StorageIndex { page, byte: 0 };
        let length = self.page_size();
        let ptr = self.read_slice(index, length)?.as_ptr() as usize;
        erase_page(ptr, length)
    }
}

pub struct SyscallUpgradeStorage {
    page_size: usize,
    partition: ModRange,
    metadata: ModRange,
}

impl SyscallUpgradeStorage {
    /// Provides access to the other upgrade partition and metadata if available.
    ///
    /// The implementation assumes that storage locations returned by the kernel through
    /// `memop_nr::STORAGE_*` calls are in address space order.
    ///
    /// # Errors
    ///
    /// Returns `CustomError` if any of the following conditions do not hold:
    /// - The page size is a power of two.
    /// - The storage slices are page-aligned.
    /// - There are not partition or metadata slices.
    /// Returns a `NotAligned` error if partitions or metadata ranges are
    /// - not exclusive or,
    /// - not consecutive.
    pub fn new() -> StorageResult<SyscallUpgradeStorage> {
        let mut locations = SyscallUpgradeStorage {
            page_size: get_info(command_nr::get_info_nr::PAGE_SIZE, 0)?,
            partition: ModRange::new_empty(),
            metadata: ModRange::new_empty(),
        };
        if !locations.page_size.is_power_of_two() {
            return Err(StorageError::CustomError);
        }
        for i in 0..memop(memop_nr::STORAGE_CNT, 0)? {
            let storage_type = memop(memop_nr::STORAGE_TYPE, i)?;
            match storage_type {
                storage_type::PARTITION | storage_type::METADATA => (),
                _ => continue,
            };
            let storage_ptr = memop(memop_nr::STORAGE_PTR, i)?;
            let storage_len = memop(memop_nr::STORAGE_LEN, i)?;
            if !locations.is_page_aligned(storage_ptr) || !locations.is_page_aligned(storage_len) {
                return Err(StorageError::CustomError);
            }
            let range = ModRange::new(storage_ptr, storage_len);
            match storage_type {
                storage_type::PARTITION => {
                    locations.partition = locations
                        .partition
                        .append(range)
                        .ok_or(StorageError::NotAligned)?
                }
                storage_type::METADATA => {
                    locations.metadata = locations
                        .metadata
                        .append(range)
                        .ok_or(StorageError::NotAligned)?
                }
                _ => (),
            };
        }
        if locations.partition.is_empty() || locations.metadata.is_empty() {
            Err(StorageError::CustomError)
        } else {
            Ok(locations)
        }
    }

    fn is_page_aligned(&self, x: usize) -> bool {
        is_aligned(self.page_size, x)
    }
}

impl UpgradeStorage for SyscallUpgradeStorage {
    fn read_partition(&self, offset: usize, length: usize) -> StorageResult<&[u8]> {
        let address = self.partition.start() + offset;
        if self
            .partition
            .contains_range(&ModRange::new(address, length))
        {
            Ok(unsafe { core::slice::from_raw_parts(address as *const u8, length) })
        } else {
            Err(StorageError::OutOfBounds)
        }
    }

    fn write_partition(&mut self, offset: usize, data: &[u8]) -> StorageResult<()> {
        let address = self.partition.start() + offset;
        if self
            .partition
            .contains_range(&ModRange::new(address, data.len()))
        {
            // Erases all pages that have their first byte in the write range.
            // Since we expect calls in order, we don't want to erase half-written pages.
            for address in ModRange::new(address, data.len()).aligned_iter(self.page_size) {
                erase_page(address, self.page_size)?;
            }
            write_slice(address, data)
        } else {
            Err(StorageError::OutOfBounds)
        }
    }

    fn partition_address(&self) -> usize {
        self.partition.start()
    }

    fn partition_length(&self) -> usize {
        self.partition.length()
    }

    fn read_metadata(&self) -> StorageResult<&[u8]> {
        Ok(unsafe {
            core::slice::from_raw_parts(self.metadata.start() as *const u8, self.metadata.length())
        })
    }

    fn write_metadata(&mut self, data: &[u8]) -> StorageResult<()> {
        // If less data is passed in than is reserved, assume the rest is 0xFF.
        if data.len() <= self.metadata.length() {
            for address in self.metadata.aligned_iter(self.page_size) {
                erase_page(address, self.page_size)?;
            }
            write_slice(self.metadata.start(), data)
        } else {
            Err(StorageError::OutOfBounds)
        }
    }
}
