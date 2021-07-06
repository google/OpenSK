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

use super::helper::{create_range, find_slice, is_aligned};
use alloc::vec::Vec;
use core::ops::RangeInclusive;
use libtock_core::syscalls;
use persistent_store::{Storage, StorageError, StorageIndex, StorageResult};

const DRIVER_NUMBER: usize = 0x50003;

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

fn write_slice_op(ptr: usize, value: &[u8]) -> StorageResult<()> {
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

    let code = syscalls::command(DRIVER_NUMBER, command_nr::WRITE_SLICE, ptr, value.len());
    if code.is_err() {
        return Err(StorageError::CustomError);
    }

    Ok(())
}

fn erase_page_op(ptr: usize, page_length: usize) -> StorageResult<()> {
    let code = syscalls::command(DRIVER_NUMBER, command_nr::ERASE_PAGE, ptr, page_length);
    if code.is_err() {
        return Err(StorageError::CustomError);
    }
    Ok(())
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
    ///
    /// Returns `OutOfBounds` the number of pages does not fit in the storage.
    pub fn new(mut num_pages: usize) -> StorageResult<SyscallStorage> {
        let mut syscall = SyscallStorage {
            word_size: get_info(command_nr::get_info_nr::WORD_SIZE, 0)?,
            page_size: get_info(command_nr::get_info_nr::PAGE_SIZE, 0)?,
            num_pages,
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
            let max_storage_len = memop(memop_nr::STORAGE_LEN, i)?;
            if !syscall.is_page_aligned(storage_ptr) || !syscall.is_page_aligned(max_storage_len) {
                return Err(StorageError::CustomError);
            }
            let storage_len = core::cmp::min(num_pages * syscall.page_size, max_storage_len);
            num_pages -= storage_len / syscall.page_size;
            syscall
                .storage_locations
                .push(unsafe { core::slice::from_raw_parts(storage_ptr as *mut u8, storage_len) });
        }
        if num_pages > 0 {
            // The storage locations don't have enough pages.
            return Err(StorageError::OutOfBounds);
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
        write_slice_op(ptr, value)
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let index = StorageIndex { page, byte: 0 };
        let length = self.page_size();
        let ptr = self.read_slice(index, length)?.as_ptr() as usize;
        erase_page_op(ptr, length)
    }
}

pub struct UpgradeLocations {
    page_size: usize,
    partitions: Vec<RangeInclusive<usize>>,
    metadata: RangeInclusive<usize>,
}

impl UpgradeLocations {
    /// Provides access to the other upgrade partition and metadata if available.
    ///
    /// # Errors
    ///
    /// Returns `CustomError` if any of the following conditions do not hold:
    /// - The page size is a power of two.
    /// - The storage slices are page-aligned.
    pub fn new() -> StorageResult<UpgradeLocations> {
        let mut locations = UpgradeLocations {
            page_size: get_info(command_nr::get_info_nr::PAGE_SIZE, 0)?,
            partitions: Vec::new(),
            metadata: 1..=0,
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
            let range = create_range(storage_ptr, storage_len);
            match storage_type {
                storage_type::PARTITION => locations.partitions.push(range),
                // We only expect one page of metadata.
                storage_type::METADATA => {
                    // TODO replace with is_empty with stable Rust 1.47.0
                    if locations.metadata.start() > locations.metadata.end() {
                        locations.metadata = range;
                    } else {
                        return Err(StorageError::CustomError);
                    }
                }
                _ => (),
            };
        }
        Ok(locations)
    }

    fn is_page_aligned(&self, x: usize) -> bool {
        is_aligned(self.page_size, x)
    }

    pub fn is_page_in_partition(&self, page_address: usize) -> bool {
        self.partitions
            .iter()
            .any(|storage_location| storage_location.contains(&page_address))
    }

    pub fn is_page_in_metadata(&self, page_address: usize) -> bool {
        self.metadata.contains(&page_address)
    }

    pub fn rewrite_page(&self, page_ptr: usize, value: &[u8]) -> StorageResult<()> {
        if !self.is_page_aligned(page_ptr) || !self.is_page_aligned(value.len()) {
            return Err(StorageError::NotAligned);
        }
        erase_page_op(page_ptr, self.page_size)?;
        write_slice_op(page_ptr, value)
    }
}
