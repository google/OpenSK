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

use alloc::vec::Vec;
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

/// Checks whether the address is aligned with the block_size.
///
/// Requires block_size to be a power of two.
fn is_aligned(block_size: usize, address: usize) -> bool {
    address & (block_size - 1) == 0
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
            || !is_aligned(syscall.word_size, syscall.page_size)
        {
            return Err(StorageError::CustomError);
        }
        for i in 0..memop(memop_nr::STORAGE_CNT, 0)? {
            if memop(memop_nr::STORAGE_TYPE, i)? != storage_type::STORE {
                continue;
            }
            let storage_ptr = memop(memop_nr::STORAGE_PTR, i)?;
            let max_storage_len = memop(memop_nr::STORAGE_LEN, i)?;
            if !is_aligned(syscall.page_size, storage_ptr)
                || !is_aligned(syscall.page_size, max_storage_len)
            {
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
        if !is_aligned(self.word_size, index.byte) || !is_aligned(self.word_size, value.len()) {
            return Err(StorageError::NotAligned);
        }
        let ptr = self.read_slice(index, value.len())?.as_ptr() as usize;

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

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let index = StorageIndex { page, byte: 0 };
        let length = self.page_size();
        let ptr = self.read_slice(index, length)?.as_ptr() as usize;
        let code = syscalls::command(DRIVER_NUMBER, command_nr::ERASE_PAGE, ptr, length);
        if code.is_err() {
            return Err(StorageError::CustomError);
        }
        Ok(())
    }
}

fn find_slice<'a>(
    slices: &'a [&'a [u8]],
    mut start: usize,
    length: usize,
) -> StorageResult<&'a [u8]> {
    for slice in slices {
        if start >= slice.len() {
            start -= slice.len();
            continue;
        }
        if start + length > slice.len() {
            break;
        }
        return Ok(&slice[start..][..length]);
    }
    Err(StorageError::OutOfBounds)
}

struct PartitionSlice {
    pub ptr: usize,
    pub len: usize,
}

impl PartitionSlice {
    pub fn contains(&self, address: usize) -> bool {
        // We want to check the 2 following inequalities:
        // (1) `ptr <= address`
        // (2) `address <= ptr + len`
        // However, the second one may overflow written as is. Using (1), we rewrite to:
        // (3) `address - ptr <= len`
        self.ptr <= address && address - self.ptr <= self.len
    }
}

pub struct Partition {
    page_size: usize,
    partition_locations: Vec<PartitionSlice>,
    metadata_location: PartitionSlice,
}

impl Partition {
    /// Provides access to the other partition if available.
    ///
    /// # Errors
    ///
    /// Returns `CustomError` if any of the following conditions do not hold:
    /// - The page size is a power of two.
    /// - The storage slices are page-aligned.
    pub fn new() -> StorageResult<Partition> {
        let page_size = get_info(command_nr::get_info_nr::PAGE_SIZE, 0)?;
        if !page_size.is_power_of_two() {
            return Err(StorageError::CustomError);
        }
        let mut partition_locations = Vec::new();
        let mut metadata_location = None;
        for i in 0..memop(memop_nr::STORAGE_CNT, 0)? {
            let storage_type = memop(memop_nr::STORAGE_TYPE, i)?;
            match storage_type {
                storage_type::STORE => continue,
                storage_type::PARTITION | storage_type::METADATA => (),
                _ => return Err(StorageError::CustomError),
            };
            let storage_ptr = memop(memop_nr::STORAGE_PTR, i)?;
            let storage_len = memop(memop_nr::STORAGE_LEN, i)?;
            if !is_aligned(page_size, storage_ptr) || !is_aligned(page_size, storage_len) {
                return Err(StorageError::CustomError);
            }
            match storage_type {
                storage_type::PARTITION => partition_locations.push(PartitionSlice {
                    ptr: storage_ptr,
                    len: storage_len,
                }),
                // We only expect one page of metadata.
                storage_type::METADATA => {
                    if metadata_location.is_none() {
                        metadata_location = Some(PartitionSlice {
                            ptr: storage_ptr,
                            len: storage_len,
                        });
                    } else {
                        return Err(StorageError::CustomError);
                    }
                }
                _ => (),
            };
        }
        if let Some(metadata_location) = metadata_location {
            Ok(Partition {
                page_size,
                partition_locations,
                metadata_location,
            })
        } else {
            Err(StorageError::CustomError)
        }
    }

    pub fn is_page_in_partition(&self, page_address: usize) -> bool {
        self.partition_locations
            .iter()
            .any(|storage_location| storage_location.contains(page_address))
    }

    pub fn is_page_in_metadata(&self, page_address: usize) -> bool {
        self.metadata_location.contains(page_address)
    }

    pub fn rewrite_page(&self, page_ptr: usize, value: &mut [u8]) -> StorageResult<()> {
        let value_len = value.len();
        if !is_aligned(self.page_size, page_ptr) || !is_aligned(self.page_size, value_len) {
            return Err(StorageError::NotAligned);
        }

        let shared_memory = syscalls::allow(DRIVER_NUMBER, allow_nr::WRITE_SLICE, value);
        if shared_memory.is_err() {
            return Err(StorageError::CustomError);
        }
        let code = syscalls::command(DRIVER_NUMBER, command_nr::ERASE_PAGE, page_ptr, value_len);
        if code.is_err() {
            return Err(StorageError::CustomError);
        }
        let code = syscalls::command(DRIVER_NUMBER, command_nr::WRITE_SLICE, page_ptr, value_len);
        if code.is_err() {
            return Err(StorageError::CustomError);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_slice_ok() {
        assert_eq!(
            find_slice(&[&[1, 2, 3, 4]], 0, 4).ok(),
            Some(&[1u8, 2, 3, 4] as &[u8])
        );
        assert_eq!(
            find_slice(&[&[1, 2, 3, 4], &[5, 6]], 1, 2).ok(),
            Some(&[2u8, 3] as &[u8])
        );
        assert_eq!(
            find_slice(&[&[1, 2, 3, 4], &[5, 6]], 4, 2).ok(),
            Some(&[5u8, 6] as &[u8])
        );
        assert_eq!(
            find_slice(&[&[1, 2, 3, 4], &[5, 6]], 4, 0).ok(),
            Some(&[] as &[u8])
        );
        assert!(find_slice(&[], 0, 1).is_err());
        assert!(find_slice(&[&[1, 2, 3, 4], &[5, 6]], 6, 0).is_err());
        assert!(find_slice(&[&[1, 2, 3, 4], &[5, 6]], 3, 2).is_err());
    }

    #[test]
    fn alignment() {
        for exponent in 0..8 {
            let block_size = 1 << exponent;
            for i in range(10) {
                assert!(is_aligned(block_size, block_size * i));
            }
            for i in range(block_size) {
                assert!(!is_aligned(block_size, block_size + i));
            }
        }
    }

    #[test]
    fn partition_slice_contains() {
        let ptr = 0x200;
        let len = 0x100;
        let slice = PartitionSlice { ptr, len };
        for i in ptr..ptr + len {
            assert!(slice.contains(i));
        }
        for i in ptr - len..ptr {
            assert!(!slice.contains(i));
        }
        for i in ptr + len..ptr + 2 * len {
            assert!(!slice.contains(i));
        }
    }
}
