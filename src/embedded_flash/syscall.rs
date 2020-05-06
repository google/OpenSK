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

use super::{Index, Storage, StorageError, StorageResult};
use libtock::syscalls;

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

fn get_info(nr: usize) -> StorageResult<usize> {
    let code = unsafe { syscalls::command(DRIVER_NUMBER, command_nr::GET_INFO, nr, 0) };
    if code < 0 {
        Err(StorageError::KernelError { code })
    } else {
        Ok(code as usize)
    }
}

pub struct SyscallStorage {
    word_size: usize,
    page_size: usize,
    max_word_writes: usize,
    max_page_erases: usize,
    storage: &'static mut [u8],
}

impl SyscallStorage {
    /// Provides access to the embedded flash if available.
    ///
    /// # Safety
    ///
    /// The `storage` must be readable.
    ///
    /// # Errors
    ///
    /// Returns `BadFlash` if any of the following conditions do not hold:
    /// - The word size is not a power of two.
    /// - The page size is not a power of two.
    /// - The page size is not a multiple of the word size.
    ///
    /// Returns `NotAligned` if any of the following conditions do not hold:
    /// - `storage` is page-aligned.
    /// - `storage.len()` is a multiple of the page size.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate ctap2;
    /// # use ctap2::embedded_flash::SyscallStorage;
    /// # use ctap2::embedded_flash::StorageResult;
    /// # const STORAGE_ADDR: usize = 0x1000;
    /// # const STORAGE_SIZE: usize = 0x1000;
    /// # fn foo() -> StorageResult<SyscallStorage> {
    /// // This is safe because we create and use `storage` only once in the whole program.
    /// let storage = unsafe {
    ///     core::slice::from_raw_parts_mut(STORAGE_ADDR as *mut u8, STORAGE_SIZE)
    /// };
    /// // This is safe because `storage` is readable.
    /// unsafe { SyscallStorage::new(storage) }
    /// # }
    /// ```
    pub unsafe fn new(storage: &'static mut [u8]) -> StorageResult<SyscallStorage> {
        let word_size = get_info(command_nr::get_info_nr::WORD_SIZE)?;
        let page_size = get_info(command_nr::get_info_nr::PAGE_SIZE)?;
        let max_word_writes = get_info(command_nr::get_info_nr::MAX_WORD_WRITES)?;
        let max_page_erases = get_info(command_nr::get_info_nr::MAX_PAGE_ERASES)?;
        if !word_size.is_power_of_two() || !page_size.is_power_of_two() {
            return Err(StorageError::BadFlash);
        }
        let syscall = SyscallStorage {
            word_size,
            page_size,
            max_word_writes,
            max_page_erases,
            storage,
        };
        if !syscall.is_word_aligned(page_size) {
            return Err(StorageError::BadFlash);
        }
        if syscall.is_page_aligned(syscall.storage.as_ptr() as usize)
            && syscall.is_page_aligned(syscall.storage.len())
        {
            Ok(syscall)
        } else {
            Err(StorageError::NotAligned)
        }
    }

    fn is_word_aligned(&self, x: usize) -> bool {
        x & (self.word_size - 1) == 0
    }

    fn is_page_aligned(&self, x: usize) -> bool {
        x & (self.page_size - 1) == 0
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
        self.storage.len() / self.page_size
    }

    fn max_word_writes(&self) -> usize {
        self.max_word_writes
    }

    fn max_page_erases(&self) -> usize {
        self.max_page_erases
    }

    fn read_slice(&self, index: Index, length: usize) -> StorageResult<&[u8]> {
        Ok(&self.storage[index.range(length, self)?])
    }

    fn write_slice(&mut self, index: Index, value: &[u8]) -> StorageResult<()> {
        if !self.is_word_aligned(index.byte) || !self.is_word_aligned(value.len()) {
            return Err(StorageError::NotAligned);
        }
        let range = index.range(value.len(), self)?;
        let code = unsafe {
            syscalls::allow_ptr(
                DRIVER_NUMBER,
                allow_nr::WRITE_SLICE,
                // We rely on the driver not writing to the slice. This should use read-only allow
                // when available. See https://github.com/tock/tock/issues/1274.
                value.as_ptr() as *mut u8,
                value.len(),
            )
        };
        if code < 0 {
            return Err(StorageError::KernelError { code });
        }
        let code = unsafe {
            syscalls::command(
                DRIVER_NUMBER,
                command_nr::WRITE_SLICE,
                self.storage[range].as_ptr() as usize,
                0,
            )
        };
        if code < 0 {
            return Err(StorageError::KernelError { code });
        }
        Ok(())
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let range = Index { page, byte: 0 }.range(self.page_size(), self)?;
        let code = unsafe {
            syscalls::command(
                DRIVER_NUMBER,
                command_nr::ERASE_PAGE,
                self.storage[range].as_ptr() as usize,
                0,
            )
        };
        if code < 0 {
            return Err(StorageError::KernelError { code });
        }
        Ok(())
    }
}
