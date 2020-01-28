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

#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Index {
    pub page: usize,
    pub byte: usize,
}

#[derive(Debug)]
pub enum StorageError {
    BadFlash,
    NotAligned,
    OutOfBounds,
    KernelError { code: isize },
}

pub type StorageResult<T> = Result<T, StorageError>;

/// Abstraction for embedded flash storage.
pub trait Storage {
    /// Returns the size of a word in bytes.
    fn word_size(&self) -> usize;

    /// Returns the size of a page in bytes.
    fn page_size(&self) -> usize;

    /// Returns the number of pages in the storage.
    fn num_pages(&self) -> usize;

    /// Returns how many times a word can be written between page erasures.
    fn max_word_writes(&self) -> usize;

    /// Returns how many times a page can be erased in the lifetime of the flash.
    fn max_page_erases(&self) -> usize;

    /// Reads a slice from the storage.
    ///
    /// The slice does not need to be word-aligned.
    ///
    /// # Errors
    ///
    /// The `index` must designate `length` bytes in the storage.
    fn read_slice(&self, index: Index, length: usize) -> StorageResult<&[u8]>;

    /// Writes a word-aligned slice to the storage.
    ///
    /// The written words should not have been written too many times since last page erasure.
    ///
    /// # Errors
    ///
    /// The following preconditions must hold:
    /// - `index` must be word-aligned.
    /// - `value.len()` must be a multiple of the word size.
    /// - `index` must designate `value.len()` bytes in the storage.
    /// - `value` must be in memory until [read-only allow][tock_1274] is resolved.
    ///
    /// [tock_1274]: https://github.com/tock/tock/issues/1274.
    fn write_slice(&mut self, index: Index, value: &[u8]) -> StorageResult<()>;

    /// Erases a page of the storage.
    ///
    /// # Errors
    ///
    /// The `page` must be in the storage.
    fn erase_page(&mut self, page: usize) -> StorageResult<()>;
}

impl Index {
    /// Returns whether a slice fits in a storage page.
    fn is_valid(self, length: usize, storage: &impl Storage) -> bool {
        self.page < storage.num_pages()
            && storage
                .page_size()
                .checked_sub(length)
                .map(|limit| self.byte <= limit)
                .unwrap_or(false)
    }

    /// Returns the range of a valid slice.
    ///
    /// The range starts at `self` with `length` bytes.
    pub fn range(
        self,
        length: usize,
        storage: &impl Storage,
    ) -> StorageResult<core::ops::Range<usize>> {
        if self.is_valid(length, storage) {
            let start = self.page * storage.page_size() + self.byte;
            Ok(start..start + length)
        } else {
            Err(StorageError::OutOfBounds)
        }
    }
}
