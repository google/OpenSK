// Copyright 2019-2020 Google LLC
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

//! Flash storage abstraction.

use alloc::borrow::Cow;

/// Represents a byte position in a storage.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StorageIndex {
    pub page: usize,
    pub byte: usize,
}

/// Represents a possible storage error.
#[derive(Debug, PartialEq, Eq)]
pub enum StorageError {
    /// Arguments are not correctly aligned.
    NotAligned,

    /// Arguments are out of bounds.
    OutOfBounds,

    /// Implementation-specific error.
    CustomError,
}

#[cfg(feature = "std")]
impl From<std::io::Error> for StorageError {
    fn from(_: std::io::Error) -> Self {
        Self::CustomError
    }
}

pub type StorageResult<T> = Result<T, StorageError>;

/// Abstracts a flash storage.
pub trait Storage {
    /// The size of a word in bytes.
    ///
    /// A word is the smallest unit of writable flash.
    fn word_size(&self) -> usize;

    /// The size of a page in bytes.
    ///
    /// A page is the smallest unit of erasable flash.
    fn page_size(&self) -> usize;

    /// The number of pages in the storage.
    fn num_pages(&self) -> usize;

    /// Maximum number of times a word can be written between page erasures.
    fn max_word_writes(&self) -> usize;

    /// Maximum number of times a page can be erased.
    fn max_page_erases(&self) -> usize;

    /// Reads a byte slice from the storage.
    ///
    /// The `index` must designate `length` bytes in the storage.
    ///
    /// Note that we use `Cow` just because it derefs to `[u8]`. We don't really need the fact that
    /// one can convert it to a `Vec`. In particular we don't do it in the store implementation.
    fn read_slice(&self, index: StorageIndex, length: usize) -> StorageResult<Cow<[u8]>>;

    /// Writes a word slice to the storage.
    ///
    /// The following pre-conditions must hold:
    /// - The `index` must designate `value.len()` bytes in the storage.
    /// - Both `index` and `value.len()` must be word-aligned.
    /// - The written words should not have been written [too many](Self::max_word_writes) times
    ///   since the last page erasure.
    fn write_slice(&mut self, index: StorageIndex, value: &[u8]) -> StorageResult<()>;

    /// Erases a page of the storage.
    ///
    /// The `page` must be in the storage, i.e. less than [`Storage::num_pages`]. And the page
    /// should not have been erased [too many](Self::max_page_erases) times.
    fn erase_page(&mut self, page: usize) -> StorageResult<()>;
}

impl StorageIndex {
    /// Whether a slice fits in a storage page.
    fn is_valid(self, length: usize, storage: &impl Storage) -> bool {
        let page_size = storage.page_size();
        self.page < storage.num_pages() && length <= page_size && self.byte <= page_size - length
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
