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

//! Provides a linear view into a storage.

use core::ops::Range;

use alloc::borrow::Cow;
use alloc::vec::Vec;

use crate::{Storage, StorageError, StorageIndex, StorageResult};

/// Provides a linear view into a storage.
///
/// The storage may be read and written as if it were a contiguous slice. This implementation is not
/// power-loss resistant.
pub struct Linear<S: Storage> {
    pub storage: S,
}

impl<S: Storage> Linear<S> {
    /// Returns the length of the storage.
    ///
    /// In particular, offsets should be less than this value (or equal for the one-past-the-end
    /// offset).
    pub fn length(&self) -> usize {
        self.storage.num_pages() * self.storage.page_size()
    }

    /// Reads a slice from the storage (ignoring page boundaries).
    ///
    /// This function may allocate if the slice spans multiple pages (because they may not be
    /// contiguous). However, a slice is returned if the range fits within a page.
    pub fn read(&self, range: Range<usize>) -> StorageResult<Cow<[u8]>> {
        if range.is_empty() {
            return Ok(Cow::Borrowed(&[]));
        }
        let Range { start, end } = range;
        if end < start {
            return Err(StorageError::OutOfBounds);
        }
        let page_size = self.storage.page_size();
        let mut index = StorageIndex {
            page: start / page_size,
            byte: start % page_size,
        };
        let mut length = end - start;
        if end <= (index.page + 1) * page_size {
            // The range fits in a page.
            return self.storage.read_slice(index, length);
        }
        // The range doesn't fit in a page.
        let mut result = Vec::with_capacity(length);
        while length > 0 {
            let slice_length = core::cmp::min(length, page_size - index.byte);
            result.extend_from_slice(&self.storage.read_slice(index, slice_length)?);
            index.page += 1;
            index.byte = 0;
            length -= slice_length;
        }
        Ok(Cow::Owned(result))
    }

    /// Writes a slice to the storage (ignoring page boundaries and regardless of previous value).
    ///
    /// This function will erase pages as needed (and restore the non-overwritten parts). As such it
    /// may allocate and is not power-loss resistant.
    pub fn write(&mut self, offset: usize, mut value: &[u8]) -> StorageResult<()> {
        if self.length() < value.len() || self.length() - value.len() < offset {
            return Err(StorageError::OutOfBounds);
        }
        let page_size = self.storage.page_size();
        let mut index = StorageIndex {
            page: offset / page_size,
            byte: offset % page_size,
        };
        while !value.is_empty() {
            let length = core::cmp::min(value.len(), page_size - index.byte);
            self.write_within(index, &value[..length])?;
            index.page += 1;
            index.byte = 0;
            value = &value[length..];
        }
        Ok(())
    }

    /// Erases a slice from the storage (ignoring page boundaries and preserving previous value).
    ///
    /// This is equivalent to writing a slice of `0xff` bytes but doesn't need the slice as
    /// argument. But the function still allocates to preserve previous values if needed and is thus
    /// still not power-loss resistant.
    pub fn erase(&mut self, mut range: Range<usize>) -> StorageResult<()> {
        if range.end < range.start || self.length() < range.end {
            return Err(StorageError::OutOfBounds);
        }
        let page_size = self.storage.page_size();
        let mut index = StorageIndex {
            page: range.start / page_size,
            byte: range.start % page_size,
        };
        while !range.is_empty() {
            let length = core::cmp::min(range.len(), page_size - index.byte);
            self.erase_within(index, length)?;
            index.page += 1;
            index.byte = 0;
            range.start += length;
        }
        Ok(())
    }

    /// Writes a slice fitting a page (regardless of previous value).
    ///
    /// This function will erase the page if needed and restore the non-overwritten part. This is
    /// not power-loss resistant.
    fn write_within(&mut self, index: StorageIndex, value: &[u8]) -> StorageResult<()> {
        self.erase_within(index, value.len())?;
        self.write_unaligned(index, value)
    }

    /// Writes a slice fitting a page (assuming erased but not necessarily word-aligned).
    fn write_unaligned(&mut self, mut index: StorageIndex, mut value: &[u8]) -> StorageResult<()> {
        let word_size = self.storage.word_size();
        // Align the beginning if needed.
        let unaligned = index.byte % word_size;
        if unaligned != 0 {
            let len = core::cmp::min(value.len(), word_size - unaligned);
            index.byte -= unaligned;
            let mut word = self.storage.read_slice(index, word_size)?.into_owned();
            word[unaligned..unaligned + len].copy_from_slice(&value[..len]);
            self.storage.write_slice(index, &word)?;
            value = &value[len..];
            index.byte += word_size;
        }
        // Write as long as aligned.
        let len = value.len() - (value.len() % word_size);
        self.storage.write_slice(index, &value[..len])?;
        value = &value[len..];
        index.byte += len;
        // Write the unaligned end if needed.
        if !value.is_empty() {
            let mut word = self.storage.read_slice(index, word_size)?.into_owned();
            word[..value.len()].copy_from_slice(value);
            self.storage.write_slice(index, &word)?;
        }
        Ok(())
    }

    /// Erases a slice fitting a page (regardless of previous value).
    ///
    /// This function will erase the page if needed and restore the non-overwritten part. This is
    /// not power-loss resistant.
    fn erase_within(&mut self, index: StorageIndex, length: usize) -> StorageResult<()> {
        let previous_value = self.storage.read_slice(index, length)?;
        if previous_value.iter().all(|&x| x == 0xff) {
            // The slice is already erased, so nothing to do.
            return Ok(());
        }
        // We must erase the page, so we save the rest.
        let complement = self.save_complement(index, length)?;
        self.storage.erase_page(index.page)?;
        self.restore_complement(index.page, complement)
    }

    /// Saves the complement of a slice fitting a page.
    fn save_complement(&self, index: StorageIndex, length: usize) -> StorageResult<Complement> {
        let page_size = self.storage.page_size();
        let prefix = self
            .storage
            .read_slice(
                StorageIndex {
                    page: index.page,
                    byte: 0,
                },
                index.byte,
            )?
            .into_owned();
        let suffix = self
            .storage
            .read_slice(
                StorageIndex {
                    page: index.page,
                    byte: index.byte + length,
                },
                page_size - index.byte - length,
            )?
            .into_owned();
        Ok(Complement { prefix, suffix })
    }

    /// Restores the complement of a slice fitting a page.
    fn restore_complement(&mut self, page: usize, complement: Complement) -> StorageResult<()> {
        let page_size = self.storage.page_size();
        let Complement { prefix, suffix } = complement;
        self.write_unaligned(StorageIndex { page, byte: 0 }, &prefix)?;
        self.write_unaligned(
            StorageIndex {
                page,
                byte: page_size - suffix.len(),
            },
            &suffix,
        )?;
        Ok(())
    }
}

/// Represents the complement of a slice within a page.
struct Complement {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::MINIMAL;
    use crate::{BufferOptions, BufferStorage};

    /// Creates a linear view into a fresh minimal buffer storage.
    fn new_linear() -> Linear<BufferStorage> {
        let mut options = BufferOptions::from(&MINIMAL);
        options.strict_mode = false;
        let storage = vec![0xff; MINIMAL.num_pages * MINIMAL.page_size].into_boxed_slice();
        let storage = BufferStorage::new(storage, options);
        Linear { storage }
    }

    /// Returns some interesting test ranges.
    fn ranges(linear: &Linear<BufferStorage>) -> Vec<Range<usize>> {
        let storage_length = linear.length();
        let page_size = linear.storage.page_size();
        let count = 2 * linear.storage.word_size();
        let mut ranges = Vec::new();
        let convert = |page: usize, byte: usize, rev| {
            if rev {
                (page + 1) * page_size - byte
            } else {
                page * page_size + byte
            }
        };
        for &start_rev in [false, true].iter() {
            for &length_rev in [false, true].iter() {
                for start_page in 0..=2 {
                    for length_page in 0..2 {
                        for start_byte in 0..count {
                            for length_byte in 0..count {
                                let start = convert(start_page, start_byte, start_rev);
                                let length = convert(length_page, length_byte, length_rev);
                                ranges.push(start..start + length);
                                let end = storage_length - start;
                                let start = end - length;
                                ranges.push(start..end);
                            }
                        }
                    }
                }
            }
        }
        ranges
    }

    #[test]
    fn simple_usage() {
        let mut linear = new_linear();
        linear.write(3, b"hello").unwrap();
        assert_eq!(
            linear.read(0..10).unwrap(),
            &b"\xff\xff\xffhello\xff\xff"[..]
        );
        linear.write(5, b"y you").unwrap();
        assert_eq!(linear.read(0..10).unwrap(), &b"\xff\xff\xffhey you"[..]);
        linear.erase(6..10).unwrap();
        assert_eq!(
            linear.read(0..10).unwrap(),
            &b"\xff\xff\xffhey\xff\xff\xff\xff"[..]
        );
    }

    #[test]
    fn round_trip() {
        let mut linear = new_linear();
        let pattern: Vec<u8> = (0..255).collect();
        for range in ranges(&linear) {
            // Check that writing and reading back gives the same value.
            let value = &pattern[..range.len()];
            assert_eq!(linear.write(range.start, value), Ok(()), "{:?}", range);
            match linear.read(range.clone()) {
                Ok(actual) => assert_eq!(actual, value, "{:?}", range),
                Err(error) => panic!("{:?} {:?}", error, range),
            }
        }
    }

    #[test]
    fn out_of_bound() {
        let mut linear = new_linear();
        let length = linear.length();
        assert!(linear.read(length..length + 1).is_err());
        assert!(linear.read(length + 1..length + 5).is_err());
        assert!(linear.read(0..length + 1).is_err());
        assert!(linear.read(length - 10..length + 1).is_err());
        assert!(linear.write(length, &[0]).is_err());
        assert!(linear.write(length - 10, &[0; 11]).is_err());
    }

    #[test]
    fn erase_before() {
        let mut linear = new_linear();
        let pattern: Vec<u8> = (0..255).collect();
        for mut range in ranges(&linear) {
            if range.is_empty() {
                continue;
            }
            let value = &pattern[..range.len()];
            // We write the pattern.
            assert_eq!(linear.write(range.start, value), Ok(()), "{:?}", range);
            // We erase the pattern except for the last byte.
            range.end -= 1;
            assert_eq!(linear.erase(range.clone()), Ok(()), "{:?}", range);
            // We check that the pattern was erased except for the last byte.
            match linear.read(range.clone()) {
                Ok(actual) => assert_eq!(actual, vec![0xff; range.len()], "{:?}", range),
                Err(error) => panic!("{:?} {:?}", error, range),
            }
            // We check that the last byte is still there.
            range.start = range.end;
            range.end += 1;
            match linear.read(range.clone()) {
                Ok(actual) => assert_eq!(actual, &value[value.len() - 1..], "{:?}", range),
                Err(error) => panic!("{:?} {:?}", error, range),
            }
        }
    }

    #[test]
    fn erase_after() {
        let mut linear = new_linear();
        let pattern: Vec<u8> = (0..255).collect();
        for mut range in ranges(&linear) {
            if range.is_empty() {
                continue;
            }
            let value = &pattern[..range.len()];
            // We write the pattern.
            assert_eq!(linear.write(range.start, value), Ok(()), "{:?}", range);
            // We erase the pattern except for the first byte.
            range.start += 1;
            assert_eq!(linear.erase(range.clone()), Ok(()), "{:?}", range);
            // We check that the pattern was erased except for the first byte.
            match linear.read(range.clone()) {
                Ok(actual) => assert_eq!(actual, vec![0xff; range.len()], "{:?}", range),
                Err(error) => panic!("{:?} {:?}", error, range),
            }
            // We check that the first byte is still there.
            range.end = range.start;
            range.start -= 1;
            match linear.read(range.clone()) {
                Ok(actual) => assert_eq!(actual, &value[..1], "{:?}", range),
                Err(error) => panic!("{:?} {:?}", error, range),
            }
        }
    }
}
