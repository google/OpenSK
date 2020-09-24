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
use alloc::boxed::Box;
use alloc::vec;

pub struct BufferStorage {
    storage: Box<[u8]>,
    options: BufferOptions,
    word_writes: Box<[usize]>,
    page_erases: Box<[usize]>,
    snapshot: Snapshot,
}

#[derive(Copy, Clone, Debug)]
pub struct BufferOptions {
    /// Size of a word in bytes.
    pub word_size: usize,

    /// Size of a page in bytes.
    pub page_size: usize,

    /// How many times a word can be written between page erasures
    pub max_word_writes: usize,

    /// How many times a page can be erased.
    pub max_page_erases: usize,

    /// Bits cannot be written from 0 to 1.
    pub strict_write: bool,
}

impl BufferStorage {
    /// Creates a fake embedded flash using a buffer.
    ///
    /// This implementation checks that no words are written more than `max_word_writes` between
    /// page erasures and than no pages are erased more than `max_page_erases`. If `strict_write` is
    /// true, it also checks that no bits are written from 0 to 1. It also permits to take snapshots
    /// of the storage during write and erase operations (although words would still be written or
    /// erased completely).
    ///
    /// # Panics
    ///
    /// The following preconditions must hold:
    /// - `options.word_size` must be a power of two.
    /// - `options.page_size` must be a power of two.
    /// - `options.page_size` must be word-aligned.
    /// - `storage.len()` must be page-aligned.
    pub fn new(storage: Box<[u8]>, options: BufferOptions) -> BufferStorage {
        assert!(options.word_size.is_power_of_two());
        assert!(options.page_size.is_power_of_two());
        let num_words = storage.len() / options.word_size;
        let num_pages = storage.len() / options.page_size;
        let buffer = BufferStorage {
            storage,
            options,
            word_writes: vec![0; num_words].into_boxed_slice(),
            page_erases: vec![0; num_pages].into_boxed_slice(),
            snapshot: Snapshot::Ready,
        };
        assert!(buffer.is_word_aligned(buffer.options.page_size));
        assert!(buffer.is_page_aligned(buffer.storage.len()));
        buffer
    }

    /// Takes a snapshot of the storage after a given amount of word operations.
    ///
    /// Each time a word is written or erased, the delay is decremented if positive. Otherwise, a
    /// snapshot is taken before the operation is executed.
    ///
    /// # Panics
    ///
    /// Panics if a snapshot has been armed and not examined.
    pub fn arm_snapshot(&mut self, delay: usize) {
        self.snapshot.arm(delay);
    }

    /// Unarms and returns the snapshot or the delay remaining.
    ///
    /// # Panics
    ///
    /// Panics if a snapshot was not armed.
    pub fn get_snapshot(&mut self) -> Result<Box<[u8]>, usize> {
        self.snapshot.get()
    }

    /// Takes a snapshot of the storage.
    pub fn take_snapshot(&self) -> Box<[u8]> {
        self.storage.clone()
    }

    /// Returns the storage.
    pub fn get_storage(self) -> Box<[u8]> {
        self.storage
    }

    fn is_word_aligned(&self, x: usize) -> bool {
        x & (self.options.word_size - 1) == 0
    }

    fn is_page_aligned(&self, x: usize) -> bool {
        x & (self.options.page_size - 1) == 0
    }

    /// Writes a slice to the storage.
    ///
    /// The slice `value` is written to `index`. The `erase` boolean specifies whether this is an
    /// erase operation or a write operation which matters for the checks and updating the shadow
    /// storage. This also takes a snapshot of the storage if a snapshot was armed and the delay has
    /// elapsed.
    ///
    /// The following preconditions should hold:
    /// - `index` is word-aligned.
    /// - `value.len()` is word-aligned.
    ///
    /// The following checks are performed:
    /// - The region of length `value.len()` starting at `index` fits in a storage page.
    /// - A word is not written more than `max_word_writes`.
    /// - A page is not erased more than `max_page_erases`.
    /// - The new word only switches 1s to 0s (only if `strict_write` is set).
    fn update_storage(&mut self, index: Index, value: &[u8], erase: bool) -> StorageResult<()> {
        debug_assert!(self.is_word_aligned(index.byte) && self.is_word_aligned(value.len()));
        let dst = index.range(value.len(), self)?.step_by(self.word_size());
        let src = value.chunks(self.word_size());
        // Check and update page shadow.
        if erase {
            let page = index.page;
            assert!(self.page_erases[page] < self.max_page_erases());
            self.page_erases[page] += 1;
        }
        for (byte, val) in dst.zip(src) {
            let range = byte..byte + self.word_size();
            // The driver doesn't write identical words.
            if &self.storage[range.clone()] == val {
                continue;
            }
            // Check and update word shadow.
            let word = byte / self.word_size();
            if erase {
                self.word_writes[word] = 0;
            } else {
                assert!(self.word_writes[word] < self.max_word_writes());
                self.word_writes[word] += 1;
            }
            // Check strict write.
            if !erase && self.options.strict_write {
                for (byte, &val) in range.clone().zip(val) {
                    assert_eq!(self.storage[byte] & val, val);
                }
            }
            // Take snapshot if armed and delay expired.
            self.snapshot.take(&self.storage);
            // Write storage
            self.storage[range].copy_from_slice(val);
        }
        Ok(())
    }
}

impl Storage for BufferStorage {
    fn word_size(&self) -> usize {
        self.options.word_size
    }

    fn page_size(&self) -> usize {
        self.options.page_size
    }

    fn num_pages(&self) -> usize {
        self.storage.len() / self.options.page_size
    }

    fn max_word_writes(&self) -> usize {
        self.options.max_word_writes
    }

    fn max_page_erases(&self) -> usize {
        self.options.max_page_erases
    }

    fn read_slice(&self, index: Index, length: usize) -> StorageResult<&[u8]> {
        Ok(&self.storage[index.range(length, self)?])
    }

    fn write_slice(&mut self, index: Index, value: &[u8]) -> StorageResult<()> {
        if !self.is_word_aligned(index.byte) || !self.is_word_aligned(value.len()) {
            return Err(StorageError::NotAligned);
        }
        self.update_storage(index, value, false)
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let index = Index { page, byte: 0 };
        let value = vec![0xff; self.page_size()];
        self.update_storage(index, &value, true)
    }
}

// Controls when a snapshot of the storage is taken.
//
// This can be used to simulate power-offs while the device is writing to the storage or erasing a
// page in the storage.
enum Snapshot {
    // Mutable word operations have normal behavior.
    Ready,
    // If the delay is positive, mutable word operations decrement it. If the count is zero, mutable
    // word operations take a snapshot of the storage.
    Armed { delay: usize },
    // Mutable word operations have normal behavior.
    Taken { storage: Box<[u8]> },
}

impl Snapshot {
    fn arm(&mut self, delay: usize) {
        match self {
            Snapshot::Ready => *self = Snapshot::Armed { delay },
            _ => panic!(),
        }
    }

    fn get(&mut self) -> Result<Box<[u8]>, usize> {
        let mut snapshot = Snapshot::Ready;
        core::mem::swap(self, &mut snapshot);
        match snapshot {
            Snapshot::Armed { delay } => Err(delay),
            Snapshot::Taken { storage } => Ok(storage),
            _ => panic!(),
        }
    }

    fn take(&mut self, storage: &[u8]) {
        if let Snapshot::Armed { delay } = self {
            if *delay == 0 {
                let storage = storage.to_vec().into_boxed_slice();
                *self = Snapshot::Taken { storage };
            } else {
                *delay -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NUM_PAGES: usize = 2;
    const OPTIONS: BufferOptions = BufferOptions {
        word_size: 4,
        page_size: 16,
        max_word_writes: 2,
        max_page_erases: 3,
        strict_write: true,
    };
    // Those words are decreasing bit patterns. Bits are only changed from 1 to 0 and at last one
    // bit is changed.
    const BLANK_WORD: &[u8] = &[0xff, 0xff, 0xff, 0xff];
    const FIRST_WORD: &[u8] = &[0xee, 0xdd, 0xbb, 0x77];
    const SECOND_WORD: &[u8] = &[0xca, 0xc9, 0xa9, 0x65];
    const THIRD_WORD: &[u8] = &[0x88, 0x88, 0x88, 0x44];

    fn new_storage() -> Box<[u8]> {
        vec![0xff; NUM_PAGES * OPTIONS.page_size].into_boxed_slice()
    }

    #[test]
    fn words_are_decreasing() {
        fn assert_is_decreasing(prev: &[u8], next: &[u8]) {
            for (&prev, &next) in prev.iter().zip(next.iter()) {
                assert_eq!(prev & next, next);
                assert!(prev != next);
            }
        }
        assert_is_decreasing(BLANK_WORD, FIRST_WORD);
        assert_is_decreasing(FIRST_WORD, SECOND_WORD);
        assert_is_decreasing(SECOND_WORD, THIRD_WORD);
    }

    #[test]
    fn options_ok() {
        let buffer = BufferStorage::new(new_storage(), OPTIONS);
        assert_eq!(buffer.word_size(), OPTIONS.word_size);
        assert_eq!(buffer.page_size(), OPTIONS.page_size);
        assert_eq!(buffer.num_pages(), NUM_PAGES);
        assert_eq!(buffer.max_word_writes(), OPTIONS.max_word_writes);
        assert_eq!(buffer.max_page_erases(), OPTIONS.max_page_erases);
    }

    #[test]
    fn read_write_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = Index { page: 0, byte: 0 };
        let next_index = Index { page: 0, byte: 4 };
        assert_eq!(buffer.read_slice(index, 4).unwrap(), BLANK_WORD);
        buffer.write_slice(index, FIRST_WORD).unwrap();
        assert_eq!(buffer.read_slice(index, 4).unwrap(), FIRST_WORD);
        assert_eq!(buffer.read_slice(next_index, 4).unwrap(), BLANK_WORD);
    }

    #[test]
    fn erase_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = Index { page: 0, byte: 0 };
        let other_index = Index { page: 1, byte: 0 };
        buffer.write_slice(index, FIRST_WORD).unwrap();
        buffer.write_slice(other_index, FIRST_WORD).unwrap();
        assert_eq!(buffer.read_slice(index, 4).unwrap(), FIRST_WORD);
        assert_eq!(buffer.read_slice(other_index, 4).unwrap(), FIRST_WORD);
        buffer.erase_page(0).unwrap();
        assert_eq!(buffer.read_slice(index, 4).unwrap(), BLANK_WORD);
        assert_eq!(buffer.read_slice(other_index, 4).unwrap(), FIRST_WORD);
    }

    #[test]
    fn invalid_range() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = Index { page: 0, byte: 12 };
        let half_index = Index { page: 0, byte: 14 };
        let over_index = Index { page: 0, byte: 16 };
        let bad_page = Index { page: 2, byte: 0 };

        // Reading a word in the storage is ok.
        assert!(buffer.read_slice(index, 4).is_ok());
        // Reading a half-word in the storage is ok.
        assert!(buffer.read_slice(half_index, 2).is_ok());
        // Reading even a single byte outside a page is not ok.
        assert!(buffer.read_slice(over_index, 1).is_err());
        // But reading an empty slice just after a page is ok.
        assert!(buffer.read_slice(over_index, 0).is_ok());
        // Reading even an empty slice outside the storage is not ok.
        assert!(buffer.read_slice(bad_page, 0).is_err());

        // Writing a word in the storage is ok.
        assert!(buffer.write_slice(index, FIRST_WORD).is_ok());
        // Writing an unaligned word is not ok.
        assert!(buffer.write_slice(half_index, FIRST_WORD).is_err());
        // Writing a word outside a page is not ok.
        assert!(buffer.write_slice(over_index, FIRST_WORD).is_err());
        // But writing an empty slice just after a page is ok.
        assert!(buffer.write_slice(over_index, &[]).is_ok());
        // Writing even an empty slice outside the storage is not ok.
        assert!(buffer.write_slice(bad_page, &[]).is_err());

        // Only pages in the storage can be erased.
        assert!(buffer.erase_page(0).is_ok());
        assert!(buffer.erase_page(2).is_err());
    }

    #[test]
    fn write_twice_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = Index { page: 0, byte: 4 };
        assert!(buffer.write_slice(index, FIRST_WORD).is_ok());
        assert!(buffer.write_slice(index, SECOND_WORD).is_ok());
    }

    #[test]
    fn write_twice_and_once_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = Index { page: 0, byte: 0 };
        let next_index = Index { page: 0, byte: 4 };
        assert!(buffer.write_slice(index, FIRST_WORD).is_ok());
        assert!(buffer.write_slice(index, SECOND_WORD).is_ok());
        assert!(buffer.write_slice(next_index, THIRD_WORD).is_ok());
    }

    #[test]
    #[should_panic]
    fn write_three_times_panics() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = Index { page: 0, byte: 4 };
        assert!(buffer.write_slice(index, FIRST_WORD).is_ok());
        assert!(buffer.write_slice(index, SECOND_WORD).is_ok());
        let _ = buffer.write_slice(index, THIRD_WORD);
    }

    #[test]
    fn write_twice_then_once_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = Index { page: 0, byte: 0 };
        assert!(buffer.write_slice(index, FIRST_WORD).is_ok());
        assert!(buffer.write_slice(index, SECOND_WORD).is_ok());
        assert!(buffer.erase_page(0).is_ok());
        assert!(buffer.write_slice(index, FIRST_WORD).is_ok());
    }

    #[test]
    fn erase_three_times_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        assert!(buffer.erase_page(0).is_ok());
        assert!(buffer.erase_page(0).is_ok());
        assert!(buffer.erase_page(0).is_ok());
    }

    #[test]
    fn erase_three_times_and_once_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        assert!(buffer.erase_page(0).is_ok());
        assert!(buffer.erase_page(0).is_ok());
        assert!(buffer.erase_page(0).is_ok());
        assert!(buffer.erase_page(1).is_ok());
    }

    #[test]
    #[should_panic]
    fn erase_four_times_panics() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        assert!(buffer.erase_page(0).is_ok());
        assert!(buffer.erase_page(0).is_ok());
        assert!(buffer.erase_page(0).is_ok());
        let _ = buffer.erase_page(0).is_ok();
    }

    #[test]
    #[should_panic]
    fn switch_zero_to_one_panics() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = Index { page: 0, byte: 0 };
        assert!(buffer.write_slice(index, SECOND_WORD).is_ok());
        let _ = buffer.write_slice(index, FIRST_WORD);
    }

    #[test]
    fn get_storage_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = Index { page: 0, byte: 4 };
        buffer.write_slice(index, FIRST_WORD).unwrap();
        let storage = buffer.get_storage();
        assert_eq!(&storage[..4], BLANK_WORD);
        assert_eq!(&storage[4..8], FIRST_WORD);
    }

    #[test]
    fn snapshot_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = Index { page: 0, byte: 0 };
        let value = [FIRST_WORD, SECOND_WORD].concat();
        buffer.arm_snapshot(1);
        buffer.write_slice(index, &value).unwrap();
        let storage = buffer.get_snapshot().unwrap();
        assert_eq!(&storage[..8], &[FIRST_WORD, BLANK_WORD].concat()[..]);
        let storage = buffer.take_snapshot();
        assert_eq!(&storage[..8], &value[..]);
    }
}
