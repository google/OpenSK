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

//! Flash storage for testing.
//!
//! [`BufferStorage`] implements the flash [`Storage`] interface but doesn't interface with an
//! actual flash storage. Instead it uses a buffer in memory to represent the storage state.

use crate::{Storage, StorageError, StorageIndex, StorageResult};
use alloc::borrow::{Borrow, Cow};
use alloc::boxed::Box;
use alloc::vec;

/// Simulates a flash storage using a buffer in memory.
///
/// This buffer storage can be used in place of an actual flash storage. It is particularly useful
/// for tests and fuzzing, for which it has dedicated functionalities.
///
/// This storage tracks how many times words are written between page erase cycles, how many times
/// pages are erased, and whether an operation flips bits in the wrong direction. Operations panic
/// if those conditions are broken (optional). This storage also permits to interrupt operations for
/// inspection or to corrupt the operation.
#[derive(Clone)]
pub struct BufferStorage {
    /// Content of the storage.
    storage: Box<[u8]>,

    /// Options of the storage.
    options: BufferOptions,

    /// Number of times a word was written since the last time its page was erased.
    word_writes: Box<[usize]>,

    /// Number of times a page was erased.
    page_erases: Box<[usize]>,

    /// Interruption state.
    interruption: Interruption,
}

/// Options of a buffer storage.
#[derive(Clone, Debug)]
pub struct BufferOptions {
    /// Size of a word in bytes.
    pub word_size: usize,

    /// Size of a page in bytes.
    pub page_size: usize,

    /// How many times a word can be written between page erase cycles.
    pub max_word_writes: usize,

    /// How many times a page can be erased.
    pub max_page_erases: usize,

    /// Whether the storage should check the flash invariant.
    ///
    /// When set, the following conditions would panic:
    /// - A bit is written from 0 to 1.
    /// - A word is written more than [`Self::max_word_writes`].
    /// - A page is erased more than [`Self::max_page_erases`].
    pub strict_mode: bool,
}

/// Corrupts a slice given actual and expected value.
///
/// A corruption function is called exactly once and takes 2 arguments:
/// - A mutable slice representing the storage before the interrupted operation.
/// - A shared slice representing what the storage would have been if the operation was not
///   interrupted.
///
/// The corruption function may flip an arbitrary number of bits in the mutable slice, but may only
/// flip bits that differ between both slices.
pub type BufferCorruptFunction<'a> = Box<dyn FnOnce(&mut [u8], &[u8]) + 'a>;

impl BufferStorage {
    /// Creates a buffer storage.
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
            interruption: Interruption::Ready,
        };
        assert!(buffer.is_word_aligned(buffer.options.page_size));
        assert!(buffer.is_page_aligned(buffer.storage.len()));
        buffer
    }

    /// Arms an interruption after a given delay.
    ///
    /// Before each subsequent mutable operation (write or erase), the delay is decremented if
    /// positive. If the delay is elapsed, the operation is saved and an error is returned.
    /// Subsequent operations will panic until either of:
    /// - The interrupted operation is [corrupted](BufferStorage::corrupt_operation).
    /// - The interruption is [reset](BufferStorage::reset_interruption).
    ///
    /// # Panics
    ///
    /// Panics if an interruption is already armed.
    pub fn arm_interruption(&mut self, delay: usize) {
        self.interruption.arm(delay);
    }

    /// Disarms an interruption that did not trigger.
    ///
    /// Returns the remaining delay.
    ///
    /// # Panics
    ///
    /// Panics if any of the following conditions hold:
    /// - An interruption was not [armed](BufferStorage::arm_interruption).
    /// - An interruption was armed and it has triggered.
    pub fn disarm_interruption(&mut self) -> usize {
        self.interruption.get().err().unwrap()
    }

    /// Resets an interruption regardless of triggering.
    ///
    /// # Panics
    ///
    /// Panics if an interruption was not [armed](BufferStorage::arm_interruption).
    pub fn reset_interruption(&mut self) {
        let _ = self.interruption.get();
    }

    /// Corrupts an interrupted operation.
    ///
    /// Applies the corruption function to the storage. Counters are updated accordingly:
    /// - If a word is fully written, its counter is incremented regardless of whether other words
    ///   of the same operation have been fully written.
    /// - If a page is fully erased, its counter is incremented (and its word counters are reset).
    ///
    /// # Panics
    ///
    /// Panics if any of the following conditions hold:
    /// - An interruption was not [armed](BufferStorage::arm_interruption).
    /// - An interruption was armed but did not trigger.
    /// - The corruption function corrupts more bits than allowed.
    /// - The interrupted operation itself would have panicked.
    pub fn corrupt_operation(&mut self, corrupt: BufferCorruptFunction) {
        let operation = self.interruption.get().unwrap();
        let range = self.operation_range(&operation).unwrap();
        let mut before = self.storage[range.clone()].to_vec().into_boxed_slice();
        match operation {
            BufferOperation::Write { value: after, .. } => {
                corrupt(&mut before, &after);
                self.incr_word_writes(range.start, &before, &after);
            }
            BufferOperation::Erase { page } => {
                let after = vec![0xff; self.page_size()].into_boxed_slice();
                corrupt(&mut before, &after);
                if before == after {
                    self.incr_page_erases(page);
                }
            }
        };
        self.storage[range].copy_from_slice(&before);
    }

    /// Returns the number of times a word was written.
    pub fn get_word_writes(&self, word: usize) -> usize {
        self.word_writes[word]
    }

    /// Returns the number of times a page was erased.
    pub fn get_page_erases(&self, page: usize) -> usize {
        self.page_erases[page]
    }

    /// Sets the number of times a page was erased.
    pub fn set_page_erases(&mut self, page: usize, cycle: usize) {
        self.page_erases[page] = cycle;
    }

    /// Returns whether a number is word-aligned.
    fn is_word_aligned(&self, x: usize) -> bool {
        x & (self.options.word_size - 1) == 0
    }

    /// Returns whether a number is page-aligned.
    fn is_page_aligned(&self, x: usize) -> bool {
        x & (self.options.page_size - 1) == 0
    }

    /// Updates the counters as if a page was erased.
    ///
    /// The page counter of that page is incremented and the word counters of that page are reset.
    ///
    /// # Panics
    ///
    /// Panics if the [maximum number of erase cycles per page](BufferOptions::max_page_erases) is
    /// reached.
    fn incr_page_erases(&mut self, page: usize) {
        // Check that pages are not erased too many times.
        if self.options.strict_mode {
            assert!(self.page_erases[page] < self.max_page_erases());
        }
        self.page_erases[page] += 1;
        let num_words = self.page_size() / self.word_size();
        for word in 0..num_words {
            self.word_writes[page * num_words + word] = 0;
        }
    }

    /// Updates the word counters as if a partial write occurred.
    ///
    /// The partial write is described as if `complete` was supposed to be written to the storage
    /// starting at byte `index`, but actually only `value` was written. Word counters are
    /// incremented only if their value would change and they would be completely written.
    ///
    /// # Preconditions
    ///
    /// - `index` must be word-aligned.
    /// - `value` and `complete` must have the same word-aligned length.
    ///
    /// # Panics
    ///
    /// Panics if the [maximum number of writes per word](BufferOptions::max_word_writes) is
    /// reached.
    fn incr_word_writes(&mut self, index: usize, value: &[u8], complete: &[u8]) {
        let word_size = self.word_size();
        for i in 0..value.len() / word_size {
            let range = core::ops::Range {
                start: i * word_size,
                end: (i + 1) * word_size,
            };
            // Partial word writes do not count.
            if value[range.clone()] != complete[range.clone()] {
                continue;
            }
            // Words are written only if necessary.
            if value[range.clone()] == self.storage[index..][range] {
                continue;
            }
            let word = index / word_size + i;
            // Check that words are not written too many times.
            if self.options.strict_mode {
                assert!(self.word_writes[word] < self.max_word_writes());
            }
            self.word_writes[word] += 1;
        }
    }

    /// Returns the storage range of an operation.
    fn operation_range(
        &self,
        operation: &BufferOperation<impl Borrow<[u8]>>,
    ) -> StorageResult<core::ops::Range<usize>> {
        match *operation {
            BufferOperation::Write { index, ref value } => index.range(value.borrow().len(), self),
            BufferOperation::Erase { page } => {
                StorageIndex { page, byte: 0 }.range(self.page_size(), self)
            }
        }
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

    fn read_slice(&self, index: StorageIndex, length: usize) -> StorageResult<Cow<[u8]>> {
        Ok(Cow::Borrowed(&self.storage[index.range(length, self)?]))
    }

    fn write_slice(&mut self, index: StorageIndex, value: &[u8]) -> StorageResult<()> {
        if !self.is_word_aligned(index.byte) || !self.is_word_aligned(value.len()) {
            return Err(StorageError::NotAligned);
        }
        let operation = BufferOperation::Write { index, value };
        let range = self.operation_range(&operation)?;
        // Interrupt operation if armed and delay expired.
        self.interruption.tick(&operation)?;
        // Check and update counters.
        self.incr_word_writes(range.start, value, value);
        // Check that bits are correctly flipped.
        if self.options.strict_mode {
            for (byte, &val) in range.clone().zip(value.iter()) {
                assert_eq!(self.storage[byte] & val, val);
            }
        }
        // Write to the storage.
        self.storage[range].copy_from_slice(value);
        Ok(())
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let operation = BufferOperation::Erase { page };
        let range = self.operation_range(&operation)?;
        // Interrupt operation if armed and delay expired.
        self.interruption.tick(&operation)?;
        // Check and update counters.
        self.incr_page_erases(page);
        // Write to the storage.
        for byte in &mut self.storage[range] {
            *byte = 0xff;
        }
        Ok(())
    }
}

impl core::fmt::Display for BufferStorage {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        let num_pages = self.num_pages();
        let num_words = self.page_size() / self.word_size();
        let num_bytes = self.word_size();
        for page in 0..num_pages {
            write!(f, "[{}]", self.page_erases[page])?;
            for word in 0..num_words {
                write!(f, " [{}]", self.word_writes[page * num_words + word])?;
                for byte in 0..num_bytes {
                    let index = (page * num_words + word) * num_bytes + byte;
                    write!(f, "{:02x}", self.storage[index])?;
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

/// Represents a storage operation.
///
/// It is polymorphic over the ownership of the byte slice to avoid unnecessary copies.
#[derive(Clone, Debug, PartialEq, Eq)]
enum BufferOperation<ByteSlice: Borrow<[u8]>> {
    /// Represents a write operation.
    Write {
        /// The storage index at which the write should occur.
        index: StorageIndex,

        /// The slice that should be written.
        value: ByteSlice,
    },

    /// Represents an erase operation.
    Erase {
        /// The page that should be erased.
        page: usize,
    },
}

/// Represents a storage operation owning its byte slices.
type OwnedBufferOperation = BufferOperation<Box<[u8]>>;

/// Represents a storage operation sharing its byte slices.
type SharedBufferOperation<'a> = BufferOperation<&'a [u8]>;

impl<'a> SharedBufferOperation<'a> {
    fn to_owned(&self) -> OwnedBufferOperation {
        match *self {
            BufferOperation::Write { index, value } => BufferOperation::Write {
                index,
                value: value.to_vec().into_boxed_slice(),
            },
            BufferOperation::Erase { page } => BufferOperation::Erase { page },
        }
    }
}

/// Controls when an operation is interrupted.
///
/// This can be used to simulate power-offs while the device is writing to the storage or erasing a
/// page in the storage.
#[derive(Clone)]
enum Interruption {
    /// Mutable operations have normal behavior.
    Ready,

    /// If the delay is positive, mutable operations decrement it. If the count is zero, mutable
    /// operations fail and are saved.
    Armed { delay: usize },

    /// Mutable operations panic.
    Saved { operation: OwnedBufferOperation },
}

impl Interruption {
    /// Arms an interruption for a given delay.
    ///
    /// # Panics
    ///
    /// Panics if an interruption is already armed.
    fn arm(&mut self, delay: usize) {
        match self {
            Interruption::Ready => *self = Interruption::Armed { delay },
            _ => panic!(),
        }
    }

    /// Disarms an interruption.
    ///
    /// Returns the interrupted operation if any, otherwise the remaining delay.
    ///
    /// # Panics
    ///
    /// Panics if an interruption was not armed.
    fn get(&mut self) -> Result<OwnedBufferOperation, usize> {
        let mut interruption = Interruption::Ready;
        core::mem::swap(self, &mut interruption);
        match interruption {
            Interruption::Armed { delay } => Err(delay),
            Interruption::Saved { operation } => Ok(operation),
            _ => panic!(),
        }
    }

    /// Interrupts an operation if the delay is over.
    ///
    /// Decrements the delay if positive. Otherwise, the operation is stored and an error is
    /// returned to interrupt the operation.
    ///
    /// # Panics
    ///
    /// Panics if an operation has already been interrupted and the interruption has not been
    /// disarmed.
    fn tick(&mut self, operation: &SharedBufferOperation) -> StorageResult<()> {
        match self {
            Interruption::Ready => (),
            Interruption::Armed { delay } if *delay == 0 => {
                let operation = operation.to_owned();
                *self = Interruption::Saved { operation };
                return Err(StorageError::CustomError);
            }
            Interruption::Armed { delay } => *delay -= 1,
            Interruption::Saved { .. } => panic!(),
        }
        Ok(())
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
        strict_mode: true,
    };
    // Those words are decreasing bit patterns. Bits are only changed from 1 to 0 and at least one
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
        let index = StorageIndex { page: 0, byte: 0 };
        let next_index = StorageIndex { page: 0, byte: 4 };
        assert_eq!(buffer.read_slice(index, 4).unwrap(), BLANK_WORD);
        buffer.write_slice(index, FIRST_WORD).unwrap();
        assert_eq!(buffer.read_slice(index, 4).unwrap(), FIRST_WORD);
        assert_eq!(buffer.read_slice(next_index, 4).unwrap(), BLANK_WORD);
    }

    #[test]
    fn erase_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = StorageIndex { page: 0, byte: 0 };
        let other_index = StorageIndex { page: 1, byte: 0 };
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
        let index = StorageIndex { page: 0, byte: 12 };
        let half_index = StorageIndex { page: 0, byte: 14 };
        let over_index = StorageIndex { page: 0, byte: 16 };
        let bad_page = StorageIndex { page: 2, byte: 0 };

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
        let index = StorageIndex { page: 0, byte: 4 };
        assert!(buffer.write_slice(index, FIRST_WORD).is_ok());
        assert!(buffer.write_slice(index, SECOND_WORD).is_ok());
    }

    #[test]
    fn write_twice_and_once_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = StorageIndex { page: 0, byte: 0 };
        let next_index = StorageIndex { page: 0, byte: 4 };
        assert!(buffer.write_slice(index, FIRST_WORD).is_ok());
        assert!(buffer.write_slice(index, SECOND_WORD).is_ok());
        assert!(buffer.write_slice(next_index, THIRD_WORD).is_ok());
    }

    #[test]
    #[should_panic]
    fn write_three_times_panics() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = StorageIndex { page: 0, byte: 4 };
        assert!(buffer.write_slice(index, FIRST_WORD).is_ok());
        assert!(buffer.write_slice(index, SECOND_WORD).is_ok());
        let _ = buffer.write_slice(index, THIRD_WORD);
    }

    #[test]
    fn write_twice_then_once_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);
        let index = StorageIndex { page: 0, byte: 0 };
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
        let index = StorageIndex { page: 0, byte: 0 };
        assert!(buffer.write_slice(index, SECOND_WORD).is_ok());
        let _ = buffer.write_slice(index, FIRST_WORD);
    }

    #[test]
    fn interrupt_delay_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);

        // Interrupt the second operation.
        buffer.arm_interruption(1);

        // The first operation should not fail.
        buffer
            .write_slice(StorageIndex { page: 0, byte: 0 }, &[0x5c; 8])
            .unwrap();
        // The delay should be decremented.
        assert_eq!(buffer.disarm_interruption(), 0);
        // The storage should have been modified.
        assert_eq!(&buffer.storage[..8], &[0x5c; 8]);
        assert!(buffer.storage[8..].iter().all(|&x| x == 0xff));
    }

    #[test]
    fn interrupt_save_ok() {
        let mut buffer = BufferStorage::new(new_storage(), OPTIONS);

        // Interrupt the second operation.
        buffer.arm_interruption(1);

        // The second operation should fail.
        buffer
            .write_slice(StorageIndex { page: 0, byte: 0 }, &[0x5c; 8])
            .unwrap();
        assert!(buffer
            .write_slice(StorageIndex { page: 0, byte: 8 }, &[0x93; 8])
            .is_err());
        // The operation should represent the change.
        buffer.corrupt_operation(Box::new(|_, value| assert_eq!(value, &[0x93; 8])));
        // The storage should not have been modified.
        assert_eq!(&buffer.storage[..8], &[0x5c; 8]);
        assert!(buffer.storage[8..].iter().all(|&x| x == 0xff));
    }
}
