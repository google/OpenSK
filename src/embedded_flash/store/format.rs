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

use super::super::{Index, Storage};
use super::{bitfield, StoreConfig, StoreEntry, StoreError};
use alloc::vec::Vec;

/// Whether a user entry is a replace entry.
pub enum IsReplace {
    /// This is a replace entry.
    Replace,

    /// This is an insert entry.
    Insert,
}

/// Helpers to parse the store format.
///
/// See the store module-level documentation for information about the format.
pub struct Format {
    pub word_size: usize,
    pub page_size: usize,
    pub num_pages: usize,
    pub max_page_erases: usize,
    pub num_tags: usize,

    /// Whether an entry is present.
    ///
    /// - 0 for entries (user entries or internal entries).
    /// - 1 for free space until the end of the page.
    present_bit: usize,

    /// Whether an entry is deleted.
    ///
    /// - 0 for deleted entries.
    /// - 1 for alive entries.
    deleted_bit: usize,

    /// Whether an entry is internal.
    ///
    /// - 0 for internal entries.
    /// - 1 for user entries.
    internal_bit: usize,

    /// Whether a user entry is a replace entry.
    ///
    /// - 0 for replace entries.
    /// - 1 for insert entries.
    replace_bit: usize,

    /// The data length of a user entry.
    length_range: bitfield::BitRange,

    /// The tag of a user entry.
    tag_range: bitfield::BitRange,

    /// The page index of a replace entry.
    replace_page_range: bitfield::BitRange,

    /// The byte index of a replace entry.
    replace_byte_range: bitfield::BitRange,

    /// The index of the page to erase.
    ///
    /// This is only present for internal entries.
    old_page_range: bitfield::BitRange,

    /// The current erase count of the page to erase.
    ///
    /// This is only present for internal entries.
    saved_erase_count_range: bitfield::BitRange,

    /// Whether a page is initialized.
    ///
    /// - 0 for initialized pages.
    /// - 1 for uninitialized pages.
    initialized_bit: usize,

    /// The erase count of a page.
    erase_count_range: bitfield::BitRange,

    /// Whether a page is being compacted.
    ///
    /// - 0 for pages being compacted.
    /// - 1 otherwise.
    compacting_bit: usize,

    /// The page index to which a page is being compacted.
    new_page_range: bitfield::BitRange,
}

impl Format {
    /// Returns a helper to parse the store format for a given storage and config.
    ///
    /// # Errors
    ///
    /// Returns `None` if any of the following conditions does not hold:
    /// - The word size must be a power of two.
    /// - The page size must be a power of two.
    /// - There should be at least 2 pages in the storage.
    /// - It should be possible to write a word at least twice.
    /// - It should be possible to erase a page at least once.
    /// - There should be at least 1 tag.
    pub fn new<S: Storage, C: StoreConfig>(storage: &S, config: &C) -> Option<Format> {
        let word_size = storage.word_size();
        let page_size = storage.page_size();
        let num_pages = storage.num_pages();
        let max_word_writes = storage.max_word_writes();
        let max_page_erases = storage.max_page_erases();
        let num_tags = config.num_tags();
        if !(word_size.is_power_of_two()
            && page_size.is_power_of_two()
            && num_pages > 1
            && max_word_writes >= 2
            && max_page_erases > 0
            && num_tags > 0)
        {
            return None;
        }
        // Compute how many bits we need to store the fields.
        let page_bits = num_bits(num_pages);
        let byte_bits = num_bits(page_size);
        let tag_bits = num_bits(num_tags);
        let erase_bits = num_bits(max_page_erases + 1);
        // Compute the bit position of the fields.
        let present_bit = 0;
        let deleted_bit = present_bit + 1;
        let internal_bit = deleted_bit + 1;
        let replace_bit = internal_bit + 1;
        let length_range = bitfield::BitRange {
            start: replace_bit + 1,
            length: byte_bits,
        };
        let tag_range = bitfield::BitRange {
            start: length_range.end(),
            length: tag_bits,
        };
        let replace_page_range = bitfield::BitRange {
            start: tag_range.end(),
            length: page_bits,
        };
        let replace_byte_range = bitfield::BitRange {
            start: replace_page_range.end(),
            length: byte_bits,
        };
        let old_page_range = bitfield::BitRange {
            start: internal_bit + 1,
            length: page_bits,
        };
        let saved_erase_count_range = bitfield::BitRange {
            start: old_page_range.end(),
            length: erase_bits,
        };
        let initialized_bit = 0;
        let erase_count_range = bitfield::BitRange {
            start: initialized_bit + 1,
            length: erase_bits,
        };
        let compacting_bit = erase_count_range.end();
        let new_page_range = bitfield::BitRange {
            start: compacting_bit + 1,
            length: page_bits,
        };
        let format = Format {
            word_size,
            page_size,
            num_pages,
            max_page_erases,
            num_tags,
            present_bit,
            deleted_bit,
            internal_bit,
            replace_bit,
            length_range,
            tag_range,
            replace_page_range,
            replace_byte_range,
            old_page_range,
            saved_erase_count_range,
            initialized_bit,
            erase_count_range,
            compacting_bit,
            new_page_range,
        };
        // Make sure all the following conditions hold:
        // - The page header is one word.
        // - The internal entry is one word.
        // - The entry header fits in one word.
        if format.page_header_size() != word_size
            || format.internal_entry_size() != word_size
            || format.header_size() > word_size
        {
            return None;
        }
        Some(format)
    }

    /// Ensures a user entry is valid.
    pub fn validate_entry(&self, entry: StoreEntry) -> Result<(), StoreError> {
        if entry.tag >= self.num_tags {
            return Err(StoreError::InvalidTag);
        }
        if entry.data.len() >= self.page_size {
            return Err(StoreError::StoreFull);
        }
        Ok(())
    }

    /// Returns the entry header length in bytes.
    ///
    /// This is the smallest number of bytes necessary to store all fields of the entry info up to
    /// and including `length`.
    pub fn header_size(&self) -> usize {
        self.bits_to_bytes(self.length_range.end())
    }

    /// Returns the entry info length in bytes.
    ///
    /// This is the number of bytes necessary to store all fields of the entry info. This also
    /// includes the internal padding to protect the `committed` bit from the `deleted` bit.
    fn info_size(&self, is_replace: IsReplace) -> usize {
        let suffix_bits = 2; // committed + complete
        let info_bits = match is_replace {
            IsReplace::Replace => self.replace_byte_range.end() + suffix_bits,
            IsReplace::Insert => self.tag_range.end() + suffix_bits,
        };
        let info_size = self.bits_to_bytes(info_bits);
        // If the suffix bits would end up in the header, we need to add one byte for them.
        if info_size == self.header_size() {
            info_size + 1
        } else {
            info_size
        }
    }

    /// Returns the length in bytes of an entry.
    ///
    /// This depends on the length of the user data and whether the entry replaces an old entry or
    /// is an insertion. This also includes the internal padding to protect the `committed` bit from
    /// the `deleted` bit.
    pub fn entry_size(&self, is_replace: IsReplace, length: usize) -> usize {
        let mut entry_size = length + self.info_size(is_replace);
        let word_size = self.word_size;
        entry_size = self.align_word(entry_size);
        // The entry must be at least 2 words such that the `committed` and `deleted` bits are on
        // different words.
        if entry_size == word_size {
            entry_size += word_size;
        }
        entry_size
    }

    /// Returns the length in bytes of an internal entry.
    pub fn internal_entry_size(&self) -> usize {
        let length = self.bits_to_bytes(self.saved_erase_count_range.end());
        self.align_word(length)
    }

    pub fn is_present(&self, header: &[u8]) -> bool {
        bitfield::is_zero(self.present_bit, header, bitfield::NO_GAP)
    }

    pub fn set_present(&self, header: &mut [u8]) {
        bitfield::set_zero(self.present_bit, header, bitfield::NO_GAP)
    }

    pub fn is_deleted(&self, header: &[u8]) -> bool {
        bitfield::is_zero(self.deleted_bit, header, bitfield::NO_GAP)
    }

    /// Returns whether an entry is present and not deleted.
    pub fn is_alive(&self, header: &[u8]) -> bool {
        self.is_present(header) && !self.is_deleted(header)
    }

    pub fn set_deleted(&self, header: &mut [u8]) {
        bitfield::set_zero(self.deleted_bit, header, bitfield::NO_GAP)
    }

    pub fn is_internal(&self, header: &[u8]) -> bool {
        bitfield::is_zero(self.internal_bit, header, bitfield::NO_GAP)
    }

    pub fn set_internal(&self, header: &mut [u8]) {
        bitfield::set_zero(self.internal_bit, header, bitfield::NO_GAP)
    }

    pub fn is_replace(&self, header: &[u8]) -> IsReplace {
        if bitfield::is_zero(self.replace_bit, header, bitfield::NO_GAP) {
            IsReplace::Replace
        } else {
            IsReplace::Insert
        }
    }

    fn set_replace(&self, header: &mut [u8]) {
        bitfield::set_zero(self.replace_bit, header, bitfield::NO_GAP)
    }

    pub fn get_length(&self, header: &[u8]) -> usize {
        bitfield::get_range(self.length_range, header, bitfield::NO_GAP)
    }

    fn set_length(&self, header: &mut [u8], length: usize) {
        bitfield::set_range(self.length_range, header, bitfield::NO_GAP, length)
    }

    pub fn get_data<'a>(&self, entry: &'a [u8]) -> &'a [u8] {
        &entry[self.header_size()..][..self.get_length(entry)]
    }

    /// Returns the span of user data in an entry.
    ///
    /// The complement of this gap in the entry is exactly the entry info. The header is before the
    /// gap and the footer is after the gap.
    fn entry_gap(&self, entry: &[u8]) -> bitfield::ByteGap {
        let start = self.header_size();
        let length = self.get_length(entry);
        bitfield::ByteGap { start, length }
    }

    pub fn get_tag(&self, entry: &[u8]) -> usize {
        bitfield::get_range(self.tag_range, entry, self.entry_gap(entry))
    }

    fn set_tag(&self, entry: &mut [u8], tag: usize) {
        bitfield::set_range(self.tag_range, entry, self.entry_gap(entry), tag)
    }

    pub fn get_replace_index(&self, entry: &[u8]) -> Index {
        let gap = self.entry_gap(entry);
        let page = bitfield::get_range(self.replace_page_range, entry, gap);
        let byte = bitfield::get_range(self.replace_byte_range, entry, gap);
        Index { page, byte }
    }

    fn set_replace_page(&self, entry: &mut [u8], page: usize) {
        bitfield::set_range(self.replace_page_range, entry, self.entry_gap(entry), page)
    }

    fn set_replace_byte(&self, entry: &mut [u8], byte: usize) {
        bitfield::set_range(self.replace_byte_range, entry, self.entry_gap(entry), byte)
    }

    /// Returns the bit position of the `committed` bit.
    ///
    /// This cannot be precomputed like other fields since it depends on the length of the entry.
    fn committed_bit(&self, entry: &[u8]) -> usize {
        8 * entry.len() - 2
    }

    /// Returns the bit position of the `complete` bit.
    ///
    /// This cannot be precomputed like other fields since it depends on the length of the entry.
    fn complete_bit(&self, entry: &[u8]) -> usize {
        8 * entry.len() - 1
    }

    pub fn is_committed(&self, entry: &[u8]) -> bool {
        bitfield::is_zero(self.committed_bit(entry), entry, bitfield::NO_GAP)
    }

    pub fn set_committed(&self, entry: &mut [u8]) {
        bitfield::set_zero(self.committed_bit(entry), entry, bitfield::NO_GAP)
    }

    pub fn is_complete(&self, entry: &[u8]) -> bool {
        bitfield::is_zero(self.complete_bit(entry), entry, bitfield::NO_GAP)
    }

    fn set_complete(&self, entry: &mut [u8]) {
        bitfield::set_zero(self.complete_bit(entry), entry, bitfield::NO_GAP)
    }

    pub fn get_old_page(&self, header: &[u8]) -> usize {
        bitfield::get_range(self.old_page_range, header, bitfield::NO_GAP)
    }

    pub fn set_old_page(&self, header: &mut [u8], old_page: usize) {
        bitfield::set_range(self.old_page_range, header, bitfield::NO_GAP, old_page)
    }

    pub fn get_saved_erase_count(&self, header: &[u8]) -> usize {
        bitfield::get_range(self.saved_erase_count_range, header, bitfield::NO_GAP)
    }

    pub fn set_saved_erase_count(&self, header: &mut [u8], erase_count: usize) {
        bitfield::set_range(
            self.saved_erase_count_range,
            header,
            bitfield::NO_GAP,
            erase_count,
        )
    }

    /// Builds an entry for replace or insert operations.
    pub fn build_entry(&self, replace: Option<Index>, user_entry: StoreEntry) -> Vec<u8> {
        let StoreEntry { tag, data } = user_entry;
        let is_replace = match replace {
            None => IsReplace::Insert,
            Some(_) => IsReplace::Replace,
        };
        let entry_len = self.entry_size(is_replace, data.len());
        let mut entry = Vec::with_capacity(entry_len);
        // Build the header.
        entry.resize(self.header_size(), 0xff);
        self.set_present(&mut entry[..]);
        self.set_length(&mut entry[..], data.len());
        // Add the data.
        entry.extend_from_slice(data);
        // Build the footer.
        entry.resize(entry_len, 0xff);
        self.set_tag(&mut entry[..], tag);
        self.set_complete(&mut entry[..]);
        match replace {
            None => self.set_committed(&mut entry[..]),
            Some(Index { page, byte }) => {
                self.set_replace(&mut entry[..]);
                self.set_replace_page(&mut entry[..], page);
                self.set_replace_byte(&mut entry[..], byte);
            }
        }
        entry
    }

    /// Builds an entry for replace or insert operations.
    pub fn build_erase_entry(&self, old_page: usize, saved_erase_count: usize) -> Vec<u8> {
        let mut entry = vec![0xff; self.internal_entry_size()];
        self.set_present(&mut entry[..]);
        self.set_internal(&mut entry[..]);
        self.set_old_page(&mut entry[..], old_page);
        self.set_saved_erase_count(&mut entry[..], saved_erase_count);
        entry
    }

    /// Returns the length in bytes of a page header entry.
    ///
    /// This includes the word padding.
    pub fn page_header_size(&self) -> usize {
        self.align_word(self.bits_to_bytes(self.erase_count_range.end()))
    }

    pub fn is_initialized(&self, header: &[u8]) -> bool {
        bitfield::is_zero(self.initialized_bit, header, bitfield::NO_GAP)
    }

    pub fn set_initialized(&self, header: &mut [u8]) {
        bitfield::set_zero(self.initialized_bit, header, bitfield::NO_GAP)
    }

    pub fn get_erase_count(&self, header: &[u8]) -> usize {
        bitfield::get_range(self.erase_count_range, header, bitfield::NO_GAP)
    }

    pub fn set_erase_count(&self, header: &mut [u8], count: usize) {
        bitfield::set_range(self.erase_count_range, header, bitfield::NO_GAP, count)
    }

    pub fn is_compacting(&self, header: &[u8]) -> bool {
        bitfield::is_zero(self.compacting_bit, header, bitfield::NO_GAP)
    }

    pub fn set_compacting(&self, header: &mut [u8]) {
        bitfield::set_zero(self.compacting_bit, header, bitfield::NO_GAP)
    }

    pub fn get_new_page(&self, header: &[u8]) -> usize {
        bitfield::get_range(self.new_page_range, header, bitfield::NO_GAP)
    }

    pub fn set_new_page(&self, header: &mut [u8], new_page: usize) {
        bitfield::set_range(self.new_page_range, header, bitfield::NO_GAP, new_page)
    }

    /// Returns the smallest word boundary greater or equal to a value.
    fn align_word(&self, value: usize) -> usize {
        let word_size = self.word_size;
        (value + word_size - 1) / word_size * word_size
    }

    /// Returns the minimum number of bytes to represent a given number of bits.
    fn bits_to_bytes(&self, bits: usize) -> usize {
        (bits + 7) / 8
    }
}

/// Returns the number of bits necessary to write numbers smaller than `x`.
fn num_bits(x: usize) -> usize {
    x.next_power_of_two().trailing_zeros() as usize
}

#[test]
fn num_bits_ok() {
    assert_eq!(num_bits(0), 0);
    assert_eq!(num_bits(1), 0);
    assert_eq!(num_bits(2), 1);
    assert_eq!(num_bits(3), 2);
    assert_eq!(num_bits(4), 2);
    assert_eq!(num_bits(5), 3);
    assert_eq!(num_bits(8), 3);
    assert_eq!(num_bits(9), 4);
    assert_eq!(num_bits(16), 4);
}
