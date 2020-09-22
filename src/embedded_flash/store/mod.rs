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

//! Provides a multi-purpose data-structure.
//!
//! # Description
//!
//! The `Store` data-structure permits to iterate, find, insert, delete, and replace entries in a
//! multi-set. The mutable operations (insert, delete, and replace) are atomic, in the sense that if
//! power is lost during the operation, then the operation might either succeed or fail but the
//! store remains in a coherent state. The data-structure is flash-efficient, in the sense that it
//! tries to minimize the number of times a page is erased.
//!
//! An _entry_ is made of a _tag_, which is a number, and a _data_, which is a slice of bytes. The
//! tag is stored efficiently by using unassigned bits of the entry header and footer. For example,
//! it can be used to decide how to deserialize the data. It is not necessary to use tags since a
//! prefix of the data could be used to decide how to deserialize the rest.
//!
//! Entries can also be associated to a set of _keys_. The find operation permits to retrieve all
//! entries associated to a given key. The same key can be associated to multiple entries and the
//! same entry can be associated to multiple keys.
//!
//! # Storage
//!
//! The data-structure is parametric over its storage which must implement the `Storage` trait.
//! There are currently 2 implementations of this trait:
//! - `SyscallStorage` using the `embedded_flash` syscall API for production builds.
//! - `BufferStorage` using a heap-allocated buffer for testing.
//!
//! # Configuration
//!
//! The data-structure can be configured with the `StoreConfig` trait. By implementing this trait,
//! the number of possible tags and the association between keys and entries are defined.
//!
//! # Properties
//!
//! The data-structure provides the following properties:
//! - When an operation returns success, then the represented multi-set is updated accordingly. For
//!   example, an inserted entry can be found without alteration until replaced or deleted.
//! - When an operation returns an error, the resulting multi-set state is described in the error
//!   documentation.
//! - When power is lost before an operation returns, the operation will either succeed or be
//!   rolled-back on the next initialization. So the multi-set would be either left unchanged or
//!   updated accordingly.
//!
//! Those properties rely on the following assumptions:
//! - Writing a word to flash is atomic. When power is lost, the word is either fully written or not
//!   written at all.
//! - Reading a word from flash is deterministic. When power is lost while writing or erasing a word
//!   (erasing a page containing that word), reading that word repeatedly returns the same result
//!   (until it is written or its page is erased).
//! - To decide whether a page has been erased, it is enough to test if all its bits are equal to 1.
//!
//! The properties may still hold outside those assumptions but with weaker probabilities as the
//! usage diverges from the assumptions.
//!
//! # Implementation
//!
//! The store is a page-aligned sequence of bits. It matches the following grammar:
//!
//! ```text
//! Store := Page*
//! Page := PageHeader (Entry | InternalEntry)*  Padding(page)
//! PageHeader :=  // must fit in one word
//!     initialized:1
//!     erase_count:erase_bits
//!     compacting:1
//!     new_page:page_bits
//!     Padding(word)
//! Entry := Header Data Footer
//! // Let X be the byte (word-aligned for sensitive queries) following `length` in `Info`.
//! Header := Info[..X]  // must fit in one word
//! Footer := Info[X..]  // must fit in one word
//! Info :=
//!     present=0
//!     deleted:1
//!     internal=1
//!     replace:1
//!     sensitive:1
//!     length:byte_bits
//!     tag:tag_bits
//!     [  // present if `replace` is 0
//!         replace_page:page_bits
//!         replace_byte:byte_bits
//!     ]
//!     [Padding(bit)]  // until `complete` is the last bit of a different word than `present`
//!     committed:1
//!     complete=0
//! InternalEntry :=
//!     present=0
//!     deleted:1
//!     internal=0
//!     old_page:page_bits
//!     saved_erase_count:erase_bits
//!     Padding(word)
//! Padding(X) := 1* until X-aligned
//! ```
//!
//! For bit flags, a value of 0 means true and a value of 1 means false. So when erased, bits are
//! false. They can be set to true by writing 0.
//!
//! The `Entry` rule is for user entries and the `InternalEntry` rule is for internal entries of the
//! store. Currently, there is only one kind of internal entry: an entry to erase the page being
//! compacted.
//!
//! The `Header` and `Footer` rules are computed from the `Info` rule. An entry could simply be the
//! concatenation of internal metadata and the user data. However, to optimize the size in flash, we
//! splice the user data in the middle of the metadata. The reason is that we can only write twice
//! the same word and for replace entries we need to write the deleted bit and the committed bit
//! independently. Also, this is important for the complete bit to be the last written bit (since
//! slices are written to flash from low to high addresses). Here is the representation of a
//! specific replace entry for a specific configuration:
//!
//! ```text
//! page_bits=6
//! byte_bits=9
//! tag_bits=5
//!
//! byte.bit name
//!    0.0   present
//!    0.1   deleted
//!    0.2   internal
//!    0.3   replace
//!    0.4   sensitive
//!    0.5   length (9 bits)
//!    1.6   tag (least significant 2 bits out of 5)
//! (the header ends at the first byte boundary after `length`)
//!    2.0   <user data> (2 bytes in this example)
//! (the footer starts immediately after the user data)
//!    4.0   tag (most significant 3 bits out of 5)
//!    4.3   replace_page (6 bits)
//!    5.1   replace_byte (9 bits)
//!    6.2   padding (make sure the 2 properties below hold)
//!    7.6   committed
//!    7.7   complete (on a different word than `present`)
//!    8.0   <end> (word-aligned)
//! ```
//!
//! The store should always contain at least one blank page, so that it is always possible to
//! compact.

// TODO(cretin): We don't need inner padding for insert entries. The store format can be:
//   InsertEntry | ReplaceEntry | InternalEntry (maybe rename to EraseEntry)
//   InsertEntry padding is until `complete` is the last bit of a word.
//   ReplaceEntry padding is until `complete` is the last bit of a different word than `present`.
// TODO(cretin): Add checksum (may play the same role as the completed bit) and recovery strategy?
// TODO(cretin): Add corruption (deterministic but undetermined reads) to fuzzing.
// TODO(cretin): Add more complex transactions? (this does not seem necessary yet)
// TODO(cretin): Add possibility to shred an entry (force compact page after delete)?

mod bitfield;
mod format;

use self::format::{Format, IsReplace};
use super::{Index, Storage};
#[cfg(any(test, feature = "ram_storage"))]
use crate::embedded_flash::BufferStorage;
#[cfg(any(test, feature = "ram_storage"))]
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Configures a store.
pub trait StoreConfig {
    /// How entries are keyed.
    ///
    /// To disable keys, this may be defined to `()` or even better a custom empty enum.
    type Key: Ord;

    /// Number of entry tags.
    ///
    /// All tags must be smaller than this value.
    ///
    /// To disable tags, this function should return `1`. The only valid tag would then be `0`.
    fn num_tags(&self) -> usize;

    /// Specifies the set of keys of an entry.
    ///
    /// If keys are not used, this function can immediately return. Otherwise, it should call
    /// `associate_key` for each key that should be associated to `entry`.
    fn keys(&self, entry: StoreEntry, associate_key: impl FnMut(Self::Key));
}

/// Errors returned by store operations.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The operation could not proceed because the store is full.
    StoreFull,

    /// The operation could not proceed because the provided tag is invalid.
    InvalidTag,

    /// The operation could not proceed because the preconditions do not hold.
    InvalidPrecondition,
}

/// The position of an entry in the store.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Copy, Clone)]
pub struct StoreIndex {
    /// The index of this entry in the storage.
    index: Index,

    /// The generation at which this index is valid.
    ///
    /// See the documentation of the field with the same name in the `Store` struct.
    generation: usize,
}

/// A user entry.
#[cfg_attr(feature = "std", derive(Debug, PartialEq, Eq))]
#[derive(Copy, Clone)]
pub struct StoreEntry<'a> {
    /// The tag of the entry.
    ///
    /// Must be smaller than the configured number of tags.
    pub tag: usize,

    /// The data of the entry.
    pub data: &'a [u8],

    /// Whether the data is sensitive.
    ///
    /// Sensitive data is overwritten with zeroes when the entry is deleted.
    pub sensitive: bool,
}

/// Implements a configurable multi-set on top of any storage.
pub struct Store<S: Storage, C: StoreConfig> {
    storage: S,
    config: C,
    format: Format,

    /// The index of the blank page reserved for compaction.
    blank_page: usize,

    /// Counts the number of compactions since the store creation.
    ///
    /// A `StoreIndex` is valid only if they originate from the same generation. This is checked by
    /// operations that take a `StoreIndex` as argument.
    generation: usize,
}

impl<S: Storage, C: StoreConfig> Store<S, C> {
    /// Creates a new store.
    ///
    /// Initializes the storage if it is fresh (filled with `0xff`). Rolls-back or completes an
    /// operation if the store was powered off in the middle of that operation. In other words,
    /// operations are atomic.
    ///
    /// # Errors
    ///
    /// Returns `None` if `storage` and/or `config` are not supported.
    pub fn new(storage: S, config: C) -> Option<Store<S, C>> {
        let format = Format::new(&storage, &config)?;
        let blank_page = format.num_pages;
        let mut store = Store {
            storage,
            config,
            format,
            blank_page,
            generation: 0,
        };
        // Finish any ongoing page compaction.
        store.recover_compact_page();
        // Finish or roll-back any other entry-level operations.
        store.recover_entry_operations();
        // Initialize uninitialized pages.
        store.initialize_storage();
        Some(store)
    }

    /// Iterates over all entries in the store.
    pub fn iter(&self) -> impl Iterator<Item = (StoreIndex, StoreEntry)> {
        Iter::new(self).filter_map(move |(index, entry)| {
            if self.format.is_alive(entry) {
                Some((
                    StoreIndex {
                        index,
                        generation: self.generation,
                    },
                    StoreEntry {
                        tag: self.format.get_tag(entry),
                        data: self.format.get_data(entry),
                        sensitive: self.format.is_sensitive(entry),
                    },
                ))
            } else {
                None
            }
        })
    }

    /// Iterates over all entries matching a key in the store.
    pub fn find_all<'a>(
        &'a self,
        key: &'a C::Key,
    ) -> impl Iterator<Item = (StoreIndex, StoreEntry)> + 'a {
        self.iter().filter(move |&(_, entry)| {
            let mut has_match = false;
            self.config.keys(entry, |k| has_match |= key == &k);
            has_match
        })
    }

    /// Returns the first entry matching a key in the store.
    ///
    /// This is a convenience function for when at most one entry should match the key.
    ///
    /// # Panics
    ///
    /// In debug mode, panics if more than one entry matches the key.
    pub fn find_one<'a>(&'a self, key: &'a C::Key) -> Option<(StoreIndex, StoreEntry<'a>)> {
        let mut iter = self.find_all(key);
        let first = iter.next()?;
        let has_only_one_element = iter.next().is_none();
        debug_assert!(has_only_one_element);
        Some(first)
    }

    /// Deletes an entry from the store.
    pub fn delete(&mut self, index: StoreIndex) -> Result<(), StoreError> {
        if self.generation != index.generation {
            return Err(StoreError::InvalidPrecondition);
        }
        self.delete_index(index.index);
        Ok(())
    }

    /// Replaces an entry with another with the same tag in the store.
    ///
    /// This operation (like others) is atomic. If it returns successfully, then the old entry is
    /// deleted and the new is inserted. If it fails, the old entry is not deleted and the new entry
    /// is not inserted. If power is lost during the operation, during next startup, the operation
    /// is either rolled-back (like in case of failure) or completed (like in case of success).
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `StoreFull` if the new entry does not fit in the store.
    /// - `InvalidTag` if the tag of the new entry is not smaller than the configured number of
    ///   tags.
    pub fn replace(&mut self, old: StoreIndex, new: StoreEntry) -> Result<(), StoreError> {
        if self.generation != old.generation {
            return Err(StoreError::InvalidPrecondition);
        }
        self.format.validate_entry(new)?;
        let mut old_index = old.index;
        // Find a slot.
        let entry_len = self.replace_len(new.sensitive, new.data.len());
        let index = self.find_slot_for_write(entry_len, Some(&mut old_index))?;
        // Build a new entry replacing the old one.
        let entry = self.format.build_entry(Some(old_index), new);
        debug_assert_eq!(entry.len(), entry_len);
        // Write the new entry.
        self.write_entry(index, &entry);
        // Commit the new entry, which both deletes the old entry and commits the new one.
        self.commit_index(index);
        Ok(())
    }

    /// Inserts an entry in the store.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `StoreFull` if the new entry does not fit in the store.
    /// - `InvalidTag` if the tag of the new entry is not smaller than the configured number of
    ///   tags.
    pub fn insert(&mut self, entry: StoreEntry) -> Result<(), StoreError> {
        self.format.validate_entry(entry)?;
        // Build entry.
        let entry = self.format.build_entry(None, entry);
        // Find a slot.
        let index = self.find_slot_for_write(entry.len(), None)?;
        // Write entry.
        self.write_entry(index, &entry);
        Ok(())
    }

    /// Returns the byte cost of a replace operation.
    ///
    /// Computes the length in bytes that would be used in the storage if a replace operation is
    /// executed provided the data of the new entry has `length` bytes and whether this data is
    /// sensitive.
    pub fn replace_len(&self, sensitive: bool, length: usize) -> usize {
        self.format
            .entry_size(IsReplace::Replace, sensitive, length)
    }

    /// Returns the byte cost of an insert operation.
    ///
    /// Computes the length in bytes that would be used in the storage if an insert operation is
    /// executed provided the data of the inserted entry has `length` bytes and whether this data is
    /// sensitive.
    #[allow(dead_code)]
    pub fn insert_len(&self, sensitive: bool, length: usize) -> usize {
        self.format.entry_size(IsReplace::Insert, sensitive, length)
    }

    /// Returns the erase count of all pages.
    ///
    /// The value at index `page` of the result is the number of times page `page` was erased. This
    /// number is an underestimate in case power was lost when this page was erased.
    #[allow(dead_code)]
    pub fn compaction_info(&self) -> Vec<usize> {
        let mut info = Vec::with_capacity(self.format.num_pages);
        for page in 0..self.format.num_pages {
            let (page_header, _) = self.read_page_header(page);
            let erase_count = self.format.get_erase_count(page_header);
            info.push(erase_count);
        }
        info
    }

    /// Completes any ongoing page compaction.
    fn recover_compact_page(&mut self) {
        for page in 0..self.format.num_pages {
            let (page_header, _) = self.read_page_header(page);
            if self.format.is_compacting(page_header) {
                let new_page = self.format.get_new_page(page_header);
                self.compact_page(page, new_page);
            }
        }
    }

    /// Rolls-back or completes any ongoing operation.
    fn recover_entry_operations(&mut self) {
        for page in 0..self.format.num_pages {
            let (page_header, mut index) = self.read_page_header(page);
            if !self.format.is_initialized(page_header) {
                // Skip uninitialized pages.
                continue;
            }
            while index.byte < self.format.page_size {
                let entry_index = index;
                let entry = self.read_entry(index);
                index.byte += entry.len();
                if !self.format.is_present(entry) {
                    // Reached the end of the page.
                } else if self.format.is_deleted(entry) {
                    // Wipe sensitive data if needed.
                    self.wipe_sensitive_data(entry_index);
                } else if self.format.is_internal(entry) {
                    // Finish page compaction.
                    self.erase_page(entry_index);
                } else if !self.format.is_complete(entry) {
                    // Roll-back incomplete operations.
                    self.delete_index(entry_index);
                } else if !self.format.is_committed(entry) {
                    // Finish complete but uncommitted operations.
                    self.commit_index(entry_index)
                }
            }
        }
    }

    /// Initializes uninitialized pages.
    fn initialize_storage(&mut self) {
        for page in 0..self.format.num_pages {
            let (header, index) = self.read_page_header(page);
            if self.format.is_initialized(header) {
                // Update blank page.
                let first_entry = self.read_entry(index);
                if !self.format.is_present(first_entry) {
                    self.blank_page = page;
                }
            } else {
                // We set the erase count to zero the very first time we initialize a page.
                self.initialize_page(page, 0);
            }
        }
        debug_assert!(self.blank_page != self.format.num_pages);
    }

    /// Marks an entry as deleted.
    ///
    /// The provided index must point to the beginning of an entry.
    fn delete_index(&mut self, index: Index) {
        self.update_word(index, |format, word| format.set_deleted(word));
        self.wipe_sensitive_data(index);
    }

    /// Wipes the data of a sensitive entry.
    ///
    /// If the entry at the provided index is sensitive, overwrites the data with zeroes. Otherwise,
    /// does nothing.
    fn wipe_sensitive_data(&mut self, mut index: Index) {
        let entry = self.read_entry(index);
        debug_assert!(self.format.is_present(entry));
        debug_assert!(self.format.is_deleted(entry));
        if self.format.is_internal(entry) || !self.format.is_sensitive(entry) {
            // No need to wipe the data.
            return;
        }
        let gap = self.format.entry_gap(entry);
        let data = gap.slice(entry);
        if data.iter().all(|&byte| byte == 0x00) {
            // The data is already wiped.
            return;
        }
        index.byte += gap.start;
        self.storage
            .write_slice(index, &vec![0; gap.length])
            .unwrap();
    }

    /// Finds a page with enough free space.
    ///
    /// Returns an index to the free space of a page which can hold an entry of `length` bytes. If
    /// necessary, pages may be compacted to free space. In that case, if provided, the `old_index`
    /// is updated according to compaction.
    fn find_slot_for_write(
        &mut self,
        length: usize,
        mut old_index: Option<&mut Index>,
    ) -> Result<Index, StoreError> {
        loop {
            if let Some(index) = self.choose_slot_for_write(length) {
                return Ok(index);
            }
            match self.choose_page_for_compact() {
                None => return Err(StoreError::StoreFull),
                Some(page) => {
                    let blank_page = self.blank_page;
                    // Compact the chosen page and update the old index to point to the entry in the
                    // new page if it happened to be in the old page. This is essentially a way to
                    // avoid index invalidation due to compaction.
                    let map = self.compact_page(page, blank_page);
                    if let Some(old_index) = &mut old_index {
                        map_index(page, blank_page, &map, old_index);
                    }
                }
            }
        }
    }

    /// Returns whether a page has enough free space.
    ///
    /// Returns an index to the free space of a page with smallest free space that may hold `length`
    /// bytes.
    fn choose_slot_for_write(&self, length: usize) -> Option<Index> {
        Iter::new(self)
            .filter(|(index, entry)| {
                index.page != self.blank_page
                    && !self.format.is_present(entry)
                    && length <= entry.len()
            })
            .min_by_key(|(_, entry)| entry.len())
            .map(|(index, _)| index)
    }

    /// Returns the page that should be compacted.
    fn choose_page_for_compact(&self) -> Option<usize> {
        // TODO(cretin): This could be optimized by using some cost function depending on:
        // - the erase count
        // - the length of the free space
        // - the length of the alive entries
        // We want to minimize this cost. We could also take into account the length of the entry we
        // want to write to bound the number of compaction before failing with StoreFull.
        //
        // We should also make sure that all pages (including if they have no deleted entries and no
        // free space) are eventually compacted (ideally to a heavily used page) to benefit from the
        // low erase count of those pages.
        (0..self.format.num_pages)
            .map(|page| (page, self.page_info(page)))
            .filter(|&(page, ref info)| {
                page != self.blank_page
                    && info.erase_count < self.format.max_page_erases
                    && info.deleted_length > self.format.internal_entry_size()
            })
            .min_by(|(_, lhs_info), (_, rhs_info)| lhs_info.compare_for_compaction(rhs_info))
            .map(|(page, _)| page)
    }

    fn page_info(&self, page: usize) -> PageInfo {
        let (page_header, mut index) = self.read_page_header(page);
        let mut info = PageInfo {
            erase_count: self.format.get_erase_count(page_header),
            deleted_length: 0,
            free_length: 0,
        };
        while index.byte < self.format.page_size {
            let entry = self.read_entry(index);
            index.byte += entry.len();
            if !self.format.is_present(entry) {
                debug_assert_eq!(info.free_length, 0);
                info.free_length = entry.len();
            } else if self.format.is_deleted(entry) {
                info.deleted_length += entry.len();
            }
        }
        debug_assert_eq!(index.page, page);
        info
    }

    fn read_slice(&self, index: Index, length: usize) -> &[u8] {
        self.storage.read_slice(index, length).unwrap()
    }

    /// Reads an entry (with header and footer) at a given index.
    ///
    /// If no entry is present, returns the free space up to the end of the page.
    fn read_entry(&self, index: Index) -> &[u8] {
        let first_byte = self.read_slice(index, 1);
        let max_length = self.format.page_size - index.byte;
        let mut length = if !self.format.is_present(first_byte) {
            max_length
        } else if self.format.is_internal(first_byte) {
            self.format.internal_entry_size()
        } else {
            // We don't know if the entry is sensitive or not, but it doesn't matter here. We just
            // need to read the replace, sensitive, and length fields.
            let header = self.read_slice(index, self.format.header_size(false));
            let replace = self.format.is_replace(header);
            let sensitive = self.format.is_sensitive(header);
            let length = self.format.get_length(header);
            self.format.entry_size(replace, sensitive, length)
        };
        // Truncate the length to fit the page. This can only happen in case of corruption or
        // partial writes.
        length = core::cmp::min(length, max_length);
        self.read_slice(index, length)
    }

    /// Reads a page header.
    ///
    /// Also returns the index after the page header.
    fn read_page_header(&self, page: usize) -> (&[u8], Index) {
        let mut index = Index { page, byte: 0 };
        let page_header = self.read_slice(index, self.format.page_header_size());
        index.byte += page_header.len();
        (page_header, index)
    }

    /// Updates a word at a given index.
    ///
    /// The `update` function is called with the word at `index`. The input value is the current
    /// value of the word. The output value is the value that will be written. It should only change
    /// bits from 1 to 0.
    fn update_word(&mut self, index: Index, update: impl FnOnce(&Format, &mut [u8])) {
        let word_size = self.format.word_size;
        let mut word = self.read_slice(index, word_size).to_vec();
        update(&self.format, &mut word);
        self.storage.write_slice(index, &word).unwrap();
    }

    fn write_entry(&mut self, index: Index, entry: &[u8]) {
        self.storage.write_slice(index, entry).unwrap();
    }

    /// Initializes a page by writing the page header.
    ///
    /// If the page is not erased, it is first erased.
    fn initialize_page(&mut self, page: usize, erase_count: usize) {
        let index = Index { page, byte: 0 };
        let page = self.read_slice(index, self.format.page_size);
        if !page.iter().all(|&byte| byte == 0xff) {
            self.storage.erase_page(index.page).unwrap();
        }
        self.update_word(index, |format, header| {
            format.set_initialized(header);
            format.set_erase_count(header, erase_count);
        });
        self.blank_page = index.page;
    }

    /// Commits a replace entry.
    ///
    /// Deletes the old entry and commits the new entry.
    fn commit_index(&mut self, mut index: Index) {
        let entry = self.read_entry(index);
        index.byte += entry.len();
        let word_size = self.format.word_size;
        debug_assert!(entry.len() >= 2 * word_size);
        match self.format.is_replace(entry) {
            IsReplace::Replace => {
                let delete_index = self.format.get_replace_index(entry);
                self.delete_index(delete_index);
            }
            IsReplace::Insert => debug_assert!(false),
        };
        index.byte -= word_size;
        self.update_word(index, |format, word| format.set_committed(word));
    }

    /// Compacts a page to an other.
    ///
    /// Returns the mapping from the alive entries in the old page to their index in the new page.
    fn compact_page(&mut self, old_page: usize, new_page: usize) -> BTreeMap<usize, usize> {
        // Write the old page as being compacted to the new page.
        let mut erase_count = 0;
        self.update_word(
            Index {
                page: old_page,
                byte: 0,
            },
            |format, header| {
                erase_count = format.get_erase_count(header);
                format.set_compacting(header);
                format.set_new_page(header, new_page);
            },
        );
        // Copy alive entries from the old page to the new page.
        let page_header_size = self.format.page_header_size();
        let mut old_index = Index {
            page: old_page,
            byte: page_header_size,
        };
        let mut new_index = Index {
            page: new_page,
            byte: page_header_size,
        };
        let mut map = BTreeMap::new();
        while old_index.byte < self.format.page_size {
            let old_entry = self.read_entry(old_index);
            let old_entry_index = old_index.byte;
            old_index.byte += old_entry.len();
            if !self.format.is_alive(old_entry) {
                continue;
            }
            let previous_mapping = map.insert(old_entry_index, new_index.byte);
            debug_assert!(previous_mapping.is_none());
            // We need to copy the old entry because it is in the storage and we are going to write
            // to the storage. Rust cannot tell that both entries don't overlap.
            let old_entry = old_entry.to_vec();
            self.write_entry(new_index, &old_entry);
            new_index.byte += old_entry.len();
        }
        // Save the old page index and erase count to the new page.
        let erase_index = new_index;
        let erase_entry = self.format.build_erase_entry(old_page, erase_count);
        self.write_entry(new_index, &erase_entry);
        // Erase the page.
        self.erase_page(erase_index);
        // Increase generation.
        self.generation += 1;
        map
    }

    /// Commits an internal entry.
    ///
    /// The only kind of internal entry is to erase a page, which first erases the page, then
    /// initializes it with the saved erase count, and finally deletes the internal entry.
    fn erase_page(&mut self, erase_index: Index) {
        let erase_entry = self.read_entry(erase_index);
        debug_assert!(self.format.is_present(erase_entry));
        debug_assert!(!self.format.is_deleted(erase_entry));
        debug_assert!(self.format.is_internal(erase_entry));
        let old_page = self.format.get_old_page(erase_entry);
        let erase_count = self.format.get_saved_erase_count(erase_entry) + 1;
        // Erase the page.
        self.storage.erase_page(old_page).unwrap();
        // Initialize the page.
        self.initialize_page(old_page, erase_count);
        // Delete the internal entry.
        self.delete_index(erase_index);
    }
}

// Those functions are not meant for production.
#[cfg(any(test, feature = "ram_storage"))]
impl<C: StoreConfig> Store<BufferStorage, C> {
    /// Takes a snapshot of the storage after a given amount of word operations.
    pub fn arm_snapshot(&mut self, delay: usize) {
        self.storage.arm_snapshot(delay);
    }

    /// Unarms and returns the snapshot or the delay remaining.
    pub fn get_snapshot(&mut self) -> Result<Box<[u8]>, usize> {
        self.storage.get_snapshot()
    }

    /// Takes a snapshot of the storage.
    pub fn take_snapshot(&self) -> Box<[u8]> {
        self.storage.take_snapshot()
    }

    /// Returns the storage.
    pub fn get_storage(self) -> Box<[u8]> {
        self.storage.get_storage()
    }

    /// Erases and initializes a page with a given erase count.
    pub fn set_erase_count(&mut self, page: usize, erase_count: usize) {
        self.initialize_page(page, erase_count);
    }

    /// Returns whether all deleted sensitive entries have been wiped.
    pub fn deleted_entries_are_wiped(&self) -> bool {
        for (_, entry) in Iter::new(self) {
            if !self.format.is_present(entry)
                || !self.format.is_deleted(entry)
                || self.format.is_internal(entry)
                || !self.format.is_sensitive(entry)
            {
                continue;
            }
            let gap = self.format.entry_gap(entry);
            let data = gap.slice(entry);
            if !data.iter().all(|&byte| byte == 0x00) {
                return false;
            }
        }
        true
    }
}

/// Maps an index from an old page to a new page if needed.
fn map_index(old_page: usize, new_page: usize, map: &BTreeMap<usize, usize>, index: &mut Index) {
    if index.page == old_page {
        index.page = new_page;
        index.byte = *map.get(&index.byte).unwrap();
    }
}

/// Page information for compaction.
struct PageInfo {
    /// How many times the page was erased.
    erase_count: usize,

    /// Cumulative length of deleted entries (including header and footer).
    deleted_length: usize,

    /// Length of the free space.
    free_length: usize,
}

impl PageInfo {
    /// Returns whether a page should be compacted before another.
    fn compare_for_compaction(&self, rhs: &PageInfo) -> core::cmp::Ordering {
        self.erase_count
            .cmp(&rhs.erase_count)
            .then(rhs.deleted_length.cmp(&self.deleted_length))
            .then(self.free_length.cmp(&rhs.free_length))
    }
}

/// Iterates over all entries (including free space) of a store.
struct Iter<'a, S: Storage, C: StoreConfig> {
    store: &'a Store<S, C>,
    index: Index,
}

impl<'a, S: Storage, C: StoreConfig> Iter<'a, S, C> {
    fn new(store: &'a Store<S, C>) -> Iter<'a, S, C> {
        let index = Index {
            page: 0,
            byte: store.format.page_header_size(),
        };
        Iter { store, index }
    }
}

impl<'a, S: Storage, C: StoreConfig> Iterator for Iter<'a, S, C> {
    type Item = (Index, &'a [u8]);

    fn next(&mut self) -> Option<(Index, &'a [u8])> {
        if self.index.byte == self.store.format.page_size {
            self.index.page += 1;
            self.index.byte = self.store.format.page_header_size();
        }
        if self.index.page == self.store.format.num_pages {
            return None;
        }
        let index = self.index;
        let entry = self.store.read_entry(self.index);
        self.index.byte += entry.len();
        Some((index, entry))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BufferOptions, BufferStorage};
    use super::*;

    struct Config;

    const WORD_SIZE: usize = 4;
    const PAGE_SIZE: usize = 8 * WORD_SIZE;
    const NUM_PAGES: usize = 3;

    impl StoreConfig for Config {
        type Key = u8;

        fn num_tags(&self) -> usize {
            1
        }

        fn keys(&self, entry: StoreEntry, mut add: impl FnMut(u8)) {
            assert_eq!(entry.tag, 0);
            if !entry.data.is_empty() {
                add(entry.data[0]);
            }
        }
    }

    fn new_buffer(storage: Box<[u8]>) -> BufferStorage {
        let options = BufferOptions {
            word_size: WORD_SIZE,
            page_size: PAGE_SIZE,
            max_word_writes: 2,
            max_page_erases: 2,
            strict_write: true,
        };
        BufferStorage::new(storage, options)
    }

    fn new_store() -> Store<BufferStorage, Config> {
        let storage = vec![0xff; NUM_PAGES * PAGE_SIZE].into_boxed_slice();
        Store::new(new_buffer(storage), Config).unwrap()
    }

    #[test]
    fn insert_ok() {
        let mut store = new_store();
        assert_eq!(store.iter().count(), 0);
        let tag = 0;
        let key = 1;
        let data = &[key, 2];
        let entry = StoreEntry {
            tag,
            data,
            sensitive: false,
        };
        store.insert(entry).unwrap();
        assert_eq!(store.iter().count(), 1);
        assert_eq!(store.find_one(&key).unwrap().1, entry);
    }

    #[test]
    fn insert_sensitive_ok() {
        let mut store = new_store();
        let tag = 0;
        let key = 1;
        let data = &[key, 4];
        let entry = StoreEntry {
            tag,
            data,
            sensitive: true,
        };
        store.insert(entry).unwrap();
        assert_eq!(store.iter().count(), 1);
        assert_eq!(store.find_one(&key).unwrap().1, entry);
    }

    #[test]
    fn delete_ok() {
        let mut store = new_store();
        let tag = 0;
        let key = 1;
        let entry = StoreEntry {
            tag,
            data: &[key, 2],
            sensitive: false,
        };
        store.insert(entry).unwrap();
        assert_eq!(store.find_all(&key).count(), 1);
        let (index, _) = store.find_one(&key).unwrap();
        store.delete(index).unwrap();
        assert_eq!(store.find_all(&key).count(), 0);
        assert_eq!(store.iter().count(), 0);
    }

    #[test]
    fn delete_sensitive_ok() {
        let mut store = new_store();
        let tag = 0;
        let key = 1;
        let entry = StoreEntry {
            tag,
            data: &[key, 2],
            sensitive: true,
        };
        store.insert(entry).unwrap();
        assert_eq!(store.find_all(&key).count(), 1);
        let (index, _) = store.find_one(&key).unwrap();
        store.delete(index).unwrap();
        assert_eq!(store.find_all(&key).count(), 0);
        assert_eq!(store.iter().count(), 0);
        assert!(store.deleted_entries_are_wiped());
    }

    #[test]
    fn insert_until_full() {
        let mut store = new_store();
        let tag = 0;
        let mut key = 0;
        while store
            .insert(StoreEntry {
                tag,
                data: &[key, 0],
                sensitive: false,
            })
            .is_ok()
        {
            key += 1;
        }
        assert!(key > 0);
    }

    #[test]
    fn compact_ok() {
        let mut store = new_store();
        let tag = 0;
        let mut key = 0;
        while store
            .insert(StoreEntry {
                tag,
                data: &[key, 0],
                sensitive: false,
            })
            .is_ok()
        {
            key += 1;
        }
        let (index, _) = store.find_one(&0).unwrap();
        store.delete(index).unwrap();
        store
            .insert(StoreEntry {
                tag: 0,
                data: &[key, 0],
                sensitive: false,
            })
            .unwrap();
        for k in 1..=key {
            assert_eq!(store.find_all(&k).count(), 1);
        }
    }

    #[test]
    fn reboot_ok() {
        let mut store = new_store();
        let tag = 0;
        let key = 1;
        let data = &[key, 2];
        let entry = StoreEntry {
            tag,
            data,
            sensitive: false,
        };
        store.insert(entry).unwrap();

        // Reboot the store.
        let store = store.get_storage();
        let store = Store::new(new_buffer(store), Config).unwrap();

        assert_eq!(store.iter().count(), 1);
        assert_eq!(store.find_one(&key).unwrap().1, entry);
    }

    #[test]
    fn replace_atomic() {
        let tag = 0;
        let key = 1;
        let old_entry = StoreEntry {
            tag,
            data: &[key, 2, 3, 4, 5, 6],
            sensitive: false,
        };
        let new_entry = StoreEntry {
            tag,
            data: &[key, 7, 8, 9],
            sensitive: false,
        };
        let mut delay = 0;
        loop {
            let mut store = new_store();
            store.insert(old_entry).unwrap();
            store.arm_snapshot(delay);
            let (index, _) = store.find_one(&key).unwrap();
            store.replace(index, new_entry).unwrap();
            let (complete, store) = match store.get_snapshot() {
                Err(_) => (true, store.get_storage()),
                Ok(store) => (false, store),
            };
            let store = Store::new(new_buffer(store), Config).unwrap();
            assert_eq!(store.iter().count(), 1);
            assert_eq!(store.find_all(&key).count(), 1);
            let (_, cur_entry) = store.find_one(&key).unwrap();
            assert!((cur_entry == old_entry && !complete) || cur_entry == new_entry);
            if complete {
                break;
            }
            delay += 1;
        }
    }

    #[test]
    fn compact_atomic() {
        let tag = 0;
        let mut delay = 0;
        loop {
            let mut store = new_store();
            let mut key = 0;
            while store
                .insert(StoreEntry {
                    tag,
                    data: &[key, 0],
                    sensitive: false,
                })
                .is_ok()
            {
                key += 1;
            }
            let (index, _) = store.find_one(&0).unwrap();
            store.delete(index).unwrap();
            let (index, _) = store.find_one(&1).unwrap();
            store.arm_snapshot(delay);
            store
                .replace(
                    index,
                    StoreEntry {
                        tag,
                        data: &[1, 1],
                        sensitive: false,
                    },
                )
                .unwrap();
            let (complete, store) = match store.get_snapshot() {
                Err(_) => (true, store.get_storage()),
                Ok(store) => (false, store),
            };
            let store = Store::new(new_buffer(store), Config).unwrap();
            assert_eq!(store.iter().count(), key as usize - 1);
            for k in 2..key {
                assert_eq!(store.find_all(&k).count(), 1);
                assert_eq!(
                    store.find_one(&k).unwrap().1,
                    StoreEntry {
                        tag,
                        data: &[k, 0],
                        sensitive: false,
                    }
                );
            }
            assert_eq!(store.find_all(&1).count(), 1);
            let (_, entry) = store.find_one(&1).unwrap();
            assert_eq!(entry.tag, tag);
            assert!((entry.data == [1, 0] && !complete) || entry.data == [1, 1]);
            if complete {
                break;
            }
            delay += 1;
        }
    }

    #[test]
    fn invalid_tag() {
        let mut store = new_store();
        let entry = StoreEntry {
            tag: 1,
            data: &[],
            sensitive: false,
        };
        assert_eq!(store.insert(entry), Err(StoreError::InvalidTag));
    }

    #[test]
    fn invalid_length() {
        let mut store = new_store();
        let entry = StoreEntry {
            tag: 0,
            data: &[0; PAGE_SIZE],
            sensitive: false,
        };
        assert_eq!(store.insert(entry), Err(StoreError::StoreFull));
    }
}
