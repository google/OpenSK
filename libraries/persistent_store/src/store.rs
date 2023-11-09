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

//! Store implementation.

use crate::format::{
    is_erased, CompactInfo, Format, Header, InitInfo, InternalEntry, Padding, ParsedWord, Position,
    Word, WordState,
};
#[cfg(feature = "std")]
pub use crate::model::StoreOperation;
#[cfg(feature = "std")]
pub use crate::BufferStorage;
use crate::{usize_to_nat, Nat, Storage, StorageError, StorageIndex};
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::cmp::{max, min, Ordering};
use core::convert::TryFrom;
#[cfg(feature = "std")]
use std::collections::HashSet;

/// Errors returned by store operations.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// Invalid argument.
    ///
    /// The store is left unchanged. The operation will repeatedly fail until the argument is fixed.
    InvalidArgument,

    /// Not enough capacity.
    ///
    /// The store is left unchanged. The operation will repeatedly fail until capacity is freed.
    NoCapacity,

    /// Reached end of lifetime.
    ///
    /// The store is left unchanged. The operation will repeatedly fail until emergency lifetime is
    /// added.
    NoLifetime,

    /// A storage operation failed.
    ///
    /// The consequences depend on the storage failure. In particular, the operation may or may not
    /// have succeeded, and the storage may have become invalid. Before doing any other operation,
    /// the store should be [recovered](Store::recover). The operation may then be retried if
    /// idempotent.
    StorageError,

    /// Storage is invalid.
    ///
    /// The storage should be erased and the store [recovered](Store::recover). The store would be
    /// empty and have lost track of lifetime.
    InvalidStorage,
}

impl From<StorageError> for StoreError {
    fn from(error: StorageError) -> StoreError {
        match error {
            StorageError::CustomError => StoreError::StorageError,
            // The store always calls the storage correctly.
            StorageError::NotAligned | StorageError::OutOfBounds => unreachable!(),
        }
    }
}

/// Result of store operations.
pub type StoreResult<T> = Result<T, StoreError>;

/// Converts an Option into a StoreResult.
///
/// The None case is considered invalid and returns [`StoreError::InvalidStorage`].
fn or_invalid<T>(x: Option<T>) -> StoreResult<T> {
    x.ok_or(StoreError::InvalidStorage)
}

/// Progression ratio for store metrics.
///
/// This is used for the [`Store::capacity`] and [`Store::lifetime`] metrics. Those metrics are
/// measured in words.
///
/// # Invariant
///
/// - The used value does not exceed the total: `used` ≤ `total`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StoreRatio {
    /// How much of the metric is used.
    pub(crate) used: Nat,

    /// How much of the metric can be used at most.
    pub(crate) total: Nat,
}

impl StoreRatio {
    /// How much of the metric is used.
    pub fn used(self) -> usize {
        self.used as usize
    }

    /// How much of the metric can be used at most.
    pub fn total(self) -> usize {
        self.total as usize
    }

    /// How much of the metric is remaining.
    pub fn remaining(self) -> usize {
        (self.total - self.used) as usize
    }
}

/// Safe pointer to an entry.
///
/// A store handle stays valid at least until the next mutable operation. Store operations taking a
/// handle as argument always verify that the handle is still valid.
#[derive(Clone, Debug)]
pub struct StoreHandle {
    /// The key of the entry.
    key: Nat,

    /// The position of the entry.
    pos: Position,

    /// The length in bytes of the value.
    len: Nat,
}

impl StoreHandle {
    /// Returns the key of the entry.
    pub fn get_key(&self) -> usize {
        self.key as usize
    }

    /// Returns the value length of the entry.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidArgument`] if the entry has been deleted or compacted.
    pub fn get_length<S: Storage>(&self, store: &Store<S>) -> StoreResult<usize> {
        store.get_length(self)
    }

    /// Returns the value of the entry.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidArgument`] if the entry has been deleted or compacted.
    pub fn get_value<S: Storage>(&self, store: &Store<S>) -> StoreResult<Vec<u8>> {
        store.get_value(self)
    }
}

/// Represents an update to the store as part of a transaction.
#[derive(Clone, Debug)]
pub enum StoreUpdate<ByteSlice: Borrow<[u8]>> {
    /// Inserts or replaces an entry in the store.
    Insert { key: usize, value: ByteSlice },

    /// Removes an entry from the store.
    Remove { key: usize },
}

impl<ByteSlice: Borrow<[u8]>> StoreUpdate<ByteSlice> {
    /// Returns the key affected by the update.
    pub fn key(&self) -> usize {
        match *self {
            StoreUpdate::Insert { key, .. } => key,
            StoreUpdate::Remove { key } => key,
        }
    }

    /// Returns the value written by the update.
    pub fn value(&self) -> Option<&[u8]> {
        match self {
            StoreUpdate::Insert { value, .. } => Some(value.borrow()),
            StoreUpdate::Remove { .. } => None,
        }
    }
}

pub type StoreIter<'a> = Box<dyn Iterator<Item = StoreResult<StoreHandle>> + 'a>;

/// Implements a store with a map interface over a storage.
#[derive(Clone)]
pub struct Store<S: Storage> {
    /// The underlying storage.
    storage: S,

    /// The storage configuration.
    format: Format,

    /// The position of the first word in the store.
    head: Option<Position>,

    /// The list of the position of the user entries.
    ///
    /// The position is encoded as the word offset from the [head](Store::head).
    entries: Option<Vec<u16>>,
}

impl<S: Storage> Store<S> {
    /// Resumes or initializes a store for a given storage.
    ///
    /// If the storage is completely erased, it is initialized. Otherwise, a possible interrupted
    /// operation is recovered by being either completed or rolled-back. In case of error, the
    /// storage ownership is returned.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidArgument`] if the storage is not
    /// [supported](Format::is_storage_supported).
    pub fn new(storage: S) -> Result<Store<S>, (StoreError, S)> {
        let format = match Format::new(&storage) {
            None => return Err((StoreError::InvalidArgument, storage)),
            Some(x) => x,
        };
        let mut store = Store {
            storage,
            format,
            head: None,
            entries: None,
        };
        if let Err(error) = store.recover() {
            return Err((error, store.storage));
        }
        Ok(store)
    }

    /// Extracts the storage.
    pub fn extract_storage(self) -> S {
        self.storage
    }

    /// Iterates over the entries.
    pub fn iter(&self) -> StoreResult<StoreIter<'_>> {
        let head = or_invalid(self.head)?;
        Ok(Box::new(or_invalid(self.entries.as_ref())?.iter().map(
            move |&offset| {
                let pos = head + offset as Nat;
                match self.parse_entry(&mut pos.clone())? {
                    ParsedEntry::User(Header {
                        key, length: len, ..
                    }) => Ok(StoreHandle { key, pos, len }),
                    _ => Err(StoreError::InvalidStorage),
                }
            },
        )))
    }

    /// Returns the current and total capacity in words.
    ///
    /// The capacity represents the size of what is stored.
    pub fn capacity(&self) -> StoreResult<StoreRatio> {
        let total = self.format.total_capacity();
        let mut used = 0;
        for handle in self.iter()? {
            let handle = handle?;
            used += 1 + self.format.bytes_to_words(handle.len);
        }
        Ok(StoreRatio { used, total })
    }

    /// Returns the current and total lifetime in words.
    ///
    /// The lifetime represents the age of the storage. The limit is an over-approximation by at
    /// most the maximum length of a value (the actual limit depends on the length of the prefix of
    /// the first physical page once all its erase cycles have been used).
    pub fn lifetime(&self) -> StoreResult<StoreRatio> {
        let total = self.format.total_lifetime().get();
        let used = self.tail()?.get();
        Ok(StoreRatio { used, total })
    }

    /// Applies a sequence of updates as a single transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidArgument`] in the following circumstances:
    /// - There are [too many](Format::max_updates) updates.
    /// - The updates overlap, i.e. their keys are not disjoint.
    /// - The updates are invalid, e.g. key [out of bound](Format::max_key) or value [too
    ///   long](Format::max_value_len).
    pub fn transaction<ByteSlice: Borrow<[u8]>>(
        &mut self,
        updates: &[StoreUpdate<ByteSlice>],
    ) -> StoreResult<()> {
        let count = usize_to_nat(updates.len());
        if count == 0 {
            return Ok(());
        }
        if count == 1 {
            match updates[0] {
                StoreUpdate::Insert { key, ref value } => return self.insert(key, value.borrow()),
                StoreUpdate::Remove { key } => return self.remove(key),
            }
        }
        // Get the sorted keys. Fail if the transaction is invalid.
        let sorted_keys = match self.format.transaction_valid(updates) {
            None => return Err(StoreError::InvalidArgument),
            Some(x) => x,
        };
        // Reserve the capacity.
        self.reserve(self.format.transaction_capacity(updates))?;
        // Write the marker entry.
        let marker = self.tail()?;
        let entry = self
            .format
            .build_internal(InternalEntry::Marker { count })?;
        self.write_slice(marker, &entry)?;
        self.init_page(marker, marker)?;
        // Write the updates.
        let mut tail = marker + 1;
        for update in updates {
            let length = match *update {
                StoreUpdate::Insert { key, ref value } => {
                    let entry = self.format.build_user(usize_to_nat(key), value.borrow())?;
                    let word_size = self.format.word_size();
                    let footer = usize_to_nat(entry.len()) / word_size - 1;
                    self.write_slice(tail, &entry[..(footer * word_size) as usize])?;
                    self.write_slice(tail + footer, &entry[(footer * word_size) as usize..])?;
                    footer
                }
                StoreUpdate::Remove { key } => {
                    let key = usize_to_nat(key);
                    let remove = self.format.build_internal(InternalEntry::Remove { key })?;
                    self.write_slice(tail, &remove)?;
                    0
                }
            };
            self.init_page(tail, tail + length)?;
            tail += 1 + length;
        }
        // Apply the transaction.
        self.transaction_apply(&sorted_keys, marker)
    }

    /// Removes multiple entries as part of a single transaction.
    ///
    /// Entries with a key larger or equal to `min_key` are deleted.
    pub fn clear(&mut self, min_key: usize) -> StoreResult<()> {
        let min_key = usize_to_nat(min_key);
        if min_key > self.format.max_key() {
            return Err(StoreError::InvalidArgument);
        }
        let clear = self
            .format
            .build_internal(InternalEntry::Clear { min_key })?;
        // We always have one word available. We can't use `reserve` because this is internal
        // capacity, not user capacity.
        while self.immediate_capacity()? < 1 {
            self.compact()?;
        }
        let tail = self.tail()?;
        self.write_slice(tail, &clear)?;
        self.clear_delete(tail)
    }

    /// Compacts the store once if needed.
    ///
    /// If the immediate capacity is at least `length` words, then nothing is modified. Otherwise,
    /// one page is compacted.
    pub fn prepare(&mut self, length: usize) -> Result<(), StoreError> {
        if self.capacity()?.remaining() < length {
            return Err(StoreError::NoCapacity);
        }
        if self.immediate_capacity()? < usize_to_nat(length) {
            self.compact()?;
        }
        Ok(())
    }

    /// Recovers a possible interrupted operation.
    ///
    /// If the storage is completely erased, it is initialized.
    pub fn recover(&mut self) -> StoreResult<()> {
        self.recover_initialize()?;
        self.recover_erase()?;
        self.recover_compaction()?;
        self.recover_operation()?;
        Ok(())
    }

    /// Returns the value of an entry given its key.
    pub fn find(&self, key: usize) -> StoreResult<Option<Vec<u8>>> {
        Ok(match self.find_handle(key)? {
            None => None,
            Some(handle) => Some(self.get_value(&handle)?),
        })
    }

    /// Returns a handle to an entry given its key.
    pub fn find_handle(&self, key: usize) -> StoreResult<Option<StoreHandle>> {
        let key = usize_to_nat(key);
        for handle in self.iter()? {
            let handle = handle?;
            if handle.key == key {
                return Ok(Some(handle));
            }
        }
        Ok(None)
    }

    /// Inserts an entry in the store.
    ///
    /// If an entry for the same key is already present, it is replaced.
    pub fn insert(&mut self, key: usize, value: &[u8]) -> StoreResult<()> {
        // NOTE: This (and transaction) could take a position hint on the value to delete.
        let key = usize_to_nat(key);
        let value_len = usize_to_nat(value.len());
        if key > self.format.max_key() || value_len > self.format.max_value_len() {
            return Err(StoreError::InvalidArgument);
        }
        let entry = self.format.build_user(key, value)?;
        let entry_len = usize_to_nat(entry.len());
        self.reserve(entry_len / self.format.word_size())?;
        let tail = self.tail()?;
        let word_size = self.format.word_size();
        let footer = entry_len / word_size - 1;
        self.write_slice(tail, &entry[..(footer * word_size) as usize])?;
        self.write_slice(tail + footer, &entry[(footer * word_size) as usize..])?;
        self.push_entry(tail)?;
        self.insert_init(tail, footer, key)
    }

    /// Removes an entry given its key.
    ///
    /// This is not an error if there is no entry for this key.
    pub fn remove(&mut self, key: usize) -> StoreResult<()> {
        let key = usize_to_nat(key);
        if key > self.format.max_key() {
            return Err(StoreError::InvalidArgument);
        }
        self.delete_keys(&[key], self.tail()?)
    }

    /// Removes an entry given a handle.
    pub fn remove_handle(&mut self, handle: &StoreHandle) -> StoreResult<()> {
        self.check_handle(handle)?;
        self.delete_pos(handle.pos, self.format.bytes_to_words(handle.len))?;
        self.remove_entry(handle.pos)
    }

    /// Returns the maximum length in bytes of a value.
    pub fn max_value_length(&self) -> usize {
        self.format.max_value_len() as usize
    }

    /// Returns the length of the value of an entry given its handle.
    fn get_length(&self, handle: &StoreHandle) -> StoreResult<usize> {
        self.check_handle(handle)?;
        let mut pos = handle.pos;
        match self.parse_entry(&mut pos)? {
            ParsedEntry::User(header) => Ok(header.length as usize),
            ParsedEntry::Padding => Err(StoreError::InvalidArgument),
            _ => Err(StoreError::InvalidStorage),
        }
    }

    /// Returns the value of an entry given its handle.
    fn get_value(&self, handle: &StoreHandle) -> StoreResult<Vec<u8>> {
        self.check_handle(handle)?;
        let mut pos = handle.pos;
        match self.parse_entry(&mut pos)? {
            ParsedEntry::User(header) => {
                let mut result = self.read_slice(handle.pos + 1, header.length);
                if header.flipped {
                    let last_byte = result.len() - 1;
                    result[last_byte] = 0xff;
                }
                Ok(result)
            }
            ParsedEntry::Padding => Err(StoreError::InvalidArgument),
            _ => Err(StoreError::InvalidStorage),
        }
    }

    /// Initializes the storage if completely erased or partially initialized.
    fn recover_initialize(&mut self) -> StoreResult<()> {
        let word_size = self.format.word_size();
        for page in 0..self.format.num_pages() {
            let content = self.read_page(page);
            let (init, rest) = content.split_at(word_size as usize);
            if (page > 0 && !is_erased(init)) || !is_erased(rest) {
                return Ok(());
            }
        }
        let index = self.format.index_init(0);
        let init_info = self.format.build_init(InitInfo {
            cycle: 0,
            prefix: 0,
        })?;
        self.storage_write_slice(index, &init_info)
    }

    /// Recovers a possible compaction interrupted while erasing the page.
    fn recover_erase(&mut self) -> StoreResult<()> {
        let mut pos = self.get_extremum_page_head(Ordering::Greater)?;
        let end = pos.next_page(&self.format);
        while pos < end {
            let entry_pos = pos;
            match self.parse_entry(&mut pos)? {
                ParsedEntry::Internal(InternalEntry::Erase { .. }) => {
                    return self.compact_erase(entry_pos)
                }
                ParsedEntry::Padding | ParsedEntry::User(_) => (),
                _ => break,
            }
        }
        Ok(())
    }

    /// Recovers a possible compaction interrupted while copying the entries.
    fn recover_compaction(&mut self) -> StoreResult<()> {
        let head = self.get_extremum_page_head(Ordering::Less)?;
        self.head = Some(head);
        let head_page = head.page(&self.format);
        match self.parse_compact(head_page)? {
            WordState::Erased => Ok(()),
            WordState::Partial => self.compact(),
            WordState::Valid(_) => self.compact_copy(),
        }
    }

    /// Recover a possible interrupted operation which is not a compaction.
    fn recover_operation(&mut self) -> StoreResult<()> {
        self.entries = Some(Vec::new());
        let mut pos = or_invalid(self.head)?;
        let mut prev_pos = pos;
        let end = pos + self.format.window_size();
        while pos < end {
            let entry_pos = pos;
            match self.parse_entry(&mut pos)? {
                ParsedEntry::Tail => break,
                ParsedEntry::User(_) => self.push_entry(entry_pos)?,
                ParsedEntry::Padding => {
                    self.wipe_span(entry_pos + 1, pos - entry_pos - 1)?;
                }
                ParsedEntry::Internal(InternalEntry::Erase { .. }) => {
                    return Err(StoreError::InvalidStorage);
                }
                ParsedEntry::Internal(InternalEntry::Clear { .. }) => {
                    return self.clear_delete(entry_pos);
                }
                ParsedEntry::Internal(InternalEntry::Marker { .. }) => {
                    return self.recover_transaction(entry_pos, end);
                }
                ParsedEntry::Internal(InternalEntry::Remove { .. }) => {
                    self.set_padding(entry_pos)?;
                }
                ParsedEntry::Partial => {
                    return self.recover_wipe_partial(entry_pos, pos - entry_pos - 1);
                }
                ParsedEntry::PartialUser => {
                    return self.recover_delete_user(entry_pos, pos - entry_pos - 1);
                }
            }
            prev_pos = entry_pos;
        }
        pos = prev_pos;
        if let ParsedEntry::User(header) = self.parse_entry(&mut pos)? {
            self.insert_init(prev_pos, pos - prev_pos - 1, header.key)?;
        }
        Ok(())
    }

    /// Recovers a possible interrupted transaction.
    fn recover_transaction(&mut self, marker: Position, end: Position) -> StoreResult<()> {
        let mut pos = marker;
        let count = match self.parse_entry(&mut pos)? {
            ParsedEntry::Internal(InternalEntry::Marker { count }) => count,
            _ => return Err(StoreError::InvalidStorage),
        };
        let sorted_keys = self.recover_transaction_keys(count, pos, end)?;
        match usize_to_nat(sorted_keys.len()).cmp(&count) {
            Ordering::Less => (),
            Ordering::Equal => return self.transaction_apply(&sorted_keys, marker),
            Ordering::Greater => return Err(StoreError::InvalidStorage),
        }
        while pos < end {
            let entry_pos = pos;
            match self.parse_entry(&mut pos)? {
                ParsedEntry::Tail => break,
                ParsedEntry::Padding => (),
                ParsedEntry::User(_) => {
                    self.delete_pos(entry_pos, pos - entry_pos - 1)?;
                }
                ParsedEntry::Internal(InternalEntry::Remove { .. }) => {
                    self.set_padding(entry_pos)?;
                }
                ParsedEntry::Partial => {
                    self.recover_wipe_partial(entry_pos, pos - entry_pos - 1)?;
                    break;
                }
                ParsedEntry::PartialUser => {
                    self.recover_delete_user(entry_pos, pos - entry_pos - 1)?;
                    break;
                }
                ParsedEntry::Internal(InternalEntry::Erase { .. })
                | ParsedEntry::Internal(InternalEntry::Clear { .. })
                | ParsedEntry::Internal(InternalEntry::Marker { .. }) => {
                    return Err(StoreError::InvalidStorage);
                }
            }
        }
        self.init_page(marker, marker)?;
        self.set_padding(marker)?;
        Ok(())
    }

    /// Returns the domain of a possible interrupted transaction.
    ///
    /// The domain is returned as a sorted list of keys.
    fn recover_transaction_keys(
        &mut self,
        count: Nat,
        mut pos: Position,
        end: Position,
    ) -> StoreResult<Vec<Nat>> {
        let mut sorted_keys = Vec::with_capacity(count as usize);
        let mut prev_pos = pos;
        while pos < end {
            let entry_pos = pos;
            let key = match self.parse_entry(&mut pos)? {
                ParsedEntry::Tail
                | ParsedEntry::Padding
                | ParsedEntry::Partial
                | ParsedEntry::PartialUser => break,
                ParsedEntry::User(header) => header.key,
                ParsedEntry::Internal(InternalEntry::Remove { key }) => key,
                ParsedEntry::Internal(_) => return Err(StoreError::InvalidStorage),
            };
            match sorted_keys.binary_search(&key) {
                Ok(_) => return Err(StoreError::InvalidStorage),
                Err(pos) => sorted_keys.insert(pos, key),
            }
            prev_pos = entry_pos;
        }
        pos = prev_pos;
        match self.parse_entry(&mut pos)? {
            ParsedEntry::User(_) | ParsedEntry::Internal(InternalEntry::Remove { .. }) => {
                let length = pos - prev_pos - 1;
                self.init_page(prev_pos, prev_pos + length)?;
            }
            _ => (),
        }
        Ok(sorted_keys)
    }

    /// Completes a possible partial entry wipe.
    fn recover_wipe_partial(&mut self, pos: Position, length: Nat) -> StoreResult<()> {
        self.wipe_span(pos + 1, length)?;
        self.init_page(pos, pos + length)?;
        self.set_padding(pos)?;
        Ok(())
    }

    /// Completes a possible partial entry deletion.
    fn recover_delete_user(&mut self, pos: Position, length: Nat) -> StoreResult<()> {
        self.init_page(pos, pos + length)?;
        self.delete_pos(pos, length)
    }

    /// Checks that a handle still points in the current window.
    ///
    /// In particular, the handle has not been compacted.
    fn check_handle(&self, handle: &StoreHandle) -> StoreResult<()> {
        if handle.pos < or_invalid(self.head)? {
            Err(StoreError::InvalidArgument)
        } else {
            Ok(())
        }
    }

    /// Compacts the store as needed.
    ///
    /// If there is at least `length` words of remaining capacity, pages are compacted until that
    /// amount is immediately available.
    fn reserve(&mut self, length: Nat) -> Result<(), StoreError> {
        if self.capacity()?.remaining() < length as usize {
            return Err(StoreError::NoCapacity);
        }
        while self.immediate_capacity()? < length {
            self.compact()?;
        }
        Ok(())
    }

    /// Continues an entry insertion after it has been written.
    fn insert_init(&mut self, pos: Position, length: Nat, key: Nat) -> StoreResult<()> {
        self.init_page(pos, pos + length)?;
        self.delete_keys(&[key], pos)?;
        Ok(())
    }

    /// Compacts one page.
    fn compact(&mut self) -> StoreResult<()> {
        let head = or_invalid(self.head)?;
        if head.cycle(&self.format) >= self.format.max_page_erases() {
            return Err(StoreError::NoLifetime);
        }
        let tail = max(self.tail()?, head.next_page(&self.format));
        let index = self.format.index_compact(head.page(&self.format));
        let compact_info = self
            .format
            .build_compact(CompactInfo { tail: tail - head })?;
        self.storage_write_slice(index, &compact_info)?;
        self.compact_copy()
    }

    /// Continues a compaction after its compact page info has been written.
    fn compact_copy(&mut self) -> StoreResult<()> {
        let mut head = or_invalid(self.head)?;
        let page = head.page(&self.format);
        let end = head.next_page(&self.format);
        let mut tail = match self.parse_compact(page)? {
            WordState::Valid(CompactInfo { tail }) => head + tail,
            _ => return Err(StoreError::InvalidStorage),
        };
        if tail < end {
            return Err(StoreError::InvalidStorage);
        }
        while head < end {
            let pos = head;
            match self.parse_entry(&mut head)? {
                ParsedEntry::Tail => break,
                // This can happen if we copy to the next page. We actually reached the tail but we
                // read what we just copied.
                ParsedEntry::Partial if head > end => break,
                ParsedEntry::User(_) => (),
                ParsedEntry::Padding => continue,
                _ => return Err(StoreError::InvalidStorage),
            };
            let length = head - pos;
            // We have to copy the slice for 2 reasons:
            // 1. We would need to work around the lifetime. This is possible using unsafe.
            // 2. We can't pass a flash slice to the kernel. This should get fixed with
            //    https://github.com/tock/tock/issues/1274.
            let entry = self.read_slice(pos, length * self.format.word_size());
            self.remove_entry(pos)?;
            self.write_slice(tail, &entry)?;
            self.push_entry(tail)?;
            self.init_page(tail, tail + (length - 1))?;
            tail += length;
        }
        let erase = self.format.build_internal(InternalEntry::Erase { page })?;
        self.write_slice(tail, &erase)?;
        self.init_page(tail, tail)?;
        self.compact_erase(tail)
    }

    /// Continues a compaction after its erase entry has been written.
    fn compact_erase(&mut self, erase: Position) -> StoreResult<()> {
        // Read the page to erase from the erase entry.
        let mut page = match self.parse_entry(&mut erase.clone())? {
            ParsedEntry::Internal(InternalEntry::Erase { page }) => page,
            _ => return Err(StoreError::InvalidStorage),
        };
        // Erase the page.
        self.storage_erase_page(page)?;
        // Update the head.
        page = (page + 1) % self.format.num_pages();
        let init = match self.parse_init(page)? {
            WordState::Valid(x) => x,
            _ => return Err(StoreError::InvalidStorage),
        };
        let head = self.format.page_head(init, page);
        if let Some(entries) = &mut self.entries {
            let head_offset = or_invalid(u16::try_from(head - or_invalid(self.head)?).ok())?;
            for entry in entries {
                *entry = or_invalid(entry.checked_sub(head_offset))?;
            }
        }
        self.head = Some(head);
        // Wipe the overlapping entry from the erased page.
        let pos = head.page_begin(&self.format);
        self.wipe_span(pos, head - pos)?;
        // Mark the erase entry as done.
        self.set_padding(erase)?;
        Ok(())
    }

    /// Continues a transaction after it has been written.
    fn transaction_apply(&mut self, sorted_keys: &[Nat], marker: Position) -> StoreResult<()> {
        self.delete_keys(sorted_keys, marker)?;
        self.set_padding(marker)?;
        let end = or_invalid(self.head)? + self.format.window_size();
        let mut pos = marker + 1;
        while pos < end {
            let entry_pos = pos;
            match self.parse_entry(&mut pos)? {
                ParsedEntry::Tail => break,
                ParsedEntry::User(_) => self.push_entry(entry_pos)?,
                ParsedEntry::Internal(InternalEntry::Remove { .. }) => {
                    self.set_padding(entry_pos)?
                }
                _ => return Err(StoreError::InvalidStorage),
            }
        }
        Ok(())
    }

    /// Continues a clear operation after its internal entry has been written.
    fn clear_delete(&mut self, clear: Position) -> StoreResult<()> {
        self.init_page(clear, clear)?;
        let min_key = match self.parse_entry(&mut clear.clone())? {
            ParsedEntry::Internal(InternalEntry::Clear { min_key }) => min_key,
            _ => return Err(StoreError::InvalidStorage),
        };
        self.delete_if(clear, |key| key >= min_key)?;
        self.set_padding(clear)?;
        Ok(())
    }

    /// Deletes a set of entries up to a certain position.
    fn delete_keys(&mut self, sorted_keys: &[Nat], end: Position) -> StoreResult<()> {
        self.delete_if(end, |key| sorted_keys.binary_search(&key).is_ok())
    }

    /// Deletes entries matching a predicate up to a certain position.
    fn delete_if(&mut self, end: Position, delete: impl Fn(Nat) -> bool) -> StoreResult<()> {
        let head = or_invalid(self.head)?;
        let mut entries = or_invalid(self.entries.take())?;
        let mut i = 0;
        while i < entries.len() {
            let pos = head + entries[i] as Nat;
            if pos >= end {
                break;
            }
            let header = match self.parse_entry(&mut pos.clone())? {
                ParsedEntry::User(x) => x,
                _ => return Err(StoreError::InvalidStorage),
            };
            if delete(header.key) {
                self.delete_pos(pos, self.format.bytes_to_words(header.length))?;
                entries.swap_remove(i);
            } else {
                i += 1;
            }
        }
        self.entries = Some(entries);
        Ok(())
    }

    /// Deletes the entry at a given position.
    fn delete_pos(&mut self, pos: Position, length: Nat) -> StoreResult<()> {
        self.set_deleted(pos)?;
        self.wipe_span(pos + 1, length)?;
        Ok(())
    }

    /// Writes the init info of a page between 2 positions if needed.
    ///
    /// The positions should designate the first and last word of an entry. The init info of the
    /// highest page is written in any of the following conditions:
    /// - The entry starts at the beginning of a virtual page.
    /// - The entry spans 2 pages.
    fn init_page(&mut self, first: Position, last: Position) -> StoreResult<()> {
        debug_assert!(first <= last);
        debug_assert!(last - first < self.format.virt_page_size());
        let new_first = if first.word(&self.format) == 0 {
            first
        } else if first.page(&self.format) == last.page(&self.format) {
            return Ok(());
        } else {
            last + 1
        };
        let page = new_first.page(&self.format);
        if let WordState::Valid(_) = self.parse_init(page)? {
            return Ok(());
        }
        let index = self.format.index_init(page);
        let init_info = self.format.build_init(InitInfo {
            cycle: new_first.cycle(&self.format),
            prefix: new_first.word(&self.format),
        })?;
        self.storage_write_slice(index, &init_info)?;
        Ok(())
    }

    /// Sets the padding bit of a user header.
    fn set_padding(&mut self, pos: Position) -> StoreResult<()> {
        let mut word = Word::from_slice(&self.read_word(pos));
        self.format.set_padding(&mut word)?;
        self.write_slice(pos, &word.as_slice())?;
        Ok(())
    }

    /// Sets the deleted bit of a user header.
    fn set_deleted(&mut self, pos: Position) -> StoreResult<()> {
        let mut word = Word::from_slice(&self.read_word(pos));
        self.format.set_deleted(&mut word);
        self.write_slice(pos, &word.as_slice())?;
        Ok(())
    }

    /// Wipes a slice of words.
    fn wipe_span(&mut self, pos: Position, length: Nat) -> StoreResult<()> {
        let length = (length * self.format.word_size()) as usize;
        self.write_slice(pos, &vec![0x00; length])
    }

    /// Returns an extremum page.
    ///
    /// With `Greater` returns the most recent page (or the tail). With `Less` returns the oldest
    /// page (or the head).
    fn get_extremum_page_head(&self, ordering: Ordering) -> StoreResult<Position> {
        let mut best = None;
        for page in 0..self.format.num_pages() {
            let init = match self.parse_init(page)? {
                WordState::Valid(x) => x,
                _ => continue,
            };
            let pos = self.format.page_head(init, page);
            if best.map_or(true, |x| pos.cmp(&x) == ordering) {
                best = Some(pos);
            }
        }
        // There is always at least one initialized page.
        or_invalid(best)
    }

    /// Returns the number of words that can be written without compaction.
    fn immediate_capacity(&self) -> StoreResult<Nat> {
        let tail = self.tail()?;
        let end = or_invalid(self.head)? + self.format.virt_size();
        Ok(end.get().saturating_sub(tail.get()))
    }

    /// Returns the position of the first word in the store.
    #[cfg(feature = "std")]
    pub(crate) fn head(&self) -> StoreResult<Position> {
        or_invalid(self.head)
    }

    /// Returns one past the position of the last word in the store.
    pub(crate) fn tail(&self) -> StoreResult<Position> {
        let mut pos = self.get_extremum_page_head(Ordering::Greater)?;
        let end = pos.next_page(&self.format);
        while pos < end {
            if let ParsedEntry::Tail = self.parse_entry(&mut pos)? {
                break;
            }
        }
        Ok(pos)
    }

    fn push_entry(&mut self, pos: Position) -> StoreResult<()> {
        let entries = match &mut self.entries {
            None => return Ok(()),
            Some(x) => x,
        };
        let head = or_invalid(self.head)?;
        let offset = or_invalid(u16::try_from(pos - head).ok())?;
        debug_assert!(!entries.contains(&offset));
        entries.push(offset);
        Ok(())
    }

    fn remove_entry(&mut self, pos: Position) -> StoreResult<()> {
        let entries = match &mut self.entries {
            None => return Ok(()),
            Some(x) => x,
        };
        let head = or_invalid(self.head)?;
        let offset = or_invalid(u16::try_from(pos - head).ok())?;
        let i = or_invalid(entries.iter().position(|x| *x == offset))?;
        entries.swap_remove(i);
        Ok(())
    }

    /// Parses the entry at a given position.
    ///
    /// The position is updated to point to the next entry.
    fn parse_entry(&self, pos: &mut Position) -> StoreResult<ParsedEntry> {
        let valid = match self.parse_word(*pos)? {
            WordState::Erased | WordState::Partial => return Ok(self.parse_partial(pos)),
            WordState::Valid(x) => x,
        };
        Ok(match valid {
            ParsedWord::Padding(Padding { length }) => {
                *pos += 1 + length;
                ParsedEntry::Padding
            }
            ParsedWord::Header(header) if header.length > self.format.max_value_len() => {
                self.parse_partial(pos)
            }
            ParsedWord::Header(header) => {
                let length = self.format.bytes_to_words(header.length);
                let footer = match length {
                    0 => None,
                    _ => Some(self.read_word(*pos + length)),
                };
                if header.check(footer.as_deref()) {
                    if header.key > self.format.max_key() {
                        return Err(StoreError::InvalidStorage);
                    }
                    *pos += 1 + length;
                    ParsedEntry::User(header)
                } else if footer.map_or(true, |x| is_erased(&x)) {
                    self.parse_partial(pos)
                } else {
                    *pos += 1 + length;
                    ParsedEntry::PartialUser
                }
            }
            ParsedWord::Internal(internal) => {
                *pos += 1;
                ParsedEntry::Internal(internal)
            }
        })
    }

    /// Parses a possible partial user entry.
    ///
    /// This does look ahead past the header and possible erased word in case words near the end of
    /// the entry were written first.
    fn parse_partial(&self, pos: &mut Position) -> ParsedEntry {
        let mut length = None;
        for i in 0..self.format.max_prefix_len() {
            if !is_erased(&self.read_word(*pos + i)) {
                length = Some(i);
            }
        }
        match length {
            None => ParsedEntry::Tail,
            Some(length) => {
                *pos += 1 + length;
                ParsedEntry::Partial
            }
        }
    }

    /// Parses the init info of a page.
    fn parse_init(&self, page: Nat) -> StoreResult<WordState<InitInfo>> {
        let index = self.format.index_init(page);
        let word = self.storage_read_slice(index, self.format.word_size());
        self.format.parse_init(Word::from_slice(&word))
    }

    /// Parses the compact info of a page.
    fn parse_compact(&self, page: Nat) -> StoreResult<WordState<CompactInfo>> {
        let index = self.format.index_compact(page);
        let word = self.storage_read_slice(index, self.format.word_size());
        self.format.parse_compact(Word::from_slice(&word))
    }

    /// Parses a word from the virtual storage.
    fn parse_word(&self, pos: Position) -> StoreResult<WordState<ParsedWord>> {
        self.format
            .parse_word(Word::from_slice(&self.read_word(pos)))
    }

    /// Reads a slice from the virtual storage.
    ///
    /// The slice may span 2 pages.
    fn read_slice(&self, pos: Position, length: Nat) -> Vec<u8> {
        let mut result = Vec::with_capacity(length as usize);
        let index = pos.index(&self.format);
        let max_length = self.format.page_size() - usize_to_nat(index.byte);
        result.extend_from_slice(&self.storage_read_slice(index, min(length, max_length)));
        if length > max_length {
            // The slice spans the next page.
            let index = pos.next_page(&self.format).index(&self.format);
            result.extend_from_slice(&self.storage_read_slice(index, length - max_length));
        }
        result
    }

    /// Reads a word from the virtual storage.
    fn read_word(&self, pos: Position) -> Cow<[u8]> {
        self.storage_read_slice(pos.index(&self.format), self.format.word_size())
    }

    /// Reads a physical page.
    fn read_page(&self, page: Nat) -> Cow<[u8]> {
        let index = StorageIndex {
            page: page as usize,
            byte: 0,
        };
        self.storage_read_slice(index, self.format.page_size())
    }

    /// Reads a slice from the physical storage.
    fn storage_read_slice(&self, index: StorageIndex, length: Nat) -> Cow<[u8]> {
        // The only possible failures are if the slice spans multiple pages.
        self.storage.read_slice(index, length as usize).unwrap()
    }

    /// Writes a slice to the virtual storage.
    ///
    /// The slice may span 2 pages.
    fn write_slice(&mut self, pos: Position, value: &[u8]) -> StoreResult<()> {
        let index = pos.index(&self.format);
        let max_length = (self.format.page_size() - usize_to_nat(index.byte)) as usize;
        self.storage_write_slice(index, &value[..min(value.len(), max_length)])?;
        if value.len() > max_length {
            // The slice spans the next page.
            let index = pos.next_page(&self.format).index(&self.format);
            self.storage_write_slice(index, &value[max_length..])?;
        }
        Ok(())
    }

    /// Writes a slice to the physical storage.
    ///
    /// Only starts writing the slice from the first word that needs to be written (because it
    /// differs from the current value).
    fn storage_write_slice(&mut self, index: StorageIndex, value: &[u8]) -> StoreResult<()> {
        let word_size = self.format.word_size();
        debug_assert!(usize_to_nat(value.len()) % word_size == 0);
        let slice = self.storage.read_slice(index, value.len())?;
        // Skip as many words that don't need to be written as possible.
        for start in (0..usize_to_nat(value.len())).step_by(word_size as usize) {
            if is_write_needed(
                &slice[start as usize..][..word_size as usize],
                &value[start as usize..][..word_size as usize],
            )? {
                // We must write the remaining slice.
                let index = StorageIndex {
                    page: index.page,
                    byte: (usize_to_nat(index.byte) + start) as usize,
                };
                let value = &value[start as usize..];
                self.storage.write_slice(index, value)?;
                break;
            }
        }
        // There is nothing remaining to write.
        Ok(())
    }

    /// Erases a page if not already erased.
    fn storage_erase_page(&mut self, page: Nat) -> StoreResult<()> {
        if !is_erased(&self.read_page(page)) {
            self.storage.erase_page(page as usize)?;
        }
        Ok(())
    }
}

// Those functions are not meant for production.
#[cfg(feature = "std")]
impl Store<BufferStorage> {
    /// Returns the storage configuration.
    pub fn format(&self) -> &Format {
        &self.format
    }

    /// Accesses the storage.
    pub fn storage(&self) -> &BufferStorage {
        &self.storage
    }

    /// Accesses the storage mutably.
    pub fn storage_mut(&mut self) -> &mut BufferStorage {
        &mut self.storage
    }

    /// Returns the value of a possibly deleted entry.
    ///
    /// If the value has been partially compacted, only return the non-compacted part. Returns an
    /// empty value if it has been fully compacted.
    pub fn inspect_value(&self, handle: &StoreHandle) -> Vec<u8> {
        let head = self.head.unwrap();
        let length = self.format.bytes_to_words(handle.len);
        if head <= handle.pos {
            // The value has not been compacted.
            self.read_slice(handle.pos + 1, handle.len)
        } else if (handle.pos + length).page(&self.format) == head.page(&self.format) {
            // The value has been partially compacted.
            let next_page = handle.pos.next_page(&self.format);
            let erased_len = (next_page - (handle.pos + 1)) * self.format.word_size();
            self.read_slice(next_page, handle.len - erased_len)
        } else {
            // The value has been fully compacted.
            Vec::new()
        }
    }

    /// Applies an operation and returns the deleted entries.
    ///
    /// Note that the deleted entries are before any compaction, so they may point outside the
    /// window. This is more expressive than returning the deleted entries after compaction since
    /// compaction can be controlled independently.
    pub fn apply(&mut self, operation: &StoreOperation) -> (Vec<StoreHandle>, StoreResult<()>) {
        let deleted = |store: &Store<BufferStorage>, delete_key: &dyn Fn(usize) -> bool| {
            store
                .iter()
                .unwrap()
                .filter(|x| x.is_err() || delete_key(x.as_ref().unwrap().key as usize))
                .collect::<Result<Vec<_>, _>>()
        };
        match *operation {
            StoreOperation::Transaction { ref updates } => {
                let keys: HashSet<usize> = updates.iter().map(|x| x.key()).collect();
                match deleted(self, &|key| keys.contains(&key)) {
                    Ok(deleted) => (deleted, self.transaction(updates)),
                    Err(error) => (Vec::new(), Err(error)),
                }
            }
            StoreOperation::Clear { min_key } => match deleted(self, &|key| key >= min_key) {
                Ok(deleted) => (deleted, self.clear(min_key)),
                Err(error) => (Vec::new(), Err(error)),
            },
            StoreOperation::Prepare { length } => (Vec::new(), self.prepare(length)),
        }
    }

    /// Initializes an erased storage as if it has been erased `cycle` times.
    pub fn init_with_cycle(storage: &mut BufferStorage, cycle: usize) {
        let format = Format::new(storage).unwrap();
        // Write the init info of the first page.
        let mut index = format.index_init(0);
        let init_info = format
            .build_init(InitInfo {
                cycle: usize_to_nat(cycle),
                prefix: 0,
            })
            .unwrap();
        storage.write_slice(index, &init_info).unwrap();
        // Pad the first word of the page. This makes the store looks used, otherwise we may confuse
        // it with a partially initialized store.
        index.byte += 2 * format.word_size() as usize;
        storage
            .write_slice(index, &vec![0; format.word_size() as usize])
            .unwrap();
        // Inform the storage that the pages have been used.
        for page in 0..storage.num_pages() {
            storage.set_page_erases(page, cycle);
        }
    }
}

/// Represents an entry in the store.
#[derive(Debug)]
enum ParsedEntry {
    /// Padding entry.
    ///
    /// This can be any of the following:
    /// - A deleted user entry.
    /// - A completed internal entry.
    /// - A wiped partial entry.
    Padding,

    /// Non-deleted user entry.
    User(Header),

    /// Internal entry.
    Internal(InternalEntry),

    /// Partial user entry with non-erased footer.
    ///
    /// The fact that the footer is not erased and does not checksum, means that the header is
    /// valid. In particular, the length is valid. We cannot wipe the entry because wiping the
    /// footer may validate the checksum. So we mark the entry as deleted, which also wipes it.
    PartialUser,

    /// Partial entry.
    ///
    /// This can be any of the following:
    /// - A partial user entry with erased footer.
    /// - A partial user entry with invalid length.
    Partial,

    /// End of entries.
    ///
    /// In particular this is where the next entry will be written.
    Tail,
}

/// Returns whether 2 slices are different.
///
/// Returns an error if `target` has a bit set to one for which `source` is set to zero.
fn is_write_needed(source: &[u8], target: &[u8]) -> StoreResult<bool> {
    debug_assert_eq!(source.len(), target.len());
    for (&source, &target) in source.iter().zip(target.iter()) {
        if source & target != target {
            return Err(StoreError::InvalidStorage);
        }
        if source != target {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::MINIMAL;

    #[test]
    fn is_write_needed_ok() {
        assert_eq!(is_write_needed(&[], &[]), Ok(false));
        assert_eq!(is_write_needed(&[0], &[0]), Ok(false));
        assert_eq!(is_write_needed(&[0], &[1]), Err(StoreError::InvalidStorage));
        assert_eq!(is_write_needed(&[1], &[0]), Ok(true));
        assert_eq!(is_write_needed(&[1], &[1]), Ok(false));
    }

    #[test]
    fn init_ok() {
        assert!(MINIMAL.new_driver().power_on().is_ok());
    }

    #[test]
    fn insert_ok() {
        let mut driver = MINIMAL.new_driver().power_on().unwrap();
        // Empty entry.
        driver.insert(0, &[]).unwrap();
        driver.insert(1, &[]).unwrap();
        driver.check().unwrap();
        // Last word is erased but last bit is not user data.
        driver.insert(0, &[0xff]).unwrap();
        driver.insert(1, &[0xff]).unwrap();
        driver.check().unwrap();
        // Last word is erased and last bit is user data.
        driver.insert(0, &[0xff, 0xff, 0xff, 0xff]).unwrap();
        driver.insert(1, &[0xff, 0xff, 0xff, 0xff]).unwrap();
        driver.insert(2, &[0x5c; 6]).unwrap();
        driver.check().unwrap();
        // Entry spans 2 pages.
        assert_eq!(driver.store().tail().unwrap().get(), 13);
        driver.insert(3, &[0x5c; 8]).unwrap();
        driver.check().unwrap();
        assert_eq!(driver.store().tail().unwrap().get(), 16);
        // Entry ends a page.
        driver.insert(2, &[0x93; (28 - 16 - 1) * 4]).unwrap();
        driver.check().unwrap();
        assert_eq!(driver.store().tail().unwrap().get(), 28);
        // Entry starts a page.
        driver.insert(3, &[0x81; 10]).unwrap();
        driver.check().unwrap();
    }

    #[test]
    fn remove_ok() {
        let mut driver = MINIMAL.new_driver().power_on().unwrap();
        // Remove absent entry.
        driver.remove(0).unwrap();
        driver.remove(1).unwrap();
        driver.check().unwrap();
        // Remove last inserted entry.
        driver.insert(0, &[0x5c; 6]).unwrap();
        driver.remove(0).unwrap();
        driver.check().unwrap();
        // Remove empty entries.
        driver.insert(0, &[]).unwrap();
        driver.insert(1, &[]).unwrap();
        driver.remove(0).unwrap();
        driver.remove(1).unwrap();
        driver.check().unwrap();
        // Remove entry with flipped bit.
        driver.insert(0, &[0xff]).unwrap();
        driver.insert(1, &[0xff; 4]).unwrap();
        driver.remove(0).unwrap();
        driver.remove(1).unwrap();
        driver.check().unwrap();
        // Write some entries with one spanning 2 pages.
        driver.insert(2, &[0x93; 9]).unwrap();
        assert_eq!(driver.store().tail().unwrap().get(), 13);
        driver.insert(3, &[0x81; 10]).unwrap();
        assert_eq!(driver.store().tail().unwrap().get(), 17);
        driver.insert(4, &[0x76; 11]).unwrap();
        driver.check().unwrap();
        // Remove the entry spanning 2 pages.
        driver.remove(3).unwrap();
        driver.check().unwrap();
        // Write some entries with one ending a page and one starting the next.
        assert_eq!(driver.store().tail().unwrap().get(), 21);
        driver.insert(2, &[0xd7; (28 - 21 - 1) * 4]).unwrap();
        assert_eq!(driver.store().tail().unwrap().get(), 28);
        driver.insert(4, &[0xe2; 21]).unwrap();
        driver.check().unwrap();
        // Remove them.
        driver.remove(2).unwrap();
        driver.remove(4).unwrap();
        driver.check().unwrap();
    }

    #[test]
    fn prepare_ok() {
        let mut driver = MINIMAL.new_driver().power_on().unwrap();

        // Don't compact if enough immediate capacity.
        assert_eq!(driver.store().immediate_capacity().unwrap(), 39);
        assert_eq!(driver.store().capacity().unwrap().remaining(), 34);
        assert_eq!(driver.store().head().unwrap().get(), 0);
        driver.store_mut().prepare(34).unwrap();
        assert_eq!(driver.store().head().unwrap().get(), 0);

        // Fill the store.
        for key in 0..4 {
            driver.insert(key, &[0x38; 28]).unwrap();
        }
        driver.check().unwrap();
        assert_eq!(driver.store().immediate_capacity().unwrap(), 7);
        assert_eq!(driver.store().capacity().unwrap().remaining(), 2);
        // Removing entries increases available capacity but not immediate capacity.
        driver.remove(0).unwrap();
        driver.remove(2).unwrap();
        driver.check().unwrap();
        assert_eq!(driver.store().immediate_capacity().unwrap(), 7);
        assert_eq!(driver.store().capacity().unwrap().remaining(), 18);

        // Prepare for next write (7 words data + 1 word overhead).
        assert_eq!(driver.store().head().unwrap().get(), 0);
        driver.store_mut().prepare(8).unwrap();
        driver.check().unwrap();
        assert_eq!(driver.store().head().unwrap().get(), 16);
        // The available capacity did not change, but the immediate capacity is above 8.
        assert_eq!(driver.store().immediate_capacity().unwrap(), 14);
        assert_eq!(driver.store().capacity().unwrap().remaining(), 18);
    }

    #[test]
    fn reboot_ok() {
        let mut driver = MINIMAL.new_driver().power_on().unwrap();

        // Do some operations and reboot.
        driver.insert(0, &[0x38; 24]).unwrap();
        driver.insert(1, &[0x5c; 13]).unwrap();
        driver = driver.power_off().power_on().unwrap();
        driver.check().unwrap();

        // Do more operations and reboot.
        driver.insert(2, &[0x93; 1]).unwrap();
        driver.remove(0).unwrap();
        driver.insert(3, &[0xde; 9]).unwrap();
        driver = driver.power_off().power_on().unwrap();
        driver.check().unwrap();
    }

    #[test]
    fn entries_ok() {
        let mut driver = MINIMAL.new_driver().power_on().unwrap();

        // The store is initially empty.
        assert!(driver.store().entries.as_ref().unwrap().is_empty());

        // Inserted elements are added.
        const LEN: usize = 6;
        driver.insert(0, &[0x38; (LEN - 1) * 4]).unwrap();
        driver.insert(1, &[0x5c; 4]).unwrap();
        assert_eq!(driver.store().entries, Some(vec![0, LEN as u16]));

        // Deleted elements are removed.
        driver.remove(0).unwrap();
        assert_eq!(driver.store().entries, Some(vec![LEN as u16]));
    }
}
