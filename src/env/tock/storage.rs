// Copyright 2019-2023 Google LLC
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

use super::storage_helper::{find_slice, is_aligned, ModRange, Partition};
use super::upgrade_helper::{
    check_metadata, parse_metadata_hash, parse_metadata_version, METADATA_SIGN_OFFSET,
};
use super::TockEnv;
use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::marker::PhantomData;
use libtock_drivers::result::TockResult;
use libtock_drivers::storage::{Storage as LibtockStorage, StorageType};
use libtock_platform as platform;
use libtock_platform::Syscalls;
use opensk::api::crypto::sha256::Sha256;
use opensk::env::Sha;
use persistent_store::{Storage, StorageError, StorageIndex, StorageResult};

const UPGRADE_PUBLIC_KEY: &[u8; 65] =
    include_bytes!(concat!(env!("OUT_DIR"), "/opensk_upgrade_pubkey.bin"));

fn to_storage_result<T>(result: TockResult<T>) -> StorageResult<T> {
    result.map_err(|_| StorageError::CustomError)
}

unsafe fn read_slice(address: usize, length: usize) -> &'static [u8] {
    core::slice::from_raw_parts(address as *const u8, length)
}

pub struct TockStorage<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config> {
    word_size: usize,
    page_size: usize,
    num_pages: usize,
    max_word_writes: usize,
    max_page_erases: usize,
    storage_locations: Vec<&'static [u8]>,
    s: PhantomData<S>,
    c: PhantomData<C>,
}

impl<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config> TockStorage<S, C> {
    /// Provides access to the embedded flash if available.
    ///
    /// # Errors
    ///
    /// Returns `CustomError` if any of the following conditions do not hold:
    /// - The word size is a power of two.
    /// - The page size is a power of two.
    /// - The page size is a multiple of the word size.
    /// - The storage is page-aligned.
    pub fn new() -> StorageResult<TockStorage<S, C>> {
        let word_size = to_storage_result(LibtockStorage::<S, C>::word_size())?;
        let page_size = to_storage_result(LibtockStorage::<S, C>::page_size())?;
        let max_word_writes = to_storage_result(LibtockStorage::<S, C>::max_word_writes())?;
        let max_page_erases = to_storage_result(LibtockStorage::<S, C>::max_page_erases())?;
        let mut syscall = TockStorage {
            word_size,
            page_size,
            num_pages: 0,
            max_word_writes,
            max_page_erases,
            storage_locations: Vec::new(),
            s: PhantomData,
            c: PhantomData,
        };
        if !syscall.word_size.is_power_of_two()
            || !syscall.page_size.is_power_of_two()
            || !syscall.is_word_aligned(syscall.page_size)
        {
            return Err(StorageError::CustomError);
        }
        let num_storage_locations = to_storage_result(LibtockStorage::<S, C>::storage_cnt())?;
        for i in 0..num_storage_locations {
            let storage_type = to_storage_result(LibtockStorage::<S, C>::storage_type(i))?;
            if !matches!(storage_type, StorageType::Store) {
                continue;
            }
            let storage_ptr = to_storage_result(LibtockStorage::<S, C>::storage_ptr(i))?;
            let storage_len = to_storage_result(LibtockStorage::<S, C>::storage_len(i))?;
            if !syscall.is_page_aligned(storage_ptr) || !syscall.is_page_aligned(storage_len) {
                return Err(StorageError::CustomError);
            }
            syscall.num_pages += storage_len / syscall.page_size;
            syscall
                .storage_locations
                .push(unsafe { core::slice::from_raw_parts(storage_ptr as *mut u8, storage_len) });
        }
        Ok(syscall)
    }

    fn is_word_aligned(&self, x: usize) -> bool {
        is_aligned(self.word_size, x)
    }

    fn is_page_aligned(&self, x: usize) -> bool {
        is_aligned(self.page_size, x)
    }
}

impl<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config> Storage
    for TockStorage<S, C>
{
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

    fn read_slice(&self, index: StorageIndex, length: usize) -> StorageResult<Cow<[u8]>> {
        let start = index.range(length, self)?.start;
        find_slice(&self.storage_locations, start, length).map(Cow::Borrowed)
    }

    fn write_slice(&mut self, index: StorageIndex, value: &[u8]) -> StorageResult<()> {
        if !self.is_word_aligned(index.byte) || !self.is_word_aligned(value.len()) {
            return Err(StorageError::NotAligned);
        }
        let ptr = self.read_slice(index, value.len())?.as_ptr() as usize;
        to_storage_result(LibtockStorage::<S, C>::write_slice(ptr, value))
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let index = StorageIndex { page, byte: 0 };
        let length = self.page_size();
        let ptr = self.read_slice(index, length)?.as_ptr() as usize;
        to_storage_result(LibtockStorage::<S, C>::erase_page(ptr, length))
    }
}

pub struct TockUpgradeStorage<
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
> {
    page_size: usize,
    partition: Partition,
    metadata: ModRange,
    running_metadata: ModRange,
    identifier: u32,
    s: PhantomData<S>,
    c: PhantomData<C>,
}

impl<S, C> TockUpgradeStorage<S, C>
where
    S: Syscalls,
    C: platform::allow_ro::Config + platform::subscribe::Config,
{
    // Ideally, the kernel should tell us metadata and partitions directly.
    // This code only works for one layout, refactor this into the storage driver to support more.
    const METADATA_ADDRESS: usize = 0x4000;
    const PARTITION_ADDRESS_A: usize = 0x20000;
    const PARTITION_ADDRESS_B: usize = 0x60000;

    /// Provides access to the other upgrade partition and metadata if available.
    ///
    /// The implementation assumes that storage locations returned by the kernel through
    /// `memop_nr::STORAGE_*` calls are in address space order.
    ///
    /// # Errors
    ///
    /// Returns `CustomError` if any of the following conditions do not hold:
    /// - The page size is a power of two.
    /// - The storage slices are page-aligned.
    /// - There are no partition or no metadata slices.
    /// Returns a `NotAligned` error if partitions or metadata ranges are
    /// - not exclusive or,
    /// - not consecutive.
    pub fn new() -> StorageResult<TockUpgradeStorage<S, C>> {
        let mut locations = TockUpgradeStorage {
            page_size: to_storage_result(LibtockStorage::<S, C>::page_size())?,
            partition: Partition::default(),
            metadata: ModRange::new_empty(),
            running_metadata: ModRange::new_empty(),
            identifier: Self::PARTITION_ADDRESS_A as u32,
            s: PhantomData,
            c: PhantomData,
        };
        if !locations.page_size.is_power_of_two() {
            return Err(StorageError::CustomError);
        }
        let mut firmware_range = ModRange::new_empty();
        for i in 0..to_storage_result(LibtockStorage::<S, C>::storage_cnt())? {
            let storage_type = to_storage_result(LibtockStorage::<S, C>::storage_type(i))?;
            if !matches!(storage_type, StorageType::Partition) {
                continue;
            };
            let storage_ptr = to_storage_result(LibtockStorage::<S, C>::storage_ptr(i))?;
            let storage_len = to_storage_result(LibtockStorage::<S, C>::storage_len(i))?;
            if !locations.is_page_aligned(storage_ptr) || !locations.is_page_aligned(storage_len) {
                return Err(StorageError::CustomError);
            }
            let range = ModRange::new(storage_ptr, storage_len);
            match range.start() {
                Self::METADATA_ADDRESS => {
                    // Will be swapped if we are on B.
                    locations.metadata = ModRange::new(range.start(), locations.page_size);
                    locations.running_metadata =
                        ModRange::new(range.start() + locations.page_size, locations.page_size);
                }
                _ => {
                    if !firmware_range.append(&range) {
                        return Err(StorageError::NotAligned);
                    }
                }
            }
        }
        if firmware_range.is_empty()
            || locations.metadata.is_empty()
            || locations.running_metadata.is_empty()
        {
            return Err(StorageError::CustomError);
        }
        if firmware_range.start() == Self::PARTITION_ADDRESS_B {
            core::mem::swap(&mut locations.metadata, &mut locations.running_metadata);
            locations.identifier = Self::PARTITION_ADDRESS_B as u32;
        }
        if !locations.partition.append(locations.metadata.clone()) {
            return Err(StorageError::NotAligned);
        }
        if !locations.partition.append(firmware_range) {
            return Err(StorageError::NotAligned);
        }
        Ok(locations)
    }

    fn is_page_aligned(&self, x: usize) -> bool {
        is_aligned(self.page_size, x)
    }

    /// Returns whether the metadata is contained in this range or not.
    ///
    /// Assumes that metadata is written in one call per range. If the metadata is only partially
    /// contained, returns an error.
    fn contains_metadata(&self, checked_range: &ModRange) -> StorageResult<bool> {
        if checked_range.intersects_range(&self.metadata) {
            if checked_range.contains_range(&self.metadata) {
                Ok(true)
            } else {
                Err(StorageError::NotAligned)
            }
        } else {
            Ok(false)
        }
    }

    /// Checks if the metadata's hash matches the partition's content.
    fn check_partition_hash(&self, metadata: &[u8]) -> StorageResult<()> {
        let start_address = self.metadata.start() + METADATA_SIGN_OFFSET;
        let mut hasher = Sha::<TockEnv<S>>::new();
        for range in self.partition.ranges_from(start_address) {
            let partition_slice = unsafe { read_slice(range.start(), range.length()) };
            // The hash implementation handles this in chunks, so no memory issues.
            hasher.update(partition_slice);
        }
        let mut computed_hash = [0; 32];
        hasher.finalize(&mut computed_hash);
        if &computed_hash != parse_metadata_hash(metadata) {
            return Err(StorageError::CustomError);
        }
        Ok(())
    }

    pub fn write_bundle(&mut self, offset: usize, data: Vec<u8>) -> StorageResult<()> {
        if data.is_empty() {
            return Err(StorageError::OutOfBounds);
        }
        let address = self
            .partition
            .find_address(offset, data.len())
            .ok_or(StorageError::OutOfBounds)?;
        let write_range = ModRange::new(address, data.len());
        if self.contains_metadata(&write_range)? {
            let new_metadata = &data[self.metadata.start() - address..][..self.metadata.length()];
            check_metadata::<TockEnv<S, C>, S, C>(self, UPGRADE_PUBLIC_KEY, new_metadata)?;
        }

        // Erases all pages that have their first byte in the write range.
        // Since we expect calls in order, we don't want to erase half-written pages.
        for address in write_range.aligned_iter(self.page_size) {
            to_storage_result(LibtockStorage::<S, C>::erase_page(address, self.page_size))?;
        }
        to_storage_result(LibtockStorage::<S, C>::write_slice(address, &data))?;
        let written_slice = unsafe { read_slice(address, data.len()) };
        if written_slice != data {
            return Err(StorageError::CustomError);
        }
        // Case: Last slice is written.
        if data.len() == self.partition.length() - offset {
            let metadata = unsafe { read_slice(self.metadata.start(), self.metadata.length()) };
            self.check_partition_hash(metadata)?;
        }
        Ok(())
    }

    pub fn bundle_identifier(&self) -> u32 {
        self.identifier
    }

    pub fn running_firmware_version(&self) -> u64 {
        let running_metadata = unsafe {
            read_slice(
                self.running_metadata.start(),
                self.running_metadata.length(),
            )
        };
        parse_metadata_version(running_metadata)
    }
}
