// Copyright 2019-2021 Google LLC
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

use crate::api::upgrade_storage::helper::{find_slice, is_aligned, ModRange};
use crate::api::upgrade_storage::UpgradeStorage;
use alloc::borrow::Cow;
use alloc::vec::Vec;
use arrayref::array_ref;
use byteorder::{ByteOrder, LittleEndian};
use core::cell::Cell;
use crypto::sha256::Sha256;
use crypto::{ecdsa, Hash256};
use libtock_core::{callback, syscalls};
use persistent_store::{Storage, StorageError, StorageIndex, StorageResult};

const DRIVER_NUMBER: usize = 0x50003;

const UPGRADE_PUBLIC_KEY: &[u8; 65] =
    include_bytes!(concat!(env!("OUT_DIR"), "/opensk_upgrade_pubkey.bin"));

mod subscribe_nr {
    pub const DONE: usize = 0;
}

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

mod memop_nr {
    pub const STORAGE_CNT: u32 = 12;
    pub const STORAGE_PTR: u32 = 13;
    pub const STORAGE_LEN: u32 = 14;
    pub const STORAGE_TYPE: u32 = 15;
}

mod storage_type {
    pub const STORE: usize = 1;
    pub const PARTITION: usize = 2;
}

fn get_info(nr: usize, arg: usize) -> StorageResult<usize> {
    let code = syscalls::command(DRIVER_NUMBER, command_nr::GET_INFO, nr, arg);
    code.map_err(|_| StorageError::CustomError)
}

fn memop(nr: u32, arg: usize) -> StorageResult<usize> {
    let code = unsafe { syscalls::raw::memop(nr, arg) };
    if code < 0 {
        Err(StorageError::CustomError)
    } else {
        Ok(code as usize)
    }
}

fn block_command(driver: usize, cmd: usize, arg1: usize, arg2: usize) -> StorageResult<()> {
    let done = Cell::new(None);
    let mut alarm = |status| done.set(Some(status));
    let subscription = syscalls::subscribe::<callback::Identity1Consumer, _>(
        DRIVER_NUMBER,
        subscribe_nr::DONE,
        &mut alarm,
    );
    if subscription.is_err() {
        return Err(StorageError::CustomError);
    }

    let code = syscalls::command(driver, cmd, arg1, arg2);
    if code.is_err() {
        return Err(StorageError::CustomError);
    }

    libtock_drivers::util::yieldk_for(|| done.get().is_some());
    if done.get().unwrap() == 0 {
        Ok(())
    } else {
        Err(StorageError::CustomError)
    }
}

fn write_slice(ptr: usize, value: &[u8]) -> StorageResult<()> {
    let code = unsafe {
        syscalls::raw::allow(
            DRIVER_NUMBER,
            allow_nr::WRITE_SLICE,
            // We rely on the driver not writing to the slice. This should use read-only allow
            // when available. See https://github.com/tock/tock/issues/1274.
            value.as_ptr() as *mut u8,
            value.len(),
        )
    };
    if code < 0 {
        return Err(StorageError::CustomError);
    }

    block_command(DRIVER_NUMBER, command_nr::WRITE_SLICE, ptr, value.len())
}

fn erase_page(ptr: usize, page_length: usize) -> StorageResult<()> {
    block_command(DRIVER_NUMBER, command_nr::ERASE_PAGE, ptr, page_length)
}

pub struct TockStorage {
    word_size: usize,
    page_size: usize,
    num_pages: usize,
    max_word_writes: usize,
    max_page_erases: usize,
    storage_locations: Vec<&'static [u8]>,
}

impl TockStorage {
    /// Provides access to the embedded flash if available.
    ///
    /// # Errors
    ///
    /// Returns `CustomError` if any of the following conditions do not hold:
    /// - The word size is a power of two.
    /// - The page size is a power of two.
    /// - The page size is a multiple of the word size.
    /// - The storage is page-aligned.
    pub fn new() -> StorageResult<TockStorage> {
        let mut syscall = TockStorage {
            word_size: get_info(command_nr::get_info_nr::WORD_SIZE, 0)?,
            page_size: get_info(command_nr::get_info_nr::PAGE_SIZE, 0)?,
            num_pages: 0,
            max_word_writes: get_info(command_nr::get_info_nr::MAX_WORD_WRITES, 0)?,
            max_page_erases: get_info(command_nr::get_info_nr::MAX_PAGE_ERASES, 0)?,
            storage_locations: Vec::new(),
        };
        if !syscall.word_size.is_power_of_two()
            || !syscall.page_size.is_power_of_two()
            || !syscall.is_word_aligned(syscall.page_size)
        {
            return Err(StorageError::CustomError);
        }
        for i in 0..memop(memop_nr::STORAGE_CNT, 0)? {
            if memop(memop_nr::STORAGE_TYPE, i)? != storage_type::STORE {
                continue;
            }
            let storage_ptr = memop(memop_nr::STORAGE_PTR, i)?;
            let storage_len = memop(memop_nr::STORAGE_LEN, i)?;
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

impl Storage for TockStorage {
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
        write_slice(ptr, value)
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let index = StorageIndex { page, byte: 0 };
        let length = self.page_size();
        let ptr = self.read_slice(index, length)?.as_ptr() as usize;
        erase_page(ptr, length)
    }
}

pub struct TockUpgradeStorage {
    page_size: usize,
    partition: ModRange,
    metadata: ModRange,
}

impl TockUpgradeStorage {
    const METADATA_ADDRESS_A: usize = 0x4000;
    const METADATA_ADDRESS_B: usize = 0x5000;

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
    /// - There are not partition or metadata slices.
    /// Returns a `NotAligned` error if partitions or metadata ranges are
    /// - not exclusive or,
    /// - not consecutive.
    pub fn new() -> StorageResult<TockUpgradeStorage> {
        let mut locations = TockUpgradeStorage {
            page_size: get_info(command_nr::get_info_nr::PAGE_SIZE, 0)?,
            partition: ModRange::new_empty(),
            metadata: ModRange::new_empty(),
        };
        if !locations.page_size.is_power_of_two() {
            return Err(StorageError::CustomError);
        }
        for i in 0..memop(memop_nr::STORAGE_CNT, 0)? {
            let storage_type = memop(memop_nr::STORAGE_TYPE, i)?;
            if !matches!(storage_type, storage_type::PARTITION) {
                continue;
            };
            let storage_ptr = memop(memop_nr::STORAGE_PTR, i)?;
            let storage_len = memop(memop_nr::STORAGE_LEN, i)?;
            if !locations.is_page_aligned(storage_ptr) || !locations.is_page_aligned(storage_len) {
                return Err(StorageError::CustomError);
            }
            let range = ModRange::new(storage_ptr, storage_len);
            match range.start() {
                Self::METADATA_ADDRESS_A | Self::METADATA_ADDRESS_B => locations.metadata = range,
                _ => {
                    locations.partition = locations
                        .partition
                        .append(range)
                        .ok_or(StorageError::NotAligned)?
                }
            }
        }
        if locations.partition.is_empty() {
            return Err(StorageError::CustomError);
        }
        Ok(locations)
    }

    fn is_page_aligned(&self, x: usize) -> bool {
        is_aligned(self.page_size, x)
    }
}

impl UpgradeStorage for TockUpgradeStorage {
    fn read_partition(&self, offset: usize, length: usize) -> StorageResult<&[u8]> {
        if length == 0 {
            return Err(StorageError::OutOfBounds);
        }
        let address = self.partition.start() + offset;
        if self
            .partition
            .contains_range(&ModRange::new(address, length))
        {
            Ok(unsafe { core::slice::from_raw_parts(address as *const u8, length) })
        } else {
            Err(StorageError::OutOfBounds)
        }
    }

    fn write_partition(&mut self, offset: usize, data: &[u8]) -> StorageResult<()> {
        if data.is_empty() {
            return Err(StorageError::OutOfBounds);
        }
        let address = self.partition.start() + offset;
        let write_range = ModRange::new(address, data.len());
        if self.partition.contains_range(&write_range) {
            // Erases all pages that have their first byte in the write range.
            // Since we expect calls in order, we don't want to erase half-written pages.
            for address in write_range.aligned_iter(self.page_size) {
                erase_page(address, self.page_size)?;
            }
            write_slice(address, data)
        } else {
            Err(StorageError::OutOfBounds)
        }
    }

    fn partition_address(&self) -> usize {
        self.partition.start()
    }

    fn partition_length(&self) -> usize {
        self.partition.length()
    }

    fn read_metadata(&self) -> StorageResult<&[u8]> {
        Ok(unsafe {
            core::slice::from_raw_parts(self.metadata.start() as *const u8, self.metadata.length())
        })
    }

    fn write_metadata(&mut self, data: &[u8]) -> StorageResult<()> {
        if data.len() != self.metadata.length() {
            return Err(StorageError::CustomError);
        }
        // Compares the hash inside the metadata to the actual hash.
        parse_metadata(self, UPGRADE_PUBLIC_KEY, &data)?;
        for address in self.metadata.aligned_iter(self.page_size) {
            erase_page(address, self.page_size)?;
        }
        write_slice(self.metadata.start(), data)
    }
}

/// Parses the metadata of an upgrade, and checks its correctness.
///
/// The metadata is a page starting with:
/// - 32 B upgrade hash (SHA256)
/// - 64 B signature,
/// that are not signed over. The second part is included in the signature with
/// -  8 B version and
/// -  4 B partition address in little endian encoding
/// written at METADATA_SIGN_OFFSET.
///
/// Checks hash and signature correctness, and whether the partition offset matches.
fn parse_metadata(
    upgrade_locations: &impl UpgradeStorage,
    public_key_bytes: &[u8],
    metadata: &[u8],
) -> StorageResult<()> {
    const METADATA_LEN: usize = 0x1000;
    const METADATA_SIGN_OFFSET: usize = 0x800;
    if metadata.len() != METADATA_LEN {
        return Err(StorageError::CustomError);
    }

    let metadata_address = LittleEndian::read_u32(&metadata[METADATA_SIGN_OFFSET + 8..][..4]);
    if metadata_address as usize != upgrade_locations.partition_address() {
        return Err(StorageError::CustomError);
    }

    // The hash implementation handles this in chunks, so no memory issues.
    let partition_slice =
        upgrade_locations.read_partition(0, upgrade_locations.partition_length())?;
    let mut hasher = Sha256::new();
    hasher.update(&metadata[METADATA_SIGN_OFFSET..]);
    hasher.update(partition_slice);
    let computed_hash = hasher.finalize();
    if &computed_hash != array_ref!(metadata, 0, 32) {
        return Err(StorageError::CustomError);
    }

    verify_signature(
        array_ref!(metadata, 32, 64),
        public_key_bytes,
        &computed_hash,
    )?;
    Ok(())
}

/// Verifies the signature over the given hash.
///
/// The public key is COSE encoded, and the hash is a SHA256.
fn verify_signature(
    signature_bytes: &[u8; 64],
    public_key_bytes: &[u8],
    signed_hash: &[u8; 32],
) -> StorageResult<()> {
    let signature =
        ecdsa::Signature::from_bytes(signature_bytes).ok_or(StorageError::CustomError)?;
    let public_key = ecdsa::PubKey::from_bytes_uncompressed(public_key_bytes)
        .ok_or(StorageError::CustomError)?;
    if !public_key.verify_hash_vartime(signed_hash, &signature) {
        return Err(StorageError::CustomError);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;
    use crate::env::Env;

    #[test]
    fn test_parse_metadata() {
        let mut env = TestEnv::new();
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let upgrade_locations = env.upgrade_storage().unwrap();

        const METADATA_LEN: usize = 0x1000;
        const METADATA_SIGN_OFFSET: usize = 0x800;
        let mut metadata = vec![0xFF; METADATA_LEN];
        LittleEndian::write_u32(&mut metadata[METADATA_SIGN_OFFSET + 8..][..4], 0x60000);

        let partition_length = upgrade_locations.partition_length();
        let mut signed_over_data = metadata[METADATA_SIGN_OFFSET..].to_vec();
        signed_over_data.extend(
            upgrade_locations
                .read_partition(0, partition_length)
                .unwrap(),
        );
        let signed_hash = Sha256::hash(&signed_over_data);

        metadata[..32].copy_from_slice(&signed_hash);
        let signature = private_key.sign_rfc6979::<Sha256>(&signed_over_data);
        let mut signature_bytes = [0; ecdsa::Signature::BYTES_LENGTH];
        signature.to_bytes(&mut signature_bytes);
        metadata[32..96].copy_from_slice(&signature_bytes);

        let public_key = private_key.genpk();
        let mut public_key_bytes = [0; 65];
        public_key.to_bytes_uncompressed(&mut public_key_bytes);

        assert_eq!(
            parse_metadata(upgrade_locations, &public_key_bytes, &metadata),
            Ok(())
        );

        // Manipulating the partition address fails.
        metadata[METADATA_SIGN_OFFSET] = 0x88;
        assert_eq!(
            parse_metadata(upgrade_locations, &public_key_bytes, &metadata),
            Err(StorageError::CustomError)
        );
        metadata[METADATA_SIGN_OFFSET] = 0x00;
        // Any manipulation of signed data fails.
        metadata[METADATA_LEN - 1] = 0x88;
        assert_eq!(
            parse_metadata(upgrade_locations, &public_key_bytes, &metadata),
            Err(StorageError::CustomError)
        );
        metadata[METADATA_LEN - 1] = 0xFF;
        // Manipulating the hash fails.
        metadata[0] ^= 0x01;
        assert_eq!(
            parse_metadata(upgrade_locations, &public_key_bytes, &metadata),
            Err(StorageError::CustomError)
        );
        metadata[0] ^= 0x01;
        // Manipulating the signature fails.
        metadata[32] ^= 0x01;
        assert_eq!(
            parse_metadata(upgrade_locations, &public_key_bytes, &metadata),
            Err(StorageError::CustomError)
        );
        metadata[32] ^= 0x01;
        // Manipulating the partition data fails.
        upgrade_locations.write_partition(0, &[0x88; 1]).unwrap();
        assert_eq!(
            parse_metadata(upgrade_locations, &public_key_bytes, &metadata),
            Err(StorageError::CustomError)
        );
    }

    #[test]
    fn test_verify_signature() {
        let mut env = TestEnv::new();
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let message = [0x44; 64];
        let signed_hash = Sha256::hash(&message);
        let signature = private_key.sign_rfc6979::<Sha256>(&message);

        let mut signature_bytes = [0; ecdsa::Signature::BYTES_LENGTH];
        signature.to_bytes(&mut signature_bytes);

        let public_key = private_key.genpk();
        let mut public_key_bytes = [0; 65];
        public_key.to_bytes_uncompressed(&mut public_key_bytes);

        assert_eq!(
            verify_signature(&signature_bytes, &public_key_bytes, &signed_hash),
            Ok(())
        );
        assert_eq!(
            verify_signature(&signature_bytes, &public_key_bytes, &[0x55; 32]),
            Err(StorageError::CustomError)
        );
        public_key_bytes[0] ^= 0x01;
        assert_eq!(
            verify_signature(&signature_bytes, &public_key_bytes, &signed_hash),
            Err(StorageError::CustomError)
        );
        public_key_bytes[0] ^= 0x01;
        signature_bytes[0] ^= 0x01;
        assert_eq!(
            verify_signature(&signature_bytes, &public_key_bytes, &signed_hash),
            Err(StorageError::CustomError)
        );
    }
}
