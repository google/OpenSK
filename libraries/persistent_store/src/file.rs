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

//! File-backed persistent flash storage for virtual authenticator.
//!
//! [`FileStorage`] implements the flash [`Storage`] interface but doesn't interface with an
//! actual flash storage. Instead it uses a host-based file to persist the storage state.

use crate::{BufferOptions, Storage, StorageIndex, StorageResult};
use alloc::borrow::Cow;
use core::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Simulates a flash storage using a host-based file.
///
/// This is usable for emulating authenticator hardware on VM hypervisor's host OS
pub struct FileStorage {
    // Options of the storage
    buffer_options: BufferOptions,

    /// File for persisting contents of the storage
    /// Reading data from File requires mutable reference, as seeking and reading data
    /// changes file's current position.
    /// All operations on backing file internally always first seek to needed position,
    /// so it's safe to borrow mutable reference to backing file for the time of operation.
    backing_file_ref: RefCell<File>,
}

const PAGE_SIZE: usize = 0x1000;
const NUM_PAGES: usize = 20;

impl FileStorage {
    pub fn new(path: &Path) -> StorageResult<FileStorage> {
        let buffer_options = BufferOptions {
            word_size: 4,
            page_size: PAGE_SIZE,
            max_word_writes: 2,
            max_page_erases: 10000,
            strict_mode: true,
        };

        let mut backing_file_ref = RefCell::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?,
        );
        let backing_file = backing_file_ref.get_mut();
        let file_len = backing_file.metadata()?.len();
        let store_len: u64 = (PAGE_SIZE * NUM_PAGES) as u64;

        if file_len == 0 {
            backing_file.seek(SeekFrom::Start(0))?;
            for _ in 0..NUM_PAGES {
                let buf = [0xffu8; PAGE_SIZE];
                backing_file.write(&buf)?;
            }
        } else if file_len != store_len {
            // FileStorage buffer should be of fixed size, opening previously saved file
            // from storage of different size is not supported
            panic!("Invalid file size {}, should be {}", file_len, store_len);
        }
        Ok(FileStorage {
            buffer_options,
            backing_file_ref,
        })
    }
}

impl Storage for FileStorage {
    fn word_size(&self) -> usize {
        self.buffer_options.word_size
    }

    fn page_size(&self) -> usize {
        self.buffer_options.page_size
    }

    fn num_pages(&self) -> usize {
        NUM_PAGES
    }

    fn max_word_writes(&self) -> usize {
        self.buffer_options.max_word_writes
    }

    fn max_page_erases(&self) -> usize {
        self.buffer_options.max_page_erases
    }

    fn read_slice(&self, index: StorageIndex, length: usize) -> StorageResult<Cow<[u8]>> {
        let mut backing_file = self.backing_file_ref.borrow_mut();
        backing_file.seek(SeekFrom::Start(
            (index.page * self.page_size() + index.byte) as u64,
        ))?;
        let mut buf = vec![0u8; length];
        backing_file.read_exact(&mut buf)?;
        Ok(Cow::Owned(buf))
    }

    fn write_slice(&mut self, index: StorageIndex, value: &[u8]) -> StorageResult<()> {
        let mut backing_file = self.backing_file_ref.borrow_mut();
        backing_file.seek(SeekFrom::Start(
            (index.page * self.page_size() + index.byte) as u64,
        ))?;
        backing_file.write_all(value)?;
        Ok(())
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let mut backing_file = self.backing_file_ref.borrow_mut();
        backing_file.seek(SeekFrom::Start((page * self.page_size()) as u64))?;
        backing_file.write_all(&vec![0xffu8; self.page_size()][..])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const BLANK_WORD: &[u8] = &[0xff, 0xff, 0xff, 0xff];
    const DATA_WORD: &[u8] = &[0xee, 0xdd, 0xbb, 0x77];

    const FILE_NAME: &str = "opensk_storage.bin";

    fn make_tmp_dir() -> PathBuf {
        let tmp_dir = TempDir::new().unwrap();
        tmp_dir.into_path()
    }

    fn remove_tmp_dir(tmp_dir: PathBuf) {
        std::fs::remove_dir_all(tmp_dir).unwrap();
    }

    fn temp_storage(tmp_dir: &PathBuf) -> FileStorage {
        let mut tmp_file = tmp_dir.clone();
        tmp_file.push(FILE_NAME);
        FileStorage::new(&tmp_file).unwrap()
    }

    #[test]
    fn read_write_persist_ok() {
        let index = StorageIndex { page: 0, byte: 0 };
        let next_index = StorageIndex { page: 0, byte: 4 };

        let tmp_dir = make_tmp_dir();
        {
            let mut file_storage = temp_storage(&tmp_dir);
            assert_eq!(file_storage.read_slice(index, 4).unwrap(), BLANK_WORD);
            file_storage.write_slice(index, DATA_WORD).unwrap();
            assert_eq!(file_storage.read_slice(index, 4).unwrap(), DATA_WORD);
            assert_eq!(file_storage.read_slice(next_index, 4).unwrap(), BLANK_WORD);
        }
        // Reload and check the data from previously persisted storage
        {
            let file_storage = temp_storage(&tmp_dir);
            assert_eq!(file_storage.read_slice(index, 4).unwrap(), DATA_WORD);
            assert_eq!(file_storage.read_slice(next_index, 4).unwrap(), BLANK_WORD);
        }
        remove_tmp_dir(tmp_dir);
    }
}
