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

use crate::{Storage, StorageIndex, StorageResult};
use alloc::borrow::Cow;
use core::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Simulates a flash storage using a host-based file.
///
/// This is usable for emulating authenticator hardware on VM hypervisor's host OS.
pub struct FileStorage {
    // Options of the storage.
    options: FileOptions,

    /// File for persisting contents of the storage.
    ///
    /// Reading data from File requires mutable reference, as seeking and reading data
    /// changes file's current position.
    ///
    /// All operations on backing file internally always first seek to needed position,
    /// so it's safe to borrow mutable reference to backing file for the time of operation.
    file: RefCell<File>,
}

/// Options for file-backed storage.
pub struct FileOptions {
    /// Size of a word in bytes.
    pub word_size: usize,

    /// Size of a page in bytes.
    pub page_size: usize,

    /// Number of pages in storage.
    pub num_pages: usize,
}

impl FileStorage {
    pub fn new(path: &Path, options: FileOptions) -> StorageResult<FileStorage> {
        let mut file_ref = RefCell::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?,
        );
        let file = file_ref.get_mut();
        let file_len = file.metadata()?.len();
        let store_len: u64 = (options.page_size * options.num_pages) as u64;

        if file_len == 0 {
            file.seek(SeekFrom::Start(0))?;
            let buf = vec![0xff; options.page_size];
            for _ in 0..options.num_pages {
                file.write(&buf)?;
            }
        } else if file_len != store_len {
            // FileStorage buffer should be of fixed size, opening previously saved file
            // from storage of different size is not supported
            panic!("Invalid file size {}, should be {}", file_len, store_len);
        }
        Ok(FileStorage {
            options,
            file: file_ref,
        })
    }
}

impl Storage for FileStorage {
    fn word_size(&self) -> usize {
        self.options.word_size
    }

    fn page_size(&self) -> usize {
        self.options.page_size
    }

    fn num_pages(&self) -> usize {
        self.options.num_pages
    }

    fn max_word_writes(&self) -> usize {
        // We can write an unlimited amount of times in a file, but the store arithmetic
        // uses `Nat` so the value should fit in a `Nat`.
        u32::MAX as usize
    }

    fn max_page_erases(&self) -> usize {
        // We can "erase" an unlimited amount of times in a file, but the store format
        // encodes the number of erase cycles on 16 bits.
        u16::MAX as usize
    }

    fn read_slice(&self, index: StorageIndex, length: usize) -> StorageResult<Cow<[u8]>> {
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(index.range(length, self)?.start as u64))?;
        let mut buf = vec![0u8; length];
        file.read_exact(&mut buf)?;
        Ok(Cow::Owned(buf))
    }

    fn write_slice(&mut self, index: StorageIndex, value: &[u8]) -> StorageResult<()> {
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(
            index.range(value.len(), self)?.start as u64,
        ))?;
        file.write_all(value)?;
        Ok(())
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        let mut file = self.file.borrow_mut();
        let index = StorageIndex { page, byte: 0 };
        file.seek(SeekFrom::Start(
            index.range(self.page_size(), self)?.start as u64,
        ))?;
        file.write_all(&vec![0xff; self.page_size()][..])?;
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

    const OPTIONS: FileOptions = FileOptions {
        word_size: 4,
        page_size: 0x1000,
        num_pages: 20,
    };

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
        FileStorage::new(&tmp_file, OPTIONS).unwrap()
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
