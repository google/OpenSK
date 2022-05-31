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

use crate::{BufferOptions, BufferStorage, Storage, StorageIndex, StorageResult};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Simulates a flash storage using a host-based file.
///
/// It provides same functions as BufferStorage for testing, but also saves stored
/// data between application restarts.
///
/// Metadata, such as word write and page erase counters are not saved between restarts.
///
pub struct FileStorage {
    /// Content of the storage.
    storage: BufferStorage,
    /// File to persist contents of the storage.
    backing_file: File,
}

const PAGE_SIZE: usize = 0x1000;
const NUM_PAGES: usize = 20;

impl FileStorage {
    pub fn new(path: &Path) -> StorageResult<FileStorage> {
        let options = BufferOptions {
            word_size: 4,
            page_size: PAGE_SIZE,
            max_word_writes: 2,
            max_page_erases: 10000,
            strict_mode: true,
        };
        let store = vec![0xff; NUM_PAGES * PAGE_SIZE].into_boxed_slice();
        let store_size = (&store).len() as u64;
        let mut storage = BufferStorage::new(store, options);

        let mut backing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;
        let file_len = backing_file.metadata()?.len();

        if file_len == 0 {
            backing_file.set_len(store_size)?;
            backing_file.seek(SeekFrom::Start(0))?;
            for i in 0..storage.num_pages() {
                let buf = storage.read_slice(StorageIndex { page: i, byte: 0 }, PAGE_SIZE)?;
                backing_file.write(&buf)?;
            }
        } else if file_len == store_size {
            backing_file.seek(SeekFrom::Start(0))?;
            let mut buf = [0u8; PAGE_SIZE];
            for i in 0..storage.num_pages() {
                backing_file.read(&mut buf)?;
                storage.write_slice(StorageIndex { page: i, byte: 0 }, &buf)?;
            }
        } else {
            // FileStorage buffer should be of fixed size, opening previously saved file
            // from storage of different size is not supported
            panic!("Invalid file size {}, should be {}", file_len, store_size);
        }
        Ok(FileStorage {
            backing_file,
            storage,
        })
    }
}

impl Storage for FileStorage {
    fn word_size(&self) -> usize {
        self.storage.word_size()
    }

    fn page_size(&self) -> usize {
        self.storage.page_size()
    }

    fn num_pages(&self) -> usize {
        self.storage.num_pages()
    }

    fn max_word_writes(&self) -> usize {
        self.storage.max_word_writes()
    }

    fn max_page_erases(&self) -> usize {
        self.storage.max_page_erases()
    }

    fn read_slice(&self, index: StorageIndex, length: usize) -> StorageResult<&[u8]> {
        self.storage.read_slice(index, length)
    }

    fn write_slice(&mut self, index: StorageIndex, value: &[u8]) -> StorageResult<()> {
        self.backing_file.seek(SeekFrom::Start(
            (index.page * self.page_size() + index.byte) as u64,
        ))?;
        self.backing_file.write_all(value)?;
        self.storage.write_slice(index, value)
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        self.backing_file
            .seek(SeekFrom::Start((page * self.page_size()) as u64))?;
        self.backing_file
            .write_all(&vec![0xffu8; self.page_size()][..])?;
        self.storage.erase_page(page)
    }
}

impl core::fmt::Display for FileStorage {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        self.storage.fmt(f)
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
