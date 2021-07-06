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

#[cfg(any(test, not(feature = "std")))]
mod helper;
#[cfg(not(feature = "std"))]
mod syscall;

#[cfg(not(feature = "std"))]
pub use self::syscall::SyscallStorage;

/// Storage definition for production.
#[cfg(not(feature = "std"))]
mod prod {
    pub type Storage = super::SyscallStorage;

    pub fn new_storage(num_pages: usize) -> Storage {
        Storage::new(num_pages).unwrap()
    }
}
#[cfg(not(feature = "std"))]
pub use self::prod::{new_storage, Storage};

/// Partition definition for production.
#[cfg(not(feature = "std"))]
pub use self::syscall::UpgradeLocations;

/// Definitions for testing.
#[cfg(feature = "std")]
mod test {
    use persistent_store::{StorageError, StorageResult};

    const PAGE_SIZE: usize = 0x1000;

    pub type Storage = persistent_store::BufferStorage;

    pub fn new_storage(num_pages: usize) -> Storage {
        let store = vec![0xff; num_pages * PAGE_SIZE].into_boxed_slice();
        let options = persistent_store::BufferOptions {
            word_size: 4,
            page_size: PAGE_SIZE,
            max_word_writes: 2,
            max_page_erases: 10000,
            strict_mode: true,
        };
        Storage::new(store, options)
    }

    fn is_page_aligned(x: usize) -> bool {
        x & (PAGE_SIZE - 1) == 0
    }

    /// Mock implementation of a partition, only tests page alignment.
    pub struct UpgradeLocations;

    impl UpgradeLocations {
        pub fn new() -> StorageResult<UpgradeLocations> {
            Ok(UpgradeLocations)
        }

        pub fn is_page_in_partition(&self, page_address: usize) -> bool {
            is_page_aligned(page_address)
        }

        pub fn is_page_in_metadata(&self, page_address: usize) -> bool {
            is_page_aligned(page_address)
        }

        pub fn rewrite_page(&self, page_ptr: usize, value: &[u8]) -> StorageResult<()> {
            if !is_page_aligned(page_ptr) || value.len() != PAGE_SIZE {
                return Err(StorageError::NotAligned);
            }
            Ok(())
        }
    }
}
#[cfg(feature = "std")]
pub use self::test::{new_storage, Storage};

#[cfg(feature = "std")]
pub use self::test::UpgradeLocations;
