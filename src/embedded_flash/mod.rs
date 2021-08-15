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

#[cfg(feature = "std")]
mod buffer_upgrade;
mod helper;
#[cfg(not(feature = "std"))]
mod syscall;
mod upgrade_storage;

pub use upgrade_storage::UpgradeStorage;

/// Definitions for production.
#[cfg(not(feature = "std"))]
mod prod {
    use super::syscall::{SyscallStorage, SyscallUpgradeStorage};

    pub type Storage = SyscallStorage;

    pub fn new_storage() -> persistent_store::StorageResult<Storage> {
        Storage::new()
    }

    pub type UpgradeLocations = SyscallUpgradeStorage;
}
#[cfg(not(feature = "std"))]
pub use self::prod::{new_storage, Storage, UpgradeLocations};

/// Definitions for testing.
#[cfg(feature = "std")]
mod test {
    use super::buffer_upgrade::BufferUpgradeStorage;

    pub type Storage = persistent_store::BufferStorage;

    pub fn new_storage() -> persistent_store::StorageResult<Storage> {
        // Use the Nordic configuration.
        const PAGE_SIZE: usize = 0x1000;
        const NUM_PAGES: usize = 20;
        let store = vec![0xff; NUM_PAGES * PAGE_SIZE].into_boxed_slice();
        let options = persistent_store::BufferOptions {
            word_size: 4,
            page_size: PAGE_SIZE,
            max_word_writes: 2,
            max_page_erases: 10000,
            strict_mode: true,
        };
        Ok(Storage::new(store, options))
    }

    pub type UpgradeLocations = BufferUpgradeStorage;
}
#[cfg(feature = "std")]
pub use self::test::{new_storage, Storage, UpgradeLocations};
