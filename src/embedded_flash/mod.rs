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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UpgradeIdentifier {
    A = 0,
    B = 1,
}

pub use upgrade_storage::UpgradeStorage;

/// Definitions for production.
#[cfg(not(feature = "std"))]
mod prod {
    use super::syscall::{SyscallStorage, SyscallUpgradeStorage};

    pub type Storage = SyscallStorage;

    pub fn new_storage(num_pages: usize) -> Storage {
        Storage::new(num_pages).unwrap()
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

    pub fn new_storage(num_pages: usize) -> Storage {
        const PAGE_SIZE: usize = 0x1000;
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

    pub type UpgradeLocations = BufferUpgradeStorage;
}
#[cfg(feature = "std")]
pub use self::test::{new_storage, Storage, UpgradeLocations};
