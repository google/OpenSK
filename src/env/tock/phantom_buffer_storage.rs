// Copyright 2023 Google LLC
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

use alloc::borrow::Cow;
use core::marker::PhantomData;
use libtock_platform as platform;
use libtock_platform::Syscalls;
use persistent_store::{
    BufferCorruptFunction, BufferOptions, BufferStorage, Storage, StorageIndex, StorageResult,
};

/// Wrapper with phantom data for the test storage implementation.
pub struct PhantomBufferStorage<
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
> {
    storage: BufferStorage,
    s: PhantomData<S>,
    c: PhantomData<C>,
}

impl<S, C> PhantomBufferStorage<S, C>
where
    S: Syscalls,
    C: platform::allow_ro::Config + platform::subscribe::Config,
{
    pub fn new(storage: Box<[u8]>, options: BufferOptions) -> Self {
        Self {
            storage: BufferStorage::new(storage, options),
            s: PhantomData,
            c: PhantomData,
        }
    }

    pub fn arm_interruption(&mut self, delay: usize) {
        self.storage.arm_interruption(delay);
    }

    pub fn disarm_interruption(&mut self) -> usize {
        self.storage.disarm_interruption()
    }

    pub fn reset_interruption(&mut self) {
        self.storage.reset_interruption();
    }

    pub fn corrupt_operation(&mut self, corrupt: BufferCorruptFunction) {
        self.storage.corrupt_operation(corrupt);
    }

    pub fn get_word_writes(&self, word: usize) -> usize {
        self.storage.get_word_writes(word)
    }

    pub fn get_page_erases(&self, page: usize) -> usize {
        self.storage.get_page_erases(page)
    }

    pub fn set_page_erases(&mut self, page: usize, cycle: usize) {
        self.storage.set_page_erases(page, cycle);
    }
}

impl<S, C> Storage for PhantomBufferStorage<S, C>
where
    S: Syscalls,
    C: platform::allow_ro::Config + platform::subscribe::Config,
{
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

    fn read_slice(&self, index: StorageIndex, length: usize) -> StorageResult<Cow<[u8]>> {
        self.storage.read_slice(index, length)
    }

    fn write_slice(&mut self, index: StorageIndex, value: &[u8]) -> StorageResult<()> {
        self.storage.write_slice(index, value)
    }

    fn erase_page(&mut self, page: usize) -> StorageResult<()> {
        self.storage.erase_page(page)
    }
}
