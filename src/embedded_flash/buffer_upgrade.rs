// Copyright 2021 Google LLC
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

use super::helper::ModRange;
use super::upgrade_storage::UpgradeStorage;
use alloc::boxed::Box;
use persistent_store::{StorageError, StorageResult};

const PARTITION_START: usize = 0x20000;
const PARTITION_LENGTH: usize = 0x40000;
const METADATA_LENGTH: usize = 0x1000;

pub struct BufferUpgradeStorage {
    /// Content of the partition storage.
    partition: Box<[u8]>,

    /// Content of the metadata storage.
    metadata: Box<[u8]>,
}

impl BufferUpgradeStorage {
    pub fn new() -> StorageResult<BufferUpgradeStorage> {
        Ok(BufferUpgradeStorage {
            partition: vec![0xff; PARTITION_LENGTH].into_boxed_slice(),
            metadata: vec![0xff; METADATA_LENGTH].into_boxed_slice(),
        })
    }
}

impl UpgradeStorage for BufferUpgradeStorage {
    fn read_partition(&self, offset: usize, length: usize) -> StorageResult<&[u8]> {
        let partition_range = ModRange::new(PARTITION_START, self.partition.len());
        if partition_range.contains_range(&ModRange::new(offset, length)) {
            Ok(&self.partition[offset - PARTITION_START..][..length])
        } else {
            Err(StorageError::OutOfBounds)
        }
    }

    fn write_partition(&mut self, offset: usize, data: &[u8]) -> StorageResult<()> {
        let partition_range = ModRange::new(PARTITION_START, self.partition.len());
        if partition_range.contains_range(&ModRange::new(offset, data.len())) {
            self.partition[offset - PARTITION_START..][..data.len()].copy_from_slice(data);
            Ok(())
        } else {
            Err(StorageError::OutOfBounds)
        }
    }

    fn read_metadata(&self) -> StorageResult<&[u8]> {
        Ok(&self.metadata[..])
    }

    fn write_metadata(&mut self, data: &[u8]) -> StorageResult<()> {
        if data.len() <= METADATA_LENGTH {
            self.metadata.copy_from_slice(&[0xff; METADATA_LENGTH]);
            self.metadata[..data.len()].copy_from_slice(data);
            Ok(())
        } else {
            Err(StorageError::NotAligned)
        }
    }
}
