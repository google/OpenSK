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
        if length == 0 {
            return Ok(&[]);
        }
        let partition_range = ModRange::new(0, self.partition.len());
        if partition_range.contains_range(&ModRange::new(offset, length)) {
            Ok(&self.partition[offset..][..length])
        } else {
            Err(StorageError::OutOfBounds)
        }
    }

    fn write_partition(&mut self, offset: usize, data: &[u8]) -> StorageResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        let partition_range = ModRange::new(0, self.partition.len());
        if partition_range.contains_range(&ModRange::new(offset, data.len())) {
            self.partition[offset..][..data.len()].copy_from_slice(data);
            Ok(())
        } else {
            Err(StorageError::OutOfBounds)
        }
    }

    fn partition_address(&self) -> usize {
        0x60000
    }

    fn partition_length(&self) -> usize {
        PARTITION_LENGTH
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
            Err(StorageError::OutOfBounds)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_partition() {
        let mut storage = BufferUpgradeStorage::new().unwrap();
        assert_eq!(storage.read_partition(0, 2).unwrap(), &[0xFF, 0xFF]);
        assert!(storage.write_partition(1, &[0x88, 0x88]).is_ok());
        assert_eq!(storage.read_partition(0, 2).unwrap(), &[0xFF, 0x88]);
        assert_eq!(
            storage.write_partition(PARTITION_LENGTH - 1, &[0x88, 0x88]),
            Err(StorageError::OutOfBounds)
        );
        assert_eq!(
            storage.read_partition(PARTITION_LENGTH - 2, 2).unwrap(),
            &[0xFF, 0xFF]
        );
        assert_eq!(
            storage.read_partition(PARTITION_LENGTH - 1, 2),
            Err(StorageError::OutOfBounds)
        );
        assert_eq!(
            storage.read_partition(PARTITION_LENGTH + 1, 0).unwrap(),
            &[]
        );
        assert!(storage.write_partition(4, &[]).is_ok());
        assert!(storage.write_partition(PARTITION_LENGTH + 4, &[]).is_ok());
    }

    #[test]
    fn partition_slice() {
        let storage = BufferUpgradeStorage::new().unwrap();
        assert_eq!(storage.partition_address(), 0x60000);
        assert_eq!(storage.partition_length(), PARTITION_LENGTH);
    }

    #[test]
    fn read_write_metadata() {
        let mut storage = BufferUpgradeStorage::new().unwrap();
        assert_eq!(storage.read_metadata().unwrap(), &[0xFF; METADATA_LENGTH]);
        assert!(storage.write_metadata(&[0x88, 0x88]).is_ok());
        assert_eq!(
            storage.write_metadata(&[0x88; METADATA_LENGTH + 1]),
            Err(StorageError::OutOfBounds)
        );
        let new_metadata = storage.read_metadata().unwrap();
        assert_eq!(&new_metadata[0..2], &[0x88, 0x88]);
        assert_eq!(&new_metadata[2..], &[0xFF; METADATA_LENGTH - 2]);
        assert!(storage.write_metadata(&[]).is_ok());
        assert_eq!(storage.read_metadata().unwrap(), &[0xFF; METADATA_LENGTH]);
    }
}
