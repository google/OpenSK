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

use persistent_store::StorageResult;

/// Accessors to storage locations used for upgrading from a CTAP command.
pub trait UpgradeStorage {
    /// Reads a slice of the partition, if within bounds.
    ///
    /// The offset is relative to the start of the partition.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::OutOfBounds`] if the requested slice is not inside the partition.
    fn read_partition(&self, offset: usize, length: usize) -> StorageResult<&[u8]>;

    /// Writes the given data to the given offset address, if within bounds of the partition.
    ///
    /// The offset is relative to the start of the partition.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::OutOfBounds`] if the data does not fit the partition.
    fn write_partition(&mut self, offset: usize, data: &[u8]) -> StorageResult<()>;

    /// Returns the length of the partition.
    fn partition_length(&self) -> usize;

    /// Reads the metadata location.
    fn read_metadata(&self) -> StorageResult<&[u8]>;

    /// Writes the given data into the metadata location.
    ///
    /// The passed in data is appended with 0xFF bytes if shorter than the metadata storage.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::OutOfBounds`] if the data is too long to fit the metadata storage.
    fn write_metadata(&mut self, data: &[u8]) -> StorageResult<()>;
}
