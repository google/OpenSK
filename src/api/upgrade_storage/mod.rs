// Copyright 2021-2022 Google LLC
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

pub(crate) mod helper;

/// Accessors to storage locations used for upgrading from a CTAP command.
pub trait UpgradeStorage {
    /// Reads a slice of the partition, if within bounds.
    ///
    /// The offset is relative to the start of the partition, excluding holes. The partition is
    /// presented as one connected component. Therefore, the offset does not easily translate
    /// to physical memory address address of the slice.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::OutOfBounds`] if the requested slice is not inside the partition.
    fn read_partition(&self, offset: usize, length: usize) -> StorageResult<&[u8]>;

    /// Writes the given data to the given offset address, if within bounds of the partition.
    ///
    /// The offset is relative to the start of the partition, excluding holes.
    /// See `read_partition`.
    ///
    /// # Errors
    ///
    /// - Returns [`StorageError::OutOfBounds`] if the data does not fit the partition.
    /// - Returns [`StorageError::CustomError`] if any Metadata check fails.
    fn write_partition(&mut self, offset: usize, data: &[u8]) -> StorageResult<()>;

    /// Returns an identifier for the partition.
    ///
    /// Use this to determine whether you are writing to A or B.
    fn partition_identifier(&self) -> u32;

    /// Returns the length of the partition.
    fn partition_length(&self) -> usize;

    /// Returns the currently running firmware version.
    fn running_firmware_version(&self) -> u64;
}
