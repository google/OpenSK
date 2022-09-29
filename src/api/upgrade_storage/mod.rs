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
    /// Writes the given data to the given offset address, if within bounds of the partition.
    ///
    /// The offset is relative to the start of the partition, excluding holes.
    /// See `read_partition`.
    ///
    /// The hash is the SHA256 of the data slice. This hash is not a security feature, use it to
    /// check your data integrity.
    ///
    /// # Errors
    ///
    /// - Returns [`StorageError::OutOfBounds`] if the data does not fit the partition.
    /// - Returns [`StorageError::CustomError`] if any Metadata or hash check fails.
    fn write_partition(&mut self, offset: usize, data: &[u8], hash: &[u8; 32])
        -> StorageResult<()>;

    /// Returns an identifier for the partition.
    ///
    /// Use this to determine whether you are writing to A or B.
    fn partition_identifier(&self) -> u32;

    /// Returns the currently running firmware version.
    fn running_firmware_version(&self) -> u64;
}
