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

use alloc::vec::Vec;
use persistent_store::StorageResult;

pub(crate) mod helper;

/// Accessors to storage locations used for upgrading from a CTAP command.
pub trait UpgradeStorage {
    /// Processes the given data as part of an upgrade.
    ///
    /// The offset indicates the data location inside the bundle.
    ///
    /// # Errors
    ///
    /// - Returns [`StorageError::OutOfBounds`] if the data does not fit.
    /// - Returns [`StorageError::CustomError`] if any Metadata or other check fails.
    fn write_bundle(&mut self, offset: usize, data: Vec<u8>) -> StorageResult<()>;

    /// Returns an identifier for the requested bundle.
    ///
    /// Use this to determine whether you are writing to A or B.
    fn bundle_identifier(&self) -> u32;

    /// Returns the currently running firmware version.
    fn running_firmware_version(&self) -> u64;
}
