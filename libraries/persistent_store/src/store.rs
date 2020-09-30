// Copyright 2019-2020 Google LLC
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

use crate::StorageError;

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// Invalid argument.
    ///
    /// The store is left unchanged. The operation will repeatedly fail until the argument is fixed.
    InvalidArgument,

    /// Not enough capacity.
    ///
    /// The store is left unchanged. The operation will repeatedly fail until capacity is freed.
    NoCapacity,

    /// Reached end of lifetime.
    ///
    /// The store is left unchanged. The operation will repeatedly fail until emergency lifetime is
    /// added.
    NoLifetime,

    /// A storage operation failed.
    ///
    /// The consequences depend on the storage failure. In particular, the operation may or may not
    /// have succeeded, and the storage may have become invalid. Before doing any other operation,
    /// the store should be [recovered]. The operation may then be retried if idempotent.
    ///
    /// [recovered]: struct.Store.html#method.recover
    StorageError,

    /// Storage is invalid.
    ///
    /// The storage should be erased and the store [recovered]. The store would be empty and have
    /// lost track of lifetime.
    ///
    /// [recovered]: struct.Store.html#method.recover
    InvalidStorage,
}

impl From<StorageError> for StoreError {
    fn from(error: StorageError) -> StoreError {
        match error {
            StorageError::CustomError => StoreError::StorageError,
            // The store always calls the storage correctly.
            StorageError::NotAligned | StorageError::OutOfBounds => unreachable!(),
        }
    }
}

pub type StoreResult<T> = Result<T, StoreError>;
