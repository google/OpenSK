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
use alloc::vec::Vec;

/// Errors returned by store operations.
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

/// Result of store operations.
pub type StoreResult<T> = Result<T, StoreError>;

/// Progression ratio for store metrics.
///
/// This is used for the [capacity] and [lifetime] metrics. Those metrics are measured in words.
///
/// # Invariant
///
/// - The used value does not exceed the total: `used <= total`.
///
/// [capacity]: struct.Store.html#method.capacity
/// [lifetime]: struct.Store.html#method.lifetime
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct StoreRatio {
    /// How much of the metric is used.
    pub(crate) used: usize,

    /// How much of the metric can be used at most.
    pub(crate) total: usize,
}

impl StoreRatio {
    /// How much of the metric is used.
    pub fn used(self) -> usize {
        self.used
    }

    /// How much of the metric can be used at most.
    pub fn total(self) -> usize {
        self.total
    }

    /// How much of the metric is remaining.
    pub fn remaining(self) -> usize {
        self.total - self.used
    }
}

/// Represents an update to the store as part of a transaction.
#[derive(Clone, Debug)]
pub enum StoreUpdate {
    /// Inserts or replaces an entry in the store.
    Insert { key: usize, value: Vec<u8> },

    /// Removes an entry from the store.
    Remove { key: usize },
}

impl StoreUpdate {
    /// Returns the key affected by the update.
    pub fn key(&self) -> usize {
        match *self {
            StoreUpdate::Insert { key, .. } => key,
            StoreUpdate::Remove { key } => key,
        }
    }

    /// Returns the value written by the update.
    pub fn value(&self) -> Option<&[u8]> {
        match self {
            StoreUpdate::Insert { value, .. } => Some(value),
            StoreUpdate::Remove { .. } => None,
        }
    }
}
