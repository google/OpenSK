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

use persistent_store::{StorageError, StorageResult};

/// Reads a slice from a list of slices.
///
/// The returned slice contains the interval `[start, start+length)`.
///
/// # Preconditions
///
/// - The passed in slices must not overlap.
/// - The requested slice must fit entirely within a single one of the slices.
pub fn find_slice<'a>(
    slices: &'a [&'a [u8]],
    mut start: usize,
    length: usize,
) -> StorageResult<&'a [u8]> {
    for slice in slices {
        if start >= slice.len() {
            start -= slice.len();
            continue;
        }
        if start + length > slice.len() {
            break;
        }
        return Ok(&slice[start..][..length]);
    }
    Err(StorageError::OutOfBounds)
}

/// Checks whether the address is aligned with the block size.
///
/// Requires `block_size` to be a power of two.
pub fn is_aligned(block_size: usize, address: usize) -> bool {
    debug_assert!(block_size.is_power_of_two());
    address & (block_size - 1) == 0
}

/// A range implementation using start and length.
pub struct ModRange {
    start: usize,
    length: usize,
}

impl ModRange {
    /// Returns a new range of given start and length.
    ///
    /// If the largest contained address would overflow the address space, return an empty range.
    pub fn new(start: usize, length: usize) -> Self {
        if start.checked_add(length - 1).is_none() {
            return Self::new_empty();
        }
        ModRange { start, length }
    }

    /// Create a new empty range.
    pub fn new_empty() -> Self {
        ModRange {
            start: 0,
            length: 0,
        }
    }

    /// Returns whether this range contains any addresses.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns whether the given address is inside the range.
    pub fn contains(&self, x: usize) -> bool {
        // We want to check the 2 following inequalities:
        // (1) `start <= x`
        // (2) `x < start + length`
        // However, the second one may overflow written as is. Using (1), we rewrite to:
        // (3) `x - start <= length`
        self.start <= x && x - self.start < self.length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_slice_ok() {
        assert_eq!(
            find_slice(&[&[1, 2, 3, 4]], 0, 4).ok(),
            Some(&[1u8, 2, 3, 4] as &[u8])
        );
        assert_eq!(
            find_slice(&[&[1, 2, 3, 4], &[5, 6]], 1, 2).ok(),
            Some(&[2u8, 3] as &[u8])
        );
        assert_eq!(
            find_slice(&[&[1, 2, 3, 4], &[5, 6]], 4, 2).ok(),
            Some(&[5u8, 6] as &[u8])
        );
        assert_eq!(
            find_slice(&[&[1, 2, 3, 4], &[5, 6]], 4, 0).ok(),
            Some(&[] as &[u8])
        );
        assert!(find_slice(&[], 0, 1).is_err());
        assert!(find_slice(&[&[1, 2, 3, 4], &[5, 6]], 6, 0).is_err());
        assert!(find_slice(&[&[1, 2, 3, 4], &[5, 6]], 3, 2).is_err());
    }

    #[test]
    fn alignment() {
        for exponent in 0..8 {
            let block_size = 1 << exponent;
            for i in 0..10 {
                assert!(is_aligned(block_size, block_size * i));
            }
            for i in 1..block_size {
                assert!(!is_aligned(block_size, block_size + i));
            }
        }
    }

    #[test]
    fn mod_range_is_empty() {
        assert!(!ModRange::new(0x200, 0x100).is_empty());
        assert!(ModRange::new(0x200, 0).is_empty());
        assert!(ModRange::new_empty().is_empty());
        assert!(ModRange::new(usize::MAX, 2).is_empty());
    }

    #[test]
    fn mod_range_contains() {
        let start = 0x200;
        let length = 0x100;
        let range = ModRange::new(start, length);
        assert!(!range.contains(0x300));
        for i in start..start + length {
            assert!(range.contains(i));
        }
        for i in start - length..start {
            assert!(!range.contains(i));
        }
        for i in start + length..start + 2 * length {
            assert!(!range.contains(i));
        }
        assert!(!ModRange::new_empty().contains(0));
        assert!(ModRange::new(usize::MAX, 1).contains(usize::MAX));
        assert!(!ModRange::new(usize::MAX, 2).contains(usize::MAX));
    }
}
