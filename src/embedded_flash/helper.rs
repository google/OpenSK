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

// For compiling with std outside of tests.
#![cfg_attr(feature = "std", allow(dead_code))]

use core::iter::Iterator;
use persistent_store::{StorageError, StorageResult};

/// Reads a slice from a list of slices.
///
/// The returned slice contains the interval `[start, start+length)`.
///
/// # Errors
///
/// Returns [`StorageError::OutOfBounds`] if the range is not within exactly one slice.
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
///
/// The range is treated as the interval `[start, start + length)`.
/// All objects with length of 0, regardless of the start value, are considered empty.
pub struct ModRange {
    start: usize,
    length: usize,
}

impl ModRange {
    /// Returns a new range of given start and length.
    pub fn new(start: usize, length: usize) -> ModRange {
        ModRange { start, length }
    }

    /// Create a new empty range.
    pub fn new_empty() -> ModRange {
        ModRange::new(0, 0)
    }

    /// Returns the start of the range.
    pub fn start(&self) -> usize {
        self.start
    }

    /// Returns the length of the range.
    pub fn length(&self) -> usize {
        self.length
    }

    /// Returns whether this range contains any addresses.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the disjoint union with the other range, if is consecutive.
    ///
    /// Appending empty ranges is not possible.
    /// Appending to the empty range returns the other range.
    pub fn append(&self, other: ModRange) -> Option<ModRange> {
        if self.is_empty() {
            return Some(other);
        }
        if other.is_empty() {
            return None;
        }
        if self.start >= other.start {
            return None;
        }
        if self.length != other.start - self.start {
            return None;
        }
        let new_length = self.length.checked_add(other.length);
        new_length.map(|l| ModRange::new(self.start, l))
    }

    /// Returns whether the given range is fully contained.
    ///
    /// Mathematically, we calculate whether: `self ∩ range = range`.
    pub fn contains_range(&self, range: &ModRange) -> bool {
        range.is_empty()
            || (self.start <= range.start
                && range.length <= self.length
                && range.start - self.start <= self.length - range.length)
    }

    /// Returns an iterator for all contained numbers that are divisible by the modulus.
    ///
    /// Be aware that `usize::MAX` is a special case for simplicity. It is never in the returned
    /// iterator, even when divisible by `modulus` and contained in the range.
    pub fn aligned_iter(&self, modulus: usize) -> impl Iterator<Item = usize> {
        let remainder = self.start % modulus;
        // Saturating first and limit in case they are usize::MAX.
        let first = if remainder == 0 {
            self.start
        } else {
            (self.start - remainder).saturating_add(modulus)
        };
        let limit = self.start.saturating_add(self.length);
        (first..limit).step_by(modulus)
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
    fn mod_range_parameters() {
        let range = ModRange::new(200, 100);
        assert_eq!(range.start(), 200);
        assert_eq!(range.length(), 100);
        assert_eq!(ModRange::new_empty().length(), 0);
    }

    #[test]
    fn mod_range_is_empty() {
        assert!(!ModRange::new(200, 100).is_empty());
        assert!(ModRange::new(200, 0).is_empty());
        assert!(ModRange::new_empty().is_empty());
        assert!(!ModRange::new(usize::MAX, 2).is_empty());
    }

    #[test]
    fn mod_range_append() {
        let range = ModRange::new(200, 100);
        let new_range = range.append(ModRange::new(300, 400)).unwrap();
        assert!(new_range.start() == 200);
        assert!(new_range.length() == 500);
        assert!(range.append(ModRange::new(299, 400)).is_none());
        assert!(range.append(ModRange::new(301, 400)).is_none());
        assert!(range.append(ModRange::new(200, 400)).is_none());
        let empty_append = ModRange::new_empty()
            .append(ModRange::new(200, 100))
            .unwrap();
        assert!(empty_append.start() == 200);
        assert!(empty_append.length() == 100);
    }

    #[test]
    fn mod_range_contains_range() {
        let range = ModRange::new(200, 100);
        assert!(!range.contains_range(&ModRange::new(199, 100)));
        assert!(!range.contains_range(&ModRange::new(201, 100)));
        assert!(!range.contains_range(&ModRange::new(199, 99)));
        assert!(!range.contains_range(&ModRange::new(202, 99)));
        assert!(!range.contains_range(&ModRange::new(200, 101)));
        assert!(range.contains_range(&ModRange::new(200, 100)));
        assert!(range.contains_range(&ModRange::new(200, 99)));
        assert!(range.contains_range(&ModRange::new(201, 99)));
        assert!(ModRange::new_empty().contains_range(&ModRange::new_empty()));
        assert!(ModRange::new(usize::MAX, 1).contains_range(&ModRange::new(usize::MAX, 1)));
        assert!(ModRange::new(usize::MAX, 2).contains_range(&ModRange::new(usize::MAX, 2)));
    }

    #[test]
    fn mod_range_aligned_iter() {
        let mut iter = ModRange::new(200, 100).aligned_iter(100);
        assert_eq!(iter.next(), Some(200));
        assert_eq!(iter.next(), None);
        let mut iter = ModRange::new(200, 101).aligned_iter(100);
        assert_eq!(iter.next(), Some(200));
        assert_eq!(iter.next(), Some(300));
        assert_eq!(iter.next(), None);
        let mut iter = ModRange::new(199, 100).aligned_iter(100);
        assert_eq!(iter.next(), Some(200));
        assert_eq!(iter.next(), None);
        let mut iter = ModRange::new(201, 99).aligned_iter(100);
        assert_eq!(iter.next(), None);
        let mut iter = ModRange::new(usize::MAX - 16, 20).aligned_iter(16);
        assert_eq!(iter.next(), Some(0xf_fff_fff_fff_fff_ff0));
        assert_eq!(iter.next(), None);
    }
}
