// Copyright 2019-2023 Google LLC
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

use alloc::vec::Vec;
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
#[derive(Clone, Debug, PartialEq, Eq)]
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

    /// Returns the disjoint union with the other range, if consecutive.
    ///
    /// Appending empty ranges is not possible.
    /// Appending to the empty range returns the other range.
    ///
    /// Returns true if successful.
    pub fn append(&mut self, other: &ModRange) -> bool {
        if self.is_empty() {
            self.start = other.start;
            self.length = other.length;
            return true;
        }
        if other.is_empty() {
            return false;
        }
        if self.start >= other.start {
            return false;
        }
        if self.length != other.start - self.start {
            return false;
        }
        if let Some(new_length) = self.length.checked_add(other.length) {
            self.length = new_length;
            true
        } else {
            false
        }
    }

    /// Helper function to check whether a range starts within another.
    fn starts_inside(&self, range: &ModRange) -> bool {
        !range.is_empty() && self.start >= range.start && self.start - range.start < range.length
    }

    /// Returns whether the given range has intersects.
    ///
    /// Mathematically, we calculate whether: `self ∩ range ≠ ∅`.
    pub fn intersects_range(&self, range: &ModRange) -> bool {
        self.starts_inside(range) || range.starts_inside(self)
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
    pub fn aligned_iter(&self, modulus: usize) -> impl Iterator<Item = usize> {
        (self.start..=usize::MAX)
            .take(self.length)
            // Skip the minimum number of elements to align.
            .skip((modulus - self.start % modulus) % modulus)
            // Only return aligned elements.
            .step_by(modulus)
    }
}

#[derive(Default)]
pub struct Partition {
    ranges: Vec<ModRange>,
}

impl Partition {
    /// Total length of all ranges.
    pub fn length(&self) -> usize {
        self.ranges.iter().map(|r| r.length()).sum()
    }

    /// Appends the given range.
    ///
    /// Ranges should be appending with ascending start addresses.
    pub fn append(&mut self, range: ModRange) -> bool {
        if let Some(last_range) = self.ranges.last_mut() {
            if range.start() <= last_range.start()
                || range.start() - last_range.start() < last_range.length()
            {
                return false;
            }
            if !last_range.append(&range) {
                self.ranges.push(range);
            }
        } else {
            self.ranges.push(range);
        }
        true
    }

    /// Returns the start address that corresponds to the given offset.
    ///
    /// If the offset bigger than the accumulated length or the requested slice doesn't fit a
    /// connected component, return `None`.
    pub fn find_address(&self, mut offset: usize, length: usize) -> Option<usize> {
        for range in &self.ranges {
            if offset < range.length() {
                return if range.length() - offset >= length {
                    Some(range.start() + offset)
                } else {
                    None
                };
            }
            offset -= range.length()
        }
        None
    }

    pub fn ranges_from(&self, start_address: usize) -> Vec<ModRange> {
        let mut result = Vec::new();
        for range in &self.ranges {
            match start_address.checked_sub(range.start()) {
                None | Some(0) => result.push(range.clone()),
                Some(offset) => {
                    if range.length() > offset {
                        result.push(ModRange::new(start_address, range.length() - offset));
                    }
                }
            }
        }
        result
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
        let mut range = ModRange::new(200, 100);
        assert!(range.append(&ModRange::new(300, 400)));
        assert!(range.start() == 200);
        assert!(range.length() == 500);
        assert!(!range.append(&ModRange::new(499, 400)));
        assert!(!range.append(&ModRange::new(501, 400)));
        assert!(!range.append(&ModRange::new(300, 400)));
        let mut range = ModRange::new_empty();
        assert!(range.append(&ModRange::new(200, 100)));
        assert!(range.start() == 200);
        assert!(range.length() == 100);
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
    fn mod_range_intersects_range() {
        let range = ModRange::new(200, 100);
        assert!(range.intersects_range(&ModRange::new(200, 1)));
        assert!(range.intersects_range(&ModRange::new(299, 1)));
        assert!(!range.intersects_range(&ModRange::new(199, 1)));
        assert!(!range.intersects_range(&ModRange::new(300, 1)));
        assert!(!ModRange::new_empty().intersects_range(&ModRange::new_empty()));
        assert!(!ModRange::new_empty().intersects_range(&ModRange::new(200, 100)));
        assert!(!ModRange::new(200, 100).intersects_range(&ModRange::new_empty()));
        assert!(ModRange::new(usize::MAX, 1).intersects_range(&ModRange::new(usize::MAX, 1)));
        assert!(ModRange::new(usize::MAX, 2).intersects_range(&ModRange::new(usize::MAX, 2)));
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
        assert_eq!(iter.next(), Some(0xffff_ffff_ffff_fff0));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn partition_append() {
        let mut partition = Partition::default();
        partition.append(ModRange::new(0x4000, 0x1000));
        partition.append(ModRange::new(0x20000, 0x20000));
        partition.append(ModRange::new(0x40000, 0x20000));
        assert_eq!(partition.find_address(0, 1), Some(0x4000));
        assert_eq!(partition.length(), 0x41000);
    }

    #[test]
    fn partition_find_address() {
        let mut partition = Partition::default();
        partition.append(ModRange::new(0x4000, 0x1000));
        partition.append(ModRange::new(0x20000, 0x20000));
        partition.append(ModRange::new(0x40000, 0x20000));
        assert_eq!(partition.find_address(0, 0x1000), Some(0x4000));
        assert_eq!(partition.find_address(0x1000, 0x1000), Some(0x20000));
        assert_eq!(partition.find_address(0x20000, 0x1000), Some(0x3F000));
        assert_eq!(partition.find_address(0x21000, 0x1000), Some(0x40000));
        assert_eq!(partition.find_address(0x40000, 0x1000), Some(0x5F000));
        assert_eq!(partition.find_address(0x41000, 0x1000), None);
        assert_eq!(partition.find_address(0x40000, 0x2000), None);
    }

    #[test]
    fn partition_ranges_from() {
        let mut partition = Partition::default();
        partition.append(ModRange::new(0x4000, 0x1000));
        partition.append(ModRange::new(0x20000, 0x20000));
        partition.append(ModRange::new(0x40000, 0x20000));
        let all_ranges = partition.ranges_from(0);
        let from_start_ranges = partition.ranges_from(0x4000);
        assert_eq!(&all_ranges, &from_start_ranges);
        assert_eq!(all_ranges.len(), 2);
        assert_eq!(all_ranges[0], ModRange::new(0x4000, 0x1000));
        assert_eq!(all_ranges[1], ModRange::new(0x20000, 0x40000));
        let second_range = partition.ranges_from(0x20000);
        let same_second_range = partition.ranges_from(0x1F000);
        assert_eq!(&second_range, &same_second_range);
        assert_eq!(&second_range, &all_ranges[1..]);
        let partial_range = partition.ranges_from(0x30000);
        assert_eq!(partial_range[0], ModRange::new(0x30000, 0x30000));
    }
}
