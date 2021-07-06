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

use core::ops::RangeInclusive;
use persistent_store::{StorageError, StorageResult};

/// Returns a slice from a list of slices that contains the interval [start, start+length).
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

/// Checks whether the address is aligned with the block_size.
///
/// Requires block_size to be a power of two.
pub fn is_aligned(block_size: usize, address: usize) -> bool {
    address & (block_size - 1) == 0
}

/// Returns a range object.
///
/// If the range contains indices outside of usize, it returns an empty range.
#[allow(clippy::reversed_empty_ranges)]
pub fn create_range(ptr: usize, len: usize) -> RangeInclusive<usize> {
    if len == 0 {
        return 1..=0;
    }
    if let Some(end) = ptr.checked_add(len - 1) {
        ptr..=end
    } else {
        1..=0
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
    fn partition_slice_contains() {
        let ptr = 0x200;
        let len = 0x100;
        let range = create_range(ptr, len);
        assert!(!range.contains(&0x300));
        for i in ptr..ptr + len {
            assert!(range.contains(&i));
        }
        for i in ptr - len..ptr {
            assert!(!range.contains(&i));
        }
        for i in ptr + len..ptr + 2 * len {
            assert!(!range.contains(&i));
        }
        assert!(!create_range(0, 0).contains(&0));
        assert!(create_range(usize::MAX, 1).contains(&usize::MAX));
        assert!(!create_range(usize::MAX, 2).contains(&usize::MAX));
    }
}
