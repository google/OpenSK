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

//! Support for fragmented entries.
//!
//! This module permits to handle entries larger than the [maximum value
//! length](Store::max_value_length) by storing ordered consecutive fragments in a sequence of keys.
//! The first keys hold fragments of maximal length, followed by a possibly partial fragment. The
//! remaining keys are not used.

use crate::{Storage, Store, StoreError, StoreHandle, StoreResult, StoreUpdate};
use alloc::vec::Vec;
use core::ops::Range;

/// Represents a sequence of keys.
#[allow(clippy::len_without_is_empty)]
pub trait Keys {
    /// Returns the number of keys.
    fn len(&self) -> usize;

    /// Returns the position of a key in the sequence.
    fn pos(&self, key: usize) -> Option<usize>;

    /// Returns the key of a position in the sequence.
    ///
    /// # Preconditions
    ///
    /// The position must be within the length: `pos` < [`Self::len`].
    fn key(&self, pos: usize) -> usize;
}

impl Keys for Range<usize> {
    fn len(&self) -> usize {
        self.end - self.start
    }

    fn pos(&self, key: usize) -> Option<usize> {
        if self.start <= key && key < self.end {
            Some(key - self.start)
        } else {
            None
        }
    }

    fn key(&self, pos: usize) -> usize {
        debug_assert!(pos < Keys::len(self));
        self.start + pos
    }
}

/// Reads the concatenated value of a sequence of keys.
pub fn read(store: &Store<impl Storage>, keys: &impl Keys) -> StoreResult<Option<Vec<u8>>> {
    let handles = get_handles(store, keys)?;
    if handles.is_empty() {
        return Ok(None);
    }
    let mut result = Vec::with_capacity(handles.len() * store.max_value_length());
    for handle in handles {
        result.extend(handle.get_value(store)?);
    }
    Ok(Some(result))
}

/// Reads a range from the concatenated value of a sequence of keys.
///
/// This is equivalent to calling [`read`] then taking the range except that:
/// - Only the needed chunks are read.
/// - The range is truncated to fit in the value.
pub fn read_range(
    store: &Store<impl Storage>,
    keys: &impl Keys,
    range: Range<usize>,
) -> StoreResult<Option<Vec<u8>>> {
    let range_len = match range.end.checked_sub(range.start) {
        None => return Err(StoreError::InvalidArgument),
        Some(x) => x,
    };
    let handles = get_handles(store, keys)?;
    if handles.is_empty() {
        return Ok(None);
    }
    let mut result = Vec::with_capacity(range_len);
    let mut offset = 0;
    for handle in handles {
        let start = range.start.saturating_sub(offset);
        let length = handle.get_length(store)?;
        let end = core::cmp::min(range.end.saturating_sub(offset), length);
        offset += length;
        if start < end {
            result.extend(&handle.get_value(store)?[start..end]);
        }
    }
    Ok(Some(result))
}

/// Writes a value to a sequence of keys as chunks.
pub fn write(store: &mut Store<impl Storage>, keys: &impl Keys, value: &[u8]) -> StoreResult<()> {
    let handles = get_handles(store, keys)?;
    let keys_len = keys.len();
    let mut updates = Vec::with_capacity(keys_len);
    let mut chunks = value.chunks(store.max_value_length());
    for pos in 0..keys_len {
        let key = keys.key(pos);
        match (handles.get(pos), chunks.next()) {
            // No existing handle and no new chunk: nothing to do.
            (None, None) => (),
            // Existing handle and no new chunk: remove old handle.
            (Some(_), None) => updates.push(StoreUpdate::Remove { key }),
            // Existing handle with same value as new chunk: nothing to do.
            (Some(handle), Some(value)) if handle.get_value(store)? == value => (),
            // New chunk: Write (or overwrite) the new value.
            (_, Some(value)) => updates.push(StoreUpdate::Insert { key, value }),
        }
    }
    if chunks.next().is_some() {
        // The value is too long.
        return Err(StoreError::InvalidArgument);
    }
    store.transaction(&updates)
}

/// Deletes the value of a sequence of keys.
pub fn delete(store: &mut Store<impl Storage>, keys: &impl Keys) -> StoreResult<()> {
    let updates: Vec<StoreUpdate<Vec<u8>>> = get_handles(store, keys)?
        .iter()
        .map(|handle| StoreUpdate::Remove {
            key: handle.get_key(),
        })
        .collect();
    store.transaction(&updates)
}

/// Returns the handles of a sequence of keys.
///
/// The handles are truncated to the keys that are present.
fn get_handles(store: &Store<impl Storage>, keys: &impl Keys) -> StoreResult<Vec<StoreHandle>> {
    let keys_len = keys.len();
    let mut handles: Vec<Option<StoreHandle>> = vec![None; keys_len];
    for handle in store.iter()? {
        let handle = handle?;
        let pos = match keys.pos(handle.get_key()) {
            Some(pos) => pos,
            None => continue,
        };
        if pos >= keys_len {
            return Err(StoreError::InvalidArgument);
        }
        if let Some(old_handle) = &handles[pos] {
            if old_handle.get_key() != handle.get_key() {
                // The user provided a non-injective `pos` function.
                return Err(StoreError::InvalidArgument);
            } else {
                return Err(StoreError::InvalidStorage);
            }
        }
        handles[pos] = Some(handle);
    }
    let num_handles = handles.iter().filter(|x| x.is_some()).count();
    let mut result = Vec::with_capacity(num_handles);
    for (i, handle) in handles.into_iter().enumerate() {
        match (i < num_handles, handle) {
            (true, Some(handle)) => result.push(handle),
            (false, None) => (),
            // We should have `num_handles` Somes followed by Nones.
            _ => return Err(StoreError::InvalidStorage),
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::MINIMAL;

    #[test]
    fn read_empty_entry() {
        let store = MINIMAL.new_store();
        assert_eq!(read(&store, &(0..4)), Ok(None));
    }

    #[test]
    fn read_single_chunk() {
        let mut store = MINIMAL.new_store();
        let value = b"hello".to_vec();
        assert_eq!(store.insert(0, &value), Ok(()));
        assert_eq!(read(&store, &(0..4)), Ok(Some(value)));
    }

    #[test]
    fn read_multiple_chunks() {
        let mut store = MINIMAL.new_store();
        let value: Vec<_> = (0..60).collect();
        assert_eq!(store.insert(0, &value[..52]), Ok(()));
        assert_eq!(store.insert(1, &value[52..]), Ok(()));
        assert_eq!(read(&store, &(0..4)), Ok(Some(value)));
    }

    #[test]
    fn read_range_first_chunk() {
        let mut store = MINIMAL.new_store();
        let value: Vec<_> = (0..60).collect();
        assert_eq!(store.insert(0, &value[..52]), Ok(()));
        assert_eq!(store.insert(1, &value[52..]), Ok(()));
        assert_eq!(
            read_range(&store, &(0..4), 0..10),
            Ok(Some((0..10).collect()))
        );
        assert_eq!(
            read_range(&store, &(0..4), 10..20),
            Ok(Some((10..20).collect()))
        );
        assert_eq!(
            read_range(&store, &(0..4), 40..52),
            Ok(Some((40..52).collect()))
        );
    }

    #[test]
    fn read_range_second_chunk() {
        let mut store = MINIMAL.new_store();
        let value: Vec<_> = (0..60).collect();
        assert_eq!(store.insert(0, &value[..52]), Ok(()));
        assert_eq!(store.insert(1, &value[52..]), Ok(()));
        assert_eq!(read_range(&store, &(0..4), 52..53), Ok(Some(vec![52])));
        assert_eq!(read_range(&store, &(0..4), 53..54), Ok(Some(vec![53])));
        assert_eq!(read_range(&store, &(0..4), 59..60), Ok(Some(vec![59])));
    }

    #[test]
    fn read_range_both_chunks() {
        let mut store = MINIMAL.new_store();
        let value: Vec<_> = (0..60).collect();
        assert_eq!(store.insert(0, &value[..52]), Ok(()));
        assert_eq!(store.insert(1, &value[52..]), Ok(()));
        assert_eq!(
            read_range(&store, &(0..4), 40..60),
            Ok(Some((40..60).collect()))
        );
        assert_eq!(
            read_range(&store, &(0..4), 0..60),
            Ok(Some((0..60).collect()))
        );
    }

    #[test]
    fn read_range_outside() {
        let mut store = MINIMAL.new_store();
        let value: Vec<_> = (0..60).collect();
        assert_eq!(store.insert(0, &value[..52]), Ok(()));
        assert_eq!(store.insert(1, &value[52..]), Ok(()));
        assert_eq!(
            read_range(&store, &(0..4), 40..100),
            Ok(Some((40..60).collect()))
        );
        assert_eq!(read_range(&store, &(0..4), 60..100), Ok(Some(vec![])));
    }

    #[test]
    fn write_single_chunk() {
        let mut store = MINIMAL.new_store();
        let value = b"hello".to_vec();
        assert_eq!(write(&mut store, &(0..4), &value), Ok(()));
        assert_eq!(store.find(0), Ok(Some(value)));
        assert_eq!(store.find(1), Ok(None));
        assert_eq!(store.find(2), Ok(None));
        assert_eq!(store.find(3), Ok(None));
    }

    #[test]
    fn write_multiple_chunks() {
        let mut store = MINIMAL.new_store();
        let value: Vec<_> = (0..60).collect();
        assert_eq!(write(&mut store, &(0..4), &value), Ok(()));
        assert_eq!(store.find(0), Ok(Some((0..52).collect())));
        assert_eq!(store.find(1), Ok(Some((52..60).collect())));
        assert_eq!(store.find(2), Ok(None));
        assert_eq!(store.find(3), Ok(None));
    }

    #[test]
    fn overwrite_less_chunks() {
        let mut store = MINIMAL.new_store();
        let value: Vec<_> = (0..60).collect();
        assert_eq!(store.insert(0, &value[..52]), Ok(()));
        assert_eq!(store.insert(1, &value[52..]), Ok(()));
        let value: Vec<_> = (42..69).collect();
        assert_eq!(write(&mut store, &(0..4), &value), Ok(()));
        assert_eq!(store.find(0), Ok(Some((42..69).collect())));
        assert_eq!(store.find(1), Ok(None));
        assert_eq!(store.find(2), Ok(None));
        assert_eq!(store.find(3), Ok(None));
    }

    #[test]
    fn overwrite_needed_chunks() {
        let mut store = MINIMAL.new_store();
        let mut value: Vec<_> = (0..60).collect();
        assert_eq!(store.insert(0, &value[..52]), Ok(()));
        assert_eq!(store.insert(1, &value[52..]), Ok(()));
        // Current lifetime is 2 words of overhead (2 insert) and 60 bytes of data.
        let mut lifetime = 2 + 60 / 4;
        assert_eq!(store.lifetime().unwrap().used(), lifetime);
        // Update the value.
        value.extend(60..80);
        assert_eq!(write(&mut store, &(0..4), &value), Ok(()));
        // Added lifetime is 1 word of overhead (1 insert) and (80 - 52) bytes of data.
        lifetime += 1 + (80 - 52) / 4;
        assert_eq!(store.lifetime().unwrap().used(), lifetime);
    }

    #[test]
    fn delete_empty() {
        let mut store = MINIMAL.new_store();
        assert_eq!(delete(&mut store, &(0..4)), Ok(()));
        assert_eq!(store.find(0), Ok(None));
        assert_eq!(store.find(1), Ok(None));
        assert_eq!(store.find(2), Ok(None));
        assert_eq!(store.find(3), Ok(None));
    }

    #[test]
    fn delete_chunks() {
        let mut store = MINIMAL.new_store();
        let value: Vec<_> = (0..60).collect();
        assert_eq!(store.insert(0, &value[..52]), Ok(()));
        assert_eq!(store.insert(1, &value[52..]), Ok(()));
        assert_eq!(delete(&mut store, &(0..4)), Ok(()));
        assert_eq!(store.find(0), Ok(None));
        assert_eq!(store.find(1), Ok(None));
        assert_eq!(store.find(2), Ok(None));
        assert_eq!(store.find(3), Ok(None));
    }
}
