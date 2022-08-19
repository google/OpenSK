// Copyright 2022 Google LLC
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

//! Support for concatenated entries.
//!
//! This module permits to store multiple indexed values under the same key by concatenation. Such
//! values must be at most 255 bytes and there can't be more than 255 such values under the same
//! key (they are indexed with a `u8`).
//!
//! The rationale for using those particular constraints is that we want the number of bits to store
//! the index and the number of bits to store the length to fit in an integer number of bytes
//! (because the values are an integer number of bytes). Using only one byte is too restrictive
//! (e.g. 8 values of at most 31 bytes or 16 values of at most 15 bytes). Using 2 bytes is plenty of
//! space, so using one byte for each field makes parsing simpler and faster.
//!
//! The format is thus `(index:u8 length:u8 payload:[u8; length])*`. The concatenation is not
//! particularly sorted.

use crate::{Storage, Store, StoreError, StoreResult};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::ops::Range;

/// Reads a value from a concatenated entry.
pub fn read(store: &Store<impl Storage>, key: usize, index: u8) -> StoreResult<Option<Vec<u8>>> {
    let values = match store.find(key)? {
        None => return Ok(None),
        Some(x) => x,
    };
    Ok(find(&values, index)?.map(|range| values[range].to_vec()))
}

/// Writes a value to a concatenated entry.
pub fn write(
    store: &mut Store<impl Storage>,
    key: usize,
    index: u8,
    value: &[u8],
) -> StoreResult<()> {
    if value.len() > 255 {
        return Err(StoreError::InvalidArgument);
    }
    let mut values = store.find(key)?.unwrap_or(vec![]);
    match find(&values, index)? {
        None => {
            values.push(index);
            values.push(value.len() as u8);
            values.extend_from_slice(value);
        }
        Some(mut range) => {
            values[range.start - 1] = value.len() as u8;
            match range.len().cmp(&value.len()) {
                Ordering::Less => {
                    let diff = value.len() - range.len();
                    values.resize(values.len() + diff, 0);
                    values[range.end..].rotate_right(diff);
                    range.end += diff;
                }
                Ordering::Equal => (),
                Ordering::Greater => {
                    let diff = range.len() - value.len();
                    range.end -= diff;
                    values[range.end..].rotate_left(diff);
                    values.truncate(values.len() - diff);
                }
            }
            values[range].copy_from_slice(value);
        }
    }
    store.insert(key, &values)
}

/// Deletes the value from a concatenated entry.
pub fn delete(store: &mut Store<impl Storage>, key: usize, index: u8) -> StoreResult<()> {
    let mut values = match store.find(key)? {
        None => return Ok(()),
        Some(x) => x,
    };
    let mut range = match find(&values, index)? {
        None => return Ok(()),
        Some(x) => x,
    };
    range.start -= 2;
    values[range.start..].rotate_left(range.len());
    values.truncate(values.len() - range.len());
    store.insert(key, &values)
}

fn find(values: &[u8], index: u8) -> StoreResult<Option<Range<usize>>> {
    let mut pos = 0;
    while pos < values.len() {
        if pos == values.len() - 1 {
            return Err(StoreError::InvalidStorage);
        }
        let len = values[pos + 1] as usize;
        if len > values.len() - 2 || pos > values.len() - 2 - len {
            return Err(StoreError::InvalidStorage);
        }
        if index == values[pos] {
            return Ok(Some(pos + 2..pos + 2 + len));
        }
        pos += 2 + len;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::MINIMAL;

    #[test]
    fn read_empty_entry() {
        let store = MINIMAL.new_store();
        assert_eq!(read(&store, 0, 0), Ok(None));
        assert_eq!(read(&store, 0, 1), Ok(None));
    }

    #[test]
    fn read_missing_value() {
        let mut store = MINIMAL.new_store();
        let value = b"\x00\x03foo\x02\x05hello".to_vec();
        store.insert(0, &value).unwrap();
        assert_eq!(read(&store, 0, 1), Ok(None));
    }

    #[test]
    fn read_existing_value() {
        let mut store = MINIMAL.new_store();
        let value = b"\x00\x03foo\x02\x05hello".to_vec();
        store.insert(0, &value).unwrap();
        assert_eq!(read(&store, 0, 0), Ok(Some(b"foo".to_vec())));
        assert_eq!(read(&store, 0, 2), Ok(Some(b"hello".to_vec())));
    }

    #[test]
    fn read_invalid_entry_too_long() {
        let mut store = MINIMAL.new_store();
        let value = b"\x00\x03foo\x02\x08hello".to_vec();
        store.insert(0, &value).unwrap();
        assert_eq!(read(&store, 0, 1), Err(StoreError::InvalidStorage));
    }

    #[test]
    fn read_invalid_entry_too_short() {
        let mut store = MINIMAL.new_store();
        let value = b"\x00\x03foo\x02".to_vec();
        store.insert(0, &value).unwrap();
        assert_eq!(read(&store, 0, 1), Err(StoreError::InvalidStorage));
    }

    #[test]
    fn write_empty_entry() {
        let mut store = MINIMAL.new_store();
        assert_eq!(write(&mut store, 0, 0, b"foo"), Ok(()));
        assert_eq!(store.find(0), Ok(Some(b"\x00\x03foo".to_vec())));
    }

    #[test]
    fn write_missing_value() {
        let mut store = MINIMAL.new_store();
        let value = b"\x00\x03foo".to_vec();
        store.insert(0, &value).unwrap();
        assert_eq!(write(&mut store, 0, 1, b"bar"), Ok(()));
        assert_eq!(store.find(0), Ok(Some(b"\x00\x03foo\x01\x03bar".to_vec())));
    }

    #[test]
    fn write_existing_value_same_size() {
        let mut store = MINIMAL.new_store();
        let value = b"\x00\x03foo\x02\x05hello".to_vec();
        store.insert(0, &value).unwrap();
        assert_eq!(write(&mut store, 0, 0, b"bar"), Ok(()));
        assert_eq!(
            store.find(0),
            Ok(Some(b"\x00\x03bar\x02\x05hello".to_vec()))
        );
    }

    #[test]
    fn write_existing_value_longer() {
        let mut store = MINIMAL.new_store();
        let value = b"\x00\x03foo\x02\x05hello".to_vec();
        store.insert(0, &value).unwrap();
        assert_eq!(write(&mut store, 0, 0, b"barrage"), Ok(()));
        assert_eq!(
            store.find(0),
            Ok(Some(b"\x00\x07barrage\x02\x05hello".to_vec()))
        );
    }

    #[test]
    fn write_existing_value_shorter() {
        let mut store = MINIMAL.new_store();
        let value = b"\x00\x08football\x02\x05hello".to_vec();
        store.insert(0, &value).unwrap();
        assert_eq!(write(&mut store, 0, 0, b"bar"), Ok(()));
        assert_eq!(
            store.find(0),
            Ok(Some(b"\x00\x03bar\x02\x05hello".to_vec()))
        );
    }

    #[test]
    fn delete_empty_entry() {
        let mut store = MINIMAL.new_store();
        assert_eq!(delete(&mut store, 0, 0), Ok(()));
        assert_eq!(delete(&mut store, 0, 1), Ok(()));
    }

    #[test]
    fn delete_missing_value() {
        let mut store = MINIMAL.new_store();
        let value = b"\x00\x03foo\x02\x05hello".to_vec();
        store.insert(0, &value).unwrap();
        assert_eq!(delete(&mut store, 0, 1), Ok(()));
        assert_eq!(
            store.find(0),
            Ok(Some(b"\x00\x03foo\x02\x05hello".to_vec()))
        );
    }

    #[test]
    fn delete_existing_value() {
        let mut store = MINIMAL.new_store();
        let value = b"\x00\x03foo\x02\x05hello".to_vec();
        store.insert(0, &value).unwrap();
        assert_eq!(delete(&mut store, 0, 0), Ok(()));
        assert_eq!(store.find(0), Ok(Some(b"\x02\x05hello".to_vec())));
    }
}
