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

use persistent_store::fragment;

mod config;

#[test]
fn read_empty_entry() {
    let store = config::MINIMAL.new_store();
    assert_eq!(fragment::read(&store, &(0..4)), Ok(None));
}

#[test]
fn read_single_chunk() {
    let mut store = config::MINIMAL.new_store();
    let value = b"hello".to_vec();
    assert_eq!(store.insert(0, &value), Ok(()));
    assert_eq!(fragment::read(&store, &(0..4)), Ok(Some(value)));
}

#[test]
fn read_multiple_chunks() {
    let mut store = config::MINIMAL.new_store();
    let value: Vec<_> = (0..60).collect();
    assert_eq!(store.insert(0, &value[..52]), Ok(()));
    assert_eq!(store.insert(1, &value[52..]), Ok(()));
    assert_eq!(fragment::read(&store, &(0..4)), Ok(Some(value)));
}

#[test]
fn read_range_first_chunk() {
    let mut store = config::MINIMAL.new_store();
    let value: Vec<_> = (0..60).collect();
    assert_eq!(store.insert(0, &value[..52]), Ok(()));
    assert_eq!(store.insert(1, &value[52..]), Ok(()));
    assert_eq!(
        fragment::read_range(&store, &(0..4), 0..10),
        Ok(Some((0..10).collect()))
    );
    assert_eq!(
        fragment::read_range(&store, &(0..4), 10..20),
        Ok(Some((10..20).collect()))
    );
    assert_eq!(
        fragment::read_range(&store, &(0..4), 40..52),
        Ok(Some((40..52).collect()))
    );
}

#[test]
fn read_range_second_chunk() {
    let mut store = config::MINIMAL.new_store();
    let value: Vec<_> = (0..60).collect();
    assert_eq!(store.insert(0, &value[..52]), Ok(()));
    assert_eq!(store.insert(1, &value[52..]), Ok(()));
    assert_eq!(
        fragment::read_range(&store, &(0..4), 52..53),
        Ok(Some(vec![52]))
    );
    assert_eq!(
        fragment::read_range(&store, &(0..4), 53..54),
        Ok(Some(vec![53]))
    );
    assert_eq!(
        fragment::read_range(&store, &(0..4), 59..60),
        Ok(Some(vec![59]))
    );
}

#[test]
fn read_range_both_chunks() {
    let mut store = config::MINIMAL.new_store();
    let value: Vec<_> = (0..60).collect();
    assert_eq!(store.insert(0, &value[..52]), Ok(()));
    assert_eq!(store.insert(1, &value[52..]), Ok(()));
    assert_eq!(
        fragment::read_range(&store, &(0..4), 40..60),
        Ok(Some((40..60).collect()))
    );
    assert_eq!(
        fragment::read_range(&store, &(0..4), 0..60),
        Ok(Some((0..60).collect()))
    );
}

#[test]
fn read_range_outside() {
    let mut store = config::MINIMAL.new_store();
    let value: Vec<_> = (0..60).collect();
    assert_eq!(store.insert(0, &value[..52]), Ok(()));
    assert_eq!(store.insert(1, &value[52..]), Ok(()));
    assert_eq!(
        fragment::read_range(&store, &(0..4), 40..100),
        Ok(Some((40..60).collect()))
    );
    assert_eq!(
        fragment::read_range(&store, &(0..4), 60..100),
        Ok(Some(vec![]))
    );
}

#[test]
fn write_single_chunk() {
    let mut store = config::MINIMAL.new_store();
    let value = b"hello".to_vec();
    assert_eq!(fragment::write(&mut store, &(0..4), &value), Ok(()));
    assert_eq!(store.find(0), Ok(Some(value)));
    assert_eq!(store.find(1), Ok(None));
    assert_eq!(store.find(2), Ok(None));
    assert_eq!(store.find(3), Ok(None));
}

#[test]
fn write_multiple_chunks() {
    let mut store = config::MINIMAL.new_store();
    let value: Vec<_> = (0..60).collect();
    assert_eq!(fragment::write(&mut store, &(0..4), &value), Ok(()));
    assert_eq!(store.find(0), Ok(Some((0..52).collect())));
    assert_eq!(store.find(1), Ok(Some((52..60).collect())));
    assert_eq!(store.find(2), Ok(None));
    assert_eq!(store.find(3), Ok(None));
}

#[test]
fn overwrite_less_chunks() {
    let mut store = config::MINIMAL.new_store();
    let value: Vec<_> = (0..60).collect();
    assert_eq!(store.insert(0, &value[..52]), Ok(()));
    assert_eq!(store.insert(1, &value[52..]), Ok(()));
    let value: Vec<_> = (42..69).collect();
    assert_eq!(fragment::write(&mut store, &(0..4), &value), Ok(()));
    assert_eq!(store.find(0), Ok(Some((42..69).collect())));
    assert_eq!(store.find(1), Ok(None));
    assert_eq!(store.find(2), Ok(None));
    assert_eq!(store.find(3), Ok(None));
}

#[test]
fn overwrite_needed_chunks() {
    let mut store = config::MINIMAL.new_store();
    let mut value: Vec<_> = (0..60).collect();
    assert_eq!(store.insert(0, &value[..52]), Ok(()));
    assert_eq!(store.insert(1, &value[52..]), Ok(()));
    // Current lifetime is 2 words of overhead (2 insert) and 60 bytes of data.
    let mut lifetime = 2 + 60 / 4;
    assert_eq!(store.lifetime().unwrap().used(), lifetime);
    // Update the value.
    value.extend(60..80);
    assert_eq!(fragment::write(&mut store, &(0..4), &value), Ok(()));
    // Added lifetime is 1 word of overhead (1 insert) and (80 - 52) bytes of data.
    lifetime += 1 + (80 - 52) / 4;
    assert_eq!(store.lifetime().unwrap().used(), lifetime);
}

#[test]
fn delete_empty() {
    let mut store = config::MINIMAL.new_store();
    assert_eq!(fragment::delete(&mut store, &(0..4)), Ok(()));
    assert_eq!(store.find(0), Ok(None));
    assert_eq!(store.find(1), Ok(None));
    assert_eq!(store.find(2), Ok(None));
    assert_eq!(store.find(3), Ok(None));
}

#[test]
fn delete_chunks() {
    let mut store = config::MINIMAL.new_store();
    let value: Vec<_> = (0..60).collect();
    assert_eq!(store.insert(0, &value[..52]), Ok(()));
    assert_eq!(store.insert(1, &value[52..]), Ok(()));
    assert_eq!(fragment::delete(&mut store, &(0..4)), Ok(()));
    assert_eq!(store.find(0), Ok(None));
    assert_eq!(store.find(1), Ok(None));
    assert_eq!(store.find(2), Ok(None));
    assert_eq!(store.find(3), Ok(None));
}
