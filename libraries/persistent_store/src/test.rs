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

use crate::{BufferOptions, BufferStorage, Store, StoreDriverOff};

#[derive(Clone)]
pub struct Config {
    pub word_size: usize,
    pub page_size: usize,
    pub num_pages: usize,
    pub max_word_writes: usize,
    pub max_page_erases: usize,
}

impl Config {
    pub fn new_driver(&self) -> StoreDriverOff {
        StoreDriverOff::new(self.into(), self.num_pages)
    }

    pub fn new_store(&self) -> Store<BufferStorage> {
        self.new_driver().power_on().unwrap().extract_store()
    }
}

impl<'a> From<&'a Config> for BufferOptions {
    fn from(config: &'a Config) -> Self {
        BufferOptions {
            word_size: config.word_size,
            page_size: config.page_size,
            max_word_writes: config.max_word_writes,
            max_page_erases: config.max_page_erases,
            strict_mode: true,
        }
    }
}

pub const MINIMAL: Config = Config {
    word_size: 4,
    page_size: 64,
    num_pages: 5,
    max_word_writes: 2,
    max_page_erases: 9,
};

const NORDIC: Config = Config {
    word_size: 4,
    page_size: 0x1000,
    num_pages: 20,
    max_word_writes: 2,
    max_page_erases: 10000,
};

const TITAN: Config = Config {
    word_size: 4,
    page_size: 0x800,
    num_pages: 10,
    max_word_writes: 2,
    max_page_erases: 10000,
};

#[test]
fn nordic_capacity() {
    let driver = NORDIC.new_driver().power_on().unwrap();
    assert_eq!(driver.model().capacity().total, 19123);
}

#[test]
fn titan_capacity() {
    let driver = TITAN.new_driver().power_on().unwrap();
    assert_eq!(driver.model().capacity().total, 4315);
}

#[test]
fn minimal_virt_page_size() {
    // Make sure a virtual page has 14 words. We use this property in the other tests below to
    // know whether entries are spanning, starting, and ending pages.
    assert_eq!(MINIMAL.new_driver().model().format().virt_page_size(), 14);
}
