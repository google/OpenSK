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

use persistent_store::{BufferOptions, BufferStorage, Store, StoreDriverOff};

#[derive(Clone)]
pub struct Config {
    word_size: usize,
    page_size: usize,
    num_pages: usize,
    max_word_writes: usize,
    max_page_erases: usize,
}

impl Config {
    pub fn new_driver(&self) -> StoreDriverOff {
        let options = BufferOptions {
            word_size: self.word_size,
            page_size: self.page_size,
            max_word_writes: self.max_word_writes,
            max_page_erases: self.max_page_erases,
            strict_mode: true,
        };
        StoreDriverOff::new(options, self.num_pages)
    }

    pub fn new_store(&self) -> Store<BufferStorage> {
        self.new_driver().power_on().unwrap().extract_store()
    }
}

pub const MINIMAL: Config = Config {
    word_size: 4,
    page_size: 64,
    num_pages: 5,
    max_word_writes: 2,
    max_page_erases: 9,
};
