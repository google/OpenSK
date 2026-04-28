// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use opensk::api::crypto::HASH_SIZE;
use opensk::api::crypto::sha256::Sha256;
use wasefire::crypto::hash::{Algorithm, Digest};

pub(crate) struct Impl(Digest);

impl Sha256 for Impl {
    fn new() -> Self {
        Impl(Digest::new(Algorithm::Sha256).unwrap())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self, output: &mut [u8; HASH_SIZE]) {
        self.0.finalize(output).unwrap()
    }
}
