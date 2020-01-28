// Copyright 2019 Google LLC
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

#[cfg(test)]
use subtle::CtOption;

pub type Block16 = [u8; 16];

#[inline(always)]
pub fn xor_block_16(block: &mut Block16, mask: &Block16) {
    for i in 0..16 {
        block[i] ^= mask[i];
    }
}

#[cfg(test)]
pub trait ToOption<T> {
    fn to_option(self) -> Option<T>;
}

#[cfg(test)]
impl<T> ToOption<T> for CtOption<T> {
    fn to_option(self) -> Option<T> {
        if bool::from(self.is_some()) {
            Some(self.unwrap())
        } else {
            None
        }
    }
}
