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

use opensk::api::crypto::Crypto;

use crate::env::WasefireEnv;

mod aes256;
mod ecdh;
mod ecdsa;
#[cfg(feature = "ed25519")]
mod ed25519;
mod hkdf256;
mod hmac256;
mod sha256;

impl Crypto for WasefireEnv {
    type Aes256 = aes256::Impl;
    type Ecdh = Self;
    type Ecdsa = Self;
    #[cfg(feature = "ed25519")]
    type Ed25519 = Self;
    type Sha256 = sha256::Impl;
    type Hmac256 = Self;
    type Hkdf256 = Self;
}
