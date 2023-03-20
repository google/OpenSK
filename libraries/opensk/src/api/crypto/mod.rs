// Copyright 2023 Google LLC
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

pub mod ecdh;
pub mod ecdsa;
#[cfg(feature = "rust_crypto")]
pub mod rust_crypto;
#[cfg(not(feature = "rust_crypto"))]
pub mod software_crypto;
#[cfg(feature = "rust_crypto")]
pub use rust_crypto as software_crypto;
pub mod hmac256;
pub mod sha256;

use self::ecdh::Ecdh;
use self::ecdsa::Ecdsa;
use self::hmac256::Hmac256;
use self::sha256::Sha256;

/// The size of field elements in the elliptic curve P256.
pub const EC_FIELD_SIZE: usize = 32;

/// The size of a serialized ECDSA signature.
pub const EC_SIGNATURE_SIZE: usize = 2 * EC_FIELD_SIZE;

/// The size in bytes of a SHA256.
pub const HASH_SIZE: usize = 32;

/// The size in bytes of truncated HMAC.
pub const HMAC_KEY_SIZE: usize = 32;

/// The size in bytes of truncated HMAC.
pub const TRUNCATED_HMAC_SIZE: usize = 16;

/// Necessary cryptographic primitives for CTAP.
pub trait Crypto {
    type Ecdh: Ecdh;
    type Ecdsa: Ecdsa;
    type Sha256: Sha256;
    type Hmac256: Hmac256;
}
