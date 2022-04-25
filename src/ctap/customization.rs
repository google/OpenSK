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

//! This file contains all customizable constants.
//!
//! If you adapt them, make sure to run the tests before flashing the firmware.
//! Our deploy script enforces the invariants.

// ###########################################################################
// Constants for performance optimization or adapting to different hardware.
//
// Those constants may be modified before compilation to tune the behavior of
// the key.
// ###########################################################################

/// Sets the maximum blob size stored with the credBlob extension.
///
/// # Invariant
///
/// - The length must be at least 32.
pub const MAX_CRED_BLOB_LENGTH: usize = 32;

/// Limits the number of considered entries in credential lists.
///
/// # Invariant
///
/// - This value, if present, must be at least 1 (more is preferred).
///
/// Depending on your memory, you can use Some(n) to limit request sizes in
/// MakeCredential and GetAssertion. This affects allowList and excludeList.
pub const MAX_CREDENTIAL_COUNT_IN_LIST: Option<usize> = None;

/// Limits the size of largeBlobs the authenticator stores.
///
/// # Invariant
///
/// - The allowed size must be at least 1024.
/// - The array must fit into the shards reserved in storage/key.rs.
pub const MAX_LARGE_BLOB_ARRAY_SIZE: usize = 2048;

/// Sets the number of resident keys you can store.
///
/// # Invariant
///
/// - The storage key CREDENTIALS must fit at least this number of credentials.
///
/// Limiting the number of resident keys permits to ensure a minimum number of
/// counter increments.
/// Let:
/// - P the number of pages (NUM_PAGES in the board definition)
/// - K the maximum number of resident keys (MAX_SUPPORTED_RESIDENT_KEYS)
/// - S the maximum size of a resident key (about 500)
/// - C the number of erase cycles (10000)
/// - I the minimum number of counter increments
///
/// We have: I = (P * 4084 - 5107 - K * S) / 8 * C
///
/// With P=20 and K=150, we have I=2M which is enough for 500 increments per day
/// for 10 years.
pub const MAX_SUPPORTED_RESIDENT_KEYS: usize = 150;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_invariants() {
        // Two invariants are currently tested in different files:
        // - storage.rs: if MAX_LARGE_BLOB_ARRAY_SIZE fits the shards
        // - storage/key.rs: if MAX_SUPPORTED_RESIDENT_KEYS fits CREDENTIALS
        assert!(MAX_CRED_BLOB_LENGTH >= 32);
        if let Some(count) = MAX_CREDENTIAL_COUNT_IN_LIST {
            assert!(count >= 1);
        }
        assert!(MAX_LARGE_BLOB_ARRAY_SIZE >= 1024);
    }
}
