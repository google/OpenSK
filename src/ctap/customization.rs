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

use crate::ctap::data_formats::EnterpriseAttestationMode;

/// Allows usage of enterprise attestation.
///
/// # Invariant
///
/// - Enterprise and batch attestation can not both be active.
/// - If the mode is VendorFacilitated, ENTERPRISE_RP_ID_LIST must be non-empty.
///
/// For privacy reasons, it is disabled by default. You can choose between:
/// - EnterpriseAttestationMode::VendorFacilitated
/// - EnterpriseAttestationMode::PlatformManaged
///
/// VendorFacilitated
/// Enterprise attestation is restricted to ENTERPRISE_RP_ID_LIST. Add your
/// enterprises domain, e.g. "example.com", to the list below.
///
/// PlatformManaged
/// All relying parties can request an enterprise attestation. The authenticator
/// trusts the platform to filter requests.
///
/// To enable the feature, send the subcommand enableEnterpriseAttestation in
/// AuthenticatorConfig. An enterprise might want to customize the type of
/// attestation that is used. OpenSK defaults to batch attestation. Configuring
/// individual certificates then makes authenticators identifiable.
///
/// OpenSK prevents activating batch and enterprise attestation together. The
/// current implementation uses the same key material at the moment, and these
/// two modes have conflicting privacy guarantees.
/// If you implement your own enterprise attestation mechanism, and you want
/// batch attestation at the same time, proceed carefully and remove the
/// assertion.
pub const ENTERPRISE_ATTESTATION_MODE: Option<EnterpriseAttestationMode> = None;

/// Lists relying party IDs that can perform enterprise attestation.
///
/// # Invariant
///
/// - If the mode is VendorFacilitated, ENTERPRISE_RP_ID_LIST must be non-empty.
///
/// This list is only considered if the enterprise attestation mode is
/// VendorFacilitated.
pub const ENTERPRISE_RP_ID_LIST: &[&str] = &[];

/// Enables or disables basic attestation for FIDO2.
///
/// # Invariant
///
/// - Enterprise and batch attestation can not both be active (see above).
///
/// The basic attestation uses the signing key configured with a vendor command
/// as a batch key. If you turn batch attestation on, be aware that it is your
/// responsibility to safely generate and store the key material. Also, the
/// batches must have size of at least 100k authenticators before using new key
/// material.
/// U2F is unaffected by this setting.
///
/// https://www.w3.org/TR/webauthn/#attestation
pub const USE_BATCH_ATTESTATION: bool = false;

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
        assert!(!USE_BATCH_ATTESTATION || ENTERPRISE_ATTESTATION_MODE.is_none());
        if let Some(EnterpriseAttestationMode::VendorFacilitated) = ENTERPRISE_ATTESTATION_MODE {
            assert!(!ENTERPRISE_RP_ID_LIST.is_empty());
        } else {
            assert!(ENTERPRISE_RP_ID_LIST.is_empty());
        }
        assert!(MAX_CRED_BLOB_LENGTH >= 32);
        if let Some(count) = MAX_CREDENTIAL_COUNT_IN_LIST {
            assert!(count >= 1);
        }
        assert!(MAX_LARGE_BLOB_ARRAY_SIZE >= 1024);
    }
}
