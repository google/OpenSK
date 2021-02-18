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

use crate::ctap::data_formats::{CredentialProtectionPolicy, EnterpriseAttestationMode};

/// ###########################################################################
/// Constants for adjusting privacy and protection levels.
/// ###########################################################################

/// Changes the default level for the credProtect extension.
///
/// You can change this value to one of the following for more privacy:
/// - CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList
/// - CredentialProtectionPolicy::UserVerificationRequired
///
/// UserVerificationOptionalWithCredentialIdList
/// Resident credentials that are not in the allowList or excludeList can not be
/// discovered without user verification.
///
/// UserVerificationRequired
/// No resident credentials can be discovered without user verification.
///
/// This can improve privacy, but can make usage less comfortable.
pub const DEFAULT_CRED_PROTECT: Option<CredentialProtectionPolicy> = None;

/// Sets the intial minimum PIN length in code points.
///
/// # Invariant
///
/// - The minimum PIN length must be at least 4.
/// - The minimum PIN length must be at most 63.
/// - DEFAULT_MIN_PIN_LENGTH_RP_IDS must be non-empty if MAX_RP_IDS_LENGTH is 0.
///
/// Only the RP IDs listed in DEFAULT_MIN_PIN_LENGTH_RP_IDS are allowed to read
/// the minimum PIN length with the minPinLength extension.
/// Requiring longer PINs can help establish trust between users and relying
/// parties. It makes user verification harder to break, but less convenient.
/// NIST recommends at least 6-digit PINs in section 5.1.9.1:
/// https://pages.nist.gov/800-63-3/sp800-63b.html
///
/// Reset reverts the minimum PIN length to this DEFAULT_MIN_PIN_LENGTH.
pub const DEFAULT_MIN_PIN_LENGTH: u8 = 4;
pub const DEFAULT_MIN_PIN_LENGTH_RP_IDS: &[&str] = &[];

/// Enforces the alwaysUv option.
///
/// When setting to true, commands require a PIN.
/// Also, alwaysUv can not be disabled by commands.
///
/// A certification (additional to FIDO Alliance's) might require enforcing
/// alwaysUv. Otherwise, users should have the choice to configure alwaysUv.
/// Calling toggleAlwaysUv is preferred over enforcing alwaysUv here.
pub const ENFORCE_ALWAYS_UV: bool = false;

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
pub const ENTERPRISE_RP_ID_LIST: &[&str] = &[];

/// Sets the number of consecutive failed PINs before blocking interaction.
///
/// # Invariant
///
/// - CTAP2.0: Maximum PIN retries must be 8.
/// - CTAP2.1: Maximum PIN retries must be 8 at most.
///
/// The fail retry counter is reset after entering the correct PIN.
pub const MAX_PIN_RETRIES: u8 = 8;

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

/// Enables or disables signature counters.
///
/// The signature counter is currently implemented as a global counter.
/// The specification strongly suggests to have per-credential counters.
/// Implementing those means you can't have an infinite amount of server-side
/// credentials anymore. Also, since counters need frequent writes on the
/// persistent storage, we might need a flash friendly implementation. This
/// solution is a compromise to be compatible with U2F and not wasting storage.
///
/// https://www.w3.org/TR/webauthn/#signature-counter
pub const USE_SIGNATURE_COUNTER: bool = true;

/// ###########################################################################
/// Constants for performance optimization or adapting to different hardware.
///
/// Those constants may be modified before compilation to tune the behavior of
/// the key.
/// ###########################################################################

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

/// Limits the number of RP IDs that can change the minimum PIN length.
///
/// # Invariant
///
/// - If this value is 0, DEFAULT_MIN_PIN_LENGTH_RP_IDS must be non-empty.
///
/// You can use this constant to have an upper limit in storage requirements.
/// This might be useful if you want to more reliably predict the remaining
/// storage. Stored string can still be of arbitrary length though, until RP ID
/// truncation is implemented.
/// Outside of memory considerations, you can set this value to 0 if only RP IDs
/// in DEFAULT_MIN_PIN_LENGTH_RP_IDS should be allowed to change the minimum PIN
/// length.
pub const MAX_RP_IDS_LENGTH: usize = 8;

/// Sets the number of resident keys you can store.
///
/// # Invariant
///
/// - The storage key CREDENTIALS must fit at least this number of credentials.
///
/// This value has implications on the flash lifetime, please see the
/// documentation for NUM_PAGES below.
pub const MAX_SUPPORTED_RESIDENT_KEYS: usize = 150;

/// Sets the number of pages used for persistent storage.
///
/// The number of pages should be at least 3 and at most what the flash can
/// hold. There should be no reason to put a small number here, except that the
/// latency of flash operations is linear in the number of pages. This may
/// improve in the future. Currently, using 20 pages gives between 20ms and
/// 240ms per operation. The rule of thumb is between 1ms and 12ms per
/// additional page.
///
/// Limiting the number of resident keys permits to ensure a minimum number of
/// counter increments.
/// Let:
/// - P the number of pages (NUM_PAGES)
/// - K the maximum number of resident keys (MAX_SUPPORTED_RESIDENT_KEYS)
/// - S the maximum size of a resident key (about 500)
/// - C the number of erase cycles (10000)
/// - I the minimum number of counter increments
///
/// We have: I = (P * 4084 - 5107 - K * S) / 8 * C
///
/// With P=20 and K=150, we have I=2M which is enough for 500 increments per day
/// for 10 years.
pub const NUM_PAGES: usize = 20;

#[allow(clippy::assertions_on_constants)]
pub fn check_invariants() {
    assert!(DEFAULT_MIN_PIN_LENGTH >= 4);
    assert!(DEFAULT_MIN_PIN_LENGTH <= 63);
    assert!(!USE_BATCH_ATTESTATION || ENTERPRISE_ATTESTATION_MODE.is_none());
    if let Some(EnterpriseAttestationMode::VendorFacilitated) = ENTERPRISE_ATTESTATION_MODE {
        assert!(!ENTERPRISE_RP_ID_LIST.is_empty());
    }
    assert!(MAX_PIN_RETRIES <= 8);
    assert!(MAX_CRED_BLOB_LENGTH >= 32);
    if let Some(count) = MAX_CREDENTIAL_COUNT_IN_LIST {
        assert!(count >= 1);
    }
    assert!(MAX_LARGE_BLOB_ARRAY_SIZE >= 1024);
    // Storage tests check if MAX_LARGE_BLOB_ARRAY_SIZE fits the shards.
    if MAX_RP_IDS_LENGTH == 0 {
        assert!(!DEFAULT_MIN_PIN_LENGTH_RP_IDS.is_empty());
    }
    // Storage keys tests check if MAX_SUPPORTED_RESIDENT_KEYS fits CREDENTIALS.
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_invariants() {
        check_invariants();
    }
}
