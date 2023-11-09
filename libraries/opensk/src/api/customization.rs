// Copyright 2022-2023 Google LLC
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

use crate::ctap::data_formats::{CredentialProtectionPolicy, EnterpriseAttestationMode};
use alloc::string::String;
use alloc::vec::Vec;

pub const AAGUID_LENGTH: usize = 16;

pub trait Customization {
    /// Authenticator Attestation Global Unique Identifier
    fn aaguid(&self) -> &'static [u8; AAGUID_LENGTH];

    // ###########################################################################
    // Constants for adjusting privacy and protection levels.
    // ###########################################################################

    /// Removes support for PIN protocol v1.
    ///
    /// We support PIN protocol v2, "intended to aid FIPS certification".
    /// To certify, you might want to remove support for v1 using this customization.
    fn allows_pin_protocol_v1(&self) -> bool;

    /// Changes the default level for the credProtect extension.
    ///
    /// You can change this value to one of the following for more privacy:
    /// - CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList
    /// - CredentialProtectionPolicy::UserVerificationRequired
    ///
    /// UserVerificationOptionalWithCredentialIdList
    /// Resident credentials are discoverable with
    /// - an allowList,
    /// - an excludeList,
    /// - user verification.
    ///
    /// UserVerificationRequired
    /// Resident credentials are discoverable with user verification only.
    ///
    /// This can improve privacy, but can make usage less comfortable.
    fn default_cred_protect(&self) -> Option<CredentialProtectionPolicy>;

    /// Sets the initial minimum PIN length in code points.
    ///
    /// # Invariant
    ///
    /// - The minimum PIN length must be at least 4.
    /// - The minimum PIN length must be at most 63.
    /// - default_min_pin_length_rp_ids() must be non-empty if max_rp_ids_length() is 0.
    ///
    /// Requiring longer PINs can help establish trust between users and relying
    /// parties. It makes user verification harder to break, but less convenient.
    /// NIST recommends at least 6-digit PINs in section 5.1.9.1:
    /// https://pages.nist.gov/800-63-3/sp800-63b.html
    ///
    /// Reset reverts the minimum PIN length to this DEFAULT_MIN_PIN_LENGTH.
    fn default_min_pin_length(&self) -> u8;

    /// Lists relying parties that can read the minimum PIN length.
    ///
    /// # Invariant
    ///
    /// - default_min_pin_length_rp_ids() must be non-empty if max_rp_ids_length() is 0
    ///
    /// Only the RP IDs listed in default_min_pin_length_rp_ids are allowed to read
    /// the minimum PIN length with the minPinLength extension.
    fn default_min_pin_length_rp_ids(&self) -> Vec<String>;

    /// Enforces the alwaysUv option.
    ///
    /// When setting to true, commands require a PIN.
    /// Also, alwaysUv can not be disabled by commands.
    ///
    /// A certification (additional to FIDO Alliance's) might require enforcing
    /// alwaysUv. Otherwise, users should have the choice to configure alwaysUv.
    /// Calling toggleAlwaysUv is preferred over enforcing alwaysUv here.
    fn enforce_always_uv(&self) -> bool;

    /// Allows usage of enterprise attestation.
    ///
    /// # Invariant
    ///
    /// - Enterprise and batch attestation can not both be active.
    /// - If the mode is VendorFacilitated, enterprise_attestation_mode() must be non-empty.
    ///
    /// For privacy reasons, it is disabled by default. You can choose between:
    /// - EnterpriseAttestationMode::VendorFacilitated
    /// - EnterpriseAttestationMode::PlatformManaged
    ///
    /// VendorFacilitated
    /// Enterprise attestation is restricted to enterprise_attestation_mode(). Add your
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
    fn enterprise_attestation_mode(&self) -> Option<EnterpriseAttestationMode>;

    /// Lists relying party IDs that can perform enterprise attestation.
    ///
    /// # Invariant
    ///
    /// - If the mode is VendorFacilitated, enterprise_attestation_mode() must be non-empty.
    ///
    /// This list is only considered if enterprise attestation is used.
    #[cfg(feature = "std")]
    fn enterprise_rp_id_list(&self) -> Vec<String>;

    /// Returns whether the rp_id is contained in enterprise_rp_id_list().
    fn is_enterprise_rp_id(&self, rp_id: &str) -> bool;

    /// Maximum message size send for CTAP commands.
    ///
    /// The maximum value is 7609, as HID packets can not encode longer messages.
    /// 1024 is the default mentioned in the authenticatorLargeBlobs commands.
    /// Larger values are preferred, as that allows more parameters in commands.
    /// If long commands are too unreliable on your hardware, consider decreasing
    /// this value.
    fn max_msg_size(&self) -> usize;

    /// Sets the number of consecutive failed PINs before blocking interaction.
    ///
    /// # Invariant
    ///
    /// - CTAP2.0: Maximum PIN retries must be 8.
    /// - CTAP2.1: Maximum PIN retries must be 8 at most.
    ///
    /// The fail retry counter is reset after entering the correct PIN.
    fn max_pin_retries(&self) -> u8;

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
    fn use_batch_attestation(&self) -> bool;

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
    fn use_signature_counter(&self) -> bool;

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
    /// - OpenSK puts a limit that the length must be at most 64, as it needs to
    ///   be persisted in the credential ID.
    fn max_cred_blob_length(&self) -> usize;

    /// Limits the number of considered entries in credential lists.
    ///
    /// # Invariant
    ///
    /// - This value, if present, must be at least 1 (more is preferred).
    ///
    /// Depending on your memory, you can use Some(n) to limit request sizes in
    /// MakeCredential and GetAssertion. This affects allowList and excludeList.
    fn max_credential_count_in_list(&self) -> Option<usize>;

    /// Limits the size of largeBlobs the authenticator stores.
    ///
    /// # Invariant
    ///
    /// - The allowed size must be at least 1024.
    /// - The array must fit into the shards reserved in storage/key.rs.
    fn max_large_blob_array_size(&self) -> usize;

    /// Limits the number of RP IDs that can change the minimum PIN length.
    ///
    /// # Invariant
    ///
    /// - If this value is 0, default_min_pin_length_rp_ids() must be non-empty.
    ///
    /// You can use this constant to have an upper limit in storage requirements.
    /// This might be useful if you want to more reliably predict the remaining
    /// storage. Stored string can still be of arbitrary length though, until RP ID
    /// truncation is implemented.
    /// Outside of memory considerations, you can set this value to 0 if only RP IDs
    /// in default_min_pin_length_rp_ids() should be allowed to change the minimum
    /// PIN length.
    fn max_rp_ids_length(&self) -> usize;

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
    /// - K the maximum number of resident keys (max_supported_resident_keys())
    /// - S the maximum size of a resident key (about 500)
    /// - C the number of erase cycles (10000)
    /// - I the minimum number of counter increments
    ///
    /// We have: I = (P * 4084 - 5107 - K * S) / 8 * C
    ///
    /// With P=20 and K=150, we have I=2M which is enough for 500 increments per day
    /// for 10 years.
    fn max_supported_resident_keys(&self) -> usize;
}

#[derive(Clone)]
pub struct CustomizationImpl {
    pub aaguid: &'static [u8; AAGUID_LENGTH],
    pub allows_pin_protocol_v1: bool,
    pub default_cred_protect: Option<CredentialProtectionPolicy>,
    pub default_min_pin_length: u8,
    pub default_min_pin_length_rp_ids: &'static [&'static str],
    pub enforce_always_uv: bool,
    pub enterprise_attestation_mode: Option<EnterpriseAttestationMode>,
    pub enterprise_rp_id_list: &'static [&'static str],
    pub max_msg_size: usize,
    pub max_pin_retries: u8,
    pub use_batch_attestation: bool,
    pub use_signature_counter: bool,
    pub max_cred_blob_length: usize,
    pub max_credential_count_in_list: Option<usize>,
    pub max_large_blob_array_size: usize,
    pub max_rp_ids_length: usize,
    pub max_supported_resident_keys: usize,
}

pub const DEFAULT_CUSTOMIZATION: CustomizationImpl = CustomizationImpl {
    aaguid: &[0; AAGUID_LENGTH],
    allows_pin_protocol_v1: true,
    default_cred_protect: None,
    default_min_pin_length: 4,
    default_min_pin_length_rp_ids: &[],
    enforce_always_uv: false,
    enterprise_attestation_mode: None,
    enterprise_rp_id_list: &[],
    max_msg_size: 7609,
    max_pin_retries: 8,
    use_batch_attestation: false,
    use_signature_counter: true,
    max_cred_blob_length: 32,
    max_credential_count_in_list: None,
    max_large_blob_array_size: 2048,
    max_rp_ids_length: 8,
    max_supported_resident_keys: 150,
};

impl Customization for CustomizationImpl {
    fn aaguid(&self) -> &'static [u8; AAGUID_LENGTH] {
        self.aaguid
    }

    fn allows_pin_protocol_v1(&self) -> bool {
        self.allows_pin_protocol_v1
    }

    fn default_cred_protect(&self) -> Option<CredentialProtectionPolicy> {
        self.default_cred_protect
    }

    fn default_min_pin_length(&self) -> u8 {
        self.default_min_pin_length
    }

    fn default_min_pin_length_rp_ids(&self) -> Vec<String> {
        self.default_min_pin_length_rp_ids
            .iter()
            .map(|s| String::from(*s))
            .collect()
    }

    fn enforce_always_uv(&self) -> bool {
        self.enforce_always_uv
    }

    fn enterprise_attestation_mode(&self) -> Option<EnterpriseAttestationMode> {
        self.enterprise_attestation_mode
    }

    #[cfg(feature = "std")]
    fn enterprise_rp_id_list(&self) -> Vec<String> {
        self.enterprise_rp_id_list
            .iter()
            .map(|s| String::from(*s))
            .collect()
    }

    fn is_enterprise_rp_id(&self, rp_id: &str) -> bool {
        self.enterprise_rp_id_list.contains(&rp_id)
    }

    fn max_msg_size(&self) -> usize {
        self.max_msg_size
    }

    fn max_pin_retries(&self) -> u8 {
        self.max_pin_retries
    }

    fn use_batch_attestation(&self) -> bool {
        self.use_batch_attestation
    }

    fn use_signature_counter(&self) -> bool {
        self.use_signature_counter
    }

    fn max_cred_blob_length(&self) -> usize {
        self.max_cred_blob_length
    }

    fn max_credential_count_in_list(&self) -> Option<usize> {
        self.max_credential_count_in_list
    }

    fn max_large_blob_array_size(&self) -> usize {
        self.max_large_blob_array_size
    }

    fn max_rp_ids_length(&self) -> usize {
        self.max_rp_ids_length
    }

    fn max_supported_resident_keys(&self) -> usize {
        self.max_supported_resident_keys
    }
}

#[cfg(feature = "std")]
pub fn is_valid(customization: &impl Customization) -> bool {
    // Two invariants are currently tested in different files:
    // - storage.rs: if max_large_blob_array_size() fits the shards
    // - storage/key.rs: if max_supported_resident_keys() fits CREDENTIALS

    // Max message size must be between 1024 and 7609.
    if customization.max_msg_size() < 1024 || customization.max_msg_size() > 7609 {
        return false;
    }

    // Default min pin length must be between 4 and 63.
    if customization.default_min_pin_length() < 4 || customization.default_min_pin_length() > 63 {
        return false;
    }

    // OpenSK prevents activating batch and enterprise attestation together. The
    // current implementation uses the same key material at the moment, and these
    // two modes have conflicting privacy guarantees.
    if customization.use_batch_attestation()
        && customization.enterprise_attestation_mode().is_some()
    {
        return false;
    }

    // enterprise_rp_id_list() should be non-empty in vendor facilitated mode.
    if matches!(
        customization.enterprise_attestation_mode(),
        Some(EnterpriseAttestationMode::VendorFacilitated)
    ) && customization.enterprise_rp_id_list().is_empty()
    {
        return false;
    }

    // enterprise_rp_id_list() should be empty without an enterprise attestation mode.
    if customization.enterprise_attestation_mode().is_none()
        && !customization.enterprise_rp_id_list().is_empty()
    {
        return false;
    }

    // Max pin retries must be less or equal than 8.
    if customization.max_pin_retries() > 8 {
        return false;
    }

    // Max cred blob length should be at least 32, and at most 64.
    if customization.max_cred_blob_length() < 32 || customization.max_cred_blob_length() > 64 {
        return false;
    }

    // Max credential count in list should be positive if exists.
    if let Some(count) = customization.max_credential_count_in_list() {
        if count < 1 {
            return false;
        }
    }

    // Max large blob array size should not be less than 1024.
    if customization.max_large_blob_array_size() < 1024 {
        return false;
    }

    // Default min pin length rp ids must be non-empty if max rp ids length is 0.
    if customization.max_rp_ids_length() == 0
        && customization.default_min_pin_length_rp_ids().is_empty()
    {
        return false;
    }

    true
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_invariants() {
        assert!(is_valid(&DEFAULT_CUSTOMIZATION));
    }
}
