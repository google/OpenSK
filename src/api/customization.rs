// Copyright 2022 Google LLC
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

use crate::ctap::data_formats::CredentialProtectionPolicy;

pub trait Customization {
    // ###########################################################################
    // Constants for adjusting privacy and protection levels.
    // ###########################################################################

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
    /// - default_min_pin_length_rp_ids() must be non-empty if MAX_RP_IDS_LENGTH is 0.
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
    /// - default_min_pin_length_rp_ids() must be non-empty if MAX_RP_IDS_LENGTH is 0
    ///
    /// Only the RP IDs listed in default_min_pin_length_rp_ids are allowed to read
    /// the minimum PIN length with the minPinLength extension.
    fn default_min_pin_length_rp_ids(&self) -> &[&str];

    /// Maximum message size send for CTAP commands.
    ///
    /// The maximum value is 7609, as HID packets can not encode longer messages.
    /// 1024 is the default mentioned in the authenticatorLargeBlobs commands.
    /// Larger values are preferred, as that allows more parameters in commands.
    /// If long commands are too unreliable on your hardware, consider decreasing
    /// this value.
    fn max_msg_size(&self) -> usize;

    // ###########################################################################
    // Constants for performance optimization or adapting to different hardware.
    //
    // Those constants may be modified before compilation to tune the behavior of
    // the key.
    // ###########################################################################

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
}

#[derive(Clone)]
pub struct CustomizationImpl {
    pub default_min_pin_length: u8,
    pub default_min_pin_length_rp_ids: &'static [&'static str],
    pub default_cred_protect: Option<CredentialProtectionPolicy>,
    pub max_msg_size: usize,
    pub max_rp_ids_length: usize,
}

pub const DEFAULT_CUSTOMIZATION: CustomizationImpl = CustomizationImpl {
    default_min_pin_length: 4,
    default_min_pin_length_rp_ids: &[],
    default_cred_protect: None,
    max_msg_size: 7609,
    max_rp_ids_length: 8,
};

impl Customization for CustomizationImpl {
    fn default_cred_protect(&self) -> Option<CredentialProtectionPolicy> {
        self.default_cred_protect
    }

    fn default_min_pin_length(&self) -> u8 {
        self.default_min_pin_length
    }

    fn default_min_pin_length_rp_ids(&self) -> &[&str] {
        self.default_min_pin_length_rp_ids
    }

    fn max_msg_size(&self) -> usize {
        self.max_msg_size
    }

    fn max_rp_ids_length(&self) -> usize {
        self.max_rp_ids_length
    }
}

#[cfg(feature = "std")]
pub fn is_valid(customization: &impl Customization) -> bool {
    // Max message size must be between 1024 and 7609.
    if customization.max_msg_size() < 1024 || customization.max_msg_size() > 7609 {
        return false;
    }

    // Default min pin length must be between 4 and 63.
    if customization.default_min_pin_length() < 4 || customization.default_min_pin_length() > 63 {
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
    #[allow(clippy::assertions_on_constants)]
    fn test_invariants() {
        assert!(is_valid(&DEFAULT_CUSTOMIZATION));
    }
}
