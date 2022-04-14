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

    /// Maximum message size send for CTAP commands.
    ///
    /// The maximum value is 7609, as HID packets can not encode longer messages.
    /// 1024 is the default mentioned in the authenticatorLargeBlobs commands.
    /// Larger values are preferred, as that allows more parameters in commands.
    /// If long commands are too unreliable on your hardware, consider decreasing
    /// this value.
    fn max_msg_size(&self) -> usize;
}

#[derive(Clone)]
pub struct CustomizationImpl {
    pub default_cred_protect: Option<CredentialProtectionPolicy>,
    pub max_msg_size: usize,
}

pub const DEFAULT_CUSTOMIZATION: CustomizationImpl = CustomizationImpl {
    default_cred_protect: None,
    max_msg_size: 7609,
};

impl Customization for CustomizationImpl {
    fn default_cred_protect(&self) -> Option<CredentialProtectionPolicy> {
        self.default_cred_protect
    }

    fn max_msg_size(&self) -> usize {
        self.max_msg_size
    }
}

#[cfg(feature = "std")]
pub fn is_valid(customization: &impl Customization) -> bool {
    // Max message size must be between 1024 and 7609.
    if customization.max_msg_size() < 1024 || customization.max_msg_size() > 7609 {
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
