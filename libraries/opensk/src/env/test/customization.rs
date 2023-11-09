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

use crate::api::customization::{Customization, CustomizationImpl, AAGUID_LENGTH};
use crate::ctap::data_formats::{CredentialProtectionPolicy, EnterpriseAttestationMode};
use alloc::string::String;
use alloc::vec::Vec;

pub struct TestCustomization {
    aaguid: &'static [u8; AAGUID_LENGTH],
    allows_pin_protocol_v1: bool,
    default_cred_protect: Option<CredentialProtectionPolicy>,
    default_min_pin_length: u8,
    default_min_pin_length_rp_ids: Vec<String>,
    enforce_always_uv: bool,
    enterprise_attestation_mode: Option<EnterpriseAttestationMode>,
    enterprise_rp_id_list: Vec<String>,
    max_msg_size: usize,
    max_pin_retries: u8,
    use_batch_attestation: bool,
    use_signature_counter: bool,
    max_cred_blob_length: usize,
    max_credential_count_in_list: Option<usize>,
    max_large_blob_array_size: usize,
    max_rp_ids_length: usize,
    max_supported_resident_keys: usize,
}

impl TestCustomization {
    pub fn set_allows_pin_protocol_v1(&mut self, is_allowed: bool) {
        self.allows_pin_protocol_v1 = is_allowed;
    }

    pub fn setup_enterprise_attestation(
        &mut self,
        mode: Option<EnterpriseAttestationMode>,
        rp_id_list: Option<Vec<String>>,
    ) {
        self.enterprise_attestation_mode = mode;
        if let Some(rp_id_list) = rp_id_list {
            self.enterprise_rp_id_list = rp_id_list;
        }
    }
}

impl Customization for TestCustomization {
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
        self.default_min_pin_length_rp_ids.clone()
    }

    fn enforce_always_uv(&self) -> bool {
        self.enforce_always_uv
    }

    fn enterprise_attestation_mode(&self) -> Option<EnterpriseAttestationMode> {
        self.enterprise_attestation_mode
    }

    fn enterprise_rp_id_list(&self) -> Vec<String> {
        self.enterprise_rp_id_list.clone()
    }

    fn is_enterprise_rp_id(&self, rp_id: &str) -> bool {
        self.enterprise_rp_id_list.iter().any(|id| id == rp_id)
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

impl From<CustomizationImpl> for TestCustomization {
    fn from(c: CustomizationImpl) -> Self {
        let CustomizationImpl {
            aaguid,
            allows_pin_protocol_v1,
            default_cred_protect,
            default_min_pin_length,
            default_min_pin_length_rp_ids,
            enforce_always_uv,
            enterprise_attestation_mode,
            enterprise_rp_id_list,
            max_msg_size,
            max_pin_retries,
            use_batch_attestation,
            use_signature_counter,
            max_cred_blob_length,
            max_credential_count_in_list,
            max_large_blob_array_size,
            max_rp_ids_length,
            max_supported_resident_keys,
        } = c;

        let default_min_pin_length_rp_ids = default_min_pin_length_rp_ids
            .iter()
            .map(|s| String::from(*s))
            .collect::<Vec<_>>();

        let enterprise_rp_id_list = enterprise_rp_id_list
            .iter()
            .map(|s| String::from(*s))
            .collect::<Vec<_>>();

        Self {
            aaguid,
            allows_pin_protocol_v1,
            default_cred_protect,
            default_min_pin_length,
            default_min_pin_length_rp_ids,
            enforce_always_uv,
            enterprise_attestation_mode,
            enterprise_rp_id_list,
            max_msg_size,
            max_pin_retries,
            use_batch_attestation,
            use_signature_counter,
            max_cred_blob_length,
            max_credential_count_in_list,
            max_large_blob_array_size,
            max_rp_ids_length,
            max_supported_resident_keys,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::customization::{is_valid, DEFAULT_CUSTOMIZATION};

    #[test]
    fn test_invariants() {
        let customization = TestCustomization::from(DEFAULT_CUSTOMIZATION.clone());
        assert!(is_valid(&customization));
    }
}
