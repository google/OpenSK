use crate::api::customization::{Customization, CustomizationImpl};
use crate::ctap::data_formats::{CredentialProtectionPolicy, EnterpriseAttestationMode};
use alloc::string::String;
use alloc::vec::Vec;

pub struct TestCustomization {
    pub default_cred_protect: Option<CredentialProtectionPolicy>,
    pub default_min_pin_length: u8,
    pub default_min_pin_length_rp_ids: Vec<String>,
    pub enforce_always_uv: bool,
    pub enterprise_attestation_mode: Option<EnterpriseAttestationMode>,
    pub enterprise_rp_id_list: Vec<String>,
    pub max_msg_size: usize,
    pub max_pin_retries: u8,
    pub use_batch_attestation: bool,
    pub use_signature_counter: bool,
    pub max_rp_ids_length: usize,
}

impl Customization for TestCustomization {
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

    fn max_rp_ids_length(&self) -> usize {
        self.max_rp_ids_length
    }
}

impl From<CustomizationImpl> for TestCustomization {
    fn from(c: CustomizationImpl) -> Self {
        let CustomizationImpl {
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
            max_rp_ids_length,
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
            max_rp_ids_length,
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
