use std::slice::from_raw_parts;

use crate::api::customization::{Customization, CustomizationImpl};
use crate::ctap::data_formats::CredentialProtectionPolicy;

pub struct TestCustomization {
    pub default_cred_protect: Option<CredentialProtectionPolicy>,
    pub default_min_pin_length: u8,
    default_min_pin_length_rp_ids_backing_store: Vec<String>,
    default_min_pin_length_rp_ids: Vec<*const str>,
    pub enforce_always_uv: bool,
    pub max_msg_size: usize,
    pub max_pin_retries: u8,
    pub use_signature_counter: bool,
    pub max_rp_ids_length: usize,
}

impl TestCustomization {
    pub fn set_default_min_pin_length_rp_ids(&mut self, rp_ids: Vec<String>) {
        self.default_min_pin_length_rp_ids_backing_store = rp_ids;
        self.default_min_pin_length_rp_ids = self
            .default_min_pin_length_rp_ids_backing_store
            .iter()
            .map(|s| s.as_ref() as *const str)
            .collect::<Vec<_>>();
    }
}

impl Customization for TestCustomization {
    fn default_cred_protect(&self) -> Option<CredentialProtectionPolicy> {
        self.default_cred_protect
    }

    fn default_min_pin_length(&self) -> u8 {
        self.default_min_pin_length
    }

    fn default_min_pin_length_rp_ids(&self) -> &[&str] {
        let length = self.default_min_pin_length_rp_ids.len();
        let rp_ids = self.default_min_pin_length_rp_ids.as_ptr() as *const &str;
        unsafe { from_raw_parts(rp_ids, length) }
    }

    fn enforce_always_uv(&self) -> bool {
        self.enforce_always_uv
    }

    fn max_msg_size(&self) -> usize {
        self.max_msg_size
    }

    fn max_pin_retries(&self) -> u8 {
        self.max_pin_retries
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
            max_msg_size,
            max_pin_retries,
            use_signature_counter,
            max_rp_ids_length,
        } = c;

        let default_min_pin_length_rp_ids_backing_store = default_min_pin_length_rp_ids
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>();

        let mut ret = Self {
            default_cred_protect,
            default_min_pin_length,
            default_min_pin_length_rp_ids_backing_store,
            default_min_pin_length_rp_ids: vec![],
            enforce_always_uv,
            max_msg_size,
            max_pin_retries,
            use_signature_counter,
            max_rp_ids_length,
        };

        ret.default_min_pin_length_rp_ids = ret
            .default_min_pin_length_rp_ids_backing_store
            .iter()
            .map(|s| s.as_ref() as *const str)
            .collect::<Vec<_>>();

        ret
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

    #[test]
    fn test_vec_storage_impl() {
        let mut customization = TestCustomization::from(DEFAULT_CUSTOMIZATION.clone());
        assert!(customization.default_min_pin_length_rp_ids().is_empty());
        customization
            .set_default_min_pin_length_rp_ids(vec!["abc.com".to_owned(), "def.com".to_owned()]);
        assert_eq!(
            customization.default_min_pin_length_rp_ids(),
            ["abc.com", "def.com"]
        );
        customization.set_default_min_pin_length_rp_ids(vec!["example.com".to_owned()]);
        assert_eq!(
            customization.default_min_pin_length_rp_ids(),
            ["example.com"]
        );
    }
}
