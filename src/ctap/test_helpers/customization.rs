use crate::ctap::data_formats::EnterpriseAttestationMode;
use crate::env::test::customization::TestCustomization;

pub fn setup_enterprise_attestation(
    customization: &mut TestCustomization,
    mode: Option<EnterpriseAttestationMode>,
    rp_id_list: Option<Vec<String>>,
) {
    customization.enterprise_attestation_mode = mode;
    if let Some(rp_id_list) = rp_id_list {
        customization.enterprise_rp_id_list = rp_id_list;
    }
}
