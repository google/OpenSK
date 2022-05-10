use crate::clock::CtapInstant;
use crate::ctap::command::{
    AuthenticatorAttestationMaterial, AuthenticatorConfigParameters,
    AuthenticatorVendorConfigureParameters, Command,
};
use crate::ctap::data_formats::ConfigSubCommand;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::{key_material, Channel, CtapState};
use crate::env::Env;

// In tests where we define a dummy user-presence check that immediately returns, the channel
// ID is irrelevant, so we pass this (dummy but valid) value.
const DUMMY_CHANNEL: Channel = Channel::MainHid([0x12, 0x34, 0x56, 0x78]);
#[cfg(feature = "vendor_hid")]
const VENDOR_CHANNEL: Channel = Channel::VendorHid([0x12, 0x34, 0x56, 0x78]);

pub fn setup_enterprise_attestation(
    state: &mut CtapState,
    env: &mut impl Env,
) -> Result<AuthenticatorAttestationMaterial, Ctap2StatusCode> {
    let dummy_key = [0x41; key_material::ATTESTATION_PRIVATE_KEY_LENGTH];
    let dummy_cert = vec![0xdd; 20];
    let attestation_material = AuthenticatorAttestationMaterial {
        certificate: dummy_cert,
        private_key: dummy_key,
    };
    let configure_params = AuthenticatorVendorConfigureParameters {
        lockdown: false,
        attestation_material: Some(attestation_material.clone()),
    };
    #[cfg(feature = "vendor_hid")]
    let vendor_channel = VENDOR_CHANNEL;
    #[cfg(not(feature = "vendor_hid"))]
    let vendor_channel = DUMMY_CHANNEL;
    let vendor_command = Command::AuthenticatorVendorConfigure(configure_params);
    state.process_parsed_command(env, vendor_command, vendor_channel, CtapInstant::new(0))?;

    let config_params = AuthenticatorConfigParameters {
        sub_command: ConfigSubCommand::EnableEnterpriseAttestation,
        sub_command_params: None,
        pin_uv_auth_param: None,
        pin_uv_auth_protocol: None,
    };
    let config_command = Command::AuthenticatorConfig(config_params);
    state.process_parsed_command(env, config_command, DUMMY_CHANNEL, CtapInstant::new(0))?;

    Ok(attestation_material)
}
