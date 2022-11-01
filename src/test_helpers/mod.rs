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

use crate::clock::CtapInstant;
use crate::ctap::client_pin::{ClientPin, PIN_TOKEN_LENGTH};
use crate::ctap::command::{
    AuthenticatorAttestationMaterial, AuthenticatorConfigParameters,
    AuthenticatorVendorConfigureParameters, Command,
};
use crate::ctap::data_formats::{ConfigSubCommand, PinUvAuthProtocol};
use crate::ctap::pin_protocol::authenticate_pin_uv_auth_token;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::{key_material, storage, Channel, CtapState};
use crate::env::Env;

// In tests where we define a dummy user-presence check that immediately returns, the channel
// ID is irrelevant, so we pass this (dummy but valid) value.
const DUMMY_CHANNEL: Channel = Channel::MainHid([0x12, 0x34, 0x56, 0x78]);
#[cfg(feature = "vendor_hid")]
const VENDOR_CHANNEL: Channel = Channel::VendorHid([0x12, 0x34, 0x56, 0x78]);

pub fn enable_enterprise_attestation(
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

pub fn enable_pin_uv(
    state: &mut CtapState,
    env: &mut impl Env,
    pin_uv_auth_protocol: PinUvAuthProtocol,
    slot_id: usize,
    client_data_hash: &[u8],
) -> Result<Vec<u8>, Ctap2StatusCode> {
    let key_agreement_key = crypto::ecdh::SecKey::gensk(env.rng());
    let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
    let client_pin = ClientPin::new_test(
        env,
        slot_id,
        key_agreement_key,
        pin_uv_auth_token,
        pin_uv_auth_protocol,
    );
    state.set_client_pin_for_test(client_pin);
    storage::set_pin(env, slot_id, &[0x88; 16], 4)?;

    Ok(authenticate_pin_uv_auth_token(
        &pin_uv_auth_token,
        client_data_hash,
        pin_uv_auth_protocol,
    ))
}
