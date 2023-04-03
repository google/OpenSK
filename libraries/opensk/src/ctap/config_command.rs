// Copyright 2020-2023 Google LLC
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

use super::client_pin::{ClientPin, PinPermission};
use super::command::AuthenticatorConfigParameters;
use super::data_formats::{ConfigSubCommand, ConfigSubCommandParams, SetMinPinLengthParams};
use super::response::ResponseData;
use super::status_code::Ctap2StatusCode;
use crate::api::customization::Customization;
use crate::ctap::storage;
use crate::env::Env;
use alloc::vec;

/// Processes the subcommand enableEnterpriseAttestation for AuthenticatorConfig.
fn process_enable_enterprise_attestation(
    env: &mut impl Env,
) -> Result<ResponseData, Ctap2StatusCode> {
    if env.customization().enterprise_attestation_mode().is_some() {
        storage::enable_enterprise_attestation(env)?;
        Ok(ResponseData::AuthenticatorConfig)
    } else {
        Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
    }
}

/// Processes the subcommand toggleAlwaysUv for AuthenticatorConfig.
fn process_toggle_always_uv(env: &mut impl Env) -> Result<ResponseData, Ctap2StatusCode> {
    storage::toggle_always_uv(env)?;
    Ok(ResponseData::AuthenticatorConfig)
}

/// Processes the subcommand setMinPINLength for AuthenticatorConfig.
fn process_set_min_pin_length(
    env: &mut impl Env,
    params: SetMinPinLengthParams,
) -> Result<ResponseData, Ctap2StatusCode> {
    let SetMinPinLengthParams {
        new_min_pin_length,
        min_pin_length_rp_ids,
        force_change_pin,
    } = params;
    let store_min_pin_length = storage::min_pin_length(env)?;
    let new_min_pin_length = new_min_pin_length.unwrap_or(store_min_pin_length);
    if new_min_pin_length < store_min_pin_length {
        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION);
    }
    let mut force_change_pin = force_change_pin.unwrap_or(false);
    if force_change_pin && storage::pin_hash(env)?.is_none() {
        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
    }
    if let Some(old_length) = storage::pin_code_point_length(env)? {
        force_change_pin |= new_min_pin_length > old_length;
    }
    if force_change_pin {
        storage::force_pin_change(env)?;
    }
    storage::set_min_pin_length(env, new_min_pin_length)?;
    if let Some(min_pin_length_rp_ids) = min_pin_length_rp_ids {
        storage::set_min_pin_length_rp_ids(env, min_pin_length_rp_ids)?;
    }
    Ok(ResponseData::AuthenticatorConfig)
}

/// Processes the AuthenticatorConfig command.
pub fn process_config<E: Env>(
    env: &mut E,
    client_pin: &mut ClientPin<E>,
    params: AuthenticatorConfigParameters,
) -> Result<ResponseData, Ctap2StatusCode> {
    let AuthenticatorConfigParameters {
        sub_command,
        sub_command_params,
        pin_uv_auth_protocol,
        pin_uv_auth_param,
    } = params;

    let enforce_uv =
        !matches!(sub_command, ConfigSubCommand::ToggleAlwaysUv) && storage::has_always_uv(env)?;
    if storage::pin_hash(env)?.is_some() || enforce_uv {
        let pin_uv_auth_param =
            pin_uv_auth_param.ok_or(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)?;
        let pin_uv_auth_protocol =
            pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
        // Constants are taken from the specification, section 6.11, step 4.2.
        let mut config_data = vec![0xFF; 32];
        config_data.extend(&[0x0D, sub_command as u8]);
        if let Some(sub_command_params) = sub_command_params.clone() {
            super::cbor_write(sub_command_params.into(), &mut config_data)?;
        }
        client_pin.verify_pin_uv_auth_token(
            &config_data,
            &pin_uv_auth_param,
            pin_uv_auth_protocol,
        )?;
        client_pin.has_permission(PinPermission::AuthenticatorConfiguration)?;
    }

    match sub_command {
        ConfigSubCommand::EnableEnterpriseAttestation => process_enable_enterprise_attestation(env),
        ConfigSubCommand::ToggleAlwaysUv => process_toggle_always_uv(env),
        ConfigSubCommand::SetMinPinLength => {
            if let Some(ConfigSubCommandParams::SetMinPinLength(params)) = sub_command_params {
                process_set_min_pin_length(env, params)
            } else {
                Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
            }
        }
        _ => Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::crypto::ecdh::SecretKey as _;
    use crate::api::customization::Customization;
    use crate::ctap::data_formats::PinUvAuthProtocol;
    use crate::ctap::pin_protocol::authenticate_pin_uv_auth_token;
    use crate::env::test::TestEnv;
    use crate::env::EcdhSk;

    #[test]
    fn test_process_enable_enterprise_attestation() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );

        let config_params = AuthenticatorConfigParameters {
            sub_command: ConfigSubCommand::EnableEnterpriseAttestation,
            sub_command_params: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let config_response = process_config(&mut env, &mut client_pin, config_params);

        if env.customization().enterprise_attestation_mode().is_some() {
            assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
            assert_eq!(storage::enterprise_attestation(&mut env), Ok(true));
        } else {
            assert_eq!(
                config_response,
                Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
            );
        }
    }

    #[test]
    fn test_process_toggle_always_uv() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );

        let config_params = AuthenticatorConfigParameters {
            sub_command: ConfigSubCommand::ToggleAlwaysUv,
            sub_command_params: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert!(storage::has_always_uv(&mut env).unwrap());

        let config_params = AuthenticatorConfigParameters {
            sub_command: ConfigSubCommand::ToggleAlwaysUv,
            sub_command_params: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        if env.customization().enforce_always_uv() {
            assert_eq!(
                config_response,
                Err(Ctap2StatusCode::CTAP2_ERR_OPERATION_DENIED)
            );
        } else {
            assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
            assert!(!storage::has_always_uv(&mut env).unwrap());
        }
    }

    fn test_helper_process_toggle_always_uv_with_pin(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            pin_uv_auth_protocol,
        );
        storage::set_pin(&mut env, &[0x88; 16], 4).unwrap();

        let mut config_data = vec![0xFF; 32];
        config_data.extend(&[0x0D, ConfigSubCommand::ToggleAlwaysUv as u8]);
        let pin_uv_auth_param =
            authenticate_pin_uv_auth_token(&pin_uv_auth_token, &config_data, pin_uv_auth_protocol);
        let config_params = AuthenticatorConfigParameters {
            sub_command: ConfigSubCommand::ToggleAlwaysUv,
            sub_command_params: None,
            pin_uv_auth_param: Some(pin_uv_auth_param.clone()),
            pin_uv_auth_protocol: Some(pin_uv_auth_protocol),
        };
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        if env.customization().enforce_always_uv() {
            assert_eq!(
                config_response,
                Err(Ctap2StatusCode::CTAP2_ERR_OPERATION_DENIED)
            );
            return;
        }
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert!(storage::has_always_uv(&mut env).unwrap());

        let config_params = AuthenticatorConfigParameters {
            sub_command: ConfigSubCommand::ToggleAlwaysUv,
            sub_command_params: None,
            pin_uv_auth_param: Some(pin_uv_auth_param),
            pin_uv_auth_protocol: Some(pin_uv_auth_protocol),
        };
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert!(!storage::has_always_uv(&mut env).unwrap());
    }

    #[test]
    fn test_process_toggle_always_uv_with_pin_v1() {
        test_helper_process_toggle_always_uv_with_pin(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_toggle_always_uv_with_pin_v2() {
        test_helper_process_toggle_always_uv_with_pin(PinUvAuthProtocol::V2);
    }

    fn create_min_pin_config_params(
        min_pin_length: u8,
        min_pin_length_rp_ids: Option<Vec<String>>,
    ) -> AuthenticatorConfigParameters {
        let set_min_pin_length_params = SetMinPinLengthParams {
            new_min_pin_length: Some(min_pin_length),
            min_pin_length_rp_ids,
            force_change_pin: None,
        };
        AuthenticatorConfigParameters {
            sub_command: ConfigSubCommand::SetMinPinLength,
            sub_command_params: Some(ConfigSubCommandParams::SetMinPinLength(
                set_min_pin_length_params,
            )),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
        }
    }

    #[test]
    fn test_process_set_min_pin_length() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );

        // First, increase minimum PIN length from 4 to 6 without PIN auth.
        let min_pin_length = 6;
        let config_params = create_min_pin_config_params(min_pin_length, None);
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert_eq!(storage::min_pin_length(&mut env), Ok(min_pin_length));

        // Second, increase minimum PIN length from 6 to 8 with PIN auth.
        // The stored PIN or its length don't matter since we control the token.
        storage::set_pin(&mut env, &[0x88; 16], 8).unwrap();
        let min_pin_length = 8;
        let mut config_params = create_min_pin_config_params(min_pin_length, None);
        let pin_uv_auth_param = vec![
            0x5C, 0x69, 0x71, 0x29, 0xBD, 0xCC, 0x53, 0xE8, 0x3C, 0x97, 0x62, 0xDD, 0x90, 0x29,
            0xB2, 0xDE,
        ];
        config_params.pin_uv_auth_param = Some(pin_uv_auth_param);
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert_eq!(storage::min_pin_length(&mut env), Ok(min_pin_length));

        // Third, decreasing the minimum PIN length from 8 to 7 fails.
        let mut config_params = create_min_pin_config_params(7, None);
        let pin_uv_auth_param = vec![
            0xC5, 0xEA, 0xC1, 0x5E, 0x7F, 0x80, 0x70, 0x1A, 0x4E, 0xC4, 0xAD, 0x85, 0x35, 0xD8,
            0xA7, 0x71,
        ];
        config_params.pin_uv_auth_param = Some(pin_uv_auth_param);
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(
            config_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION)
        );
        assert_eq!(storage::min_pin_length(&mut env), Ok(min_pin_length));
    }

    #[test]
    fn test_process_set_min_pin_length_rp_ids() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );

        // First, set RP IDs without PIN auth.
        let min_pin_length = 6;
        let min_pin_length_rp_ids = vec!["example.com".to_string()];
        let config_params =
            create_min_pin_config_params(min_pin_length, Some(min_pin_length_rp_ids.clone()));
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert_eq!(storage::min_pin_length(&mut env), Ok(min_pin_length));
        assert_eq!(
            storage::min_pin_length_rp_ids(&mut env),
            Ok(min_pin_length_rp_ids)
        );

        // Second, change the RP IDs with PIN auth.
        let min_pin_length = 8;
        let min_pin_length_rp_ids = vec!["another.example.com".to_string()];
        // The stored PIN or its length don't matter since we control the token.
        storage::set_pin(&mut env, &[0x88; 16], 8).unwrap();
        let mut config_params =
            create_min_pin_config_params(min_pin_length, Some(min_pin_length_rp_ids.clone()));
        let pin_uv_auth_param = vec![
            0x40, 0x51, 0x2D, 0xAC, 0x2D, 0xE2, 0x15, 0x77, 0x5C, 0xF9, 0x5B, 0x62, 0x9A, 0x2D,
            0xD6, 0xDA,
        ];
        config_params.pin_uv_auth_param = Some(pin_uv_auth_param.clone());
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert_eq!(storage::min_pin_length(&mut env), Ok(min_pin_length));
        assert_eq!(
            storage::min_pin_length_rp_ids(&mut env),
            Ok(min_pin_length_rp_ids.clone())
        );

        // Third, changing RP IDs with bad PIN auth fails.
        // One PIN auth shouldn't work for different lengths.
        let mut config_params =
            create_min_pin_config_params(9, Some(min_pin_length_rp_ids.clone()));
        config_params.pin_uv_auth_param = Some(pin_uv_auth_param.clone());
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(
            config_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(storage::min_pin_length(&mut env), Ok(min_pin_length));
        assert_eq!(
            storage::min_pin_length_rp_ids(&mut env),
            Ok(min_pin_length_rp_ids.clone())
        );

        // Forth, changing RP IDs with bad PIN auth fails.
        // One PIN auth shouldn't work for different RP IDs.
        let mut config_params = create_min_pin_config_params(
            min_pin_length,
            Some(vec!["counter.example.com".to_string()]),
        );
        config_params.pin_uv_auth_param = Some(pin_uv_auth_param);
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(
            config_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(storage::min_pin_length(&mut env), Ok(min_pin_length));
        assert_eq!(
            storage::min_pin_length_rp_ids(&mut env),
            Ok(min_pin_length_rp_ids)
        );
    }

    #[test]
    fn test_process_set_min_pin_length_force_pin_change_implicit() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );

        storage::set_pin(&mut env, &[0x88; 16], 4).unwrap();
        // Increase min PIN, force PIN change.
        let min_pin_length = 6;
        let mut config_params = create_min_pin_config_params(min_pin_length, None);
        let pin_uv_auth_param = Some(vec![
            0x81, 0x37, 0x37, 0xF3, 0xD8, 0x69, 0xBD, 0x74, 0xFE, 0x88, 0x30, 0x8C, 0xC4, 0x2E,
            0xA8, 0xC8,
        ]);
        config_params.pin_uv_auth_param = pin_uv_auth_param;
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert_eq!(storage::min_pin_length(&mut env), Ok(min_pin_length));
        assert_eq!(storage::has_force_pin_change(&mut env), Ok(true));
    }

    #[test]
    fn test_process_set_min_pin_length_force_pin_change_explicit() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );

        storage::set_pin(&mut env, &[0x88; 16], 4).unwrap();
        let pin_uv_auth_param = Some(vec![
            0xE3, 0x74, 0xF4, 0x27, 0xBE, 0x7D, 0x40, 0xB5, 0x71, 0xB6, 0xB4, 0x1A, 0xD2, 0xC1,
            0x53, 0xD7,
        ]);
        let set_min_pin_length_params = SetMinPinLengthParams {
            new_min_pin_length: Some(storage::min_pin_length(&mut env).unwrap()),
            min_pin_length_rp_ids: None,
            force_change_pin: Some(true),
        };
        let config_params = AuthenticatorConfigParameters {
            sub_command: ConfigSubCommand::SetMinPinLength,
            sub_command_params: Some(ConfigSubCommandParams::SetMinPinLength(
                set_min_pin_length_params,
            )),
            pin_uv_auth_param,
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
        };
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert_eq!(storage::has_force_pin_change(&mut env), Ok(true));
    }

    #[test]
    fn test_process_config_vendor_prototype() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );

        let config_params = AuthenticatorConfigParameters {
            sub_command: ConfigSubCommand::VendorPrototype,
            sub_command_params: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let config_response = process_config(&mut env, &mut client_pin, config_params);
        assert_eq!(
            config_response,
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );
    }
}
