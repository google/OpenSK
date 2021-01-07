// Copyright 2020 Google LLC
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

use super::check_pin_uv_auth_protocol;
use super::command::AuthenticatorConfigParameters;
use super::data_formats::{ConfigSubCommand, ConfigSubCommandParams, SetMinPinLengthParams};
use super::pin_protocol_v1::PinProtocolV1;
use super::response::ResponseData;
use super::status_code::Ctap2StatusCode;
use super::storage::PersistentStore;
use alloc::vec;

fn process_set_min_pin_length(
    persistent_store: &mut PersistentStore,
    pin_protocol_v1: &mut PinProtocolV1,
    params: SetMinPinLengthParams,
) -> Result<ResponseData, Ctap2StatusCode> {
    let SetMinPinLengthParams {
        new_min_pin_length,
        min_pin_length_rp_ids,
        force_change_pin,
    } = params;
    let store_min_pin_length = persistent_store.min_pin_length()?;
    let new_min_pin_length = new_min_pin_length.unwrap_or(store_min_pin_length);
    if new_min_pin_length < store_min_pin_length {
        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION);
    }
    let mut force_change_pin = force_change_pin.unwrap_or(false);
    if force_change_pin && persistent_store.pin_hash()?.is_none() {
        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
    }
    if let Some(old_length) = persistent_store.pin_code_point_length()? {
        force_change_pin |= new_min_pin_length > old_length;
    }
    pin_protocol_v1.force_pin_change |= force_change_pin;
    // TODO(kaczmarczyck) actually force a PIN change
    persistent_store.set_min_pin_length(new_min_pin_length)?;
    if let Some(min_pin_length_rp_ids) = min_pin_length_rp_ids {
        persistent_store.set_min_pin_length_rp_ids(min_pin_length_rp_ids)?;
    }
    Ok(ResponseData::AuthenticatorConfig)
}

pub fn process_config(
    persistent_store: &mut PersistentStore,
    pin_protocol_v1: &mut PinProtocolV1,
    params: AuthenticatorConfigParameters,
) -> Result<ResponseData, Ctap2StatusCode> {
    let AuthenticatorConfigParameters {
        sub_command,
        sub_command_params,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
    } = params;

    if persistent_store.pin_hash()?.is_some() {
        // TODO(kaczmarczyck) The error code is specified inconsistently with other commands.
        check_pin_uv_auth_protocol(pin_uv_auth_protocol)
            .map_err(|_| Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)?;
        let auth_param = pin_uv_auth_param.ok_or(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)?;
        let mut config_data = vec![0xFF; 32];
        config_data.extend(&[0x0D, sub_command as u8]);
        if let Some(sub_command_params) = sub_command_params.clone() {
            if !cbor::write(sub_command_params.into(), &mut config_data) {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
            }
        }
        if !pin_protocol_v1.verify_pin_auth_token(&config_data, &auth_param) {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }
    }

    match sub_command {
        ConfigSubCommand::SetMinPinLength => {
            if let Some(ConfigSubCommandParams::SetMinPinLength(params)) = sub_command_params {
                process_set_min_pin_length(persistent_store, pin_protocol_v1, params)
            } else {
                Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
            }
        }
        _ => Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER),
    }
}

#[cfg(test)]
mod test {
    use super::super::command::AuthenticatorConfigParameters;
    use super::*;
    use crypto::rng256::ThreadRng256;

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
            pin_uv_auth_protocol: Some(1),
        }
    }

    #[test]
    fn test_process_set_min_pin_length() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pin_uv_auth_token = [0x55; 32];
        let mut pin_protocol_v1 = PinProtocolV1::new_test(key_agreement_key, pin_uv_auth_token);

        // First, increase minimum PIN length from 4 to 6 without PIN auth.
        let min_pin_length = 6;
        let config_params = create_min_pin_config_params(min_pin_length, None);
        let config_response =
            process_config(&mut persistent_store, &mut pin_protocol_v1, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert_eq!(persistent_store.min_pin_length(), Ok(min_pin_length));

        // Second, increase minimum PIN length from 6 to 8 with PIN auth.
        // The stored PIN or its length don't matter since we control the token.
        persistent_store.set_pin(&[0x88; 16], 8).unwrap();
        let min_pin_length = 8;
        let mut config_params = create_min_pin_config_params(min_pin_length, None);
        let pin_auth = vec![
            0x5C, 0x69, 0x71, 0x29, 0xBD, 0xCC, 0x53, 0xE8, 0x3C, 0x97, 0x62, 0xDD, 0x90, 0x29,
            0xB2, 0xDE,
        ];
        config_params.pin_uv_auth_param = Some(pin_auth);
        let config_response =
            process_config(&mut persistent_store, &mut pin_protocol_v1, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert_eq!(persistent_store.min_pin_length(), Ok(min_pin_length));

        // Third, decreasing the minimum PIN length from 8 to 7 fails.
        let mut config_params = create_min_pin_config_params(7, None);
        let pin_auth = vec![
            0xC5, 0xEA, 0xC1, 0x5E, 0x7F, 0x80, 0x70, 0x1A, 0x4E, 0xC4, 0xAD, 0x85, 0x35, 0xD8,
            0xA7, 0x71,
        ];
        config_params.pin_uv_auth_param = Some(pin_auth);
        let config_response =
            process_config(&mut persistent_store, &mut pin_protocol_v1, config_params);
        assert_eq!(
            config_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION)
        );
        assert_eq!(persistent_store.min_pin_length(), Ok(min_pin_length));
    }

    #[test]
    fn test_process_set_min_pin_length_rp_ids() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pin_uv_auth_token = [0x55; 32];
        let mut pin_protocol_v1 = PinProtocolV1::new_test(key_agreement_key, pin_uv_auth_token);

        // First, set RP IDs without PIN auth.
        let min_pin_length = 6;
        let min_pin_length_rp_ids = vec!["example.com".to_string()];
        let config_params =
            create_min_pin_config_params(min_pin_length, Some(min_pin_length_rp_ids.clone()));
        let config_response =
            process_config(&mut persistent_store, &mut pin_protocol_v1, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert_eq!(persistent_store.min_pin_length(), Ok(min_pin_length));
        assert_eq!(
            persistent_store.min_pin_length_rp_ids(),
            Ok(min_pin_length_rp_ids)
        );

        // Second, change the RP IDs with PIN auth.
        let min_pin_length = 8;
        let min_pin_length_rp_ids = vec!["another.example.com".to_string()];
        // The stored PIN or its length don't matter since we control the token.
        persistent_store.set_pin(&[0x88; 16], 8).unwrap();
        let mut config_params =
            create_min_pin_config_params(min_pin_length, Some(min_pin_length_rp_ids.clone()));
        let pin_auth = vec![
            0x40, 0x51, 0x2D, 0xAC, 0x2D, 0xE2, 0x15, 0x77, 0x5C, 0xF9, 0x5B, 0x62, 0x9A, 0x2D,
            0xD6, 0xDA,
        ];
        config_params.pin_uv_auth_param = Some(pin_auth.clone());
        let config_response =
            process_config(&mut persistent_store, &mut pin_protocol_v1, config_params);
        assert_eq!(config_response, Ok(ResponseData::AuthenticatorConfig));
        assert_eq!(persistent_store.min_pin_length(), Ok(min_pin_length));
        assert_eq!(
            persistent_store.min_pin_length_rp_ids(),
            Ok(min_pin_length_rp_ids.clone())
        );

        // Third, changing RP IDs with bad PIN auth fails.
        // One PIN auth shouldn't work for different lengths.
        let mut config_params =
            create_min_pin_config_params(9, Some(min_pin_length_rp_ids.clone()));
        config_params.pin_uv_auth_param = Some(pin_auth.clone());
        let config_response =
            process_config(&mut persistent_store, &mut pin_protocol_v1, config_params);
        assert_eq!(
            config_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(persistent_store.min_pin_length(), Ok(min_pin_length));
        assert_eq!(
            persistent_store.min_pin_length_rp_ids(),
            Ok(min_pin_length_rp_ids.clone())
        );

        // Forth, changing RP IDs with bad PIN auth fails.
        // One PIN auth shouldn't work for different RP IDs.
        let mut config_params = create_min_pin_config_params(
            min_pin_length,
            Some(vec!["counter.example.com".to_string()]),
        );
        config_params.pin_uv_auth_param = Some(pin_auth);
        let config_response =
            process_config(&mut persistent_store, &mut pin_protocol_v1, config_params);
        assert_eq!(
            config_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(persistent_store.min_pin_length(), Ok(min_pin_length));
        assert_eq!(
            persistent_store.min_pin_length_rp_ids(),
            Ok(min_pin_length_rp_ids)
        );
    }

    #[test]
    fn test_process_config_vendor_prototype() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pin_uv_auth_token = [0x55; 32];
        let mut pin_protocol_v1 = PinProtocolV1::new_test(key_agreement_key, pin_uv_auth_token);

        let config_params = AuthenticatorConfigParameters {
            sub_command: ConfigSubCommand::VendorPrototype,
            sub_command_params: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let config_response =
            process_config(&mut persistent_store, &mut pin_protocol_v1, config_params);
        assert_eq!(
            config_response,
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );
    }
}