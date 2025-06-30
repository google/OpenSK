// Copyright 2025 Google LLC
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
use super::command::{
    AuthenticatorBioEnrollmentParameters, BioEnrollmentSubCommand, BioEnrollmentSubCommandParams,
};
use super::data_formats::{extract_byte_string, extract_map, extract_text_string, ok_or_missing};
use super::response::{AuthenticatorBioEnrollmentResponse, ResponseData};
use super::status_code::{Ctap2StatusCode, CtapResult};
use super::{send_packets, storage, Channel, CtapHid, KeepaliveStatus};
use crate::api::customization::Customization;
use crate::api::fingerprint::{Fingerprint, FingerprintCheckError};
use crate::api::persist::Persist;
use crate::env::Env;
use crate::Transport;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use sk_cbor as cbor;
use sk_cbor::{cbor_map_options, destructure_cbor_map};

/// Identifier for internal fingerprint modality.
const MODALITY: u64 = 1;
/// Maximum wait time for fingerprint authentication.
const UV_TIMEOUT_MS: usize = 30000;
/// Wait time for a fingerprint sensor response per iteration.
const FINGERPRINT_TIMEOUT_MS: usize = 500;

#[derive(Debug, PartialEq, Eq)]
pub struct TemplateInfo {
    pub template_id: Vec<u8>,
    pub template_friendly_name: Option<String>,
}

impl TryFrom<cbor::Value> for TemplateInfo {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> CtapResult<Self> {
        destructure_cbor_map! {
            let {
                0x01 => template_id,
                0x02 => template_friendly_name,
            } = extract_map(cbor_value)?;
        }

        let template_id = extract_byte_string(ok_or_missing(template_id)?)?;
        let template_friendly_name = template_friendly_name
            .map(extract_text_string)
            .transpose()?;

        Ok(Self {
            template_id,
            template_friendly_name,
        })
    }
}

impl From<TemplateInfo> for cbor::Value {
    fn from(template_info: TemplateInfo) -> Self {
        cbor_map_options! {
            0x01 => template_info.template_id,
            0x02 => template_info.template_friendly_name,
        }
    }
}

/// Uses to fingerprint sensor to establish user verification.
pub fn perform_built_in_uv<E: Env>(
    env: &mut E,
    channel: Channel,
    internal_retry: bool,
) -> CtapResult<()> {
    if storage::uv_retries(env)? == 0 {
        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
    }
    env.fingerprint().check_fingerprint_init();
    let result = check_fingerprint_loop(env, channel, internal_retry);
    env.fingerprint().check_fingerprint_complete();
    result
}

/// Helper function that blinks LEDs while trying fingerprint UV.
///
/// Does not clear LEDs.
fn check_fingerprint_loop<E: Env>(
    env: &mut E,
    channel: Channel,
    internal_retry: bool,
) -> CtapResult<()> {
    const FINGERPRINT_TIMEOUT_LOOPS: usize = UV_TIMEOUT_MS / FINGERPRINT_TIMEOUT_MS;
    let mut retries = if internal_retry {
        env.customization().max_uv_attempts_for_internal_retries()
    } else {
        1
    };
    let (cid, transport) = match channel {
        Channel::MainHid(cid) => (cid, Transport::MainHid),
        #[cfg(feature = "vendor_hid")]
        Channel::VendorHid(cid) => (cid, Transport::VendorHid),
    };
    let endpoint = transport.usb_endpoint();

    // We need to give the user time to touch the device during UV.
    // Also, on Windows, it seems we need to send KEEPALIVEs to
    // avoid timeouts, so we need to do the check incrementally.
    for _ in 0..FINGERPRINT_TIMEOUT_LOOPS {
        match env.fingerprint().check_fingerprint(FINGERPRINT_TIMEOUT_MS) {
            Ok(()) => {
                return storage::reset_uv_retries(env);
            }
            Err(error) => {
                match error {
                    FingerprintCheckError::NoMatch | FingerprintCheckError::Other => {
                        storage::decr_uv_retries(env)?;
                        if storage::uv_retries(env)? == 0 {
                            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
                        }
                        retries -= 1;
                        if retries == 0 {
                            return Err(Ctap2StatusCode::CTAP2_ERR_UV_INVALID);
                        }
                    }
                    FingerprintCheckError::Timeout => {
                        // Send a KEEPALIVE to avoid timeouts on Windows.
                        let keepalive_msg = CtapHid::<E>::keepalive(cid, KeepaliveStatus::UpNeeded);
                        send_packets(env, endpoint, keepalive_msg)?;
                    }
                }
            }
        }
    }
    Err(Ctap2StatusCode::CTAP2_ERR_USER_ACTION_TIMEOUT)
}

fn enroll_begin<E: Env>(
    env: &mut E,
    sub_command_params: BioEnrollmentSubCommandParams,
) -> CtapResult<ResponseData> {
    let template_id = env.fingerprint().prepare_enrollment()?;
    let timeout_ms = sub_command_params.timeout_milliseconds;
    let (sample_status, remaining_samples) =
        env.fingerprint().capture_sample(&template_id, timeout_ms)?;
    let response = AuthenticatorBioEnrollmentResponse {
        template_id: Some(template_id),
        last_enroll_sample_status: Some(sample_status),
        remaining_samples: Some(remaining_samples as u64),
        ..Default::default()
    };
    Ok(ResponseData::AuthenticatorBioEnrollment(Some(response)))
}

fn enroll_capture_next_sample<E: Env>(
    env: &mut E,
    sub_command_params: BioEnrollmentSubCommandParams,
) -> CtapResult<ResponseData> {
    let template_id = ok_or_missing(sub_command_params.template_id)?;
    let timeout_ms = sub_command_params.timeout_milliseconds;
    let (sample_status, remaining_samples) =
        env.fingerprint().capture_sample(&template_id, timeout_ms)?;
    if remaining_samples == 0 {
        env.persist().store_template_id(template_id)?;
    }
    let response = AuthenticatorBioEnrollmentResponse {
        last_enroll_sample_status: Some(sample_status),
        remaining_samples: Some(remaining_samples as u64),
        ..Default::default()
    };
    Ok(ResponseData::AuthenticatorBioEnrollment(Some(response)))
}

fn cancel_current_enrollment<E: Env>(env: &mut E) -> CtapResult<ResponseData> {
    env.fingerprint().cancel_enrollment()?;
    Ok(ResponseData::AuthenticatorBioEnrollment(None))
}

fn enumerate_enrollments<E: Env>(env: &mut E) -> CtapResult<ResponseData> {
    let template_infos = env.persist().template_infos()?;
    if template_infos.is_empty() {
        return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
    }
    let response = AuthenticatorBioEnrollmentResponse {
        template_infos: Some(template_infos),
        ..Default::default()
    };
    Ok(ResponseData::AuthenticatorBioEnrollment(Some(response)))
}

fn set_friendly_name<E: Env>(
    env: &mut E,
    sub_command_params: BioEnrollmentSubCommandParams,
) -> CtapResult<ResponseData> {
    let template_id = ok_or_missing(sub_command_params.template_id)?;
    let friendly_name = ok_or_missing(sub_command_params.template_friendly_name)?;
    if friendly_name.len() > env.customization().max_template_friendly_name() {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_LENGTH);
    }
    env.persist()
        .store_friendly_name(&template_id, friendly_name)?;
    Ok(ResponseData::AuthenticatorBioEnrollment(None))
}

fn remove_enrollment<E: Env>(
    env: &mut E,
    sub_command_params: BioEnrollmentSubCommandParams,
) -> CtapResult<ResponseData> {
    let template_id = ok_or_missing(sub_command_params.template_id)?;
    // Will return an error if the template_id is unknown.
    env.persist().remove_template_id(&template_id)?;
    env.fingerprint().remove_enrollment(&template_id)?;
    Ok(ResponseData::AuthenticatorBioEnrollment(None))
}

fn get_fingerprint_sensor_info<E: Env>(env: &mut E) -> CtapResult<ResponseData> {
    let response = AuthenticatorBioEnrollmentResponse {
        modality: Some(MODALITY),
        fingerprint_kind: Some(env.fingerprint().fingerprint_kind() as u64),
        max_capture_samples_required_for_enroll: Some(
            env.fingerprint().max_capture_samples_required_for_enroll() as u64,
        ),
        max_template_friendly_name: Some(env.customization().max_template_friendly_name() as u64),
        ..Default::default()
    };
    Ok(ResponseData::AuthenticatorBioEnrollment(Some(response)))
}

pub fn process_bio_enrollment<E: Env>(
    env: &mut E,
    client_pin: &mut ClientPin<E>,
    params: AuthenticatorBioEnrollmentParameters,
) -> CtapResult<ResponseData> {
    // Enforcing modaility is not explicitly mentioned in the specification.
    // https://github.com/fido-alliance/fido-2-specs/issues/1673
    // Let's be strict until we know which is correct.
    if params.sub_command.is_some() {
        let modality = ok_or_missing(params.modality)?;
        if modality != MODALITY {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
    }
    // Some subcommands don't need parameters or authentication.
    match params.sub_command {
        Some(BioEnrollmentSubCommand::CancelCurrentEnrollment) => {
            return cancel_current_enrollment(env);
        }
        Some(BioEnrollmentSubCommand::GetFingerprintSensorInfo) => {
            return get_fingerprint_sensor_info(env);
        }
        None => {
            if params.get_modality != Some(true) {
                return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
            }
            let response = AuthenticatorBioEnrollmentResponse {
                modality: Some(MODALITY),
                ..Default::default()
            };
            return Ok(ResponseData::AuthenticatorBioEnrollment(Some(response)));
        }
        _ => {}
    }
    let sub_command = params.sub_command.unwrap();
    let pin_uv_auth_param = params
        .pin_uv_auth_param
        .ok_or(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)?;
    let pin_uv_auth_protocol = params
        .pin_uv_auth_protocol
        .ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
    let mut command_data = vec![MODALITY as u8, sub_command as u8];
    if let Some(sub_command_params) = params.sub_command_params.clone() {
        super::cbor_write(sub_command_params.into(), &mut command_data)?;
    }
    client_pin.verify_pin_uv_auth_token(&command_data, &pin_uv_auth_param, pin_uv_auth_protocol)?;
    client_pin.has_permission(PinPermission::BioEnrollment)?;
    // Now we process all other subcommands that need PIN UV authentication.
    if sub_command == BioEnrollmentSubCommand::EnumerateEnrollments {
        return enumerate_enrollments(env);
    }
    let sub_command_params = ok_or_missing(params.sub_command_params)?;
    match sub_command {
        BioEnrollmentSubCommand::EnrollBegin => enroll_begin(env, sub_command_params),
        BioEnrollmentSubCommand::EnrollCaptureNextSample => {
            enroll_capture_next_sample(env, sub_command_params)
        }
        BioEnrollmentSubCommand::SetFriendlyName => set_friendly_name(env, sub_command_params),
        BioEnrollmentSubCommand::RemoveEnrollment => remove_enrollment(env, sub_command_params),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::crypto::ecdh::SecretKey;
    use crate::ctap::data_formats::PinUvAuthProtocol;
    use crate::ctap::pin_protocol::authenticate_pin_uv_auth_token;
    use crate::env::test::TestEnv;
    use crate::env::EcdhSk;
    use sk_cbor::cbor_map;

    const DUMMY_CHANNEL: Channel = Channel::MainHid([0x12, 0x34, 0x56, 0x78]);

    fn create_fingerprint(env: &mut TestEnv) -> Vec<u8> {
        let template_id = env.fingerprint().prepare_enrollment().unwrap();
        while env
            .fingerprint()
            .capture_sample(&template_id, Some(30_000))
            .unwrap()
            .1
            > 0
        {}
        assert_eq!(env.persist().store_template_id(template_id.clone()), Ok(()));
        template_id
    }

    #[test]
    fn test_perform_built_in_uv() {
        let mut env = TestEnv::default();
        create_fingerprint(&mut env);
        assert_eq!(perform_built_in_uv(&mut env, DUMMY_CHANNEL, true), Ok(()));
        assert_eq!(perform_built_in_uv(&mut env, DUMMY_CHANNEL, false), Ok(()));
    }

    #[test]
    fn test_perform_built_in_uv_unenrolled() {
        let mut env = TestEnv::default();
        assert_eq!(
            perform_built_in_uv(&mut env, DUMMY_CHANNEL, false),
            Err(Ctap2StatusCode::CTAP2_ERR_UV_INVALID)
        );
    }

    #[test]
    fn test_perform_built_in_uv_unenrolled_internal_retry() {
        let mut env = TestEnv::default();
        if env.customization().max_uv_attempts_for_internal_retries()
            == env.customization().max_uv_retries()
        {
            assert_eq!(
                perform_built_in_uv(&mut env, DUMMY_CHANNEL, true),
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED)
            );
        } else {
            assert_eq!(
                perform_built_in_uv(&mut env, DUMMY_CHANNEL, true),
                Err(Ctap2StatusCode::CTAP2_ERR_UV_INVALID)
            );
        }
    }

    #[test]
    fn test_from_into_template_info() {
        let cbor_template_info = cbor_map! {
            0x01 => vec![0x00],
            0x02 => "Name",
        };
        let template_info = TemplateInfo::try_from(cbor_template_info.clone());
        let expected_template_info = TemplateInfo {
            template_id: vec![0x00],
            template_friendly_name: Some(String::from("Name")),
        };
        assert_eq!(template_info, Ok(expected_template_info));
        let created_cbor: cbor::Value = template_info.unwrap().into();
        assert_eq!(created_cbor, cbor_template_info);
    }

    #[test]
    fn test_enumerate_enrollments() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let pin_uv_auth_protocol = PinUvAuthProtocol::V2;
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            pin_uv_auth_protocol,
        );
        env.persist().set_pin(&[0x88; 16], 4).unwrap();

        let sub_command = BioEnrollmentSubCommand::EnumerateEnrollments;
        let command_data = vec![MODALITY as u8, sub_command as u8];
        let pin_uv_auth_param =
            authenticate_pin_uv_auth_token(&pin_uv_auth_token, &command_data, pin_uv_auth_protocol);
        let params = AuthenticatorBioEnrollmentParameters {
            modality: Some(MODALITY),
            sub_command: Some(sub_command),
            sub_command_params: None,
            pin_uv_auth_protocol: Some(pin_uv_auth_protocol),
            pin_uv_auth_param: Some(pin_uv_auth_param),
            get_modality: None,
        };
        let response = process_bio_enrollment(&mut env, &mut client_pin, params.clone());
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION));

        let template_id = create_fingerprint(&mut env);
        let response = process_bio_enrollment(&mut env, &mut client_pin, params);
        match response.unwrap() {
            ResponseData::AuthenticatorBioEnrollment(Some(response)) => {
                assert!(response.modality.is_none());
                assert!(response.fingerprint_kind.is_none());
                assert!(response.max_capture_samples_required_for_enroll.is_none());
                assert!(response.template_id.is_none());
                assert!(response.last_enroll_sample_status.is_none());
                assert!(response.remaining_samples.is_none());
                assert!(response.max_template_friendly_name.is_none());
                let template_infos = response.template_infos.unwrap();
                assert_eq!(template_infos.len(), 1);
                assert_eq!(template_infos[0].template_id, template_id);
            }
            _ => panic!("Invalid response type"),
        };
    }
}
