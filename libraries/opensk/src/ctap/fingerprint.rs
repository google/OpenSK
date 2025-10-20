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
use crate::api::rng::Rng;
use crate::ctap::cbor_write;
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

/// Captures all generated template IDs in the enrollment process.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EnrollmentStatus {
    temporary_id: Option<Vec<u8>>,
    hardware_id: Option<Vec<u8>>,
}

impl EnrollmentStatus {
    /// Resets the enrollment status.
    pub fn clear(&mut self) {
        self.temporary_id = None;
        self.hardware_id = None;
    }

    /// Returns the fingerprint sensor's template ID choice.
    pub fn internal_id(&self) -> Option<Vec<u8>> {
        self.hardware_id.clone()
    }

    /// Checks whether the incoming template ID form CTAP is plausible.
    pub fn check_template_id(&self, template_id: &[u8]) -> bool {
        if let Some(existing_id) = &self.temporary_id {
            existing_id == template_id
        } else if let Some(existing_id) = &self.hardware_id {
            existing_id == template_id
        } else {
            false
        }
    }

    /// Sets a temporary ID if none exist yet, or returns an error.
    pub fn insert_temporary_id(&mut self, template_id: &[u8]) -> CtapResult<()> {
        if self.temporary_id.is_some() || self.hardware_id.is_some() {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        self.temporary_id = Some(template_id.to_vec());
        Ok(())
    }

    /// Sets a hardware ID, if consistent with the status so far.
    pub fn insert_hardware_id(&mut self, template_id: &[u8]) -> CtapResult<()> {
        if let Some(existing_id) = &self.hardware_id {
            if existing_id != template_id {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
            }
        } else {
            self.hardware_id = Some(template_id.to_vec());
        }
        Ok(())
    }
}

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
        return Err(Ctap2StatusCode::CTAP2_ERR_UV_BLOCKED);
    }
    env.fingerprint().check_fingerprint_init()?;
    let result = check_fingerprint_loop(env, channel, internal_retry);
    env.fingerprint().check_fingerprint_complete()?;
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
                            return Err(Ctap2StatusCode::CTAP2_ERR_UV_BLOCKED);
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

/// Helper function to move the template ID into persistent storage.
fn finish_enrollment<E: Env>(
    env: &mut E,
    enrollment_status: &mut EnrollmentStatus,
) -> CtapResult<()> {
    if let Some(template_id) = enrollment_status.internal_id() {
        env.persist().store_template_id(template_id)?;
    } else {
        return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
    }
    enrollment_status.clear();
    Ok(())
}

/// Logic for the enrollBegin subcommand.
fn enroll_begin<E: Env>(
    env: &mut E,
    sub_command_params: Option<BioEnrollmentSubCommandParams>,
    enrollment_status: &mut EnrollmentStatus,
) -> CtapResult<ResponseData> {
    enrollment_status.clear();
    env.fingerprint().prepare_enrollment()?;
    let timeout_ms = sub_command_params.and_then(|p| p.timeout_milliseconds);
    let (sample_status, remaining_samples, hardware_id) =
        env.fingerprint().capture_sample(timeout_ms)?;
    // We need to remember if this is a fake ID or hardware ID to overwrite it later.
    let template_id = if let Some(template_id) = hardware_id {
        enrollment_status.insert_hardware_id(&template_id)?;
        template_id
    } else {
        let random_id = env.rng().gen_uniform_u8x32().to_vec();
        enrollment_status.insert_temporary_id(&random_id)?;
        random_id
    };
    if remaining_samples == 0 {
        finish_enrollment(env, enrollment_status)?;
    }
    let response = AuthenticatorBioEnrollmentResponse {
        template_id: Some(template_id),
        last_enroll_sample_status: Some(sample_status),
        remaining_samples: Some(remaining_samples as u64),
        ..Default::default()
    };
    Ok(ResponseData::AuthenticatorBioEnrollment(Some(response)))
}

/// Logic for the enrollCaptureNextSample subcommand.
fn enroll_capture_next_sample<E: Env>(
    env: &mut E,
    sub_command_params: BioEnrollmentSubCommandParams,
    enrollment_status: &mut EnrollmentStatus,
) -> CtapResult<ResponseData> {
    let external_id = ok_or_missing(sub_command_params.template_id)?;
    if !enrollment_status.check_template_id(&external_id) {
        // CTAP does not specify what to do in this case.
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    let timeout_ms = sub_command_params.timeout_milliseconds;
    let (sample_status, remaining_samples, hardware_id) =
        env.fingerprint().capture_sample(timeout_ms)?;
    if let Some(template_id) = hardware_id {
        enrollment_status.insert_hardware_id(&template_id)?;
    }
    if remaining_samples == 0 {
        finish_enrollment(env, enrollment_status)?;
    }
    let response = AuthenticatorBioEnrollmentResponse {
        last_enroll_sample_status: Some(sample_status),
        remaining_samples: Some(remaining_samples as u64),
        ..Default::default()
    };
    Ok(ResponseData::AuthenticatorBioEnrollment(Some(response)))
}

/// Logic for the cancelCurrentEnrollment subcommand.
fn cancel_current_enrollment<E: Env>(
    env: &mut E,
    enrollment_status: &mut EnrollmentStatus,
) -> CtapResult<ResponseData> {
    enrollment_status.clear();
    env.fingerprint().cancel_enrollment()?;
    Ok(ResponseData::AuthenticatorBioEnrollment(None))
}

/// Logic for the enumerateEnrollments subcommand.
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

/// Logic for the setFriendlyName subcommand.
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

/// Logic for the removeEnrollment subcommand.
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

/// Logic for the getFingerprintSensorInfo subcommand.
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

/// Handles the authenticatorBioEnrollment command.
pub fn process_bio_enrollment<E: Env>(
    env: &mut E,
    client_pin: &mut ClientPin<E>,
    params: AuthenticatorBioEnrollmentParameters,
    enrollment_status: &mut EnrollmentStatus,
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
            return cancel_current_enrollment(env, enrollment_status);
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
        cbor_write(sub_command_params.into(), &mut command_data)?;
    }
    client_pin.verify_pin_uv_auth_token(&command_data, &pin_uv_auth_param, pin_uv_auth_protocol)?;
    client_pin.has_permission(PinPermission::BioEnrollment)?;
    // Now we process all other subcommands that need PIN UV authentication.
    match sub_command {
        // Since the subcommand parameter map can be empty, the whole map might be missing.
        // In CTAP, the parameter is not marked as optional, but Chrome omits it when empty.
        BioEnrollmentSubCommand::EnrollBegin => {
            enroll_begin(env, params.sub_command_params, enrollment_status)
        }
        BioEnrollmentSubCommand::EnrollCaptureNextSample => enroll_capture_next_sample(
            env,
            ok_or_missing(params.sub_command_params)?,
            enrollment_status,
        ),
        BioEnrollmentSubCommand::EnumerateEnrollments => enumerate_enrollments(env),
        BioEnrollmentSubCommand::SetFriendlyName => {
            set_friendly_name(env, ok_or_missing(params.sub_command_params)?)
        }
        BioEnrollmentSubCommand::RemoveEnrollment => {
            remove_enrollment(env, ok_or_missing(params.sub_command_params)?)
        }
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

    #[test]
    fn test_perform_built_in_uv() {
        let mut env = TestEnv::default();
        assert!(env.create_fingerprint().is_ok());
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
                Err(Ctap2StatusCode::CTAP2_ERR_UV_BLOCKED)
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
    fn test_modality() {
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

        let params = AuthenticatorBioEnrollmentParameters {
            modality: None,
            sub_command: None,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
            get_modality: Some(true),
        };
        let response = process_bio_enrollment(
            &mut env,
            &mut client_pin,
            params,
            &mut EnrollmentStatus::default(),
        );
        match response.unwrap() {
            ResponseData::AuthenticatorBioEnrollment(Some(response)) => {
                let expected = AuthenticatorBioEnrollmentResponse {
                    modality: Some(MODALITY),
                    ..Default::default()
                };
                assert_eq!(response, expected);
            }
            _ => panic!("Invalid response type"),
        };
    }

    fn call_subcommand_with_status(
        env: &mut TestEnv,
        sub_command: BioEnrollmentSubCommand,
        sub_command_params: Option<BioEnrollmentSubCommandParams>,
        use_pin_uv: bool,
        enrollment_status: &mut EnrollmentStatus,
    ) -> CtapResult<ResponseData> {
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let pin_uv_auth_protocol = PinUvAuthProtocol::V2;
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            env,
            key_agreement_key,
            pin_uv_auth_token,
            pin_uv_auth_protocol,
        );
        let pin_uv_auth_param = if use_pin_uv {
            env.persist().set_pin(&[0x88; 16], 4).unwrap();
            let mut command_data = vec![MODALITY as u8, sub_command as u8];
            if let Some(sub_command_params) = sub_command_params.clone() {
                cbor_write(sub_command_params.into(), &mut command_data)?;
            }
            Some(authenticate_pin_uv_auth_token(
                &pin_uv_auth_token,
                &command_data,
                pin_uv_auth_protocol,
            ))
        } else {
            None
        };

        let params = AuthenticatorBioEnrollmentParameters {
            modality: Some(MODALITY),
            sub_command: Some(sub_command),
            sub_command_params,
            pin_uv_auth_protocol: Some(pin_uv_auth_protocol),
            pin_uv_auth_param,
            get_modality: None,
        };
        process_bio_enrollment(env, &mut client_pin, params, enrollment_status)
    }

    fn call_subcommand(
        env: &mut TestEnv,
        sub_command: BioEnrollmentSubCommand,
        sub_command_params: Option<BioEnrollmentSubCommandParams>,
        use_pin_uv: bool,
    ) -> CtapResult<ResponseData> {
        call_subcommand_with_status(
            env,
            sub_command,
            sub_command_params,
            use_pin_uv,
            &mut EnrollmentStatus::default(),
        )
    }

    #[test]
    fn test_enrollment_cycle() {
        let mut env = TestEnv::default();
        let sub_command_params = BioEnrollmentSubCommandParams {
            template_id: None,
            template_friendly_name: None,
            timeout_milliseconds: Some(10_000),
        };
        let mut enrollment_status = EnrollmentStatus::default();
        let response = call_subcommand_with_status(
            &mut env,
            BioEnrollmentSubCommand::EnrollBegin,
            Some(sub_command_params),
            true,
            &mut enrollment_status,
        );
        let (template_id, mut remaining_samples) = match response.unwrap() {
            ResponseData::AuthenticatorBioEnrollment(Some(response)) => (
                response.template_id.unwrap(),
                response.remaining_samples.unwrap(),
            ),
            _ => panic!("Invalid response type"),
        };

        while remaining_samples > 0 {
            let sub_command_params = BioEnrollmentSubCommandParams {
                template_id: Some(template_id.clone()),
                template_friendly_name: None,
                timeout_milliseconds: Some(10_000),
            };
            let response = call_subcommand_with_status(
                &mut env,
                BioEnrollmentSubCommand::EnrollCaptureNextSample,
                Some(sub_command_params),
                true,
                &mut enrollment_status,
            );
            match response.unwrap() {
                ResponseData::AuthenticatorBioEnrollment(Some(response)) => {
                    remaining_samples = response.remaining_samples.unwrap()
                }
                _ => panic!("Invalid response type"),
            };
        }
        assert_eq!(enrollment_status, EnrollmentStatus::default());

        let response = call_subcommand(
            &mut env,
            BioEnrollmentSubCommand::EnumerateEnrollments,
            None,
            true,
        );
        // This is the actual hardware template ID that we stored.
        let template_id = match response.unwrap() {
            ResponseData::AuthenticatorBioEnrollment(Some(response)) => {
                response.template_infos.unwrap().pop().unwrap().template_id
            }
            _ => panic!("Invalid response type"),
        };

        let sub_command_params = BioEnrollmentSubCommandParams {
            template_id: Some(template_id.clone()),
            template_friendly_name: Some(String::from("Name")),
            timeout_milliseconds: None,
        };
        let response = call_subcommand(
            &mut env,
            BioEnrollmentSubCommand::SetFriendlyName,
            Some(sub_command_params),
            true,
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorBioEnrollment(None)));

        let response = call_subcommand(
            &mut env,
            BioEnrollmentSubCommand::EnumerateEnrollments,
            None,
            true,
        );
        match response.unwrap() {
            ResponseData::AuthenticatorBioEnrollment(Some(response)) => {
                let expected = AuthenticatorBioEnrollmentResponse {
                    template_infos: Some(vec![TemplateInfo {
                        template_id: template_id.clone(),
                        template_friendly_name: Some(String::from("Name")),
                    }]),
                    ..Default::default()
                };
                assert_eq!(response, expected);
            }
            _ => panic!("Invalid response type"),
        };

        let sub_command_params = BioEnrollmentSubCommandParams {
            template_id: Some(template_id),
            template_friendly_name: None,
            timeout_milliseconds: None,
        };
        let response = call_subcommand(
            &mut env,
            BioEnrollmentSubCommand::RemoveEnrollment,
            Some(sub_command_params),
            true,
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorBioEnrollment(None)));

        let response = call_subcommand(
            &mut env,
            BioEnrollmentSubCommand::EnumerateEnrollments,
            None,
            true,
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION));
    }

    #[test]
    fn test_cancel_enrollment() {
        let mut env = TestEnv::default();
        let mut enrollment_status = EnrollmentStatus::default();
        let sub_command_params = BioEnrollmentSubCommandParams {
            template_id: None,
            template_friendly_name: None,
            timeout_milliseconds: Some(10_000),
        };
        let response = call_subcommand_with_status(
            &mut env,
            BioEnrollmentSubCommand::EnrollBegin,
            Some(sub_command_params),
            true,
            &mut enrollment_status,
        );
        assert!(response.is_ok());

        // Cancel is a no-op if the call before succeeds immediately.
        let response = call_subcommand_with_status(
            &mut env,
            BioEnrollmentSubCommand::CancelCurrentEnrollment,
            None,
            false,
            &mut enrollment_status,
        );
        assert!(response.is_ok());
        assert_eq!(enrollment_status, EnrollmentStatus::default());
    }

    #[test]
    fn test_enumerate_enrollments_no_fingerprint() {
        let mut env = TestEnv::default();
        let response = call_subcommand(
            &mut env,
            BioEnrollmentSubCommand::EnumerateEnrollments,
            None,
            true,
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION));
    }

    #[test]
    fn test_enumerate_enrollments_no_pin() {
        let mut env = TestEnv::default();
        env.create_fingerprint().unwrap();
        let response = call_subcommand(
            &mut env,
            BioEnrollmentSubCommand::EnumerateEnrollments,
            None,
            false,
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED));
    }

    #[test]
    fn test_enumerate_enrollments() {
        let mut env = TestEnv::default();
        let template_id = env.create_fingerprint().unwrap();
        let response = call_subcommand(
            &mut env,
            BioEnrollmentSubCommand::EnumerateEnrollments,
            None,
            true,
        );
        match response.unwrap() {
            ResponseData::AuthenticatorBioEnrollment(Some(response)) => {
                let expected = AuthenticatorBioEnrollmentResponse {
                    template_infos: Some(vec![TemplateInfo {
                        template_id,
                        template_friendly_name: None,
                    }]),
                    ..Default::default()
                };
                assert_eq!(response, expected);
            }
            _ => panic!("Invalid response type"),
        };
    }

    #[test]
    fn test_sensor_info() {
        let mut env = TestEnv::default();
        let response = call_subcommand(
            &mut env,
            BioEnrollmentSubCommand::GetFingerprintSensorInfo,
            None,
            false,
        );
        match response.unwrap() {
            ResponseData::AuthenticatorBioEnrollment(Some(response)) => {
                assert_eq!(response.modality, Some(MODALITY));
                assert_eq!(
                    response.fingerprint_kind,
                    Some(env.fingerprint().fingerprint_kind() as u64)
                );
                assert_eq!(
                    response.max_capture_samples_required_for_enroll,
                    Some(env.fingerprint().max_capture_samples_required_for_enroll() as u64)
                );
                assert!(response.template_id.is_none());
                assert!(response.last_enroll_sample_status.is_none());
                assert!(response.remaining_samples.is_none());
                assert_eq!(
                    response.max_template_friendly_name,
                    Some(env.customization().max_template_friendly_name() as u64)
                );
                assert!(response.template_infos.is_none());
            }
            _ => panic!("Invalid response type"),
        };
    }

    #[test]
    fn test_enrollments_status_clear() {
        let mut status = EnrollmentStatus::default();
        status.insert_hardware_id(&[0x00]).unwrap();
        status.clear();
        assert_eq!(status, EnrollmentStatus::default());
    }

    #[test]
    fn test_enrollments_status_no_temporary() {
        let mut status = EnrollmentStatus::default();
        status.insert_hardware_id(&[0x01]).unwrap();
        assert_eq!(status.internal_id(), Some(vec![0x01]));
        assert!(status.check_template_id(&[0x01]));
        assert!(!status.check_template_id(&[0x02]));
    }

    #[test]
    fn test_enrollments_status_temporary_first() {
        let mut status = EnrollmentStatus::default();
        status.insert_temporary_id(&[0x02]).unwrap();
        status.insert_hardware_id(&[0x01]).unwrap();
        assert_eq!(status.internal_id(), Some(vec![0x01]));
        assert!(!status.check_template_id(&[0x01]));
        assert!(status.check_template_id(&[0x02]));
    }

    #[test]
    fn test_enrollments_status_temporary_last() {
        let mut status = EnrollmentStatus::default();
        status.insert_hardware_id(&[0x02]).unwrap();
        assert_eq!(
            status.insert_temporary_id(&[0x01]),
            Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
        );
    }

    #[test]
    fn test_enrollments_status_multiple_hardware() {
        let mut status = EnrollmentStatus::default();
        status.insert_hardware_id(&[0x01]).unwrap();
        assert_eq!(status.insert_hardware_id(&[0x01]), Ok(()));
        assert_eq!(
            status.insert_hardware_id(&[0x02]),
            Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
        );
        assert_eq!(status.internal_id(), Some(vec![0x01]));
        assert!(status.check_template_id(&[0x01]));
        assert!(!status.check_template_id(&[0x02]));
    }
}
