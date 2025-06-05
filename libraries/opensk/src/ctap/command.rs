// Copyright 2019-2023 Google LLC
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

use super::cbor_read;
#[cfg(feature = "fingerprint")]
use super::data_formats::extract_bool;
use super::data_formats::{
    extract_array, extract_byte_string, extract_map, extract_text_string, extract_unsigned,
    ok_or_missing, ClientPinSubCommand, CoseKey, CredentialManagementSubCommand,
    CredentialManagementSubCommandParameters, GetAssertionExtensions, GetAssertionOptions,
    MakeCredentialExtensions, MakeCredentialOptions, PinUvAuthProtocol,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameter, PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
};
#[cfg(feature = "config_command")]
use super::data_formats::{ConfigSubCommand, ConfigSubCommandParams, SetMinPinLengthParams};
use super::status_code::Ctap2StatusCode;
use crate::ctap::status_code::CtapResult;
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use core::convert::TryFrom;
#[cfg(all(test, feature = "fingerprint"))]
use enum_iterator::IntoEnumIterator;
use sk_cbor as cbor;
#[cfg(feature = "fingerprint")]
use sk_cbor::cbor_map_options;
use sk_cbor::destructure_cbor_map;

// CTAP specification (version 20190130) section 6.1
#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Command {
    AuthenticatorMakeCredential(AuthenticatorMakeCredentialParameters),
    AuthenticatorGetAssertion(AuthenticatorGetAssertionParameters),
    AuthenticatorGetInfo,
    AuthenticatorClientPin(AuthenticatorClientPinParameters),
    AuthenticatorReset,
    AuthenticatorGetNextAssertion,
    #[cfg(feature = "fingerprint")]
    AuthenticatorBioEnrollment(AuthenticatorBioEnrollmentParameters),
    AuthenticatorCredentialManagement(AuthenticatorCredentialManagementParameters),
    AuthenticatorSelection,
    AuthenticatorLargeBlobs(AuthenticatorLargeBlobsParameters),
    #[cfg(feature = "config_command")]
    AuthenticatorConfig(AuthenticatorConfigParameters),
}

impl Command {
    const AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;
    const AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;
    const AUTHENTICATOR_GET_INFO: u8 = 0x04;
    const AUTHENTICATOR_CLIENT_PIN: u8 = 0x06;
    const AUTHENTICATOR_RESET: u8 = 0x07;
    const AUTHENTICATOR_GET_NEXT_ASSERTION: u8 = 0x08;
    #[cfg(feature = "fingerprint")]
    const AUTHENTICATOR_BIO_ENROLLMENT: u8 = 0x09;
    const AUTHENTICATOR_CREDENTIAL_MANAGEMENT: u8 = 0x0A;
    const AUTHENTICATOR_SELECTION: u8 = 0x0B;
    const AUTHENTICATOR_LARGE_BLOBS: u8 = 0x0C;
    #[cfg(feature = "config_command")]
    const AUTHENTICATOR_CONFIG: u8 = 0x0D;
    const _AUTHENTICATOR_VENDOR_FIRST: u8 = 0x40;
    // This commands is the same as AUTHENTICATOR_CREDENTIAL_MANAGEMENT but is duplicated as a
    // vendor command for legacy and compatibility reasons. See
    // https://github.com/Yubico/libfido2/issues/628 for more information.
    const AUTHENTICATOR_VENDOR_CREDENTIAL_MANAGEMENT: u8 = 0x41;
    const _AUTHENTICATOR_VENDOR_LAST: u8 = 0xBF;

    pub fn deserialize(bytes: &[u8]) -> CtapResult<Command> {
        if bytes.is_empty() {
            // The error to return is not specified, missing parameter seems to fit best.
            return Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER);
        }

        let command_value = bytes[0];
        match command_value {
            Command::AUTHENTICATOR_MAKE_CREDENTIAL => {
                let decoded_cbor = cbor_read(&bytes[1..])?;
                Ok(Command::AuthenticatorMakeCredential(
                    AuthenticatorMakeCredentialParameters::try_from(decoded_cbor)?,
                ))
            }
            Command::AUTHENTICATOR_GET_ASSERTION => {
                let decoded_cbor = cbor_read(&bytes[1..])?;
                Ok(Command::AuthenticatorGetAssertion(
                    AuthenticatorGetAssertionParameters::try_from(decoded_cbor)?,
                ))
            }
            Command::AUTHENTICATOR_GET_INFO => {
                // Parameters are ignored.
                Ok(Command::AuthenticatorGetInfo)
            }
            Command::AUTHENTICATOR_CLIENT_PIN => {
                let decoded_cbor = cbor_read(&bytes[1..])?;
                Ok(Command::AuthenticatorClientPin(
                    AuthenticatorClientPinParameters::try_from(decoded_cbor)?,
                ))
            }
            Command::AUTHENTICATOR_RESET => {
                // Parameters are ignored.
                Ok(Command::AuthenticatorReset)
            }
            Command::AUTHENTICATOR_GET_NEXT_ASSERTION => {
                // Parameters are ignored.
                Ok(Command::AuthenticatorGetNextAssertion)
            }
            #[cfg(feature = "fingerprint")]
            Command::AUTHENTICATOR_BIO_ENROLLMENT => {
                let decoded_cbor = cbor_read(&bytes[1..])?;
                Ok(Command::AuthenticatorBioEnrollment(
                    AuthenticatorBioEnrollmentParameters::try_from(decoded_cbor)?,
                ))
            }
            Command::AUTHENTICATOR_CREDENTIAL_MANAGEMENT
            | Command::AUTHENTICATOR_VENDOR_CREDENTIAL_MANAGEMENT => {
                let decoded_cbor = cbor_read(&bytes[1..])?;
                Ok(Command::AuthenticatorCredentialManagement(
                    AuthenticatorCredentialManagementParameters::try_from(decoded_cbor)?,
                ))
            }
            Command::AUTHENTICATOR_SELECTION => {
                // Parameters are ignored.
                Ok(Command::AuthenticatorSelection)
            }
            Command::AUTHENTICATOR_LARGE_BLOBS => {
                let decoded_cbor = cbor_read(&bytes[1..])?;
                Ok(Command::AuthenticatorLargeBlobs(
                    AuthenticatorLargeBlobsParameters::try_from(decoded_cbor)?,
                ))
            }
            #[cfg(feature = "config_command")]
            Command::AUTHENTICATOR_CONFIG => {
                let decoded_cbor = cbor_read(&bytes[1..])?;
                Ok(Command::AuthenticatorConfig(
                    AuthenticatorConfigParameters::try_from(decoded_cbor)?,
                ))
            }
            _ => Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct AuthenticatorMakeCredentialParameters {
    pub client_data_hash: Vec<u8>,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameter>,
    pub exclude_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    // Extensions are optional, but we can use defaults for all missing fields.
    pub extensions: MakeCredentialExtensions,
    // Same for options, use defaults when not present.
    pub options: MakeCredentialOptions,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
    pub enterprise_attestation: Option<u64>,
}

impl TryFrom<cbor::Value> for AuthenticatorMakeCredentialParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> CtapResult<Self> {
        destructure_cbor_map! {
            let {
                0x01 => client_data_hash,
                0x02 => rp,
                0x03 => user,
                0x04 => cred_param_vec,
                0x05 => exclude_list,
                0x06 => extensions,
                0x07 => options,
                0x08 => pin_uv_auth_param,
                0x09 => pin_uv_auth_protocol,
                0x0A => enterprise_attestation,
            } = extract_map(cbor_value)?;
        }

        let client_data_hash = extract_byte_string(ok_or_missing(client_data_hash)?)?;
        let rp = PublicKeyCredentialRpEntity::try_from(ok_or_missing(rp)?)?;
        let user = PublicKeyCredentialUserEntity::try_from(ok_or_missing(user)?)?;

        let cred_param_vec = extract_array(ok_or_missing(cred_param_vec)?)?;
        let pub_key_cred_params = cred_param_vec
            .into_iter()
            .map(PublicKeyCredentialParameter::try_from)
            .collect::<CtapResult<Vec<PublicKeyCredentialParameter>>>()?;

        let exclude_list = match exclude_list {
            Some(entry) => {
                let exclude_list_vec = extract_array(entry)?;
                let exclude_list = exclude_list_vec
                    .into_iter()
                    .map(PublicKeyCredentialDescriptor::try_from)
                    .collect::<CtapResult<Vec<PublicKeyCredentialDescriptor>>>()?;
                Some(exclude_list)
            }
            None => None,
        };

        let extensions = extensions
            .map(MakeCredentialExtensions::try_from)
            .transpose()?
            .unwrap_or_default();

        let options = options
            .map(MakeCredentialOptions::try_from)
            .transpose()?
            .unwrap_or_default();

        let pin_uv_auth_param = pin_uv_auth_param.map(extract_byte_string).transpose()?;
        let pin_uv_auth_protocol = pin_uv_auth_protocol
            .map(PinUvAuthProtocol::try_from)
            .transpose()?;
        // We don't convert into EnterpriseAttestationMode to maintain the correct order of errors.
        let enterprise_attestation = enterprise_attestation.map(extract_unsigned).transpose()?;

        Ok(AuthenticatorMakeCredentialParameters {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list,
            extensions,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
            enterprise_attestation,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct AuthenticatorGetAssertionParameters {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allow_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    // Extensions are optional, but we can use defaults for all missing fields.
    pub extensions: GetAssertionExtensions,
    // Same for options, use defaults when not present.
    pub options: GetAssertionOptions,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
}

impl TryFrom<cbor::Value> for AuthenticatorGetAssertionParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> CtapResult<Self> {
        destructure_cbor_map! {
            let {
                0x01 => rp_id,
                0x02 => client_data_hash,
                0x03 => allow_list,
                0x04 => extensions,
                0x05 => options,
                0x06 => pin_uv_auth_param,
                0x07 => pin_uv_auth_protocol,
            } = extract_map(cbor_value)?;
        }

        let rp_id = extract_text_string(ok_or_missing(rp_id)?)?;
        let client_data_hash = extract_byte_string(ok_or_missing(client_data_hash)?)?;

        let allow_list = match allow_list {
            Some(entry) => {
                let allow_list_vec = extract_array(entry)?;
                let allow_list = allow_list_vec
                    .into_iter()
                    .map(PublicKeyCredentialDescriptor::try_from)
                    .collect::<CtapResult<Vec<PublicKeyCredentialDescriptor>>>()?;
                Some(allow_list)
            }
            None => None,
        };

        let extensions = extensions
            .map(GetAssertionExtensions::try_from)
            .transpose()?
            .unwrap_or_default();

        let options = options
            .map(GetAssertionOptions::try_from)
            .transpose()?
            .unwrap_or_default();

        let pin_uv_auth_param = pin_uv_auth_param.map(extract_byte_string).transpose()?;
        let pin_uv_auth_protocol = pin_uv_auth_protocol
            .map(PinUvAuthProtocol::try_from)
            .transpose()?;

        Ok(AuthenticatorGetAssertionParameters {
            rp_id,
            client_data_hash,
            allow_list,
            extensions,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct AuthenticatorClientPinParameters {
    pub pin_uv_auth_protocol: PinUvAuthProtocol,
    pub sub_command: ClientPinSubCommand,
    pub key_agreement: Option<CoseKey>,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub new_pin_enc: Option<Vec<u8>>,
    pub pin_hash_enc: Option<Vec<u8>>,
    pub permissions: Option<u8>,
    pub permissions_rp_id: Option<String>,
}

impl TryFrom<cbor::Value> for AuthenticatorClientPinParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> CtapResult<Self> {
        destructure_cbor_map! {
            let {
                0x01 => pin_uv_auth_protocol,
                0x02 => sub_command,
                0x03 => key_agreement,
                0x04 => pin_uv_auth_param,
                0x05 => new_pin_enc,
                0x06 => pin_hash_enc,
                0x09 => permissions,
                0x0A => permissions_rp_id,
            } = extract_map(cbor_value)?;
        }

        let pin_uv_auth_protocol =
            PinUvAuthProtocol::try_from(ok_or_missing(pin_uv_auth_protocol)?)?;
        let sub_command = ClientPinSubCommand::try_from(ok_or_missing(sub_command)?)?;
        let key_agreement = key_agreement.map(CoseKey::try_from).transpose()?;
        let pin_uv_auth_param = pin_uv_auth_param.map(extract_byte_string).transpose()?;
        let new_pin_enc = new_pin_enc.map(extract_byte_string).transpose()?;
        let pin_hash_enc = pin_hash_enc.map(extract_byte_string).transpose()?;
        // We expect a bit field of 8 bits, and drop everything else.
        // This means we ignore extensions in future versions.
        let permissions = permissions
            .map(extract_unsigned)
            .transpose()?
            .map(|p| p as u8);
        let permissions_rp_id = permissions_rp_id.map(extract_text_string).transpose()?;

        Ok(AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            sub_command,
            key_agreement,
            pin_uv_auth_param,
            new_pin_enc,
            pin_hash_enc,
            permissions,
            permissions_rp_id,
        })
    }
}

#[cfg(feature = "fingerprint")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatorBioEnrollmentParameters {
    pub modality: Option<u64>,
    pub sub_command: Option<BioEnrollmentSubCommand>,
    pub sub_command_params: Option<BioEnrollmentSubCommandParams>,
    pub pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub get_modality: Option<bool>,
}

#[cfg(feature = "fingerprint")]
impl TryFrom<cbor::Value> for AuthenticatorBioEnrollmentParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Self::Error> {
        destructure_cbor_map! {
            let {
                0x01 => modality,
                0x02 => sub_command,
                0x03 => sub_command_params,
                0x04 => pin_uv_auth_protocol,
                0x05 => pin_uv_auth_param,
                0x06 => get_modality,
            } = extract_map(cbor_value)?;
        }

        let modality = modality.map(extract_unsigned).transpose()?;
        let sub_command = sub_command
            .map(BioEnrollmentSubCommand::try_from)
            .transpose()?;
        let sub_command_params = sub_command_params
            .map(BioEnrollmentSubCommandParams::try_from)
            .transpose()?;
        let pin_uv_auth_protocol = pin_uv_auth_protocol
            .map(PinUvAuthProtocol::try_from)
            .transpose()?;
        let pin_uv_auth_param = pin_uv_auth_param.map(extract_byte_string).transpose()?;
        let get_modality = get_modality.map(extract_bool).transpose()?;

        Ok(AuthenticatorBioEnrollmentParameters {
            modality,
            sub_command,
            sub_command_params,
            pin_uv_auth_protocol,
            pin_uv_auth_param,
            get_modality,
        })
    }
}

#[cfg(feature = "fingerprint")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(IntoEnumIterator))]
pub enum BioEnrollmentSubCommand {
    EnrollBegin = 0x01,
    EnrollCaptureNextSample = 0x02,
    CancelCurrentEnrollment = 0x03,
    EnumerateEnrollments = 0x04,
    SetFriendlyName = 0x05,
    RemoveEnrollment = 0x06,
    GetFingerprintSensorInfo = 0x07,
}

#[cfg(feature = "fingerprint")]
impl From<BioEnrollmentSubCommand> for cbor::Value {
    fn from(subcommand: BioEnrollmentSubCommand) -> Self {
        (subcommand as u64).into()
    }
}

#[cfg(feature = "fingerprint")]
impl TryFrom<cbor::Value> for BioEnrollmentSubCommand {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> CtapResult<Self> {
        let subcommand_int = extract_unsigned(cbor_value)?;
        match subcommand_int {
            0x01 => Ok(BioEnrollmentSubCommand::EnrollBegin),
            0x02 => Ok(BioEnrollmentSubCommand::EnrollCaptureNextSample),
            0x03 => Ok(BioEnrollmentSubCommand::CancelCurrentEnrollment),
            0x04 => Ok(BioEnrollmentSubCommand::EnumerateEnrollments),
            0x05 => Ok(BioEnrollmentSubCommand::SetFriendlyName),
            0x06 => Ok(BioEnrollmentSubCommand::RemoveEnrollment),
            0x07 => Ok(BioEnrollmentSubCommand::GetFingerprintSensorInfo),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND),
        }
    }
}

#[cfg(feature = "fingerprint")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BioEnrollmentSubCommandParams {
    pub template_id: Option<Vec<u8>>,
    pub template_friendly_name: Option<String>,
    pub timeout_milliseconds: Option<usize>,
}

#[cfg(feature = "fingerprint")]
impl TryFrom<cbor::Value> for BioEnrollmentSubCommandParams {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Self::Error> {
        destructure_cbor_map! {
            let {
                0x01 => template_id,
                0x02 => template_friendly_name,
                0x03 => timeout_milliseconds,
            } = extract_map(cbor_value)?;
        }

        let template_id = template_id.map(extract_byte_string).transpose()?;
        let template_friendly_name = template_friendly_name
            .map(extract_text_string)
            .transpose()?;
        let timeout_milliseconds = timeout_milliseconds
            .map(extract_unsigned)
            .transpose()?
            .map(usize::try_from)
            .transpose()
            .map_err(|_| Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;

        Ok(BioEnrollmentSubCommandParams {
            template_id,
            template_friendly_name,
            timeout_milliseconds,
        })
    }
}

#[cfg(feature = "fingerprint")]
impl From<BioEnrollmentSubCommandParams> for cbor::Value {
    fn from(sub_command_params: BioEnrollmentSubCommandParams) -> Self {
        cbor_map_options! {
            0x01 => sub_command_params.template_id,
            0x02 => sub_command_params.template_friendly_name,
            0x03 => sub_command_params.timeout_milliseconds.map(|u| u as u64),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatorLargeBlobsParameters {
    pub get: Option<usize>,
    pub set: Option<Vec<u8>>,
    pub offset: usize,
    pub length: Option<usize>,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
}

impl TryFrom<cbor::Value> for AuthenticatorLargeBlobsParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> CtapResult<Self> {
        destructure_cbor_map! {
            let {
                0x01 => get,
                0x02 => set,
                0x03 => offset,
                0x04 => length,
                0x05 => pin_uv_auth_param,
                0x06 => pin_uv_auth_protocol,
            } = extract_map(cbor_value)?;
        }

        // careful: some missing parameters here are CTAP1_ERR_INVALID_PARAMETER
        let get = get.map(extract_unsigned).transpose()?.map(|u| u as usize);
        let set = set.map(extract_byte_string).transpose()?;
        let offset =
            extract_unsigned(offset.ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?)? as usize;
        let length = length
            .map(extract_unsigned)
            .transpose()?
            .map(|u| u as usize);
        let pin_uv_auth_param = pin_uv_auth_param.map(extract_byte_string).transpose()?;
        let pin_uv_auth_protocol = pin_uv_auth_protocol
            .map(PinUvAuthProtocol::try_from)
            .transpose()?;

        if get.is_some() == set.is_some() {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        if get.is_some()
            && (length.is_some() || pin_uv_auth_param.is_some() || pin_uv_auth_protocol.is_some())
        {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        if set.is_some() && ((offset == 0) != length.is_some()) {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }

        Ok(AuthenticatorLargeBlobsParameters {
            get,
            set,
            offset,
            length,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        })
    }
}

#[cfg(feature = "config_command")]
#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatorConfigParameters {
    pub sub_command: ConfigSubCommand,
    pub sub_command_params: Option<ConfigSubCommandParams>,
    pub pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
    pub pin_uv_auth_param: Option<Vec<u8>>,
}

#[cfg(feature = "config_command")]
impl TryFrom<cbor::Value> for AuthenticatorConfigParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> CtapResult<Self> {
        destructure_cbor_map! {
            let {
                0x01 => sub_command,
                0x02 => sub_command_params,
                0x03 => pin_uv_auth_protocol,
                0x04 => pin_uv_auth_param,
            } = extract_map(cbor_value)?;
        }

        let sub_command = ConfigSubCommand::try_from(ok_or_missing(sub_command)?)?;
        let sub_command_params = match sub_command {
            ConfigSubCommand::SetMinPinLength => Some(ConfigSubCommandParams::SetMinPinLength(
                SetMinPinLengthParams::try_from(ok_or_missing(sub_command_params)?)?,
            )),
            _ => None,
        };
        let pin_uv_auth_protocol = pin_uv_auth_protocol
            .map(PinUvAuthProtocol::try_from)
            .transpose()?;
        let pin_uv_auth_param = pin_uv_auth_param.map(extract_byte_string).transpose()?;

        Ok(AuthenticatorConfigParameters {
            sub_command,
            sub_command_params,
            pin_uv_auth_protocol,
            pin_uv_auth_param,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatorCredentialManagementParameters {
    pub sub_command: CredentialManagementSubCommand,
    pub sub_command_params: Option<CredentialManagementSubCommandParameters>,
    pub pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
    pub pin_uv_auth_param: Option<Vec<u8>>,
}

impl TryFrom<cbor::Value> for AuthenticatorCredentialManagementParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> CtapResult<Self> {
        destructure_cbor_map! {
            let {
                0x01 => sub_command,
                0x02 => sub_command_params,
                0x03 => pin_uv_auth_protocol,
                0x04 => pin_uv_auth_param,
            } = extract_map(cbor_value)?;
        }

        let sub_command = CredentialManagementSubCommand::try_from(ok_or_missing(sub_command)?)?;
        let sub_command_params = sub_command_params
            .map(CredentialManagementSubCommandParameters::try_from)
            .transpose()?;
        let pin_uv_auth_protocol = pin_uv_auth_protocol
            .map(PinUvAuthProtocol::try_from)
            .transpose()?;
        let pin_uv_auth_param = pin_uv_auth_param.map(extract_byte_string).transpose()?;

        Ok(AuthenticatorCredentialManagementParameters {
            sub_command,
            sub_command_params,
            pin_uv_auth_protocol,
            pin_uv_auth_param,
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::data_formats::{
        AuthenticatorTransport, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
        PublicKeyCredentialUserEntity,
    };
    use super::super::ES256_CRED_PARAM;
    use super::*;
    #[cfg(feature = "fingerprint")]
    use cbor::cbor_int;
    use cbor::{cbor_array, cbor_map};

    #[test]
    fn test_from_cbor_make_credential_parameters() {
        let cbor_value = cbor_map! {
            0x01 => vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
            0x02 => cbor_map! {
                "id" => "example.com",
                "icon" => "example.com/icon.png",
                "name" => "Example",
            },
            0x03 => cbor_map! {
                "id" => vec![0x1D, 0x1D, 0x1D, 0x1D],
                "icon" => "example.com/foo/icon.png",
                "name" => "foo",
                "displayName" => "bar",
            },
            0x04 => cbor_array![ES256_CRED_PARAM],
            0x05 => cbor_array![],
            0x08 => vec![0x12, 0x34],
            0x09 => 1,
            0x0A => 2,
        };
        let returned_make_credential_parameters =
            AuthenticatorMakeCredentialParameters::try_from(cbor_value).unwrap();

        let client_data_hash = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let rp = PublicKeyCredentialRpEntity {
            rp_id: "example.com".to_string(),
            rp_name: Some("Example".to_string()),
            rp_icon: Some("example.com/icon.png".to_string()),
        };
        let user = PublicKeyCredentialUserEntity {
            user_id: vec![0x1D, 0x1D, 0x1D, 0x1D],
            user_name: Some("foo".to_string()),
            user_display_name: Some("bar".to_string()),
            user_icon: Some("example.com/foo/icon.png".to_string()),
        };
        let options = MakeCredentialOptions {
            rk: false,
            uv: false,
        };
        let expected_make_credential_parameters = AuthenticatorMakeCredentialParameters {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params: vec![ES256_CRED_PARAM],
            exclude_list: Some(vec![]),
            extensions: MakeCredentialExtensions::default(),
            options,
            pin_uv_auth_param: Some(vec![0x12, 0x34]),
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            enterprise_attestation: Some(2),
        };

        assert_eq!(
            returned_make_credential_parameters,
            expected_make_credential_parameters
        );
    }

    #[test]
    fn test_from_cbor_get_assertion_parameters() {
        let cbor_value = cbor_map! {
            0x01 => "example.com",
            0x02 => vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
            0x03 => cbor_array![ cbor_map! {
                "id" => vec![0x2D, 0x2D, 0x2D, 0x2D],
                "type" => "public-key",
                "transports" => cbor_array!["usb"],
            } ],
            0x06 => vec![0x12, 0x34],
            0x07 => 1,
        };
        let returned_get_assertion_parameters =
            AuthenticatorGetAssertionParameters::try_from(cbor_value).unwrap();

        let rp_id = "example.com".to_string();
        let client_data_hash = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pub_key_cred_descriptor = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: vec![0x2D, 0x2D, 0x2D, 0x2D],
            transports: Some(vec![AuthenticatorTransport::Usb]),
        };
        let options = GetAssertionOptions {
            up: true,
            uv: false,
        };
        let expected_get_assertion_parameters = AuthenticatorGetAssertionParameters {
            rp_id,
            client_data_hash,
            allow_list: Some(vec![pub_key_cred_descriptor]),
            extensions: GetAssertionExtensions::default(),
            options,
            pin_uv_auth_param: Some(vec![0x12, 0x34]),
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
        };

        assert_eq!(
            returned_get_assertion_parameters,
            expected_get_assertion_parameters
        );
    }

    #[test]
    fn test_from_cbor_client_pin_parameters() {
        let cose_key = CoseKey::example_ecdh_pubkey();
        let cbor_value = cbor_map! {
            0x01 => 1,
            0x02 => ClientPinSubCommand::GetPinRetries,
            0x03 => cbor::Value::from(cose_key.clone()),
            0x04 => vec! [0xBB],
            0x05 => vec! [0xCC],
            0x06 => vec! [0xDD],
            0x09 => 0x03,
            0x0A => "example.com",
        };
        let returned_client_pin_parameters =
            AuthenticatorClientPinParameters::try_from(cbor_value).unwrap();

        let expected_client_pin_parameters = AuthenticatorClientPinParameters {
            pin_uv_auth_protocol: PinUvAuthProtocol::V1,
            sub_command: ClientPinSubCommand::GetPinRetries,
            key_agreement: Some(cose_key),
            pin_uv_auth_param: Some(vec![0xBB]),
            new_pin_enc: Some(vec![0xCC]),
            pin_hash_enc: Some(vec![0xDD]),
            permissions: Some(0x03),
            permissions_rp_id: Some("example.com".to_string()),
        };
        assert_eq!(
            returned_client_pin_parameters,
            expected_client_pin_parameters
        );
    }

    #[test]
    fn test_deserialize_get_info() {
        let cbor_bytes = [Command::AUTHENTICATOR_GET_INFO];
        let command = Command::deserialize(&cbor_bytes);
        assert_eq!(command, Ok(Command::AuthenticatorGetInfo));
    }

    #[test]
    fn test_deserialize_reset() {
        // Adding some random bytes to see if they are ignored.
        let cbor_bytes = [Command::AUTHENTICATOR_RESET, 0xAB, 0xCD, 0xEF];
        let command = Command::deserialize(&cbor_bytes);
        assert_eq!(command, Ok(Command::AuthenticatorReset));
    }

    #[test]
    fn test_deserialize_get_next_assertion() {
        let cbor_bytes = [Command::AUTHENTICATOR_GET_NEXT_ASSERTION];
        let command = Command::deserialize(&cbor_bytes);
        assert_eq!(command, Ok(Command::AuthenticatorGetNextAssertion));
    }

    #[test]
    #[cfg(feature = "fingerprint")]
    fn test_from_cbor_bio_enrollment_parameters() {
        let sub_command_params_cbor_value = cbor_map! {
            0x01 => vec![0x01],
            0x02 => "Name",
            0x03 => 1000,
        };
        let cbor_value = cbor_map! {
            0x01 => 1,
            0x02 => BioEnrollmentSubCommand::EnrollBegin,
            0x03 => sub_command_params_cbor_value,
            0x04 => 1,
            0x05 => vec![0xBB],
            0x06 => true,
        };
        let returned_bio_enrollment_parameters =
            AuthenticatorBioEnrollmentParameters::try_from(cbor_value).unwrap();

        let expected_sub_command_params = BioEnrollmentSubCommandParams {
            template_id: Some(vec![0x01]),
            template_friendly_name: Some(String::from("Name")),
            timeout_milliseconds: Some(1000),
        };
        let expected_bio_enrollment_parameters = AuthenticatorBioEnrollmentParameters {
            modality: Some(1),
            sub_command: Some(BioEnrollmentSubCommand::EnrollBegin),
            sub_command_params: Some(expected_sub_command_params),
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param: Some(vec![0xBB]),
            get_modality: Some(true),
        };
        assert_eq!(
            returned_bio_enrollment_parameters,
            expected_bio_enrollment_parameters
        );
    }

    #[test]
    #[cfg(feature = "fingerprint")]
    fn test_from_into_bio_enrollment_sub_command() {
        let cbor_sub_command: cbor::Value = cbor_int!(0x01);
        let sub_command = BioEnrollmentSubCommand::try_from(cbor_sub_command.clone());
        let expected_sub_command = BioEnrollmentSubCommand::EnrollBegin;
        assert_eq!(sub_command, Ok(expected_sub_command));
        let created_cbor: cbor::Value = sub_command.unwrap().into();
        assert_eq!(created_cbor, cbor_sub_command);

        for command in BioEnrollmentSubCommand::into_enum_iter() {
            let created_cbor: cbor::Value = command.clone().into();
            let reconstructed = BioEnrollmentSubCommand::try_from(created_cbor).unwrap();
            assert_eq!(command, reconstructed);
        }
    }

    #[test]
    #[cfg(feature = "fingerprint")]
    fn test_from_into_bio_enrollment_sub_command_params() {
        let cbor_sub_command_params = cbor_map! {
            0x01 => vec![0x1D; 32],
            0x02 => "Name",
            0x03 => 30_000,
        };
        let sub_command_params =
            BioEnrollmentSubCommandParams::try_from(cbor_sub_command_params.clone());
        let expected_sub_command_params = BioEnrollmentSubCommandParams {
            template_id: Some(vec![0x1D; 32]),
            template_friendly_name: Some(String::from("Name")),
            timeout_milliseconds: Some(30_000),
        };
        assert_eq!(sub_command_params, Ok(expected_sub_command_params));
        let created_cbor: cbor::Value = sub_command_params.unwrap().into();
        assert_eq!(created_cbor, cbor_sub_command_params);
    }

    #[test]
    #[cfg(feature = "config_command")]
    fn test_from_cbor_config_parameters() {
        let cbor_value = cbor_map! {
            0x01 => ConfigSubCommand::SetMinPinLength as u64,
            0x02 => cbor_map!{
                0x01 => 6,
                0x02 => cbor_array![String::from("example.com")],
                0x03 => true,
            },
            0x03 => 1,
            0x04 => vec! [0x9A; 16],
        };
        let returned_config_parameters =
            AuthenticatorConfigParameters::try_from(cbor_value).unwrap();

        let sub_command_params = ConfigSubCommandParams::SetMinPinLength(SetMinPinLengthParams {
            new_min_pin_length: Some(6),
            min_pin_length_rp_ids: Some(vec![String::from("example.com")]),
            force_change_pin: Some(true),
        });
        let expected_config_parameters = AuthenticatorConfigParameters {
            sub_command: ConfigSubCommand::SetMinPinLength,
            sub_command_params: Some(sub_command_params),
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param: Some(vec![0x9A; 16]),
        };

        assert_eq!(returned_config_parameters, expected_config_parameters);
    }

    #[test]
    fn test_from_cbor_cred_management_parameters() {
        let cbor_value = cbor_map! {
            0x01 => CredentialManagementSubCommand::EnumerateCredentialsBegin as u64,
            0x02 => cbor_map!{
                0x01 => vec![0x1D; 32],
            },
            0x03 => 1,
            0x04 => vec! [0x9A; 16],
        };
        let returned_cred_management_parameters =
            AuthenticatorCredentialManagementParameters::try_from(cbor_value).unwrap();

        let params = CredentialManagementSubCommandParameters {
            rp_id_hash: Some(vec![0x1D; 32]),
            credential_id: None,
            user: None,
        };
        let expected_cred_management_parameters = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateCredentialsBegin,
            sub_command_params: Some(params),
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param: Some(vec![0x9A; 16]),
        };

        assert_eq!(
            returned_cred_management_parameters,
            expected_cred_management_parameters
        );
    }

    #[test]
    fn test_deserialize_selection() {
        let cbor_bytes = [Command::AUTHENTICATOR_SELECTION];
        let command = Command::deserialize(&cbor_bytes);
        assert_eq!(command, Ok(Command::AuthenticatorSelection));
    }

    #[test]
    fn test_from_cbor_large_blobs_parameters() {
        const MIN_LARGE_BLOB_LEN: usize = 17;

        // successful get
        let cbor_value = cbor_map! {
            0x01 => 2,
            0x03 => 4,
        };
        let returned_large_blobs_parameters =
            AuthenticatorLargeBlobsParameters::try_from(cbor_value).unwrap();
        let expected_large_blobs_parameters = AuthenticatorLargeBlobsParameters {
            get: Some(2),
            set: None,
            offset: 4,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        assert_eq!(
            returned_large_blobs_parameters,
            expected_large_blobs_parameters
        );

        // successful first set
        let cbor_value = cbor_map! {
            0x02 => vec! [0x5E],
            0x03 => 0,
            0x04 => MIN_LARGE_BLOB_LEN as u64,
            0x05 => vec! [0xA9],
            0x06 => 1,
        };
        let returned_large_blobs_parameters =
            AuthenticatorLargeBlobsParameters::try_from(cbor_value).unwrap();
        let expected_large_blobs_parameters = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(vec![0x5E]),
            offset: 0,
            length: Some(MIN_LARGE_BLOB_LEN),
            pin_uv_auth_param: Some(vec![0xA9]),
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
        };
        assert_eq!(
            returned_large_blobs_parameters,
            expected_large_blobs_parameters
        );

        // successful next set
        let cbor_value = cbor_map! {
            0x02 => vec! [0x5E],
            0x03 => 1,
            0x05 => vec! [0xA9],
            0x06 => 1,
        };
        let returned_large_blobs_parameters =
            AuthenticatorLargeBlobsParameters::try_from(cbor_value).unwrap();
        let expected_large_blobs_parameters = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(vec![0x5E]),
            offset: 1,
            length: None,
            pin_uv_auth_param: Some(vec![0xA9]),
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
        };
        assert_eq!(
            returned_large_blobs_parameters,
            expected_large_blobs_parameters
        );

        // failing with neither get nor set
        let cbor_value = cbor_map! {
            0x03 => 4,
            0x05 => vec! [0xA9],
            0x06 => 1,
        };
        assert_eq!(
            AuthenticatorLargeBlobsParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        // failing with get and set
        let cbor_value = cbor_map! {
            0x01 => 2,
            0x02 => vec! [0x5E],
            0x03 => 4,
            0x05 => vec! [0xA9],
            0x06 => 1,
        };
        assert_eq!(
            AuthenticatorLargeBlobsParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        // failing with get and length
        let cbor_value = cbor_map! {
            0x01 => 2,
            0x03 => 4,
            0x04 => MIN_LARGE_BLOB_LEN as u64,
            0x05 => vec! [0xA9],
            0x06 => 1,
        };
        assert_eq!(
            AuthenticatorLargeBlobsParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        // failing with zero offset and no length present
        let cbor_value = cbor_map! {
            0x02 => vec! [0x5E],
            0x03 => 0,
            0x05 => vec! [0xA9],
            0x06 => 1,
        };
        assert_eq!(
            AuthenticatorLargeBlobsParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        // failing with non-zero offset and length present
        let cbor_value = cbor_map! {
            0x02 => vec! [0x5E],
            0x03 => 4,
            0x04 => MIN_LARGE_BLOB_LEN as u64,
            0x05 => vec! [0xA9],
            0x06 => 1,
        };
        assert_eq!(
            AuthenticatorLargeBlobsParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );
    }
}
