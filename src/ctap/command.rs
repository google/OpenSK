// Copyright 2019-2021 Google LLC
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

use super::customization::{MAX_CREDENTIAL_COUNT_IN_LIST, MAX_LARGE_BLOB_ARRAY_SIZE};
use super::data_formats::{
    extract_array, extract_bool, extract_byte_string, extract_map, extract_text_string,
    extract_unsigned, ok_or_missing, ClientPinSubCommand, ConfigSubCommand, ConfigSubCommandParams,
    CoseKey, CredentialManagementSubCommand, CredentialManagementSubCommandParameters,
    GetAssertionExtensions, GetAssertionOptions, MakeCredentialExtensions, MakeCredentialOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameter, PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity, SetMinPinLengthParams,
};
use super::key_material;
use super::status_code::Ctap2StatusCode;
use alloc::string::String;
use alloc::vec::Vec;
use arrayref::array_ref;
use cbor::destructure_cbor_map;
use core::convert::TryFrom;

// This constant is a consequence of the structure of messages.
const MIN_LARGE_BLOB_LEN: usize = 17;

// CTAP specification (version 20190130) section 6.1
#[derive(Debug, PartialEq)]
pub enum Command {
    AuthenticatorMakeCredential(AuthenticatorMakeCredentialParameters),
    AuthenticatorGetAssertion(AuthenticatorGetAssertionParameters),
    AuthenticatorGetInfo,
    AuthenticatorClientPin(AuthenticatorClientPinParameters),
    AuthenticatorReset,
    AuthenticatorGetNextAssertion,
    AuthenticatorCredentialManagement(AuthenticatorCredentialManagementParameters),
    AuthenticatorSelection,
    AuthenticatorLargeBlobs(AuthenticatorLargeBlobsParameters),
    AuthenticatorConfig(AuthenticatorConfigParameters),
    // Vendor specific commands
    AuthenticatorVendorConfigure(AuthenticatorVendorConfigureParameters),
}

impl From<cbor::reader::DecoderError> for Ctap2StatusCode {
    fn from(_: cbor::reader::DecoderError) -> Self {
        Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR
    }
}

impl Command {
    const AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;
    const AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;
    const AUTHENTICATOR_GET_INFO: u8 = 0x04;
    const AUTHENTICATOR_CLIENT_PIN: u8 = 0x06;
    const AUTHENTICATOR_RESET: u8 = 0x07;
    const AUTHENTICATOR_GET_NEXT_ASSERTION: u8 = 0x08;
    // Implement Bio Enrollment when your hardware supports biometrics.
    const _AUTHENTICATOR_BIO_ENROLLMENT: u8 = 0x09;
    const AUTHENTICATOR_CREDENTIAL_MANAGEMENT: u8 = 0x0A;
    const AUTHENTICATOR_SELECTION: u8 = 0x0B;
    const AUTHENTICATOR_LARGE_BLOBS: u8 = 0x0C;
    const AUTHENTICATOR_CONFIG: u8 = 0x0D;
    const _AUTHENTICATOR_VENDOR_FIRST: u8 = 0x40;
    const AUTHENTICATOR_VENDOR_CONFIGURE: u8 = 0x40;
    const _AUTHENTICATOR_VENDOR_LAST: u8 = 0xBF;

    pub fn deserialize(bytes: &[u8]) -> Result<Command, Ctap2StatusCode> {
        if bytes.is_empty() {
            // The error to return is not specified, missing parameter seems to fit best.
            return Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER);
        }

        let command_value = bytes[0];
        match command_value {
            Command::AUTHENTICATOR_MAKE_CREDENTIAL => {
                let decoded_cbor = cbor::read(&bytes[1..])?;
                Ok(Command::AuthenticatorMakeCredential(
                    AuthenticatorMakeCredentialParameters::try_from(decoded_cbor)?,
                ))
            }
            Command::AUTHENTICATOR_GET_ASSERTION => {
                let decoded_cbor = cbor::read(&bytes[1..])?;
                Ok(Command::AuthenticatorGetAssertion(
                    AuthenticatorGetAssertionParameters::try_from(decoded_cbor)?,
                ))
            }
            Command::AUTHENTICATOR_GET_INFO => {
                // Parameters are ignored.
                Ok(Command::AuthenticatorGetInfo)
            }
            Command::AUTHENTICATOR_CLIENT_PIN => {
                let decoded_cbor = cbor::read(&bytes[1..])?;
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
            Command::AUTHENTICATOR_CREDENTIAL_MANAGEMENT => {
                let decoded_cbor = cbor::read(&bytes[1..])?;
                Ok(Command::AuthenticatorCredentialManagement(
                    AuthenticatorCredentialManagementParameters::try_from(decoded_cbor)?,
                ))
            }
            Command::AUTHENTICATOR_SELECTION => {
                // Parameters are ignored.
                Ok(Command::AuthenticatorSelection)
            }
            Command::AUTHENTICATOR_LARGE_BLOBS => {
                let decoded_cbor = cbor::read(&bytes[1..])?;
                Ok(Command::AuthenticatorLargeBlobs(
                    AuthenticatorLargeBlobsParameters::try_from(decoded_cbor)?,
                ))
            }
            Command::AUTHENTICATOR_CONFIG => {
                let decoded_cbor = cbor::read(&bytes[1..])?;
                Ok(Command::AuthenticatorConfig(
                    AuthenticatorConfigParameters::try_from(decoded_cbor)?,
                ))
            }
            Command::AUTHENTICATOR_VENDOR_CONFIGURE => {
                let decoded_cbor = cbor::read(&bytes[1..])?;
                Ok(Command::AuthenticatorVendorConfigure(
                    AuthenticatorVendorConfigureParameters::try_from(decoded_cbor)?,
                ))
            }
            _ => Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND),
        }
    }
}

#[derive(Debug, PartialEq)]
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
    pub pin_uv_auth_protocol: Option<u64>,
    pub enterprise_attestation: Option<u64>,
}

impl TryFrom<cbor::Value> for AuthenticatorMakeCredentialParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
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
            .collect::<Result<Vec<PublicKeyCredentialParameter>, Ctap2StatusCode>>()?;

        let exclude_list = match exclude_list {
            Some(entry) => {
                let exclude_list_vec = extract_array(entry)?;
                let list_len = MAX_CREDENTIAL_COUNT_IN_LIST.unwrap_or(exclude_list_vec.len());
                let exclude_list = exclude_list_vec
                    .into_iter()
                    .take(list_len)
                    .map(PublicKeyCredentialDescriptor::try_from)
                    .collect::<Result<Vec<PublicKeyCredentialDescriptor>, Ctap2StatusCode>>()?;
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
        let pin_uv_auth_protocol = pin_uv_auth_protocol.map(extract_unsigned).transpose()?;
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

#[derive(Debug, PartialEq)]
pub struct AuthenticatorGetAssertionParameters {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allow_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    // Extensions are optional, but we can use defaults for all missing fields.
    pub extensions: GetAssertionExtensions,
    // Same for options, use defaults when not present.
    pub options: GetAssertionOptions,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_protocol: Option<u64>,
}

impl TryFrom<cbor::Value> for AuthenticatorGetAssertionParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
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
                let list_len = MAX_CREDENTIAL_COUNT_IN_LIST.unwrap_or(allow_list_vec.len());
                let allow_list = allow_list_vec
                    .into_iter()
                    .take(list_len)
                    .map(PublicKeyCredentialDescriptor::try_from)
                    .collect::<Result<Vec<PublicKeyCredentialDescriptor>, Ctap2StatusCode>>()?;
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
        let pin_uv_auth_protocol = pin_uv_auth_protocol.map(extract_unsigned).transpose()?;

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

#[derive(Debug, PartialEq)]
pub struct AuthenticatorClientPinParameters {
    pub pin_protocol: u64,
    pub sub_command: ClientPinSubCommand,
    pub key_agreement: Option<CoseKey>,
    pub pin_auth: Option<Vec<u8>>,
    pub new_pin_enc: Option<Vec<u8>>,
    pub pin_hash_enc: Option<Vec<u8>>,
    pub permissions: Option<u8>,
    pub permissions_rp_id: Option<String>,
}

impl TryFrom<cbor::Value> for AuthenticatorClientPinParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                0x01 => pin_protocol,
                0x02 => sub_command,
                0x03 => key_agreement,
                0x04 => pin_auth,
                0x05 => new_pin_enc,
                0x06 => pin_hash_enc,
                0x09 => permissions,
                0x0A => permissions_rp_id,
            } = extract_map(cbor_value)?;
        }

        let pin_protocol = extract_unsigned(ok_or_missing(pin_protocol)?)?;
        let sub_command = ClientPinSubCommand::try_from(ok_or_missing(sub_command)?)?;
        let key_agreement = key_agreement.map(CoseKey::try_from).transpose()?;
        let pin_auth = pin_auth.map(extract_byte_string).transpose()?;
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
            pin_protocol,
            sub_command,
            key_agreement,
            pin_auth,
            new_pin_enc,
            pin_hash_enc,
            permissions,
            permissions_rp_id,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct AuthenticatorLargeBlobsParameters {
    pub get: Option<usize>,
    pub set: Option<Vec<u8>>,
    pub offset: usize,
    pub length: Option<usize>,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_protocol: Option<u64>,
}

impl TryFrom<cbor::Value> for AuthenticatorLargeBlobsParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
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
        let pin_uv_auth_protocol = pin_uv_auth_protocol.map(extract_unsigned).transpose()?;

        if get.is_none() && set.is_none() {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        if get.is_some() && set.is_some() {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        if get.is_some()
            && (length.is_some() || pin_uv_auth_param.is_some() || pin_uv_auth_protocol.is_some())
        {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        if set.is_some() && offset == 0 {
            match length {
                None => return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER),
                Some(len) if len > MAX_LARGE_BLOB_ARRAY_SIZE => {
                    return Err(Ctap2StatusCode::CTAP2_ERR_LARGE_BLOB_STORAGE_FULL)
                }
                Some(len) if len < MIN_LARGE_BLOB_LEN => {
                    return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
                }
                Some(_) => (),
            }
        }
        if set.is_some() && offset != 0 && length.is_some() {
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

#[derive(Debug, PartialEq)]
pub struct AuthenticatorConfigParameters {
    pub sub_command: ConfigSubCommand,
    pub sub_command_params: Option<ConfigSubCommandParams>,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_protocol: Option<u64>,
}

impl TryFrom<cbor::Value> for AuthenticatorConfigParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                0x01 => sub_command,
                0x02 => sub_command_params,
                0x03 => pin_uv_auth_param,
                0x04 => pin_uv_auth_protocol,
            } = extract_map(cbor_value)?;
        }

        let sub_command = ConfigSubCommand::try_from(ok_or_missing(sub_command)?)?;
        let sub_command_params = match sub_command {
            ConfigSubCommand::SetMinPinLength => Some(ConfigSubCommandParams::SetMinPinLength(
                SetMinPinLengthParams::try_from(ok_or_missing(sub_command_params)?)?,
            )),
            _ => None,
        };
        let pin_uv_auth_param = pin_uv_auth_param.map(extract_byte_string).transpose()?;
        let pin_uv_auth_protocol = pin_uv_auth_protocol.map(extract_unsigned).transpose()?;

        Ok(AuthenticatorConfigParameters {
            sub_command,
            sub_command_params,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct AuthenticatorAttestationMaterial {
    pub certificate: Vec<u8>,
    pub private_key: [u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH],
}

impl TryFrom<cbor::Value> for AuthenticatorAttestationMaterial {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                0x01 => certificate,
                0x02 => private_key,
            } = extract_map(cbor_value)?;
        }
        let certificate = extract_byte_string(ok_or_missing(certificate)?)?;
        let private_key = extract_byte_string(ok_or_missing(private_key)?)?;
        if private_key.len() != key_material::ATTESTATION_PRIVATE_KEY_LENGTH {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        let private_key = array_ref!(private_key, 0, key_material::ATTESTATION_PRIVATE_KEY_LENGTH);
        Ok(AuthenticatorAttestationMaterial {
            certificate,
            private_key: *private_key,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct AuthenticatorCredentialManagementParameters {
    pub sub_command: CredentialManagementSubCommand,
    pub sub_command_params: Option<CredentialManagementSubCommandParameters>,
    pub pin_protocol: Option<u64>,
    pub pin_auth: Option<Vec<u8>>,
}

impl TryFrom<cbor::Value> for AuthenticatorCredentialManagementParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                0x01 => sub_command,
                0x02 => sub_command_params,
                0x03 => pin_protocol,
                0x04 => pin_auth,
            } = extract_map(cbor_value)?;
        }

        let sub_command = CredentialManagementSubCommand::try_from(ok_or_missing(sub_command)?)?;
        let sub_command_params = sub_command_params
            .map(CredentialManagementSubCommandParameters::try_from)
            .transpose()?;
        let pin_protocol = pin_protocol.map(extract_unsigned).transpose()?;
        let pin_auth = pin_auth.map(extract_byte_string).transpose()?;

        Ok(AuthenticatorCredentialManagementParameters {
            sub_command,
            sub_command_params,
            pin_protocol,
            pin_auth,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct AuthenticatorVendorConfigureParameters {
    pub lockdown: bool,
    pub attestation_material: Option<AuthenticatorAttestationMaterial>,
}

impl TryFrom<cbor::Value> for AuthenticatorVendorConfigureParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                0x01 => lockdown,
                0x02 => attestation_material,
            } = extract_map(cbor_value)?;
        }
        let lockdown = lockdown.map_or(Ok(false), extract_bool)?;
        let attestation_material = attestation_material
            .map(AuthenticatorAttestationMaterial::try_from)
            .transpose()?;
        Ok(AuthenticatorVendorConfigureParameters {
            lockdown,
            attestation_material,
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
    use cbor::{cbor_array, cbor_map};
    use crypto::rng256::ThreadRng256;

    #[test]
    fn test_from_cbor_make_credential_parameters() {
        let cbor_value = cbor_map! {
            0x01 => vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
            0x02 => cbor_map! {
                "id" => "example.com",
                "name" => "Example",
                "icon" => "example.com/icon.png",
            },
            0x03 => cbor_map! {
                "id" => vec![0x1D, 0x1D, 0x1D, 0x1D],
                "name" => "foo",
                "displayName" => "bar",
                "icon" => "example.com/foo/icon.png",
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
            pin_uv_auth_protocol: Some(1),
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
                "type" => "public-key",
                "id" => vec![0x2D, 0x2D, 0x2D, 0x2D],
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
            pin_uv_auth_protocol: Some(1),
        };

        assert_eq!(
            returned_get_assertion_parameters,
            expected_get_assertion_parameters
        );
    }

    #[test]
    fn test_from_cbor_client_pin_parameters() {
        let mut rng = ThreadRng256 {};
        let sk = crypto::ecdh::SecKey::gensk(&mut rng);
        let pk = sk.genpk();
        let cose_key = CoseKey::from(pk);

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
            pin_protocol: 1,
            sub_command: ClientPinSubCommand::GetPinRetries,
            key_agreement: Some(cose_key),
            pin_auth: Some(vec![0xBB]),
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
            pin_protocol: Some(1),
            pin_auth: Some(vec![0x9A; 16]),
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
            pin_uv_auth_protocol: Some(1),
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
            pin_uv_auth_protocol: Some(1),
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

        // failing with length smaller than minimum
        let cbor_value = cbor_map! {
            0x02 => vec! [0x5E],
            0x03 => 0,
            0x04 => MIN_LARGE_BLOB_LEN as u64 - 1,
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

    #[test]
    fn test_vendor_configure() {
        // Incomplete command
        let mut cbor_bytes = vec![Command::AUTHENTICATOR_VENDOR_CONFIGURE];
        let command = Command::deserialize(&cbor_bytes);
        assert_eq!(command, Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR));

        cbor_bytes.extend(&[0xA1, 0x01, 0xF5]);
        let command = Command::deserialize(&cbor_bytes);
        assert_eq!(
            command,
            Ok(Command::AuthenticatorVendorConfigure(
                AuthenticatorVendorConfigureParameters {
                    lockdown: true,
                    attestation_material: None
                }
            ))
        );

        let dummy_cert = [0xddu8; 20];
        let dummy_pkey = [0x41u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH];

        // Attestation key is too short.
        let cbor_value = cbor_map! {
            0x01 => false,
            0x02 => cbor_map! {
                0x01 => dummy_cert,
                0x02 => dummy_pkey[..key_material::ATTESTATION_PRIVATE_KEY_LENGTH - 1]
            }
        };
        assert_eq!(
            AuthenticatorVendorConfigureParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        // Missing private key
        let cbor_value = cbor_map! {
            0x01 => false,
            0x02 => cbor_map! {
                0x01 => dummy_cert
            }
        };
        assert_eq!(
            AuthenticatorVendorConfigureParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
        );

        // Missing certificate
        let cbor_value = cbor_map! {
            0x01 => false,
            0x02 => cbor_map! {
                0x02 => dummy_pkey
            }
        };
        assert_eq!(
            AuthenticatorVendorConfigureParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
        );

        // Valid
        let cbor_value = cbor_map! {
            0x01 => false,
            0x02 => cbor_map! {
                0x01 => dummy_cert,
                0x02 => dummy_pkey
            }
        };
        assert_eq!(
            AuthenticatorVendorConfigureParameters::try_from(cbor_value),
            Ok(AuthenticatorVendorConfigureParameters {
                lockdown: false,
                attestation_material: Some(AuthenticatorAttestationMaterial {
                    certificate: dummy_cert.to_vec(),
                    private_key: dummy_pkey
                })
            })
        );
    }
}
