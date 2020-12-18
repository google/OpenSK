// Copyright 2019 Google LLC
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

use super::data_formats::{
    extract_array, extract_bool, extract_byte_string, extract_map, extract_text_string,
    extract_unsigned, ok_or_missing, ClientPinSubCommand, CoseKey, GetAssertionExtensions,
    GetAssertionOptions, MakeCredentialExtensions, MakeCredentialOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameter, PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
};
use super::key_material;
use super::status_code::Ctap2StatusCode;
use alloc::string::String;
use alloc::vec::Vec;
use arrayref::array_ref;
use cbor::destructure_cbor_map;
use core::convert::TryFrom;

// Depending on your memory, you can use Some(n) to limit request sizes in
// MakeCredential and GetAssertion. This affects allowList and excludeList.
// You might also want to set the max credential size in process_get_info then.
pub const MAX_CREDENTIAL_COUNT_IN_LIST: Option<usize> = None;

// CTAP specification (version 20190130) section 6.1
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
pub enum Command {
    AuthenticatorMakeCredential(AuthenticatorMakeCredentialParameters),
    AuthenticatorGetAssertion(AuthenticatorGetAssertionParameters),
    AuthenticatorGetInfo,
    AuthenticatorClientPin(AuthenticatorClientPinParameters),
    AuthenticatorReset,
    AuthenticatorGetNextAssertion,
    #[cfg(feature = "with_ctap2_1")]
    AuthenticatorSelection,
    // TODO(kaczmarczyck) implement FIDO 2.1 commands (see below consts)
    // Vendor specific commands
    AuthenticatorVendorConfigure(AuthenticatorVendorConfigureParameters),
}

impl From<cbor::reader::DecoderError> for Ctap2StatusCode {
    fn from(_: cbor::reader::DecoderError) -> Self {
        Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR
    }
}

// TODO: Remove this `allow(dead_code)` once the constants are used.
#[allow(dead_code)]
impl Command {
    const AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;
    const AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;
    const AUTHENTICATOR_GET_INFO: u8 = 0x04;
    const AUTHENTICATOR_CLIENT_PIN: u8 = 0x06;
    const AUTHENTICATOR_RESET: u8 = 0x07;
    const AUTHENTICATOR_GET_NEXT_ASSERTION: u8 = 0x08;
    // TODO(kaczmarczyck) use or remove those constants
    const AUTHENTICATOR_BIO_ENROLLMENT: u8 = 0x09;
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
            #[cfg(feature = "with_ctap2_1")]
            Command::AUTHENTICATOR_SELECTION => {
                // Parameters are ignored.
                Ok(Command::AuthenticatorSelection)
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

#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
pub struct AuthenticatorMakeCredentialParameters {
    pub client_data_hash: Vec<u8>,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameter>,
    pub exclude_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub extensions: Option<MakeCredentialExtensions>,
    // Even though options are optional, we can use the default if not present.
    pub options: MakeCredentialOptions,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_protocol: Option<u64>,
}

impl TryFrom<cbor::Value> for AuthenticatorMakeCredentialParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                1 => client_data_hash,
                2 => rp,
                3 => user,
                4 => cred_param_vec,
                5 => exclude_list,
                6 => extensions,
                7 => options,
                8 => pin_uv_auth_param,
                9 => pin_uv_auth_protocol,
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
            .transpose()?;

        let options = match options {
            Some(entry) => MakeCredentialOptions::try_from(entry)?,
            None => MakeCredentialOptions {
                rk: false,
                uv: false,
            },
        };

        let pin_uv_auth_param = pin_uv_auth_param.map(extract_byte_string).transpose()?;
        let pin_uv_auth_protocol = pin_uv_auth_protocol.map(extract_unsigned).transpose()?;

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
        })
    }
}

#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
pub struct AuthenticatorGetAssertionParameters {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allow_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub extensions: Option<GetAssertionExtensions>,
    // Even though options are optional, we can use the default if not present.
    pub options: GetAssertionOptions,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_protocol: Option<u64>,
}

impl TryFrom<cbor::Value> for AuthenticatorGetAssertionParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                1 => rp_id,
                2 => client_data_hash,
                3 => allow_list,
                4 => extensions,
                5 => options,
                6 => pin_uv_auth_param,
                7 => pin_uv_auth_protocol,
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
            .transpose()?;

        let options = match options {
            Some(entry) => GetAssertionOptions::try_from(entry)?,
            None => GetAssertionOptions {
                up: true,
                uv: false,
            },
        };

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

#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
pub struct AuthenticatorClientPinParameters {
    pub pin_protocol: u64,
    pub sub_command: ClientPinSubCommand,
    pub key_agreement: Option<CoseKey>,
    pub pin_auth: Option<Vec<u8>>,
    pub new_pin_enc: Option<Vec<u8>>,
    pub pin_hash_enc: Option<Vec<u8>>,
    #[cfg(feature = "with_ctap2_1")]
    pub min_pin_length: Option<u8>,
    #[cfg(feature = "with_ctap2_1")]
    pub min_pin_length_rp_ids: Option<Vec<String>>,
    #[cfg(feature = "with_ctap2_1")]
    pub permissions: Option<u8>,
    #[cfg(feature = "with_ctap2_1")]
    pub permissions_rp_id: Option<String>,
}

impl TryFrom<cbor::Value> for AuthenticatorClientPinParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        #[cfg(not(feature = "with_ctap2_1"))]
        destructure_cbor_map! {
            let {
                1 => pin_protocol,
                2 => sub_command,
                3 => key_agreement,
                4 => pin_auth,
                5 => new_pin_enc,
                6 => pin_hash_enc,
            } = extract_map(cbor_value)?;
        }
        #[cfg(feature = "with_ctap2_1")]
        destructure_cbor_map! {
            let {
                1 => pin_protocol,
                2 => sub_command,
                3 => key_agreement,
                4 => pin_auth,
                5 => new_pin_enc,
                6 => pin_hash_enc,
                7 => min_pin_length,
                8 => min_pin_length_rp_ids,
                9 => permissions,
                10 => permissions_rp_id,
            } = extract_map(cbor_value)?;
        }

        let pin_protocol = extract_unsigned(ok_or_missing(pin_protocol)?)?;
        let sub_command = ClientPinSubCommand::try_from(ok_or_missing(sub_command)?)?;
        let key_agreement = key_agreement.map(extract_map).transpose()?.map(CoseKey);
        let pin_auth = pin_auth.map(extract_byte_string).transpose()?;
        let new_pin_enc = new_pin_enc.map(extract_byte_string).transpose()?;
        let pin_hash_enc = pin_hash_enc.map(extract_byte_string).transpose()?;
        #[cfg(feature = "with_ctap2_1")]
        let min_pin_length = min_pin_length
            .map(extract_unsigned)
            .transpose()?
            .map(u8::try_from)
            .transpose()
            .map_err(|_| Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION)?;
        #[cfg(feature = "with_ctap2_1")]
        let min_pin_length_rp_ids = match min_pin_length_rp_ids {
            Some(entry) => Some(
                extract_array(entry)?
                    .into_iter()
                    .map(extract_text_string)
                    .collect::<Result<Vec<String>, Ctap2StatusCode>>()?,
            ),
            None => None,
        };
        #[cfg(feature = "with_ctap2_1")]
        // We expect a bit field of 8 bits, and drop everything else.
        // This means we ignore extensions in future versions.
        let permissions = permissions
            .map(extract_unsigned)
            .transpose()?
            .map(|p| p as u8);
        #[cfg(feature = "with_ctap2_1")]
        let permissions_rp_id = permissions_rp_id.map(extract_text_string).transpose()?;

        Ok(AuthenticatorClientPinParameters {
            pin_protocol,
            sub_command,
            key_agreement,
            pin_auth,
            new_pin_enc,
            pin_hash_enc,
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length,
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length_rp_ids,
            #[cfg(feature = "with_ctap2_1")]
            permissions,
            #[cfg(feature = "with_ctap2_1")]
            permissions_rp_id,
        })
    }
}

#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
pub struct AuthenticatorAttestationMaterial {
    pub certificate: Vec<u8>,
    pub private_key: [u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH],
}

impl TryFrom<cbor::Value> for AuthenticatorAttestationMaterial {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                1 => certificate,
                2 => private_key,
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

#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
pub struct AuthenticatorVendorConfigureParameters {
    pub lockdown: bool,
    pub attestation_material: Option<AuthenticatorAttestationMaterial>,
}

impl TryFrom<cbor::Value> for AuthenticatorVendorConfigureParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                1 => lockdown,
                2 => attestation_material,
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
    use alloc::collections::BTreeMap;
    use cbor::{cbor_array, cbor_map};

    #[test]
    fn test_from_cbor_make_credential_parameters() {
        let cbor_value = cbor_map! {
            1 => vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
            2 => cbor_map! {
                "id" => "example.com",
                "name" => "Example",
                "icon" => "example.com/icon.png",
            },
            3 => cbor_map! {
                "id" => vec![0x1D, 0x1D, 0x1D, 0x1D],
                "name" => "foo",
                "displayName" => "bar",
                "icon" => "example.com/foo/icon.png",
            },
            4 => cbor_array![ES256_CRED_PARAM],
            5 => cbor_array![],
            8 => vec![0x12, 0x34],
            9 => 1,
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
            extensions: None,
            options,
            pin_uv_auth_param: Some(vec![0x12, 0x34]),
            pin_uv_auth_protocol: Some(1),
        };

        assert_eq!(
            returned_make_credential_parameters,
            expected_make_credential_parameters
        );
    }

    #[test]
    fn test_from_cbor_get_assertion_parameters() {
        let cbor_value = cbor_map! {
            1 => "example.com",
            2 => vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
            3 => cbor_array![ cbor_map! {
                "type" => "public-key",
                "id" => vec![0x2D, 0x2D, 0x2D, 0x2D],
                "transports" => cbor_array!["usb"],
            } ],
            6 => vec![0x12, 0x34],
            7 => 1,
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
            extensions: None,
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
        // TODO(kaczmarczyck) inline the #cfg when #128 is resolved:
        // https://github.com/google/OpenSK/issues/128
        #[cfg(not(feature = "with_ctap2_1"))]
        let cbor_value = cbor_map! {
            1 => 1,
            2 => ClientPinSubCommand::GetPinRetries,
            3 => cbor_map!{},
            4 => vec! [0xBB],
            5 => vec! [0xCC],
            6 => vec! [0xDD],
        };
        #[cfg(feature = "with_ctap2_1")]
        let cbor_value = cbor_map! {
            1 => 1,
            2 => ClientPinSubCommand::GetPinRetries,
            3 => cbor_map!{},
            4 => vec! [0xBB],
            5 => vec! [0xCC],
            6 => vec! [0xDD],
            7 => 4,
            8 => cbor_array!["example.com"],
            9 => 0x03,
            10 => "example.com",
        };
        let returned_pin_protocol_parameters =
            AuthenticatorClientPinParameters::try_from(cbor_value).unwrap();

        let expected_pin_protocol_parameters = AuthenticatorClientPinParameters {
            pin_protocol: 1,
            sub_command: ClientPinSubCommand::GetPinRetries,
            key_agreement: Some(CoseKey(BTreeMap::new())),
            pin_auth: Some(vec![0xBB]),
            new_pin_enc: Some(vec![0xCC]),
            pin_hash_enc: Some(vec![0xDD]),
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length: Some(4),
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length_rp_ids: Some(vec!["example.com".to_string()]),
            #[cfg(feature = "with_ctap2_1")]
            permissions: Some(0x03),
            #[cfg(feature = "with_ctap2_1")]
            permissions_rp_id: Some("example.com".to_string()),
        };

        assert_eq!(
            returned_pin_protocol_parameters,
            expected_pin_protocol_parameters
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

    #[cfg(feature = "with_ctap2_1")]
    #[test]
    fn test_deserialize_selection() {
        let cbor_bytes = [Command::AUTHENTICATOR_SELECTION];
        let command = Command::deserialize(&cbor_bytes);
        assert_eq!(command, Ok(Command::AuthenticatorSelection));
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
            1 => false,
            2 => cbor_map! {
                1 => dummy_cert,
                2 => dummy_pkey[..key_material::ATTESTATION_PRIVATE_KEY_LENGTH - 1]
            }
        };
        assert_eq!(
            AuthenticatorVendorConfigureParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        // Missing private key
        let cbor_value = cbor_map! {
            1 => false,
            2 => cbor_map! {
                1 => dummy_cert
            }
        };
        assert_eq!(
            AuthenticatorVendorConfigureParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
        );

        // Missing certificate
        let cbor_value = cbor_map! {
            1 => false,
            2 => cbor_map! {
                2 => dummy_pkey
            }
        };
        assert_eq!(
            AuthenticatorVendorConfigureParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
        );

        // Valid
        let cbor_value = cbor_map! {
            1 => false,
            2 => cbor_map! {
                1 => dummy_cert,
                2 => dummy_pkey
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
