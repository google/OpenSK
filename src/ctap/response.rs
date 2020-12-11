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

#[cfg(feature = "with_ctap2_1")]
use super::data_formats::{AuthenticatorTransport, PublicKeyCredentialParameter};
use super::data_formats::{
    CoseKey, CredentialProtectionPolicy, PackedAttestationStatement, PublicKeyCredentialDescriptor,
    PublicKeyCredentialUserEntity,
};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use cbor::{cbor_array_vec, cbor_bool, cbor_map_btree, cbor_map_options, cbor_text};

#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
pub enum ResponseData {
    AuthenticatorMakeCredential(AuthenticatorMakeCredentialResponse),
    AuthenticatorGetAssertion(AuthenticatorGetAssertionResponse),
    AuthenticatorGetNextAssertion(AuthenticatorGetAssertionResponse),
    AuthenticatorGetInfo(AuthenticatorGetInfoResponse),
    AuthenticatorClientPin(Option<AuthenticatorClientPinResponse>),
    AuthenticatorReset,
    #[cfg(feature = "with_ctap2_1")]
    AuthenticatorSelection,
    AuthenticatorVendor(AuthenticatorVendorResponse),
}

impl From<ResponseData> for Option<cbor::Value> {
    fn from(response: ResponseData) -> Self {
        match response {
            ResponseData::AuthenticatorMakeCredential(data) => Some(data.into()),
            ResponseData::AuthenticatorGetAssertion(data) => Some(data.into()),
            ResponseData::AuthenticatorGetNextAssertion(data) => Some(data.into()),
            ResponseData::AuthenticatorGetInfo(data) => Some(data.into()),
            ResponseData::AuthenticatorClientPin(Some(data)) => Some(data.into()),
            ResponseData::AuthenticatorClientPin(None) => None,
            ResponseData::AuthenticatorReset => None,
            #[cfg(feature = "with_ctap2_1")]
            ResponseData::AuthenticatorSelection => None,
            ResponseData::AuthenticatorVendor(data) => Some(data.into()),
        }
    }
}

#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
pub struct AuthenticatorMakeCredentialResponse {
    pub fmt: String,
    pub auth_data: Vec<u8>,
    pub att_stmt: PackedAttestationStatement,
}

impl From<AuthenticatorMakeCredentialResponse> for cbor::Value {
    fn from(make_credential_response: AuthenticatorMakeCredentialResponse) -> Self {
        let AuthenticatorMakeCredentialResponse {
            fmt,
            auth_data,
            att_stmt,
        } = make_credential_response;

        cbor_map_options! {
            1 => fmt,
            2 => auth_data,
            3 => att_stmt,
        }
    }
}

#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
pub struct AuthenticatorGetAssertionResponse {
    pub credential: Option<PublicKeyCredentialDescriptor>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user: Option<PublicKeyCredentialUserEntity>,
    pub number_of_credentials: Option<u64>,
}

impl From<AuthenticatorGetAssertionResponse> for cbor::Value {
    fn from(get_assertion_response: AuthenticatorGetAssertionResponse) -> Self {
        let AuthenticatorGetAssertionResponse {
            credential,
            auth_data,
            signature,
            user,
            number_of_credentials,
        } = get_assertion_response;

        cbor_map_options! {
            1 => credential,
            2 => auth_data,
            3 => signature,
            4 => user,
            5 => number_of_credentials,
        }
    }
}

#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
pub struct AuthenticatorGetInfoResponse {
    // TODO(kaczmarczyck) add maxAuthenticatorConfigLength and defaultCredProtect
    pub versions: Vec<String>,
    pub extensions: Option<Vec<String>>,
    pub aaguid: [u8; 16],
    pub options: Option<BTreeMap<String, bool>>,
    pub max_msg_size: Option<u64>,
    pub pin_protocols: Option<Vec<u64>>,
    #[cfg(feature = "with_ctap2_1")]
    pub max_credential_count_in_list: Option<u64>,
    #[cfg(feature = "with_ctap2_1")]
    pub max_credential_id_length: Option<u64>,
    #[cfg(feature = "with_ctap2_1")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
    #[cfg(feature = "with_ctap2_1")]
    pub algorithms: Option<Vec<PublicKeyCredentialParameter>>,
    pub default_cred_protect: Option<CredentialProtectionPolicy>,
    #[cfg(feature = "with_ctap2_1")]
    pub min_pin_length: u8,
    #[cfg(feature = "with_ctap2_1")]
    pub firmware_version: Option<u64>,
}

impl From<AuthenticatorGetInfoResponse> for cbor::Value {
    #[cfg(feature = "with_ctap2_1")]
    fn from(get_info_response: AuthenticatorGetInfoResponse) -> Self {
        let AuthenticatorGetInfoResponse {
            versions,
            extensions,
            aaguid,
            options,
            max_msg_size,
            pin_protocols,
            max_credential_count_in_list,
            max_credential_id_length,
            transports,
            algorithms,
            default_cred_protect,
            min_pin_length,
            firmware_version,
        } = get_info_response;

        let options_cbor: Option<cbor::Value> = options.map(|options| {
            let option_map: BTreeMap<_, _> = options
                .into_iter()
                .map(|(key, value)| (cbor_text!(key), cbor_bool!(value)))
                .collect();
            cbor_map_btree!(option_map)
        });

        cbor_map_options! {
            0x01 => cbor_array_vec!(versions),
            0x02 => extensions.map(|vec| cbor_array_vec!(vec)),
            0x03 => &aaguid,
            0x04 => options_cbor,
            0x05 => max_msg_size,
            0x06 => pin_protocols.map(|vec| cbor_array_vec!(vec)),
            0x07 => max_credential_count_in_list,
            0x08 => max_credential_id_length,
            0x09 => transports.map(|vec| cbor_array_vec!(vec)),
            0x0A => algorithms.map(|vec| cbor_array_vec!(vec)),
            0x0C => default_cred_protect.map(|p| p as u64),
            0x0D => min_pin_length as u64,
            0x0E => firmware_version,
        }
    }

    #[cfg(not(feature = "with_ctap2_1"))]
    fn from(get_info_response: AuthenticatorGetInfoResponse) -> Self {
        let AuthenticatorGetInfoResponse {
            versions,
            extensions,
            aaguid,
            options,
            max_msg_size,
            pin_protocols,
            default_cred_protect,
        } = get_info_response;

        let options_cbor: Option<cbor::Value> = options.map(|options| {
            let option_map: BTreeMap<_, _> = options
                .into_iter()
                .map(|(key, value)| (cbor_text!(key), cbor_bool!(value)))
                .collect();
            cbor_map_btree!(option_map)
        });

        cbor_map_options! {
            0x01 => cbor_array_vec!(versions),
            0x02 => extensions.map(|vec| cbor_array_vec!(vec)),
            0x03 => &aaguid,
            0x04 => options_cbor,
            0x05 => max_msg_size,
            0x06 => pin_protocols.map(|vec| cbor_array_vec!(vec)),
            0x0C => default_cred_protect.map(|p| p as u64),
        }
    }
}

#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
pub struct AuthenticatorClientPinResponse {
    pub key_agreement: Option<CoseKey>,
    pub pin_token: Option<Vec<u8>>,
    pub retries: Option<u64>,
}

impl From<AuthenticatorClientPinResponse> for cbor::Value {
    fn from(client_pin_response: AuthenticatorClientPinResponse) -> Self {
        let AuthenticatorClientPinResponse {
            key_agreement,
            pin_token,
            retries,
        } = client_pin_response;

        cbor_map_options! {
            1 => key_agreement.map(|cose_key| cbor_map_btree!(cose_key.0)),
            2 => pin_token,
            3 => retries,
        }
    }
}

#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
pub struct AuthenticatorVendorResponse {
    pub cert_programmed: bool,
    pub pkey_programmed: bool,
}

impl From<AuthenticatorVendorResponse> for cbor::Value {
    fn from(vendor_response: AuthenticatorVendorResponse) -> Self {
        let AuthenticatorVendorResponse {
            cert_programmed,
            pkey_programmed,
        } = vendor_response;

        cbor_map_options! {
            1 => cert_programmed,
            2 => pkey_programmed,
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::data_formats::PackedAttestationStatement;
    #[cfg(feature = "with_ctap2_1")]
    use super::super::ES256_CRED_PARAM;
    use super::*;
    use cbor::{cbor_bytes, cbor_map};

    #[test]
    fn test_make_credential_into_cbor() {
        let certificate: cbor::values::KeyType = cbor_bytes![vec![0x5C, 0x5C, 0x5C, 0x5C]];
        let att_stmt = PackedAttestationStatement {
            alg: 1,
            sig: vec![0x55, 0x55, 0x55, 0x55],
            x5c: Some(vec![vec![0x5C, 0x5C, 0x5C, 0x5C]]),
            ecdaa_key_id: Some(vec![0xEC, 0xDA, 0x1D]),
        };
        let cbor_packed_attestation_statement = cbor_map! {
            "alg" => 1,
            "sig" => vec![0x55, 0x55, 0x55, 0x55],
            "x5c" => cbor_array_vec![vec![certificate]],
            "ecdaaKeyId" => vec![0xEC, 0xDA, 0x1D],
        };

        let make_credential_response = AuthenticatorMakeCredentialResponse {
            fmt: "packed".to_string(),
            auth_data: vec![0xAD],
            att_stmt,
        };
        let response_cbor: Option<cbor::Value> =
            ResponseData::AuthenticatorMakeCredential(make_credential_response).into();
        let expected_cbor = cbor_map_options! {
            1 => "packed",
            2 => vec![0xAD],
            3 => cbor_packed_attestation_statement,
        };
        assert_eq!(response_cbor, Some(expected_cbor));
    }

    #[test]
    fn test_get_assertion_into_cbor() {
        let get_assertion_response = AuthenticatorGetAssertionResponse {
            credential: None,
            auth_data: vec![0xAD],
            signature: vec![0x51],
            user: None,
            number_of_credentials: None,
        };
        let response_cbor: Option<cbor::Value> =
            ResponseData::AuthenticatorGetAssertion(get_assertion_response).into();
        let expected_cbor = cbor_map_options! {
            2 => vec![0xAD],
            3 => vec![0x51],
        };
        assert_eq!(response_cbor, Some(expected_cbor));
    }

    #[test]
    fn test_get_info_into_cbor() {
        let versions = vec!["FIDO_2_0".to_string()];
        let get_info_response = AuthenticatorGetInfoResponse {
            versions: versions.clone(),
            extensions: None,
            aaguid: [0x00; 16],
            options: None,
            max_msg_size: None,
            pin_protocols: None,
            #[cfg(feature = "with_ctap2_1")]
            max_credential_count_in_list: None,
            #[cfg(feature = "with_ctap2_1")]
            max_credential_id_length: None,
            #[cfg(feature = "with_ctap2_1")]
            transports: None,
            #[cfg(feature = "with_ctap2_1")]
            algorithms: None,
            default_cred_protect: None,
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length: 4,
            #[cfg(feature = "with_ctap2_1")]
            firmware_version: None,
        };
        let response_cbor: Option<cbor::Value> =
            ResponseData::AuthenticatorGetInfo(get_info_response).into();
        #[cfg(not(feature = "with_ctap2_1"))]
        let expected_cbor = cbor_map_options! {
            0x01 => cbor_array_vec![versions],
            0x03 => vec![0x00; 16],
        };
        #[cfg(feature = "with_ctap2_1")]
        let expected_cbor = cbor_map_options! {
            0x01 => cbor_array_vec![versions],
            0x03 => vec![0x00; 16],
            0x0D => 4,
        };
        assert_eq!(response_cbor, Some(expected_cbor));
    }

    #[test]
    #[cfg(feature = "with_ctap2_1")]
    fn test_get_info_optionals_into_cbor() {
        let mut options_map = BTreeMap::new();
        options_map.insert(String::from("rk"), true);
        let get_info_response = AuthenticatorGetInfoResponse {
            versions: vec!["FIDO_2_0".to_string()],
            extensions: Some(vec!["extension".to_string()]),
            aaguid: [0x00; 16],
            options: Some(options_map),
            max_msg_size: Some(1024),
            pin_protocols: Some(vec![1]),
            max_credential_count_in_list: Some(20),
            max_credential_id_length: Some(256),
            transports: Some(vec![AuthenticatorTransport::Usb]),
            algorithms: Some(vec![ES256_CRED_PARAM]),
            default_cred_protect: Some(CredentialProtectionPolicy::UserVerificationRequired),
            min_pin_length: 4,
            firmware_version: Some(0),
        };
        let response_cbor: Option<cbor::Value> =
            ResponseData::AuthenticatorGetInfo(get_info_response).into();
        let expected_cbor = cbor_map_options! {
            0x01 => cbor_array_vec![vec!["FIDO_2_0"]],
            0x02 => cbor_array_vec![vec!["extension"]],
            0x03 => vec![0x00; 16],
            0x04 => cbor_map! {"rk" => true},
            0x05 => 1024,
            0x06 => cbor_array_vec![vec![1]],
            0x07 => 20,
            0x08 => 256,
            0x09 => cbor_array_vec![vec!["usb"]],
            0x0A => cbor_array_vec![vec![ES256_CRED_PARAM]],
            0x0C => CredentialProtectionPolicy::UserVerificationRequired as u64,
            0x0D => 4,
            0x0E => 0,
        };
        assert_eq!(response_cbor, Some(expected_cbor));
    }

    #[test]
    fn test_used_client_pin_into_cbor() {
        let client_pin_response = AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: Some(vec![70]),
            retries: None,
        };
        let response_cbor: Option<cbor::Value> =
            ResponseData::AuthenticatorClientPin(Some(client_pin_response)).into();
        let expected_cbor = cbor_map_options! {
            2 => vec![70],
        };
        assert_eq!(response_cbor, Some(expected_cbor));
    }

    #[test]
    fn test_empty_client_pin_into_cbor() {
        let response_cbor: Option<cbor::Value> = ResponseData::AuthenticatorClientPin(None).into();
        assert_eq!(response_cbor, None);
    }

    #[test]
    fn test_reset_into_cbor() {
        let response_cbor: Option<cbor::Value> = ResponseData::AuthenticatorReset.into();
        assert_eq!(response_cbor, None);
    }

    #[cfg(feature = "with_ctap2_1")]
    #[test]
    fn test_selection_into_cbor() {
        let response_cbor: Option<cbor::Value> = ResponseData::AuthenticatorSelection.into();
        assert_eq!(response_cbor, None);
    }

    #[test]
    fn test_vendor_response_into_cbor() {
        let response_cbor: Option<cbor::Value> =
            ResponseData::AuthenticatorVendor(AuthenticatorVendorResponse {
                cert_programmed: true,
                pkey_programmed: false,
            })
            .into();
        assert_eq!(
            response_cbor,
            Some(cbor_map_options! {
                1 => true,
                2 => false,
            })
        );
        let response_cbor: Option<cbor::Value> =
            ResponseData::AuthenticatorVendor(AuthenticatorVendorResponse {
                cert_programmed: false,
                pkey_programmed: true,
            })
            .into();
        assert_eq!(
            response_cbor,
            Some(cbor_map_options! {
                1 => false,
                2 => true,
            })
        );
    }
}
