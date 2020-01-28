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
    CoseKey, PackedAttestationStatement, PublicKeyCredentialDescriptor,
    PublicKeyCredentialUserEntity,
};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
pub enum ResponseData {
    AuthenticatorMakeCredential(AuthenticatorMakeCredentialResponse),
    AuthenticatorGetAssertion(AuthenticatorGetAssertionResponse),
    AuthenticatorGetNextAssertion(AuthenticatorGetAssertionResponse),
    AuthenticatorGetInfo(AuthenticatorGetInfoResponse),
    AuthenticatorClientPin(Option<AuthenticatorClientPinResponse>),
    AuthenticatorReset,
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
    // TODO(kaczmarczyck) add fields from 2.1
    pub versions: Vec<String>,
    pub extensions: Option<Vec<String>>,
    pub aaguid: [u8; 16],
    pub options: Option<BTreeMap<String, bool>>,
    pub max_msg_size: Option<u64>,
    pub pin_protocols: Option<Vec<u64>>,
}

impl From<AuthenticatorGetInfoResponse> for cbor::Value {
    fn from(get_info_response: AuthenticatorGetInfoResponse) -> Self {
        let AuthenticatorGetInfoResponse {
            versions,
            extensions,
            aaguid,
            options,
            max_msg_size,
            pin_protocols,
        } = get_info_response;

        let options_cbor: Option<cbor::Value> = options.map(|options| {
            let option_map: BTreeMap<_, _> = options
                .into_iter()
                .map(|(key, value)| (cbor_text!(key), cbor_bool!(value)))
                .collect();
            cbor_map_btree!(option_map)
        });

        cbor_map_options! {
            1 => cbor_array_vec!(versions),
            2 => extensions.map(|vec| cbor_array_vec!(vec)),
            3 => &aaguid,
            4 => options_cbor,
            5 => max_msg_size,
            6 => pin_protocols.map(|vec| cbor_array_vec!(vec)),
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

#[cfg(test)]
mod test {
    use super::super::data_formats::PackedAttestationStatement;
    use super::*;

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
        let get_info_response = AuthenticatorGetInfoResponse {
            versions: vec!["FIDO_2_0".to_string()],
            extensions: None,
            aaguid: [0x00; 16],
            options: None,
            max_msg_size: None,
            pin_protocols: None,
        };
        let response_cbor: Option<cbor::Value> =
            ResponseData::AuthenticatorGetInfo(get_info_response).into();
        let expected_cbor = cbor_map_options! {
            1 => cbor_array_vec![vec!["FIDO_2_0"]],
            3 => vec![0x00; 16],
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
}
