// Copyright 2020-2021 Google LLC
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
use super::command::AuthenticatorLargeBlobsParameters;
use super::response::{AuthenticatorLargeBlobsResponse, ResponseData};
use super::status_code::Ctap2StatusCode;
use crate::api::crypto::sha256::Sha256;
use crate::api::customization::Customization;
use crate::ctap::storage;
use crate::env::{Env, Sha};
use alloc::vec;
use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};

/// The length of the truncated hash that is appended to the large blob data.
const TRUNCATED_HASH_LEN: usize = 16;

pub struct LargeBlobs {
    buffer: Vec<u8>,
    expected_length: usize,
    expected_next_offset: usize,
}

/// Implements the logic for the AuthenticatorLargeBlobs command and keeps its state.
impl LargeBlobs {
    pub fn new() -> LargeBlobs {
        LargeBlobs {
            buffer: Vec::new(),
            expected_length: 0,
            expected_next_offset: 0,
        }
    }

    /// Process the large blob command.
    pub fn process_command<E: Env>(
        &mut self,
        env: &mut E,
        client_pin: &mut ClientPin<E>,
        large_blobs_params: AuthenticatorLargeBlobsParameters,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let AuthenticatorLargeBlobsParameters {
            get,
            set,
            offset,
            length,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        } = large_blobs_params;

        let max_fragment_size = env.customization().max_msg_size() - 64;

        if let Some(get) = get {
            if get > max_fragment_size || offset.checked_add(get).is_none() {
                return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_LENGTH);
            }
            let config = storage::get_large_blob_array(env, offset, get)?;
            return Ok(ResponseData::AuthenticatorLargeBlobs(Some(
                AuthenticatorLargeBlobsResponse { config },
            )));
        }

        if let Some(mut set) = set {
            if set.len() > max_fragment_size {
                return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_LENGTH);
            }
            if offset == 0 {
                self.expected_length =
                    length.ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
                if self.expected_length > env.customization().max_large_blob_array_size() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_LARGE_BLOB_STORAGE_FULL);
                }
                self.expected_next_offset = 0;
            }
            if offset != self.expected_next_offset {
                return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_SEQ);
            }
            if storage::pin_hash(env)?.is_some() || storage::has_always_uv(env)? {
                let pin_uv_auth_param =
                    pin_uv_auth_param.ok_or(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)?;
                let pin_uv_auth_protocol =
                    pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
                let mut large_blob_data = vec![0xFF; 32];
                large_blob_data.extend(&[0x0C, 0x00]);
                let mut offset_bytes = [0u8; 4];
                LittleEndian::write_u32(&mut offset_bytes, offset as u32);
                large_blob_data.extend(&offset_bytes);
                large_blob_data.extend(&Sha::<E>::digest(set.as_slice()));
                client_pin.verify_pin_uv_auth_token(
                    &large_blob_data,
                    &pin_uv_auth_param,
                    pin_uv_auth_protocol,
                )?;
                client_pin.has_permission(PinPermission::LargeBlobWrite)?;
            }
            if offset + set.len() > self.expected_length {
                return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
            }
            if offset == 0 {
                self.buffer = Vec::with_capacity(self.expected_length);
            }
            self.buffer.append(&mut set);
            self.expected_next_offset = self.buffer.len();
            if self.expected_next_offset == self.expected_length {
                self.expected_length = 0;
                self.expected_next_offset = 0;
                // Must be a positive number.
                let buffer_hash_index = self.buffer.len() - TRUNCATED_HASH_LEN;
                if Sha::<E>::digest(&self.buffer[..buffer_hash_index])[..TRUNCATED_HASH_LEN]
                    != self.buffer[buffer_hash_index..]
                {
                    self.buffer = Vec::new();
                    return Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE);
                }
                storage::commit_large_blob_array(env, &self.buffer)?;
                self.buffer = Vec::new();
            }
            return Ok(ResponseData::AuthenticatorLargeBlobs(None));
        }

        // This should be unreachable, since the command has either get or set.
        Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
    }
}

#[cfg(test)]
mod test {
    use super::super::data_formats::PinUvAuthProtocol;
    use super::super::pin_protocol::authenticate_pin_uv_auth_token;
    use super::*;
    use crate::api::crypto::ecdh::SecretKey as EcdhSecretKey;
    use crate::env::test::TestEnv;
    use crate::env::EcdhSk;

    #[test]
    fn test_process_command_get_empty() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );
        let mut large_blobs = LargeBlobs::new();

        let large_blob = vec![
            0x80, 0x76, 0xBE, 0x8B, 0x52, 0x8D, 0x00, 0x75, 0xF7, 0xAA, 0xE9, 0x8D, 0x6F, 0xA5,
            0x7A, 0x6D, 0x3C,
        ];
        let large_blobs_params = AuthenticatorLargeBlobsParameters {
            get: Some(large_blob.len()),
            set: None,
            offset: 0,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let large_blobs_response =
            large_blobs.process_command(&mut env, &mut client_pin, large_blobs_params);
        match large_blobs_response.unwrap() {
            ResponseData::AuthenticatorLargeBlobs(Some(response)) => {
                assert_eq!(response.config, large_blob);
            }
            _ => panic!("Invalid response type"),
        };
    }

    #[test]
    fn test_process_command_commit_and_get() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );
        let mut large_blobs = LargeBlobs::new();

        const BLOB_LEN: usize = 200;
        const DATA_LEN: usize = BLOB_LEN - TRUNCATED_HASH_LEN;
        let mut large_blob = vec![0x1B; DATA_LEN];
        large_blob
            .extend_from_slice(&Sha::<TestEnv>::digest(&large_blob[..])[..TRUNCATED_HASH_LEN]);

        let large_blobs_params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(large_blob[..BLOB_LEN / 2].to_vec()),
            offset: 0,
            length: Some(BLOB_LEN),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let large_blobs_response =
            large_blobs.process_command(&mut env, &mut client_pin, large_blobs_params);
        assert_eq!(
            large_blobs_response,
            Ok(ResponseData::AuthenticatorLargeBlobs(None))
        );

        let large_blobs_params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(large_blob[BLOB_LEN / 2..].to_vec()),
            offset: BLOB_LEN / 2,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let large_blobs_response =
            large_blobs.process_command(&mut env, &mut client_pin, large_blobs_params);
        assert_eq!(
            large_blobs_response,
            Ok(ResponseData::AuthenticatorLargeBlobs(None))
        );

        let large_blobs_params = AuthenticatorLargeBlobsParameters {
            get: Some(BLOB_LEN),
            set: None,
            offset: 0,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let large_blobs_response =
            large_blobs.process_command(&mut env, &mut client_pin, large_blobs_params);
        match large_blobs_response.unwrap() {
            ResponseData::AuthenticatorLargeBlobs(Some(response)) => {
                assert_eq!(response.config, large_blob);
            }
            _ => panic!("Invalid response type"),
        };
    }

    #[test]
    fn test_process_command_commit_unexpected_offset() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );
        let mut large_blobs = LargeBlobs::new();

        const BLOB_LEN: usize = 200;
        const DATA_LEN: usize = BLOB_LEN - TRUNCATED_HASH_LEN;
        let mut large_blob = vec![0x1B; DATA_LEN];
        large_blob
            .extend_from_slice(&Sha::<TestEnv>::digest(&large_blob[..])[..TRUNCATED_HASH_LEN]);

        let large_blobs_params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(large_blob[..BLOB_LEN / 2].to_vec()),
            offset: 0,
            length: Some(BLOB_LEN),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let large_blobs_response =
            large_blobs.process_command(&mut env, &mut client_pin, large_blobs_params);
        assert_eq!(
            large_blobs_response,
            Ok(ResponseData::AuthenticatorLargeBlobs(None))
        );

        let large_blobs_params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(large_blob[BLOB_LEN / 2..].to_vec()),
            // The offset is 1 too big.
            offset: BLOB_LEN / 2 + 1,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let large_blobs_response =
            large_blobs.process_command(&mut env, &mut client_pin, large_blobs_params);
        assert_eq!(
            large_blobs_response,
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_SEQ),
        );
    }

    #[test]
    fn test_process_command_commit_unexpected_length() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );
        let mut large_blobs = LargeBlobs::new();

        const BLOB_LEN: usize = 200;
        const DATA_LEN: usize = BLOB_LEN - TRUNCATED_HASH_LEN;
        let mut large_blob = vec![0x1B; DATA_LEN];
        large_blob
            .extend_from_slice(&Sha::<TestEnv>::digest(&large_blob[..])[..TRUNCATED_HASH_LEN]);

        let large_blobs_params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(large_blob[..BLOB_LEN / 2].to_vec()),
            offset: 0,
            // The length is 1 too small.
            length: Some(BLOB_LEN - 1),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let large_blobs_response =
            large_blobs.process_command(&mut env, &mut client_pin, large_blobs_params);
        assert_eq!(
            large_blobs_response,
            Ok(ResponseData::AuthenticatorLargeBlobs(None))
        );

        let large_blobs_params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(large_blob[BLOB_LEN / 2..].to_vec()),
            offset: BLOB_LEN / 2,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let large_blobs_response =
            large_blobs.process_command(&mut env, &mut client_pin, large_blobs_params);
        assert_eq!(
            large_blobs_response,
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER),
        );
    }

    #[test]
    fn test_process_command_commit_end_offset_overflow() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );
        let mut large_blobs = LargeBlobs::new();

        let large_blobs_params = AuthenticatorLargeBlobsParameters {
            get: Some(1),
            set: None,
            offset: usize::MAX,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        assert_eq!(
            large_blobs.process_command(&mut env, &mut client_pin, large_blobs_params),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_LENGTH),
        );
    }

    #[test]
    fn test_process_command_commit_unexpected_hash() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );
        let mut large_blobs = LargeBlobs::new();

        const BLOB_LEN: usize = 20;
        // This blob does not have an appropriate hash.
        let large_blob = vec![0x1B; BLOB_LEN];

        let large_blobs_params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(large_blob.to_vec()),
            offset: 0,
            length: Some(BLOB_LEN),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let large_blobs_response =
            large_blobs.process_command(&mut env, &mut client_pin, large_blobs_params);
        assert_eq!(
            large_blobs_response,
            Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE),
        );
    }

    fn test_helper_process_command_commit_with_pin(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let mut client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            pin_uv_auth_protocol,
        );
        let mut large_blobs = LargeBlobs::new();

        const BLOB_LEN: usize = 20;
        const DATA_LEN: usize = BLOB_LEN - TRUNCATED_HASH_LEN;
        let mut large_blob = vec![0x1B; DATA_LEN];
        large_blob
            .extend_from_slice(&Sha::<TestEnv>::digest(&large_blob[..])[..TRUNCATED_HASH_LEN]);

        storage::set_pin(&mut env, &[0u8; 16], 4).unwrap();
        let mut large_blob_data = vec![0xFF; 32];
        // Command constant and offset bytes.
        large_blob_data.extend(&[0x0C, 0x00, 0x00, 0x00, 0x00, 0x00]);
        large_blob_data.extend(&Sha::<TestEnv>::digest(&large_blob));
        let pin_uv_auth_param = authenticate_pin_uv_auth_token(
            &pin_uv_auth_token,
            &large_blob_data,
            pin_uv_auth_protocol,
        );

        let large_blobs_params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(large_blob),
            offset: 0,
            length: Some(BLOB_LEN),
            pin_uv_auth_param: Some(pin_uv_auth_param),
            pin_uv_auth_protocol: Some(pin_uv_auth_protocol),
        };
        let large_blobs_response =
            large_blobs.process_command(&mut env, &mut client_pin, large_blobs_params);
        assert_eq!(
            large_blobs_response,
            Ok(ResponseData::AuthenticatorLargeBlobs(None))
        );
    }

    #[test]
    fn test_process_command_commit_with_pin_v1() {
        test_helper_process_command_commit_with_pin(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_command_commit_with_pin_v2() {
        test_helper_process_command_commit_with_pin(PinUvAuthProtocol::V2);
    }
}
