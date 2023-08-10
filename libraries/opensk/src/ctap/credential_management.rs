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
use super::command::AuthenticatorCredentialManagementParameters;
use super::data_formats::{
    CredentialManagementSubCommand, CredentialManagementSubCommandParameters,
    PublicKeyCredentialDescriptor, PublicKeyCredentialRpEntity, PublicKeyCredentialSource,
    PublicKeyCredentialUserEntity,
};
use super::response::{AuthenticatorCredentialManagementResponse, ResponseData};
use super::status_code::Ctap2StatusCode;
use super::{Channel, StatefulCommand, StatefulPermission};
use crate::api::crypto::sha256::Sha256;
use crate::ctap::storage;
use crate::env::{Env, Sha};
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Generates a set with all existing RP IDs.
fn get_stored_rp_ids(env: &mut impl Env) -> Result<BTreeSet<String>, Ctap2StatusCode> {
    let mut rp_set = BTreeSet::new();
    let mut iter_result = Ok(());
    for (_, credential) in storage::iter_credentials(env, &mut iter_result)? {
        rp_set.insert(credential.rp_id);
    }
    iter_result?;
    Ok(rp_set)
}

/// Generates the response for subcommands enumerating RPs.
fn enumerate_rps_response<E: Env>(
    rp_id: String,
    total_rps: Option<u64>,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    let rp_id_hash = Some(Sha::<E>::digest(rp_id.as_bytes()).to_vec());
    let rp = Some(PublicKeyCredentialRpEntity {
        rp_id,
        rp_name: None,
        rp_icon: None,
    });
    Ok(AuthenticatorCredentialManagementResponse {
        rp,
        rp_id_hash,
        total_rps,
        ..Default::default()
    })
}

/// Generates the response for subcommands enumerating credentials.
fn enumerate_credentials_response<E: Env>(
    credential: PublicKeyCredentialSource,
    total_credentials: Option<u64>,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    let PublicKeyCredentialSource {
        key_type,
        credential_id,
        private_key,
        rp_id: _,
        user_handle,
        user_display_name,
        cred_protect_policy,
        creation_order: _,
        user_name,
        user_icon,
        cred_blob: _,
        large_blob_key,
    } = credential;
    let user = PublicKeyCredentialUserEntity {
        user_id: user_handle,
        user_name,
        user_display_name,
        user_icon,
    };
    let credential_id = PublicKeyCredentialDescriptor {
        key_type,
        key_id: credential_id,
        transports: None, // You can set USB as a hint here.
    };
    let public_key = private_key.get_pub_key::<E>()?;
    Ok(AuthenticatorCredentialManagementResponse {
        user: Some(user),
        credential_id: Some(credential_id),
        public_key: Some(public_key),
        total_credentials,
        cred_protect: cred_protect_policy,
        large_blob_key,
        ..Default::default()
    })
}

/// Check if the token permissions have the correct associated RP ID.
///
/// Either no RP ID is associated, or the RP ID matches the stored credential.
fn check_rp_id_permissions<E: Env>(
    env: &mut E,
    client_pin: &mut ClientPin<E>,
    credential_id: &[u8],
) -> Result<(), Ctap2StatusCode> {
    // Pre-check a sufficient condition before calling the store.
    if client_pin.has_no_rp_id_permission().is_ok() {
        return Ok(());
    }
    let (_, credential) = storage::find_credential_item(env, credential_id)?;
    client_pin.has_no_or_rp_id_permission(&credential.rp_id)
}

/// Processes the subcommand getCredsMetadata for CredentialManagement.
fn process_get_creds_metadata(
    env: &mut impl Env,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    Ok(AuthenticatorCredentialManagementResponse {
        existing_resident_credentials_count: Some(storage::count_credentials(env)? as u64),
        max_possible_remaining_resident_credentials_count: Some(
            storage::remaining_credentials(env)? as u64,
        ),
        ..Default::default()
    })
}

/// Processes the subcommand enumerateRPsBegin for CredentialManagement.
fn process_enumerate_rps_begin<E: Env>(
    env: &mut E,
    stateful_command_permission: &mut StatefulPermission<E>,
    channel: Channel,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    let mut rp_set = get_stored_rp_ids(env)?;
    let total_rps = rp_set.len();

    if total_rps > 1 {
        stateful_command_permission.set_command(env, StatefulCommand::EnumerateRps(1), channel);
    }
    let rp_id = rp_set
        .pop_first()
        .ok_or(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)?;
    enumerate_rps_response::<E>(rp_id, Some(total_rps as u64))
}

/// Processes the subcommand enumerateRPsGetNextRP for CredentialManagement.
fn process_enumerate_rps_get_next_rp<E: Env>(
    env: &mut E,
    stateful_command_permission: &mut StatefulPermission<E>,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    let rp_id_index = stateful_command_permission.next_enumerate_rp(env)?;
    let rp_set = get_stored_rp_ids(env)?;
    // A BTreeSet is already sorted.
    let rp_id = rp_set
        .into_iter()
        .nth(rp_id_index)
        .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)?;
    enumerate_rps_response::<E>(rp_id, None)
}

/// Processes the subcommand enumerateCredentialsBegin for CredentialManagement.
fn process_enumerate_credentials_begin<E: Env>(
    env: &mut E,
    stateful_command_permission: &mut StatefulPermission<E>,
    client_pin: &mut ClientPin<E>,
    sub_command_params: CredentialManagementSubCommandParameters,
    channel: Channel,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    let rp_id_hash = sub_command_params
        .rp_id_hash
        .ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
    client_pin.has_no_or_rp_id_hash_permission(&rp_id_hash[..])?;
    let mut iter_result = Ok(());
    let iter = storage::iter_credentials(env, &mut iter_result)?;
    let mut rp_credentials: Vec<usize> = iter
        .filter_map(|(key, credential)| {
            let cred_rp_id_hash = Sha::<E>::digest(credential.rp_id.as_bytes());
            if cred_rp_id_hash == rp_id_hash.as_slice() {
                Some(key)
            } else {
                None
            }
        })
        .collect();
    iter_result?;
    let total_credentials = rp_credentials.len();
    let current_key = rp_credentials
        .pop()
        .ok_or(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)?;
    let credential = storage::get_credential(env, current_key)?;
    if total_credentials > 1 {
        stateful_command_permission.set_command(
            env,
            StatefulCommand::EnumerateCredentials(rp_credentials),
            channel,
        );
    }
    enumerate_credentials_response::<E>(credential, Some(total_credentials as u64))
}

/// Processes the subcommand enumerateCredentialsGetNextCredential for CredentialManagement.
fn process_enumerate_credentials_get_next_credential<E: Env>(
    env: &mut E,
    stateful_command_permission: &mut StatefulPermission<E>,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    let credential_key = stateful_command_permission.next_enumerate_credential(env)?;
    let credential = storage::get_credential(env, credential_key)?;
    enumerate_credentials_response::<E>(credential, None)
}

/// Processes the subcommand deleteCredential for CredentialManagement.
fn process_delete_credential<E: Env>(
    env: &mut E,
    client_pin: &mut ClientPin<E>,
    sub_command_params: CredentialManagementSubCommandParameters,
) -> Result<(), Ctap2StatusCode> {
    let credential_id = sub_command_params
        .credential_id
        .ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?
        .key_id;
    check_rp_id_permissions(env, client_pin, &credential_id)?;
    storage::delete_credential(env, &credential_id)
}

/// Processes the subcommand updateUserInformation for CredentialManagement.
fn process_update_user_information<E: Env>(
    env: &mut E,
    client_pin: &mut ClientPin<E>,
    sub_command_params: CredentialManagementSubCommandParameters,
) -> Result<(), Ctap2StatusCode> {
    let credential_id = sub_command_params
        .credential_id
        .ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?
        .key_id;
    let user = sub_command_params
        .user
        .ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
    check_rp_id_permissions(env, client_pin, &credential_id)?;
    storage::update_credential(env, &credential_id, user)
}

/// Processes the CredentialManagement command and all its subcommands.
pub fn process_credential_management<E: Env>(
    env: &mut E,
    stateful_command_permission: &mut StatefulPermission<E>,
    client_pin: &mut ClientPin<E>,
    cred_management_params: AuthenticatorCredentialManagementParameters,
    channel: Channel,
) -> Result<ResponseData, Ctap2StatusCode> {
    let AuthenticatorCredentialManagementParameters {
        sub_command,
        sub_command_params,
        pin_uv_auth_protocol,
        pin_uv_auth_param,
    } = cred_management_params;

    match (sub_command, stateful_command_permission.get_command(env)) {
        (
            CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            Ok(StatefulCommand::EnumerateRps(_)),
        )
        | (
            CredentialManagementSubCommand::EnumerateCredentialsGetNextCredential,
            Ok(StatefulCommand::EnumerateCredentials(_)),
        ) => (),
        (_, _) => {
            stateful_command_permission.clear();
        }
    }

    match sub_command {
        CredentialManagementSubCommand::GetCredsMetadata
        | CredentialManagementSubCommand::EnumerateRpsBegin
        | CredentialManagementSubCommand::EnumerateCredentialsBegin
        | CredentialManagementSubCommand::DeleteCredential
        | CredentialManagementSubCommand::UpdateUserInformation => {
            let pin_uv_auth_param =
                pin_uv_auth_param.ok_or(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)?;
            let pin_uv_auth_protocol =
                pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
            let mut management_data = vec![sub_command as u8];
            if let Some(sub_command_params) = sub_command_params.clone() {
                super::cbor_write(sub_command_params.into(), &mut management_data)?;
            }
            client_pin.verify_pin_uv_auth_token(
                &management_data,
                &pin_uv_auth_param,
                pin_uv_auth_protocol,
            )?;
            // The RP ID permission is handled differently per subcommand below.
            client_pin.has_permission(PinPermission::CredentialManagement)?;
        }
        CredentialManagementSubCommand::EnumerateRpsGetNextRp
        | CredentialManagementSubCommand::EnumerateCredentialsGetNextCredential => {}
    }

    let response = match sub_command {
        CredentialManagementSubCommand::GetCredsMetadata => {
            client_pin.has_no_rp_id_permission()?;
            Some(process_get_creds_metadata(env)?)
        }
        CredentialManagementSubCommand::EnumerateRpsBegin => {
            client_pin.has_no_rp_id_permission()?;
            Some(process_enumerate_rps_begin(
                env,
                stateful_command_permission,
                channel,
            )?)
        }
        CredentialManagementSubCommand::EnumerateRpsGetNextRp => Some(
            process_enumerate_rps_get_next_rp(env, stateful_command_permission)?,
        ),
        CredentialManagementSubCommand::EnumerateCredentialsBegin => {
            Some(process_enumerate_credentials_begin(
                env,
                stateful_command_permission,
                client_pin,
                sub_command_params.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                channel,
            )?)
        }
        CredentialManagementSubCommand::EnumerateCredentialsGetNextCredential => Some(
            process_enumerate_credentials_get_next_credential(env, stateful_command_permission)?,
        ),
        CredentialManagementSubCommand::DeleteCredential => {
            process_delete_credential(
                env,
                client_pin,
                sub_command_params.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
            )?;
            None
        }
        CredentialManagementSubCommand::UpdateUserInformation => {
            process_update_user_information(
                env,
                client_pin,
                sub_command_params.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
            )?;
            None
        }
    };
    Ok(ResponseData::AuthenticatorCredentialManagement(response))
}

#[cfg(test)]
mod test {
    use super::super::data_formats::{PinUvAuthProtocol, PublicKeyCredentialType};
    use super::super::pin_protocol::authenticate_pin_uv_auth_token;
    use super::super::CtapState;
    use super::*;
    use crate::api::crypto::ecdh::SecretKey as _;
    use crate::api::private_key::PrivateKey;
    use crate::api::rng::Rng;
    use crate::env::test::TestEnv;
    use crate::env::EcdhSk;

    const DUMMY_CHANNEL: Channel = Channel::MainHid([0x12, 0x34, 0x56, 0x78]);

    fn create_credential_source(env: &mut TestEnv) -> PublicKeyCredentialSource {
        let private_key = PrivateKey::new_ecdsa(env);
        PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: env.rng().gen_uniform_u8x32().to_vec(),
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x01],
            user_display_name: Some("display_name".to_string()),
            cred_protect_policy: None,
            creation_order: 0,
            user_name: Some("name".to_string()),
            user_icon: Some("icon".to_string()),
            cred_blob: None,
            large_blob_key: None,
        }
    }

    fn test_helper_process_get_creds_metadata(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            pin_uv_auth_protocol,
        );
        let credential_source = create_credential_source(&mut env);

        let mut ctap_state = CtapState::new(&mut env);
        ctap_state.client_pin = client_pin;

        storage::set_pin(&mut env, &[0u8; 16], 4).unwrap();
        let management_data = vec![CredentialManagementSubCommand::GetCredsMetadata as u8];
        let pin_uv_auth_param = authenticate_pin_uv_auth_token(
            &pin_uv_auth_token,
            &management_data,
            pin_uv_auth_protocol,
        );

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::GetCredsMetadata,
            sub_command_params: None,
            pin_uv_auth_protocol: Some(pin_uv_auth_protocol),
            pin_uv_auth_param: Some(pin_uv_auth_param.clone()),
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        let initial_capacity = match cred_management_response.unwrap() {
            ResponseData::AuthenticatorCredentialManagement(Some(response)) => {
                assert_eq!(response.existing_resident_credentials_count, Some(0));
                response
                    .max_possible_remaining_resident_credentials_count
                    .unwrap()
            }
            _ => panic!("Invalid response type"),
        };

        storage::store_credential(&mut env, credential_source).unwrap();

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::GetCredsMetadata,
            sub_command_params: None,
            pin_uv_auth_protocol: Some(pin_uv_auth_protocol),
            pin_uv_auth_param: Some(pin_uv_auth_param),
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        match cred_management_response.unwrap() {
            ResponseData::AuthenticatorCredentialManagement(Some(response)) => {
                assert_eq!(response.existing_resident_credentials_count, Some(1));
                assert_eq!(
                    response.max_possible_remaining_resident_credentials_count,
                    Some(initial_capacity - 1)
                );
            }
            _ => panic!("Invalid response type"),
        };
    }

    #[test]
    fn test_process_get_creds_metadata_v1() {
        test_helper_process_get_creds_metadata(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_creds_metadata_v2() {
        test_helper_process_get_creds_metadata(PinUvAuthProtocol::V2);
    }

    #[test]
    fn test_process_enumerate_rps_with_uv() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );
        let credential_source1 = create_credential_source(&mut env);
        let mut credential_source2 = create_credential_source(&mut env);
        credential_source2.rp_id = "another.example.com".to_string();

        let mut ctap_state = CtapState::new(&mut env);
        ctap_state.client_pin = client_pin;

        storage::store_credential(&mut env, credential_source1).unwrap();
        storage::store_credential(&mut env, credential_source2).unwrap();

        storage::set_pin(&mut env, &[0u8; 16], 4).unwrap();
        let pin_uv_auth_param = Some(vec![
            0x1A, 0xA4, 0x96, 0xDA, 0x62, 0x80, 0x28, 0x13, 0xEB, 0x32, 0xB9, 0xF1, 0xD2, 0xA9,
            0xD0, 0xD1,
        ]);

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsBegin,
            sub_command_params: None,
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param,
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        let first_rp_id = match cred_management_response.unwrap() {
            ResponseData::AuthenticatorCredentialManagement(Some(response)) => {
                assert_eq!(response.total_rps, Some(2));
                let rp_id = response.rp.unwrap().rp_id;
                let rp_id_hash = Sha::<TestEnv>::digest(rp_id.as_bytes());
                assert_eq!(rp_id_hash, response.rp_id_hash.unwrap().as_slice());
                rp_id
            }
            _ => panic!("Invalid response type"),
        };

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        let second_rp_id = match cred_management_response.unwrap() {
            ResponseData::AuthenticatorCredentialManagement(Some(response)) => {
                assert_eq!(response.total_rps, None);
                let rp_id = response.rp.unwrap().rp_id;
                let rp_id_hash = Sha::<TestEnv>::digest(rp_id.as_bytes());
                assert_eq!(rp_id_hash, response.rp_id_hash.unwrap().as_slice());
                rp_id
            }
            _ => panic!("Invalid response type"),
        };

        assert!(first_rp_id != second_rp_id);
        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        assert_eq!(
            cred_management_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_enumerate_rps_completeness() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );
        let credential_source = create_credential_source(&mut env);

        let mut ctap_state = CtapState::new(&mut env);
        ctap_state.client_pin = client_pin;

        const NUM_CREDENTIALS: usize = 20;
        for i in 0..NUM_CREDENTIALS {
            let mut credential = credential_source.clone();
            credential.rp_id = i.to_string();
            storage::store_credential(&mut env, credential).unwrap();
        }

        storage::set_pin(&mut env, &[0u8; 16], 4).unwrap();
        let pin_uv_auth_param = Some(vec![
            0x1A, 0xA4, 0x96, 0xDA, 0x62, 0x80, 0x28, 0x13, 0xEB, 0x32, 0xB9, 0xF1, 0xD2, 0xA9,
            0xD0, 0xD1,
        ]);

        let mut rp_set = BTreeSet::new();
        // This mut is just to make the test code shorter.
        // The command is different on the first loop iteration.
        let mut cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsBegin,
            sub_command_params: None,
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param,
        };

        for _ in 0..NUM_CREDENTIALS {
            let cred_management_response = process_credential_management(
                &mut env,
                &mut ctap_state.stateful_command_permission,
                &mut ctap_state.client_pin,
                cred_management_params,
                DUMMY_CHANNEL,
            );
            match cred_management_response.unwrap() {
                ResponseData::AuthenticatorCredentialManagement(Some(response)) => {
                    if rp_set.is_empty() {
                        assert_eq!(response.total_rps, Some(NUM_CREDENTIALS as u64));
                    } else {
                        assert_eq!(response.total_rps, None);
                    }
                    let rp_id = response.rp.unwrap().rp_id;
                    let rp_id_hash = Sha::<TestEnv>::digest(rp_id.as_bytes());
                    assert_eq!(rp_id_hash, response.rp_id_hash.unwrap().as_slice());
                    assert!(!rp_set.contains(&rp_id));
                    rp_set.insert(rp_id);
                }
                _ => panic!("Invalid response type"),
            };
            cred_management_params = AuthenticatorCredentialManagementParameters {
                sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
                sub_command_params: None,
                pin_uv_auth_protocol: None,
                pin_uv_auth_param: None,
            };
        }

        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        assert_eq!(
            cred_management_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_enumerate_credentials_with_uv() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );
        let credential_source1 = create_credential_source(&mut env);
        let mut credential_source2 = create_credential_source(&mut env);
        credential_source2.user_handle = vec![0x02];
        credential_source2.user_name = Some("user2".to_string());
        credential_source2.user_display_name = Some("User Two".to_string());
        credential_source2.user_icon = Some("icon2".to_string());

        let mut ctap_state = CtapState::new(&mut env);
        ctap_state.client_pin = client_pin;

        storage::store_credential(&mut env, credential_source1).unwrap();
        storage::store_credential(&mut env, credential_source2).unwrap();

        storage::set_pin(&mut env, &[0u8; 16], 4).unwrap();
        let pin_uv_auth_param = Some(vec![
            0xF8, 0xB0, 0x3C, 0xC1, 0xD5, 0x58, 0x9C, 0xB7, 0x4D, 0x42, 0xA1, 0x64, 0x14, 0x28,
            0x2B, 0x68,
        ]);

        let sub_command_params = CredentialManagementSubCommandParameters {
            rp_id_hash: Some(Sha::<TestEnv>::digest(b"example.com").to_vec()),
            credential_id: None,
            user: None,
        };
        // RP ID hash:
        // A379A6F6EEAFB9A55E378C118034E2751E682FAB9F2D30AB13D2125586CE1947
        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateCredentialsBegin,
            sub_command_params: Some(sub_command_params),
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param,
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        let first_credential_id = match cred_management_response.unwrap() {
            ResponseData::AuthenticatorCredentialManagement(Some(response)) => {
                assert!(response.user.is_some());
                assert!(response.public_key.is_some());
                assert_eq!(response.total_credentials, Some(2));
                response.credential_id.unwrap().key_id
            }
            _ => panic!("Invalid response type"),
        };

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateCredentialsGetNextCredential,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        let second_credential_id = match cred_management_response.unwrap() {
            ResponseData::AuthenticatorCredentialManagement(Some(response)) => {
                assert!(response.user.is_some());
                assert!(response.public_key.is_some());
                assert_eq!(response.total_credentials, None);
                response.credential_id.unwrap().key_id
            }
            _ => panic!("Invalid response type"),
        };

        assert!(first_credential_id != second_credential_id);
        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateCredentialsGetNextCredential,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        assert_eq!(
            cred_management_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_delete_credential() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );
        let mut credential_source = create_credential_source(&mut env);
        credential_source.credential_id = vec![0x1D; 32];

        let mut ctap_state = CtapState::new(&mut env);
        ctap_state.client_pin = client_pin;

        storage::store_credential(&mut env, credential_source).unwrap();

        storage::set_pin(&mut env, &[0u8; 16], 4).unwrap();
        let pin_uv_auth_param = Some(vec![
            0xBD, 0xE3, 0xEF, 0x8A, 0x77, 0x01, 0xB1, 0x69, 0x19, 0xE6, 0x62, 0xB9, 0x9B, 0x89,
            0x9C, 0x64,
        ]);

        let credential_id = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: vec![0x1D; 32],
            transports: None, // You can set USB as a hint here.
        };
        let sub_command_params = CredentialManagementSubCommandParameters {
            rp_id_hash: None,
            credential_id: Some(credential_id),
            user: None,
        };
        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::DeleteCredential,
            sub_command_params: Some(sub_command_params.clone()),
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param: pin_uv_auth_param.clone(),
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        assert_eq!(
            cred_management_response,
            Ok(ResponseData::AuthenticatorCredentialManagement(None))
        );

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::DeleteCredential,
            sub_command_params: Some(sub_command_params),
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param,
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        assert_eq!(
            cred_management_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)
        );
    }

    #[test]
    fn test_process_update_user_information() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );
        let mut credential_source = create_credential_source(&mut env);
        credential_source.credential_id = vec![0x1D; 32];

        let mut ctap_state = CtapState::new(&mut env);
        ctap_state.client_pin = client_pin;

        storage::store_credential(&mut env, credential_source).unwrap();

        storage::set_pin(&mut env, &[0u8; 16], 4).unwrap();
        let pin_uv_auth_param = Some(vec![
            0xA5, 0x55, 0x8F, 0x03, 0xC3, 0xD3, 0x73, 0x1C, 0x07, 0xDA, 0x1F, 0x8C, 0xC7, 0xBD,
            0x9D, 0xB7,
        ]);

        let credential_id = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: vec![0x1D; 32],
            transports: None, // You can set USB as a hint here.
        };
        let new_user = PublicKeyCredentialUserEntity {
            user_id: vec![0xFF],
            user_name: Some("new_name".to_string()),
            user_display_name: Some("new_display_name".to_string()),
            user_icon: Some("new_icon".to_string()),
        };
        let sub_command_params = CredentialManagementSubCommandParameters {
            rp_id_hash: None,
            credential_id: Some(credential_id),
            user: Some(new_user),
        };
        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::UpdateUserInformation,
            sub_command_params: Some(sub_command_params),
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param,
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        assert_eq!(
            cred_management_response,
            Ok(ResponseData::AuthenticatorCredentialManagement(None))
        );

        let updated_credential = storage::find_credential(&mut env, "example.com", &[0x1D; 32])
            .unwrap()
            .unwrap();
        assert_eq!(updated_credential.user_handle, vec![0x01]);
        assert_eq!(&updated_credential.user_name.unwrap(), "new_name");
        assert_eq!(
            &updated_credential.user_display_name.unwrap(),
            "new_display_name"
        );
        assert_eq!(&updated_credential.user_icon.unwrap(), "new_icon");
    }

    #[test]
    fn test_process_credential_management_invalid_pin_uv_auth_param() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::new(&mut env);

        storage::set_pin(&mut env, &[0u8; 16], 4).unwrap();

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::GetCredsMetadata,
            sub_command_params: None,
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param: Some(vec![0u8; 16]),
        };
        let cred_management_response = process_credential_management(
            &mut env,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.client_pin,
            cred_management_params,
            DUMMY_CHANNEL,
        );
        assert_eq!(
            cred_management_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}
