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

use super::command::AuthenticatorCredentialManagementParameters;
use super::data_formats::{
    CoseKey, CredentialManagementSubCommand, CredentialManagementSubCommandParameters,
    PublicKeyCredentialDescriptor, PublicKeyCredentialRpEntity, PublicKeyCredentialSource,
    PublicKeyCredentialUserEntity,
};
use super::pin_protocol_v1::{PinPermission, PinProtocolV1};
use super::response::{AuthenticatorCredentialManagementResponse, ResponseData};
use super::status_code::Ctap2StatusCode;
use super::storage::PersistentStore;
use super::{check_pin_uv_auth_protocol, StatefulCommand, StatefulPermission};
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use crypto::sha256::Sha256;
use crypto::Hash256;
use libtock_drivers::timer::ClockValue;

/// Generates a set with all existing RP IDs.
fn get_stored_rp_ids(
    persistent_store: &PersistentStore,
) -> Result<BTreeSet<String>, Ctap2StatusCode> {
    let mut rp_set = BTreeSet::new();
    let mut iter_result = Ok(());
    for (_, credential) in persistent_store.iter_credentials(&mut iter_result)? {
        rp_set.insert(credential.rp_id);
    }
    iter_result?;
    Ok(rp_set)
}

/// Generates the response for subcommands enumerating RPs.
fn enumerate_rps_response(
    rp_id: Option<String>,
    total_rps: Option<u64>,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    let rp = rp_id.clone().map(|rp_id| PublicKeyCredentialRpEntity {
        rp_id,
        rp_name: None,
        rp_icon: None,
    });
    let rp_id_hash = rp_id.map(|rp_id| Sha256::hash(rp_id.as_bytes()).to_vec());

    Ok(AuthenticatorCredentialManagementResponse {
        rp,
        rp_id_hash,
        total_rps,
        ..Default::default()
    })
}

/// Generates the response for subcommands enumerating credentials.
fn enumerate_credentials_response(
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
    let public_key = CoseKey::from(private_key.genpk());
    Ok(AuthenticatorCredentialManagementResponse {
        user: Some(user),
        credential_id: Some(credential_id),
        public_key: Some(public_key),
        total_credentials,
        cred_protect: cred_protect_policy,
        // TODO(kaczmarczyck) add when largeBlobKey extension is implemented
        large_blob_key: None,
        ..Default::default()
    })
}

/// Processes the subcommand getCredsMetadata for CredentialManagement.
fn process_get_creds_metadata(
    persistent_store: &PersistentStore,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    Ok(AuthenticatorCredentialManagementResponse {
        existing_resident_credentials_count: Some(persistent_store.count_credentials()? as u64),
        max_possible_remaining_resident_credentials_count: Some(
            persistent_store.remaining_credentials()? as u64,
        ),
        ..Default::default()
    })
}

/// Processes the subcommand enumerateRPsBegin for CredentialManagement.
fn process_enumerate_rps_begin(
    persistent_store: &PersistentStore,
    stateful_command_permission: &mut StatefulPermission,
    now: ClockValue,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    let rp_set = get_stored_rp_ids(persistent_store)?;
    let total_rps = rp_set.len();

    // TODO(kaczmarczyck) should we return CTAP2_ERR_NO_CREDENTIALS if empty?
    if total_rps > 1 {
        stateful_command_permission.set_command(now, StatefulCommand::EnumerateRps(1));
    }
    // TODO https://github.com/rust-lang/rust/issues/62924 replace with pop_first()
    enumerate_rps_response(rp_set.into_iter().next(), Some(total_rps as u64))
}

/// Processes the subcommand enumerateRPsGetNextRP for CredentialManagement.
fn process_enumerate_rps_get_next_rp(
    persistent_store: &PersistentStore,
    stateful_command_permission: &mut StatefulPermission,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    let rp_id_index = stateful_command_permission.next_enumerate_rp()?;
    let rp_set = get_stored_rp_ids(persistent_store)?;
    // A BTreeSet is already sorted.
    let rp_id = rp_set
        .into_iter()
        .nth(rp_id_index)
        .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)?;
    enumerate_rps_response(Some(rp_id), None)
}

/// Processes the subcommand enumerateCredentialsBegin for CredentialManagement.
fn process_enumerate_credentials_begin(
    persistent_store: &PersistentStore,
    stateful_command_permission: &mut StatefulPermission,
    sub_command_params: CredentialManagementSubCommandParameters,
    now: ClockValue,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    let rp_id_hash = sub_command_params
        .rp_id_hash
        .ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
    let mut iter_result = Ok(());
    let iter = persistent_store.iter_credentials(&mut iter_result)?;
    let mut rp_credentials: Vec<usize> = iter
        .filter_map(|(key, credential)| {
            let cred_rp_id_hash = Sha256::hash(credential.rp_id.as_bytes());
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
    let credential = persistent_store.get_credential(current_key)?;
    if total_credentials > 1 {
        stateful_command_permission
            .set_command(now, StatefulCommand::EnumerateCredentials(rp_credentials));
    }
    enumerate_credentials_response(credential, Some(total_credentials as u64))
}

/// Processes the subcommand enumerateCredentialsGetNextCredential for CredentialManagement.
fn process_enumerate_credentials_get_next_credential(
    persistent_store: &PersistentStore,
    stateful_command_permission: &mut StatefulPermission,
) -> Result<AuthenticatorCredentialManagementResponse, Ctap2StatusCode> {
    let credential_key = stateful_command_permission.next_enumerate_credential()?;
    let credential = persistent_store.get_credential(credential_key)?;
    enumerate_credentials_response(credential, None)
}

/// Processes the subcommand deleteCredential for CredentialManagement.
fn process_delete_credential(
    persistent_store: &mut PersistentStore,
    sub_command_params: CredentialManagementSubCommandParameters,
) -> Result<(), Ctap2StatusCode> {
    let credential_id = sub_command_params
        .credential_id
        .ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?
        .key_id;
    persistent_store.delete_credential(&credential_id)
}

/// Processes the subcommand updateUserInformation for CredentialManagement.
fn process_update_user_information(
    persistent_store: &mut PersistentStore,
    sub_command_params: CredentialManagementSubCommandParameters,
) -> Result<(), Ctap2StatusCode> {
    let credential_id = sub_command_params
        .credential_id
        .ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?
        .key_id;
    let user = sub_command_params
        .user
        .ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
    persistent_store.update_credential(&credential_id, user)
}

/// Processes the CredentialManagement command and all its subcommands.
pub fn process_credential_management(
    persistent_store: &mut PersistentStore,
    stateful_command_permission: &mut StatefulPermission,
    pin_protocol_v1: &mut PinProtocolV1,
    cred_management_params: AuthenticatorCredentialManagementParameters,
    now: ClockValue,
) -> Result<ResponseData, Ctap2StatusCode> {
    let AuthenticatorCredentialManagementParameters {
        sub_command,
        sub_command_params,
        pin_protocol,
        pin_auth,
    } = cred_management_params;

    match (sub_command, stateful_command_permission.get_command()) {
        (
            CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            Ok(StatefulCommand::EnumerateRps(_)),
        )
        | (
            CredentialManagementSubCommand::EnumerateCredentialsGetNextCredential,
            Ok(StatefulCommand::EnumerateCredentials(_)),
        ) => stateful_command_permission.check_command_permission(now)?,
        (_, _) => {
            stateful_command_permission.clear();
        }
    }

    match sub_command {
        CredentialManagementSubCommand::GetCredsMetadata
        | CredentialManagementSubCommand::EnumerateRpsBegin
        | CredentialManagementSubCommand::DeleteCredential
        | CredentialManagementSubCommand::EnumerateCredentialsBegin
        | CredentialManagementSubCommand::UpdateUserInformation => {
            check_pin_uv_auth_protocol(pin_protocol)?;
            persistent_store
                .pin_hash()?
                .ok_or(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)?;
            let pin_auth = pin_auth.ok_or(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)?;
            let mut management_data = vec![sub_command as u8];
            if let Some(sub_command_params) = sub_command_params.clone() {
                if !cbor::write(sub_command_params.into(), &mut management_data) {
                    return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
                }
            }
            if !pin_protocol_v1.verify_pin_auth_token(&management_data, &pin_auth) {
                return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
            }
            pin_protocol_v1.has_permission(PinPermission::CredentialManagement)?;
            pin_protocol_v1.has_no_permission_rp_id()?;
            // TODO(kaczmarczyck) sometimes allow a RP ID
        }
        CredentialManagementSubCommand::EnumerateRpsGetNextRp
        | CredentialManagementSubCommand::EnumerateCredentialsGetNextCredential => {}
    }

    let response = match sub_command {
        CredentialManagementSubCommand::GetCredsMetadata => {
            Some(process_get_creds_metadata(persistent_store)?)
        }
        CredentialManagementSubCommand::EnumerateRpsBegin => Some(process_enumerate_rps_begin(
            persistent_store,
            stateful_command_permission,
            now,
        )?),
        CredentialManagementSubCommand::EnumerateRpsGetNextRp => Some(
            process_enumerate_rps_get_next_rp(persistent_store, stateful_command_permission)?,
        ),
        CredentialManagementSubCommand::EnumerateCredentialsBegin => {
            Some(process_enumerate_credentials_begin(
                persistent_store,
                stateful_command_permission,
                sub_command_params.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                now,
            )?)
        }
        CredentialManagementSubCommand::EnumerateCredentialsGetNextCredential => {
            Some(process_enumerate_credentials_get_next_credential(
                persistent_store,
                stateful_command_permission,
            )?)
        }
        CredentialManagementSubCommand::DeleteCredential => {
            process_delete_credential(
                persistent_store,
                sub_command_params.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
            )?;
            None
        }
        CredentialManagementSubCommand::UpdateUserInformation => {
            process_update_user_information(
                persistent_store,
                sub_command_params.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
            )?;
            None
        }
    };
    Ok(ResponseData::AuthenticatorCredentialManagement(response))
}

#[cfg(test)]
mod test {
    use super::super::data_formats::PublicKeyCredentialType;
    use super::super::CtapState;
    use super::*;
    use crypto::rng256::{Rng256, ThreadRng256};

    const CLOCK_FREQUENCY_HZ: usize = 32768;
    const DUMMY_CLOCK_VALUE: ClockValue = ClockValue::new(0, CLOCK_FREQUENCY_HZ);

    fn create_credential_source(rng: &mut impl Rng256) -> PublicKeyCredentialSource {
        let private_key = crypto::ecdsa::SecKey::gensk(rng);
        PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: rng.gen_uniform_u8x32().to_vec(),
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x01],
            user_display_name: Some("display_name".to_string()),
            cred_protect_policy: None,
            creation_order: 0,
            user_name: Some("name".to_string()),
            user_icon: Some("icon".to_string()),
            cred_blob: None,
        }
    }

    #[test]
    fn test_process_get_creds_metadata() {
        let mut rng = ThreadRng256 {};
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pin_uv_auth_token = [0x55; 32];
        let pin_protocol_v1 = PinProtocolV1::new_test(key_agreement_key, pin_uv_auth_token);
        let credential_source = create_credential_source(&mut rng);

        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        ctap_state.pin_protocol_v1 = pin_protocol_v1;

        ctap_state.persistent_store.set_pin(&[0u8; 16], 4).unwrap();
        let pin_auth = Some(vec![
            0xC5, 0xFB, 0x75, 0x55, 0x98, 0xB5, 0x19, 0x01, 0xB3, 0x31, 0x7D, 0xFE, 0x1D, 0xF5,
            0xFB, 0x00,
        ]);

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::GetCredsMetadata,
            sub_command_params: None,
            pin_protocol: Some(1),
            pin_auth: pin_auth.clone(),
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
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

        ctap_state
            .persistent_store
            .store_credential(credential_source)
            .unwrap();

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::GetCredsMetadata,
            sub_command_params: None,
            pin_protocol: Some(1),
            pin_auth,
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
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
    fn test_process_enumerate_rps_with_uv() {
        let mut rng = ThreadRng256 {};
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pin_uv_auth_token = [0x55; 32];
        let pin_protocol_v1 = PinProtocolV1::new_test(key_agreement_key, pin_uv_auth_token);
        let credential_source1 = create_credential_source(&mut rng);
        let mut credential_source2 = create_credential_source(&mut rng);
        credential_source2.rp_id = "another.example.com".to_string();

        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        ctap_state.pin_protocol_v1 = pin_protocol_v1;

        ctap_state
            .persistent_store
            .store_credential(credential_source1)
            .unwrap();
        ctap_state
            .persistent_store
            .store_credential(credential_source2)
            .unwrap();

        ctap_state.persistent_store.set_pin(&[0u8; 16], 4).unwrap();
        let pin_auth = Some(vec![
            0x1A, 0xA4, 0x96, 0xDA, 0x62, 0x80, 0x28, 0x13, 0xEB, 0x32, 0xB9, 0xF1, 0xD2, 0xA9,
            0xD0, 0xD1,
        ]);

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsBegin,
            sub_command_params: None,
            pin_protocol: Some(1),
            pin_auth,
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
        );
        let first_rp_id = match cred_management_response.unwrap() {
            ResponseData::AuthenticatorCredentialManagement(Some(response)) => {
                assert_eq!(response.total_rps, Some(2));
                let rp_id = response.rp.unwrap().rp_id;
                let rp_id_hash = Sha256::hash(rp_id.as_bytes());
                assert_eq!(rp_id_hash, response.rp_id_hash.unwrap().as_slice());
                rp_id
            }
            _ => panic!("Invalid response type"),
        };

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            sub_command_params: None,
            pin_protocol: None,
            pin_auth: None,
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
        );
        let second_rp_id = match cred_management_response.unwrap() {
            ResponseData::AuthenticatorCredentialManagement(Some(response)) => {
                assert_eq!(response.total_rps, None);
                let rp_id = response.rp.unwrap().rp_id;
                let rp_id_hash = Sha256::hash(rp_id.as_bytes());
                assert_eq!(rp_id_hash, response.rp_id_hash.unwrap().as_slice());
                rp_id
            }
            _ => panic!("Invalid response type"),
        };

        assert!(first_rp_id != second_rp_id);
        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            sub_command_params: None,
            pin_protocol: None,
            pin_auth: None,
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
        );
        assert_eq!(
            cred_management_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_enumerate_rps_completeness() {
        let mut rng = ThreadRng256 {};
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pin_uv_auth_token = [0x55; 32];
        let pin_protocol_v1 = PinProtocolV1::new_test(key_agreement_key, pin_uv_auth_token);
        let credential_source = create_credential_source(&mut rng);

        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        ctap_state.pin_protocol_v1 = pin_protocol_v1;

        const NUM_CREDENTIALS: usize = 20;
        for i in 0..NUM_CREDENTIALS {
            let mut credential = credential_source.clone();
            credential.rp_id = i.to_string();
            ctap_state
                .persistent_store
                .store_credential(credential)
                .unwrap();
        }

        ctap_state.persistent_store.set_pin(&[0u8; 16], 4).unwrap();
        let pin_auth = Some(vec![
            0x1A, 0xA4, 0x96, 0xDA, 0x62, 0x80, 0x28, 0x13, 0xEB, 0x32, 0xB9, 0xF1, 0xD2, 0xA9,
            0xD0, 0xD1,
        ]);

        let mut rp_set = BTreeSet::new();
        // This mut is just to make the test code shorter.
        // The command is different on the first loop iteration.
        let mut cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsBegin,
            sub_command_params: None,
            pin_protocol: Some(1),
            pin_auth,
        };

        for _ in 0..NUM_CREDENTIALS {
            let cred_management_response = process_credential_management(
                &mut ctap_state.persistent_store,
                &mut ctap_state.stateful_command_permission,
                &mut ctap_state.pin_protocol_v1,
                cred_management_params,
                DUMMY_CLOCK_VALUE,
            );
            match cred_management_response.unwrap() {
                ResponseData::AuthenticatorCredentialManagement(Some(response)) => {
                    if rp_set.is_empty() {
                        assert_eq!(response.total_rps, Some(NUM_CREDENTIALS as u64));
                    } else {
                        assert_eq!(response.total_rps, None);
                    }
                    let rp_id = response.rp.unwrap().rp_id;
                    let rp_id_hash = Sha256::hash(rp_id.as_bytes());
                    assert_eq!(rp_id_hash, response.rp_id_hash.unwrap().as_slice());
                    assert!(!rp_set.contains(&rp_id));
                    rp_set.insert(rp_id);
                }
                _ => panic!("Invalid response type"),
            };
            cred_management_params = AuthenticatorCredentialManagementParameters {
                sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
                sub_command_params: None,
                pin_protocol: None,
                pin_auth: None,
            };
        }

        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
        );
        assert_eq!(
            cred_management_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_enumerate_credentials_with_uv() {
        let mut rng = ThreadRng256 {};
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pin_uv_auth_token = [0x55; 32];
        let pin_protocol_v1 = PinProtocolV1::new_test(key_agreement_key, pin_uv_auth_token);
        let credential_source1 = create_credential_source(&mut rng);
        let mut credential_source2 = create_credential_source(&mut rng);
        credential_source2.user_handle = vec![0x02];
        credential_source2.user_name = Some("user2".to_string());
        credential_source2.user_display_name = Some("User Two".to_string());
        credential_source2.user_icon = Some("icon2".to_string());

        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        ctap_state.pin_protocol_v1 = pin_protocol_v1;

        ctap_state
            .persistent_store
            .store_credential(credential_source1)
            .unwrap();
        ctap_state
            .persistent_store
            .store_credential(credential_source2)
            .unwrap();

        ctap_state.persistent_store.set_pin(&[0u8; 16], 4).unwrap();
        let pin_auth = Some(vec![
            0xF8, 0xB0, 0x3C, 0xC1, 0xD5, 0x58, 0x9C, 0xB7, 0x4D, 0x42, 0xA1, 0x64, 0x14, 0x28,
            0x2B, 0x68,
        ]);

        let sub_command_params = CredentialManagementSubCommandParameters {
            rp_id_hash: Some(Sha256::hash(b"example.com").to_vec()),
            credential_id: None,
            user: None,
        };
        // RP ID hash:
        // A379A6F6EEAFB9A55E378C118034E2751E682FAB9F2D30AB13D2125586CE1947
        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateCredentialsBegin,
            sub_command_params: Some(sub_command_params),
            pin_protocol: Some(1),
            pin_auth,
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
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
            pin_protocol: None,
            pin_auth: None,
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
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
            pin_protocol: None,
            pin_auth: None,
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
        );
        assert_eq!(
            cred_management_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_delete_credential() {
        let mut rng = ThreadRng256 {};
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pin_uv_auth_token = [0x55; 32];
        let pin_protocol_v1 = PinProtocolV1::new_test(key_agreement_key, pin_uv_auth_token);
        let mut credential_source = create_credential_source(&mut rng);
        credential_source.credential_id = vec![0x1D; 32];

        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        ctap_state.pin_protocol_v1 = pin_protocol_v1;

        ctap_state
            .persistent_store
            .store_credential(credential_source)
            .unwrap();

        ctap_state.persistent_store.set_pin(&[0u8; 16], 4).unwrap();
        let pin_auth = Some(vec![
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
            pin_protocol: Some(1),
            pin_auth: pin_auth.clone(),
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
        );
        assert_eq!(
            cred_management_response,
            Ok(ResponseData::AuthenticatorCredentialManagement(None))
        );

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::DeleteCredential,
            sub_command_params: Some(sub_command_params),
            pin_protocol: Some(1),
            pin_auth,
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
        );
        assert_eq!(
            cred_management_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)
        );
    }

    #[test]
    fn test_process_update_user_information() {
        let mut rng = ThreadRng256 {};
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pin_uv_auth_token = [0x55; 32];
        let pin_protocol_v1 = PinProtocolV1::new_test(key_agreement_key, pin_uv_auth_token);
        let mut credential_source = create_credential_source(&mut rng);
        credential_source.credential_id = vec![0x1D; 32];

        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        ctap_state.pin_protocol_v1 = pin_protocol_v1;

        ctap_state
            .persistent_store
            .store_credential(credential_source)
            .unwrap();

        ctap_state.persistent_store.set_pin(&[0u8; 16], 4).unwrap();
        let pin_auth = Some(vec![
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
            pin_protocol: Some(1),
            pin_auth,
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
        );
        assert_eq!(
            cred_management_response,
            Ok(ResponseData::AuthenticatorCredentialManagement(None))
        );

        let updated_credential = ctap_state
            .persistent_store
            .find_credential("example.com", &[0x1D; 32], false)
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
    fn test_process_credential_management_invalid_pin_protocol() {
        let mut rng = ThreadRng256 {};
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pin_uv_auth_token = [0x55; 32];
        let pin_protocol_v1 = PinProtocolV1::new_test(key_agreement_key, pin_uv_auth_token);

        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        ctap_state.pin_protocol_v1 = pin_protocol_v1;

        ctap_state.persistent_store.set_pin(&[0u8; 16], 4).unwrap();
        let pin_auth = Some(vec![
            0xC5, 0xFB, 0x75, 0x55, 0x98, 0xB5, 0x19, 0x01, 0xB3, 0x31, 0x7D, 0xFE, 0x1D, 0xF5,
            0xFB, 0x00,
        ]);

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::GetCredsMetadata,
            sub_command_params: None,
            pin_protocol: Some(123456),
            pin_auth,
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
        );
        assert_eq!(
            cred_management_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_process_credential_management_invalid_pin_auth() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        ctap_state.persistent_store.set_pin(&[0u8; 16], 4).unwrap();

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::GetCredsMetadata,
            sub_command_params: None,
            pin_protocol: Some(1),
            pin_auth: Some(vec![0u8; 16]),
        };
        let cred_management_response = process_credential_management(
            &mut ctap_state.persistent_store,
            &mut ctap_state.stateful_command_permission,
            &mut ctap_state.pin_protocol_v1,
            cred_management_params,
            DUMMY_CLOCK_VALUE,
        );
        assert_eq!(
            cred_management_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}
