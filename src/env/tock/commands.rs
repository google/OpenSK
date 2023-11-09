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

use super::TockEnv;
use alloc::vec;
use alloc::vec::Vec;
use arrayref::array_ref;
use core::convert::TryFrom;
use libtock_platform::Syscalls;
use opensk::api::attestation_store::{self, Attestation, AttestationStore};
use opensk::api::crypto::sha256::Sha256;
use opensk::api::crypto::EC_FIELD_SIZE;
#[cfg(not(feature = "with_ctap1"))]
use opensk::api::customization::Customization;
#[cfg(not(feature = "std"))]
use opensk::ctap::check_user_presence;
use opensk::ctap::data_formats::{
    extract_bool, extract_byte_string, extract_map, extract_unsigned, ok_or_missing,
};
use opensk::ctap::secret::Secret;
use opensk::ctap::status_code::Ctap2StatusCode;
use opensk::ctap::{cbor_read, cbor_write, Channel};
use opensk::env::{Env, Sha};
use sk_cbor::{cbor_map_options, destructure_cbor_map};
use {libtock_platform as platform, sk_cbor as cbor};

const VENDOR_COMMAND_CONFIGURE: u8 = 0x40;
const VENDOR_COMMAND_UPGRADE: u8 = 0x42;
const VENDOR_COMMAND_UPGRADE_INFO: u8 = 0x43;

pub fn process_vendor_command<
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
>(
    env: &mut TockEnv<S, C>,
    bytes: &[u8],
    channel: Channel,
) -> Option<Vec<u8>> {
    #[cfg(feature = "vendor_hid")]
    if matches!(channel, Channel::MainHid(_)) {
        return None;
    }
    process_cbor(env, bytes, channel).unwrap_or_else(|e| Some(vec![e as u8]))
}

fn process_cbor<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config>(
    env: &mut TockEnv<S, C>,
    bytes: &[u8],
    channel: Channel,
) -> Result<Option<Vec<u8>>, Ctap2StatusCode> {
    match bytes[0] {
        VENDOR_COMMAND_CONFIGURE => {
            let decoded_cbor = cbor_read(&bytes[1..])?;
            let params = VendorConfigureParameters::try_from(decoded_cbor)?;
            let response = process_vendor_configure(env, params, channel)?;
            Ok(Some(encode_cbor(response.into())))
        }
        VENDOR_COMMAND_UPGRADE => {
            let decoded_cbor = cbor_read(&bytes[1..])?;
            let params = VendorUpgradeParameters::try_from(decoded_cbor)?;
            process_vendor_upgrade(env, params)?;
            Ok(Some(vec![Ctap2StatusCode::CTAP2_OK as u8]))
        }
        VENDOR_COMMAND_UPGRADE_INFO => {
            let response = process_vendor_upgrade_info(env)?;
            Ok(Some(encode_cbor(response.into())))
        }
        _ => Ok(None),
    }
}

fn encode_cbor(value: cbor::Value) -> Vec<u8> {
    let mut response_vec = vec![Ctap2StatusCode::CTAP2_OK as u8];
    if cbor_write(value, &mut response_vec).is_err() {
        vec![Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR as u8]
    } else {
        response_vec
    }
}

fn process_vendor_configure<
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
>(
    env: &mut TockEnv<S, C>,
    params: VendorConfigureParameters,
    // Unused in std only
    _channel: Channel,
) -> Result<VendorConfigureResponse, Ctap2StatusCode> {
    if params.attestation_material.is_some() || params.lockdown {
        // This is removed in std so we don't need too many mocks in TockEnv.
        #[cfg(not(feature = "std"))]
        check_user_presence(env, _channel)?;
    }
    // This command is for U2F support and we use the batch attestation there.
    let attestation_id = attestation_store::Id::Batch;

    // Sanity checks
    let current_attestation = env.attestation_store().get(&attestation_id)?;
    let response = match params.attestation_material {
        None => VendorConfigureResponse {
            cert_programmed: current_attestation.is_some(),
            pkey_programmed: current_attestation.is_some(),
        },
        Some(data) => {
            // We don't overwrite the attestation if it's already set. We don't return any error
            // to not leak information.
            if current_attestation.is_none() {
                let attestation = Attestation {
                    private_key: Secret::from_exposed_secret(data.private_key),
                    certificate: data.certificate,
                };
                env.attestation_store()
                    .set(&attestation_id, Some(&attestation))?;
            }
            VendorConfigureResponse {
                cert_programmed: true,
                pkey_programmed: true,
            }
        }
    };
    if params.lockdown {
        // To avoid bricking the authenticator, we only allow lockdown
        // to happen if both values are programmed or if both U2F/CTAP1 and
        // batch attestation are disabled.
        #[cfg(feature = "with_ctap1")]
        let need_certificate = true;
        #[cfg(not(feature = "with_ctap1"))]
        let need_certificate = env.customization().use_batch_attestation();

        if (need_certificate && !(response.pkey_programmed && response.cert_programmed))
            || !env.lock_firmware_protection()
        {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
    }
    Ok(response)
}

fn process_vendor_upgrade<
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
>(
    env: &mut TockEnv<S, C>,
    params: VendorUpgradeParameters,
) -> Result<(), Ctap2StatusCode> {
    let VendorUpgradeParameters { offset, data, hash } = params;
    let calculated_hash = Sha::<TockEnv<S>>::digest(&data);
    if hash != calculated_hash {
        return Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE);
    }
    env.upgrade_storage()
        .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND)?
        .write_bundle(offset, data)
        .map_err(|_| Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
}

fn process_vendor_upgrade_info<
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
>(
    env: &mut TockEnv<S, C>,
) -> Result<VendorUpgradeInfoResponse, Ctap2StatusCode> {
    let upgrade_locations = env
        .upgrade_storage()
        .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND)?;
    Ok(VendorUpgradeInfoResponse {
        info: upgrade_locations.bundle_identifier(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationMaterial {
    pub certificate: Vec<u8>,
    pub private_key: [u8; EC_FIELD_SIZE],
}

impl TryFrom<cbor::Value> for AttestationMaterial {
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
        if private_key.len() != EC_FIELD_SIZE {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        let private_key = array_ref!(private_key, 0, EC_FIELD_SIZE);
        Ok(AttestationMaterial {
            certificate,
            private_key: *private_key,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct VendorConfigureParameters {
    pub lockdown: bool,
    pub attestation_material: Option<AttestationMaterial>,
}

impl TryFrom<cbor::Value> for VendorConfigureParameters {
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
            .map(AttestationMaterial::try_from)
            .transpose()?;
        Ok(VendorConfigureParameters {
            lockdown,
            attestation_material,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct VendorUpgradeParameters {
    pub offset: usize,
    pub data: Vec<u8>,
    pub hash: [u8; 32],
}

impl TryFrom<cbor::Value> for VendorUpgradeParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                0x01 => offset,
                0x02 => data,
                0x03 => hash,
            } = extract_map(cbor_value)?;
        }
        let offset = extract_unsigned(ok_or_missing(offset)?)? as usize;
        let data = extract_byte_string(ok_or_missing(data)?)?;
        let hash = <[u8; 32]>::try_from(extract_byte_string(ok_or_missing(hash)?)?)
            .map_err(|_| Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
        Ok(VendorUpgradeParameters { offset, data, hash })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct VendorConfigureResponse {
    pub cert_programmed: bool,
    pub pkey_programmed: bool,
}

impl From<VendorConfigureResponse> for cbor::Value {
    fn from(vendor_response: VendorConfigureResponse) -> Self {
        let VendorConfigureResponse {
            cert_programmed,
            pkey_programmed,
        } = vendor_response;

        cbor_map_options! {
            0x01 => cert_programmed,
            0x02 => pkey_programmed,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct VendorUpgradeInfoResponse {
    pub info: u32,
}

impl From<VendorUpgradeInfoResponse> for cbor::Value {
    fn from(vendor_upgrade_info_response: VendorUpgradeInfoResponse) -> Self {
        let VendorUpgradeInfoResponse { info } = vendor_upgrade_info_response;

        cbor_map_options! {
            0x01 => info as u64,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cbor::cbor_map;
    use libtock_unittest::fake::Syscalls;

    const DUMMY_CHANNEL: Channel = Channel::MainHid([0x12, 0x34, 0x56, 0x78]);
    #[cfg(feature = "vendor_hid")]
    const VENDOR_CHANNEL: Channel = Channel::VendorHid([0x12, 0x34, 0x56, 0x78]);

    #[test]
    fn test_process_cbor_unrelated_input() {
        let mut env = TockEnv::<Syscalls>::default();
        let cbor_bytes = vec![0x01];
        assert_eq!(process_cbor(&mut env, &cbor_bytes, DUMMY_CHANNEL), Ok(None));
    }

    #[test]
    fn test_process_cbor_invalid_input() {
        let mut env = TockEnv::<Syscalls>::default();
        let cbor_bytes = vec![VENDOR_COMMAND_CONFIGURE];
        assert_eq!(
            process_cbor(&mut env, &cbor_bytes, DUMMY_CHANNEL),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
        );
    }

    #[test]
    fn test_process_cbor_valid_input() {
        let mut env = TockEnv::<Syscalls>::default();
        let cbor_bytes = vec![VENDOR_COMMAND_UPGRADE_INFO];
        assert!(process_cbor(&mut env, &cbor_bytes, DUMMY_CHANNEL)
            .unwrap()
            .is_some());
    }

    #[test]
    #[cfg(feature = "vendor_hid")]
    fn test_process_command_valid_vendor_hid() {
        let mut env = TockEnv::<Syscalls>::default();
        let cbor_bytes = vec![VENDOR_COMMAND_UPGRADE_INFO];
        assert!(process_cbor(&mut env, &cbor_bytes, VENDOR_CHANNEL)
            .unwrap()
            .is_some());
        assert!(process_vendor_command(&mut env, &cbor_bytes, VENDOR_CHANNEL).is_some());
    }

    #[test]
    fn test_vendor_configure_parameters() {
        let dummy_cert = [0xddu8; 20];
        let dummy_pkey = [0x41u8; EC_FIELD_SIZE];

        // Attestation key is too short.
        let cbor_value = cbor_map! {
            0x01 => false,
            0x02 => cbor_map! {
                0x01 => dummy_cert,
                0x02 => dummy_pkey[..EC_FIELD_SIZE - 1]
            }
        };
        assert_eq!(
            VendorConfigureParameters::try_from(cbor_value),
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
            VendorConfigureParameters::try_from(cbor_value),
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
            VendorConfigureParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
        );

        // Valid
        let cbor_value = cbor_map! {
            0x01 => false,
            0x02 => cbor_map! {
                0x01 => dummy_cert,
                0x02 => dummy_pkey
            },
        };
        assert_eq!(
            VendorConfigureParameters::try_from(cbor_value),
            Ok(VendorConfigureParameters {
                lockdown: false,
                attestation_material: Some(AttestationMaterial {
                    certificate: dummy_cert.to_vec(),
                    private_key: dummy_pkey
                }),
            })
        );
    }

    #[test]
    fn test_vendor_upgrade_parameters() {
        // Missing offset
        let cbor_value = cbor_map! {
            0x02 => [0xFF; 0x100],
            0x03 => [0x44; 32],
        };
        assert_eq!(
            VendorUpgradeParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
        );

        // Missing data
        let cbor_value = cbor_map! {
            0x01 => 0x1000,
            0x03 => [0x44; 32],
        };
        assert_eq!(
            VendorUpgradeParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
        );

        // Invalid hash size
        let cbor_value = cbor_map! {
            0x01 => 0x1000,
            0x02 => [0xFF; 0x100],
            0x03 => [0x44; 33],
        };
        assert_eq!(
            VendorUpgradeParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        // Missing hash
        let cbor_value = cbor_map! {
            0x01 => 0x1000,
            0x02 => [0xFF; 0x100],
        };
        assert_eq!(
            VendorUpgradeParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
        );

        // Valid
        let cbor_value = cbor_map! {
            0x01 => 0x1000,
            0x02 => [0xFF; 0x100],
            0x03 => [0x44; 32],
        };
        assert_eq!(
            VendorUpgradeParameters::try_from(cbor_value),
            Ok(VendorUpgradeParameters {
                offset: 0x1000,
                data: vec![0xFF; 0x100],
                hash: [0x44; 32],
            })
        );
    }

    #[test]
    fn test_deserialize_vendor_upgrade_info() {
        let mut env = TockEnv::<Syscalls>::default();
        let cbor_bytes = [VENDOR_COMMAND_UPGRADE_INFO];
        assert!(process_cbor(&mut env, &cbor_bytes, DUMMY_CHANNEL)
            .unwrap()
            .is_some());
    }

    #[test]
    fn test_vendor_configure() {
        let mut env = TockEnv::<Syscalls>::default();

        // Nothing should be configured at the beginning
        let response = process_vendor_configure(
            &mut env,
            VendorConfigureParameters {
                lockdown: false,
                attestation_material: None,
            },
            DUMMY_CHANNEL,
        );
        assert_eq!(
            response,
            Ok(VendorConfigureResponse {
                cert_programmed: false,
                pkey_programmed: false,
            })
        );

        // Inject dummy values
        let dummy_key = [0x41u8; EC_FIELD_SIZE];
        let dummy_cert = [0xddu8; 20];
        let response = process_vendor_configure(
            &mut env,
            VendorConfigureParameters {
                lockdown: false,
                attestation_material: Some(AttestationMaterial {
                    certificate: dummy_cert.to_vec(),
                    private_key: dummy_key,
                }),
            },
            DUMMY_CHANNEL,
        );
        assert_eq!(
            response,
            Ok(VendorConfigureResponse {
                cert_programmed: true,
                pkey_programmed: true,
            })
        );
        assert_eq!(
            env.attestation_store().get(&attestation_store::Id::Batch),
            Ok(Some(Attestation {
                private_key: Secret::from_exposed_secret(dummy_key),
                certificate: dummy_cert.to_vec(),
            }))
        );

        // Try to inject other dummy values and check that initial values are retained.
        let other_dummy_key = [0x44u8; EC_FIELD_SIZE];
        let response = process_vendor_configure(
            &mut env,
            VendorConfigureParameters {
                lockdown: false,
                attestation_material: Some(AttestationMaterial {
                    certificate: dummy_cert.to_vec(),
                    private_key: other_dummy_key,
                }),
            },
            DUMMY_CHANNEL,
        );
        assert_eq!(
            response,
            Ok(VendorConfigureResponse {
                cert_programmed: true,
                pkey_programmed: true,
            })
        );
        assert_eq!(
            env.attestation_store().get(&attestation_store::Id::Batch),
            Ok(Some(Attestation {
                private_key: Secret::from_exposed_secret(dummy_key),
                certificate: dummy_cert.to_vec(),
            }))
        );

        // Now try to lock the device, but that is currently not supported.
        let response = process_vendor_configure(
            &mut env,
            VendorConfigureParameters {
                lockdown: true,
                attestation_material: None,
            },
            DUMMY_CHANNEL,
        );
        assert_eq!(
            response,
            Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
        );
    }

    #[test]
    fn test_vendor_upgrade() {
        // The test partition storage has size 0x40000.
        // The test metadata storage has size 0x1000.
        // The test identifier matches partition B.
        let mut env = TockEnv::<Syscalls>::default();

        const METADATA_LEN: usize = 0x1000;
        let metadata = vec![0xFF; METADATA_LEN];
        let metadata_hash = Sha::<TockEnv<Syscalls>>::digest(&metadata);
        let data = vec![0xFF; 0x1000];
        let hash = Sha::<TockEnv<Syscalls>>::digest(&data);

        // Write to partition.
        let response = process_vendor_upgrade(
            &mut env,
            VendorUpgradeParameters {
                offset: 0x20000,
                data: data.clone(),
                hash,
            },
        );
        assert_eq!(response, Ok(()));

        // TockEnv doesn't check the metadata, test its parser in your Env.
        let response = process_vendor_upgrade(
            &mut env,
            VendorUpgradeParameters {
                offset: 0,
                data: metadata.clone(),
                hash: metadata_hash,
            },
        );
        assert_eq!(response, Ok(()));

        // TockEnv doesn't check the metadata, test its parser in your Env.
        let response = process_vendor_upgrade(
            &mut env,
            VendorUpgradeParameters {
                offset: METADATA_LEN,
                data: data.clone(),
                hash,
            },
        );
        assert_eq!(response, Ok(()));

        // Write metadata of a wrong size.
        let response = process_vendor_upgrade(
            &mut env,
            VendorUpgradeParameters {
                offset: 0,
                data: metadata[..METADATA_LEN - 1].to_vec(),
                hash: metadata_hash,
            },
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE));

        // Write outside of the partition.
        let response = process_vendor_upgrade(
            &mut env,
            VendorUpgradeParameters {
                offset: 0x41000,
                data: data.clone(),
                hash,
            },
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER));

        // Write a bad hash.
        let response = process_vendor_upgrade(
            &mut env,
            VendorUpgradeParameters {
                offset: 0x20000,
                data,
                hash: [0xEE; 32],
            },
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE));
    }

    #[test]
    fn test_vendor_upgrade_no_second_partition() {
        let mut env = TockEnv::<Syscalls>::default();
        env.disable_upgrade_storage();

        let data = vec![0xFF; 0x1000];
        let hash = Sha::<TockEnv<Syscalls>>::digest(&data);
        let response = process_vendor_upgrade(
            &mut env,
            VendorUpgradeParameters {
                offset: 0,
                data,
                hash,
            },
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND));
    }

    #[test]
    fn test_vendor_upgrade_info() {
        let mut env = TockEnv::<Syscalls>::default();
        let bundle_identifier = env.upgrade_storage().unwrap().bundle_identifier();

        let upgrade_info_reponse = process_vendor_upgrade_info(&mut env);
        assert_eq!(
            upgrade_info_reponse,
            Ok(VendorUpgradeInfoResponse {
                info: bundle_identifier,
            })
        );
    }

    #[test]
    fn test_vendor_response_into_cbor() {
        let response_cbor: cbor::Value = VendorConfigureResponse {
            cert_programmed: true,
            pkey_programmed: false,
        }
        .into();
        assert_eq!(
            response_cbor,
            cbor_map_options! {
                0x01 => true,
                0x02 => false,
            }
        );
        let response_cbor: cbor::Value = VendorConfigureResponse {
            cert_programmed: false,
            pkey_programmed: true,
        }
        .into();
        assert_eq!(
            response_cbor,
            cbor_map_options! {
                0x01 => false,
                0x02 => true,
            }
        );
    }

    #[test]
    fn test_vendor_upgrade_info_into_cbor() {
        let vendor_upgrade_info_response = VendorUpgradeInfoResponse { info: 0x00060000 };
        let response_cbor: cbor::Value = vendor_upgrade_info_response.into();
        let expected_cbor = cbor_map! {
            0x01 => 0x00060000,
        };
        assert_eq!(response_cbor, expected_cbor);
    }
}
