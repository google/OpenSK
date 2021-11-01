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

use super::apdu::{Apdu, ApduStatusCode};
use super::hid::ChannelID;
use super::status_code::Ctap2StatusCode;
use super::CtapState;
use alloc::vec::Vec;
use arrayref::array_ref;
use core::convert::Into;
use core::convert::TryFrom;
use crypto::rng256::Rng256;
use libtock_drivers::timer::ClockValue;

// For now, they're the same thing with apdu.rs containing the authoritative definition
pub type Ctap1StatusCode = ApduStatusCode;

// The specification referenced in this file is at:
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.pdf

#[cfg_attr(any(test, feature = "debug_ctap"), derive(Clone, Debug))]
#[derive(PartialEq)]
pub enum Ctap1Flags {
    CheckOnly = 0x07,
    EnforceUpAndSign = 0x03,
    DontEnforceUpAndSign = 0x08,
}

impl TryFrom<u8> for Ctap1Flags {
    type Error = Ctap1StatusCode;

    fn try_from(value: u8) -> Result<Ctap1Flags, Ctap1StatusCode> {
        match value {
            0x07 => Ok(Ctap1Flags::CheckOnly),
            0x03 => Ok(Ctap1Flags::EnforceUpAndSign),
            0x08 => Ok(Ctap1Flags::DontEnforceUpAndSign),
            _ => Err(Ctap1StatusCode::SW_WRONG_DATA),
        }
    }
}

impl Into<u8> for Ctap1Flags {
    fn into(self) -> u8 {
        self as u8
    }
}

#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
// TODO: remove #allow when https://github.com/rust-lang/rust/issues/64362 is fixed
enum U2fCommand {
    #[allow(dead_code)]
    Register {
        challenge: [u8; 32],
        application: [u8; 32],
    },
    #[allow(dead_code)]
    Authenticate {
        challenge: [u8; 32],
        application: [u8; 32],
        key_handle: Vec<u8>,
        flags: Ctap1Flags,
    },
    Version,
    #[allow(dead_code)]
    VendorSpecific {
        payload: Vec<u8>,
    },
}

impl TryFrom<&[u8]> for U2fCommand {
    type Error = Ctap1StatusCode;

    fn try_from(message: &[u8]) -> Result<Self, Ctap1StatusCode> {
        let apdu: Apdu = match Apdu::try_from(message) {
            Ok(apdu) => apdu,
            Err(apdu_status_code) => {
                return Err(Ctap1StatusCode::try_from(apdu_status_code).unwrap())
            }
        };

        let lc = apdu.lc as usize;

        // ISO7816 Apdu Header format. Each cell is 1 byte. Note that the CTAP flavor always
        // encodes the length on 3 bytes and doesn't use the field "Le" (Length Expected).
        // We keep the 2 byte of "Le" for the packet length in mind, but always ignore its value.
        // Lc is using big-endian encoding
        // +-----+-----+----+----+-----+-----+-----+
        // | CLA | INS | P1 | P2 | Lc1 | Lc2 | Lc3 |
        // +-----+-----+----+----+-----+-----+-----+
        if apdu.header.cla != Ctap1Command::CTAP1_CLA {
            return Err(Ctap1StatusCode::SW_CLA_INVALID);
        }

        // Since there is always request data, the expected length is either omitted or
        // encoded in 2 bytes.
        if lc != apdu.data.len() && lc + 2 != apdu.data.len() {
            return Err(Ctap1StatusCode::SW_WRONG_LENGTH);
        }

        match apdu.header.ins {
            // U2F raw message format specification, Section 4.1
            // +-----------------+-------------------+
            // + Challenge (32B) | Application (32B) |
            // +-----------------+-------------------+
            Ctap1Command::U2F_REGISTER => {
                if lc != 64 {
                    return Err(Ctap1StatusCode::SW_WRONG_LENGTH);
                }
                Ok(Self::Register {
                    challenge: *array_ref!(apdu.data, 0, 32),
                    application: *array_ref!(apdu.data, 32, 32),
                })
            }

            // U2F raw message format specification, Section 5.1
            // +-----------------+-------------------+---------------------+------------+
            // + Challenge (32B) | Application (32B) | key handle len (1B) | key handle |
            // +-----------------+-------------------+---------------------+------------+
            Ctap1Command::U2F_AUTHENTICATE => {
                if lc < 65 {
                    return Err(Ctap1StatusCode::SW_WRONG_LENGTH);
                }
                let handle_length = apdu.data[64] as usize;
                if lc != 65 + handle_length {
                    return Err(Ctap1StatusCode::SW_WRONG_LENGTH);
                }
                let flag = Ctap1Flags::try_from(apdu.header.p1)?;
                Ok(Self::Authenticate {
                    challenge: *array_ref!(apdu.data, 0, 32),
                    application: *array_ref!(apdu.data, 32, 32),
                    key_handle: apdu.data[65..].to_vec(),
                    flags: flag,
                })
            }

            // U2F raw message format specification, Section 6.1
            Ctap1Command::U2F_VERSION => {
                if lc != 0 {
                    return Err(Ctap1StatusCode::SW_WRONG_LENGTH);
                }
                Ok(Self::Version)
            }

            // For Vendor specific command.
            Ctap1Command::VENDOR_SPECIFIC_FIRST..=Ctap1Command::VENDOR_SPECIFIC_LAST => {
                Ok(Self::VendorSpecific {
                    payload: apdu.data.to_vec(),
                })
            }

            _ => Err(Ctap1StatusCode::SW_INS_INVALID),
        }
    }
}

pub struct Ctap1Command {}

impl Ctap1Command {
    const CTAP1_CLA: u8 = 0;
    // This byte is used in Register, but only serves backwards compatibility.
    const LEGACY_BYTE: u8 = 0x05;
    // This byte is hardcoded into the specification of Authenticate.
    const USER_PRESENCE_INDICATOR_BYTE: u8 = 0x01;

    // CTAP1/U2F commands
    // U2F raw message format specification 1.2 (version 20170411)
    const U2F_REGISTER: u8 = 0x01;
    const U2F_AUTHENTICATE: u8 = 0x02;
    const U2F_VERSION: u8 = 0x03;
    const VENDOR_SPECIFIC_FIRST: u8 = 0x40;
    const VENDOR_SPECIFIC_LAST: u8 = 0xBF;

    pub fn process_command<R, CheckUserPresence>(
        message: &[u8],
        ctap_state: &mut CtapState<R, CheckUserPresence>,
        clock_value: ClockValue,
    ) -> Result<Vec<u8>, Ctap1StatusCode>
    where
        R: Rng256,
        CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>,
    {
        let command = U2fCommand::try_from(message)?;
        match command {
            U2fCommand::Register {
                challenge,
                application,
            } => {
                if !ctap_state.u2f_up_state.consume_up(clock_value) {
                    return Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED);
                }
                Ctap1Command::process_register(challenge, application, ctap_state)
            }

            U2fCommand::Authenticate {
                challenge,
                application,
                key_handle,
                flags,
            } => {
                // The order is important due to side effects of checking user presence.
                if flags == Ctap1Flags::EnforceUpAndSign
                    && !ctap_state.u2f_up_state.consume_up(clock_value)
                {
                    return Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED);
                }
                Ctap1Command::process_authenticate(
                    challenge,
                    application,
                    key_handle,
                    flags,
                    ctap_state,
                )
            }

            // U2F raw message format specification (version 20170411) section 6.3
            U2fCommand::Version => Ok(Vec::<u8>::from(super::U2F_VERSION_STRING)),

            // TODO: should we return an error instead such as SW_INS_NOT_SUPPORTED?
            U2fCommand::VendorSpecific { .. } => Err(Ctap1StatusCode::SW_SUCCESS),
        }
    }

    // U2F raw message format specification (version 20170411) section 4.3
    // In case of success we need to send back the following reply
    // (excluding ISO7816 success code)
    // +------+--------------------+---------------------+------------+------------+------+
    // + 0x05 | User pub key (65B) | key handle len (1B) | key handle | X.509 Cert | Sign |
    // +------+--------------------+---------------------+------------+------------+------+
    //
    // Where Sign is an ECDSA signature over the following structure:
    // +------+-------------------+-----------------+------------+--------------------+
    // + 0x00 | application (32B) | challenge (32B) | key handle | User pub key (65B) |
    // +------+-------------------+-----------------+------------+--------------------+
    fn process_register<R, CheckUserPresence>(
        challenge: [u8; 32],
        application: [u8; 32],
        ctap_state: &mut CtapState<R, CheckUserPresence>,
    ) -> Result<Vec<u8>, Ctap1StatusCode>
    where
        R: Rng256,
        CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>,
    {
        let sk = crypto::ecdsa::SecKey::gensk(ctap_state.rng);
        let pk = sk.genpk();
        let key_handle = ctap_state
            .encrypt_key_handle(sk, &application)
            .map_err(|_| Ctap1StatusCode::SW_INTERNAL_EXCEPTION)?;
        if key_handle.len() > 0xFF {
            // This is just being defensive with unreachable code.
            return Err(Ctap1StatusCode::SW_INTERNAL_EXCEPTION);
        }

        let certificate = ctap_state
            .persistent_store
            .attestation_certificate()
            .map_err(|_| Ctap1StatusCode::SW_MEMERR)?
            .ok_or(Ctap1StatusCode::SW_INTERNAL_EXCEPTION)?;
        let private_key = ctap_state
            .persistent_store
            .attestation_private_key()
            .map_err(|_| Ctap1StatusCode::SW_INTERNAL_EXCEPTION)?
            .ok_or(Ctap1StatusCode::SW_INTERNAL_EXCEPTION)?;

        let mut response = Vec::with_capacity(105 + key_handle.len() + certificate.len());
        response.push(Ctap1Command::LEGACY_BYTE);
        let user_pk = pk.to_uncompressed();
        response.extend_from_slice(&user_pk);
        response.push(key_handle.len() as u8);
        response.extend(key_handle.clone());
        response.extend_from_slice(&certificate);

        // The first byte is reserved.
        let mut signature_data = Vec::with_capacity(66 + key_handle.len());
        signature_data.push(0x00);
        signature_data.extend(&application);
        signature_data.extend(&challenge);
        signature_data.extend(key_handle);
        signature_data.extend_from_slice(&user_pk);

        let attestation_key = crypto::ecdsa::SecKey::from_bytes(&private_key).unwrap();
        let signature = attestation_key.sign_rfc6979::<crypto::sha256::Sha256>(&signature_data);

        response.extend(signature.to_asn1_der());
        Ok(response)
    }

    // U2F raw message format specification (version 20170411) section 5.4
    // In case of success we need to send back the following reply
    // (excluding ISO7816 success code)
    // +---------+--------------+-----------+
    // + UP (1B) | Counter (4B) | Signature |
    // +---------+--------------+-----------+
    // UP only has 2 defined values:
    //  - 0x00: user presence was not verified
    //  - 0x01: user presence was verified
    //
    // Where Signature is an ECDSA signature over the following structure:
    // +-------------------+---------+--------------+-----------------+
    // + application (32B) | UP (1B) | Counter (4B) | challenge (32B) |
    // +-------------------+---------+--------------+-----------------+
    fn process_authenticate<R, CheckUserPresence>(
        challenge: [u8; 32],
        application: [u8; 32],
        key_handle: Vec<u8>,
        flags: Ctap1Flags,
        ctap_state: &mut CtapState<R, CheckUserPresence>,
    ) -> Result<Vec<u8>, Ctap1StatusCode>
    where
        R: Rng256,
        CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>,
    {
        let credential_source = ctap_state
            .decrypt_credential_source(key_handle, &application)
            .map_err(|_| Ctap1StatusCode::SW_WRONG_DATA)?;
        if let Some(credential_source) = credential_source {
            if flags == Ctap1Flags::CheckOnly {
                return Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED);
            }
            ctap_state
                .increment_global_signature_counter()
                .map_err(|_| Ctap1StatusCode::SW_WRONG_DATA)?;
            let mut signature_data = ctap_state
                .generate_auth_data(&application, Ctap1Command::USER_PRESENCE_INDICATOR_BYTE)
                .map_err(|_| Ctap1StatusCode::SW_WRONG_DATA)?;
            signature_data.extend(&challenge);
            let signature = credential_source
                .private_key
                .sign_rfc6979::<crypto::sha256::Sha256>(&signature_data);

            let mut response = signature_data[application.len()..application.len() + 5].to_vec();
            response.extend(signature.to_asn1_der());
            Ok(response)
        } else {
            Err(Ctap1StatusCode::SW_WRONG_DATA)
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::{key_material, CREDENTIAL_ID_SIZE, USE_SIGNATURE_COUNTER};
    use super::*;
    use crypto::rng256::ThreadRng256;
    use crypto::Hash256;

    const CLOCK_FREQUENCY_HZ: usize = 32768;
    const START_CLOCK_VALUE: ClockValue = ClockValue::new(0, CLOCK_FREQUENCY_HZ);
    const TIMEOUT_CLOCK_VALUE: ClockValue = ClockValue::new(
        (30001 * CLOCK_FREQUENCY_HZ as isize) / 1000,
        CLOCK_FREQUENCY_HZ,
    );

    fn create_register_message(application: &[u8; 32]) -> Vec<u8> {
        let mut message = vec![
            Ctap1Command::CTAP1_CLA,
            Ctap1Command::U2F_REGISTER,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
        ];
        let challenge = [0x0C; 32];
        message.extend(&challenge);
        message.extend(application);
        message
    }

    fn create_authenticate_message(
        application: &[u8; 32],
        flags: Ctap1Flags,
        key_handle: &Vec<u8>,
    ) -> Vec<u8> {
        let mut message = vec![
            Ctap1Command::CTAP1_CLA,
            Ctap1Command::U2F_AUTHENTICATE,
            flags.into(),
            0x00,
            0x00,
            0x00,
            65 + CREDENTIAL_ID_SIZE as u8,
        ];
        let challenge = [0x0C; 32];
        message.extend(&challenge);
        message.extend(application);
        message.push(CREDENTIAL_ID_SIZE as u8);
        message.extend(key_handle);
        message
    }

    #[test]
    fn test_process_register() {
        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        let application = [0x0A; 32];
        let message = create_register_message(&application);
        ctap_state.u2f_up_state.consume_up(START_CLOCK_VALUE);
        ctap_state.u2f_up_state.grant_up(START_CLOCK_VALUE);
        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        // Certificate and private key are missing
        assert_eq!(response, Err(Ctap1StatusCode::SW_INTERNAL_EXCEPTION));

        let fake_key = [0x41u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH];
        assert!(ctap_state
            .persistent_store
            .set_attestation_private_key(&fake_key)
            .is_ok());
        ctap_state.u2f_up_state.consume_up(START_CLOCK_VALUE);
        ctap_state.u2f_up_state.grant_up(START_CLOCK_VALUE);
        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        // Certificate is still missing
        assert_eq!(response, Err(Ctap1StatusCode::SW_INTERNAL_EXCEPTION));

        let fake_cert = [0x99u8; 100]; // Arbitrary length
        assert!(ctap_state
            .persistent_store
            .set_attestation_certificate(&fake_cert[..])
            .is_ok());
        ctap_state.u2f_up_state.consume_up(START_CLOCK_VALUE);
        ctap_state.u2f_up_state.grant_up(START_CLOCK_VALUE);
        let response =
            Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE).unwrap();
        assert_eq!(response[0], Ctap1Command::LEGACY_BYTE);
        assert_eq!(response[66], CREDENTIAL_ID_SIZE as u8);
        assert!(ctap_state
            .decrypt_credential_source(response[67..67 + CREDENTIAL_ID_SIZE].to_vec(), &application)
            .unwrap()
            .is_some());
        const CERT_START: usize = 67 + CREDENTIAL_ID_SIZE;
        assert_eq!(
            &response[CERT_START..CERT_START + fake_cert.len()],
            &fake_cert[..]
        );
    }

    #[test]
    fn test_process_register_bad_message() {
        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        let application = [0x0A; 32];
        let message = create_register_message(&application);
        let response = Ctap1Command::process_command(
            &message[..message.len() - 1],
            &mut ctap_state,
            START_CLOCK_VALUE,
        );

        assert_eq!(response, Err(Ctap1StatusCode::SW_WRONG_LENGTH));
    }

    #[test]
    fn test_process_register_without_up() {
        let application = [0x0A; 32];
        let message = create_register_message(&application);

        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        ctap_state.u2f_up_state.consume_up(START_CLOCK_VALUE);
        ctap_state.u2f_up_state.grant_up(START_CLOCK_VALUE);
        let response =
            Ctap1Command::process_command(&message, &mut ctap_state, TIMEOUT_CLOCK_VALUE);
        assert_eq!(response, Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED));
    }

    #[test]
    fn test_process_authenticate_check_only() {
        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let sk = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = ctap_state.encrypt_key_handle(sk, &application).unwrap();
        let message = create_authenticate_message(&application, Ctap1Flags::CheckOnly, &key_handle);

        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        assert_eq!(response, Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED));
    }

    #[test]
    fn test_process_authenticate_check_only_wrong_rp() {
        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let sk = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = ctap_state.encrypt_key_handle(sk, &application).unwrap();
        let application = [0x55; 32];
        let message = create_authenticate_message(&application, Ctap1Flags::CheckOnly, &key_handle);

        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        assert_eq!(response, Err(Ctap1StatusCode::SW_WRONG_DATA));
    }

    #[test]
    fn test_process_authenticate_check_only_wrong_length() {
        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let sk = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = ctap_state.encrypt_key_handle(sk, &application).unwrap();
        let mut message = create_authenticate_message(
            &application,
            Ctap1Flags::DontEnforceUpAndSign,
            &key_handle,
        );

        message.push(0x00);
        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        assert!(response.is_ok());

        message.push(0x00);
        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        assert!(response.is_ok());

        message.push(0x00);
        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        assert!(response.is_ok());

        message.push(0x00);
        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        assert_eq!(response, Err(Ctap1StatusCode::SW_WRONG_LENGTH));
    }

    #[test]
    fn test_process_authenticate_check_only_wrong_cla() {
        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let sk = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = ctap_state.encrypt_key_handle(sk, &application).unwrap();
        let mut message =
            create_authenticate_message(&application, Ctap1Flags::CheckOnly, &key_handle);
        message[0] = 0xEE;

        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        assert_eq!(response, Err(Ctap1StatusCode::SW_CLA_INVALID));
    }

    #[test]
    fn test_process_authenticate_check_only_wrong_ins() {
        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let sk = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = ctap_state.encrypt_key_handle(sk, &application).unwrap();
        let mut message =
            create_authenticate_message(&application, Ctap1Flags::CheckOnly, &key_handle);
        message[1] = 0xEE;

        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        assert_eq!(response, Err(Ctap1StatusCode::SW_INS_INVALID));
    }

    #[test]
    fn test_process_authenticate_check_only_wrong_flags() {
        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let sk = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = ctap_state.encrypt_key_handle(sk, &application).unwrap();
        let mut message =
            create_authenticate_message(&application, Ctap1Flags::CheckOnly, &key_handle);
        message[2] = 0xEE;

        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        assert_eq!(response, Err(Ctap1StatusCode::SW_WRONG_DATA));
    }

    fn check_signature_counter(response: &[u8; 4], signature_counter: u32) {
        if USE_SIGNATURE_COUNTER {
            assert_eq!(u32::from_be_bytes(*response), signature_counter);
        } else {
            assert_eq!(response, &[0x00, 0x00, 0x00, 0x00]);
        }
    }

    #[test]
    fn test_process_authenticate_enforce() {
        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let sk = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = ctap_state.encrypt_key_handle(sk, &application).unwrap();
        let message =
            create_authenticate_message(&application, Ctap1Flags::EnforceUpAndSign, &key_handle);

        ctap_state.u2f_up_state.consume_up(START_CLOCK_VALUE);
        ctap_state.u2f_up_state.grant_up(START_CLOCK_VALUE);
        let response =
            Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE).unwrap();
        assert_eq!(response[0], 0x01);
        check_signature_counter(
            array_ref!(response, 1, 4),
            ctap_state
                .persistent_store
                .global_signature_counter()
                .unwrap(),
        );
    }

    #[test]
    fn test_process_authenticate_dont_enforce() {
        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let sk = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = ctap_state.encrypt_key_handle(sk, &application).unwrap();
        let message = create_authenticate_message(
            &application,
            Ctap1Flags::DontEnforceUpAndSign,
            &key_handle,
        );

        let response =
            Ctap1Command::process_command(&message, &mut ctap_state, TIMEOUT_CLOCK_VALUE).unwrap();
        assert_eq!(response[0], 0x01);
        check_signature_counter(
            array_ref!(response, 1, 4),
            ctap_state
                .persistent_store
                .global_signature_counter()
                .unwrap(),
        );
    }

    #[test]
    fn test_process_authenticate_bad_key_handle() {
        let application = [0x0A; 32];
        let key_handle = vec![0x00; CREDENTIAL_ID_SIZE];
        let message =
            create_authenticate_message(&application, Ctap1Flags::EnforceUpAndSign, &key_handle);

        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        ctap_state.u2f_up_state.consume_up(START_CLOCK_VALUE);
        ctap_state.u2f_up_state.grant_up(START_CLOCK_VALUE);
        let response = Ctap1Command::process_command(&message, &mut ctap_state, START_CLOCK_VALUE);
        assert_eq!(response, Err(Ctap1StatusCode::SW_WRONG_DATA));
    }

    #[test]
    fn test_process_authenticate_without_up() {
        let application = [0x0A; 32];
        let key_handle = vec![0x00; CREDENTIAL_ID_SIZE];
        let message =
            create_authenticate_message(&application, Ctap1Flags::EnforceUpAndSign, &key_handle);

        let mut rng = ThreadRng256 {};
        let dummy_user_presence = |_| panic!("Unexpected user presence check in CTAP1");
        let mut ctap_state = CtapState::new(&mut rng, dummy_user_presence, START_CLOCK_VALUE);

        ctap_state.u2f_up_state.consume_up(START_CLOCK_VALUE);
        ctap_state.u2f_up_state.grant_up(START_CLOCK_VALUE);
        let response =
            Ctap1Command::process_command(&message, &mut ctap_state, TIMEOUT_CLOCK_VALUE);
        assert_eq!(response, Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED));
    }
}
