// Copyright 2020 Google LLC
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

use arbitrary::{Arbitrary, Unstructured};
use arrayref::array_ref;
use core::convert::TryFrom;
use opensk::api::customization::is_valid;
use opensk::ctap::command::{
    AuthenticatorClientPinParameters, AuthenticatorGetAssertionParameters,
    AuthenticatorMakeCredentialParameters, Command,
};
use opensk::ctap::data_formats::EnterpriseAttestationMode;
use opensk::ctap::hid::{
    ChannelID, CtapHidCommand, HidPacket, HidPacketIterator, Message, MessageAssembler,
};
use opensk::ctap::{cbor_read, Channel, CtapState};
use opensk::env::test::customization::TestCustomization;
use opensk::env::test::TestEnv;
use opensk::{test_helpers, Ctap, Transport};

const CHANNEL_BROADCAST: ChannelID = [0xFF, 0xFF, 0xFF, 0xFF];

#[derive(Clone, Copy, PartialEq)]
pub enum InputType {
    CborMakeCredentialParameter,
    CborGetAssertionParameter,
    CborClientPinParameter,
    Ctap1,
}

pub enum FuzzError {
    ArbitraryError(arbitrary::Error),
    InvalidCustomization,
}

pub type FuzzResult<T> = Result<T, FuzzError>;

impl From<arbitrary::Error> for FuzzError {
    fn from(err: arbitrary::Error) -> Self {
        Self::ArbitraryError(err)
    }
}

// Converts a byte slice into Message
fn raw_to_message(data: &[u8]) -> Message {
    if data.len() <= 4 {
        let mut cid = [0; 4];
        cid[..data.len()].copy_from_slice(data);
        Message {
            cid,
            // Arbitrary command.
            cmd: CtapHidCommand::Cbor,
            payload: vec![],
        }
    } else {
        Message {
            cid: array_ref!(data, 0, 4).clone(),
            cmd: CtapHidCommand::from(data[4]),
            payload: data[5..].to_vec(),
        }
    }
}

// Returns an initialized ctap state, hid and the allocated cid
// after processing the init command.
fn initialize(ctap: &mut Ctap<TestEnv>) -> ChannelID {
    let nonce = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let message = Message {
        cid: CHANNEL_BROADCAST,
        cmd: CtapHidCommand::Init,
        payload: nonce,
    };
    let mut assembler_reply = MessageAssembler::default();
    let mut result_cid: ChannelID = Default::default();
    for pkt_request in HidPacketIterator::new(message).unwrap() {
        for pkt_reply in ctap.process_hid_packet(&pkt_request, Transport::MainHid) {
            if let Ok(Some(result)) = assembler_reply.parse_packet(ctap.env(), &pkt_reply, None) {
                result_cid.copy_from_slice(&result.payload[8..12]);
            }
        }
    }
    result_cid
}

// Checks whether the given data can be interpreted as the given type.
fn is_type(data: &[u8], input_type: InputType) -> bool {
    if input_type == InputType::Ctap1 {
        return true;
    }
    match cbor_read(data) {
        Err(_) => false,
        Ok(decoded_cbor) => match input_type {
            InputType::CborMakeCredentialParameter => {
                AuthenticatorMakeCredentialParameters::try_from(decoded_cbor).is_ok()
            }
            InputType::CborGetAssertionParameter => {
                AuthenticatorGetAssertionParameters::try_from(decoded_cbor).is_ok()
            }
            InputType::CborClientPinParameter => {
                AuthenticatorClientPinParameters::try_from(decoded_cbor).is_ok()
            }
            _ => true,
        },
    }
}

// Interprets the raw data as a complete message (with channel id, command type and payload) and
// invokes message splitting, packet processing at CTAP HID level and response assembling.
fn process_message(data: &[u8], ctap: &mut Ctap<TestEnv>) {
    let message = raw_to_message(data);
    if let Some(hid_packet_iterator) = HidPacketIterator::new(message) {
        let mut assembler_reply = MessageAssembler::default();
        for pkt_request in hid_packet_iterator {
            for pkt_reply in ctap.process_hid_packet(&pkt_request, Transport::MainHid) {
                // Only checks for assembling crashes, not for semantics.
                let _ = assembler_reply.parse_packet(ctap.env(), &pkt_reply, None);
            }
        }
    }
}

// Interprets the raw data as any ctap command (including the command byte) and
// invokes message splitting, packet processing at CTAP HID level and response assembling
// using an initialized and allocated channel.
pub fn process_ctap_any_type(data: &[u8]) -> arbitrary::Result<()> {
    let mut unstructured = Unstructured::new(data);

    let mut env = TestEnv::default();
    env.seed_rng_from_u64(u64::arbitrary(&mut unstructured)?);

    let data = unstructured.take_rest();
    // Initialize ctap state and hid and get the allocated cid.
    let mut ctap = Ctap::new(env);
    let cid = initialize(&mut ctap);
    // Wrap input as message with the allocated cid.
    let mut command = cid.to_vec();
    command.extend(data);
    process_message(&command, &mut ctap);
    Ok(())
}

fn setup_customization(
    unstructured: &mut Unstructured,
    customization: &mut TestCustomization,
) -> FuzzResult<()> {
    customization.setup_enterprise_attestation(
        Option::<EnterpriseAttestationMode>::arbitrary(unstructured)?,
        // TODO: Generate arbitrary rp_id_list (but with some dummies because content doesn't
        // matter), and use the rp ids in commands.
        None,
    );
    if !is_valid(customization) {
        return Err(FuzzError::InvalidCustomization);
    }
    Ok(())
}

fn setup_state(
    unstructured: &mut Unstructured,
    state: &mut CtapState<TestEnv>,
    env: &mut TestEnv,
) -> FuzzResult<()> {
    if bool::arbitrary(unstructured)? {
        test_helpers::enable_enterprise_attestation(state, env).ok();
    }
    Ok(())
}

// Interprets the raw data as of the given input type and
// invokes message splitting, packet processing at CTAP HID level and response assembling
// using an initialized and allocated channel.
pub fn process_ctap_specific_type(data: &[u8], input_type: InputType) -> arbitrary::Result<()> {
    let mut unstructured = Unstructured::new(data);

    let mut env = TestEnv::default();
    env.seed_rng_from_u64(u64::arbitrary(&mut unstructured)?);

    let data = unstructured.take_rest();
    if !is_type(data, input_type) {
        return Ok(());
    }
    // Initialize ctap state and hid and get the allocated cid.
    let mut ctap = Ctap::new(env);
    let cid = initialize(&mut ctap);
    // Wrap input as message with allocated cid and command type.
    let mut command = cid.to_vec();
    match input_type {
        InputType::CborMakeCredentialParameter => {
            command.extend(&[0x10, 0x01]);
        }
        InputType::CborGetAssertionParameter => {
            command.extend(&[0x10, 0x02]);
        }
        InputType::CborClientPinParameter => {
            command.extend(&[0x10, 0x06]);
        }
        InputType::Ctap1 => {
            command.extend(&[0x03]);
        }
    }
    command.extend(data);
    process_message(&command, &mut ctap);
    Ok(())
}

pub fn process_ctap_structured(data: &[u8], input_type: InputType) -> FuzzResult<()> {
    let unstructured = &mut Unstructured::new(data);

    let mut env = TestEnv::default();
    env.seed_rng_from_u64(u64::arbitrary(unstructured)?);
    setup_customization(unstructured, env.customization_mut())?;

    let mut state = CtapState::new(&mut env);
    setup_state(unstructured, &mut state, &mut env)?;

    let command = match input_type {
        InputType::CborMakeCredentialParameter => Command::AuthenticatorMakeCredential(
            AuthenticatorMakeCredentialParameters::arbitrary(unstructured)?,
        ),
        InputType::CborGetAssertionParameter => Command::AuthenticatorGetAssertion(
            AuthenticatorGetAssertionParameters::arbitrary(unstructured)?,
        ),
        InputType::CborClientPinParameter => Command::AuthenticatorClientPin(
            AuthenticatorClientPinParameters::arbitrary(unstructured)?,
        ),
        InputType::Ctap1 => {
            unimplemented!()
        }
    };

    state
        .process_parsed_command(
            &mut env,
            command,
            Channel::MainHid(ChannelID::arbitrary(unstructured)?),
        )
        .ok();

    Ok(())
}

// Splits the given data as HID packets and reassembles it, verifying that the original input message is reconstructed.
pub fn split_assemble_hid_packets(data: &[u8]) -> arbitrary::Result<()> {
    let mut unstructured = Unstructured::new(data);

    let mut env = TestEnv::default();
    env.seed_rng_from_u64(u64::arbitrary(&mut unstructured)?);

    let data = unstructured.take_rest();
    let message = raw_to_message(data);
    if let Some(hid_packet_iterator) = HidPacketIterator::new(message.clone()) {
        let mut assembler = MessageAssembler::default();
        let packets: Vec<HidPacket> = hid_packet_iterator.collect();
        if let Some((last_packet, first_packets)) = packets.split_last() {
            for packet in first_packets {
                assert_eq!(assembler.parse_packet(&mut env, packet, None), Ok(None));
            }
            assert_eq!(
                assembler.parse_packet(&mut env, last_packet, None),
                Ok(Some(message))
            );
        }
    }
    Ok(())
}
