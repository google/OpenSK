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

pub mod apdu;
mod client_pin;
pub mod command;
mod config_command;
mod credential_id;
mod credential_management;
mod crypto_wrapper;
#[cfg(feature = "with_ctap1")]
mod ctap1;
pub mod data_formats;
pub mod hid;
pub mod key_material;
mod large_blobs;
pub mod main_hid;
mod pin_protocol;
pub mod response;
pub mod status_code;
mod storage;
mod timed_permission;
mod token_state;
#[cfg(feature = "vendor_hid")]
pub mod vendor_hid;

use self::client_pin::{ClientPin, PinPermission};
use self::command::{
    AuthenticatorGetAssertionParameters, AuthenticatorMakeCredentialParameters,
    AuthenticatorVendorConfigureParameters, AuthenticatorVendorUpgradeParameters, Command,
};
use self::config_command::process_config;
use self::credential_id::{
    decrypt_credential_id, encrypt_to_credential_id, MAX_CREDENTIAL_ID_SIZE,
};
use self::credential_management::process_credential_management;
use self::crypto_wrapper::PrivateKey;
use self::data_formats::{
    AuthenticatorTransport, CredentialProtectionPolicy, EnterpriseAttestationMode,
    GetAssertionExtensions, PackedAttestationStatement, PinUvAuthProtocol,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameter, PublicKeyCredentialSource,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, SignatureAlgorithm,
};
use self::hid::{ChannelID, CtapHid, CtapHidCommand, KeepaliveStatus, ProcessedPacket};
use self::large_blobs::LargeBlobs;
use self::response::{
    AuthenticatorGetAssertionResponse, AuthenticatorGetInfoResponse,
    AuthenticatorMakeCredentialResponse, AuthenticatorVendorConfigureResponse,
    AuthenticatorVendorUpgradeInfoResponse, ResponseData,
};
use self::status_code::Ctap2StatusCode;
use self::timed_permission::TimedPermission;
#[cfg(feature = "with_ctap1")]
use self::timed_permission::U2fUserPresenceState;
use crate::api::attestation_store::{self, Attestation, AttestationStore};
use crate::api::connection::{HidConnection, SendOrRecvStatus};
use crate::api::customization::Customization;
use crate::api::firmware_protection::FirmwareProtection;
use crate::api::upgrade_storage::UpgradeStorage;
use crate::api::user_presence::{UserPresence, UserPresenceError};
use crate::clock::{ClockInt, CtapInstant, KEEPALIVE_DELAY, KEEPALIVE_DELAY_MS};
use crate::env::Env;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::convert::TryFrom;
use crypto::hmac::hmac_256;
use crypto::sha256::Sha256;
use crypto::{ecdsa, Hash256};
use embedded_time::duration::Milliseconds;
use libtock_drivers::usb_ctap_hid::UsbEndpoint;
use rng256::Rng256;
use sk_cbor as cbor;
use sk_cbor::cbor_map_options;

pub const INITIAL_SIGNATURE_COUNTER: u32 = 1;
// Set this bit when checking user presence.
const UP_FLAG: u8 = 0x01;
// Set this bit when checking user verification.
const UV_FLAG: u8 = 0x04;
// Set this bit when performing attestation.
const AT_FLAG: u8 = 0x40;
// Set this bit when an extension is used.
const ED_FLAG: u8 = 0x80;

// CTAP2 specification section 6 requires that the depth of nested CBOR structures be limited to at most four levels.
const MAX_CBOR_NESTING_DEPTH: i8 = 4;

pub const TOUCH_TIMEOUT_MS: ClockInt = 30000;
#[cfg(feature = "with_ctap1")]
pub const TOUCH_TIMEOUT: Milliseconds<ClockInt> = Milliseconds(TOUCH_TIMEOUT_MS);
#[cfg(feature = "with_ctap1")]
const U2F_UP_PROMPT_TIMEOUT: Milliseconds<ClockInt> = Milliseconds(10000 as ClockInt);
// TODO(kaczmarczyck) 2.1 allows Reset after Reset and 15 seconds?
const RESET_TIMEOUT_DURATION: Milliseconds<ClockInt> = Milliseconds(10000 as ClockInt);
const STATEFUL_COMMAND_TIMEOUT_DURATION: Milliseconds<ClockInt> = Milliseconds(30000 as ClockInt);

pub const FIDO2_VERSION_STRING: &str = "FIDO_2_0";
#[cfg(feature = "with_ctap1")]
pub const U2F_VERSION_STRING: &str = "U2F_V2";
// TODO(#106) change to final string when ready
pub const FIDO2_1_VERSION_STRING: &str = "FIDO_2_1_PRE";

// We currently only support one algorithm for signatures: ES256.
// This algorithm is requested in MakeCredential and advertized in GetInfo.
pub const ES256_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::Es256,
};

#[cfg(feature = "ed25519")]
pub const EDDSA_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::Eddsa,
};

const SUPPORTED_CRED_PARAMS: &[PublicKeyCredentialParameter] = &[
    ES256_CRED_PARAM,
    #[cfg(feature = "ed25519")]
    EDDSA_CRED_PARAM,
];

fn get_preferred_cred_param(
    params: &[PublicKeyCredentialParameter],
) -> Option<&PublicKeyCredentialParameter> {
    params
        .iter()
        .find(|&param| SUPPORTED_CRED_PARAMS.contains(param))
}

/// Transports supported by OpenSK.
///
/// An OpenSK library user annotates incoming data with this data type.
///
/// The difference between this data type and `AuthenticatorTransport` is that the latter
/// corresponds to the communication defined in the CTAP specification. This data type describes
/// the hardware path a packet took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Corresponds to CTAP's USB transport.
    MainHid,
    /// No equivalent in CTAP, used for communication outside the specification.
    #[cfg(feature = "vendor_hid")]
    VendorHid,
}

impl Transport {
    pub fn hid_connection<E: Env>(self, env: &mut E) -> &mut E::HidConnection {
        match self {
            Transport::MainHid => env.main_hid_connection(),
            #[cfg(feature = "vendor_hid")]
            Transport::VendorHid => env.vendor_hid_connection(),
        }
    }
}

/// Communication channels between authenticator and client.
///
/// From OpenSK's perspective, a channel represents a client. When we receive data from a new
/// channel, we have to assume it's a new client.
///
/// For HID, communication channels coincide with the channel ID. NFC and HID transports are unique
/// channels themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// Corresponds to CTAP's USB transport.
    MainHid(ChannelID),
    /// No equivalent in CTAP, used for communication outside the specification.
    #[cfg(feature = "vendor_hid")]
    VendorHid(ChannelID),
}

// Helpers to perform CBOR read/write while respecting CTAP2 nesting limits.
pub fn cbor_read(encoded_cbor: &[u8]) -> Result<cbor::Value, Ctap2StatusCode> {
    cbor::reader::read_nested(encoded_cbor, Some(MAX_CBOR_NESTING_DEPTH))
        .map_err(|_e| Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
}

fn cbor_write(value: cbor::Value, encoded_cbor: &mut Vec<u8>) -> Result<(), Ctap2StatusCode> {
    cbor::writer::write_nested(value, encoded_cbor, Some(MAX_CBOR_NESTING_DEPTH))
        .map_err(|_e| Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
}

// This function is adapted from https://doc.rust-lang.org/nightly/src/core/str/mod.rs.html#2110
// (as of 2020-01-20) and truncates to "max" bytes, not breaking the encoding.
// We change the return value, since we don't need the bool.
fn truncate_to_char_boundary(s: &str, mut max: usize) -> &str {
    if max >= s.len() {
        s
    } else {
        while !s.is_char_boundary(max) {
            max -= 1;
        }
        &s[..max]
    }
}

// Sends keepalive packet during user presence checking. If user agent replies with CANCEL response,
// returns Err(UserPresenceError::Canceled).
fn send_keepalive_up_needed(
    env: &mut impl Env,
    channel: Channel,
    timeout: Milliseconds<ClockInt>,
) -> Result<(), UserPresenceError> {
    let (cid, transport) = match channel {
        Channel::MainHid(cid) => (cid, Transport::MainHid),
        #[cfg(feature = "vendor_hid")]
        Channel::VendorHid(cid) => (cid, Transport::VendorHid),
    };
    let keepalive_msg = CtapHid::keepalive(cid, KeepaliveStatus::UpNeeded);
    for mut pkt in keepalive_msg {
        let ctap_hid_connection = transport.hid_connection(env);
        match ctap_hid_connection.send_and_maybe_recv(&mut pkt, timeout) {
            Ok(SendOrRecvStatus::Timeout) => {
                debug_ctap!(env, "Sending a KEEPALIVE packet timed out");
                // TODO: abort user presence test?
            }
            Err(_) => panic!("Error sending KEEPALIVE packet"),
            Ok(SendOrRecvStatus::Sent) => {
                debug_ctap!(env, "Sent KEEPALIVE packet");
            }
            Ok(SendOrRecvStatus::Received(endpoint)) => {
                let rx_transport = match endpoint {
                    UsbEndpoint::MainHid => Transport::MainHid,
                    #[cfg(feature = "vendor_hid")]
                    UsbEndpoint::VendorHid => Transport::VendorHid,
                };
                if rx_transport != transport {
                    debug_ctap!(
                        env,
                        "Received a packet on transport {:?} while sending a KEEPALIVE packet on transport {:?}",
                         rx_transport, transport
                    );
                    // Ignore this packet.
                    // TODO(liamjm): Support receiving packets on both interfaces.
                    continue;
                }

                // We only parse one packet, because we only care about CANCEL.
                let (received_cid, processed_packet) = CtapHid::process_single_packet(&pkt);
                if received_cid != &cid {
                    debug_ctap!(
                        env,
                        "Received a packet on channel ID {:?} while sending a KEEPALIVE packet",
                        received_cid,
                    );
                    return Ok(());
                }
                match processed_packet {
                    ProcessedPacket::InitPacket { cmd, .. } => {
                        if cmd == CtapHidCommand::Cancel as u8 {
                            // We ignore the payload, we can't answer with an error code anyway.
                            debug_ctap!(env, "User presence check cancelled");
                            return Err(UserPresenceError::Canceled);
                        } else {
                            debug_ctap!(
                                env,
                                "Discarded packet with command {} received while sending a KEEPALIVE packet",
                                cmd,
                            );
                        }
                    }
                    ProcessedPacket::ContinuationPacket { .. } => {
                        debug_ctap!(
                            env,
                            "Discarded continuation packet received while sending a KEEPALIVE packet",
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Blocks for user presence.
///
/// Returns an error in case of timeout, user declining presence request, or keepalive error.
fn check_user_presence(env: &mut impl Env, channel: Channel) -> Result<(), Ctap2StatusCode> {
    env.user_presence().check_init();

    // The timeout is N times the keepalive delay.
    const TIMEOUT_ITERATIONS: usize = TOUCH_TIMEOUT_MS as usize / KEEPALIVE_DELAY_MS as usize;

    // All fallible functions are called without '?' operator to always reach
    // check_complete(...) cleanup function.

    let mut result = Err(UserPresenceError::Timeout);
    for i in 0..=TIMEOUT_ITERATIONS {
        // First presence check is made without timeout. That way Env implementation may return
        // user presence check result immediately to client, without sending any keepalive packets.
        result = env.user_presence().wait_with_timeout(if i == 0 {
            Milliseconds(0)
        } else {
            KEEPALIVE_DELAY
        });
        if !matches!(result, Err(UserPresenceError::Timeout)) {
            break;
        }
        // TODO: this may take arbitrary time. Next wait's delay should be adjusted
        // accordingly, so that all wait_with_timeout invocations are separated by
        // equal time intervals. That way token indicators, such as LEDs, will blink
        // with a consistent pattern.
        let keepalive_result = send_keepalive_up_needed(env, channel, KEEPALIVE_DELAY);
        if keepalive_result.is_err() {
            debug_ctap!(
                env,
                "Sending keepalive failed with error {:?}",
                keepalive_result.as_ref().unwrap_err()
            );
            result = keepalive_result;
            break;
        }
    }

    env.user_presence().check_complete();
    result.map_err(|e| e.into())
}

/// Holds data necessary to sign an assertion for a credential.
#[derive(Clone)]
pub struct AssertionInput {
    client_data_hash: Vec<u8>,
    auth_data: Vec<u8>,
    extensions: GetAssertionExtensions,
    has_uv: bool,
}

/// Contains the state we need to store for GetNextAssertion.
pub struct AssertionState {
    assertion_input: AssertionInput,
    // Sorted by ascending order of creation, so the last element is the most recent one.
    next_credential_keys: Vec<usize>,
}

/// Stores which command currently holds state for subsequent calls.
pub enum StatefulCommand {
    Reset,
    GetAssertion(Box<AssertionState>),
    EnumerateRps(usize),
    EnumerateCredentials(Vec<usize>),
}

/// Stores the current CTAP command state and when it times out.
///
/// Some commands are executed in a series of calls to the authenticator.
/// Interleaving calls to other commands interrupt the current command and
/// remove all state and permissions. Power cycling allows the Reset command,
/// and to prevent misuse or accidents, we disallow Reset after receiving
/// different commands. Therefore, Reset behaves just like all other stateful
/// commands and is included here. Please note that the allowed time for Reset
/// differs from all other stateful commands.
///
/// Additionally, state that is held over multiple commands is assigned to a channel. We discard
/// all state when we receive data on a different channel.
pub struct StatefulPermission {
    permission: TimedPermission,
    command_type: Option<StatefulCommand>,
    channel: Option<Channel>,
}

impl StatefulPermission {
    /// Creates the command state at device startup.
    ///
    /// Resets are only possible after a power cycle. Therefore, initialization
    /// means allowing Reset, and Reset cannot be granted later.
    pub fn new_reset(now: CtapInstant) -> StatefulPermission {
        StatefulPermission {
            permission: TimedPermission::granted(now, RESET_TIMEOUT_DURATION),
            command_type: Some(StatefulCommand::Reset),
            channel: None,
        }
    }

    /// Clears all permissions and state.
    pub fn clear(&mut self) {
        self.permission = TimedPermission::waiting();
        self.command_type = None;
        self.channel = None;
    }

    /// Clears all state if communication is coming from a different channel.
    pub fn clear_old_channels(&mut self, channel: &Channel) {
        // There are different possible choices for incoming traffic on a different channel:
        // A) Always reset state (our choice).
        // B) Only reset state if the new command is stateful.
        // C) Keep state on all channels until timeout.
        //
        // If we wanted to switch to (B) or (C), we'd have to be very careful that the state does
        // not go stale. For example, we keep credential keys that we expect to still exist.
        // However, interleaving (stateless) commands could delete credentials or change the PIN,
        // which chould make invalidate our access. Some read-only commands should be okay to run,
        // but (A) is the safest and easiest solution.
        if let Some(c) = &self.channel {
            if c != channel {
                self.clear();
            }
        }
    }

    /// Clears all state if the permission timed out.
    pub fn clear_timer(&mut self, now: CtapInstant) {
        if !self.permission.is_granted(now) {
            self.clear();
        }
    }

    /// Gets a reference to the current command state, if any exists.
    pub fn get_command(&self) -> Result<&StatefulCommand, Ctap2StatusCode> {
        self.command_type
            .as_ref()
            .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
    }

    /// Sets a new command state, and starts a new clock for timeouts.
    pub fn set_command(
        &mut self,
        now: CtapInstant,
        new_command_type: StatefulCommand,
        channel: Channel,
    ) {
        match &new_command_type {
            // Reset is only allowed after a power cycle.
            StatefulCommand::Reset => unreachable!(),
            _ => {
                self.permission = TimedPermission::granted(now, STATEFUL_COMMAND_TIMEOUT_DURATION);
                self.command_type = Some(new_command_type);
                self.channel = Some(channel);
            }
        }
    }

    /// Returns the state for the next assertion and advances it.
    ///
    /// The state includes all information from GetAssertion and the storage key
    /// to the next credential that needs to be processed.
    pub fn next_assertion_credential(
        &mut self,
    ) -> Result<(AssertionInput, usize), Ctap2StatusCode> {
        if let Some(StatefulCommand::GetAssertion(assertion_state)) = &mut self.command_type {
            let credential_key = assertion_state
                .next_credential_keys
                .pop()
                .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)?;
            Ok((assertion_state.assertion_input.clone(), credential_key))
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        }
    }

    /// Returns the index to the next RP ID for enumeration and advances it.
    pub fn next_enumerate_rp(&mut self) -> Result<usize, Ctap2StatusCode> {
        if let Some(StatefulCommand::EnumerateRps(rp_id_index)) = &mut self.command_type {
            let current_index = *rp_id_index;
            *rp_id_index += 1;
            Ok(current_index)
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        }
    }

    /// Returns the next storage credential key for enumeration and advances it.
    pub fn next_enumerate_credential(&mut self) -> Result<usize, Ctap2StatusCode> {
        if let Some(StatefulCommand::EnumerateCredentials(rp_credentials)) = &mut self.command_type
        {
            rp_credentials
                .pop()
                .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        }
    }
}

// This struct currently holds all state, not only the persistent memory. The persistent members are
// in the persistent store field.
pub struct CtapState {
    client_pin: ClientPin,
    #[cfg(feature = "with_ctap1")]
    pub(crate) u2f_up_state: U2fUserPresenceState,
    // The state initializes to Reset and its timeout, and never goes back to Reset.
    stateful_command_permission: StatefulPermission,
    large_blobs: LargeBlobs,
}

impl CtapState {
    pub fn new(env: &mut impl Env, now: CtapInstant) -> Self {
        storage::init(env).ok().unwrap();
        let client_pin = ClientPin::new(env.rng());
        CtapState {
            client_pin,
            #[cfg(feature = "with_ctap1")]
            u2f_up_state: U2fUserPresenceState::new(U2F_UP_PROMPT_TIMEOUT, TOUCH_TIMEOUT),
            stateful_command_permission: StatefulPermission::new_reset(now),
            large_blobs: LargeBlobs::new(),
        }
    }

    pub fn update_timeouts(&mut self, now: CtapInstant) {
        self.stateful_command_permission.clear_timer(now);
        self.client_pin.update_timeouts(now);
    }

    pub fn increment_global_signature_counter(
        &mut self,
        env: &mut impl Env,
    ) -> Result<(), Ctap2StatusCode> {
        if env.customization().use_signature_counter() {
            let increment = env.rng().gen_uniform_u32x8()[0] % 8 + 1;
            storage::incr_global_signature_counter(env, increment)?;
        }
        Ok(())
    }

    // Returns whether CTAP1 commands are currently supported.
    // If alwaysUv is enabled and the authenticator does not support internal UV,
    // CTAP1 needs to be disabled.
    #[cfg(feature = "with_ctap1")]
    pub fn allows_ctap1(&self, env: &mut impl Env) -> Result<bool, Ctap2StatusCode> {
        Ok(!storage::has_always_uv(env)?)
    }

    pub fn process_command(
        &mut self,
        env: &mut impl Env,
        command_cbor: &[u8],
        channel: Channel,
        now: CtapInstant,
    ) -> Vec<u8> {
        let cmd = Command::deserialize(command_cbor);
        debug_ctap!(env, "Received command: {:#?}", cmd);
        let response =
            cmd.and_then(|command| self.process_parsed_command(env, command, channel, now));
        debug_ctap!(env, "Sending response: {:#?}", response);
        match response {
            Ok(response_data) => {
                let mut response_vec = vec![Ctap2StatusCode::CTAP2_OK as u8];
                if let Some(value) = response_data.into() {
                    if cbor_write(value, &mut response_vec).is_err() {
                        response_vec = vec![Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR as u8];
                    }
                }
                response_vec
            }
            Err(error_code) => vec![error_code as u8],
        }
    }

    /// Processed a command after parsing from CBOR, returning its structured output.
    ///
    /// This function contains the logic of `parse_command`, minus all CBOR encoding and decoding.
    /// It should make command parsing easier to test.
    pub fn process_parsed_command(
        &mut self,
        env: &mut impl Env,
        command: Command,
        channel: Channel,
        now: CtapInstant,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        // Correct behavior between CTAP1 and CTAP2 isn't defined yet. Just a guess.
        #[cfg(feature = "with_ctap1")]
        {
            // We create a block statement to wrap this assignment expression, because attributes
            // (like #[cfg]) are not supported on expressions.
            self.u2f_up_state = U2fUserPresenceState::new(U2F_UP_PROMPT_TIMEOUT, TOUCH_TIMEOUT);
        }
        self.stateful_command_permission
            .clear_old_channels(&channel);
        self.stateful_command_permission.clear_timer(now);
        match (&command, self.stateful_command_permission.get_command()) {
            (Command::AuthenticatorGetNextAssertion, Ok(StatefulCommand::GetAssertion(_)))
            | (Command::AuthenticatorReset, Ok(StatefulCommand::Reset))
            // AuthenticatorGetInfo still allows Reset.
            | (Command::AuthenticatorGetInfo, Ok(StatefulCommand::Reset))
            // AuthenticatorSelection still allows Reset.
            | (Command::AuthenticatorSelection, Ok(StatefulCommand::Reset))
            // AuthenticatorMakeCredential is used like AuthenticatorSelection in 2.0.
            | (Command::AuthenticatorMakeCredential(_), Ok(StatefulCommand::Reset))
            // AuthenticatorCredentialManagement handles its subcommands later.
            | (
                Command::AuthenticatorCredentialManagement(_),
                Ok(StatefulCommand::EnumerateRps(_)),
            )
            | (
                Command::AuthenticatorCredentialManagement(_),
                Ok(StatefulCommand::EnumerateCredentials(_)),
            ) => (),
            (_, _) => self.stateful_command_permission.clear(),
        }
        match &channel {
            Channel::MainHid(_) => self.process_fido_command(env, command, channel, now),
            #[cfg(feature = "vendor_hid")]
            Channel::VendorHid(_) => self.process_vendor_command(env, command, channel),
        }
    }

    fn process_fido_command(
        &mut self,
        env: &mut impl Env,
        command: Command,
        channel: Channel,
        now: CtapInstant,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        match command {
            Command::AuthenticatorMakeCredential(params) => {
                self.process_make_credential(env, params, channel)
            }
            Command::AuthenticatorGetAssertion(params) => {
                self.process_get_assertion(env, params, channel, now)
            }
            Command::AuthenticatorGetNextAssertion => self.process_get_next_assertion(env),
            Command::AuthenticatorGetInfo => self.process_get_info(env),
            Command::AuthenticatorClientPin(params) => {
                self.client_pin.process_command(env, params, now)
            }
            Command::AuthenticatorReset => self.process_reset(env, channel),
            Command::AuthenticatorCredentialManagement(params) => process_credential_management(
                env,
                &mut self.stateful_command_permission,
                &mut self.client_pin,
                params,
                channel,
                now,
            ),
            Command::AuthenticatorSelection => self.process_selection(env, channel),
            Command::AuthenticatorLargeBlobs(params) => {
                self.large_blobs
                    .process_command(env, &mut self.client_pin, params)
            }
            Command::AuthenticatorConfig(params) => {
                process_config(env, &mut self.client_pin, params)
            }
            #[cfg(feature = "vendor_hid")]
            _ => Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND),
            #[cfg(not(feature = "vendor_hid"))]
            _ => self.process_vendor_command(env, command, channel),
        }
    }

    fn process_vendor_command(
        &mut self,
        env: &mut impl Env,
        command: Command,
        channel: Channel,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        match command {
            Command::AuthenticatorVendorConfigure(params) => {
                self.process_vendor_configure(env, params, channel)
            }
            Command::AuthenticatorVendorUpgrade(params) => self.process_vendor_upgrade(env, params),
            Command::AuthenticatorVendorUpgradeInfo => self.process_vendor_upgrade_info(env),
            Command::AuthenticatorGetInfo => self.process_get_info(env),
            _ => Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND),
        }
    }

    fn pin_uv_auth_precheck(
        &mut self,
        env: &mut impl Env,
        pin_uv_auth_param: &Option<Vec<u8>>,
        pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
        channel: Channel,
    ) -> Result<(), Ctap2StatusCode> {
        if let Some(auth_param) = &pin_uv_auth_param {
            // This case was added in FIDO 2.1.
            if auth_param.is_empty() {
                check_user_presence(env, channel)?;
                if storage::pin_hash(env)?.is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                } else {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }
            }
            pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
        }
        Ok(())
    }

    fn check_cred_protect_for_listed_credential(
        &mut self,
        credential: &Option<PublicKeyCredentialSource>,
        has_uv: bool,
    ) -> bool {
        if let Some(credential) = credential {
            has_uv
                || !matches!(
                    credential.cred_protect_policy,
                    Some(CredentialProtectionPolicy::UserVerificationRequired),
                )
        } else {
            false
        }
    }

    fn process_make_credential(
        &mut self,
        env: &mut impl Env,
        make_credential_params: AuthenticatorMakeCredentialParameters,
        channel: Channel,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let AuthenticatorMakeCredentialParameters {
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
        } = make_credential_params;

        self.pin_uv_auth_precheck(env, &pin_uv_auth_param, pin_uv_auth_protocol, channel)?;

        // When more algorithms are supported, iterate and pick the first match.
        let cred_param = get_preferred_cred_param(&pub_key_cred_params)
            .ok_or(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)?;
        let algorithm = cred_param.alg;

        let rp_id = rp.rp_id;
        let ep_att = if let Some(enterprise_attestation) = enterprise_attestation {
            let authenticator_mode = env
                .customization()
                .enterprise_attestation_mode()
                .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
            if !storage::enterprise_attestation(env)? {
                return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
            }
            match (
                EnterpriseAttestationMode::try_from(enterprise_attestation)?,
                authenticator_mode,
            ) {
                (
                    EnterpriseAttestationMode::PlatformManaged,
                    EnterpriseAttestationMode::PlatformManaged,
                ) => true,
                _ => env.customization().is_enterprise_rp_id(&rp_id),
            }
        } else {
            false
        };

        // MakeCredential always requires user presence.
        // User verification depends on the PIN auth inputs, which are checked here.
        // The ED flag is added later, if applicable.
        let has_uv = pin_uv_auth_param.is_some();
        let mut flags = match pin_uv_auth_param {
            Some(pin_uv_auth_param) => {
                // This case is not mentioned in CTAP2.1, so we keep 2.0 logic.
                if storage::pin_hash(env)?.is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                }
                self.client_pin.verify_pin_uv_auth_token(
                    &client_data_hash,
                    &pin_uv_auth_param,
                    pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                self.client_pin
                    .has_permission(PinPermission::MakeCredential)?;
                self.client_pin.check_user_verified_flag()?;
                // Checking for the correct permissions_rp_id is specified earlier.
                // Error codes are identical though, so the implementation can be identical with
                // GetAssertion.
                self.client_pin.ensure_rp_id_permission(&rp_id)?;
                UV_FLAG
            }
            None => {
                if options.uv {
                    return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
                }
                if storage::has_always_uv(env)? {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                }
                // Corresponds to makeCredUvNotRqd set to true.
                if options.rk && storage::pin_hash(env)?.is_some() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                }
                0x00
            }
        };
        flags |= UP_FLAG | AT_FLAG;

        let rp_id_hash = Sha256::hash(rp_id.as_bytes());
        if let Some(exclude_list) = exclude_list {
            for cred_desc in exclude_list {
                if self.check_cred_protect_for_listed_credential(
                    &storage::find_credential(env, &rp_id, &cred_desc.key_id)?,
                    has_uv,
                ) || self.check_cred_protect_for_listed_credential(
                    &decrypt_credential_id(env, cred_desc.key_id, &rp_id_hash)?,
                    has_uv,
                ) {
                    // Perform this check, so bad actors can't brute force exclude_list
                    // without user interaction.
                    let _ = check_user_presence(env, channel);
                    return Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED);
                }
            }
        }

        check_user_presence(env, channel)?;
        self.client_pin.clear_token_flags();

        let default_cred_protect = env.customization().default_cred_protect();
        let mut cred_protect_policy = extensions.cred_protect;
        if cred_protect_policy.unwrap_or(CredentialProtectionPolicy::UserVerificationOptional)
            < default_cred_protect.unwrap_or(CredentialProtectionPolicy::UserVerificationOptional)
        {
            cred_protect_policy = default_cred_protect;
        }
        let min_pin_length =
            extensions.min_pin_length && storage::min_pin_length_rp_ids(env)?.contains(&rp_id);
        // None for no input, false for invalid input, true for valid input.
        let has_cred_blob_output = extensions.cred_blob.is_some();
        let cred_blob = extensions
            .cred_blob
            .filter(|c| c.len() <= env.customization().max_cred_blob_length());
        let cred_blob_output = if has_cred_blob_output {
            Some(cred_blob.is_some())
        } else {
            None
        };
        let has_extension_output = extensions.hmac_secret
            || extensions.cred_protect.is_some()
            || min_pin_length
            || has_cred_blob_output;
        if has_extension_output {
            flags |= ED_FLAG
        };
        let large_blob_key = match (options.rk, extensions.large_blob_key) {
            (true, Some(true)) => Some(env.rng().gen_uniform_u8x32().to_vec()),
            _ => None,
        };

        // We decide on the algorithm early, but delay key creation since it takes time.
        // We rather do that later so all intermediate checks may return faster.
        let private_key = PrivateKey::new(env, algorithm);
        let credential_id = if options.rk {
            let random_id = env.rng().gen_uniform_u8x32().to_vec();
            let credential_source = PublicKeyCredentialSource {
                key_type: PublicKeyCredentialType::PublicKey,
                credential_id: random_id.clone(),
                private_key: private_key.clone(),
                rp_id,
                user_handle: user.user_id,
                // This input is user provided, so we crop it to 64 byte for storage.
                // The UTF8 encoding is always preserved, so the string might end up shorter.
                user_display_name: user
                    .user_display_name
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                cred_protect_policy,
                creation_order: storage::new_creation_order(env)?,
                user_name: user
                    .user_name
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                user_icon: user
                    .user_icon
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                cred_blob,
                large_blob_key: large_blob_key.clone(),
            };
            storage::store_credential(env, credential_source)?;
            random_id
        } else {
            encrypt_to_credential_id(
                env,
                &private_key,
                &rp_id_hash,
                cred_protect_policy,
                cred_blob,
            )?
        };

        let mut auth_data = self.generate_auth_data(env, &rp_id_hash, flags)?;
        auth_data.extend(&storage::aaguid(env)?);
        // The length is fixed to 0x20 or 0x80 and fits one byte.
        if credential_id.len() > 0xFF {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        auth_data.extend(vec![0x00, credential_id.len() as u8]);
        auth_data.extend(&credential_id);
        let public_cose_key = private_key.get_pub_key(env)?;
        cbor_write(cbor::Value::from(public_cose_key), &mut auth_data)?;
        if has_extension_output {
            let hmac_secret_output = if extensions.hmac_secret {
                Some(true)
            } else {
                None
            };
            let min_pin_length_output = if min_pin_length {
                Some(storage::min_pin_length(env)? as u64)
            } else {
                None
            };
            let cred_protect_output = extensions.cred_protect.and(cred_protect_policy);
            let extensions_output = cbor_map_options! {
                "credBlob" => cred_blob_output,
                "credProtect" => cred_protect_output,
                "hmac-secret" => hmac_secret_output,
                "minPinLength" => min_pin_length_output,
            };
            cbor_write(extensions_output, &mut auth_data)?;
        }

        let mut signature_data = auth_data.clone();
        signature_data.extend(client_data_hash);

        let attestation_id = if ep_att {
            Some(attestation_store::Id::Enterprise)
        } else if env.customization().use_batch_attestation() {
            Some(attestation_store::Id::Batch)
        } else {
            None
        };
        let (signature, x5c) = match attestation_id {
            Some(id) => {
                let Attestation {
                    private_key,
                    certificate,
                } = env
                    .attestation_store()
                    .get(&id)?
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                let attestation_key = ecdsa::SecKey::from_bytes(&private_key).unwrap();
                (
                    attestation_key
                        .sign_rfc6979::<Sha256>(&signature_data)
                        .to_asn1_der(),
                    Some(vec![certificate]),
                )
            }
            None => (private_key.sign_and_encode(env, &signature_data)?, None),
        };
        let attestation_statement = PackedAttestationStatement {
            alg: SignatureAlgorithm::Es256 as i64,
            sig: signature,
            x5c,
            ecdaa_key_id: None,
        };
        let ep_att = if ep_att { Some(true) } else { None };
        Ok(ResponseData::AuthenticatorMakeCredential(
            AuthenticatorMakeCredentialResponse {
                fmt: String::from("packed"),
                auth_data,
                att_stmt: attestation_statement,
                ep_att,
                large_blob_key,
            },
        ))
    }

    // Generates a different per-credential secret for each UV mode.
    // The computation is deterministic, and private_key expected to be unique.
    fn generate_cred_random(
        &mut self,
        env: &mut impl Env,
        private_key: &PrivateKey,
        has_uv: bool,
    ) -> Result<[u8; 32], Ctap2StatusCode> {
        let entropy = private_key.to_bytes();
        let key = storage::cred_random_secret(env, has_uv)?;
        Ok(hmac_256::<Sha256>(&key, &entropy))
    }

    // Processes the input of a get_assertion operation for a given credential
    // and returns the correct Get(Next)Assertion response.
    fn assertion_response(
        &mut self,
        env: &mut impl Env,
        mut credential: PublicKeyCredentialSource,
        assertion_input: AssertionInput,
        number_of_credentials: Option<usize>,
        is_next: bool,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let AssertionInput {
            client_data_hash,
            mut auth_data,
            extensions,
            has_uv,
        } = assertion_input;

        // Process extensions.
        if extensions.hmac_secret.is_some() || extensions.cred_blob {
            let encrypted_output = if let Some(hmac_secret_input) = extensions.hmac_secret {
                let cred_random =
                    self.generate_cred_random(env, &credential.private_key, has_uv)?;
                Some(self.client_pin.process_hmac_secret(
                    env.rng(),
                    hmac_secret_input,
                    &cred_random,
                )?)
            } else {
                None
            };
            // This could be written more nicely with `then_some` when stable.
            let cred_blob = if extensions.cred_blob {
                Some(credential.cred_blob.unwrap_or_default())
            } else {
                None
            };
            let extensions_output = cbor_map_options! {
                "credBlob" => cred_blob,
                "hmac-secret" => encrypted_output,
            };
            cbor_write(extensions_output, &mut auth_data)?;
        }
        let large_blob_key = match extensions.large_blob_key {
            Some(true) => credential.large_blob_key,
            _ => None,
        };

        let mut signature_data = auth_data.clone();
        signature_data.extend(client_data_hash);
        let signature = credential
            .private_key
            .sign_and_encode(env, &signature_data)?;

        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential.credential_id,
            transports: None, // You can set USB as a hint here.
        };
        // Remove user identifiable information without uv.
        if !has_uv {
            credential.user_name = None;
            credential.user_display_name = None;
            credential.user_icon = None;
        }
        let user = if !credential.user_handle.is_empty() {
            Some(PublicKeyCredentialUserEntity {
                user_id: credential.user_handle,
                user_name: credential.user_name,
                user_display_name: credential.user_display_name,
                user_icon: credential.user_icon,
            })
        } else {
            None
        };
        let response_data = AuthenticatorGetAssertionResponse {
            credential: Some(cred_desc),
            auth_data,
            signature,
            user,
            number_of_credentials: number_of_credentials.map(|n| n as u64),
            large_blob_key,
        };
        // Only returned for the first GetAssertion, not for Next calls.
        if is_next {
            Ok(ResponseData::AuthenticatorGetNextAssertion(response_data))
        } else {
            Ok(ResponseData::AuthenticatorGetAssertion(response_data))
        }
    }

    // Returns the first applicable credential from the allow list.
    fn get_any_credential_from_allow_list(
        &mut self,
        env: &mut impl Env,
        allow_list: Vec<PublicKeyCredentialDescriptor>,
        rp_id: &str,
        rp_id_hash: &[u8],
        has_uv: bool,
    ) -> Result<Option<PublicKeyCredentialSource>, Ctap2StatusCode> {
        for allowed_credential in allow_list {
            let credential = storage::find_credential(env, rp_id, &allowed_credential.key_id)?;
            if self.check_cred_protect_for_listed_credential(&credential, has_uv) {
                return Ok(credential);
            }
            let credential = decrypt_credential_id(env, allowed_credential.key_id, rp_id_hash)?;
            if self.check_cred_protect_for_listed_credential(&credential, has_uv) {
                return Ok(credential);
            }
        }
        Ok(None)
    }

    fn process_get_assertion(
        &mut self,
        env: &mut impl Env,
        get_assertion_params: AuthenticatorGetAssertionParameters,
        channel: Channel,
        now: CtapInstant,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let AuthenticatorGetAssertionParameters {
            rp_id,
            client_data_hash,
            allow_list,
            extensions,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        } = get_assertion_params;

        self.pin_uv_auth_precheck(env, &pin_uv_auth_param, pin_uv_auth_protocol, channel)?;

        if extensions.hmac_secret.is_some() && !options.up {
            // The extension is actually supported, but we need user presence.
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_OPTION);
        }

        // The user verification bit depends on the existance of PIN auth, since we do
        // not support internal UV. User presence is requested as an option.
        let has_uv = pin_uv_auth_param.is_some();
        let mut flags = match pin_uv_auth_param {
            Some(pin_uv_auth_param) => {
                // This case is not mentioned in CTAP2.1, so we keep 2.0 logic.
                if storage::pin_hash(env)?.is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                }
                self.client_pin.verify_pin_uv_auth_token(
                    &client_data_hash,
                    &pin_uv_auth_param,
                    pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                self.client_pin
                    .has_permission(PinPermission::GetAssertion)?;
                // Checking for the UV flag is specified earlier for GetAssertion.
                // Error codes are identical though, so the implementation can be identical with
                // MakeCredential.
                self.client_pin.check_user_verified_flag()?;
                self.client_pin.ensure_rp_id_permission(&rp_id)?;
                UV_FLAG
            }
            None => {
                if options.uv {
                    return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
                }
                if options.up && storage::has_always_uv(env)? {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                }
                0x00
            }
        };
        if options.up {
            flags |= UP_FLAG;
        }
        if extensions.hmac_secret.is_some() || extensions.cred_blob {
            flags |= ED_FLAG;
        }

        let rp_id_hash = Sha256::hash(rp_id.as_bytes());
        let (credential, next_credential_keys) = if let Some(allow_list) = allow_list {
            (
                self.get_any_credential_from_allow_list(
                    env,
                    allow_list,
                    &rp_id,
                    &rp_id_hash,
                    has_uv,
                )?,
                vec![],
            )
        } else {
            let mut iter_result = Ok(());
            let iter = storage::iter_credentials(env, &mut iter_result)?;
            let mut stored_credentials: Vec<(usize, u64)> = iter
                .filter_map(|(key, credential)| {
                    if credential.rp_id == rp_id && (has_uv || credential.is_discoverable()) {
                        Some((key, credential.creation_order))
                    } else {
                        None
                    }
                })
                .collect();
            iter_result?;
            stored_credentials.sort_unstable_by_key(|&(_key, order)| order);
            let mut stored_credentials: Vec<usize> = stored_credentials
                .into_iter()
                .map(|(key, _order)| key)
                .collect();
            let credential = stored_credentials
                .pop()
                .map(|key| storage::get_credential(env, key))
                .transpose()?;
            (credential, stored_credentials)
        };

        let credential = credential.ok_or(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)?;

        // This check comes before CTAP2_ERR_NO_CREDENTIALS in CTAP 2.0.
        if options.up {
            check_user_presence(env, channel)?;
            self.client_pin.clear_token_flags();
        }

        self.increment_global_signature_counter(env)?;

        let assertion_input = AssertionInput {
            client_data_hash,
            auth_data: self.generate_auth_data(env, &rp_id_hash, flags)?,
            extensions,
            has_uv,
        };
        let number_of_credentials = if next_credential_keys.is_empty() {
            None
        } else {
            let number_of_credentials = Some(next_credential_keys.len() + 1);
            let assertion_state = StatefulCommand::GetAssertion(Box::new(AssertionState {
                assertion_input: assertion_input.clone(),
                next_credential_keys,
            }));
            self.stateful_command_permission
                .set_command(now, assertion_state, channel);
            number_of_credentials
        };
        self.assertion_response(
            env,
            credential,
            assertion_input,
            number_of_credentials,
            false,
        )
    }

    fn process_get_next_assertion(
        &mut self,
        env: &mut impl Env,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let (assertion_input, credential_key) = self
            .stateful_command_permission
            .next_assertion_credential()?;
        let credential = storage::get_credential(env, credential_key)?;
        self.assertion_response(env, credential, assertion_input, None, true)
    }

    fn process_get_info(&self, env: &mut impl Env) -> Result<ResponseData, Ctap2StatusCode> {
        let has_always_uv = storage::has_always_uv(env)?;
        #[cfg_attr(not(feature = "with_ctap1"), allow(unused_mut))]
        let mut versions = vec![
            String::from(FIDO2_VERSION_STRING),
            String::from(FIDO2_1_VERSION_STRING),
        ];
        #[cfg(feature = "with_ctap1")]
        if !has_always_uv {
            versions.insert(0, String::from(U2F_VERSION_STRING))
        }
        let mut options = vec![];
        if env.customization().enterprise_attestation_mode().is_some() {
            options.push((String::from("ep"), storage::enterprise_attestation(env)?));
        }
        options.append(&mut vec![
            (String::from("rk"), true),
            (String::from("up"), true),
            (String::from("alwaysUv"), has_always_uv),
            (String::from("credMgmt"), true),
            (String::from("authnrCfg"), true),
            (String::from("clientPin"), storage::pin_hash(env)?.is_some()),
            (String::from("largeBlobs"), true),
            (String::from("pinUvAuthToken"), true),
            (String::from("setMinPINLength"), true),
            (String::from("makeCredUvNotRqd"), !has_always_uv),
        ]);
        let mut pin_protocols = vec![PinUvAuthProtocol::V2 as u64];
        if env.customization().allows_pin_protocol_v1() {
            pin_protocols.push(PinUvAuthProtocol::V1 as u64);
        }

        Ok(ResponseData::AuthenticatorGetInfo(
            AuthenticatorGetInfoResponse {
                versions,
                extensions: Some(vec![
                    String::from("hmac-secret"),
                    String::from("credProtect"),
                    String::from("minPinLength"),
                    String::from("credBlob"),
                    String::from("largeBlobKey"),
                ]),
                aaguid: storage::aaguid(env)?,
                options: Some(options),
                max_msg_size: Some(env.customization().max_msg_size() as u64),
                // The order implies preference. We favor the new V2.
                pin_protocols: Some(pin_protocols),
                max_credential_count_in_list: env
                    .customization()
                    .max_credential_count_in_list()
                    .map(|c| c as u64),
                max_credential_id_length: Some(MAX_CREDENTIAL_ID_SIZE as u64),
                transports: Some(vec![AuthenticatorTransport::Usb]),
                algorithms: Some(SUPPORTED_CRED_PARAMS.to_vec()),
                max_serialized_large_blob_array: Some(
                    env.customization().max_large_blob_array_size() as u64,
                ),
                force_pin_change: Some(storage::has_force_pin_change(env)?),
                min_pin_length: storage::min_pin_length(env)?,
                firmware_version: env.upgrade_storage().map(|u| u.running_firmware_version()),
                max_cred_blob_length: Some(env.customization().max_cred_blob_length() as u64),
                max_rp_ids_for_set_min_pin_length: Some(
                    env.customization().max_rp_ids_length() as u64
                ),
                certifications: None,
                remaining_discoverable_credentials: Some(
                    storage::remaining_credentials(env)? as u64
                ),
            },
        ))
    }

    fn process_reset(
        &mut self,
        env: &mut impl Env,
        channel: Channel,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        match self.stateful_command_permission.get_command()? {
            StatefulCommand::Reset => (),
            _ => return Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED),
        }
        check_user_presence(env, channel)?;

        storage::reset(env)?;
        self.client_pin.reset(env.rng());
        #[cfg(feature = "with_ctap1")]
        {
            // We create a block statement to wrap this assignment expression, because attributes
            // (like #[cfg]) are not supported on expressions.
            self.u2f_up_state = U2fUserPresenceState::new(U2F_UP_PROMPT_TIMEOUT, TOUCH_TIMEOUT);
        }
        Ok(ResponseData::AuthenticatorReset)
    }

    fn process_selection(
        &self,
        env: &mut impl Env,
        channel: Channel,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        check_user_presence(env, channel)?;
        Ok(ResponseData::AuthenticatorSelection)
    }

    fn process_vendor_configure(
        &mut self,
        env: &mut impl Env,
        params: AuthenticatorVendorConfigureParameters,
        channel: Channel,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        if params.attestation_material.is_some() || params.lockdown {
            check_user_presence(env, channel)?;
        }
        // This command is for U2F support and we use the batch attestation there.
        let attestation_id = attestation_store::Id::Batch;

        // Sanity checks
        let current_attestation = env.attestation_store().get(&attestation_id)?;
        let response = match params.attestation_material {
            None => AuthenticatorVendorConfigureResponse {
                cert_programmed: current_attestation.is_some(),
                pkey_programmed: current_attestation.is_some(),
            },
            Some(data) => {
                // We don't overwrite the attestation if it's already set. We don't return any error
                // to not leak information.
                if current_attestation.is_none() {
                    let attestation = Attestation {
                        private_key: data.private_key,
                        certificate: data.certificate,
                    };
                    env.attestation_store()
                        .set(&attestation_id, Some(&attestation))?;
                }
                AuthenticatorVendorConfigureResponse {
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
                || !env.firmware_protection().lock()
            {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
            }
        }
        Ok(ResponseData::AuthenticatorVendorConfigure(response))
    }

    fn process_vendor_upgrade(
        &mut self,
        env: &mut impl Env,
        params: AuthenticatorVendorUpgradeParameters,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let AuthenticatorVendorUpgradeParameters { offset, data, hash } = params;
        let calculated_hash = Sha256::hash(&data);
        if hash != calculated_hash {
            return Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE);
        }
        env.upgrade_storage()
            .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND)?
            .write_bundle(offset, data)
            .map_err(|_| Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
        Ok(ResponseData::AuthenticatorVendorUpgrade)
    }

    fn process_vendor_upgrade_info(
        &self,
        env: &mut impl Env,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let upgrade_locations = env
            .upgrade_storage()
            .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND)?;
        Ok(ResponseData::AuthenticatorVendorUpgradeInfo(
            AuthenticatorVendorUpgradeInfoResponse {
                info: upgrade_locations.bundle_identifier(),
            },
        ))
    }

    pub fn generate_auth_data(
        &self,
        env: &mut impl Env,
        rp_id_hash: &[u8],
        flag_byte: u8,
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let mut auth_data = vec![];
        auth_data.extend(rp_id_hash);
        auth_data.push(flag_byte);
        // The global counter is only increased if use_signature_counter() is true.
        // It uses a big-endian representation.
        let mut signature_counter = [0u8; 4];
        BigEndian::write_u32(
            &mut signature_counter,
            storage::global_signature_counter(env)?,
        );
        auth_data.extend(&signature_counter);
        Ok(auth_data)
    }

    #[cfg(feature = "with_ctap1")]
    pub fn u2f_grant_user_presence(&mut self, now: CtapInstant) {
        self.u2f_up_state.grant_up(now)
    }

    #[cfg(feature = "with_ctap1")]
    pub fn u2f_needs_user_presence(&mut self, now: CtapInstant) -> bool {
        self.u2f_up_state.is_up_needed(now)
    }
}

#[cfg(test)]
mod test {
    use super::client_pin::PIN_TOKEN_LENGTH;
    use super::command::{
        AuthenticatorAttestationMaterial, AuthenticatorClientPinParameters,
        AuthenticatorCredentialManagementParameters,
    };
    use super::credential_id::CBOR_CREDENTIAL_ID_SIZE;
    use super::data_formats::{
        ClientPinSubCommand, CoseKey, CredentialManagementSubCommand, GetAssertionHmacSecretInput,
        GetAssertionOptions, MakeCredentialExtensions, MakeCredentialOptions, PinUvAuthProtocol,
        PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    };
    use super::pin_protocol::{authenticate_pin_uv_auth_token, PinProtocol};
    use super::*;
    use crate::api::customization;
    use crate::api::user_presence::UserPresenceResult;
    use crate::env::test::TestEnv;
    use crate::test_helpers;
    use cbor::{cbor_array, cbor_array_vec, cbor_map};

    // The keep-alive logic in the processing of some commands needs a channel ID to send
    // keep-alive packets to.
    // In tests where we define a dummy user-presence check that immediately returns, the channel
    // ID is irrelevant, so we pass this (dummy but valid) value.
    const DUMMY_CHANNEL: Channel = Channel::MainHid([0x12, 0x34, 0x56, 0x78]);
    #[cfg(feature = "vendor_hid")]
    const VENDOR_CHANNEL: Channel = Channel::VendorHid([0x12, 0x34, 0x56, 0x78]);

    fn check_make_response(
        make_credential_response: &Result<ResponseData, Ctap2StatusCode>,
        flags: u8,
        expected_aaguid: &[u8],
        expected_credential_id_size: u8,
        expected_extension_cbor: &[u8],
    ) {
        match make_credential_response.as_ref().unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                let AuthenticatorMakeCredentialResponse {
                    fmt,
                    auth_data,
                    att_stmt,
                    ep_att,
                    large_blob_key,
                } = make_credential_response;
                // The expected response is split to only assert the non-random parts.
                assert_eq!(fmt, "packed");
                let mut expected_auth_data = vec![
                    0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80,
                    0x34, 0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2,
                    0x12, 0x55, 0x86, 0xCE, 0x19, 0x47, flags, 0x00, 0x00, 0x00,
                ];
                expected_auth_data.push(INITIAL_SIGNATURE_COUNTER as u8);
                expected_auth_data.extend(expected_aaguid);
                expected_auth_data.extend(&[0x00, expected_credential_id_size]);
                assert_eq!(
                    auth_data[0..expected_auth_data.len()],
                    expected_auth_data[..]
                );
                assert_eq!(
                    &auth_data[auth_data.len() - expected_extension_cbor.len()..auth_data.len()],
                    expected_extension_cbor
                );
                assert!(ep_att.is_none());
                assert_eq!(att_stmt.alg, SignatureAlgorithm::Es256 as i64);
                assert_eq!(large_blob_key, &None);
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_get_info() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        let info_reponse =
            ctap_state.process_command(&mut env, &[0x04], DUMMY_CHANNEL, CtapInstant::new(0));

        let expected_cbor = cbor_map_options! {
             0x01 => cbor_array_vec![vec![
                    #[cfg(feature = "with_ctap1")]
                    String::from(U2F_VERSION_STRING),
                    String::from(FIDO2_VERSION_STRING),
                    String::from(FIDO2_1_VERSION_STRING),
                ]],
            0x02 => cbor_array![
                    String::from("hmac-secret"),
                    String::from("credProtect"),
                    String::from("minPinLength"),
                    String::from("credBlob"),
                    String::from("largeBlobKey"),
                ],
            0x03 => storage::aaguid(&mut env).unwrap(),
            0x04 => cbor_map_options! {
                "ep" => env.customization().enterprise_attestation_mode().map(|_| false),
                "rk" => true,
                "up" => true,
                "alwaysUv" => false,
                "credMgmt" => true,
                "authnrCfg" => true,
                "clientPin" => false,
                "largeBlobs" => true,
                "pinUvAuthToken" => true,
                "setMinPINLength" => true,
                "makeCredUvNotRqd" => true,
            },
            0x05 => env.customization().max_msg_size() as u64,
            0x06 => cbor_array![2, 1],
            0x07 => env.customization().max_credential_count_in_list().map(|c| c as u64),
            0x08 => MAX_CREDENTIAL_ID_SIZE as u64,
            0x09 => cbor_array!["usb"],
            0x0A => cbor_array_vec!(SUPPORTED_CRED_PARAMS.to_vec()),
            0x0B => env.customization().max_large_blob_array_size() as u64,
            0x0C => false,
            0x0D => storage::min_pin_length(&mut env).unwrap() as u64,
            0x0E => 0,
            0x0F => env.customization().max_cred_blob_length() as u64,
            0x10 => env.customization().max_rp_ids_length() as u64,
            0x14 => storage::remaining_credentials(&mut env).unwrap() as u64,
        };

        let mut response_cbor = vec![0x00];
        assert!(cbor_write(expected_cbor, &mut response_cbor).is_ok());
        assert_eq!(info_reponse, response_cbor);
    }

    #[test]
    fn test_get_info_no_pin_protocol_v1() {
        let mut env = TestEnv::new();
        env.customization_mut().set_allows_pin_protocol_v1(false);
        let ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        let info_response = ctap_state.process_get_info(&mut env).unwrap();
        match info_response {
            ResponseData::AuthenticatorGetInfo(response) => {
                assert_eq!(
                    response.pin_protocols,
                    Some(vec![PinUvAuthProtocol::V2 as u64])
                );
            }
            _ => panic!("Invalid response type"),
        }
    }

    fn create_minimal_make_credential_parameters() -> AuthenticatorMakeCredentialParameters {
        let client_data_hash = vec![0xCD];
        let rp = PublicKeyCredentialRpEntity {
            rp_id: String::from("example.com"),
            rp_name: None,
            rp_icon: None,
        };
        let user = PublicKeyCredentialUserEntity {
            user_id: vec![0x1D],
            user_name: None,
            user_display_name: None,
            user_icon: None,
        };
        let pub_key_cred_params = vec![ES256_CRED_PARAM];
        let options = MakeCredentialOptions {
            rk: true,
            uv: false,
        };
        AuthenticatorMakeCredentialParameters {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list: None,
            extensions: MakeCredentialExtensions::default(),
            options,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
            enterprise_attestation: None,
        }
    }

    fn create_make_credential_parameters_with_exclude_list(
        excluded_credential_id: &[u8],
    ) -> AuthenticatorMakeCredentialParameters {
        let excluded_credential_descriptor = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: excluded_credential_id.to_vec(),
            transports: None,
        };
        let exclude_list = Some(vec![excluded_credential_descriptor]);
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.exclude_list = exclude_list;
        make_credential_params
    }

    fn create_make_credential_parameters_with_cred_protect_policy(
        policy: CredentialProtectionPolicy,
    ) -> AuthenticatorMakeCredentialParameters {
        let extensions = MakeCredentialExtensions {
            cred_protect: Some(policy),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        make_credential_params
    }

    fn parse_credential_id_from_non_resident_make_credential_response(
        env: &mut impl Env,
        make_credential_response: ResponseData,
    ) -> Vec<u8> {
        match make_credential_response {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                let auth_data = make_credential_response.auth_data;
                let offset = 37 + storage::aaguid(env).unwrap().len();
                assert_eq!(auth_data[offset], 0x00);
                assert_eq!(auth_data[offset + 1] as usize, CBOR_CREDENTIAL_ID_SIZE);
                auth_data[offset + 2..offset + 2 + CBOR_CREDENTIAL_ID_SIZE].to_vec()
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_resident_process_make_credential() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        check_make_response(
            &make_credential_response,
            0x41,
            &storage::aaguid(&mut env).unwrap(),
            0x20,
            &[],
        );
    }

    #[test]
    fn test_non_resident_process_make_credential() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        check_make_response(
            &make_credential_response,
            0x41,
            &storage::aaguid(&mut env).unwrap(),
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &[],
        );
    }

    #[test]
    fn test_process_make_credential_unsupported_algorithm() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.pub_key_cred_params = vec![];
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        );
    }

    #[test]
    fn test_process_make_credential_credential_excluded() {
        let mut env = TestEnv::new();
        let excluded_private_key = PrivateKey::new_ecdsa(&mut env);
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let excluded_credential_id = vec![0x01, 0x23, 0x45, 0x67];
        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&excluded_credential_id);
        let excluded_credential_source = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: excluded_credential_id,
            private_key: excluded_private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        };
        assert!(storage::store_credential(&mut env, excluded_credential_source).is_ok());

        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );
    }

    #[test]
    fn test_process_make_credential_credential_with_cred_protect() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        let credential_id = stored_credential.credential_id;
        assert_eq!(stored_credential.cred_protect_policy, Some(test_policy));

        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        let credential_id = stored_credential.credential_id;
        assert_eq!(stored_credential.cred_protect_policy, Some(test_policy));

        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
    }

    #[test]
    fn test_non_resident_process_make_credential_credential_with_cred_protect() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
    }

    #[test]
    fn test_process_make_credential_hmac_secret() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        let expected_extension_cbor = [
            0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0xF5,
        ];
        check_make_response(
            &make_credential_response,
            0xC1,
            &storage::aaguid(&mut env).unwrap(),
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_hmac_secret_resident_key() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        let expected_extension_cbor = [
            0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0xF5,
        ];
        check_make_response(
            &make_credential_response,
            0xC1,
            &storage::aaguid(&mut env).unwrap(),
            0x20,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_min_pin_length() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        // First part: The extension is ignored, since the RP ID is not on the list.
        let extensions = MakeCredentialExtensions {
            min_pin_length: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_make_response(
            &make_credential_response,
            0x41,
            &storage::aaguid(&mut env).unwrap(),
            0x20,
            &[],
        );

        // Second part: The extension is used.
        assert_eq!(
            storage::set_min_pin_length_rp_ids(&mut env, vec!["example.com".to_string()]),
            Ok(())
        );

        let extensions = MakeCredentialExtensions {
            min_pin_length: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x6C, 0x6D, 0x69, 0x6E, 0x50, 0x69, 0x6E, 0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68,
            0x04,
        ];
        check_make_response(
            &make_credential_response,
            0xC1,
            &storage::aaguid(&mut env).unwrap(),
            0x20,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_cred_blob_ok() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0xF5,
        ];
        check_make_response(
            &make_credential_response,
            0xC1,
            &storage::aaguid(&mut env).unwrap(),
            0x20,
            &expected_extension_cbor,
        );

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.cred_blob, Some(vec![0xCB]));
    }

    #[test]
    fn test_process_make_credential_cred_blob_too_big() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB; env.customization().max_cred_blob_length() + 1]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0xF4,
        ];
        check_make_response(
            &make_credential_response,
            0xC1,
            &storage::aaguid(&mut env).unwrap(),
            0x20,
            &expected_extension_cbor,
        );

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.cred_blob, None);
    }

    #[test]
    fn test_process_make_credential_large_blob_key() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let extensions = MakeCredentialExtensions {
            large_blob_key: Some(true),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let large_blob_key = match make_credential_response.unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                make_credential_response.large_blob_key.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        assert_eq!(large_blob_key.len(), 32);

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.large_blob_key.unwrap(), large_blob_key);
    }

    fn test_helper_process_make_credential_with_pin_and_uv(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let mut env = TestEnv::new();
        let key_agreement_key = crypto::ecdh::SecKey::gensk(env.rng());
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let client_pin =
            ClientPin::new_test(key_agreement_key, pin_uv_auth_token, pin_uv_auth_protocol);

        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        ctap_state.client_pin = client_pin;
        storage::set_pin(&mut env, &[0x88; 16], 4).unwrap();

        let client_data_hash = [0xCD];
        let pin_uv_auth_param = authenticate_pin_uv_auth_token(
            &pin_uv_auth_token,
            &client_data_hash,
            pin_uv_auth_protocol,
        );
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.uv = true;
        make_credential_params.pin_uv_auth_param = Some(pin_uv_auth_param);
        make_credential_params.pin_uv_auth_protocol = Some(pin_uv_auth_protocol);
        let make_credential_response = ctap_state.process_make_credential(
            &mut env,
            make_credential_params.clone(),
            DUMMY_CHANNEL,
        );

        check_make_response(
            &make_credential_response,
            0x45,
            &storage::aaguid(&mut env).unwrap(),
            0x20,
            &[],
        );

        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        )
    }

    #[test]
    fn test_process_make_credential_with_pin_and_uv_v1() {
        test_helper_process_make_credential_with_pin_and_uv(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_make_credential_with_pin_and_uv_v2() {
        test_helper_process_make_credential_with_pin_and_uv(PinUvAuthProtocol::V2);
    }

    #[test]
    fn test_non_resident_process_make_credential_with_pin() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        storage::set_pin(&mut env, &[0x88; 16], 4).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        check_make_response(
            &make_credential_response,
            0x41,
            &storage::aaguid(&mut env).unwrap(),
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &[],
        );
    }

    #[test]
    fn test_resident_process_make_credential_with_pin() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        storage::set_pin(&mut env, &[0x88; 16], 4).unwrap();

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
        );
    }

    #[test]
    fn test_process_make_credential_with_pin_always_uv() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        storage::toggle_always_uv(&mut env).unwrap();
        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
        );

        storage::set_pin(&mut env, &[0x88; 16], 4).unwrap();
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.pin_uv_auth_param = Some(vec![0xA4; 16]);
        make_credential_params.pin_uv_auth_protocol = Some(PinUvAuthProtocol::V1);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    fn check_ep(make_credential_response: Result<ResponseData, Ctap2StatusCode>, has_ep: bool) {
        let ep_att = if has_ep { Some(true) } else { None };
        match make_credential_response.unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                assert_eq!(make_credential_response.ep_att, ep_att);
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_process_make_credential_with_enterprise_attestation_vendor_facilitated() {
        let mut env = TestEnv::new();
        env.customization_mut().setup_enterprise_attestation(
            Some(EnterpriseAttestationMode::VendorFacilitated),
            Some(vec!["example.com".to_string()]),
        );

        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        test_helpers::enable_enterprise_attestation(&mut ctap_state, &mut env).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        make_credential_params.rp = PublicKeyCredentialRpEntity {
            rp_id: "counter-example.com".to_string(),
            rp_name: None,
            rp_icon: None,
        };
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, false);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        make_credential_params.rp = PublicKeyCredentialRpEntity {
            rp_id: "counter-example.com".to_string(),
            rp_name: None,
            rp_icon: None,
        };
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, false);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);
    }

    #[test]
    fn test_process_make_credential_with_enterprise_attestation_platform_managed() {
        let mut env = TestEnv::new();
        env.customization_mut().setup_enterprise_attestation(
            Some(EnterpriseAttestationMode::PlatformManaged),
            Some(vec!["example.com".to_string()]),
        );
        assert!(customization::is_valid(env.customization()));

        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        test_helpers::enable_enterprise_attestation(&mut ctap_state, &mut env).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        make_credential_params.rp = PublicKeyCredentialRpEntity {
            rp_id: "counter-example.com".to_string(),
            rp_name: None,
            rp_icon: None,
        };
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, false);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);
    }

    #[test]
    fn test_process_make_credential_with_enterprise_attestation_invalid() {
        let mut env = TestEnv::new();
        env.customization_mut()
            .setup_enterprise_attestation(Some(EnterpriseAttestationMode::PlatformManaged), None);

        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        test_helpers::enable_enterprise_attestation(&mut ctap_state, &mut env).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(3);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION)
        );
    }

    #[test]
    fn test_process_make_credential_cancelled() {
        let mut env = TestEnv::new();
        env.user_presence().set(|| Err(UserPresenceError::Canceled));
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    fn check_assertion_response_with_user(
        response: Result<ResponseData, Ctap2StatusCode>,
        expected_user: Option<PublicKeyCredentialUserEntity>,
        flags: u8,
        signature_counter: u32,
        expected_number_of_credentials: Option<u64>,
        expected_extension_cbor: &[u8],
    ) {
        let assertion_response = match response.unwrap() {
            ResponseData::AuthenticatorGetAssertion(r) => r,
            ResponseData::AuthenticatorGetNextAssertion(r) => r,
            _ => panic!("Invalid response type"),
        };
        let AuthenticatorGetAssertionResponse {
            auth_data,
            user,
            number_of_credentials,
            ..
        } = assertion_response;
        let mut expected_auth_data = vec![
            0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80, 0x34,
            0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2, 0x12, 0x55,
            0x86, 0xCE, 0x19, 0x47, flags, 0x00, 0x00, 0x00, 0x00,
        ];
        let signature_counter_position = expected_auth_data.len() - 4;
        BigEndian::write_u32(
            &mut expected_auth_data[signature_counter_position..],
            signature_counter,
        );
        expected_auth_data.extend(expected_extension_cbor);
        assert_eq!(auth_data, expected_auth_data);
        assert_eq!(user, expected_user);
        assert_eq!(number_of_credentials, expected_number_of_credentials);
    }

    fn check_assertion_response_with_extension(
        response: Result<ResponseData, Ctap2StatusCode>,
        expected_user_id: Option<Vec<u8>>,
        signature_counter: u32,
        expected_number_of_credentials: Option<u64>,
        expected_extension_cbor: &[u8],
    ) {
        let expected_user = expected_user_id.map(|user_id| PublicKeyCredentialUserEntity {
            user_id,
            user_name: None,
            user_display_name: None,
            user_icon: None,
        });
        check_assertion_response_with_user(
            response,
            expected_user,
            0x80,
            signature_counter,
            expected_number_of_credentials,
            expected_extension_cbor,
        );
    }

    fn check_assertion_response(
        response: Result<ResponseData, Ctap2StatusCode>,
        expected_user_id: Vec<u8>,
        signature_counter: u32,
        expected_number_of_credentials: Option<u64>,
    ) {
        let expected_user = PublicKeyCredentialUserEntity {
            user_id: expected_user_id,
            user_name: None,
            user_display_name: None,
            user_icon: None,
        };
        check_assertion_response_with_user(
            response,
            Some(expected_user),
            0x00,
            signature_counter,
            expected_number_of_credentials,
            &[],
        );
    }

    #[test]
    fn test_resident_process_get_assertion() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let make_credential_params = create_minimal_make_credential_parameters();
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        let signature_counter = storage::global_signature_counter(&mut env).unwrap();
        check_assertion_response(get_assertion_response, vec![0x1D], signature_counter, None);
    }

    fn get_assertion_hmac_secret_params(
        key_agreement_key: crypto::ecdh::SecKey,
        key_agreement_response: ResponseData,
        credential_id: Option<Vec<u8>>,
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) -> AuthenticatorGetAssertionParameters {
        let mut env = TestEnv::new();
        let platform_public_key = key_agreement_key.genpk();
        let public_key = match key_agreement_response {
            ResponseData::AuthenticatorClientPin(Some(client_pin_response)) => {
                client_pin_response.key_agreement.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        let pin_protocol = PinProtocol::new_test(key_agreement_key, [0x91; 32]);
        let shared_secret = pin_protocol
            .decapsulate(public_key, pin_uv_auth_protocol)
            .unwrap();

        let salt = vec![0x01; 32];
        let salt_enc = shared_secret.as_ref().encrypt(env.rng(), &salt).unwrap();
        let salt_auth = shared_secret.authenticate(&salt_enc);
        let hmac_secret_input = GetAssertionHmacSecretInput {
            key_agreement: CoseKey::from(platform_public_key),
            salt_enc,
            salt_auth,
            pin_uv_auth_protocol,
        };
        let get_extensions = GetAssertionExtensions {
            hmac_secret: Some(hmac_secret_input),
            ..Default::default()
        };

        let credential_descriptor = credential_id.map(|key_id| PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id,
            transports: None,
        });
        let allow_list = credential_descriptor.map(|c| vec![c]);
        AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list,
            extensions: get_extensions,
            options: GetAssertionOptions {
                up: true,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        }
    }

    fn test_helper_process_get_assertion_hmac_secret(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let mut env = TestEnv::new();
        let key_agreement_key = crypto::ecdh::SecKey::gensk(env.rng());
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let make_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        make_credential_params.extensions = make_extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );

        let client_pin_params = AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            key_agreement: None,
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            permissions_rp_id: None,
        };
        let key_agreement_response =
            ctap_state
                .client_pin
                .process_command(&mut env, client_pin_params, CtapInstant::new(0));
        let get_assertion_params = get_assertion_hmac_secret_params(
            key_agreement_key,
            key_agreement_response.unwrap(),
            Some(credential_id),
            pin_uv_auth_protocol,
        );
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert!(get_assertion_response.is_ok());
    }

    #[test]
    fn test_process_get_assertion_hmac_secret_v1() {
        test_helper_process_get_assertion_hmac_secret(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_assertion_hmac_secret_v2() {
        test_helper_process_get_assertion_hmac_secret(PinUvAuthProtocol::V2);
    }

    fn test_helper_resident_process_get_assertion_hmac_secret(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let mut env = TestEnv::new();
        let key_agreement_key = crypto::ecdh::SecKey::gensk(env.rng());
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let make_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = make_extensions;
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());

        let client_pin_params = AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            key_agreement: None,
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            permissions_rp_id: None,
        };
        let key_agreement_response =
            ctap_state
                .client_pin
                .process_command(&mut env, client_pin_params, CtapInstant::new(0));
        let get_assertion_params = get_assertion_hmac_secret_params(
            key_agreement_key,
            key_agreement_response.unwrap(),
            None,
            pin_uv_auth_protocol,
        );
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert!(get_assertion_response.is_ok());
    }

    #[test]
    fn test_process_resident_get_assertion_hmac_secret_v1() {
        test_helper_resident_process_get_assertion_hmac_secret(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_resident_process_get_assertion_hmac_secret_v2() {
        test_helper_resident_process_get_assertion_hmac_secret(PinUvAuthProtocol::V2);
    }

    #[test]
    fn test_resident_process_get_assertion_with_cred_protect() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id.clone(),
            transports: None,
        };
        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: credential_id.clone(),
            private_key: private_key.clone(),
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: Some(
                CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
            ),
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc.clone()]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        let signature_counter = storage::global_signature_counter(&mut env).unwrap();
        check_assertion_response(get_assertion_response, vec![0x1D], signature_counter, None);

        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationRequired),
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );
    }

    #[test]
    fn test_non_resident_process_get_assertion_with_cred_protect() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id,
            transports: None,
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert!(get_assertion_response.is_ok());

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id,
            transports: None,
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );
    }

    #[test]
    fn test_process_get_assertion_with_cred_blob() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: Some(vec![0xCB]),
            large_blob_key: None,
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let extensions = GetAssertionExtensions {
            cred_blob: true,
            ..Default::default()
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        let signature_counter = storage::global_signature_counter(&mut env).unwrap();
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0x41, 0xCB,
        ];
        check_assertion_response_with_extension(
            get_assertion_response,
            Some(vec![0x1D]),
            signature_counter,
            None,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_non_resident_process_get_assertion_with_cred_blob() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0xF5,
        ];
        check_make_response(
            &make_credential_response,
            0xC1,
            &storage::aaguid(&mut env).unwrap(),
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &expected_extension_cbor,
        );

        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id,
            transports: None,
        };
        let extensions = GetAssertionExtensions {
            cred_blob: true,
            ..Default::default()
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        let signature_counter = storage::global_signature_counter(&mut env).unwrap();
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0x41, 0xCB,
        ];
        check_assertion_response_with_extension(
            get_assertion_response,
            None,
            signature_counter,
            None,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_get_assertion_with_large_blob_key() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: Some(vec![0x1C; 32]),
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let extensions = GetAssertionExtensions {
            large_blob_key: Some(true),
            ..Default::default()
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        let large_blob_key = match get_assertion_response.unwrap() {
            ResponseData::AuthenticatorGetAssertion(get_assertion_response) => {
                get_assertion_response.large_blob_key.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        assert_eq!(large_blob_key, vec![0x1C; 32]);
    }

    fn test_helper_process_get_next_assertion_two_credentials_with_uv(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let mut env = TestEnv::new();
        let key_agreement_key = crypto::ecdh::SecKey::gensk(env.rng());
        let pin_uv_auth_token = [0x88; 32];
        let client_pin =
            ClientPin::new_test(key_agreement_key, pin_uv_auth_token, pin_uv_auth_protocol);

        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let mut make_credential_params = create_minimal_make_credential_parameters();
        let user1 = PublicKeyCredentialUserEntity {
            user_id: vec![0x01],
            user_name: Some("user1".to_string()),
            user_display_name: Some("User One".to_string()),
            user_icon: Some("icon1".to_string()),
        };
        make_credential_params.user = user1.clone();
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        let user2 = PublicKeyCredentialUserEntity {
            user_id: vec![0x02],
            user_name: Some("user2".to_string()),
            user_display_name: Some("User Two".to_string()),
            user_icon: Some("icon2".to_string()),
        };
        make_credential_params.user = user2.clone();
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());

        ctap_state.client_pin = client_pin;
        // The PIN length is outside of the test scope and most likely incorrect.
        storage::set_pin(&mut env, &[0u8; 16], 4).unwrap();
        let client_data_hash = vec![0xCD];
        let pin_uv_auth_param = authenticate_pin_uv_auth_token(
            &pin_uv_auth_token,
            &client_data_hash,
            pin_uv_auth_protocol,
        );

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash,
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: true,
            },
            pin_uv_auth_param: Some(pin_uv_auth_param),
            pin_uv_auth_protocol: Some(pin_uv_auth_protocol),
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        let signature_counter = storage::global_signature_counter(&mut env).unwrap();
        check_assertion_response_with_user(
            get_assertion_response,
            Some(user2),
            0x04,
            signature_counter,
            Some(2),
            &[],
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        check_assertion_response_with_user(
            get_assertion_response,
            Some(user1),
            0x04,
            signature_counter,
            None,
            &[],
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_get_next_assertion_two_credentials_with_uv_v1() {
        test_helper_process_get_next_assertion_two_credentials_with_uv(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_next_assertion_two_credentials_with_uv_v2() {
        test_helper_process_get_next_assertion_two_credentials_with_uv(PinUvAuthProtocol::V2);
    }

    #[test]
    fn test_process_get_next_assertion_three_credentials_no_uv() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x01];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x02];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x03];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        let signature_counter = storage::global_signature_counter(&mut env).unwrap();
        check_assertion_response(
            get_assertion_response,
            vec![0x03],
            signature_counter,
            Some(3),
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        check_assertion_response(get_assertion_response, vec![0x02], signature_counter, None);

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        check_assertion_response(get_assertion_response, vec![0x01], signature_counter, None);

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_get_next_assertion_not_allowed() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x01];
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x02];
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert!(get_assertion_response.is_ok());

        // This is a MakeCredential command.
        let mut command_cbor = vec![0x01];
        let cbor_value = cbor_map! {
            1 => vec![0xCD; 16],
            2 => cbor_map! {
                "id" => "example.com",
            },
            3 => cbor_map! {
                "id" => vec![0x1D, 0x1D, 0x1D, 0x1D],
            },
            4 => cbor_array![ES256_CRED_PARAM],
        };
        assert!(cbor_write(cbor_value, &mut command_cbor).is_ok());
        ctap_state.process_command(&mut env, &command_cbor, DUMMY_CHANNEL, CtapInstant::new(0));

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_reset() {
        let mut env = TestEnv::new();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let credential_id = vec![0x01, 0x23, 0x45, 0x67];
        let credential_source = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        };
        assert!(storage::store_credential(&mut env, credential_source).is_ok());
        assert!(storage::count_credentials(&mut env).unwrap() > 0);

        let reset_reponse =
            ctap_state.process_command(&mut env, &[0x07], DUMMY_CHANNEL, CtapInstant::new(0));
        let expected_response = vec![0x00];
        assert_eq!(reset_reponse, expected_response);
        assert!(storage::count_credentials(&mut env).unwrap() == 0);
    }

    #[test]
    fn test_process_reset_cancelled() {
        let mut env = TestEnv::new();
        env.user_presence().set(|| Err(UserPresenceError::Canceled));
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let reset_reponse = ctap_state.process_reset(&mut env, DUMMY_CHANNEL);

        assert_eq!(
            reset_reponse,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    #[test]
    fn test_process_reset_not_first() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        // This is a GetNextAssertion command.
        ctap_state.process_command(&mut env, &[0x08], DUMMY_CHANNEL, CtapInstant::new(0));

        let reset_reponse = ctap_state.process_reset(&mut env, DUMMY_CHANNEL);
        assert_eq!(reset_reponse, Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED));
    }

    #[test]
    fn test_process_credential_management_unknown_subcommand() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        // The subcommand 0xEE does not exist.
        let reponse = ctap_state.process_command(
            &mut env,
            &[0x0A, 0xA1, 0x01, 0x18, 0xEE],
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        let expected_response = vec![Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND as u8];
        assert_eq!(reponse, expected_response);
    }

    #[test]
    fn test_process_unknown_command() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        // This command does not exist.
        let reponse =
            ctap_state.process_command(&mut env, &[0xDF], DUMMY_CHANNEL, CtapInstant::new(0));
        let expected_response = vec![Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND as u8];
        assert_eq!(reponse, expected_response);
    }

    #[test]
    fn test_signature_counter() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let mut last_counter = storage::global_signature_counter(&mut env).unwrap();
        assert!(last_counter > 0);
        for _ in 0..100 {
            assert!(ctap_state
                .increment_global_signature_counter(&mut env)
                .is_ok());
            let next_counter = storage::global_signature_counter(&mut env).unwrap();
            assert!(next_counter > last_counter);
            last_counter = next_counter;
        }
    }

    #[test]
    fn test_vendor_configure() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        // Nothing should be configured at the beginning
        let response = ctap_state.process_vendor_configure(
            &mut env,
            AuthenticatorVendorConfigureParameters {
                lockdown: false,
                attestation_material: None,
            },
            DUMMY_CHANNEL,
        );
        assert_eq!(
            response,
            Ok(ResponseData::AuthenticatorVendorConfigure(
                AuthenticatorVendorConfigureResponse {
                    cert_programmed: false,
                    pkey_programmed: false,
                }
            ))
        );

        // Inject dummy values
        let dummy_key = [0x41u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH];
        let dummy_cert = [0xddu8; 20];
        let response = ctap_state.process_vendor_configure(
            &mut env,
            AuthenticatorVendorConfigureParameters {
                lockdown: false,
                attestation_material: Some(AuthenticatorAttestationMaterial {
                    certificate: dummy_cert.to_vec(),
                    private_key: dummy_key,
                }),
            },
            DUMMY_CHANNEL,
        );
        assert_eq!(
            response,
            Ok(ResponseData::AuthenticatorVendorConfigure(
                AuthenticatorVendorConfigureResponse {
                    cert_programmed: true,
                    pkey_programmed: true,
                }
            ))
        );
        assert_eq!(
            env.attestation_store().get(&attestation_store::Id::Batch),
            Ok(Some(Attestation {
                private_key: dummy_key,
                certificate: dummy_cert.to_vec(),
            }))
        );

        // Try to inject other dummy values and check that initial values are retained.
        let other_dummy_key = [0x44u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH];
        let response = ctap_state.process_vendor_configure(
            &mut env,
            AuthenticatorVendorConfigureParameters {
                lockdown: false,
                attestation_material: Some(AuthenticatorAttestationMaterial {
                    certificate: dummy_cert.to_vec(),
                    private_key: other_dummy_key,
                }),
            },
            DUMMY_CHANNEL,
        );
        assert_eq!(
            response,
            Ok(ResponseData::AuthenticatorVendorConfigure(
                AuthenticatorVendorConfigureResponse {
                    cert_programmed: true,
                    pkey_programmed: true,
                }
            ))
        );
        assert_eq!(
            env.attestation_store().get(&attestation_store::Id::Batch),
            Ok(Some(Attestation {
                private_key: dummy_key,
                certificate: dummy_cert.to_vec(),
            }))
        );

        // Now try to lock the device
        let response = ctap_state.process_vendor_configure(
            &mut env,
            AuthenticatorVendorConfigureParameters {
                lockdown: true,
                attestation_material: None,
            },
            DUMMY_CHANNEL,
        );
        assert_eq!(
            response,
            Ok(ResponseData::AuthenticatorVendorConfigure(
                AuthenticatorVendorConfigureResponse {
                    cert_programmed: true,
                    pkey_programmed: true,
                }
            ))
        );
    }

    #[test]
    fn test_vendor_upgrade() {
        // The test partition storage has size 0x40000.
        // The test metadata storage has size 0x1000.
        // The test identifier matches partition B.
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        const METADATA_LEN: usize = 0x1000;
        let metadata = vec![0xFF; METADATA_LEN];
        let metadata_hash = Sha256::hash(&metadata);
        let data = vec![0xFF; 0x1000];
        let hash = Sha256::hash(&data);

        // Write to partition.
        let response = ctap_state.process_vendor_upgrade(
            &mut env,
            AuthenticatorVendorUpgradeParameters {
                offset: 0x20000,
                data: data.clone(),
                hash,
            },
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorVendorUpgrade));

        // TestEnv doesn't check the metadata, test its parser in your Env.
        let response = ctap_state.process_vendor_upgrade(
            &mut env,
            AuthenticatorVendorUpgradeParameters {
                offset: 0,
                data: metadata.clone(),
                hash: metadata_hash,
            },
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorVendorUpgrade));

        // TestEnv doesn't check the metadata, test its parser in your Env.
        let response = ctap_state.process_vendor_upgrade(
            &mut env,
            AuthenticatorVendorUpgradeParameters {
                offset: METADATA_LEN,
                data: data.clone(),
                hash,
            },
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorVendorUpgrade));

        // Write metadata of a wrong size.
        let response = ctap_state.process_vendor_upgrade(
            &mut env,
            AuthenticatorVendorUpgradeParameters {
                offset: 0,
                data: metadata[..METADATA_LEN - 1].to_vec(),
                hash: metadata_hash,
            },
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE));

        // Write outside of the partition.
        let response = ctap_state.process_vendor_upgrade(
            &mut env,
            AuthenticatorVendorUpgradeParameters {
                offset: 0x41000,
                data: data.clone(),
                hash,
            },
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER));

        // Write a bad hash.
        let response = ctap_state.process_vendor_upgrade(
            &mut env,
            AuthenticatorVendorUpgradeParameters {
                offset: 0x20000,
                data,
                hash: [0xEE; 32],
            },
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE));
    }

    #[test]
    fn test_vendor_upgrade_no_second_partition() {
        let mut env = TestEnv::new();
        env.disable_upgrade_storage();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let data = vec![0xFF; 0x1000];
        let hash = Sha256::hash(&data);
        let response = ctap_state.process_vendor_upgrade(
            &mut env,
            AuthenticatorVendorUpgradeParameters {
                offset: 0,
                data,
                hash,
            },
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND));
    }

    #[test]
    fn test_vendor_upgrade_info() {
        let mut env = TestEnv::new();
        let ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        let bundle_identifier = env.upgrade_storage().unwrap().bundle_identifier();

        let upgrade_info_reponse = ctap_state.process_vendor_upgrade_info(&mut env);
        assert_eq!(
            upgrade_info_reponse,
            Ok(ResponseData::AuthenticatorVendorUpgradeInfo(
                AuthenticatorVendorUpgradeInfoResponse {
                    info: bundle_identifier,
                }
            ))
        );
    }

    #[test]
    fn test_permission_timeout() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        // Write 2 credentials for later assertions.
        for i in 0..3 {
            let mut make_credential_params = create_minimal_make_credential_parameters();
            make_credential_params.user.user_id = vec![i as u8];
            assert!(ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok());
        }

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetAssertion(get_assertion_params),
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert!(get_assertion_response.is_ok());
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
            CtapInstant::new(0) + STATEFUL_COMMAND_TIMEOUT_DURATION - Milliseconds(1 as ClockInt),
        );
        assert!(get_next_assertion_response.is_ok());
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
            CtapInstant::new(0) + STATEFUL_COMMAND_TIMEOUT_DURATION + Milliseconds(1 as ClockInt),
        );
        assert_eq!(
            get_next_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_reset_timeout() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorReset,
            DUMMY_CHANNEL,
            CtapInstant::new(0) + RESET_TIMEOUT_DURATION + Milliseconds(1 as ClockInt),
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED));
    }

    #[test]
    fn test_credential_management_timeout() {
        let mut env = TestEnv::new();
        let key_agreement_key = crypto::ecdh::SecKey::gensk(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let client_pin =
            ClientPin::new_test(key_agreement_key, pin_uv_auth_token, PinUvAuthProtocol::V1);

        let private_key = PrivateKey::new_ecdsa(&mut env);
        let credential_source = PublicKeyCredentialSource {
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
        };

        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        ctap_state.client_pin = client_pin;

        for i in 0..3 {
            let mut credential = credential_source.clone();
            credential.rp_id = i.to_string();
            storage::store_credential(&mut env, credential).unwrap();
        }

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
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorCredentialManagement(cred_management_params),
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorCredentialManagement(_))
        ));

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorCredentialManagement(cred_management_params),
            DUMMY_CHANNEL,
            CtapInstant::new(0) + STATEFUL_COMMAND_TIMEOUT_DURATION - Milliseconds(1 as ClockInt),
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorCredentialManagement(_))
        ));

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorCredentialManagement(cred_management_params),
            DUMMY_CHANNEL,
            CtapInstant::new(0) + STATEFUL_COMMAND_TIMEOUT_DURATION + Milliseconds(1 as ClockInt),
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED));
    }

    #[test]
    fn test_check_user_presence() {
        // This TestEnv always returns successful user_presence checks.
        let mut env = TestEnv::new();
        let response = check_user_presence(&mut env, DUMMY_CHANNEL);
        assert!(matches!(response, Ok(_)));
    }

    #[test]
    fn test_check_user_presence_timeout() {
        // This will always return timeout.
        fn user_presence_timeout() -> UserPresenceResult {
            Err(UserPresenceError::Timeout)
        }

        let mut env = TestEnv::new();
        env.user_presence().set(user_presence_timeout);
        let response = check_user_presence(&mut env, DUMMY_CHANNEL);
        assert!(matches!(
            response,
            Err(Ctap2StatusCode::CTAP2_ERR_USER_ACTION_TIMEOUT)
        ));
    }

    #[test]
    fn test_channel_interleaving() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        const NEW_CHANNEL: Channel = Channel::MainHid([0xAA, 0xAA, 0xAA, 0xAA]);

        // Write 3 credentials for later assertions.
        for i in 0..3 {
            let mut make_credential_params = create_minimal_make_credential_parameters();
            make_credential_params.user.user_id = vec![i as u8];
            assert!(ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok());
        }

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetAssertion(get_assertion_params),
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert!(matches!(
            get_assertion_response,
            Ok(ResponseData::AuthenticatorGetAssertion(_))
        ));
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert!(get_next_assertion_response.is_ok());
        assert!(matches!(
            get_next_assertion_response,
            Ok(ResponseData::AuthenticatorGetNextAssertion(_))
        ));
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            NEW_CHANNEL,
            CtapInstant::new(0),
        );
        assert_eq!(
            get_next_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert_eq!(
            get_next_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_get_info_command() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetInfo,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorGetInfo(_))
        ));
        #[cfg(feature = "vendor_hid")]
        {
            let response = ctap_state.process_parsed_command(
                &mut env,
                Command::AuthenticatorGetInfo,
                VENDOR_CHANNEL,
                CtapInstant::new(0),
            );
            assert!(matches!(
                response,
                Ok(ResponseData::AuthenticatorGetInfo(_))
            ));
        }
    }

    #[test]
    #[cfg(feature = "vendor_hid")]
    fn test_vendor_hid_does_not_support_fido_command() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            VENDOR_CHANNEL,
            CtapInstant::new(0),
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND));
    }

    #[test]
    #[cfg(feature = "vendor_hid")]
    fn test_vendor_hid() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorVendorUpgradeInfo,
            VENDOR_CHANNEL,
            CtapInstant::new(0),
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorVendorUpgradeInfo(_))
        ));
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorVendorUpgradeInfo,
            DUMMY_CHANNEL,
            CtapInstant::new(0),
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND));
    }
}
