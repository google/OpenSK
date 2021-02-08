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
pub mod command;
mod config_command;
mod credential_management;
#[cfg(feature = "with_ctap1")]
mod ctap1;
pub mod data_formats;
pub mod hid;
mod key_material;
mod large_blobs;
mod pin_protocol_v1;
pub mod response;
pub mod status_code;
mod storage;
mod timed_permission;

use self::command::{
    AuthenticatorClientPinParameters, AuthenticatorGetAssertionParameters,
    AuthenticatorMakeCredentialParameters, AuthenticatorVendorConfigureParameters, Command,
    MAX_CREDENTIAL_COUNT_IN_LIST,
};
use self::config_command::process_config;
use self::credential_management::process_credential_management;
use self::data_formats::{
    AuthenticatorTransport, CoseKey, CredentialProtectionPolicy, EnterpriseAttestationMode,
    GetAssertionExtensions, PackedAttestationStatement, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameter, PublicKeyCredentialSource, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, SignatureAlgorithm,
};
use self::hid::ChannelID;
use self::large_blobs::{LargeBlobs, MAX_MSG_SIZE};
use self::pin_protocol_v1::{PinPermission, PinProtocolV1};
use self::response::{
    AuthenticatorGetAssertionResponse, AuthenticatorGetInfoResponse,
    AuthenticatorMakeCredentialResponse, AuthenticatorVendorResponse, ResponseData,
};
use self::status_code::Ctap2StatusCode;
use self::storage::{PersistentStore, MAX_LARGE_BLOB_ARRAY_SIZE, MAX_RP_IDS_LENGTH};
use self::timed_permission::TimedPermission;
#[cfg(feature = "with_ctap1")]
use self::timed_permission::U2fUserPresenceState;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use arrayref::array_ref;
use byteorder::{BigEndian, ByteOrder};
use cbor::cbor_map_options;
use core::convert::TryFrom;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
use crypto::cbc::{cbc_decrypt, cbc_encrypt};
use crypto::hmac::{hmac_256, verify_hmac_256};
use crypto::rng256::Rng256;
use crypto::sha256::Sha256;
use crypto::Hash256;
#[cfg(feature = "debug_ctap")]
use libtock_drivers::console::Console;
use libtock_drivers::crp;
use libtock_drivers::timer::{ClockValue, Duration};

// This flag enables or disables basic attestation for FIDO2. U2F is unaffected by
// this setting. The basic attestation uses the signing key configured with a
// vendor command as a batch key. If you turn batch attestation on, be aware that
// it is your responsibility to safely generate and store the key material. Also,
// the batches must have size of at least 100k authenticators before using new
// key material.
const USE_BATCH_ATTESTATION: bool = false;
// The signature counter is currently implemented as a global counter, if you set
// this flag to true. The spec strongly suggests to have per-credential-counters,
// but it means you can't have an infinite amount of credentials anymore. Also,
// since this is the only piece of information that needs writing often, we might
// need a flash storage friendly way to implement this feature. The implemented
// solution is a compromise to be compatible with U2F and not wasting storage.
const USE_SIGNATURE_COUNTER: bool = true;
pub const INITIAL_SIGNATURE_COUNTER: u32 = 1;
// This flag allows usage of enterprise attestation. For privacy reasons, it is
// disabled by default. You can choose between
// - EnterpriseAttestationMode::VendorFacilitated,
// - EnterpriseAttestationMode::PlatformManaged.
// For VendorFacilitated, choose an appriopriate ENTERPRISE_RP_ID_LIST.
// To enable the feature, send the subcommand enableEnterpriseAttestation in
// AuthenticatorConfig. An enterprise might want to customize the type of
// attestation that is used. OpenSK defaults to batch attestation. Configuring
// individual certificates then makes authenticators identifiable. Do NOT set
// USE_BATCH_ATTESTATION to true at the same time in this case! The code asserts
// that you don't use the same key material for batch and enterprise attestation.
// If you implement your own enterprise attestation mechanism, and you want batch
// attestation at the same time, proceed carefully and remove the assertion.
pub const ENTERPRISE_ATTESTATION_MODE: Option<EnterpriseAttestationMode> = None;
const ENTERPRISE_RP_ID_LIST: &[&str] = &[];
// Our credential ID consists of
// - 16 byte initialization vector for AES-256,
// - 32 byte ECDSA private key for the credential,
// - 32 byte relying party ID hashed with SHA256,
// - 32 byte HMAC-SHA256 over everything else.
pub const CREDENTIAL_ID_SIZE: usize = 112;
// Set this bit when checking user presence.
const UP_FLAG: u8 = 0x01;
// Set this bit when checking user verification.
const UV_FLAG: u8 = 0x04;
// Set this bit when performing attestation.
const AT_FLAG: u8 = 0x40;
// Set this bit when an extension is used.
const ED_FLAG: u8 = 0x80;

pub const TOUCH_TIMEOUT_MS: isize = 30000;
#[cfg(feature = "with_ctap1")]
const U2F_UP_PROMPT_TIMEOUT: Duration<isize> = Duration::from_ms(10000);
// TODO(kaczmarczyck) 2.1 allows Reset after Reset and 15 seconds?
const RESET_TIMEOUT_DURATION: Duration<isize> = Duration::from_ms(10000);
const STATEFUL_COMMAND_TIMEOUT_DURATION: Duration<isize> = Duration::from_ms(30000);

pub const FIDO2_VERSION_STRING: &str = "FIDO_2_0";
#[cfg(feature = "with_ctap1")]
pub const U2F_VERSION_STRING: &str = "U2F_V2";
// TODO(#106) change to final string when ready
pub const FIDO2_1_VERSION_STRING: &str = "FIDO_2_1_PRE";

// This is the currently supported PIN protocol version.
const PIN_PROTOCOL_VERSION: u64 = 1;

// We currently only support one algorithm for signatures: ES256.
// This algorithm is requested in MakeCredential and advertized in GetInfo.
pub const ES256_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::ES256,
};
// You can change this value to one of the following for more privacy.
// - Some(CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList)
// - Some(CredentialProtectionPolicy::UserVerificationRequired)
const DEFAULT_CRED_PROTECT: Option<CredentialProtectionPolicy> = None;
// Maximum size stored with the credBlob extension. Must be at least 32.
const MAX_CRED_BLOB_LENGTH: usize = 32;

// Checks the PIN protocol parameter against all supported versions.
pub fn check_pin_uv_auth_protocol(
    pin_uv_auth_protocol: Option<u64>,
) -> Result<(), Ctap2StatusCode> {
    match pin_uv_auth_protocol {
        Some(PIN_PROTOCOL_VERSION) => Ok(()),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID),
    }
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
pub struct StatefulPermission {
    permission: TimedPermission,
    command_type: Option<StatefulCommand>,
}

impl StatefulPermission {
    /// Creates the command state at device startup.
    ///
    /// Resets are only possible after a power cycle. Therefore, initialization
    /// means allowing Reset, and Reset cannot be granted later.
    pub fn new_reset(now: ClockValue) -> StatefulPermission {
        StatefulPermission {
            permission: TimedPermission::granted(now, RESET_TIMEOUT_DURATION),
            command_type: Some(StatefulCommand::Reset),
        }
    }

    /// Clears all permissions and state.
    pub fn clear(&mut self) {
        self.permission = TimedPermission::waiting();
        self.command_type = None;
    }

    /// Checks the permission timeout.
    pub fn check_command_permission(&mut self, now: ClockValue) -> Result<(), Ctap2StatusCode> {
        if self.permission.is_granted(now) {
            Ok(())
        } else {
            self.clear();
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        }
    }

    /// Gets a reference to the current command state, if any exists.
    pub fn get_command(&self) -> Result<&StatefulCommand, Ctap2StatusCode> {
        self.command_type
            .as_ref()
            .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
    }

    /// Sets a new command state, and starts a new clock for timeouts.
    pub fn set_command(&mut self, now: ClockValue, new_command_type: StatefulCommand) {
        match &new_command_type {
            // Reset is only allowed after a power cycle.
            StatefulCommand::Reset => unreachable!(),
            _ => {
                self.permission = TimedPermission::granted(now, STATEFUL_COMMAND_TIMEOUT_DURATION);
                self.command_type = Some(new_command_type);
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
pub struct CtapState<'a, R: Rng256, CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>>
{
    rng: &'a mut R,
    // A function to check user presence, ultimately returning true if user presence was detected,
    // false otherwise.
    check_user_presence: CheckUserPresence,
    persistent_store: PersistentStore,
    pin_protocol_v1: PinProtocolV1,
    #[cfg(feature = "with_ctap1")]
    pub u2f_up_state: U2fUserPresenceState,
    // The state initializes to Reset and its timeout, and never goes back to Reset.
    stateful_command_permission: StatefulPermission,
    large_blobs: LargeBlobs,
}

impl<'a, R, CheckUserPresence> CtapState<'a, R, CheckUserPresence>
where
    R: Rng256,
    CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>,
{
    pub fn new(
        rng: &'a mut R,
        check_user_presence: CheckUserPresence,
        now: ClockValue,
    ) -> CtapState<'a, R, CheckUserPresence> {
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(!USE_BATCH_ATTESTATION || ENTERPRISE_ATTESTATION_MODE.is_none());
        }

        let persistent_store = PersistentStore::new(rng);
        let pin_protocol_v1 = PinProtocolV1::new(rng);
        CtapState {
            rng,
            check_user_presence,
            persistent_store,
            pin_protocol_v1,
            #[cfg(feature = "with_ctap1")]
            u2f_up_state: U2fUserPresenceState::new(
                U2F_UP_PROMPT_TIMEOUT,
                Duration::from_ms(TOUCH_TIMEOUT_MS),
            ),
            stateful_command_permission: StatefulPermission::new_reset(now),
            large_blobs: LargeBlobs::new(),
        }
    }

    pub fn update_command_permission(&mut self, now: ClockValue) {
        // Ignore the result, just update.
        let _ = self
            .stateful_command_permission
            .check_command_permission(now);
    }

    pub fn increment_global_signature_counter(&mut self) -> Result<(), Ctap2StatusCode> {
        if USE_SIGNATURE_COUNTER {
            let increment = self.rng.gen_uniform_u32x8()[0] % 8 + 1;
            self.persistent_store
                .incr_global_signature_counter(increment)?;
        }
        Ok(())
    }

    // Encrypts the private key and relying party ID hash into a credential ID. Other
    // information, such as a user name, are not stored, because encrypted credential IDs
    // are used for credentials stored server-side. Also, we want the key handle to be
    // compatible with U2F.
    pub fn encrypt_key_handle(
        &mut self,
        private_key: crypto::ecdsa::SecKey,
        application: &[u8; 32],
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let master_keys = self.persistent_store.master_keys()?;
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&master_keys.encryption);
        let mut sk_bytes = [0; 32];
        private_key.to_bytes(&mut sk_bytes);
        let mut iv = [0; 16];
        iv.copy_from_slice(&self.rng.gen_uniform_u8x32()[..16]);

        let mut blocks = [[0u8; 16]; 4];
        blocks[0].copy_from_slice(&sk_bytes[..16]);
        blocks[1].copy_from_slice(&sk_bytes[16..]);
        blocks[2].copy_from_slice(&application[..16]);
        blocks[3].copy_from_slice(&application[16..]);
        cbc_encrypt(&aes_enc_key, iv, &mut blocks);

        let mut encrypted_id = Vec::with_capacity(0x70);
        encrypted_id.extend(&iv);
        for b in &blocks {
            encrypted_id.extend(b);
        }
        let id_hmac = hmac_256::<Sha256>(&master_keys.hmac, &encrypted_id[..]);
        encrypted_id.extend(&id_hmac);
        Ok(encrypted_id)
    }

    // Decrypts a credential ID and writes the private key into a PublicKeyCredentialSource.
    // None is returned if the HMAC test fails or the relying party does not match the
    // decrypted relying party ID hash.
    pub fn decrypt_credential_source(
        &self,
        credential_id: Vec<u8>,
        rp_id_hash: &[u8],
    ) -> Result<Option<PublicKeyCredentialSource>, Ctap2StatusCode> {
        if credential_id.len() != CREDENTIAL_ID_SIZE {
            return Ok(None);
        }
        let master_keys = self.persistent_store.master_keys()?;
        let payload_size = credential_id.len() - 32;
        if !verify_hmac_256::<Sha256>(
            &master_keys.hmac,
            &credential_id[..payload_size],
            array_ref![credential_id, payload_size, 32],
        ) {
            return Ok(None);
        }
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&master_keys.encryption);
        let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);
        let mut iv = [0; 16];
        iv.copy_from_slice(&credential_id[..16]);
        let mut blocks = [[0u8; 16]; 4];
        for i in 0..4 {
            blocks[i].copy_from_slice(&credential_id[16 * (i + 1)..16 * (i + 2)]);
        }

        cbc_decrypt(&aes_dec_key, iv, &mut blocks);
        let mut decrypted_sk = [0; 32];
        let mut decrypted_rp_id_hash = [0; 32];
        decrypted_sk[..16].clone_from_slice(&blocks[0]);
        decrypted_sk[16..].clone_from_slice(&blocks[1]);
        decrypted_rp_id_hash[..16].clone_from_slice(&blocks[2]);
        decrypted_rp_id_hash[16..].clone_from_slice(&blocks[3]);
        if rp_id_hash != decrypted_rp_id_hash {
            return Ok(None);
        }

        let sk_option = crypto::ecdsa::SecKey::from_bytes(&decrypted_sk);
        Ok(sk_option.map(|sk| PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key: sk,
            rp_id: String::from(""),
            user_handle: vec![],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        }))
    }

    pub fn process_command(
        &mut self,
        command_cbor: &[u8],
        cid: ChannelID,
        now: ClockValue,
    ) -> Vec<u8> {
        let cmd = Command::deserialize(command_cbor);
        #[cfg(feature = "debug_ctap")]
        writeln!(&mut Console::new(), "Received command: {:#?}", cmd).unwrap();
        match cmd {
            Ok(command) => {
                // Correct behavior between CTAP1 and CTAP2 isn't defined yet. Just a guess.
                #[cfg(feature = "with_ctap1")]
                {
                    self.u2f_up_state = U2fUserPresenceState::new(
                        U2F_UP_PROMPT_TIMEOUT,
                        Duration::from_ms(TOUCH_TIMEOUT_MS),
                    );
                }
                match (&command, self.stateful_command_permission.get_command()) {
                    (Command::AuthenticatorGetNextAssertion, Ok(StatefulCommand::GetAssertion(_)))
                    | (Command::AuthenticatorReset, Ok(StatefulCommand::Reset))
                    // AuthenticatorGetInfo still allows Reset.
                    | (Command::AuthenticatorGetInfo, Ok(StatefulCommand::Reset))
                    // AuthenticatorSelection still allows Reset.
                    | (Command::AuthenticatorSelection, Ok(StatefulCommand::Reset))
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
                let response = match command {
                    Command::AuthenticatorMakeCredential(params) => {
                        self.process_make_credential(params, cid)
                    }
                    Command::AuthenticatorGetAssertion(params) => {
                        self.process_get_assertion(params, cid, now)
                    }
                    Command::AuthenticatorGetNextAssertion => self.process_get_next_assertion(now),
                    Command::AuthenticatorGetInfo => self.process_get_info(),
                    Command::AuthenticatorClientPin(params) => self.process_client_pin(params),
                    Command::AuthenticatorReset => self.process_reset(cid, now),
                    Command::AuthenticatorCredentialManagement(params) => {
                        process_credential_management(
                            &mut self.persistent_store,
                            &mut self.stateful_command_permission,
                            &mut self.pin_protocol_v1,
                            params,
                            now,
                        )
                    }
                    Command::AuthenticatorSelection => self.process_selection(cid),
                    Command::AuthenticatorLargeBlobs(params) => self.large_blobs.process_command(
                        &mut self.persistent_store,
                        &mut self.pin_protocol_v1,
                        params,
                    ),
                    Command::AuthenticatorConfig(params) => process_config(
                        &mut self.persistent_store,
                        &mut self.pin_protocol_v1,
                        params,
                    ),
                    // Vendor specific commands
                    Command::AuthenticatorVendorConfigure(params) => {
                        self.process_vendor_configure(params, cid)
                    }
                };
                #[cfg(feature = "debug_ctap")]
                writeln!(&mut Console::new(), "Sending response: {:#?}", response).unwrap();
                match response {
                    Ok(response_data) => {
                        let mut response_vec = vec![0x00];
                        if let Some(value) = response_data.into() {
                            if !cbor::write(value, &mut response_vec) {
                                response_vec =
                                    vec![Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR as u8];
                            }
                        }
                        response_vec
                    }
                    Err(error_code) => vec![error_code as u8],
                }
            }
            Err(error_code) => vec![error_code as u8],
        }
    }

    fn pin_uv_auth_precheck(
        &mut self,
        pin_uv_auth_param: &Option<Vec<u8>>,
        pin_uv_auth_protocol: Option<u64>,
        cid: ChannelID,
    ) -> Result<(), Ctap2StatusCode> {
        if let Some(auth_param) = &pin_uv_auth_param {
            // This case was added in FIDO 2.1.
            if auth_param.is_empty() {
                (self.check_user_presence)(cid)?;
                if self.persistent_store.pin_hash()?.is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                } else {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }
            }

            check_pin_uv_auth_protocol(pin_uv_auth_protocol)
        } else {
            Ok(())
        }
    }

    fn process_make_credential(
        &mut self,
        make_credential_params: AuthenticatorMakeCredentialParameters,
        cid: ChannelID,
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

        self.pin_uv_auth_precheck(&pin_uv_auth_param, pin_uv_auth_protocol, cid)?;

        if !pub_key_cred_params.contains(&ES256_CRED_PARAM) {
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }

        let rp_id = rp.rp_id;
        let ep_att = if let Some(enterprise_attestation) = enterprise_attestation {
            let authenticator_mode =
                ENTERPRISE_ATTESTATION_MODE.ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
            if !self.persistent_store.enterprise_attestation()? {
                return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
            }
            match (
                EnterpriseAttestationMode::try_from(enterprise_attestation)?,
                authenticator_mode,
            ) {
                (
                    EnterpriseAttestationMode::PlatformManaged,
                    EnterpriseAttestationMode::PlatformManaged,
                ) => ENTERPRISE_RP_ID_LIST.contains(&rp_id.as_str()),
                _ => true,
            }
        } else {
            false
        };

        let mut cred_protect_policy = extensions.cred_protect;
        if cred_protect_policy.unwrap_or(CredentialProtectionPolicy::UserVerificationOptional)
            < DEFAULT_CRED_PROTECT.unwrap_or(CredentialProtectionPolicy::UserVerificationOptional)
        {
            cred_protect_policy = DEFAULT_CRED_PROTECT;
        }
        let min_pin_length = extensions.min_pin_length
            && self
                .persistent_store
                .min_pin_length_rp_ids()?
                .contains(&rp_id);
        // None for no input, false for invalid input, true for valid input.
        let has_cred_blob_output = extensions.cred_blob.is_some();
        let cred_blob = extensions
            .cred_blob
            .filter(|c| options.rk && c.len() <= MAX_CRED_BLOB_LENGTH);
        let cred_blob_output = if has_cred_blob_output {
            Some(cred_blob.is_some())
        } else {
            None
        };
        let has_extension_output = extensions.hmac_secret
            || cred_protect_policy.is_some()
            || min_pin_length
            || has_cred_blob_output;
        let large_blob_key = match (options.rk, extensions.large_blob_key) {
            (true, Some(true)) => Some(self.rng.gen_uniform_u8x32().to_vec()),
            _ => None,
        };

        let rp_id_hash = Sha256::hash(rp_id.as_bytes());
        if let Some(exclude_list) = exclude_list {
            for cred_desc in exclude_list {
                if self
                    .persistent_store
                    .find_credential(&rp_id, &cred_desc.key_id, pin_uv_auth_param.is_none())?
                    .is_some()
                    || self
                        .decrypt_credential_source(cred_desc.key_id, &rp_id_hash)?
                        .is_some()
                {
                    // Perform this check, so bad actors can't brute force exclude_list
                    // without user interaction.
                    (self.check_user_presence)(cid)?;
                    return Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED);
                }
            }
        }

        // MakeCredential always requires user presence.
        // User verification depends on the PIN auth inputs, which are checked here.
        let ed_flag = if has_extension_output { ED_FLAG } else { 0 };
        let flags = match pin_uv_auth_param {
            Some(pin_auth) => {
                if self.persistent_store.pin_hash()?.is_none() {
                    // Specification is unclear, could be CTAP2_ERR_INVALID_OPTION.
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                }
                if !self
                    .pin_protocol_v1
                    .verify_pin_auth_token(&client_data_hash, &pin_auth)
                {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
                }
                self.pin_protocol_v1
                    .has_permission(PinPermission::MakeCredential)?;
                self.pin_protocol_v1.ensure_rp_id_permission(&rp_id)?;
                UP_FLAG | UV_FLAG | AT_FLAG | ed_flag
            }
            None => {
                if self.persistent_store.pin_hash()?.is_some() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                }
                if options.uv {
                    return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
                }
                UP_FLAG | AT_FLAG | ed_flag
            }
        };

        (self.check_user_presence)(cid)?;

        let sk = crypto::ecdsa::SecKey::gensk(self.rng);
        let pk = sk.genpk();

        let credential_id = if options.rk {
            let random_id = self.rng.gen_uniform_u8x32().to_vec();
            let credential_source = PublicKeyCredentialSource {
                key_type: PublicKeyCredentialType::PublicKey,
                credential_id: random_id.clone(),
                private_key: sk.clone(),
                rp_id,
                user_handle: user.user_id,
                // This input is user provided, so we crop it to 64 byte for storage.
                // The UTF8 encoding is always preserved, so the string might end up shorter.
                user_display_name: user
                    .user_display_name
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                cred_protect_policy,
                creation_order: self.persistent_store.new_creation_order()?,
                user_name: user
                    .user_name
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                user_icon: user
                    .user_icon
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                cred_blob,
                large_blob_key: large_blob_key.clone(),
            };
            self.persistent_store.store_credential(credential_source)?;
            random_id
        } else {
            self.encrypt_key_handle(sk.clone(), &rp_id_hash)?
        };

        let mut auth_data = self.generate_auth_data(&rp_id_hash, flags)?;
        auth_data.extend(&self.persistent_store.aaguid()?);
        // The length is fixed to 0x20 or 0x70 and fits one byte.
        if credential_id.len() > 0xFF {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        auth_data.extend(vec![0x00, credential_id.len() as u8]);
        auth_data.extend(&credential_id);
        if !cbor::write(cbor::Value::from(CoseKey::from(pk)), &mut auth_data) {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        if has_extension_output {
            let hmac_secret_output = if extensions.hmac_secret {
                Some(true)
            } else {
                None
            };
            let min_pin_length_output = if min_pin_length {
                Some(self.persistent_store.min_pin_length()? as u64)
            } else {
                None
            };
            let extensions_output = cbor_map_options! {
                "hmac-secret" => hmac_secret_output,
                "credProtect" => cred_protect_policy,
                "minPinLength" => min_pin_length_output,
                "credBlob" => cred_blob_output,
            };
            if !cbor::write(extensions_output, &mut auth_data) {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
            }
        }

        let mut signature_data = auth_data.clone();
        signature_data.extend(client_data_hash);

        let (signature, x5c) = if USE_BATCH_ATTESTATION || ep_att {
            let attestation_private_key = self
                .persistent_store
                .attestation_private_key()?
                .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
            let attestation_key =
                crypto::ecdsa::SecKey::from_bytes(&attestation_private_key).unwrap();
            let attestation_certificate = self
                .persistent_store
                .attestation_certificate()?
                .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
            (
                attestation_key.sign_rfc6979::<crypto::sha256::Sha256>(&signature_data),
                Some(vec![attestation_certificate]),
            )
        } else {
            (
                sk.sign_rfc6979::<crypto::sha256::Sha256>(&signature_data),
                None,
            )
        };
        let attestation_statement = PackedAttestationStatement {
            alg: SignatureAlgorithm::ES256 as i64,
            sig: signature.to_asn1_der(),
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
        private_key: &crypto::ecdsa::SecKey,
        has_uv: bool,
    ) -> Result<[u8; 32], Ctap2StatusCode> {
        let mut private_key_bytes = [0u8; 32];
        private_key.to_bytes(&mut private_key_bytes);
        let key = self.persistent_store.cred_random_secret(has_uv)?;
        Ok(hmac_256::<Sha256>(&key, &private_key_bytes))
    }

    // Processes the input of a get_assertion operation for a given credential
    // and returns the correct Get(Next)Assertion response.
    fn assertion_response(
        &mut self,
        mut credential: PublicKeyCredentialSource,
        assertion_input: AssertionInput,
        number_of_credentials: Option<usize>,
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
                let cred_random = self.generate_cred_random(&credential.private_key, has_uv)?;
                Some(
                    self.pin_protocol_v1
                        .process_hmac_secret(hmac_secret_input, &cred_random)?,
                )
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
                "hmac-secret" => encrypted_output,
                "credBlob" => cred_blob,
            };
            if !cbor::write(extensions_output, &mut auth_data) {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
            }
        }
        let large_blob_key = match extensions.large_blob_key {
            Some(true) => credential.large_blob_key,
            _ => None,
        };

        let mut signature_data = auth_data.clone();
        signature_data.extend(client_data_hash);
        let signature = credential
            .private_key
            .sign_rfc6979::<crypto::sha256::Sha256>(&signature_data);

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
        Ok(ResponseData::AuthenticatorGetAssertion(
            AuthenticatorGetAssertionResponse {
                credential: Some(cred_desc),
                auth_data,
                signature: signature.to_asn1_der(),
                user,
                number_of_credentials: number_of_credentials.map(|n| n as u64),
                large_blob_key,
            },
        ))
    }

    // Returns the first applicable credential from the allow list.
    fn get_any_credential_from_allow_list(
        &mut self,
        allow_list: Vec<PublicKeyCredentialDescriptor>,
        rp_id: &str,
        rp_id_hash: &[u8],
        has_uv: bool,
    ) -> Result<Option<PublicKeyCredentialSource>, Ctap2StatusCode> {
        for allowed_credential in allow_list {
            let credential = self.persistent_store.find_credential(
                rp_id,
                &allowed_credential.key_id,
                !has_uv,
            )?;
            if credential.is_some() {
                return Ok(credential);
            }
            let credential =
                self.decrypt_credential_source(allowed_credential.key_id, &rp_id_hash)?;
            if credential.is_some() {
                return Ok(credential);
            }
        }
        Ok(None)
    }

    fn process_get_assertion(
        &mut self,
        get_assertion_params: AuthenticatorGetAssertionParameters,
        cid: ChannelID,
        now: ClockValue,
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

        self.pin_uv_auth_precheck(&pin_uv_auth_param, pin_uv_auth_protocol, cid)?;

        if extensions.hmac_secret.is_some() && !options.up {
            // The extension is actually supported, but we need user presence.
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_OPTION);
        }

        // The user verification bit depends on the existance of PIN auth, since we do
        // not support internal UV. User presence is requested as an option.
        let has_uv = pin_uv_auth_param.is_some();
        let mut flags = match pin_uv_auth_param {
            Some(pin_auth) => {
                if self.persistent_store.pin_hash()?.is_none() {
                    // Specification is unclear, could be CTAP2_ERR_UNSUPPORTED_OPTION.
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                }
                if !self
                    .pin_protocol_v1
                    .verify_pin_auth_token(&client_data_hash, &pin_auth)
                {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
                }
                self.pin_protocol_v1
                    .has_permission(PinPermission::GetAssertion)?;
                self.pin_protocol_v1.ensure_rp_id_permission(&rp_id)?;
                UV_FLAG
            }
            None => {
                if options.uv {
                    // The specification (inconsistently) wants CTAP2_ERR_UNSUPPORTED_OPTION.
                    return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
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
                self.get_any_credential_from_allow_list(allow_list, &rp_id, &rp_id_hash, has_uv)?,
                vec![],
            )
        } else {
            let mut iter_result = Ok(());
            let iter = self.persistent_store.iter_credentials(&mut iter_result)?;
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
                .map(|key| self.persistent_store.get_credential(key))
                .transpose()?;
            (credential, stored_credentials)
        };

        // This check comes before CTAP2_ERR_NO_CREDENTIALS in CTAP 2.0.
        // For CTAP 2.1, it was moved to a later protocol step.
        if options.up {
            (self.check_user_presence)(cid)?;
        }

        let credential = credential.ok_or(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)?;

        self.increment_global_signature_counter()?;

        let assertion_input = AssertionInput {
            client_data_hash,
            auth_data: self.generate_auth_data(&rp_id_hash, flags)?,
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
                .set_command(now, assertion_state);
            number_of_credentials
        };
        self.assertion_response(credential, assertion_input, number_of_credentials)
    }

    fn process_get_next_assertion(
        &mut self,
        now: ClockValue,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        self.stateful_command_permission
            .check_command_permission(now)?;
        let (assertion_input, credential_key) = self
            .stateful_command_permission
            .next_assertion_credential()?;
        let credential = self.persistent_store.get_credential(credential_key)?;
        self.assertion_response(credential, assertion_input, None)
    }

    fn process_get_info(&self) -> Result<ResponseData, Ctap2StatusCode> {
        let mut options_map = BTreeMap::new();
        options_map.insert(String::from("rk"), true);
        options_map.insert(
            String::from("clientPin"),
            self.persistent_store.pin_hash()?.is_some(),
        );
        options_map.insert(String::from("up"), true);
        options_map.insert(String::from("pinUvAuthToken"), true);
        options_map.insert(String::from("largeBlobs"), true);
        if ENTERPRISE_ATTESTATION_MODE.is_some() {
            options_map.insert(
                String::from("ep"),
                self.persistent_store.enterprise_attestation()?,
            );
        }
        options_map.insert(String::from("authnrCfg"), true);
        options_map.insert(String::from("credMgmt"), true);
        options_map.insert(String::from("setMinPINLength"), true);
        options_map.insert(String::from("makeCredUvNotRqd"), true);
        Ok(ResponseData::AuthenticatorGetInfo(
            AuthenticatorGetInfoResponse {
                versions: vec![
                    #[cfg(feature = "with_ctap1")]
                    String::from(U2F_VERSION_STRING),
                    String::from(FIDO2_VERSION_STRING),
                    String::from(FIDO2_1_VERSION_STRING),
                ],
                extensions: Some(vec![
                    String::from("hmac-secret"),
                    String::from("credProtect"),
                    String::from("minPinLength"),
                    String::from("credBlob"),
                    String::from("largeBlobKey"),
                ]),
                aaguid: self.persistent_store.aaguid()?,
                options: Some(options_map),
                max_msg_size: Some(MAX_MSG_SIZE as u64),
                pin_protocols: Some(vec![PIN_PROTOCOL_VERSION]),
                max_credential_count_in_list: MAX_CREDENTIAL_COUNT_IN_LIST.map(|c| c as u64),
                max_credential_id_length: Some(CREDENTIAL_ID_SIZE as u64),
                transports: Some(vec![AuthenticatorTransport::Usb]),
                algorithms: Some(vec![ES256_CRED_PARAM]),
                max_serialized_large_blob_array: Some(MAX_LARGE_BLOB_ARRAY_SIZE as u64),
                force_pin_change: Some(self.persistent_store.has_force_pin_change()?),
                min_pin_length: self.persistent_store.min_pin_length()?,
                firmware_version: None,
                max_cred_blob_length: Some(MAX_CRED_BLOB_LENGTH as u64),
                max_rp_ids_for_set_min_pin_length: Some(MAX_RP_IDS_LENGTH as u64),
                remaining_discoverable_credentials: Some(
                    self.persistent_store.remaining_credentials()? as u64,
                ),
            },
        ))
    }

    fn process_client_pin(
        &mut self,
        client_pin_params: AuthenticatorClientPinParameters,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        self.pin_protocol_v1.process_subcommand(
            self.rng,
            &mut self.persistent_store,
            client_pin_params,
        )
    }

    fn process_reset(
        &mut self,
        cid: ChannelID,
        now: ClockValue,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        self.stateful_command_permission
            .check_command_permission(now)?;
        match self.stateful_command_permission.get_command()? {
            StatefulCommand::Reset => (),
            _ => return Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED),
        }
        (self.check_user_presence)(cid)?;

        self.persistent_store.reset(self.rng)?;
        self.pin_protocol_v1.reset(self.rng);
        #[cfg(feature = "with_ctap1")]
        {
            self.u2f_up_state = U2fUserPresenceState::new(
                U2F_UP_PROMPT_TIMEOUT,
                Duration::from_ms(TOUCH_TIMEOUT_MS),
            );
        }
        Ok(ResponseData::AuthenticatorReset)
    }

    fn process_selection(&self, cid: ChannelID) -> Result<ResponseData, Ctap2StatusCode> {
        (self.check_user_presence)(cid)?;
        Ok(ResponseData::AuthenticatorSelection)
    }

    fn process_vendor_configure(
        &mut self,
        params: AuthenticatorVendorConfigureParameters,
        cid: ChannelID,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        (self.check_user_presence)(cid)?;

        // Sanity checks
        let current_priv_key = self.persistent_store.attestation_private_key()?;
        let current_cert = self.persistent_store.attestation_certificate()?;

        let response = match params.attestation_material {
            // Only reading values.
            None => AuthenticatorVendorResponse {
                cert_programmed: current_cert.is_some(),
                pkey_programmed: current_priv_key.is_some(),
            },
            // Device is already fully programmed. We don't leak information.
            Some(_) if current_cert.is_some() && current_priv_key.is_some() => {
                AuthenticatorVendorResponse {
                    cert_programmed: true,
                    pkey_programmed: true,
                }
            }
            // Device is partially or not programmed. We complete the process.
            Some(data) => {
                if let Some(current_cert) = &current_cert {
                    if current_cert != &data.certificate {
                        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
                    }
                }
                if let Some(current_priv_key) = &current_priv_key {
                    if current_priv_key != &data.private_key {
                        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
                    }
                }
                if current_cert.is_none() {
                    self.persistent_store
                        .set_attestation_certificate(&data.certificate)?;
                }
                if current_priv_key.is_none() {
                    self.persistent_store
                        .set_attestation_private_key(&data.private_key)?;
                }
                AuthenticatorVendorResponse {
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
            let need_certificate = USE_BATCH_ATTESTATION;

            if (need_certificate && !(response.pkey_programmed && response.cert_programmed))
                || crp::set_protection(crp::ProtectionLevel::FullyLocked).is_err()
            {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
            }
        }
        Ok(ResponseData::AuthenticatorVendor(response))
    }

    pub fn generate_auth_data(
        &self,
        rp_id_hash: &[u8],
        flag_byte: u8,
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let mut auth_data = vec![];
        auth_data.extend(rp_id_hash);
        auth_data.push(flag_byte);
        // The global counter is only increased if USE_SIGNATURE_COUNTER is true.
        // It uses a big-endian representation.
        let mut signature_counter = [0u8; 4];
        BigEndian::write_u32(
            &mut signature_counter,
            self.persistent_store.global_signature_counter()?,
        );
        auth_data.extend(&signature_counter);
        Ok(auth_data)
    }
}

#[cfg(test)]
mod test {
    use super::command::AuthenticatorAttestationMaterial;
    use super::data_formats::{
        CoseKey, GetAssertionHmacSecretInput, GetAssertionOptions, MakeCredentialExtensions,
        MakeCredentialOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    };
    use super::*;
    use cbor::{cbor_array, cbor_array_vec, cbor_map};
    use crypto::rng256::ThreadRng256;

    const CLOCK_FREQUENCY_HZ: usize = 32768;
    const DUMMY_CLOCK_VALUE: ClockValue = ClockValue::new(0, CLOCK_FREQUENCY_HZ);
    // The keep-alive logic in the processing of some commands needs a channel ID to send
    // keep-alive packets to.
    // In tests where we define a dummy user-presence check that immediately returns, the channel
    // ID is irrelevant, so we pass this (dummy but valid) value.
    const DUMMY_CHANNEL_ID: ChannelID = [0x12, 0x34, 0x56, 0x78];

    fn check_make_response(
        make_credential_response: Result<ResponseData, Ctap2StatusCode>,
        flags: u8,
        expected_aaguid: &[u8],
        expected_credential_id_size: u8,
        expected_extension_cbor: &[u8],
    ) {
        match make_credential_response.unwrap() {
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
                assert_eq!(att_stmt.alg, SignatureAlgorithm::ES256 as i64);
                assert_eq!(large_blob_key, None);
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_get_info() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        let info_reponse = ctap_state.process_command(&[0x04], DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);

        let expected_cbor = cbor_map_options! {
             0x01 => cbor_array_vec![vec![
                    #[cfg(feature = "with_ctap1")]
                    String::from(U2F_VERSION_STRING),
                    String::from(FIDO2_VERSION_STRING),
                    String::from(FIDO2_1_VERSION_STRING),
                ]],
            0x02 => cbor_array_vec![vec![
                    String::from("hmac-secret"),
                    String::from("credProtect"),
                    String::from("minPinLength"),
                    String::from("credBlob"),
                    String::from("largeBlobKey"),
                ]],
            0x03 => ctap_state.persistent_store.aaguid().unwrap(),
            0x04 => cbor_map_options! {
                "rk" => true,
                "clientPin" => false,
                "up" => true,
                "pinUvAuthToken" => true,
                "largeBlobs" => true,
                "ep" => ENTERPRISE_ATTESTATION_MODE.map(|_| false),
                "authnrCfg" => true,
                "credMgmt" => true,
                "setMinPINLength" => true,
                "makeCredUvNotRqd" => true,
            },
            0x05 => MAX_MSG_SIZE as u64,
            0x06 => cbor_array_vec![vec![1]],
            0x07 => MAX_CREDENTIAL_COUNT_IN_LIST.map(|c| c as u64),
            0x08 => CREDENTIAL_ID_SIZE as u64,
            0x09 => cbor_array_vec![vec!["usb"]],
            0x0A => cbor_array_vec![vec![ES256_CRED_PARAM]],
            0x0B => MAX_LARGE_BLOB_ARRAY_SIZE as u64,
            0x0C => false,
            0x0D => ctap_state.persistent_store.min_pin_length().unwrap() as u64,
            0x0F => MAX_CRED_BLOB_LENGTH as u64,
            0x10 => MAX_RP_IDS_LENGTH as u64,
            0x14 => ctap_state.persistent_store.remaining_credentials().unwrap() as u64,
        };

        let mut response_cbor = vec![0x00];
        assert!(cbor::write(expected_cbor, &mut response_cbor));
        assert_eq!(info_reponse, response_cbor);
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

    #[test]
    fn test_resident_process_make_credential() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);

        check_make_response(
            make_credential_response,
            0x41,
            &ctap_state.persistent_store.aaguid().unwrap(),
            0x20,
            &[],
        );
    }

    #[test]
    fn test_non_resident_process_make_credential() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);

        check_make_response(
            make_credential_response,
            0x41,
            &ctap_state.persistent_store.aaguid().unwrap(),
            CREDENTIAL_ID_SIZE as u8,
            &[],
        );
    }

    #[test]
    fn test_process_make_credential_unsupported_algorithm() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.pub_key_cred_params = vec![];
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);

        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        );
    }

    #[test]
    fn test_process_make_credential_credential_excluded() {
        let mut rng = ThreadRng256 {};
        let excluded_private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

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
        assert!(ctap_state
            .persistent_store
            .store_credential(excluded_credential_source)
            .is_ok());

        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );
    }

    #[test]
    fn test_process_make_credential_credential_with_cred_protect() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        assert!(make_credential_response.is_ok());

        let mut iter_result = Ok(());
        let iter = ctap_state
            .persistent_store
            .iter_credentials(&mut iter_result)
            .unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        let credential_id = stored_credential.credential_id;
        assert_eq!(stored_credential.cred_protect_policy, Some(test_policy));

        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        assert!(make_credential_response.is_ok());

        let mut iter_result = Ok(());
        let iter = ctap_state
            .persistent_store
            .iter_credentials(&mut iter_result)
            .unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        let credential_id = stored_credential.credential_id;
        assert_eq!(stored_credential.cred_protect_policy, Some(test_policy));

        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        assert!(make_credential_response.is_ok());
    }

    #[test]
    fn test_process_make_credential_hmac_secret() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);

        let expected_extension_cbor = [
            0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0xF5,
        ];
        check_make_response(
            make_credential_response,
            0xC1,
            &ctap_state.persistent_store.aaguid().unwrap(),
            CREDENTIAL_ID_SIZE as u8,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_hmac_secret_resident_key() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);

        let expected_extension_cbor = [
            0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0xF5,
        ];
        check_make_response(
            make_credential_response,
            0xC1,
            &ctap_state.persistent_store.aaguid().unwrap(),
            0x20,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_min_pin_length() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        // First part: The extension is ignored, since the RP ID is not on the list.
        let extensions = MakeCredentialExtensions {
            min_pin_length: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        check_make_response(
            make_credential_response,
            0x41,
            &ctap_state.persistent_store.aaguid().unwrap(),
            0x20,
            &[],
        );

        // Second part: The extension is used.
        assert_eq!(
            ctap_state
                .persistent_store
                .set_min_pin_length_rp_ids(vec!["example.com".to_string()]),
            Ok(())
        );

        let extensions = MakeCredentialExtensions {
            min_pin_length: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        let expected_extension_cbor = [
            0xA1, 0x6C, 0x6D, 0x69, 0x6E, 0x50, 0x69, 0x6E, 0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68,
            0x04,
        ];
        check_make_response(
            make_credential_response,
            0xC1,
            &ctap_state.persistent_store.aaguid().unwrap(),
            0x20,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_cred_blob_ok() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0xF5,
        ];
        check_make_response(
            make_credential_response,
            0xC1,
            &ctap_state.persistent_store.aaguid().unwrap(),
            0x20,
            &expected_extension_cbor,
        );

        let mut iter_result = Ok(());
        let iter = ctap_state
            .persistent_store
            .iter_credentials(&mut iter_result)
            .unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.cred_blob, Some(vec![0xCB]));
    }

    #[test]
    fn test_process_make_credential_cred_blob_too_big() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB; MAX_CRED_BLOB_LENGTH + 1]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0xF4,
        ];
        check_make_response(
            make_credential_response,
            0xC1,
            &ctap_state.persistent_store.aaguid().unwrap(),
            0x20,
            &expected_extension_cbor,
        );

        let mut iter_result = Ok(());
        let iter = ctap_state
            .persistent_store
            .iter_credentials(&mut iter_result)
            .unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.cred_blob, None);
    }

    #[test]
    fn test_process_make_credential_large_blob_key() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let extensions = MakeCredentialExtensions {
            large_blob_key: Some(true),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        let large_blob_key = match make_credential_response.unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                make_credential_response.large_blob_key.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        assert_eq!(large_blob_key.len(), 32);

        let mut iter_result = Ok(());
        let iter = ctap_state
            .persistent_store
            .iter_credentials(&mut iter_result)
            .unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.large_blob_key.unwrap(), large_blob_key);
    }

    #[test]
    fn test_process_make_credential_cancelled() {
        let mut rng = ThreadRng256 {};
        let user_presence_always_cancel = |_| Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL);
        let mut ctap_state =
            CtapState::new(&mut rng, user_presence_always_cancel, DUMMY_CLOCK_VALUE);

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);

        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    fn check_assertion_response_with_user(
        response: Result<ResponseData, Ctap2StatusCode>,
        expected_user: PublicKeyCredentialUserEntity,
        flags: u8,
        signature_counter: u32,
        expected_number_of_credentials: Option<u64>,
        expected_extension_cbor: &[u8],
    ) {
        match response.unwrap() {
            ResponseData::AuthenticatorGetAssertion(get_assertion_response) => {
                let AuthenticatorGetAssertionResponse {
                    auth_data,
                    user,
                    number_of_credentials,
                    ..
                } = get_assertion_response;
                let mut expected_auth_data = vec![
                    0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80,
                    0x34, 0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2,
                    0x12, 0x55, 0x86, 0xCE, 0x19, 0x47, flags, 0x00, 0x00, 0x00, 0x00,
                ];
                let signature_counter_position = expected_auth_data.len() - 4;
                BigEndian::write_u32(
                    &mut expected_auth_data[signature_counter_position..],
                    signature_counter,
                );
                expected_auth_data.extend(expected_extension_cbor);
                assert_eq!(auth_data, expected_auth_data);
                assert_eq!(user, Some(expected_user));
                assert_eq!(number_of_credentials, expected_number_of_credentials);
            }
            _ => panic!("Invalid response type"),
        }
    }

    fn check_assertion_response_with_extension(
        response: Result<ResponseData, Ctap2StatusCode>,
        expected_user_id: Vec<u8>,
        signature_counter: u32,
        expected_number_of_credentials: Option<u64>,
        expected_extension_cbor: &[u8],
    ) {
        let expected_user = PublicKeyCredentialUserEntity {
            user_id: expected_user_id,
            user_name: None,
            user_display_name: None,
            user_icon: None,
        };
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
            expected_user,
            0x00,
            signature_counter,
            expected_number_of_credentials,
            &[],
        );
    }

    #[test]
    fn test_resident_process_get_assertion() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let make_credential_params = create_minimal_make_credential_parameters();
        assert!(ctap_state
            .process_make_credential(make_credential_params, DUMMY_CHANNEL_ID)
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
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );
        let signature_counter = ctap_state
            .persistent_store
            .global_signature_counter()
            .unwrap();
        check_assertion_response(get_assertion_response, vec![0x1D], signature_counter, None);
    }

    #[test]
    fn test_process_get_assertion_hmac_secret() {
        let mut rng = ThreadRng256 {};
        let sk = crypto::ecdh::SecKey::gensk(&mut rng);
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let make_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        make_credential_params.extensions = make_extensions;
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        assert!(make_credential_response.is_ok());
        let credential_id = match make_credential_response.unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                let auth_data = make_credential_response.auth_data;
                let offset = 37 + ctap_state.persistent_store.aaguid().unwrap().len();
                assert_eq!(auth_data[offset], 0x00);
                assert_eq!(auth_data[offset + 1] as usize, CREDENTIAL_ID_SIZE);
                auth_data[offset + 2..offset + 2 + CREDENTIAL_ID_SIZE].to_vec()
            }
            _ => panic!("Invalid response type"),
        };

        let pk = sk.genpk();
        let hmac_secret_input = GetAssertionHmacSecretInput {
            key_agreement: CoseKey::from(pk),
            salt_enc: vec![0x02; 32],
            salt_auth: vec![0x03; 16],
        };
        let get_extensions = GetAssertionExtensions {
            hmac_secret: Some(hmac_secret_input),
            ..Default::default()
        };

        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id,
            transports: None,
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions: get_extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );

        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_OPTION)
        );
    }

    #[test]
    fn test_resident_process_get_assertion_hmac_secret() {
        let mut rng = ThreadRng256 {};
        let sk = crypto::ecdh::SecKey::gensk(&mut rng);
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let make_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = make_extensions;
        assert!(ctap_state
            .process_make_credential(make_credential_params, DUMMY_CHANNEL_ID)
            .is_ok());

        let pk = sk.genpk();
        let hmac_secret_input = GetAssertionHmacSecretInput {
            key_agreement: CoseKey::from(pk),
            salt_enc: vec![0x02; 32],
            salt_auth: vec![0x03; 16],
        };
        let get_extensions = GetAssertionExtensions {
            hmac_secret: Some(hmac_secret_input),
            ..Default::default()
        };

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: get_extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );

        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_OPTION)
        );
    }

    #[test]
    fn test_resident_process_get_assertion_with_cred_protect() {
        let mut rng = ThreadRng256 {};
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let credential_id = rng.gen_uniform_u8x32().to_vec();
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

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
        assert!(ctap_state
            .persistent_store
            .store_credential(credential)
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
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
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
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );
        let signature_counter = ctap_state
            .persistent_store
            .global_signature_counter()
            .unwrap();
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
        assert!(ctap_state
            .persistent_store
            .store_credential(credential)
            .is_ok());

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
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );
    }

    #[test]
    fn test_process_get_assertion_with_cred_blob() {
        let mut rng = ThreadRng256 {};
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let credential_id = rng.gen_uniform_u8x32().to_vec();
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

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
        assert!(ctap_state
            .persistent_store
            .store_credential(credential)
            .is_ok());

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
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );
        let signature_counter = ctap_state
            .persistent_store
            .global_signature_counter()
            .unwrap();
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0x41, 0xCB,
        ];
        check_assertion_response_with_extension(
            get_assertion_response,
            vec![0x1D],
            signature_counter,
            None,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_get_assertion_with_large_blob_key() {
        let mut rng = ThreadRng256 {};
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let credential_id = rng.gen_uniform_u8x32().to_vec();
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

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
        assert!(ctap_state
            .persistent_store
            .store_credential(credential)
            .is_ok());

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
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );
        let large_blob_key = match get_assertion_response.unwrap() {
            ResponseData::AuthenticatorGetAssertion(get_assertion_response) => {
                get_assertion_response.large_blob_key.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        assert_eq!(large_blob_key, vec![0x1C; 32]);
    }

    #[test]
    fn test_process_get_next_assertion_two_credentials_with_uv() {
        let mut rng = ThreadRng256 {};
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pin_uv_auth_token = [0x88; 32];
        let pin_protocol_v1 = PinProtocolV1::new_test(key_agreement_key, pin_uv_auth_token);

        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);
        ctap_state.pin_protocol_v1 = pin_protocol_v1;

        let mut make_credential_params = create_minimal_make_credential_parameters();
        let user1 = PublicKeyCredentialUserEntity {
            user_id: vec![0x01],
            user_name: Some("user1".to_string()),
            user_display_name: Some("User One".to_string()),
            user_icon: Some("icon1".to_string()),
        };
        make_credential_params.user = user1.clone();
        assert!(ctap_state
            .process_make_credential(make_credential_params, DUMMY_CHANNEL_ID)
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
            .process_make_credential(make_credential_params, DUMMY_CHANNEL_ID)
            .is_ok());

        // The PIN length is outside of the test scope and most likely incorrect.
        ctap_state.persistent_store.set_pin(&[0u8; 16], 4).unwrap();
        let pin_uv_auth_param = Some(vec![
            0x6F, 0x52, 0x83, 0xBF, 0x1A, 0x91, 0xEE, 0x67, 0xE9, 0xD4, 0x4C, 0x80, 0x08, 0x79,
            0x90, 0x8D,
        ]);

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: true,
            },
            pin_uv_auth_param,
            pin_uv_auth_protocol: Some(1),
        };
        let get_assertion_response = ctap_state.process_get_assertion(
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );
        let signature_counter = ctap_state
            .persistent_store
            .global_signature_counter()
            .unwrap();
        check_assertion_response_with_user(
            get_assertion_response,
            user2,
            0x04,
            signature_counter,
            Some(2),
            &[],
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(DUMMY_CLOCK_VALUE);
        check_assertion_response_with_user(
            get_assertion_response,
            user1,
            0x04,
            signature_counter,
            None,
            &[],
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(DUMMY_CLOCK_VALUE);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_get_next_assertion_three_credentials_no_uv() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x01];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(make_credential_params, DUMMY_CHANNEL_ID)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x02];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(make_credential_params, DUMMY_CHANNEL_ID)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x03];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(make_credential_params, DUMMY_CHANNEL_ID)
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
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );
        let signature_counter = ctap_state
            .persistent_store
            .global_signature_counter()
            .unwrap();
        check_assertion_response(
            get_assertion_response,
            vec![0x03],
            signature_counter,
            Some(3),
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(DUMMY_CLOCK_VALUE);
        check_assertion_response(get_assertion_response, vec![0x02], signature_counter, None);

        let get_assertion_response = ctap_state.process_get_next_assertion(DUMMY_CLOCK_VALUE);
        check_assertion_response(get_assertion_response, vec![0x01], signature_counter, None);

        let get_assertion_response = ctap_state.process_get_next_assertion(DUMMY_CLOCK_VALUE);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_get_next_assertion_not_allowed() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let get_assertion_response = ctap_state.process_get_next_assertion(DUMMY_CLOCK_VALUE);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x01];
        assert!(ctap_state
            .process_make_credential(make_credential_params, DUMMY_CHANNEL_ID)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x02];
        assert!(ctap_state
            .process_make_credential(make_credential_params, DUMMY_CHANNEL_ID)
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
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
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
        assert!(cbor::write(cbor_value, &mut command_cbor));
        ctap_state.process_command(&command_cbor, DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);

        let get_assertion_response = ctap_state.process_get_next_assertion(DUMMY_CLOCK_VALUE);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_reset() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

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
        assert!(ctap_state
            .persistent_store
            .store_credential(credential_source)
            .is_ok());
        assert!(ctap_state.persistent_store.count_credentials().unwrap() > 0);

        let reset_reponse =
            ctap_state.process_command(&[0x07], DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);
        let expected_response = vec![0x00];
        assert_eq!(reset_reponse, expected_response);
        assert!(ctap_state.persistent_store.count_credentials().unwrap() == 0);
    }

    #[test]
    fn test_process_reset_cancelled() {
        let mut rng = ThreadRng256 {};
        let user_presence_always_cancel = |_| Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL);
        let mut ctap_state =
            CtapState::new(&mut rng, user_presence_always_cancel, DUMMY_CLOCK_VALUE);

        let reset_reponse = ctap_state.process_reset(DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);

        assert_eq!(
            reset_reponse,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    #[test]
    fn test_process_reset_not_first() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        // This is a GetNextAssertion command.
        ctap_state.process_command(&[0x08], DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);

        let reset_reponse = ctap_state.process_reset(DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);
        assert_eq!(reset_reponse, Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED));
    }

    #[test]
    fn test_process_credential_management_unknown_subcommand() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        // The subcommand 0xEE does not exist.
        let reponse = ctap_state.process_command(
            &[0x0A, 0xA1, 0x01, 0x18, 0xEE],
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );
        let expected_response = vec![Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND as u8];
        assert_eq!(reponse, expected_response);
    }

    #[test]
    fn test_process_unknown_command() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        // This command does not exist.
        let reponse = ctap_state.process_command(&[0xDF], DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);
        let expected_response = vec![Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND as u8];
        assert_eq!(reponse, expected_response);
    }

    #[test]
    fn test_encrypt_decrypt_credential() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        // Usually, the relying party ID or its hash is provided by the client.
        // We are not testing the correctness of our SHA256 here, only if it is checked.
        let rp_id_hash = [0x55; 32];
        let encrypted_id = ctap_state
            .encrypt_key_handle(private_key.clone(), &rp_id_hash)
            .unwrap();
        let decrypted_source = ctap_state
            .decrypt_credential_source(encrypted_id, &rp_id_hash)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, decrypted_source.private_key);
    }

    #[test]
    fn test_encrypt_decrypt_bad_hmac() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        // Same as above.
        let rp_id_hash = [0x55; 32];
        let encrypted_id = ctap_state
            .encrypt_key_handle(private_key, &rp_id_hash)
            .unwrap();
        for i in 0..encrypted_id.len() {
            let mut modified_id = encrypted_id.clone();
            modified_id[i] ^= 0x01;
            assert!(ctap_state
                .decrypt_credential_source(modified_id, &rp_id_hash)
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn test_signature_counter() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        let mut last_counter = ctap_state
            .persistent_store
            .global_signature_counter()
            .unwrap();
        assert!(last_counter > 0);
        for _ in 0..100 {
            assert!(ctap_state.increment_global_signature_counter().is_ok());
            let next_counter = ctap_state
                .persistent_store
                .global_signature_counter()
                .unwrap();
            assert!(next_counter > last_counter);
            last_counter = next_counter;
        }
    }

    #[test]
    fn test_vendor_configure() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present, DUMMY_CLOCK_VALUE);

        // Nothing should be configured at the beginning
        let response = ctap_state.process_vendor_configure(
            AuthenticatorVendorConfigureParameters {
                lockdown: false,
                attestation_material: None,
            },
            DUMMY_CHANNEL_ID,
        );
        assert_eq!(
            response,
            Ok(ResponseData::AuthenticatorVendor(
                AuthenticatorVendorResponse {
                    cert_programmed: false,
                    pkey_programmed: false,
                }
            ))
        );

        // Inject dummy values
        let dummy_key = [0x41u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH];
        let dummy_cert = [0xddu8; 20];
        let response = ctap_state.process_vendor_configure(
            AuthenticatorVendorConfigureParameters {
                lockdown: false,
                attestation_material: Some(AuthenticatorAttestationMaterial {
                    certificate: dummy_cert.to_vec(),
                    private_key: dummy_key,
                }),
            },
            DUMMY_CHANNEL_ID,
        );
        assert_eq!(
            response,
            Ok(ResponseData::AuthenticatorVendor(
                AuthenticatorVendorResponse {
                    cert_programmed: true,
                    pkey_programmed: true,
                }
            ))
        );
        assert_eq!(
            ctap_state
                .persistent_store
                .attestation_certificate()
                .unwrap()
                .unwrap(),
            dummy_cert
        );
        assert_eq!(
            ctap_state
                .persistent_store
                .attestation_private_key()
                .unwrap()
                .unwrap(),
            dummy_key
        );

        // Try to inject other dummy values and check that initial values are retained.
        let other_dummy_key = [0x44u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH];
        let response = ctap_state.process_vendor_configure(
            AuthenticatorVendorConfigureParameters {
                lockdown: false,
                attestation_material: Some(AuthenticatorAttestationMaterial {
                    certificate: dummy_cert.to_vec(),
                    private_key: other_dummy_key,
                }),
            },
            DUMMY_CHANNEL_ID,
        );
        assert_eq!(
            response,
            Ok(ResponseData::AuthenticatorVendor(
                AuthenticatorVendorResponse {
                    cert_programmed: true,
                    pkey_programmed: true,
                }
            ))
        );
        assert_eq!(
            ctap_state
                .persistent_store
                .attestation_certificate()
                .unwrap()
                .unwrap(),
            dummy_cert
        );
        assert_eq!(
            ctap_state
                .persistent_store
                .attestation_private_key()
                .unwrap()
                .unwrap(),
            dummy_key
        );

        // Now try to lock the device
        let response = ctap_state.process_vendor_configure(
            AuthenticatorVendorConfigureParameters {
                lockdown: true,
                attestation_material: None,
            },
            DUMMY_CHANNEL_ID,
        );
        assert_eq!(
            response,
            Ok(ResponseData::AuthenticatorVendor(
                AuthenticatorVendorResponse {
                    cert_programmed: true,
                    pkey_programmed: true,
                }
            ))
        );
    }
}
