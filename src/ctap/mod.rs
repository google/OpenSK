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
mod credential_management;
mod crypto_wrapper;
#[cfg(feature = "with_ctap1")]
mod ctap1;
mod customization;
pub mod data_formats;
pub mod hid;
mod key_material;
mod large_blobs;
mod pin_protocol;
pub mod response;
pub mod status_code;
mod storage;
mod timed_permission;
mod token_state;

use self::client_pin::{ClientPin, PinPermission};
use self::command::{
    AuthenticatorGetAssertionParameters, AuthenticatorMakeCredentialParameters,
    AuthenticatorVendorConfigureParameters, AuthenticatorVendorUpgradeParameters, Command,
};
use self::config_command::process_config;
use self::credential_management::process_credential_management;
use self::crypto_wrapper::{aes256_cbc_decrypt, aes256_cbc_encrypt};
use self::customization::{
    DEFAULT_CRED_PROTECT, ENTERPRISE_ATTESTATION_MODE, ENTERPRISE_RP_ID_LIST,
    MAX_CREDENTIAL_COUNT_IN_LIST, MAX_CRED_BLOB_LENGTH, MAX_LARGE_BLOB_ARRAY_SIZE, MAX_MSG_SIZE,
    MAX_RP_IDS_LENGTH, USE_BATCH_ATTESTATION, USE_SIGNATURE_COUNTER,
};
use self::data_formats::{
    AuthenticatorTransport, CoseKey, CoseSignature, CredentialProtectionPolicy,
    EnterpriseAttestationMode, GetAssertionExtensions, PackedAttestationStatement,
    PinUvAuthProtocol, PublicKeyCredentialDescriptor, PublicKeyCredentialParameter,
    PublicKeyCredentialSource, PublicKeyCredentialType, PublicKeyCredentialUserEntity,
    SignatureAlgorithm,
};
use self::hid::ChannelID;
use self::large_blobs::LargeBlobs;
use self::response::{
    AuthenticatorGetAssertionResponse, AuthenticatorGetInfoResponse,
    AuthenticatorMakeCredentialResponse, AuthenticatorVendorConfigureResponse,
    AuthenticatorVendorUpgradeInfoResponse, ResponseData,
};
use self::status_code::Ctap2StatusCode;
use self::storage::PersistentStore;
use self::timed_permission::TimedPermission;
#[cfg(feature = "with_ctap1")]
use self::timed_permission::U2fUserPresenceState;
use crate::embedded_flash::{UpgradeLocations, UpgradeStorage};
use crate::env::{Env, UserPresence};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use arrayref::array_ref;
use byteorder::{BigEndian, ByteOrder};
use core::convert::TryFrom;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
use crypto::ecdsa;
use crypto::hmac::{hmac_256, verify_hmac_256};
use crypto::rng256::Rng256;
use crypto::sha256::Sha256;
use crypto::Hash256;
#[cfg(feature = "debug_ctap")]
use libtock_drivers::console::Console;
use libtock_drivers::crp;
use libtock_drivers::timer::{ClockValue, Duration};
use sk_cbor as cbor;
use sk_cbor::cbor_map_options;

pub const INITIAL_SIGNATURE_COUNTER: u32 = 1;
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

// CTAP2 specification section 6 requires that the depth of nested CBOR structures be limited to at most four levels.
const MAX_CBOR_NESTING_DEPTH: i8 = 4;

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

// We currently only support one algorithm for signatures: ES256.
// This algorithm is requested in MakeCredential and advertized in GetInfo.
pub const ES256_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::ES256,
};

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

/// Parses the metadata of an upgrade, and checks its correctness.
///
/// Returns the hash over the upgrade, including partition and some metadata.
/// The metadata consists of:
/// - 32B upgrade hash (SHA256)
/// -  4B timestamp (little endian encoding)
/// -  4B partition address (little endian encoding)
/// The upgrade hash is computed over the firmware image and all metadata,
/// except the hash itself.
fn parse_metadata(
    upgrade_locations: &UpgradeLocations,
    metadata: &[u8],
) -> Result<[u8; 32], Ctap2StatusCode> {
    const METADATA_LEN: usize = 40;
    if metadata.len() != METADATA_LEN {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    // The hash implementation handles this in chunks, so no memory issues.
    let partition_slice = upgrade_locations
        .read_partition(0, upgrade_locations.partition_length())
        .map_err(|_| Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
    let mut hasher = Sha256::new();
    hasher.update(partition_slice);
    hasher.update(&metadata[32..METADATA_LEN]);
    let computed_hash = hasher.finalize();
    if &computed_hash != array_ref!(metadata, 0, 32) {
        return Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE);
    }
    Ok(computed_hash)
}

/// Verifies the signature over the given hash.
///
/// The public key is COSE encoded, and the hash is a SHA256.
fn verify_signature(
    signature: Option<CoseSignature>,
    public_key_bytes: &[u8],
    signed_hash: &[u8; 32],
) -> Result<(), Ctap2StatusCode> {
    let signature =
        ecdsa::Signature::try_from(signature.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?)?;
    let cbor_public_key = cbor_read(public_key_bytes)?;
    let cose_key = CoseKey::try_from(cbor_public_key)?;
    let public_key = ecdsa::PubKey::try_from(cose_key)?;
    if !public_key.verify_hash_vartime(signed_hash, &signature) {
        return Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE);
    }
    Ok(())
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
pub struct CtapState {
    persistent_store: PersistentStore,
    client_pin: ClientPin,
    #[cfg(feature = "with_ctap1")]
    pub u2f_up_state: U2fUserPresenceState,
    // The state initializes to Reset and its timeout, and never goes back to Reset.
    stateful_command_permission: StatefulPermission,
    large_blobs: LargeBlobs,
    upgrade_locations: Option<UpgradeLocations>,
}

impl CtapState {
    pub fn new(env: &mut impl Env, now: ClockValue) -> CtapState {
        let persistent_store = PersistentStore::new(env.rng());
        let client_pin = ClientPin::new(env.rng());
        CtapState {
            persistent_store,
            client_pin,
            #[cfg(feature = "with_ctap1")]
            u2f_up_state: U2fUserPresenceState::new(
                U2F_UP_PROMPT_TIMEOUT,
                Duration::from_ms(TOUCH_TIMEOUT_MS),
            ),
            stateful_command_permission: StatefulPermission::new_reset(now),
            large_blobs: LargeBlobs::new(),
            upgrade_locations: UpgradeLocations::new().ok(),
        }
    }

    pub fn update_timeouts(&mut self, now: ClockValue) {
        // Ignore the result, just update.
        let _ = self
            .stateful_command_permission
            .check_command_permission(now);
        self.client_pin.update_timeouts(now);
    }

    pub fn increment_global_signature_counter(
        &mut self,
        env: &mut impl Env,
    ) -> Result<(), Ctap2StatusCode> {
        if USE_SIGNATURE_COUNTER {
            let increment = env.rng().gen_uniform_u32x8()[0] % 8 + 1;
            self.persistent_store
                .incr_global_signature_counter(increment)?;
        }
        Ok(())
    }

    // Returns whether CTAP1 commands are currently supported.
    // If alwaysUv is enabled and the authenticator does not support internal UV,
    // CTAP1 needs to be disabled.
    #[cfg(feature = "with_ctap1")]
    pub fn allows_ctap1(&self) -> Result<bool, Ctap2StatusCode> {
        Ok(!self.persistent_store.has_always_uv()?)
    }

    // Encrypts the private key and relying party ID hash into a credential ID. Other
    // information, such as a user name, are not stored, because encrypted credential IDs
    // are used for credentials stored server-side. Also, we want the key handle to be
    // compatible with U2F.
    pub fn encrypt_key_handle(
        &mut self,
        env: &mut impl Env,
        private_key: crypto::ecdsa::SecKey,
        application: &[u8; 32],
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let master_keys = self.persistent_store.master_keys()?;
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&master_keys.encryption);
        let mut plaintext = [0; 64];
        private_key.to_bytes(array_mut_ref!(plaintext, 0, 32));
        plaintext[32..64].copy_from_slice(application);

        let mut encrypted_id = aes256_cbc_encrypt(env.rng(), &aes_enc_key, &plaintext, true)?;
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

        let decrypted_id = aes256_cbc_decrypt(&aes_enc_key, &credential_id[..payload_size], true)?;
        if rp_id_hash != &decrypted_id[32..64] {
            return Ok(None);
        }
        let sk_option = crypto::ecdsa::SecKey::from_bytes(array_ref!(decrypted_id, 0, 32));
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
        env: &mut impl Env,
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
                        self.process_make_credential(env, params, cid)
                    }
                    Command::AuthenticatorGetAssertion(params) => {
                        self.process_get_assertion(env, params, cid, now)
                    }
                    Command::AuthenticatorGetNextAssertion => {
                        self.process_get_next_assertion(env, now)
                    }
                    Command::AuthenticatorGetInfo => self.process_get_info(),
                    Command::AuthenticatorClientPin(params) => self.client_pin.process_command(
                        env.rng(),
                        &mut self.persistent_store,
                        params,
                        now,
                    ),
                    Command::AuthenticatorReset => self.process_reset(env, cid, now),
                    Command::AuthenticatorCredentialManagement(params) => {
                        process_credential_management(
                            &mut self.persistent_store,
                            &mut self.stateful_command_permission,
                            &mut self.client_pin,
                            params,
                            now,
                        )
                    }
                    Command::AuthenticatorSelection => self.process_selection(env, cid),
                    Command::AuthenticatorLargeBlobs(params) => self.large_blobs.process_command(
                        &mut self.persistent_store,
                        &mut self.client_pin,
                        params,
                    ),
                    Command::AuthenticatorConfig(params) => {
                        process_config(&mut self.persistent_store, &mut self.client_pin, params)
                    }
                    // Vendor specific commands
                    Command::AuthenticatorVendorConfigure(params) => {
                        self.process_vendor_configure(env, params, cid)
                    }
                    Command::AuthenticatorVendorUpgrade(params) => {
                        self.process_vendor_upgrade(params)
                    }
                    Command::AuthenticatorVendorUpgradeInfo => self.process_vendor_upgrade_info(),
                };
                #[cfg(feature = "debug_ctap")]
                writeln!(&mut Console::new(), "Sending response: {:#?}", response).unwrap();
                match response {
                    Ok(response_data) => {
                        let mut response_vec = vec![0x00];
                        if let Some(value) = response_data.into() {
                            if cbor_write(value, &mut response_vec).is_err() {
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
        env: &mut impl Env,
        pin_uv_auth_param: &Option<Vec<u8>>,
        pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
        cid: ChannelID,
    ) -> Result<(), Ctap2StatusCode> {
        if let Some(auth_param) = &pin_uv_auth_param {
            // This case was added in FIDO 2.1.
            if auth_param.is_empty() {
                env.user_presence().check(cid)?;
                if self.persistent_store.pin_hash()?.is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                } else {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }
            }
            pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
        }
        Ok(())
    }

    fn process_make_credential(
        &mut self,
        env: &mut impl Env,
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

        self.pin_uv_auth_precheck(env, &pin_uv_auth_param, pin_uv_auth_protocol, cid)?;

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

        // MakeCredential always requires user presence.
        // User verification depends on the PIN auth inputs, which are checked here.
        // The ED flag is added later, if applicable.
        let has_uv = pin_uv_auth_param.is_some();
        let mut flags = match pin_uv_auth_param {
            Some(pin_uv_auth_param) => {
                // This case is not mentioned in CTAP2.1, so we keep 2.0 logic.
                if self.persistent_store.pin_hash()?.is_none() {
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
                if self.persistent_store.has_always_uv()? {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                }
                // Corresponds to makeCredUvNotRqd set to true.
                if options.rk && self.persistent_store.pin_hash()?.is_some() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                }
                0x00
            }
        };
        flags |= UP_FLAG | AT_FLAG;

        let rp_id_hash = Sha256::hash(rp_id.as_bytes());
        if let Some(exclude_list) = exclude_list {
            for cred_desc in exclude_list {
                if self
                    .persistent_store
                    .find_credential(&rp_id, &cred_desc.key_id, !has_uv)?
                    .is_some()
                    || self
                        .decrypt_credential_source(cred_desc.key_id, &rp_id_hash)?
                        .is_some()
                {
                    // Perform this check, so bad actors can't brute force exclude_list
                    // without user interaction.
                    let _ = env.user_presence().check(cid);
                    return Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED);
                }
            }
        }

        env.user_presence().check(cid)?;
        self.client_pin.clear_token_flags();

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

        let sk = crypto::ecdsa::SecKey::gensk(env.rng());
        let pk = sk.genpk();

        let credential_id = if options.rk {
            let random_id = env.rng().gen_uniform_u8x32().to_vec();
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
            self.encrypt_key_handle(env, sk.clone(), &rp_id_hash)?
        };

        let mut auth_data = self.generate_auth_data(&rp_id_hash, flags)?;
        auth_data.extend(&self.persistent_store.aaguid()?);
        // The length is fixed to 0x20 or 0x70 and fits one byte.
        if credential_id.len() > 0xFF {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        auth_data.extend(vec![0x00, credential_id.len() as u8]);
        auth_data.extend(&credential_id);
        cbor_write(cbor::Value::from(CoseKey::from(pk)), &mut auth_data)?;
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
                attestation_key.sign_rfc6979::<Sha256>(&signature_data),
                Some(vec![attestation_certificate]),
            )
        } else {
            (sk.sign_rfc6979::<Sha256>(&signature_data), None)
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
        env: &mut impl Env,
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
            .sign_rfc6979::<Sha256>(&signature_data);

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
                self.decrypt_credential_source(allowed_credential.key_id, rp_id_hash)?;
            if credential.is_some() {
                return Ok(credential);
            }
        }
        Ok(None)
    }

    fn process_get_assertion(
        &mut self,
        env: &mut impl Env,
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

        self.pin_uv_auth_precheck(env, &pin_uv_auth_param, pin_uv_auth_protocol, cid)?;

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
                if self.persistent_store.pin_hash()?.is_none() {
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
                if options.up && self.persistent_store.has_always_uv()? {
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

        let credential = credential.ok_or(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)?;

        // This check comes before CTAP2_ERR_NO_CREDENTIALS in CTAP 2.0.
        if options.up {
            env.user_presence().check(cid)?;
            self.client_pin.clear_token_flags();
        }

        self.increment_global_signature_counter(env)?;

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
        self.assertion_response(env, credential, assertion_input, number_of_credentials)
    }

    fn process_get_next_assertion(
        &mut self,
        env: &mut impl Env,
        now: ClockValue,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        self.stateful_command_permission
            .check_command_permission(now)?;
        let (assertion_input, credential_key) = self
            .stateful_command_permission
            .next_assertion_credential()?;
        let credential = self.persistent_store.get_credential(credential_key)?;
        self.assertion_response(env, credential, assertion_input, None)
    }

    fn process_get_info(&self) -> Result<ResponseData, Ctap2StatusCode> {
        let has_always_uv = self.persistent_store.has_always_uv()?;
        #[cfg_attr(not(feature = "with_ctap1"), allow(unused_mut))]
        let mut versions = vec![
            String::from(FIDO2_VERSION_STRING),
            String::from(FIDO2_1_VERSION_STRING),
        ];
        #[cfg(feature = "with_ctap1")]
        {
            if !has_always_uv {
                versions.insert(0, String::from(U2F_VERSION_STRING))
            }
        }
        let mut options = vec![];
        if ENTERPRISE_ATTESTATION_MODE.is_some() {
            options.push((
                String::from("ep"),
                self.persistent_store.enterprise_attestation()?,
            ));
        }
        options.append(&mut vec![
            (String::from("rk"), true),
            (String::from("up"), true),
            (String::from("alwaysUv"), has_always_uv),
            (String::from("credMgmt"), true),
            (String::from("authnrCfg"), true),
            (
                String::from("clientPin"),
                self.persistent_store.pin_hash()?.is_some(),
            ),
            (String::from("largeBlobs"), true),
            (String::from("pinUvAuthToken"), true),
            (String::from("setMinPINLength"), true),
            (String::from("makeCredUvNotRqd"), !has_always_uv),
        ]);

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
                aaguid: self.persistent_store.aaguid()?,
                options: Some(options),
                max_msg_size: Some(MAX_MSG_SIZE as u64),
                // The order implies preference. We favor the new V2.
                pin_protocols: Some(vec![
                    PinUvAuthProtocol::V2 as u64,
                    PinUvAuthProtocol::V1 as u64,
                ]),
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
                certifications: None,
                remaining_discoverable_credentials: Some(
                    self.persistent_store.remaining_credentials()? as u64,
                ),
            },
        ))
    }

    fn process_reset(
        &mut self,
        env: &mut impl Env,
        cid: ChannelID,
        now: ClockValue,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        self.stateful_command_permission
            .check_command_permission(now)?;
        match self.stateful_command_permission.get_command()? {
            StatefulCommand::Reset => (),
            _ => return Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED),
        }
        env.user_presence().check(cid)?;

        self.persistent_store.reset(env.rng())?;
        self.client_pin.reset(env.rng());
        #[cfg(feature = "with_ctap1")]
        {
            self.u2f_up_state = U2fUserPresenceState::new(
                U2F_UP_PROMPT_TIMEOUT,
                Duration::from_ms(TOUCH_TIMEOUT_MS),
            );
        }
        Ok(ResponseData::AuthenticatorReset)
    }

    fn process_selection(
        &self,
        env: &mut impl Env,
        cid: ChannelID,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        env.user_presence().check(cid)?;
        Ok(ResponseData::AuthenticatorSelection)
    }

    fn process_vendor_configure(
        &mut self,
        env: &mut impl Env,
        params: AuthenticatorVendorConfigureParameters,
        cid: ChannelID,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        if params.attestation_material.is_some() || params.lockdown {
            env.user_presence().check(cid)?;
        }

        // Sanity checks
        let current_priv_key = self.persistent_store.attestation_private_key()?;
        let current_cert = self.persistent_store.attestation_certificate()?;

        let response = match params.attestation_material {
            // Only reading values.
            None => AuthenticatorVendorConfigureResponse {
                cert_programmed: current_cert.is_some(),
                pkey_programmed: current_priv_key.is_some(),
            },
            // Device is already fully programmed. We don't leak information.
            Some(_) if current_cert.is_some() && current_priv_key.is_some() => {
                AuthenticatorVendorConfigureResponse {
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
            let need_certificate = USE_BATCH_ATTESTATION;

            if (need_certificate && !(response.pkey_programmed && response.cert_programmed))
                || crp::set_protection(crp::ProtectionLevel::FullyLocked).is_err()
            {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
            }
        }
        Ok(ResponseData::AuthenticatorVendorConfigure(response))
    }

    fn process_vendor_upgrade(
        &mut self,
        params: AuthenticatorVendorUpgradeParameters,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let AuthenticatorVendorUpgradeParameters {
            address,
            data,
            hash,
            signature,
        } = params;
        let upgrade_locations = self
            .upgrade_locations
            .as_mut()
            .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND)?;
        let written_slice = if let Some(address) = address {
            upgrade_locations
                .write_partition(address, &data)
                .map_err(|_| Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
            upgrade_locations
                .read_partition(address, data.len())
                .map_err(|_| Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?
        } else {
            // Compares the hash inside the metadata to the actual hash.
            let upgrade_hash = parse_metadata(upgrade_locations, &data)?;
            // Only signed firmware images may be fully written.
            verify_signature(signature, key_material::UPGRADE_PUBLIC_KEY, &upgrade_hash)?;
            // Write the metadata page after verifying that its hash is signed.
            upgrade_locations
                .write_metadata(&data)
                .map_err(|_| Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
            &upgrade_locations
                .read_metadata()
                .map_err(|_| Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?[..data.len()]
        };
        let written_hash = Sha256::hash(written_slice);
        if hash != written_hash {
            return Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE);
        }
        Ok(ResponseData::AuthenticatorVendorUpgrade)
    }

    fn process_vendor_upgrade_info(&self) -> Result<ResponseData, Ctap2StatusCode> {
        let upgrade_locations = self
            .upgrade_locations
            .as_ref()
            .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND)?;
        Ok(ResponseData::AuthenticatorVendorUpgradeInfo(
            AuthenticatorVendorUpgradeInfoResponse {
                info: upgrade_locations.partition_address() as u32,
            },
        ))
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
    use super::client_pin::PIN_TOKEN_LENGTH;
    use super::command::{AuthenticatorAttestationMaterial, AuthenticatorClientPinParameters};
    use super::data_formats::{
        ClientPinSubCommand, CoseKey, GetAssertionHmacSecretInput, GetAssertionOptions,
        MakeCredentialExtensions, MakeCredentialOptions, PinUvAuthProtocol,
        PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    };
    use super::pin_protocol::{authenticate_pin_uv_auth_token, PinProtocol};
    use super::*;
    use crate::env::test::TestEnv;
    use cbor::{cbor_array, cbor_array_vec, cbor_map};

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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        let info_reponse =
            ctap_state.process_command(&mut env, &[0x04], DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);

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
            0x03 => ctap_state.persistent_store.aaguid().unwrap(),
            0x04 => cbor_map_options! {
                "ep" => ENTERPRISE_ATTESTATION_MODE.map(|_| false),
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
            0x05 => MAX_MSG_SIZE as u64,
            0x06 => cbor_array![2, 1],
            0x07 => MAX_CREDENTIAL_COUNT_IN_LIST.map(|c| c as u64),
            0x08 => CREDENTIAL_ID_SIZE as u64,
            0x09 => cbor_array!["usb"],
            0x0A => cbor_array![ES256_CRED_PARAM],
            0x0B => MAX_LARGE_BLOB_ARRAY_SIZE as u64,
            0x0C => false,
            0x0D => ctap_state.persistent_store.min_pin_length().unwrap() as u64,
            0x0F => MAX_CRED_BLOB_LENGTH as u64,
            0x10 => MAX_RP_IDS_LENGTH as u64,
            0x14 => ctap_state.persistent_store.remaining_credentials().unwrap() as u64,
        };

        let mut response_cbor = vec![0x00];
        assert!(cbor_write(expected_cbor, &mut response_cbor).is_ok());
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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);

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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);

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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.pub_key_cred_params = vec![];
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);

        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        );
    }

    #[test]
    fn test_process_make_credential_credential_excluded() {
        let mut env = TestEnv::new();
        let excluded_private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

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
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );
    }

    #[test]
    fn test_process_make_credential_credential_with_cred_protect() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
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
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
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
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
        assert!(make_credential_response.is_ok());
    }

    #[test]
    fn test_process_make_credential_hmac_secret() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);

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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);

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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        // First part: The extension is ignored, since the RP ID is not on the list.
        let extensions = MakeCredentialExtensions {
            min_pin_length: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
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
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB; MAX_CRED_BLOB_LENGTH + 1]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let extensions = MakeCredentialExtensions {
            large_blob_key: Some(true),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
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

    fn test_helper_process_make_credential_with_pin_and_uv(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let mut env = TestEnv::new();
        let key_agreement_key = crypto::ecdh::SecKey::gensk(env.rng());
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let client_pin =
            ClientPin::new_test(key_agreement_key, pin_uv_auth_token, pin_uv_auth_protocol);

        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        ctap_state.client_pin = client_pin;
        ctap_state.persistent_store.set_pin(&[0x88; 16], 4).unwrap();

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
            DUMMY_CHANNEL_ID,
        );

        check_make_response(
            make_credential_response,
            0x45,
            &ctap_state.persistent_store.aaguid().unwrap(),
            0x20,
            &[],
        );

        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
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
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        ctap_state.persistent_store.set_pin(&[0x88; 16], 4).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);

        check_make_response(
            make_credential_response,
            0x41,
            &ctap_state.persistent_store.aaguid().unwrap(),
            0x70,
            &[],
        );
    }

    #[test]
    fn test_resident_process_make_credential_with_pin() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        ctap_state.persistent_store.set_pin(&[0x88; 16], 4).unwrap();

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
        );
    }

    #[test]
    fn test_process_make_credential_with_pin_always_uv() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        ctap_state.persistent_store.toggle_always_uv().unwrap();
        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
        );

        ctap_state.persistent_store.set_pin(&[0x88; 16], 4).unwrap();
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.pin_uv_auth_param = Some(vec![0xA4; 16]);
        make_credential_params.pin_uv_auth_protocol = Some(PinUvAuthProtocol::V1);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_process_make_credential_cancelled() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL));
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);

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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let make_credential_params = create_minimal_make_credential_parameters();
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID)
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
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );
        let signature_counter = ctap_state
            .persistent_store
            .global_signature_counter()
            .unwrap();
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
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let make_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        make_credential_params.extensions = make_extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID);
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
        let key_agreement_response = ctap_state.client_pin.process_command(
            env.rng(),
            &mut ctap_state.persistent_store,
            client_pin_params,
            DUMMY_CLOCK_VALUE,
        );
        let get_assertion_params = get_assertion_hmac_secret_params(
            key_agreement_key,
            key_agreement_response.unwrap(),
            Some(credential_id),
            pin_uv_auth_protocol,
        );
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
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
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let make_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = make_extensions;
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID)
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
        let key_agreement_response = ctap_state.client_pin.process_command(
            env.rng(),
            &mut ctap_state.persistent_store,
            client_pin_params,
            DUMMY_CLOCK_VALUE,
        );
        let get_assertion_params = get_assertion_hmac_secret_params(
            key_agreement_key,
            key_agreement_response.unwrap(),
            None,
            pin_uv_auth_protocol,
        );
        let get_assertion_response = ctap_state.process_get_assertion(
            &mut env,
            get_assertion_params,
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
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
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

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
            &mut env,
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
            &mut env,
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
            &mut env,
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
        let mut env = TestEnv::new();
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

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
            &mut env,
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
        let mut env = TestEnv::new();
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

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
            &mut env,
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

    fn test_helper_process_get_next_assertion_two_credentials_with_uv(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let mut env = TestEnv::new();
        let key_agreement_key = crypto::ecdh::SecKey::gensk(env.rng());
        let pin_uv_auth_token = [0x88; 32];
        let client_pin =
            ClientPin::new_test(key_agreement_key, pin_uv_auth_token, pin_uv_auth_protocol);

        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        let user1 = PublicKeyCredentialUserEntity {
            user_id: vec![0x01],
            user_name: Some("user1".to_string()),
            user_display_name: Some("User One".to_string()),
            user_icon: Some("icon1".to_string()),
        };
        make_credential_params.user = user1.clone();
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID)
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
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID)
            .is_ok());

        ctap_state.client_pin = client_pin;
        // The PIN length is outside of the test scope and most likely incorrect.
        ctap_state.persistent_store.set_pin(&[0u8; 16], 4).unwrap();
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

        let get_assertion_response =
            ctap_state.process_get_next_assertion(&mut env, DUMMY_CLOCK_VALUE);
        check_assertion_response_with_user(
            get_assertion_response,
            user1,
            0x04,
            signature_counter,
            None,
            &[],
        );

        let get_assertion_response =
            ctap_state.process_get_next_assertion(&mut env, DUMMY_CLOCK_VALUE);
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
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x01];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x02];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x03];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID)
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

        let get_assertion_response =
            ctap_state.process_get_next_assertion(&mut env, DUMMY_CLOCK_VALUE);
        check_assertion_response(get_assertion_response, vec![0x02], signature_counter, None);

        let get_assertion_response =
            ctap_state.process_get_next_assertion(&mut env, DUMMY_CLOCK_VALUE);
        check_assertion_response(get_assertion_response, vec![0x01], signature_counter, None);

        let get_assertion_response =
            ctap_state.process_get_next_assertion(&mut env, DUMMY_CLOCK_VALUE);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_get_next_assertion_not_allowed() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let get_assertion_response =
            ctap_state.process_get_next_assertion(&mut env, DUMMY_CLOCK_VALUE);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x01];
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x02];
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL_ID)
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
        assert!(cbor_write(cbor_value, &mut command_cbor).is_ok());
        ctap_state.process_command(&mut env, &command_cbor, DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);

        let get_assertion_response =
            ctap_state.process_get_next_assertion(&mut env, DUMMY_CLOCK_VALUE);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_reset() {
        let mut env = TestEnv::new();
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

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
            ctap_state.process_command(&mut env, &[0x07], DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);
        let expected_response = vec![0x00];
        assert_eq!(reset_reponse, expected_response);
        assert!(ctap_state.persistent_store.count_credentials().unwrap() == 0);
    }

    #[test]
    fn test_process_reset_cancelled() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL));
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let reset_reponse = ctap_state.process_reset(&mut env, DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);

        assert_eq!(
            reset_reponse,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    #[test]
    fn test_process_reset_not_first() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        // This is a GetNextAssertion command.
        ctap_state.process_command(&mut env, &[0x08], DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);

        let reset_reponse = ctap_state.process_reset(&mut env, DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);
        assert_eq!(reset_reponse, Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED));
    }

    #[test]
    fn test_process_credential_management_unknown_subcommand() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        // The subcommand 0xEE does not exist.
        let reponse = ctap_state.process_command(
            &mut env,
            &[0x0A, 0xA1, 0x01, 0x18, 0xEE],
            DUMMY_CHANNEL_ID,
            DUMMY_CLOCK_VALUE,
        );
        let expected_response = vec![Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND as u8];
        assert_eq!(reponse, expected_response);
    }

    #[test]
    fn test_process_unknown_command() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        // This command does not exist.
        let reponse =
            ctap_state.process_command(&mut env, &[0xDF], DUMMY_CHANNEL_ID, DUMMY_CLOCK_VALUE);
        let expected_response = vec![Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND as u8];
        assert_eq!(reponse, expected_response);
    }

    #[test]
    fn test_encrypt_decrypt_credential() {
        let mut env = TestEnv::new();
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        // Usually, the relying party ID or its hash is provided by the client.
        // We are not testing the correctness of our SHA256 here, only if it is checked.
        let rp_id_hash = [0x55; 32];
        let encrypted_id = ctap_state
            .encrypt_key_handle(&mut env, private_key.clone(), &rp_id_hash)
            .unwrap();
        let decrypted_source = ctap_state
            .decrypt_credential_source(encrypted_id, &rp_id_hash)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, decrypted_source.private_key);
    }

    #[test]
    fn test_encrypt_decrypt_bad_hmac() {
        let mut env = TestEnv::new();
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        // Same as above.
        let rp_id_hash = [0x55; 32];
        let encrypted_id = ctap_state
            .encrypt_key_handle(&mut env, private_key, &rp_id_hash)
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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        let mut last_counter = ctap_state
            .persistent_store
            .global_signature_counter()
            .unwrap();
        assert!(last_counter > 0);
        for _ in 0..100 {
            assert!(ctap_state
                .increment_global_signature_counter(&mut env)
                .is_ok());
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
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);

        // Nothing should be configured at the beginning
        let response = ctap_state.process_vendor_configure(
            &mut env,
            AuthenticatorVendorConfigureParameters {
                lockdown: false,
                attestation_material: None,
            },
            DUMMY_CHANNEL_ID,
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
            DUMMY_CHANNEL_ID,
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
            &mut env,
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
            Ok(ResponseData::AuthenticatorVendorConfigure(
                AuthenticatorVendorConfigureResponse {
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
            &mut env,
            AuthenticatorVendorConfigureParameters {
                lockdown: true,
                attestation_material: None,
            },
            DUMMY_CHANNEL_ID,
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
    fn test_parse_metadata() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        // The test buffer starts fully erased with 0xFF bytes.
        // The compiler issues an incorrect warning.
        #[allow(unused_mut)]
        let mut upgrade_locations = ctap_state.upgrade_locations.as_mut().unwrap();

        // Partition of 0x40000 bytes and 8 bytes metadata are hashed.
        let hashed_data = vec![0xFF; 0x40000 + 8];
        let expected_hash = Sha256::hash(&hashed_data);
        let mut metadata = vec![0xFF; 40];
        metadata[..32].copy_from_slice(&expected_hash);
        assert_eq!(
            parse_metadata(upgrade_locations, &metadata),
            Ok(expected_hash)
        );

        // Any manipulation of data fails.
        metadata[32] = 0x88;
        assert_eq!(
            parse_metadata(upgrade_locations, &metadata),
            Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE)
        );
        metadata[32] = 0xFF;
        metadata[0] ^= 0x01;
        assert_eq!(
            parse_metadata(upgrade_locations, &metadata),
            Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE)
        );
        metadata[0] ^= 0x01;
        upgrade_locations.write_partition(0, &[0x88; 1]).unwrap();
        assert_eq!(
            parse_metadata(upgrade_locations, &metadata),
            Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE)
        );
    }

    #[test]
    fn test_verify_signature() {
        let mut env = TestEnv::new();
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let message = [0x44; 64];
        let signed_hash = Sha256::hash(&message);
        let signature = private_key.sign_rfc6979::<Sha256>(&message);

        let mut signature_bytes = [0; ecdsa::Signature::BYTES_LENGTH];
        signature.to_bytes(&mut signature_bytes);
        let cose_signature = CoseSignature {
            algorithm: SignatureAlgorithm::ES256,
            bytes: signature_bytes,
        };

        let public_key = private_key.genpk();
        let mut public_key_bytes = vec![];
        cbor_write(
            cbor::Value::from(CoseKey::from(public_key)),
            &mut public_key_bytes,
        )
        .unwrap();

        assert_eq!(
            verify_signature(
                Some(cose_signature.clone()),
                &public_key_bytes,
                &signed_hash
            ),
            Ok(())
        );
        assert_eq!(
            verify_signature(Some(cose_signature.clone()), &public_key_bytes, &[0x55; 32]),
            Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE)
        );
        public_key_bytes[0] ^= 0x01;
        assert_eq!(
            verify_signature(Some(cose_signature), &public_key_bytes, &signed_hash),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
        );
        public_key_bytes[0] ^= 0x01;
        assert_eq!(
            verify_signature(None, &public_key_bytes, &signed_hash),
            Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
        );
        signature_bytes[0] ^= 0x01;
        let cose_signature = CoseSignature {
            algorithm: SignatureAlgorithm::ES256,
            bytes: signature_bytes,
        };
        assert_eq!(
            verify_signature(Some(cose_signature), &public_key_bytes, &signed_hash),
            Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE)
        );
    }

    #[test]
    fn test_vendor_upgrade() {
        // The test partition storage has size 0x40000.
        // The test metadata storage has size 0x1000.
        // The test identifier matches partition B.
        let mut env = TestEnv::new();
        let private_key = crypto::ecdsa::SecKey::gensk(env.rng());
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        const METADATA_LEN: usize = 40;

        let data = vec![0xFF; 0x1000];
        let hash = Sha256::hash(&data).to_vec();
        let upgrade_locations = ctap_state.upgrade_locations.as_ref().unwrap();
        let partition_length = upgrade_locations.partition_length();
        let mut signed_over_data = upgrade_locations
            .read_partition(0, partition_length)
            .unwrap()
            .to_vec();
        signed_over_data.extend(&[0xFF; METADATA_LEN - 32]);
        let signed_hash = Sha256::hash(&signed_over_data);
        let mut metadata = vec![0xFF; METADATA_LEN];
        metadata[..32].copy_from_slice(&signed_hash);
        let metadata_hash = Sha256::hash(&metadata).to_vec();

        let signature = private_key.sign_rfc6979::<Sha256>(&signed_over_data);
        let mut signature_bytes = [0; ecdsa::Signature::BYTES_LENGTH];
        signature.to_bytes(&mut signature_bytes);
        let cose_signature = CoseSignature {
            algorithm: SignatureAlgorithm::ES256,
            bytes: signature_bytes,
        };

        // Write to partition and metadata.
        let response = ctap_state.process_vendor_upgrade(AuthenticatorVendorUpgradeParameters {
            address: Some(0x20000),
            data: data.clone(),
            hash: hash.clone(),
            signature: None,
        });
        assert_eq!(response, Ok(ResponseData::AuthenticatorVendorUpgrade));

        // We can't inject a public key for our known private key, so the last upgrade step fails.
        // verify_signature is separately tested for that reason.
        let response = ctap_state.process_vendor_upgrade(AuthenticatorVendorUpgradeParameters {
            address: None,
            data: metadata.clone(),
            hash: metadata_hash.clone(),
            signature: Some(cose_signature.clone()),
        });
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE));

        // Write metadata of a wrong size.
        let response = ctap_state.process_vendor_upgrade(AuthenticatorVendorUpgradeParameters {
            address: None,
            data: metadata[..METADATA_LEN - 1].to_vec(),
            hash: metadata_hash,
            signature: Some(cose_signature),
        });
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER));

        // Write outside of the partition.
        let response = ctap_state.process_vendor_upgrade(AuthenticatorVendorUpgradeParameters {
            address: Some(0x40000),
            data: data.clone(),
            hash,
            signature: None,
        });
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER));

        // Write a bad hash.
        let response = ctap_state.process_vendor_upgrade(AuthenticatorVendorUpgradeParameters {
            address: Some(0x20000),
            data,
            hash: [0xEE; 32].to_vec(),
            signature: None,
        });
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_INTEGRITY_FAILURE));
    }

    #[test]
    fn test_vendor_upgrade_no_second_partition() {
        let mut env = TestEnv::new();
        let mut ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        ctap_state.upgrade_locations = None;

        let data = vec![0xFF; 0x1000];
        let hash = Sha256::hash(&data).to_vec();
        let response = ctap_state.process_vendor_upgrade(AuthenticatorVendorUpgradeParameters {
            address: Some(0),
            data,
            hash,
            signature: None,
        });
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND));
    }

    #[test]
    fn test_vendor_upgrade_info() {
        let mut env = TestEnv::new();
        let ctap_state = CtapState::new(&mut env, DUMMY_CLOCK_VALUE);
        let partition_address = ctap_state
            .upgrade_locations
            .as_ref()
            .unwrap()
            .partition_address();

        let upgrade_info_reponse = ctap_state.process_vendor_upgrade_info();
        assert_eq!(
            upgrade_info_reponse,
            Ok(ResponseData::AuthenticatorVendorUpgradeInfo(
                AuthenticatorVendorUpgradeInfoResponse {
                    info: partition_address as u32,
                }
            ))
        );
    }
}
