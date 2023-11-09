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

use super::command::AuthenticatorClientPinParameters;
use super::data_formats::{
    ok_or_missing, ClientPinSubCommand, CoseKey, GetAssertionHmacSecretInput, PinUvAuthProtocol,
};
use super::pin_protocol::{verify_pin_uv_auth_token, PinProtocol, SharedSecret};
use super::response::{AuthenticatorClientPinResponse, ResponseData};
use super::secret::Secret;
use super::status_code::Ctap2StatusCode;
use super::token_state::PinUvAuthTokenState;
#[cfg(test)]
use crate::api::crypto::ecdh::SecretKey as _;
use crate::api::crypto::hmac256::Hmac256;
use crate::api::crypto::sha256::Sha256;
use crate::api::customization::Customization;
use crate::api::key_store::KeyStore;
use crate::ctap::storage;
#[cfg(test)]
use crate::env::EcdhSk;
use crate::env::{Env, Hmac, Sha};
use alloc::str;
use alloc::string::String;
use alloc::vec::Vec;
use arrayref::array_ref;
#[cfg(test)]
use enum_iterator::IntoEnumIterator;
use subtle::ConstantTimeEq;

/// The prefix length of the PIN hash that is stored and compared.
///
/// The code assumes that this value is a multiple of the AES block length, fits
/// an u8 and is at most as long as a SHA256. The value is fixed for all PIN
/// protocols.
pub const PIN_AUTH_LENGTH: usize = 16;

/// The length of the pinUvAuthToken used throughout PIN protocols.
///
/// The code assumes that this value is a multiple of the AES block length. It
/// is fixed since CTAP2.1, and the specification suggests that it coincides
/// with the HMAC key length. Therefore a change would require a more general
/// HMAC implementation.
pub const PIN_TOKEN_LENGTH: usize = 32;

/// The length of the encrypted PINs when received by SetPin or ChangePin.
///
/// The code assumes that this value is a multiple of the AES block length. It
/// is fixed since CTAP2.1.
const PIN_PADDED_LENGTH: usize = 64;

/// Decrypts the new_pin_enc and outputs the found PIN.
fn decrypt_pin<E: Env>(
    shared_secret: &SharedSecret<E>,
    new_pin_enc: Vec<u8>,
) -> Result<Secret<[u8]>, Ctap2StatusCode> {
    let decrypted_pin = shared_secret.decrypt(&new_pin_enc)?;
    if decrypted_pin.len() != PIN_PADDED_LENGTH {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    // In CTAP 2.1, the specification changed. The new wording might lead to
    // different behavior when there are non-zero bytes after zero bytes.
    // This implementation consistently ignores those degenerate cases.
    let len = decrypted_pin
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(decrypted_pin.len());
    let mut result = Secret::new(len);
    result.copy_from_slice(&decrypted_pin[..len]);
    Ok(result)
}

/// Stores a hash prefix of the new PIN in the persistent storage, if correct.
///
/// The new PIN is passed encrypted, so it is first decrypted and stripped from
/// padding. Next, it is checked against the PIN policy. Last, it is hashed and
/// truncated for persistent storage.
fn check_and_store_new_pin<E: Env>(
    env: &mut E,
    shared_secret: &SharedSecret<E>,
    new_pin_enc: Vec<u8>,
) -> Result<(), Ctap2StatusCode> {
    let pin = decrypt_pin(shared_secret, new_pin_enc)?;
    let min_pin_length = storage::min_pin_length(env)? as usize;
    let pin_length = str::from_utf8(&pin).unwrap_or("").chars().count();
    if pin_length < min_pin_length || pin.len() == PIN_PADDED_LENGTH {
        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION);
    }
    let mut pin_hash = Secret::default();
    Sha::<E>::digest_mut(&pin, &mut pin_hash);
    let pin_hash = env
        .key_store()
        .encrypt_pin_hash(array_ref![pin_hash, 0, PIN_AUTH_LENGTH])?;
    // The PIN length is always < PIN_PADDED_LENGTH < 256.
    storage::set_pin(
        env,
        array_ref!(pin_hash, 0, PIN_AUTH_LENGTH),
        pin_length as u8,
    )?;
    Ok(())
}

#[cfg_attr(test, derive(IntoEnumIterator))]
pub enum PinPermission {
    // All variants should use integers with a single bit set.
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    CredentialManagement = 0x04,
    _BioEnrollment = 0x08,
    LargeBlobWrite = 0x10,
    #[cfg(feature = "config_command")]
    AuthenticatorConfiguration = 0x20,
}

pub struct ClientPin<E: Env> {
    pin_protocol_v1: PinProtocol<E>,
    pin_protocol_v2: PinProtocol<E>,
    consecutive_pin_mismatches: u8,
    pin_uv_auth_token_state: PinUvAuthTokenState<E>,
}

impl<E: Env> ClientPin<E> {
    pub fn new(env: &mut E) -> Self {
        ClientPin {
            pin_protocol_v1: PinProtocol::new(env),
            pin_protocol_v2: PinProtocol::new(env),
            consecutive_pin_mismatches: 0,
            pin_uv_auth_token_state: PinUvAuthTokenState::new(),
        }
    }

    /// Gets a reference to the PIN protocol of the given version.
    fn get_pin_protocol(&self, pin_uv_auth_protocol: PinUvAuthProtocol) -> &PinProtocol<E> {
        match pin_uv_auth_protocol {
            PinUvAuthProtocol::V1 => &self.pin_protocol_v1,
            PinUvAuthProtocol::V2 => &self.pin_protocol_v2,
        }
    }

    /// Gets a mutable reference to the PIN protocol of the given version.
    fn get_mut_pin_protocol(
        &mut self,
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) -> &mut PinProtocol<E> {
        match pin_uv_auth_protocol {
            PinUvAuthProtocol::V1 => &mut self.pin_protocol_v1,
            PinUvAuthProtocol::V2 => &mut self.pin_protocol_v2,
        }
    }

    /// Computes the shared secret for the given version.
    fn get_shared_secret(
        &self,
        pin_uv_auth_protocol: PinUvAuthProtocol,
        key_agreement: CoseKey,
    ) -> Result<SharedSecret<E>, Ctap2StatusCode> {
        self.get_pin_protocol(pin_uv_auth_protocol)
            .decapsulate(key_agreement, pin_uv_auth_protocol)
    }

    /// Checks the given encrypted PIN hash against the stored PIN hash.
    ///
    /// Decrypts the encrypted pin_hash and compares it to the stored pin_hash.
    /// Resets or decreases the PIN retries, depending on success or failure.
    /// Also, in case of failure, the key agreement key is randomly reset.
    fn verify_pin_hash_enc(
        &mut self,
        env: &mut E,
        pin_uv_auth_protocol: PinUvAuthProtocol,
        shared_secret: &SharedSecret<E>,
        pin_hash_enc: Vec<u8>,
    ) -> Result<(), Ctap2StatusCode> {
        match storage::pin_hash(env)? {
            Some(pin_hash) => {
                if self.consecutive_pin_mismatches >= 3 {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_BLOCKED);
                }
                storage::decr_pin_retries(env)?;
                let pin_hash = env.key_store().decrypt_pin_hash(&pin_hash)?;
                let pin_hash_dec = shared_secret
                    .decrypt(&pin_hash_enc)
                    .map_err(|_| Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)?;

                if !bool::from(pin_hash.ct_eq(&pin_hash_dec)) {
                    self.get_mut_pin_protocol(pin_uv_auth_protocol)
                        .regenerate(env);
                    if storage::pin_retries(env)? == 0 {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
                    }
                    self.consecutive_pin_mismatches += 1;
                    if self.consecutive_pin_mismatches >= 3 {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_BLOCKED);
                    }
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }
            }
            // This status code is not explicitly mentioned in the specification.
            None => return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED),
        }
        storage::reset_pin_retries(env)?;
        self.consecutive_pin_mismatches = 0;
        Ok(())
    }

    fn process_get_pin_retries(
        &self,
        env: &mut E,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_uv_auth_token: None,
            retries: Some(storage::pin_retries(env)? as u64),
            power_cycle_state: Some(self.consecutive_pin_mismatches >= 3),
        })
    }

    fn process_get_key_agreement(
        &self,
        client_pin_params: AuthenticatorClientPinParameters,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        let key_agreement = Some(
            self.get_pin_protocol(client_pin_params.pin_uv_auth_protocol)
                .get_public_key(),
        );
        Ok(AuthenticatorClientPinResponse {
            key_agreement,
            pin_uv_auth_token: None,
            retries: None,
            power_cycle_state: None,
        })
    }

    fn process_set_pin(
        &mut self,
        env: &mut E,
        client_pin_params: AuthenticatorClientPinParameters,
    ) -> Result<(), Ctap2StatusCode> {
        let AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            key_agreement,
            pin_uv_auth_param,
            new_pin_enc,
            ..
        } = client_pin_params;
        let key_agreement = ok_or_missing(key_agreement)?;
        let pin_uv_auth_param = ok_or_missing(pin_uv_auth_param)?;
        let new_pin_enc = ok_or_missing(new_pin_enc)?;

        if storage::pin_hash(env)?.is_some() {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let shared_secret = self.get_shared_secret(pin_uv_auth_protocol, key_agreement)?;
        shared_secret.verify(&new_pin_enc, &pin_uv_auth_param)?;

        check_and_store_new_pin(env, &shared_secret, new_pin_enc)?;
        storage::reset_pin_retries(env)?;
        Ok(())
    }

    fn process_change_pin(
        &mut self,
        env: &mut E,
        client_pin_params: AuthenticatorClientPinParameters,
    ) -> Result<(), Ctap2StatusCode> {
        let AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            key_agreement,
            pin_uv_auth_param,
            new_pin_enc,
            pin_hash_enc,
            ..
        } = client_pin_params;
        let key_agreement = ok_or_missing(key_agreement)?;
        let pin_uv_auth_param = ok_or_missing(pin_uv_auth_param)?;
        let new_pin_enc = ok_or_missing(new_pin_enc)?;
        let pin_hash_enc = ok_or_missing(pin_hash_enc)?;

        if storage::pin_retries(env)? == 0 {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
        }
        let shared_secret = self.get_shared_secret(pin_uv_auth_protocol, key_agreement)?;
        let mut auth_param_data = new_pin_enc.clone();
        auth_param_data.extend(&pin_hash_enc);
        shared_secret.verify(&auth_param_data, &pin_uv_auth_param)?;
        self.verify_pin_hash_enc(env, pin_uv_auth_protocol, &shared_secret, pin_hash_enc)?;

        check_and_store_new_pin(env, &shared_secret, new_pin_enc)?;
        self.pin_protocol_v1.reset_pin_uv_auth_token(env);
        self.pin_protocol_v2.reset_pin_uv_auth_token(env);
        Ok(())
    }

    fn process_get_pin_token(
        &mut self,
        env: &mut E,
        client_pin_params: AuthenticatorClientPinParameters,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        let AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            key_agreement,
            pin_hash_enc,
            permissions,
            permissions_rp_id,
            ..
        } = client_pin_params;
        let key_agreement = ok_or_missing(key_agreement)?;
        let pin_hash_enc = ok_or_missing(pin_hash_enc)?;
        if permissions.is_some() || permissions_rp_id.is_some() {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }

        if storage::pin_retries(env)? == 0 {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
        }
        let shared_secret = self.get_shared_secret(pin_uv_auth_protocol, key_agreement)?;
        self.verify_pin_hash_enc(env, pin_uv_auth_protocol, &shared_secret, pin_hash_enc)?;
        if storage::has_force_pin_change(env)? {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
        }

        self.pin_protocol_v1.reset_pin_uv_auth_token(env);
        self.pin_protocol_v2.reset_pin_uv_auth_token(env);
        self.pin_uv_auth_token_state
            .begin_using_pin_uv_auth_token(env);
        self.pin_uv_auth_token_state.set_default_permissions();
        let pin_uv_auth_token = shared_secret.encrypt(
            env,
            self.get_pin_protocol(pin_uv_auth_protocol)
                .get_pin_uv_auth_token(),
        )?;

        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_uv_auth_token: Some(pin_uv_auth_token),
            retries: None,
            power_cycle_state: None,
        })
    }

    fn process_get_pin_uv_auth_token_using_uv_with_permissions(
        &self,
        // If you want to support local user verification, implement this function.
        // Lacking a fingerprint reader, this subcommand is currently unsupported.
        _client_pin_params: AuthenticatorClientPinParameters,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // User verification is only supported through PIN currently.
        Err(Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND)
    }

    fn process_get_uv_retries(&self) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // User verification is only supported through PIN currently.
        Err(Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND)
    }

    fn process_get_pin_uv_auth_token_using_pin_with_permissions(
        &mut self,
        env: &mut E,
        mut client_pin_params: AuthenticatorClientPinParameters,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // Mutating client_pin_params is just an optimization to move it into
        // process_get_pin_token, without cloning permissions_rp_id here.
        // getPinToken requires permissions* to be None.
        let permissions = ok_or_missing(client_pin_params.permissions.take())?;
        let permissions_rp_id = client_pin_params.permissions_rp_id.take();

        if permissions == 0 {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        // This check is not mentioned protocol steps, but mentioned in a side note.
        if permissions & 0x03 != 0 && permissions_rp_id.is_none() {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }

        let response = self.process_get_pin_token(env, client_pin_params)?;
        self.pin_uv_auth_token_state.set_permissions(permissions);
        self.pin_uv_auth_token_state
            .set_permissions_rp_id(permissions_rp_id);

        Ok(response)
    }

    /// Processes the authenticatorClientPin command.
    pub fn process_command(
        &mut self,
        env: &mut E,
        client_pin_params: AuthenticatorClientPinParameters,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        if !env.customization().allows_pin_protocol_v1()
            && client_pin_params.pin_uv_auth_protocol == PinUvAuthProtocol::V1
        {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        let response = match client_pin_params.sub_command {
            ClientPinSubCommand::GetPinRetries => Some(self.process_get_pin_retries(env)?),
            ClientPinSubCommand::GetKeyAgreement => {
                Some(self.process_get_key_agreement(client_pin_params)?)
            }
            ClientPinSubCommand::SetPin => {
                self.process_set_pin(env, client_pin_params)?;
                None
            }
            ClientPinSubCommand::ChangePin => {
                self.process_change_pin(env, client_pin_params)?;
                None
            }
            ClientPinSubCommand::GetPinToken => {
                Some(self.process_get_pin_token(env, client_pin_params)?)
            }
            ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions => Some(
                self.process_get_pin_uv_auth_token_using_uv_with_permissions(client_pin_params)?,
            ),
            ClientPinSubCommand::GetUvRetries => Some(self.process_get_uv_retries()?),
            ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions => Some(
                self.process_get_pin_uv_auth_token_using_pin_with_permissions(
                    env,
                    client_pin_params,
                )?,
            ),
        };
        Ok(ResponseData::AuthenticatorClientPin(response))
    }

    /// Verifies the HMAC for the pinUvAuthToken of the given version.
    pub fn verify_pin_uv_auth_token(
        &self,
        hmac_contents: &[u8],
        pin_uv_auth_param: &[u8],
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) -> Result<(), Ctap2StatusCode> {
        if !self.pin_uv_auth_token_state.is_in_use() {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }
        verify_pin_uv_auth_token::<E>(
            self.get_pin_protocol(pin_uv_auth_protocol)
                .get_pin_uv_auth_token(),
            hmac_contents,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        )
    }

    /// Resets all held state.
    pub fn reset(&mut self, env: &mut E) {
        self.pin_protocol_v1.regenerate(env);
        self.pin_protocol_v1.reset_pin_uv_auth_token(env);
        self.pin_protocol_v2.regenerate(env);
        self.pin_protocol_v2.reset_pin_uv_auth_token(env);
        self.consecutive_pin_mismatches = 0;
        self.pin_uv_auth_token_state.stop_using_pin_uv_auth_token();
    }

    /// Verifies, computes and encrypts the HMAC-secret outputs.
    ///
    /// The salt_enc is
    /// - verified with the shared secret and salt_auth,
    /// - decrypted with the shared secret,
    /// - HMAC'ed with cred_random.
    /// The length of the output matches salt_enc and has to be 1 or 2 blocks of
    /// 32 byte.
    pub fn process_hmac_secret(
        &self,
        env: &mut E,
        hmac_secret_input: GetAssertionHmacSecretInput,
        cred_random: &[u8; 32],
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let GetAssertionHmacSecretInput {
            key_agreement,
            salt_enc,
            salt_auth,
            pin_uv_auth_protocol,
        } = hmac_secret_input;
        let shared_secret = self
            .get_pin_protocol(pin_uv_auth_protocol)
            .decapsulate(key_agreement, pin_uv_auth_protocol)?;
        shared_secret.verify(&salt_enc, &salt_auth)?;

        let decrypted_salts = shared_secret.decrypt(&salt_enc)?;
        if decrypted_salts.len() != 32 && decrypted_salts.len() != 64 {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        let mut output = Secret::new(decrypted_salts.len());
        Hmac::<E>::mac(
            cred_random,
            &decrypted_salts[..32],
            array_mut_ref![&mut output, 0, 32],
        );
        if decrypted_salts.len() == 64 {
            Hmac::<E>::mac(
                cred_random,
                &decrypted_salts[32..],
                array_mut_ref![&mut output, 32, 32],
            );
        }
        shared_secret.encrypt(env, &output)
    }

    /// Consumes flags and permissions related to the pinUvAuthToken.
    pub fn clear_token_flags(&mut self) {
        self.pin_uv_auth_token_state.clear_user_verified_flag();
        self.pin_uv_auth_token_state
            .clear_pin_uv_auth_token_permissions_except_lbw();
    }

    /// Updates the running timers, triggers timeout events.
    pub fn update_timeouts(&mut self, env: &mut E) {
        self.pin_uv_auth_token_state
            .pin_uv_auth_token_usage_timer_observer(env);
    }

    /// Checks if user verification is cached for use of the pinUvAuthToken.
    pub fn check_user_verified_flag(&mut self) -> Result<(), Ctap2StatusCode> {
        if self.pin_uv_auth_token_state.get_user_verified_flag_value() {
            Ok(())
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    /// Check if the required command's token permission is granted.
    pub fn has_permission(&self, permission: PinPermission) -> Result<(), Ctap2StatusCode> {
        self.pin_uv_auth_token_state.has_permission(permission)
    }

    /// Check if no RP ID is associated with the token permission.
    pub fn has_no_rp_id_permission(&self) -> Result<(), Ctap2StatusCode> {
        self.pin_uv_auth_token_state.has_no_permissions_rp_id()
    }

    /// Check if no or the passed RP ID is associated with the token permission.
    pub fn has_no_or_rp_id_permission(&mut self, rp_id: &str) -> Result<(), Ctap2StatusCode> {
        self.pin_uv_auth_token_state
            .has_no_permissions_rp_id()
            .or_else(|_| self.pin_uv_auth_token_state.has_permissions_rp_id(rp_id))
    }

    /// Check if no RP ID is associated with the token permission, or it matches the hash.
    pub fn has_no_or_rp_id_hash_permission(
        &self,
        rp_id_hash: &[u8],
    ) -> Result<(), Ctap2StatusCode> {
        self.pin_uv_auth_token_state
            .has_no_permissions_rp_id()
            .or_else(|_| {
                self.pin_uv_auth_token_state
                    .has_permissions_rp_id_hash(rp_id_hash)
            })
    }

    /// Check if the passed RP ID is associated with the token permission.
    ///
    /// If no RP ID is associated, associate the passed RP ID as a side effect.
    pub fn ensure_rp_id_permission(&mut self, rp_id: &str) -> Result<(), Ctap2StatusCode> {
        if self
            .pin_uv_auth_token_state
            .has_no_permissions_rp_id()
            .is_ok()
        {
            self.pin_uv_auth_token_state
                .set_permissions_rp_id(Some(String::from(rp_id)));
            return Ok(());
        }
        self.pin_uv_auth_token_state.has_permissions_rp_id(rp_id)
    }

    #[cfg(test)]
    pub fn new_test(
        env: &mut E,
        key_agreement_key: EcdhSk<E>,
        pin_uv_auth_token: [u8; PIN_TOKEN_LENGTH],
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) -> Self {
        let random_key = EcdhSk::<E>::random(env.rng());
        let (key_agreement_key_v1, key_agreement_key_v2) = match pin_uv_auth_protocol {
            PinUvAuthProtocol::V1 => (key_agreement_key, random_key),
            PinUvAuthProtocol::V2 => (random_key, key_agreement_key),
        };
        let mut pin_uv_auth_token_state = PinUvAuthTokenState::new();
        pin_uv_auth_token_state.set_permissions(0xFF);
        pin_uv_auth_token_state.begin_using_pin_uv_auth_token(env);
        Self {
            pin_protocol_v1: PinProtocol::new_test(key_agreement_key_v1, pin_uv_auth_token),
            pin_protocol_v2: PinProtocol::new_test(key_agreement_key_v2, pin_uv_auth_token),
            consecutive_pin_mismatches: 0,
            pin_uv_auth_token_state,
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::pin_protocol::authenticate_pin_uv_auth_token;
    use super::*;
    use crate::api::crypto::HASH_SIZE;
    use crate::env::test::TestEnv;
    use crate::env::EcdhSk;
    use alloc::vec;

    /// Stores a PIN hash corresponding to the dummy PIN "1234".
    fn set_standard_pin(env: &mut TestEnv) {
        let mut pin = [0u8; 64];
        pin[..4].copy_from_slice(b"1234");
        let mut pin_hash = [0u8; 16];
        pin_hash.copy_from_slice(&Sha::<TestEnv>::digest(&pin[..])[..16]);
        storage::set_pin(env, &pin_hash, 4).unwrap();
    }

    /// Fails on PINs bigger than 64 bytes.
    fn encrypt_pin(shared_secret: &SharedSecret<TestEnv>, pin: Vec<u8>) -> Vec<u8> {
        assert!(pin.len() <= 64);
        let mut env = TestEnv::default();
        let mut padded_pin = [0u8; 64];
        padded_pin[..pin.len()].copy_from_slice(&pin[..]);
        shared_secret.encrypt(&mut env, &padded_pin).unwrap()
    }

    /// Generates a ClientPin instance and a shared secret for testing.
    ///
    /// The shared secret for the desired PIN protocol is generated in a
    /// handshake with itself. The other protocol has a random private key, so
    /// tests using the wrong combination of PIN protocol and shared secret
    /// should fail.
    fn create_client_pin_and_shared_secret(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) -> (ClientPin<TestEnv>, SharedSecret<TestEnv>) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pk = key_agreement_key.public_key();
        let key_agreement = CoseKey::from_ecdh_public_key(pk);
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            pin_uv_auth_protocol,
        );
        let shared_secret = client_pin
            .get_pin_protocol(pin_uv_auth_protocol)
            .decapsulate(key_agreement, pin_uv_auth_protocol)
            .unwrap();
        (client_pin, shared_secret)
    }

    /// Generates standard input parameters to the ClientPin command.
    ///
    /// All fields are populated for simplicity, even though most are unused.
    fn create_client_pin_and_parameters(
        pin_uv_auth_protocol: PinUvAuthProtocol,
        sub_command: ClientPinSubCommand,
    ) -> (ClientPin<TestEnv>, AuthenticatorClientPinParameters) {
        let mut env = TestEnv::default();
        let (client_pin, shared_secret) = create_client_pin_and_shared_secret(pin_uv_auth_protocol);

        let pin = b"1234";
        let mut padded_pin = [0u8; 64];
        padded_pin[..pin.len()].copy_from_slice(&pin[..]);
        let pin_hash = Sha::<TestEnv>::digest(&padded_pin);
        let new_pin_enc = shared_secret.encrypt(&mut env, &padded_pin).unwrap();
        let pin_uv_auth_param = shared_secret.authenticate(&new_pin_enc);
        let pin_hash_enc = shared_secret.encrypt(&mut env, &pin_hash[..16]).unwrap();
        let (permissions, permissions_rp_id) = match sub_command {
            ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions
            | ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions => {
                (Some(0x03), Some("example.com".to_string()))
            }
            _ => (None, None),
        };
        let params = AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            sub_command,
            key_agreement: Some(
                client_pin
                    .get_pin_protocol(pin_uv_auth_protocol)
                    .get_public_key(),
            ),
            pin_uv_auth_param: Some(pin_uv_auth_param),
            new_pin_enc: Some(new_pin_enc),
            pin_hash_enc: Some(pin_hash_enc),
            permissions,
            permissions_rp_id,
        };
        (client_pin, params)
    }

    #[test]
    fn test_mix_pin_protocols() {
        let mut env = TestEnv::default();
        let client_pin = ClientPin::<TestEnv>::new(&mut env);
        let pin_protocol_v1 = client_pin.get_pin_protocol(PinUvAuthProtocol::V1);
        let pin_protocol_v2 = client_pin.get_pin_protocol(PinUvAuthProtocol::V2);
        let message = vec![0xAA; 16];

        let shared_secret_v1 = pin_protocol_v1
            .decapsulate(pin_protocol_v1.get_public_key(), PinUvAuthProtocol::V1)
            .unwrap();
        let shared_secret_v2 = pin_protocol_v2
            .decapsulate(pin_protocol_v2.get_public_key(), PinUvAuthProtocol::V2)
            .unwrap();
        let ciphertext = shared_secret_v1.encrypt(&mut env, &message).unwrap();
        let plaintext = shared_secret_v2.decrypt(&ciphertext).unwrap();
        assert_ne!(&message, &*plaintext);
        let ciphertext = shared_secret_v2.encrypt(&mut env, &message).unwrap();
        let plaintext = shared_secret_v1.decrypt(&ciphertext).unwrap();
        assert_ne!(&message, &*plaintext);

        let fake_secret_v1 = pin_protocol_v1
            .decapsulate(pin_protocol_v2.get_public_key(), PinUvAuthProtocol::V1)
            .unwrap();
        let ciphertext = shared_secret_v1.encrypt(&mut env, &message).unwrap();
        let plaintext = fake_secret_v1.decrypt(&ciphertext).unwrap();
        assert_ne!(&message, &*plaintext);
        let ciphertext = fake_secret_v1.encrypt(&mut env, &message).unwrap();
        let plaintext = shared_secret_v1.decrypt(&ciphertext).unwrap();
        assert_ne!(&message, &*plaintext);

        let fake_secret_v2 = pin_protocol_v2
            .decapsulate(pin_protocol_v1.get_public_key(), PinUvAuthProtocol::V2)
            .unwrap();
        let ciphertext = shared_secret_v2.encrypt(&mut env, &message).unwrap();
        let plaintext = fake_secret_v2.decrypt(&ciphertext).unwrap();
        assert_ne!(&message, &*plaintext);
        let ciphertext = fake_secret_v2.encrypt(&mut env, &message).unwrap();
        let plaintext = shared_secret_v2.decrypt(&ciphertext).unwrap();
        assert_ne!(&message, &*plaintext);
    }

    fn test_helper_verify_pin_hash_enc(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let mut env = TestEnv::default();
        let mut client_pin = ClientPin::<TestEnv>::new(&mut env);
        let pin_protocol = client_pin.get_pin_protocol(pin_uv_auth_protocol);
        let shared_secret = pin_protocol
            .decapsulate(pin_protocol.get_public_key(), pin_uv_auth_protocol)
            .unwrap();
        // The PIN is "1234".
        let pin_hash = [
            0x01, 0xD9, 0x88, 0x40, 0x50, 0xBB, 0xD0, 0x7A, 0x23, 0x1A, 0xEB, 0x69, 0xD8, 0x36,
            0xC4, 0x12,
        ];
        storage::set_pin(&mut env, &pin_hash, 4).unwrap();

        let pin_hash_enc = shared_secret.encrypt(&mut env, &pin_hash).unwrap();
        assert_eq!(
            client_pin.verify_pin_hash_enc(
                &mut env,
                pin_uv_auth_protocol,
                &shared_secret,
                pin_hash_enc
            ),
            Ok(())
        );

        let pin_hash_enc = vec![0xEE; 16];
        assert_eq!(
            client_pin.verify_pin_hash_enc(
                &mut env,
                pin_uv_auth_protocol,
                &shared_secret,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );

        let pin_hash_enc = shared_secret.encrypt(&mut env, &pin_hash).unwrap();
        client_pin.consecutive_pin_mismatches = 3;
        assert_eq!(
            client_pin.verify_pin_hash_enc(
                &mut env,
                pin_uv_auth_protocol,
                &shared_secret,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_BLOCKED)
        );
        client_pin.consecutive_pin_mismatches = 0;

        let pin_hash_enc = vec![0x77; PIN_AUTH_LENGTH - 1];
        assert_eq!(
            client_pin.verify_pin_hash_enc(
                &mut env,
                pin_uv_auth_protocol,
                &shared_secret,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );

        let pin_hash_enc = vec![0x77; PIN_AUTH_LENGTH + 1];
        assert_eq!(
            client_pin.verify_pin_hash_enc(
                &mut env,
                pin_uv_auth_protocol,
                &shared_secret,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );
    }

    #[test]
    fn test_verify_pin_hash_enc_v1() {
        test_helper_verify_pin_hash_enc(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_verify_pin_hash_enc_v2() {
        test_helper_verify_pin_hash_enc(PinUvAuthProtocol::V2);
    }

    fn test_helper_process_get_pin_retries(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let (mut client_pin, params) = create_client_pin_and_parameters(
            pin_uv_auth_protocol,
            ClientPinSubCommand::GetPinRetries,
        );
        let mut env = TestEnv::default();
        let expected_response = Some(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_uv_auth_token: None,
            retries: Some(storage::pin_retries(&mut env).unwrap() as u64),
            power_cycle_state: Some(false),
        });
        assert_eq!(
            client_pin.process_command(&mut env, params.clone()),
            Ok(ResponseData::AuthenticatorClientPin(expected_response))
        );

        client_pin.consecutive_pin_mismatches = 3;
        let expected_response = Some(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_uv_auth_token: None,
            retries: Some(storage::pin_retries(&mut env).unwrap() as u64),
            power_cycle_state: Some(true),
        });
        assert_eq!(
            client_pin.process_command(&mut env, params),
            Ok(ResponseData::AuthenticatorClientPin(expected_response))
        );
    }

    #[test]
    fn test_process_get_pin_retries_v1() {
        test_helper_process_get_pin_retries(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_pin_retries_v2() {
        test_helper_process_get_pin_retries(PinUvAuthProtocol::V2);
    }

    fn test_helper_process_get_key_agreement(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let (mut client_pin, params) = create_client_pin_and_parameters(
            pin_uv_auth_protocol,
            ClientPinSubCommand::GetKeyAgreement,
        );
        let mut env = TestEnv::default();
        let expected_response = Some(AuthenticatorClientPinResponse {
            key_agreement: params.key_agreement.clone(),
            pin_uv_auth_token: None,
            retries: None,
            power_cycle_state: None,
        });
        assert_eq!(
            client_pin.process_command(&mut env, params),
            Ok(ResponseData::AuthenticatorClientPin(expected_response))
        );
    }

    #[test]
    fn test_process_get_key_agreement_v1() {
        test_helper_process_get_key_agreement(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_key_agreement_v2() {
        test_helper_process_get_key_agreement(PinUvAuthProtocol::V2);
    }

    #[test]
    fn test_process_get_key_agreement_v1_not_allowed() {
        let (mut client_pin, params) = create_client_pin_and_parameters(
            PinUvAuthProtocol::V1,
            ClientPinSubCommand::GetKeyAgreement,
        );
        let mut env = TestEnv::default();
        env.customization_mut().set_allows_pin_protocol_v1(false);
        assert_eq!(
            client_pin.process_command(&mut env, params),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );
    }

    fn test_helper_process_set_pin(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let (mut client_pin, params) =
            create_client_pin_and_parameters(pin_uv_auth_protocol, ClientPinSubCommand::SetPin);
        let mut env = TestEnv::default();
        assert_eq!(
            client_pin.process_command(&mut env, params),
            Ok(ResponseData::AuthenticatorClientPin(None))
        );
    }

    #[test]
    fn test_process_set_pin_v1() {
        test_helper_process_set_pin(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_set_pin_v2() {
        test_helper_process_set_pin(PinUvAuthProtocol::V2);
    }

    fn test_helper_process_change_pin(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let (mut client_pin, mut params) =
            create_client_pin_and_parameters(pin_uv_auth_protocol, ClientPinSubCommand::ChangePin);
        let shared_secret = client_pin
            .get_pin_protocol(pin_uv_auth_protocol)
            .decapsulate(
                params.key_agreement.clone().unwrap(),
                params.pin_uv_auth_protocol,
            )
            .unwrap();
        let mut env = TestEnv::default();
        set_standard_pin(&mut env);

        let mut auth_param_data = params.new_pin_enc.clone().unwrap();
        auth_param_data.extend(params.pin_hash_enc.as_ref().unwrap());
        let pin_uv_auth_param = shared_secret.authenticate(&auth_param_data);
        params.pin_uv_auth_param = Some(pin_uv_auth_param);
        assert_eq!(
            client_pin.process_command(&mut env, params.clone()),
            Ok(ResponseData::AuthenticatorClientPin(None))
        );

        let mut bad_params = params.clone();
        bad_params.pin_hash_enc = Some(vec![0xEE; 16]);
        assert_eq!(
            client_pin.process_command(&mut env, bad_params),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );

        while storage::pin_retries(&mut env).unwrap() > 0 {
            storage::decr_pin_retries(&mut env).unwrap();
        }
        assert_eq!(
            client_pin.process_command(&mut env, params),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED)
        );
    }

    #[test]
    fn test_process_change_pin_v1() {
        test_helper_process_change_pin(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_change_pin_v2() {
        test_helper_process_change_pin(PinUvAuthProtocol::V2);
    }

    fn test_helper_process_get_pin_token(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let (mut client_pin, params) = create_client_pin_and_parameters(
            pin_uv_auth_protocol,
            ClientPinSubCommand::GetPinToken,
        );
        let shared_secret = client_pin
            .get_pin_protocol(pin_uv_auth_protocol)
            .decapsulate(
                params.key_agreement.clone().unwrap(),
                params.pin_uv_auth_protocol,
            )
            .unwrap();
        let mut env = TestEnv::default();
        set_standard_pin(&mut env);

        let response = client_pin
            .process_command(&mut env, params.clone())
            .unwrap();
        let encrypted_token = match response {
            ResponseData::AuthenticatorClientPin(Some(response)) => {
                response.pin_uv_auth_token.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        assert_eq!(
            &*shared_secret.decrypt(&encrypted_token).unwrap(),
            client_pin
                .get_pin_protocol(pin_uv_auth_protocol)
                .get_pin_uv_auth_token()
        );
        assert_eq!(
            client_pin
                .pin_uv_auth_token_state
                .has_permission(PinPermission::MakeCredential),
            Ok(())
        );
        assert_eq!(
            client_pin
                .pin_uv_auth_token_state
                .has_permission(PinPermission::GetAssertion),
            Ok(())
        );
        assert_eq!(
            client_pin
                .pin_uv_auth_token_state
                .has_no_permissions_rp_id(),
            Ok(())
        );

        let mut bad_params = params;
        bad_params.pin_hash_enc = Some(vec![0xEE; 16]);
        assert_eq!(
            client_pin.process_command(&mut env, bad_params),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );
    }

    #[test]
    fn test_process_get_pin_token_v1() {
        test_helper_process_get_pin_token(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_pin_token_v2() {
        test_helper_process_get_pin_token(PinUvAuthProtocol::V2);
    }

    fn test_helper_process_get_pin_token_force_pin_change(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let (mut client_pin, params) = create_client_pin_and_parameters(
            pin_uv_auth_protocol,
            ClientPinSubCommand::GetPinToken,
        );
        let mut env = TestEnv::default();
        set_standard_pin(&mut env);

        assert_eq!(storage::force_pin_change(&mut env), Ok(()));
        assert_eq!(
            client_pin.process_command(&mut env, params),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID),
        );
    }

    #[test]
    fn test_process_get_pin_token_force_pin_change_v1() {
        test_helper_process_get_pin_token_force_pin_change(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_pin_token_force_pin_change_v2() {
        test_helper_process_get_pin_token_force_pin_change(PinUvAuthProtocol::V2);
    }

    fn test_helper_process_get_pin_uv_auth_token_using_pin_with_permissions(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let (mut client_pin, params) = create_client_pin_and_parameters(
            pin_uv_auth_protocol,
            ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
        );
        let shared_secret = client_pin
            .get_pin_protocol(pin_uv_auth_protocol)
            .decapsulate(
                params.key_agreement.clone().unwrap(),
                params.pin_uv_auth_protocol,
            )
            .unwrap();
        let mut env = TestEnv::default();
        set_standard_pin(&mut env);

        let response = client_pin
            .process_command(&mut env, params.clone())
            .unwrap();
        let encrypted_token = match response {
            ResponseData::AuthenticatorClientPin(Some(response)) => {
                response.pin_uv_auth_token.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        assert_eq!(
            &*shared_secret.decrypt(&encrypted_token).unwrap(),
            client_pin
                .get_pin_protocol(pin_uv_auth_protocol)
                .get_pin_uv_auth_token()
        );
        assert_eq!(
            client_pin
                .pin_uv_auth_token_state
                .has_permission(PinPermission::MakeCredential),
            Ok(())
        );
        assert_eq!(
            client_pin
                .pin_uv_auth_token_state
                .has_permission(PinPermission::GetAssertion),
            Ok(())
        );
        assert_eq!(
            client_pin
                .pin_uv_auth_token_state
                .has_permissions_rp_id("example.com"),
            Ok(())
        );

        let mut bad_params = params.clone();
        bad_params.permissions = Some(0x00);
        assert_eq!(
            client_pin.process_command(&mut env, bad_params),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        let mut bad_params = params.clone();
        bad_params.permissions_rp_id = None;
        assert_eq!(
            client_pin.process_command(&mut env, bad_params),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        let mut bad_params = params;
        bad_params.pin_hash_enc = Some(vec![0xEE; 16]);
        assert_eq!(
            client_pin.process_command(&mut env, bad_params),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );
    }

    #[test]
    fn test_process_get_pin_uv_auth_token_using_pin_with_permissions_v1() {
        test_helper_process_get_pin_uv_auth_token_using_pin_with_permissions(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_pin_uv_auth_token_using_pin_with_permissions_v2() {
        test_helper_process_get_pin_uv_auth_token_using_pin_with_permissions(PinUvAuthProtocol::V2);
    }

    fn test_helper_process_get_pin_uv_auth_token_using_pin_with_permissions_force_pin_change(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let (mut client_pin, params) = create_client_pin_and_parameters(
            pin_uv_auth_protocol,
            ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
        );
        let mut env = TestEnv::default();
        set_standard_pin(&mut env);

        assert_eq!(storage::force_pin_change(&mut env), Ok(()));
        assert_eq!(
            client_pin.process_command(&mut env, params),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );
    }

    #[test]
    fn test_process_get_pin_uv_auth_token_using_pin_with_permissions_force_pin_change_v1() {
        test_helper_process_get_pin_uv_auth_token_using_pin_with_permissions_force_pin_change(
            PinUvAuthProtocol::V1,
        );
    }

    #[test]
    fn test_process_get_pin_uv_auth_token_using_pin_with_permissions_force_pin_change_v2() {
        test_helper_process_get_pin_uv_auth_token_using_pin_with_permissions_force_pin_change(
            PinUvAuthProtocol::V2,
        );
    }

    fn test_helper_decrypt_pin(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let mut env = TestEnv::default();
        let pin_protocol = PinProtocol::<TestEnv>::new(&mut env);
        let shared_secret = pin_protocol
            .decapsulate(pin_protocol.get_public_key(), pin_uv_auth_protocol)
            .unwrap();

        let new_pin_enc = encrypt_pin(&shared_secret, b"1234".to_vec());
        assert_eq!(
            &*decrypt_pin::<TestEnv>(&shared_secret, new_pin_enc).unwrap(),
            b"1234",
        );

        let new_pin_enc = encrypt_pin(&shared_secret, b"123".to_vec());
        assert_eq!(
            &*decrypt_pin::<TestEnv>(&shared_secret, new_pin_enc).unwrap(),
            b"123",
        );

        // Encrypted PIN is too short.
        let new_pin_enc = vec![0x44; 63];
        assert_eq!(
            decrypt_pin::<TestEnv>(&shared_secret, new_pin_enc),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        // Encrypted PIN is too long.
        let new_pin_enc = vec![0x44; 65];
        assert_eq!(
            decrypt_pin::<TestEnv>(&shared_secret, new_pin_enc),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );
    }

    #[test]
    fn test_decrypt_pin_v1() {
        test_helper_decrypt_pin(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_decrypt_pin_v2() {
        test_helper_decrypt_pin(PinUvAuthProtocol::V2);
    }

    fn test_helper_check_and_store_new_pin(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let mut env = TestEnv::default();
        let pin_protocol = PinProtocol::<TestEnv>::new(&mut env);
        let shared_secret = pin_protocol
            .decapsulate(pin_protocol.get_public_key(), pin_uv_auth_protocol)
            .unwrap();

        let test_cases = vec![
            // Accept PIN "1234".
            (b"1234".to_vec(), Ok(())),
            // Reject PIN "123" since it is too short.
            (
                b"123".to_vec(),
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION),
            ),
            // Reject PIN "12'\0'4" (a zero byte at index 2).
            (
                [b'1', b'2', 0, b'4'].to_vec(),
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION),
            ),
            // PINs must be at most 63 bytes long, to allow for a trailing 0u8 padding.
            (
                vec![0x30; 64],
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION),
            ),
        ];
        for (pin, result) in test_cases {
            let old_pin_hash = storage::pin_hash(&mut env).unwrap();
            let new_pin_enc = encrypt_pin(&shared_secret, pin);

            assert_eq!(
                check_and_store_new_pin(&mut env, &shared_secret, new_pin_enc),
                result
            );
            if result.is_ok() {
                assert_ne!(old_pin_hash, storage::pin_hash(&mut env).unwrap());
            } else {
                assert_eq!(old_pin_hash, storage::pin_hash(&mut env).unwrap());
            }
        }
    }

    #[test]
    fn test_check_and_store_new_pin_v1() {
        test_helper_check_and_store_new_pin(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_check_and_store_new_pin_v2() {
        test_helper_check_and_store_new_pin(PinUvAuthProtocol::V2);
    }

    /// Generates valid inputs for process_hmac_secret and returns the output.
    fn get_process_hmac_secret_decrypted_output(
        pin_uv_auth_protocol: PinUvAuthProtocol,
        cred_random: &[u8; 32],
        salt: Vec<u8>,
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let mut env = TestEnv::default();
        let (client_pin, shared_secret) = create_client_pin_and_shared_secret(pin_uv_auth_protocol);

        let salt_enc = shared_secret.encrypt(&mut env, &salt).unwrap();
        let salt_auth = shared_secret.authenticate(&salt_enc);
        let hmac_secret_input = GetAssertionHmacSecretInput {
            key_agreement: client_pin
                .get_pin_protocol(pin_uv_auth_protocol)
                .get_public_key(),
            salt_enc,
            salt_auth,
            pin_uv_auth_protocol,
        };
        let output = client_pin.process_hmac_secret(&mut env, hmac_secret_input, cred_random);
        output.map(|v| shared_secret.decrypt(&v).unwrap().expose_secret_to_vec())
    }

    fn test_helper_process_hmac_secret_bad_salt_auth(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let mut env = TestEnv::default();
        let (client_pin, shared_secret) = create_client_pin_and_shared_secret(pin_uv_auth_protocol);
        let cred_random = [0xC9; 32];

        let salt_enc = vec![0x01; 32];
        let mut salt_auth = shared_secret.authenticate(&salt_enc);
        salt_auth[0] ^= 0x01;
        let hmac_secret_input = GetAssertionHmacSecretInput {
            key_agreement: client_pin
                .get_pin_protocol(pin_uv_auth_protocol)
                .get_public_key(),
            salt_enc,
            salt_auth,
            pin_uv_auth_protocol,
        };
        let output = client_pin.process_hmac_secret(&mut env, hmac_secret_input, &cred_random);
        assert_eq!(output, Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID));
    }

    #[test]
    fn test_process_hmac_secret_bad_salt_auth_v1() {
        test_helper_process_hmac_secret_bad_salt_auth(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_hmac_secret_bad_salt_auth_v2() {
        test_helper_process_hmac_secret_bad_salt_auth(PinUvAuthProtocol::V2);
    }

    fn test_helper_process_hmac_secret_one_salt(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let cred_random = [0xC9; 32];

        let salt = vec![0x01; 32];
        let mut expected_output = [0; HASH_SIZE];
        Hmac::<TestEnv>::mac(&cred_random, &salt, &mut expected_output);

        let output =
            get_process_hmac_secret_decrypted_output(pin_uv_auth_protocol, &cred_random, salt)
                .unwrap();
        assert_eq!(&*output, &expected_output);
    }

    #[test]
    fn test_process_hmac_secret_one_salt_v1() {
        test_helper_process_hmac_secret_one_salt(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_hmac_secret_one_salt_v2() {
        test_helper_process_hmac_secret_one_salt(PinUvAuthProtocol::V2);
    }

    fn test_helper_process_hmac_secret_two_salts(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let cred_random = [0xC9; 32];

        let salt1 = [0x01; 32];
        let salt2 = [0x02; 32];
        let mut expected_output1 = [0; HASH_SIZE];
        let mut expected_output2 = [0; HASH_SIZE];
        Hmac::<TestEnv>::mac(&cred_random, &salt1, &mut expected_output1);
        Hmac::<TestEnv>::mac(&cred_random, &salt2, &mut expected_output2);

        let mut salt12 = vec![0x00; 64];
        salt12[..32].copy_from_slice(&salt1);
        salt12[32..].copy_from_slice(&salt2);
        let output =
            get_process_hmac_secret_decrypted_output(pin_uv_auth_protocol, &cred_random, salt12)
                .unwrap();
        assert_eq!(&output[..32], &expected_output1);
        assert_eq!(&output[32..], &expected_output2);

        let mut salt02 = vec![0x00; 64];
        salt02[32..].copy_from_slice(&salt2);
        let output =
            get_process_hmac_secret_decrypted_output(pin_uv_auth_protocol, &cred_random, salt02)
                .unwrap();
        assert_eq!(&output[32..], &expected_output2);

        let mut salt10 = vec![0x00; 64];
        salt10[..32].copy_from_slice(&salt1);
        let output =
            get_process_hmac_secret_decrypted_output(pin_uv_auth_protocol, &cred_random, salt10)
                .unwrap();
        assert_eq!(&output[..32], &expected_output1);
    }

    #[test]
    fn test_process_hmac_secret_two_salts_v1() {
        test_helper_process_hmac_secret_two_salts(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_hmac_secret_two_salts_v2() {
        test_helper_process_hmac_secret_two_salts(PinUvAuthProtocol::V2);
    }

    fn test_helper_process_hmac_secret_wrong_length(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let cred_random = [0xC9; 32];

        let output = get_process_hmac_secret_decrypted_output(
            pin_uv_auth_protocol,
            &cred_random,
            vec![0x5E; 48],
        );
        assert_eq!(output, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER));
    }

    #[test]
    fn test_process_hmac_secret_wrong_length_v1() {
        test_helper_process_hmac_secret_wrong_length(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_hmac_secret_wrong_length_v2() {
        test_helper_process_hmac_secret_wrong_length(PinUvAuthProtocol::V2);
    }

    #[test]
    fn test_has_permission() {
        let mut env = TestEnv::default();
        let mut client_pin = ClientPin::<TestEnv>::new(&mut env);
        client_pin.pin_uv_auth_token_state.set_permissions(0x7F);
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(
                client_pin
                    .pin_uv_auth_token_state
                    .has_permission(permission),
                Ok(())
            );
        }
        client_pin.pin_uv_auth_token_state.set_permissions(0x00);
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(
                client_pin
                    .pin_uv_auth_token_state
                    .has_permission(permission),
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
            );
        }
    }

    #[test]
    fn test_has_no_rp_id_permission() {
        let mut env = TestEnv::default();
        let mut client_pin = ClientPin::<TestEnv>::new(&mut env);
        assert_eq!(client_pin.has_no_rp_id_permission(), Ok(()));
        client_pin
            .pin_uv_auth_token_state
            .set_permissions_rp_id(Some("example.com".to_string()));
        assert_eq!(
            client_pin.has_no_rp_id_permission(),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_has_no_or_rp_id_permission() {
        let mut env = TestEnv::default();
        let mut client_pin = ClientPin::<TestEnv>::new(&mut env);
        assert_eq!(client_pin.has_no_or_rp_id_permission("example.com"), Ok(()));
        client_pin
            .pin_uv_auth_token_state
            .set_permissions_rp_id(Some("example.com".to_string()));
        assert_eq!(client_pin.has_no_or_rp_id_permission("example.com"), Ok(()));
        assert_eq!(
            client_pin.has_no_or_rp_id_permission("another.example.com"),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_has_no_or_rp_id_hash_permission() {
        let mut env = TestEnv::default();
        let mut client_pin = ClientPin::<TestEnv>::new(&mut env);
        let rp_id_hash = Sha::<TestEnv>::digest(b"example.com");
        assert_eq!(
            client_pin.has_no_or_rp_id_hash_permission(&rp_id_hash),
            Ok(())
        );
        client_pin
            .pin_uv_auth_token_state
            .set_permissions_rp_id(Some("example.com".to_string()));
        assert_eq!(
            client_pin.has_no_or_rp_id_hash_permission(&rp_id_hash),
            Ok(())
        );
        assert_eq!(
            client_pin.has_no_or_rp_id_hash_permission(&[0x4A; 32]),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_ensure_rp_id_permission() {
        let mut env = TestEnv::default();
        let mut client_pin = ClientPin::<TestEnv>::new(&mut env);
        assert_eq!(client_pin.ensure_rp_id_permission("example.com"), Ok(()));
        assert_eq!(
            client_pin
                .pin_uv_auth_token_state
                .has_permissions_rp_id("example.com"),
            Ok(())
        );
        assert_eq!(client_pin.ensure_rp_id_permission("example.com"), Ok(()));
        assert_eq!(
            client_pin.ensure_rp_id_permission("another.example.com"),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_verify_pin_uv_auth_token() {
        let mut env = TestEnv::default();
        let mut client_pin = ClientPin::<TestEnv>::new(&mut env);
        let message = [0xAA];
        client_pin
            .pin_uv_auth_token_state
            .begin_using_pin_uv_auth_token(&mut env);

        let pin_uv_auth_token_v1 = client_pin
            .get_pin_protocol(PinUvAuthProtocol::V1)
            .get_pin_uv_auth_token();
        let pin_uv_auth_param_v1 =
            authenticate_pin_uv_auth_token(pin_uv_auth_token_v1, &message, PinUvAuthProtocol::V1);
        let pin_uv_auth_token_v2 = client_pin
            .get_pin_protocol(PinUvAuthProtocol::V2)
            .get_pin_uv_auth_token();
        let pin_uv_auth_param_v2 =
            authenticate_pin_uv_auth_token(pin_uv_auth_token_v2, &message, PinUvAuthProtocol::V2);
        let pin_uv_auth_param_v1_from_v2_token =
            authenticate_pin_uv_auth_token(pin_uv_auth_token_v2, &message, PinUvAuthProtocol::V1);
        let pin_uv_auth_param_v2_from_v1_token =
            authenticate_pin_uv_auth_token(pin_uv_auth_token_v1, &message, PinUvAuthProtocol::V2);

        assert_eq!(
            client_pin.verify_pin_uv_auth_token(
                &message,
                &pin_uv_auth_param_v1,
                PinUvAuthProtocol::V1
            ),
            Ok(())
        );
        assert_eq!(
            client_pin.verify_pin_uv_auth_token(
                &message,
                &pin_uv_auth_param_v2,
                PinUvAuthProtocol::V2
            ),
            Ok(())
        );
        assert_eq!(
            client_pin.verify_pin_uv_auth_token(
                &message,
                &pin_uv_auth_param_v1,
                PinUvAuthProtocol::V2
            ),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );
        assert_eq!(
            client_pin.verify_pin_uv_auth_token(
                &message,
                &pin_uv_auth_param_v2,
                PinUvAuthProtocol::V1
            ),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );
        assert_eq!(
            client_pin.verify_pin_uv_auth_token(
                &message,
                &pin_uv_auth_param_v1_from_v2_token,
                PinUvAuthProtocol::V1
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            client_pin.verify_pin_uv_auth_token(
                &message,
                &pin_uv_auth_param_v2_from_v1_token,
                PinUvAuthProtocol::V2
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_verify_pin_uv_auth_token_not_in_use() {
        let mut env = TestEnv::default();
        let client_pin = ClientPin::<TestEnv>::new(&mut env);
        let message = [0xAA];

        let pin_uv_auth_token_v1 = client_pin
            .get_pin_protocol(PinUvAuthProtocol::V1)
            .get_pin_uv_auth_token();
        let pin_uv_auth_param_v1 =
            authenticate_pin_uv_auth_token(pin_uv_auth_token_v1, &message, PinUvAuthProtocol::V1);

        assert_eq!(
            client_pin.verify_pin_uv_auth_token(
                &message,
                &pin_uv_auth_param_v1,
                PinUvAuthProtocol::V1
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_reset() {
        let mut env = TestEnv::default();
        let mut client_pin = ClientPin::<TestEnv>::new(&mut env);
        let public_key_v1 = client_pin.pin_protocol_v1.get_public_key();
        let public_key_v2 = client_pin.pin_protocol_v2.get_public_key();
        let token_v1 = *client_pin.pin_protocol_v1.get_pin_uv_auth_token();
        let token_v2 = *client_pin.pin_protocol_v2.get_pin_uv_auth_token();
        client_pin.pin_uv_auth_token_state.set_permissions(0xFF);
        client_pin
            .pin_uv_auth_token_state
            .set_permissions_rp_id(Some(String::from("example.com")));
        client_pin.reset(&mut env);
        assert_ne!(public_key_v1, client_pin.pin_protocol_v1.get_public_key());
        assert_ne!(public_key_v2, client_pin.pin_protocol_v2.get_public_key());
        assert_ne!(
            &token_v1,
            client_pin.pin_protocol_v1.get_pin_uv_auth_token()
        );
        assert_ne!(
            &token_v2,
            client_pin.pin_protocol_v2.get_pin_uv_auth_token()
        );
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(
                client_pin.has_permission(permission),
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
            );
        }
        assert_eq!(client_pin.has_no_rp_id_permission(), Ok(()));
    }

    #[test]
    fn test_update_timeouts() {
        let (mut client_pin, mut params) = create_client_pin_and_parameters(
            PinUvAuthProtocol::V2,
            ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
        );
        let mut env = TestEnv::default();
        set_standard_pin(&mut env);
        params.permissions = Some(0xFF);

        assert!(client_pin.process_command(&mut env, params).is_ok());
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(
                client_pin
                    .pin_uv_auth_token_state
                    .has_permission(permission),
                Ok(())
            );
        }
        assert_eq!(
            client_pin
                .pin_uv_auth_token_state
                .has_permissions_rp_id("example.com"),
            Ok(())
        );

        env.clock().advance(30001);
        client_pin.update_timeouts(&mut env);
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(
                client_pin
                    .pin_uv_auth_token_state
                    .has_permission(permission),
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
            );
        }
        assert_eq!(
            client_pin
                .pin_uv_auth_token_state
                .has_permissions_rp_id("example.com"),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_clear_token_flags() {
        let (mut client_pin, mut params) = create_client_pin_and_parameters(
            PinUvAuthProtocol::V2,
            ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
        );
        let mut env = TestEnv::default();
        set_standard_pin(&mut env);
        params.permissions = Some(0xFF);

        assert!(client_pin.process_command(&mut env, params).is_ok());
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(
                client_pin
                    .pin_uv_auth_token_state
                    .has_permission(permission),
                Ok(())
            );
        }
        assert_eq!(client_pin.check_user_verified_flag(), Ok(()));

        client_pin.clear_token_flags();
        assert_eq!(
            client_pin
                .pin_uv_auth_token_state
                .has_permission(PinPermission::CredentialManagement),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            client_pin
                .pin_uv_auth_token_state
                .has_permission(PinPermission::LargeBlobWrite),
            Ok(())
        );
        assert_eq!(
            client_pin.check_user_verified_flag(),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}
