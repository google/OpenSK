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

use super::command::AuthenticatorClientPinParameters;
use super::data_formats::{ClientPinSubCommand, CoseKey, GetAssertionHmacSecretInput};
use super::response::{AuthenticatorClientPinResponse, ResponseData};
use super::status_code::Ctap2StatusCode;
use super::storage::PersistentStore;
#[cfg(feature = "with_ctap2_1")]
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryInto;
use crypto::cbc::{cbc_decrypt, cbc_encrypt};
use crypto::hmac::{hmac_256, verify_hmac_256_first_128bits};
use crypto::rng256::Rng256;
use crypto::sha256::Sha256;
use crypto::Hash256;
#[cfg(all(test, feature = "with_ctap2_1"))]
use enum_iterator::IntoEnumIterator;
use subtle::ConstantTimeEq;

// Those constants have to be multiples of 16, the AES block size.
pub const PIN_AUTH_LENGTH: usize = 16;
const PIN_PADDED_LENGTH: usize = 64;
const PIN_TOKEN_LENGTH: usize = 32;

/// Checks the given pin_auth against the truncated output of HMAC-SHA256.
fn check_pin_auth(hmac_key: &[u8], hmac_contents: &[u8], pin_auth: &[u8]) -> bool {
    if pin_auth.len() != PIN_AUTH_LENGTH {
        return false;
    }
    verify_hmac_256_first_128bits::<Sha256>(
        hmac_key,
        hmac_contents,
        array_ref![pin_auth, 0, PIN_AUTH_LENGTH],
    )
}

/// Decrypts the HMAC secret salt(s) that were encrypted with the shared secret.
/// The credRandom is used as a secret to HMAC those salts.
/// The last step is to re-encrypt the outputs.
fn encrypt_hmac_secret_output(
    shared_secret: &[u8; 32],
    salt_enc: &[u8],
    cred_random: &[u8],
) -> Result<Vec<u8>, Ctap2StatusCode> {
    if salt_enc.len() != 32 && salt_enc.len() != 64 {
        return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION);
    }
    if cred_random.len() != 32 {
        // We are strict here. We need at least 32 byte, but expect exactly 32.
        return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION);
    }
    let aes_enc_key = crypto::aes256::EncryptionKey::new(shared_secret);
    let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);
    // The specification specifically asks for a zero IV.
    let iv = [0u8; 16];

    let mut cred_random_secret = [0u8; 32];
    cred_random_secret.clone_from_slice(cred_random);

    // Initialization of 4 blocks in any case makes this function more readable.
    let mut blocks = [[0u8; 16]; 4];
    let block_len = salt_enc.len() / 16;
    for i in 0..block_len {
        blocks[i].copy_from_slice(&salt_enc[16 * i..16 * (i + 1)]);
    }
    cbc_decrypt(&aes_dec_key, iv, &mut blocks[..block_len]);

    let mut decrypted_salt1 = [0u8; 32];
    decrypted_salt1[..16].clone_from_slice(&blocks[0]);
    let output1 = hmac_256::<Sha256>(&cred_random_secret, &decrypted_salt1[..]);
    decrypted_salt1[16..].clone_from_slice(&blocks[1]);
    for i in 0..2 {
        blocks[i].copy_from_slice(&output1[16 * i..16 * (i + 1)]);
    }

    if block_len == 4 {
        let mut decrypted_salt2 = [0u8; 32];
        decrypted_salt2[..16].clone_from_slice(&blocks[2]);
        decrypted_salt2[16..].clone_from_slice(&blocks[3]);
        let output2 = hmac_256::<Sha256>(&cred_random_secret, &decrypted_salt2[..]);
        for i in 0..2 {
            blocks[i + 2].copy_from_slice(&output2[16 * i..16 * (i + 1)]);
        }
    }

    cbc_encrypt(&aes_enc_key, iv, &mut blocks[..block_len]);
    let mut encrypted_output = Vec::with_capacity(salt_enc.len());
    for b in &blocks[..block_len] {
        encrypted_output.extend(b);
    }
    Ok(encrypted_output)
}

fn check_and_store_new_pin(
    persistent_store: &mut PersistentStore,
    aes_dec_key: &crypto::aes256::DecryptionKey,
    new_pin_enc: Vec<u8>,
) -> bool {
    if new_pin_enc.len() != PIN_PADDED_LENGTH {
        return false;
    }
    let iv = [0u8; 16];
    // Assuming PIN_PADDED_LENGTH % block_size == 0 here.
    let mut blocks = [[0u8; 16]; PIN_PADDED_LENGTH / 16];
    for i in 0..PIN_PADDED_LENGTH / 16 {
        blocks[i].copy_from_slice(&new_pin_enc[i * 16..(i + 1) * 16]);
    }
    cbc_decrypt(aes_dec_key, iv, &mut blocks);
    let mut pin = vec![];
    'pin_block_loop: for block in blocks.iter().take(PIN_PADDED_LENGTH / 16) {
        for cur_char in block.iter() {
            if *cur_char != 0 {
                pin.push(*cur_char);
            } else {
                break 'pin_block_loop;
            }
        }
    }
    #[cfg(feature = "with_ctap2_1")]
    let min_pin_length = persistent_store.min_pin_length() as usize;
    #[cfg(not(feature = "with_ctap2_1"))]
    let min_pin_length = 4;
    if pin.len() < min_pin_length || pin.len() == PIN_PADDED_LENGTH {
        // TODO(kaczmarczyck) check 4 code point minimum instead
        // TODO(kaczmarczyck) check last byte == 0x00
        return false;
    }
    let mut pin_hash = [0u8; 16];
    pin_hash.copy_from_slice(&Sha256::hash(&pin[..])[..16]);
    persistent_store.set_pin_hash(&pin_hash);
    true
}

#[cfg(feature = "with_ctap2_1")]
#[cfg_attr(test, derive(IntoEnumIterator))]
// TODO remove when all variants are used
#[allow(dead_code)]
pub enum PinPermission {
    // All variants should use integers with a single bit set.
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    CredentialManagement = 0x04,
    BioEnrollment = 0x08,
    PlatformConfiguration = 0x10,
    AuthenticatorConfiguration = 0x20,
}

pub struct PinProtocolV1 {
    key_agreement_key: crypto::ecdh::SecKey,
    pin_uv_auth_token: [u8; PIN_TOKEN_LENGTH],
    consecutive_pin_mismatches: u8,
    #[cfg(feature = "with_ctap2_1")]
    permissions: u8,
    #[cfg(feature = "with_ctap2_1")]
    permissions_rp_id: Option<String>,
}

impl PinProtocolV1 {
    pub fn new(rng: &mut impl Rng256) -> PinProtocolV1 {
        let key_agreement_key = crypto::ecdh::SecKey::gensk(rng);
        let pin_uv_auth_token = rng.gen_uniform_u8x32();
        PinProtocolV1 {
            key_agreement_key,
            pin_uv_auth_token,
            consecutive_pin_mismatches: 0,
            #[cfg(feature = "with_ctap2_1")]
            permissions: 0,
            #[cfg(feature = "with_ctap2_1")]
            permissions_rp_id: None,
        }
    }

    fn check_pin_hash_enc(
        &mut self,
        rng: &mut impl Rng256,
        persistent_store: &mut PersistentStore,
        aes_dec_key: &crypto::aes256::DecryptionKey,
        pin_hash_enc: Vec<u8>,
    ) -> Result<(), Ctap2StatusCode> {
        match persistent_store.pin_hash() {
            Some(pin_hash) => {
                if self.consecutive_pin_mismatches >= 3 {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_BLOCKED);
                }
                // We need to copy the pin hash, because decrementing the pin retries below may
                // invalidate the reference (if the page containing the pin hash is compacted).
                let pin_hash = pin_hash.to_vec();
                persistent_store.decr_pin_retries();
                if pin_hash_enc.len() != PIN_AUTH_LENGTH {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }

                let iv = [0u8; 16];
                let mut blocks = [[0u8; 16]; 1];
                blocks[0].copy_from_slice(&pin_hash_enc[0..PIN_AUTH_LENGTH]);
                cbc_decrypt(aes_dec_key, iv, &mut blocks);

                let pin_comparison = array_ref![pin_hash, 0, PIN_AUTH_LENGTH].ct_eq(&blocks[0]);
                if !bool::from(pin_comparison) {
                    self.key_agreement_key = crypto::ecdh::SecKey::gensk(rng);
                    if persistent_store.pin_retries() == 0 {
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
            None => return Err(Ctap2StatusCode::CTAP2_ERR_PIN_REQUIRED),
        }
        persistent_store.reset_pin_retries();
        self.consecutive_pin_mismatches = 0;
        Ok(())
    }

    fn process_get_pin_retries(
        &self,
        persistent_store: &PersistentStore,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: None,
            retries: Some(persistent_store.pin_retries() as u64),
        })
    }

    fn process_get_key_agreement(&self) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        let pk = self.key_agreement_key.genpk();
        Ok(AuthenticatorClientPinResponse {
            key_agreement: Some(CoseKey::from(pk)),
            pin_token: None,
            retries: None,
        })
    }

    fn process_set_pin(
        &mut self,
        persistent_store: &mut PersistentStore,
        key_agreement: CoseKey,
        pin_auth: Vec<u8>,
        new_pin_enc: Vec<u8>,
    ) -> Result<(), Ctap2StatusCode> {
        if persistent_store.pin_hash().is_some() {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let pk: crypto::ecdh::PubKey = CoseKey::try_into(key_agreement)?;
        let shared_secret = self.key_agreement_key.exchange_x_sha256(&pk);

        if !check_pin_auth(&shared_secret, &new_pin_enc, &pin_auth) {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }

        let aes_enc_key = crypto::aes256::EncryptionKey::new(&shared_secret);
        let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);
        if !check_and_store_new_pin(persistent_store, &aes_dec_key, new_pin_enc) {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        persistent_store.reset_pin_retries();
        Ok(())
    }

    fn process_change_pin(
        &mut self,
        rng: &mut impl Rng256,
        persistent_store: &mut PersistentStore,
        key_agreement: CoseKey,
        pin_auth: Vec<u8>,
        new_pin_enc: Vec<u8>,
        pin_hash_enc: Vec<u8>,
    ) -> Result<(), Ctap2StatusCode> {
        if persistent_store.pin_retries() == 0 {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
        }
        let pk: crypto::ecdh::PubKey = CoseKey::try_into(key_agreement)?;
        let shared_secret = self.key_agreement_key.exchange_x_sha256(&pk);

        let mut auth_param_data = new_pin_enc.clone();
        auth_param_data.extend(&pin_hash_enc);
        if !check_pin_auth(&shared_secret, &auth_param_data, &pin_auth) {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }

        let aes_enc_key = crypto::aes256::EncryptionKey::new(&shared_secret);
        let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);
        self.check_pin_hash_enc(rng, persistent_store, &aes_dec_key, pin_hash_enc)?;

        if !check_and_store_new_pin(persistent_store, &aes_dec_key, new_pin_enc) {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        self.pin_uv_auth_token = rng.gen_uniform_u8x32();
        Ok(())
    }

    fn process_get_pin_token(
        &mut self,
        rng: &mut impl Rng256,
        persistent_store: &mut PersistentStore,
        key_agreement: CoseKey,
        pin_hash_enc: Vec<u8>,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        if persistent_store.pin_retries() == 0 {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
        }
        let pk: crypto::ecdh::PubKey = CoseKey::try_into(key_agreement)?;
        let shared_secret = self.key_agreement_key.exchange_x_sha256(&pk);

        let aes_enc_key = crypto::aes256::EncryptionKey::new(&shared_secret);
        let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);
        self.check_pin_hash_enc(rng, persistent_store, &aes_dec_key, pin_hash_enc)?;

        // Assuming PIN_TOKEN_LENGTH % block_size == 0 here.
        let iv = [0u8; 16];
        let mut blocks = [[0u8; 16]; PIN_TOKEN_LENGTH / 16];
        for (i, item) in blocks.iter_mut().take(PIN_TOKEN_LENGTH / 16).enumerate() {
            item.copy_from_slice(&self.pin_uv_auth_token[i * 16..(i + 1) * 16]);
        }
        cbc_encrypt(&aes_enc_key, iv, &mut blocks);
        let mut pin_token = vec![];
        for item in blocks.iter().take(PIN_TOKEN_LENGTH / 16) {
            pin_token.extend(item);
        }

        #[cfg(feature = "with_ctap2_1")]
        {
            self.permissions = 0x03;
            self.permissions_rp_id = None;
        }

        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: Some(pin_token),
            retries: None,
        })
    }

    #[cfg(feature = "with_ctap2_1")]
    fn process_get_pin_uv_auth_token_using_uv_with_permissions(
        &self,
        _: CoseKey,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // User verifications is only supported through PIN currently.
        #[cfg(not(feature = "with_ctap2_1"))]
        {
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND)
        }
        #[cfg(feature = "with_ctap2_1")]
        {
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND)
        }
    }

    #[cfg(feature = "with_ctap2_1")]
    fn process_get_uv_retries(&self) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // User verifications is only supported through PIN currently.
        #[cfg(not(feature = "with_ctap2_1"))]
        {
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND)
        }
        #[cfg(feature = "with_ctap2_1")]
        {
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND)
        }
    }

    #[cfg(feature = "with_ctap2_1")]
    fn process_set_min_pin_length(
        &mut self,
        persistent_store: &mut PersistentStore,
        min_pin_length: u8,
        min_pin_length_rp_ids: Option<Vec<String>>,
        pin_auth: Option<Vec<u8>>,
    ) -> Result<(), Ctap2StatusCode> {
        if min_pin_length_rp_ids.is_some() {
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION);
        }
        if persistent_store.pin_hash().is_some() {
            match pin_auth {
                Some(pin_auth) => {
                    // TODO(kaczmarczyck) not mentioned, but maybe useful?
                    // if persistent_store.pin_retries() == 0 {
                    //     return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
                    // }
                    if self.consecutive_pin_mismatches >= 3 {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_BLOCKED);
                    }
                    let mut message = vec![0xFF; 32];
                    message.extend(&[0x06, 0x08]);
                    message.extend(&[min_pin_length as u8, 0x00, 0x00, 0x00]);
                    // TODO(kaczmarczyck) commented code is useful for the extension
                    // if !cbor::write(cbor_array_vec!(min_pin_length_rp_ids), &mut message) {
                    //     return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_RESPONSE_CANNOT_WRITE_CBOR);
                    // }
                    if !check_pin_auth(&self.pin_uv_auth_token, &message, &pin_auth) {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
                    }
                }
                None => return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID),
            };
        }
        if min_pin_length < persistent_store.min_pin_length() {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        persistent_store.set_min_pin_length(min_pin_length);
        // if let Some(min_pin_length_rp_ids) = min_pin_length_rp_ids {
        //     persistent_store.set_min_pin_length_rp_ids(min_pin_length_rp_ids)?;
        // }
        Ok(())
    }

    #[cfg(feature = "with_ctap2_1")]
    fn process_get_pin_uv_auth_token_using_pin_with_permissions(
        &mut self,
        rng: &mut impl Rng256,
        persistent_store: &mut PersistentStore,
        key_agreement: CoseKey,
        pin_hash_enc: Vec<u8>,
        permissions: u8,
        permissions_rp_id: Option<String>,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        if permissions == 0 {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        // This check is not mentioned protocol steps, but mentioned in a side note.
        if permissions & 0x03 != 0 && permissions_rp_id.is_none() {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }

        let response =
            self.process_get_pin_token(rng, persistent_store, key_agreement, pin_hash_enc)?;

        self.permissions = permissions;
        self.permissions_rp_id = permissions_rp_id;

        Ok(response)
    }

    pub fn process(
        &mut self,
        rng: &mut impl Rng256,
        persistent_store: &mut PersistentStore,
        client_pin_params: AuthenticatorClientPinParameters,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let AuthenticatorClientPinParameters {
            pin_protocol,
            sub_command,
            key_agreement,
            pin_auth,
            new_pin_enc,
            pin_hash_enc,
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length,
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length_rp_ids,
            #[cfg(feature = "with_ctap2_1")]
            permissions,
            #[cfg(feature = "with_ctap2_1")]
            permissions_rp_id,
        } = client_pin_params;

        if pin_protocol != 1 {
            #[cfg(not(feature = "with_ctap2_1"))]
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
            #[cfg(feature = "with_ctap2_1")]
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }

        let response = match sub_command {
            ClientPinSubCommand::GetPinRetries => {
                Some(self.process_get_pin_retries(persistent_store)?)
            }
            ClientPinSubCommand::GetKeyAgreement => Some(self.process_get_key_agreement()?),
            ClientPinSubCommand::SetPin => {
                self.process_set_pin(
                    persistent_store,
                    key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    pin_auth.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    new_pin_enc.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                None
            }
            ClientPinSubCommand::ChangePin => {
                self.process_change_pin(
                    rng,
                    persistent_store,
                    key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    pin_auth.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    new_pin_enc.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    pin_hash_enc.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                None
            }
            ClientPinSubCommand::GetPinToken => Some(self.process_get_pin_token(
                rng,
                persistent_store,
                key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                pin_hash_enc.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
            )?),
            #[cfg(feature = "with_ctap2_1")]
            ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions => Some(
                self.process_get_pin_uv_auth_token_using_uv_with_permissions(
                    key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?,
            ),
            #[cfg(feature = "with_ctap2_1")]
            ClientPinSubCommand::GetUvRetries => Some(self.process_get_uv_retries()?),
            #[cfg(feature = "with_ctap2_1")]
            ClientPinSubCommand::SetMinPinLength => {
                self.process_set_min_pin_length(
                    persistent_store,
                    min_pin_length.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    min_pin_length_rp_ids,
                    pin_auth,
                )?;
                None
            }
            #[cfg(feature = "with_ctap2_1")]
            ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions => Some(
                self.process_get_pin_uv_auth_token_using_pin_with_permissions(
                    rng,
                    persistent_store,
                    key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    pin_hash_enc.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    permissions.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    permissions_rp_id,
                )?,
            ),
        };
        Ok(ResponseData::AuthenticatorClientPin(response))
    }

    pub fn check_pin_auth_token(&self, hmac_contents: &[u8], pin_auth: &[u8]) -> bool {
        check_pin_auth(&self.pin_uv_auth_token, &hmac_contents, &pin_auth)
    }

    pub fn reset(&mut self, rng: &mut impl Rng256) {
        self.key_agreement_key = crypto::ecdh::SecKey::gensk(rng);
        self.pin_uv_auth_token = rng.gen_uniform_u8x32();
        self.consecutive_pin_mismatches = 0;
        #[cfg(feature = "with_ctap2_1")]
        {
            self.permissions = 0;
            self.permissions_rp_id = None;
        }
    }

    pub fn process_hmac_secret(
        &self,
        hmac_secret_input: GetAssertionHmacSecretInput,
        cred_random: &Option<Vec<u8>>,
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let GetAssertionHmacSecretInput {
            key_agreement,
            salt_enc,
            salt_auth,
        } = hmac_secret_input;
        let pk: crypto::ecdh::PubKey = CoseKey::try_into(key_agreement)?;
        let shared_secret = self.key_agreement_key.exchange_x_sha256(&pk);
        // HMAC-secret does the same 16 byte truncated check.
        if !check_pin_auth(&shared_secret, &salt_enc, &salt_auth) {
            // Hard to tell what the correct error code here is.
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION);
        }

        match cred_random {
            Some(cr) => encrypt_hmac_secret_output(&shared_secret, &salt_enc[..], cr),
            // This is the case if the credential was not created with HMAC-secret.
            None => Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION),
        }
    }

    #[cfg(feature = "with_ctap2_1")]
    pub fn has_permission(&self, permission: PinPermission) -> Result<(), Ctap2StatusCode> {
        // Relies on the fact that all permissions are represented by powers of two.
        if permission as u8 & self.permissions != 0 {
            Ok(())
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    #[cfg(feature = "with_ctap2_1")]
    pub fn has_permission_for_rp_id(&mut self, rp_id: &str) -> Result<(), Ctap2StatusCode> {
        if let Some(permissions_rp_id) = &self.permissions_rp_id {
            if rp_id != permissions_rp_id {
                return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
            }
        } else {
            self.permissions_rp_id = Some(String::from(rp_id));
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto::rng256::ThreadRng256;

    fn set_standard_pin(persistent_store: &mut PersistentStore) {
        let mut pin = [0u8; 64];
        pin[0] = 0x31;
        pin[1] = 0x32;
        pin[2] = 0x33;
        pin[3] = 0x34;
        let mut pin_hash = [0u8; 16];
        pin_hash.copy_from_slice(&Sha256::hash(&pin[..])[..16]);
        persistent_store.set_pin_hash(&pin_hash);
    }

    fn encrypt_standard_pin(shared_secret: &[u8; 32]) -> Vec<u8> {
        let aes_enc_key = crypto::aes256::EncryptionKey::new(shared_secret);
        let mut blocks = [[0u8; 16]; 4];
        blocks[0][0] = 0x31;
        blocks[0][1] = 0x32;
        blocks[0][2] = 0x33;
        blocks[0][3] = 0x34;
        let iv = [0u8; 16];
        cbc_encrypt(&aes_enc_key, iv, &mut blocks);

        let mut encrypted_pin = Vec::with_capacity(64);
        for b in &blocks {
            encrypted_pin.extend(b);
        }
        encrypted_pin
    }

    fn encrypt_standard_pin_hash(shared_secret: &[u8; 32]) -> Vec<u8> {
        let aes_enc_key = crypto::aes256::EncryptionKey::new(shared_secret);
        let mut pin = [0u8; 64];
        pin[0] = 0x31;
        pin[1] = 0x32;
        pin[2] = 0x33;
        pin[3] = 0x34;
        let pin_hash = Sha256::hash(&pin);

        let mut blocks = [[0u8; 16]; 1];
        blocks[0].copy_from_slice(&pin_hash[..16]);
        let iv = [0u8; 16];
        cbc_encrypt(&aes_enc_key, iv, &mut blocks);

        let mut encrypted_pin_hash = Vec::with_capacity(16);
        encrypted_pin_hash.extend(&blocks[0]);
        encrypted_pin_hash
    }

    #[test]
    fn test_check_pin_hash_enc() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        // The PIN is "1234".
        let pin_hash = [
            0x01, 0xD9, 0x88, 0x40, 0x50, 0xBB, 0xD0, 0x7A, 0x23, 0x1A, 0xEB, 0x69, 0xD8, 0x36,
            0xC4, 0x12,
        ];
        persistent_store.set_pin_hash(&pin_hash);
        let shared_secret = [0x88; 32];
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&shared_secret);
        let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);

        let mut pin_protocol_v1 = PinProtocolV1::new(&mut rng);
        let pin_hash_enc = vec![
            0x8D, 0x7A, 0xA3, 0x9F, 0x7F, 0xC6, 0x08, 0x13, 0x9A, 0xC8, 0x56, 0x97, 0x70, 0x74,
            0x99, 0x66,
        ];
        assert_eq!(
            pin_protocol_v1.check_pin_hash_enc(
                &mut rng,
                &mut persistent_store,
                &aes_dec_key,
                pin_hash_enc
            ),
            Ok(())
        );

        let pin_hash_enc = vec![0xEE; 16];
        assert_eq!(
            pin_protocol_v1.check_pin_hash_enc(
                &mut rng,
                &mut persistent_store,
                &aes_dec_key,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );

        let pin_hash_enc = vec![
            0x8D, 0x7A, 0xA3, 0x9F, 0x7F, 0xC6, 0x08, 0x13, 0x9A, 0xC8, 0x56, 0x97, 0x70, 0x74,
            0x99, 0x66,
        ];
        pin_protocol_v1.consecutive_pin_mismatches = 3;
        assert_eq!(
            pin_protocol_v1.check_pin_hash_enc(
                &mut rng,
                &mut persistent_store,
                &aes_dec_key,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_BLOCKED)
        );
    }

    #[test]
    fn test_process_get_pin_retries() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let pin_protocol_v1 = PinProtocolV1::new(&mut rng);
        let expected_response = Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: None,
            retries: Some(persistent_store.pin_retries() as u64),
        });
        assert_eq!(
            pin_protocol_v1.process_get_pin_retries(&mut persistent_store),
            expected_response
        );
    }

    #[test]
    fn test_process_get_key_agreement() {
        let mut rng = ThreadRng256 {};
        let pin_protocol_v1 = PinProtocolV1::new(&mut rng);
        let pk = pin_protocol_v1.key_agreement_key.genpk();
        let expected_response = Ok(AuthenticatorClientPinResponse {
            key_agreement: Some(CoseKey::from(pk)),
            pin_token: None,
            retries: None,
        });
        assert_eq!(
            pin_protocol_v1.process_get_key_agreement(),
            expected_response
        );
    }

    #[test]
    fn test_process_set_pin() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let mut pin_protocol_v1 = PinProtocolV1::new(&mut rng);
        let pk = pin_protocol_v1.key_agreement_key.genpk();
        let shared_secret = pin_protocol_v1.key_agreement_key.exchange_x_sha256(&pk);
        let key_agreement = CoseKey::from(pk);
        let new_pin_enc = encrypt_standard_pin(&shared_secret);
        let pin_auth = hmac_256::<Sha256>(&shared_secret, &new_pin_enc[..])[..16].to_vec();
        assert_eq!(
            pin_protocol_v1.process_set_pin(
                &mut persistent_store,
                key_agreement,
                pin_auth,
                new_pin_enc
            ),
            Ok(())
        );
    }

    #[test]
    fn test_process_change_pin() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        set_standard_pin(&mut persistent_store);
        let mut pin_protocol_v1 = PinProtocolV1::new(&mut rng);
        let pk = pin_protocol_v1.key_agreement_key.genpk();
        let shared_secret = pin_protocol_v1.key_agreement_key.exchange_x_sha256(&pk);
        let key_agreement = CoseKey::from(pk);
        let new_pin_enc = encrypt_standard_pin(&shared_secret);
        let pin_hash_enc = encrypt_standard_pin_hash(&shared_secret);
        let mut auth_param_data = new_pin_enc.clone();
        auth_param_data.extend(&pin_hash_enc);
        let pin_auth = hmac_256::<Sha256>(&shared_secret, &auth_param_data[..])[..16].to_vec();
        assert_eq!(
            pin_protocol_v1.process_change_pin(
                &mut rng,
                &mut persistent_store,
                key_agreement.clone(),
                pin_auth.clone(),
                new_pin_enc.clone(),
                pin_hash_enc.clone()
            ),
            Ok(())
        );

        let bad_pin_hash_enc = vec![0xEE; 16];
        assert_eq!(
            pin_protocol_v1.process_change_pin(
                &mut rng,
                &mut persistent_store,
                key_agreement.clone(),
                pin_auth.clone(),
                new_pin_enc.clone(),
                bad_pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );

        while persistent_store.pin_retries() > 0 {
            persistent_store.decr_pin_retries();
        }
        assert_eq!(
            pin_protocol_v1.process_change_pin(
                &mut rng,
                &mut persistent_store,
                key_agreement,
                pin_auth,
                new_pin_enc,
                pin_hash_enc,
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED)
        );
    }

    #[test]
    fn test_process_get_pin_token() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        set_standard_pin(&mut persistent_store);
        let mut pin_protocol_v1 = PinProtocolV1::new(&mut rng);
        let pk = pin_protocol_v1.key_agreement_key.genpk();
        let shared_secret = pin_protocol_v1.key_agreement_key.exchange_x_sha256(&pk);
        let key_agreement = CoseKey::from(pk);
        let pin_hash_enc = encrypt_standard_pin_hash(&shared_secret);
        assert!(pin_protocol_v1
            .process_get_pin_token(
                &mut rng,
                &mut persistent_store,
                key_agreement.clone(),
                pin_hash_enc
            )
            .is_ok());

        let pin_hash_enc = vec![0xEE; 16];
        assert_eq!(
            pin_protocol_v1.process_get_pin_token(
                &mut rng,
                &mut persistent_store,
                key_agreement,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );
    }

    #[cfg(feature = "with_ctap2_1")]
    #[test]
    fn test_process_get_pin_uv_auth_token_using_pin_with_permissions() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        set_standard_pin(&mut persistent_store);
        let mut pin_protocol_v1 = PinProtocolV1::new(&mut rng);
        let pk = pin_protocol_v1.key_agreement_key.genpk();
        let shared_secret = pin_protocol_v1.key_agreement_key.exchange_x_sha256(&pk);
        let key_agreement = CoseKey::from(pk);
        let pin_hash_enc = encrypt_standard_pin_hash(&shared_secret);
        assert!(pin_protocol_v1
            .process_get_pin_uv_auth_token_using_pin_with_permissions(
                &mut rng,
                &mut persistent_store,
                key_agreement.clone(),
                pin_hash_enc.clone(),
                0x03,
                Some(String::from("example.com")),
            )
            .is_ok());
        assert_eq!(pin_protocol_v1.permissions, 0x03);
        assert_eq!(
            pin_protocol_v1.permissions_rp_id,
            Some(String::from("example.com"))
        );

        assert_eq!(
            pin_protocol_v1.process_get_pin_uv_auth_token_using_pin_with_permissions(
                &mut rng,
                &mut persistent_store,
                key_agreement.clone(),
                pin_hash_enc.clone(),
                0x00,
                Some(String::from("example.com")),
            ),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        assert_eq!(
            pin_protocol_v1.process_get_pin_uv_auth_token_using_pin_with_permissions(
                &mut rng,
                &mut persistent_store,
                key_agreement.clone(),
                pin_hash_enc.clone(),
                0x03,
                None,
            ),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        let pin_hash_enc = vec![0xEE; 16];
        assert_eq!(
            pin_protocol_v1.process_get_pin_uv_auth_token_using_pin_with_permissions(
                &mut rng,
                &mut persistent_store,
                key_agreement,
                pin_hash_enc,
                0x03,
                Some(String::from("example.com")),
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );
    }

    #[cfg(feature = "with_ctap2_1")]
    #[test]
    fn test_process_set_min_pin_length() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let mut pin_protocol_v1 = PinProtocolV1::new(&mut rng);
        let min_pin_length = 8;
        pin_protocol_v1.pin_uv_auth_token = [0x55; PIN_TOKEN_LENGTH];
        let pin_auth = vec![
            0x94, 0x86, 0xEF, 0x4C, 0xB3, 0x84, 0x2C, 0x85, 0x72, 0x02, 0xBF, 0xE4, 0x36, 0x22,
            0xFE, 0xC9,
        ];
        // TODO(kaczmarczyck) implement test for the min PIN length extension
        let response = pin_protocol_v1.process_set_min_pin_length(
            &mut persistent_store,
            min_pin_length,
            None,
            Some(pin_auth.clone()),
        );
        assert_eq!(response, Ok(()));
        assert_eq!(persistent_store.min_pin_length(), min_pin_length);
        let response = pin_protocol_v1.process_set_min_pin_length(
            &mut persistent_store,
            7,
            None,
            Some(pin_auth),
        );
        assert_eq!(
            response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION)
        );
        assert_eq!(persistent_store.min_pin_length(), min_pin_length);
    }

    #[test]
    fn test_process() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let mut pin_protocol_v1 = PinProtocolV1::new(&mut rng);
        let client_pin_params = AuthenticatorClientPinParameters {
            pin_protocol: 1,
            sub_command: ClientPinSubCommand::GetPinRetries,
            key_agreement: None,
            pin_auth: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length: None,
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length_rp_ids: None,
            #[cfg(feature = "with_ctap2_1")]
            permissions: None,
            #[cfg(feature = "with_ctap2_1")]
            permissions_rp_id: None,
        };
        assert!(pin_protocol_v1
            .process(&mut rng, &mut persistent_store, client_pin_params)
            .is_ok());

        let client_pin_params = AuthenticatorClientPinParameters {
            pin_protocol: 2,
            sub_command: ClientPinSubCommand::GetPinRetries,
            key_agreement: None,
            pin_auth: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length: None,
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length_rp_ids: None,
            #[cfg(feature = "with_ctap2_1")]
            permissions: None,
            #[cfg(feature = "with_ctap2_1")]
            permissions_rp_id: None,
        };
        #[cfg(not(feature = "with_ctap2_1"))]
        let error_code = Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID;
        #[cfg(feature = "with_ctap2_1")]
        let error_code = Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER;
        assert_eq!(
            pin_protocol_v1.process(&mut rng, &mut persistent_store, client_pin_params),
            Err(error_code)
        );
    }

    #[test]
    fn test_check_and_store_new_pin() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let shared_secret = [0x88; 32];
        let aes_enc_key = crypto::aes256::EncryptionKey::new(&shared_secret);
        let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);

        // The PIN "1234" should be accepted.
        let new_pin_enc = vec![
            0xC0, 0xCF, 0xAE, 0x4C, 0x79, 0x56, 0x87, 0x99, 0xE5, 0x83, 0x4F, 0xE6, 0x4D, 0xFE,
            0x53, 0x32, 0x36, 0x0D, 0xF9, 0x1E, 0x47, 0x66, 0x10, 0x5C, 0x63, 0x30, 0x1D, 0xCC,
            0x00, 0x09, 0x91, 0xA4, 0x20, 0x6B, 0x78, 0x10, 0xFE, 0xC6, 0x2E, 0x7E, 0x75, 0x14,
            0xEE, 0x01, 0x99, 0x6C, 0xD7, 0xE5, 0x2B, 0xA5, 0x7A, 0x5A, 0xE1, 0xEC, 0x69, 0x31,
            0x18, 0x35, 0x06, 0x66, 0x97, 0x84, 0x68, 0xC2,
        ];
        assert!(check_and_store_new_pin(
            &mut persistent_store,
            &aes_dec_key,
            new_pin_enc
        ));

        // The PIN "123" has only 3 characters.
        let bad_pin_enc = vec![
            0xF3, 0x54, 0x29, 0x17, 0xD4, 0xF8, 0xCD, 0x23, 0x1D, 0x59, 0xED, 0xE5, 0x33, 0x42,
            0x13, 0x39, 0x22, 0xBB, 0x91, 0x28, 0x87, 0x6A, 0xF9, 0xB1, 0x80, 0x9C, 0x9D, 0x76,
            0xFF, 0xDD, 0xB8, 0xD6, 0x8D, 0x66, 0x99, 0xA2, 0x42, 0x67, 0xB0, 0x5C, 0x82, 0x3F,
            0x08, 0x55, 0x8C, 0x04, 0xC5, 0x91, 0xF0, 0xF9, 0x58, 0x44, 0x00, 0x1B, 0x99, 0xA6,
            0x7C, 0xC7, 0x2D, 0x43, 0x74, 0x4C, 0x1D, 0x7E,
        ];
        assert!(!check_and_store_new_pin(
            &mut persistent_store,
            &aes_dec_key,
            bad_pin_enc
        ));

        // The last byte of the decrypted PIN is not padding, which is 0x00.
        let bad_pin_enc = vec![
            0x53, 0x3D, 0xAD, 0x69, 0xB6, 0x1B, 0x5F, 0xAF, 0x0F, 0x26, 0xF1, 0x33, 0xB3, 0xCC,
            0x94, 0x26, 0x68, 0xD0, 0xC4, 0x58, 0xD4, 0x2D, 0x3D, 0x8B, 0x6F, 0x1A, 0xA2, 0x0A,
            0x44, 0x47, 0xE8, 0x94, 0xF2, 0x2D, 0x99, 0xEB, 0xA1, 0xA6, 0xBE, 0x32, 0x7C, 0x99,
            0x2B, 0xB8, 0x9A, 0x15, 0x9C, 0xEA, 0x86, 0x47, 0x4B, 0x5E, 0x6C, 0xA2, 0xE2, 0xB9,
            0x0D, 0x85, 0x25, 0xD3, 0x8A, 0x46, 0x39, 0xAD,
        ];
        assert!(!check_and_store_new_pin(
            &mut persistent_store,
            &aes_dec_key,
            bad_pin_enc
        ));
    }

    #[test]
    fn test_check_pin_auth() {
        let hmac_key = [0x88; 16];
        let pin_auth = [
            0x88, 0x09, 0x41, 0x13, 0xF7, 0x97, 0x32, 0x0B, 0x3E, 0xD9, 0xBC, 0x76, 0x4F, 0x18,
            0x56, 0x5D,
        ];
        assert!(check_pin_auth(&hmac_key, &[], &pin_auth));
        assert!(!check_pin_auth(&hmac_key, &[0x00], &pin_auth));
    }

    #[test]
    fn test_encrypt_hmac_secret_output() {
        let shared_secret = [0x55; 32];
        let salt_enc = [0x5E; 32];
        let cred_random = [0xC9; 32];
        let output = encrypt_hmac_secret_output(&shared_secret, &salt_enc, &cred_random);
        assert_eq!(output.unwrap().len(), 32);

        let salt_enc = [0x5E; 48];
        let output = encrypt_hmac_secret_output(&shared_secret, &salt_enc, &cred_random);
        assert_eq!(
            output,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION)
        );

        let salt_enc = [0x5E; 64];
        let output = encrypt_hmac_secret_output(&shared_secret, &salt_enc, &cred_random);
        assert_eq!(output.unwrap().len(), 64);

        let salt_enc = [0x5E; 32];
        let cred_random = [0xC9; 33];
        let output = encrypt_hmac_secret_output(&shared_secret, &salt_enc, &cred_random);
        assert_eq!(
            output,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION)
        );
    }

    #[cfg(feature = "with_ctap2_1")]
    #[test]
    fn test_has_permission() {
        let mut rng = ThreadRng256 {};
        let mut pin_protocol_v1 = PinProtocolV1::new(&mut rng);
        pin_protocol_v1.permissions = 0x7F;
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(pin_protocol_v1.has_permission(permission), Ok(()));
        }
        pin_protocol_v1.permissions = 0x00;
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(
                pin_protocol_v1.has_permission(permission),
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
            );
        }
    }

    #[cfg(feature = "with_ctap2_1")]
    #[test]
    fn test_has_permission_for_rp_id() {
        let mut rng = ThreadRng256 {};
        let mut pin_protocol_v1 = PinProtocolV1::new(&mut rng);
        assert_eq!(
            pin_protocol_v1.has_permission_for_rp_id("example.com"),
            Ok(())
        );
        assert_eq!(
            pin_protocol_v1.permissions_rp_id,
            Some(String::from("example.com"))
        );
        assert_eq!(
            pin_protocol_v1.has_permission_for_rp_id("example.com"),
            Ok(())
        );
        assert_eq!(
            pin_protocol_v1.has_permission_for_rp_id("counter-example.com"),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}
