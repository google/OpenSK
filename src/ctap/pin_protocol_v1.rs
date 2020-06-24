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

use super::command::AuthenticatorClientPinParameters;
use super::data_formats::{ClientPinSubCommand, CoseKey, GetAssertionHmacSecretInput};
use super::response::{AuthenticatorClientPinResponse, ResponseData};
use super::status_code::Ctap2StatusCode;
use super::storage::PersistentStore;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryInto;
use crypto::cbc::{cbc_decrypt, cbc_encrypt};
use crypto::hmac::{hmac_256, verify_hmac_256_first_128bits};
use crypto::rng256::Rng256;
use crypto::sha256::Sha256;
use crypto::Hash256;
use subtle::ConstantTimeEq;

// Those constants have to be multiples of 16, the AES block size.
pub const PIN_AUTH_LENGTH: usize = 16;
const PIN_PADDED_LENGTH: usize = 64;
const PIN_TOKEN_LENGTH: usize = 32;

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

// Decrypts the HMAC secret salt(s) that were encrypted with the shared secret.
// The credRandom is used as a secret to HMAC those salts.
// The last step is to re-encrypt the outputs.
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
    let iv = [0; 16];

    let mut cred_random_secret = [0; 32];
    cred_random_secret.clone_from_slice(cred_random);

    // Initialization of 4 blocks in any case makes this function more readable.
    let mut blocks = [[0u8; 16]; 4];
    let block_len = salt_enc.len() / 16;
    for i in 0..block_len {
        blocks[i].copy_from_slice(&salt_enc[16 * i..16 * (i + 1)]);
    }
    cbc_decrypt(&aes_dec_key, iv, &mut blocks[..block_len]);

    let mut decrypted_salt1 = [0; 32];
    decrypted_salt1[..16].clone_from_slice(&blocks[0]);
    let output1 = hmac_256::<Sha256>(&cred_random_secret, &decrypted_salt1[..]);
    decrypted_salt1[16..].clone_from_slice(&blocks[1]);
    for i in 0..2 {
        blocks[i].copy_from_slice(&output1[16 * i..16 * (i + 1)]);
    }

    if block_len == 4 {
        let mut decrypted_salt2 = [0; 32];
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

pub struct PinProtocolV1 {
    key_agreement_key: crypto::ecdh::SecKey,
    pin_uv_auth_token: [u8; PIN_TOKEN_LENGTH],
    consecutive_pin_mismatches: u64,
}

impl PinProtocolV1 {
    pub fn new(rng: &mut impl Rng256) -> PinProtocolV1 {
        let key_agreement_key = crypto::ecdh::SecKey::gensk(rng);
        let pin_uv_auth_token = rng.gen_uniform_u8x32();
        PinProtocolV1 {
            key_agreement_key,
            pin_uv_auth_token,
            consecutive_pin_mismatches: 0,
        }
    }

    fn check_and_store_new_pin(
        &mut self,
        persistent_store: &mut PersistentStore,
        aes_dec_key: &crypto::aes256::DecryptionKey,
        new_pin_enc: Vec<u8>,
    ) -> bool {
        if new_pin_enc.len() != PIN_PADDED_LENGTH {
            return false;
        }
        let iv = [0; 16];
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
        if pin.len() < 4 || pin.len() == PIN_PADDED_LENGTH {
            // TODO(kaczmarczyck) check 4 code point minimum instead
            return false;
        }
        let mut pin_hash = [0; 16];
        pin_hash.copy_from_slice(&Sha256::hash(&pin[..])[..16]);
        persistent_store.set_pin_hash(&pin_hash);
        true
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

                let iv = [0; 16];
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
        if !self.check_and_store_new_pin(persistent_store, &aes_dec_key, new_pin_enc) {
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

        if !self.check_and_store_new_pin(persistent_store, &aes_dec_key, new_pin_enc) {
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
        let iv = [0; 16];
        let mut blocks = [[0u8; 16]; PIN_TOKEN_LENGTH / 16];
        for (i, item) in blocks.iter_mut().take(PIN_TOKEN_LENGTH / 16).enumerate() {
            item.copy_from_slice(&self.pin_uv_auth_token[i * 16..(i + 1) * 16]);
        }
        cbc_encrypt(&aes_enc_key, iv, &mut blocks);
        let mut pin_token = vec![];
        for item in blocks.iter().take(PIN_TOKEN_LENGTH / 16) {
            pin_token.extend(item);
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
        Ok(AuthenticatorClientPinResponse {
            // User verifications is only supported through PIN currently.
            key_agreement: None,
            pin_token: Some(vec![]),
            retries: None,
        })
    }

    #[cfg(feature = "with_ctap2_1")]
    fn process_get_uv_retries(&self) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // User verifications is only supported through PIN currently.
        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: None,
            retries: Some(0),
        })
    }

    #[cfg(feature = "with_ctap2_1")]
    fn process_set_min_pin_length(
        &mut self,
        _min_pin_length: u64,
        _min_pin_length_rp_ids: Vec<String>,
        _pin_auth: Vec<u8>,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // TODO
        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: None,
            retries: Some(0),
        })
    }

    #[cfg(feature = "with_ctap2_1")]
    fn process_get_pin_uv_auth_token_using_pin_with_permissions(
        &mut self,
        _key_agreement: CoseKey,
        _pin_hash_enc: Vec<u8>,
        _permissions: u8,
        _permissions_rp_id: String,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // TODO
        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: None,
            retries: Some(0),
        })
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
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
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
                    min_pin_length.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    min_pin_length_rp_ids.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    pin_auth.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                None
            }
            #[cfg(feature = "with_ctap2_1")]
            ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions => {
                self.process_get_pin_uv_auth_token_using_pin_with_permissions(
                    key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    pin_hash_enc.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    permissions.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    permissions_rp_id.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                None
            }
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
}

#[cfg(test)]
mod test {
    use super::*;

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
}
