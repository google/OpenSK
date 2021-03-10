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

use super::command::AuthenticatorClientPinParameters;
use super::data_formats::{ClientPinSubCommand, CoseKey, GetAssertionHmacSecretInput};
use super::pin_protocol::{verify_pin_uv_auth_token, PinProtocol, SharedSecret};
use super::response::{AuthenticatorClientPinResponse, ResponseData};
use super::status_code::Ctap2StatusCode;
use super::storage::PersistentStore;
use alloc::str;
use alloc::string::String;
use alloc::vec::Vec;
use crypto::hmac::hmac_256;
use crypto::rng256::Rng256;
use crypto::sha256::Sha256;
use crypto::Hash256;
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
/// is fixed since CTAP2.1.
pub const PIN_TOKEN_LENGTH: usize = 32;

/// The length of the encrypted PINs when received by SetPin or ChangePin.
///
/// The code assumes that this value is a multiple of the AES block length. It
/// is fixed since CTAP2.1.
const PIN_PADDED_LENGTH: usize = 64;

/// Computes and encrypts the HMAC-secret outputs.
///
/// To compute them, we first have to decrypt the HMAC secret salt(s) that were
/// encrypted with the shared secret. The credRandom is used as a secret in HMAC
/// for those salts.
fn encrypt_hmac_secret_output(
    rng: &mut impl Rng256,
    shared_secret: &dyn SharedSecret,
    salt_enc: &[u8],
    cred_random: &[u8; 32],
) -> Result<Vec<u8>, Ctap2StatusCode> {
    let decrypted_salts = shared_secret.decrypt(salt_enc)?;
    if decrypted_salts.len() != 32 && decrypted_salts.len() != 64 {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    let mut output = hmac_256::<Sha256>(&cred_random[..], &decrypted_salts[..32]).to_vec();
    if decrypted_salts.len() == 64 {
        let mut output2 = hmac_256::<Sha256>(&cred_random[..], &decrypted_salts[32..]).to_vec();
        output.append(&mut output2);
    }
    shared_secret.encrypt(rng, &output)
}

/// Decrypts the new_pin_enc and outputs the found PIN.
fn decrypt_pin(
    shared_secret: &dyn SharedSecret,
    new_pin_enc: Vec<u8>,
) -> Result<Vec<u8>, Ctap2StatusCode> {
    let decrypted_pin = shared_secret.decrypt(&new_pin_enc)?;
    if decrypted_pin.len() != PIN_PADDED_LENGTH {
        return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
    }
    // In CTAP 2.1, the specification changed. The new wording might lead to
    // different behavior when there are non-zero bytes after zero bytes.
    // This implementation consistently ignores those degenerate cases.
    Ok(decrypted_pin.into_iter().take_while(|&c| c != 0).collect())
}

/// Stores a hash prefix of the new PIN in the persistent storage, if correct.
///
/// The new PIN is passed encrypted, so it is first decrypted and stripped from
/// padding. Next, it is checked against the PIN policy. Last, it is hashed and
/// truncated for persistent storage.
fn check_and_store_new_pin(
    persistent_store: &mut PersistentStore,
    shared_secret: &dyn SharedSecret,
    new_pin_enc: Vec<u8>,
) -> Result<(), Ctap2StatusCode> {
    let pin = decrypt_pin(shared_secret, new_pin_enc)?;
    let min_pin_length = persistent_store.min_pin_length()? as usize;
    let pin_length = str::from_utf8(&pin).unwrap_or("").chars().count();
    if pin_length < min_pin_length || pin.len() == PIN_PADDED_LENGTH {
        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION);
    }
    let mut pin_hash = [0u8; PIN_AUTH_LENGTH];
    pin_hash.copy_from_slice(&Sha256::hash(&pin[..])[..PIN_AUTH_LENGTH]);
    // The PIN length is always < PIN_PADDED_LENGTH < 256.
    persistent_store.set_pin(&pin_hash, pin_length as u8)?;
    Ok(())
}

#[cfg_attr(test, derive(IntoEnumIterator))]
// TODO remove when all variants are used
#[allow(dead_code)]
pub enum PinPermission {
    // All variants should use integers with a single bit set.
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    CredentialManagement = 0x04,
    BioEnrollment = 0x08,
    LargeBlobWrite = 0x10,
    AuthenticatorConfiguration = 0x20,
}

pub struct ClientPin {
    pin_protocol_v1: PinProtocol,
    consecutive_pin_mismatches: u8,
    permissions: u8,
    permissions_rp_id: Option<String>,
}

impl ClientPin {
    pub fn new(rng: &mut impl Rng256) -> ClientPin {
        ClientPin {
            pin_protocol_v1: PinProtocol::new(rng),
            consecutive_pin_mismatches: 0,
            permissions: 0,
            permissions_rp_id: None,
        }
    }

    /// Checks the given encrypted PIN hash against the stored PIN hash.
    ///
    /// Decrypts the encrypted pin_hash and compares it to the stored pin_hash.
    /// Resets or decreases the PIN retries, depending on success or failure.
    /// Also, in case of failure, the key agreement key is randomly reset.
    fn verify_pin_hash_enc(
        &mut self,
        rng: &mut impl Rng256,
        persistent_store: &mut PersistentStore,
        shared_secret: &dyn SharedSecret,
        pin_hash_enc: Vec<u8>,
    ) -> Result<(), Ctap2StatusCode> {
        match persistent_store.pin_hash()? {
            Some(pin_hash) => {
                if self.consecutive_pin_mismatches >= 3 {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_BLOCKED);
                }
                persistent_store.decr_pin_retries()?;
                if pin_hash_enc.len() != PIN_AUTH_LENGTH {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }
                let pin_hash_dec = shared_secret.decrypt(&pin_hash_enc)?;

                if !bool::from(pin_hash.ct_eq(&pin_hash_dec)) {
                    self.pin_protocol_v1.regenerate(rng);
                    if persistent_store.pin_retries()? == 0 {
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
        persistent_store.reset_pin_retries()?;
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
            retries: Some(persistent_store.pin_retries()? as u64),
        })
    }

    fn process_get_key_agreement(&self) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        Ok(AuthenticatorClientPinResponse {
            key_agreement: Some(self.pin_protocol_v1.get_public_key()),
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
        if persistent_store.pin_hash()?.is_some() {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let shared_secret = self.pin_protocol_v1.decapsulate(key_agreement, 1)?;
        shared_secret.verify(&new_pin_enc, &pin_auth)?;

        check_and_store_new_pin(persistent_store, shared_secret.as_ref(), new_pin_enc)?;
        persistent_store.reset_pin_retries()?;
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
        if persistent_store.pin_retries()? == 0 {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
        }
        let shared_secret = self.pin_protocol_v1.decapsulate(key_agreement, 1)?;
        let mut auth_param_data = new_pin_enc.clone();
        auth_param_data.extend(&pin_hash_enc);
        shared_secret.verify(&auth_param_data, &pin_auth)?;
        self.verify_pin_hash_enc(rng, persistent_store, shared_secret.as_ref(), pin_hash_enc)?;

        check_and_store_new_pin(persistent_store, shared_secret.as_ref(), new_pin_enc)?;
        self.pin_protocol_v1.reset_pin_uv_auth_token(rng);
        Ok(())
    }

    fn process_get_pin_token(
        &mut self,
        rng: &mut impl Rng256,
        persistent_store: &mut PersistentStore,
        key_agreement: CoseKey,
        pin_hash_enc: Vec<u8>,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        if persistent_store.pin_retries()? == 0 {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
        }
        let shared_secret = self.pin_protocol_v1.decapsulate(key_agreement, 1)?;
        self.verify_pin_hash_enc(rng, persistent_store, shared_secret.as_ref(), pin_hash_enc)?;
        if persistent_store.has_force_pin_change()? {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
        }

        let pin_token = shared_secret.encrypt(rng, self.pin_protocol_v1.get_pin_uv_auth_token())?;
        self.permissions = 0x03;
        self.permissions_rp_id = None;

        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: Some(pin_token),
            retries: None,
        })
    }

    fn process_get_pin_uv_auth_token_using_uv_with_permissions(
        &self,
        // If you want to support local user verification, implement this function.
        // Lacking a fingerprint reader, this subcommand is currently unsupported.
        _key_agreement: CoseKey,
        _permissions: u8,
        _permissions_rp_id: Option<String>,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // User verifications is only supported through PIN currently.
        Err(Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND)
    }

    fn process_get_uv_retries(&self) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // User verifications is only supported through PIN currently.
        Err(Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND)
    }

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

    pub fn process_command(
        &mut self,
        rng: &mut impl Rng256,
        persistent_store: &mut PersistentStore,
        client_pin_params: AuthenticatorClientPinParameters,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            sub_command,
            key_agreement,
            pin_auth,
            new_pin_enc,
            pin_hash_enc,
            permissions,
            permissions_rp_id,
        } = client_pin_params;

        if pin_uv_auth_protocol != 1 {
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
            ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions => Some(
                self.process_get_pin_uv_auth_token_using_uv_with_permissions(
                    key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    permissions.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    permissions_rp_id,
                )?,
            ),
            ClientPinSubCommand::GetUvRetries => Some(self.process_get_uv_retries()?),
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

    pub fn verify_pin_auth_token(
        &self,
        hmac_contents: &[u8],
        pin_auth: &[u8],
    ) -> Result<(), Ctap2StatusCode> {
        // TODO(kaczmarczyck) pass the protocol number
        verify_pin_uv_auth_token(
            self.pin_protocol_v1.get_pin_uv_auth_token(),
            hmac_contents,
            pin_auth,
            1,
        )
    }

    pub fn reset(&mut self, rng: &mut impl Rng256) {
        self.pin_protocol_v1.regenerate(rng);
        self.pin_protocol_v1.reset_pin_uv_auth_token(rng);
        self.consecutive_pin_mismatches = 0;
        self.permissions = 0;
        self.permissions_rp_id = None;
    }

    pub fn process_hmac_secret(
        &self,
        rng: &mut impl Rng256,
        hmac_secret_input: GetAssertionHmacSecretInput,
        cred_random: &[u8; 32],
    ) -> Result<Vec<u8>, Ctap2StatusCode> {
        let GetAssertionHmacSecretInput {
            key_agreement,
            salt_enc,
            salt_auth,
        } = hmac_secret_input;
        let shared_secret = self.pin_protocol_v1.decapsulate(key_agreement, 1)?;
        shared_secret.verify(&salt_enc, &salt_auth)?;
        encrypt_hmac_secret_output(rng, shared_secret.as_ref(), &salt_enc[..], cred_random)
    }

    /// Check if the required command's token permission is granted.
    pub fn has_permission(&self, permission: PinPermission) -> Result<(), Ctap2StatusCode> {
        // Relies on the fact that all permissions are represented by powers of two.
        if permission as u8 & self.permissions != 0 {
            Ok(())
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    /// Check if no RP ID is associated with the token permission.
    pub fn has_no_rp_id_permission(&self) -> Result<(), Ctap2StatusCode> {
        if self.permissions_rp_id.is_some() {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }
        Ok(())
    }

    /// Check if no or the passed RP ID is associated with the token permission.
    pub fn has_no_or_rp_id_permission(&mut self, rp_id: &str) -> Result<(), Ctap2StatusCode> {
        match &self.permissions_rp_id {
            Some(p) if rp_id != p => Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID),
            _ => Ok(()),
        }
    }

    /// Check if no RP ID is associated with the token permission, or it matches the hash.
    pub fn has_no_or_rp_id_hash_permission(
        &self,
        rp_id_hash: &[u8],
    ) -> Result<(), Ctap2StatusCode> {
        match &self.permissions_rp_id {
            Some(p) if rp_id_hash != Sha256::hash(p.as_bytes()) => {
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
            }
            _ => Ok(()),
        }
    }

    /// Check if the passed RP ID is associated with the token permission.
    ///
    /// If no RP ID is associated, associate the passed RP ID as a side effect.
    pub fn ensure_rp_id_permission(&mut self, rp_id: &str) -> Result<(), Ctap2StatusCode> {
        match &self.permissions_rp_id {
            Some(p) if rp_id != p => Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID),
            None => {
                self.permissions_rp_id = Some(String::from(rp_id));
                Ok(())
            }
            _ => Ok(()),
        }
    }

    #[cfg(test)]
    pub fn new_test(
        key_agreement_key: crypto::ecdh::SecKey,
        pin_uv_auth_token: [u8; PIN_TOKEN_LENGTH],
    ) -> ClientPin {
        ClientPin {
            pin_protocol_v1: PinProtocol::new_test(key_agreement_key, pin_uv_auth_token),
            consecutive_pin_mismatches: 0,
            permissions: 0xFF,
            permissions_rp_id: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::pin_protocol::SharedSecretV1;
    use super::*;
    use alloc::vec;
    use crypto::rng256::ThreadRng256;

    /// Stores a PIN hash corresponding to the dummy PIN "1234".
    fn set_standard_pin(persistent_store: &mut PersistentStore) {
        let mut pin = [0u8; 64];
        pin[..4].copy_from_slice(b"1234");
        let mut pin_hash = [0u8; 16];
        pin_hash.copy_from_slice(&Sha256::hash(&pin[..])[..16]);
        persistent_store.set_pin(&pin_hash, 4).unwrap();
    }

    /// Encrypts the message with a zero IV and key derived from shared_secret.
    fn encrypt_message(shared_secret: &[u8; 32], message: &[u8]) -> Vec<u8> {
        let mut rng = ThreadRng256 {};
        let shared_secret = SharedSecretV1::new_test(*shared_secret);
        shared_secret.encrypt(&mut rng, message).unwrap()
    }

    /// Decrypts the message with a zero IV and key derived from shared_secret.
    fn decrypt_message(shared_secret: &[u8; 32], message: &[u8]) -> Vec<u8> {
        let shared_secret = SharedSecretV1::new_test(*shared_secret);
        shared_secret.decrypt(message).unwrap()
    }

    /// Fails on PINs bigger than 64 bytes.
    fn encrypt_pin(shared_secret: &[u8; 32], pin: Vec<u8>) -> Vec<u8> {
        assert!(pin.len() <= 64);
        let mut padded_pin = [0u8; 64];
        padded_pin[..pin.len()].copy_from_slice(&pin[..]);
        encrypt_message(shared_secret, &padded_pin)
    }

    /// Encrypts the dummy PIN "1234".
    fn encrypt_standard_pin(shared_secret: &[u8; 32]) -> Vec<u8> {
        encrypt_pin(shared_secret, b"1234".to_vec())
    }

    /// Encrypts the PIN hash corresponding to the dummy PIN "1234".
    fn encrypt_standard_pin_hash(shared_secret: &[u8; 32]) -> Vec<u8> {
        let mut pin = [0u8; 64];
        pin[..4].copy_from_slice(b"1234");
        let pin_hash = Sha256::hash(&pin);
        encrypt_message(shared_secret, &pin_hash[..16])
    }

    #[test]
    fn test_verify_pin_hash_enc() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        // The PIN is "1234".
        let pin_hash = [
            0x01, 0xD9, 0x88, 0x40, 0x50, 0xBB, 0xD0, 0x7A, 0x23, 0x1A, 0xEB, 0x69, 0xD8, 0x36,
            0xC4, 0x12,
        ];
        persistent_store.set_pin(&pin_hash, 4).unwrap();
        let shared_secret = SharedSecretV1::new_test([0x88; 32]);

        let mut client_pin = ClientPin::new(&mut rng);
        let pin_hash_enc = vec![
            0x8D, 0x7A, 0xA3, 0x9F, 0x7F, 0xC6, 0x08, 0x13, 0x9A, 0xC8, 0x56, 0x97, 0x70, 0x74,
            0x99, 0x66,
        ];
        assert_eq!(
            client_pin.verify_pin_hash_enc(
                &mut rng,
                &mut persistent_store,
                &shared_secret,
                pin_hash_enc
            ),
            Ok(())
        );

        let pin_hash_enc = vec![0xEE; 16];
        assert_eq!(
            client_pin.verify_pin_hash_enc(
                &mut rng,
                &mut persistent_store,
                &shared_secret,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );

        let pin_hash_enc = vec![
            0x8D, 0x7A, 0xA3, 0x9F, 0x7F, 0xC6, 0x08, 0x13, 0x9A, 0xC8, 0x56, 0x97, 0x70, 0x74,
            0x99, 0x66,
        ];
        client_pin.consecutive_pin_mismatches = 3;
        assert_eq!(
            client_pin.verify_pin_hash_enc(
                &mut rng,
                &mut persistent_store,
                &shared_secret,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_BLOCKED)
        );
        client_pin.consecutive_pin_mismatches = 0;

        let pin_hash_enc = vec![0x77; PIN_AUTH_LENGTH - 1];
        assert_eq!(
            client_pin.verify_pin_hash_enc(
                &mut rng,
                &mut persistent_store,
                &shared_secret,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );

        let pin_hash_enc = vec![0x77; PIN_AUTH_LENGTH + 1];
        assert_eq!(
            client_pin.verify_pin_hash_enc(
                &mut rng,
                &mut persistent_store,
                &shared_secret,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );
    }

    #[test]
    fn test_process_get_pin_retries() {
        let mut rng = ThreadRng256 {};
        let persistent_store = PersistentStore::new(&mut rng);
        let client_pin = ClientPin::new(&mut rng);
        let expected_response = Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: None,
            retries: Some(persistent_store.pin_retries().unwrap() as u64),
        });
        assert_eq!(
            client_pin.process_get_pin_retries(&persistent_store),
            expected_response
        );
    }

    #[test]
    fn test_process_get_key_agreement() {
        let mut rng = ThreadRng256 {};
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pk = key_agreement_key.genpk();
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let client_pin = ClientPin::new_test(key_agreement_key, pin_uv_auth_token);
        let expected_response = Ok(AuthenticatorClientPinResponse {
            key_agreement: Some(CoseKey::from(pk)),
            pin_token: None,
            retries: None,
        });
        assert_eq!(client_pin.process_get_key_agreement(), expected_response);
    }

    #[test]
    fn test_process_set_pin() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pk = key_agreement_key.genpk();
        let pre_secret = key_agreement_key.exchange_x(&pk);
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let mut client_pin = ClientPin::new_test(key_agreement_key, pin_uv_auth_token);
        let shared_secret = Sha256::hash(&pre_secret);
        let key_agreement = CoseKey::from(pk);
        let new_pin_enc = encrypt_standard_pin(&shared_secret);
        let pin_auth = hmac_256::<Sha256>(&shared_secret, &new_pin_enc[..])[..16].to_vec();
        assert_eq!(
            client_pin.process_set_pin(&mut persistent_store, key_agreement, pin_auth, new_pin_enc),
            Ok(())
        );
    }

    #[test]
    fn test_process_change_pin() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        set_standard_pin(&mut persistent_store);
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pk = key_agreement_key.genpk();
        let pre_secret = key_agreement_key.exchange_x(&pk);
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let mut client_pin = ClientPin::new_test(key_agreement_key, pin_uv_auth_token);
        let shared_secret = Sha256::hash(&pre_secret);
        let key_agreement = CoseKey::from(pk);
        let new_pin_enc = encrypt_standard_pin(&shared_secret);
        let pin_hash_enc = encrypt_standard_pin_hash(&shared_secret);
        let mut auth_param_data = new_pin_enc.clone();
        auth_param_data.extend(&pin_hash_enc);

        let pin_auth = hmac_256::<Sha256>(&shared_secret, &auth_param_data[..])[..16].to_vec();
        assert_eq!(
            client_pin.process_change_pin(
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
            client_pin.process_change_pin(
                &mut rng,
                &mut persistent_store,
                key_agreement.clone(),
                pin_auth.clone(),
                new_pin_enc.clone(),
                bad_pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );

        while persistent_store.pin_retries().unwrap() > 0 {
            persistent_store.decr_pin_retries().unwrap();
        }
        assert_eq!(
            client_pin.process_change_pin(
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
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pk = key_agreement_key.genpk();
        let pre_secret = key_agreement_key.exchange_x(&pk);
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let mut client_pin = ClientPin::new_test(key_agreement_key, pin_uv_auth_token);
        let shared_secret = Sha256::hash(&pre_secret);
        let key_agreement = CoseKey::from(pk);

        let pin_hash_enc = encrypt_standard_pin_hash(&shared_secret);
        assert!(client_pin
            .process_get_pin_token(
                &mut rng,
                &mut persistent_store,
                key_agreement.clone(),
                pin_hash_enc
            )
            .is_ok());

        let pin_hash_enc = vec![0xEE; 16];
        assert_eq!(
            client_pin.process_get_pin_token(
                &mut rng,
                &mut persistent_store,
                key_agreement,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID)
        );
    }

    #[test]
    fn test_process_get_pin_token_force_pin_change() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        set_standard_pin(&mut persistent_store);
        assert_eq!(persistent_store.force_pin_change(), Ok(()));
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pk = key_agreement_key.genpk();
        let pre_secret = key_agreement_key.exchange_x(&pk);
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let mut client_pin = ClientPin::new_test(key_agreement_key, pin_uv_auth_token);
        let shared_secret = Sha256::hash(&pre_secret);
        let key_agreement = CoseKey::from(pk);

        let pin_hash_enc = encrypt_standard_pin_hash(&shared_secret);
        assert_eq!(
            client_pin.process_get_pin_token(
                &mut rng,
                &mut persistent_store,
                key_agreement,
                pin_hash_enc
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID),
        );
    }

    #[test]
    fn test_process_get_pin_uv_auth_token_using_pin_with_permissions() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        set_standard_pin(&mut persistent_store);
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pk = key_agreement_key.genpk();
        let pre_secret = key_agreement_key.exchange_x(&pk);
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let mut client_pin = ClientPin::new_test(key_agreement_key, pin_uv_auth_token);
        let shared_secret = Sha256::hash(&pre_secret);
        let key_agreement = CoseKey::from(pk);

        let pin_hash_enc = encrypt_standard_pin_hash(&shared_secret);
        assert!(client_pin
            .process_get_pin_uv_auth_token_using_pin_with_permissions(
                &mut rng,
                &mut persistent_store,
                key_agreement.clone(),
                pin_hash_enc.clone(),
                0x03,
                Some(String::from("example.com")),
            )
            .is_ok());
        assert_eq!(client_pin.permissions, 0x03);
        assert_eq!(
            client_pin.permissions_rp_id,
            Some(String::from("example.com"))
        );

        assert_eq!(
            client_pin.process_get_pin_uv_auth_token_using_pin_with_permissions(
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
            client_pin.process_get_pin_uv_auth_token_using_pin_with_permissions(
                &mut rng,
                &mut persistent_store,
                key_agreement.clone(),
                pin_hash_enc,
                0x03,
                None,
            ),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        let pin_hash_enc = vec![0xEE; 16];
        assert_eq!(
            client_pin.process_get_pin_uv_auth_token_using_pin_with_permissions(
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

    #[test]
    fn test_process_get_pin_token_force_pin_change_force_pin_change() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        set_standard_pin(&mut persistent_store);
        assert_eq!(persistent_store.force_pin_change(), Ok(()));
        let key_agreement_key = crypto::ecdh::SecKey::gensk(&mut rng);
        let pk = key_agreement_key.genpk();
        let pre_secret = key_agreement_key.exchange_x(&pk);
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let mut client_pin = ClientPin::new_test(key_agreement_key, pin_uv_auth_token);
        let shared_secret = Sha256::hash(&pre_secret);
        let key_agreement = CoseKey::from(pk);

        let pin_hash_enc = encrypt_standard_pin_hash(&shared_secret);
        assert_eq!(
            client_pin.process_get_pin_uv_auth_token_using_pin_with_permissions(
                &mut rng,
                &mut persistent_store,
                key_agreement,
                pin_hash_enc,
                0x03,
                Some(String::from("example.com")),
            ),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID),
        );
    }

    #[test]
    fn test_process() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let mut client_pin = ClientPin::new(&mut rng);
        let client_pin_params = AuthenticatorClientPinParameters {
            pin_uv_auth_protocol: 1,
            sub_command: ClientPinSubCommand::GetPinRetries,
            key_agreement: None,
            pin_auth: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            permissions_rp_id: None,
        };
        assert!(client_pin
            .process_command(&mut rng, &mut persistent_store, client_pin_params)
            .is_ok());

        let client_pin_params = AuthenticatorClientPinParameters {
            pin_uv_auth_protocol: 2,
            sub_command: ClientPinSubCommand::GetPinRetries,
            key_agreement: None,
            pin_auth: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            permissions_rp_id: None,
        };
        let error_code = Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER;
        assert_eq!(
            client_pin.process_command(&mut rng, &mut persistent_store, client_pin_params),
            Err(error_code)
        );
    }

    #[test]
    fn test_decrypt_pin() {
        let shared_secret = SharedSecretV1::new_test([0x88; 32]);

        // "1234"
        let new_pin_enc = vec![
            0xC0, 0xCF, 0xAE, 0x4C, 0x79, 0x56, 0x87, 0x99, 0xE5, 0x83, 0x4F, 0xE6, 0x4D, 0xFE,
            0x53, 0x32, 0x36, 0x0D, 0xF9, 0x1E, 0x47, 0x66, 0x10, 0x5C, 0x63, 0x30, 0x1D, 0xCC,
            0x00, 0x09, 0x91, 0xA4, 0x20, 0x6B, 0x78, 0x10, 0xFE, 0xC6, 0x2E, 0x7E, 0x75, 0x14,
            0xEE, 0x01, 0x99, 0x6C, 0xD7, 0xE5, 0x2B, 0xA5, 0x7A, 0x5A, 0xE1, 0xEC, 0x69, 0x31,
            0x18, 0x35, 0x06, 0x66, 0x97, 0x84, 0x68, 0xC2,
        ];
        assert_eq!(
            decrypt_pin(&shared_secret, new_pin_enc),
            Ok(b"1234".to_vec()),
        );

        // "123"
        let new_pin_enc = vec![
            0xF3, 0x54, 0x29, 0x17, 0xD4, 0xF8, 0xCD, 0x23, 0x1D, 0x59, 0xED, 0xE5, 0x33, 0x42,
            0x13, 0x39, 0x22, 0xBB, 0x91, 0x28, 0x87, 0x6A, 0xF9, 0xB1, 0x80, 0x9C, 0x9D, 0x76,
            0xFF, 0xDD, 0xB8, 0xD6, 0x8D, 0x66, 0x99, 0xA2, 0x42, 0x67, 0xB0, 0x5C, 0x82, 0x3F,
            0x08, 0x55, 0x8C, 0x04, 0xC5, 0x91, 0xF0, 0xF9, 0x58, 0x44, 0x00, 0x1B, 0x99, 0xA6,
            0x7C, 0xC7, 0x2D, 0x43, 0x74, 0x4C, 0x1D, 0x7E,
        ];
        assert_eq!(
            decrypt_pin(&shared_secret, new_pin_enc),
            Ok(b"123".to_vec()),
        );

        // Encrypted PIN is too short.
        let new_pin_enc = vec![0x44; 63];
        assert_eq!(
            decrypt_pin(&shared_secret, new_pin_enc),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        // Encrypted PIN is too long.
        let new_pin_enc = vec![0x44; 65];
        assert_eq!(
            decrypt_pin(&shared_secret, new_pin_enc),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );
    }

    #[test]
    fn test_check_and_store_new_pin() {
        let mut rng = ThreadRng256 {};
        let mut persistent_store = PersistentStore::new(&mut rng);
        let shared_secret_hash = [0x88; 32];
        let shared_secret = SharedSecretV1::new_test(shared_secret_hash);

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
                b"12\04".to_vec(),
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION),
            ),
            // PINs must be at most 63 bytes long, to allow for a trailing 0u8 padding.
            (
                vec![0x30; 64],
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION),
            ),
        ];
        for (pin, result) in test_cases {
            let old_pin_hash = persistent_store.pin_hash().unwrap();
            let new_pin_enc = encrypt_pin(&shared_secret_hash, pin);
            assert_eq!(
                check_and_store_new_pin(&mut persistent_store, &shared_secret, new_pin_enc),
                result
            );
            if result.is_ok() {
                assert_ne!(old_pin_hash, persistent_store.pin_hash().unwrap());
            } else {
                assert_eq!(old_pin_hash, persistent_store.pin_hash().unwrap());
            }
        }
    }

    #[test]
    fn test_encrypt_hmac_secret_output() {
        let mut rng = ThreadRng256 {};
        let shared_secret_hash = [0x88; 32];
        let shared_secret = SharedSecretV1::new_test(shared_secret_hash);
        let salt_enc = [0x5E; 32];
        let cred_random = [0xC9; 32];
        let output = encrypt_hmac_secret_output(&mut rng, &shared_secret, &salt_enc, &cred_random);
        assert_eq!(output.unwrap().len(), 32);

        let salt_enc = [0x5E; 48];
        let output = encrypt_hmac_secret_output(&mut rng, &shared_secret, &salt_enc, &cred_random);
        assert_eq!(output, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER));

        let salt_enc = [0x5E; 64];
        let output = encrypt_hmac_secret_output(&mut rng, &shared_secret, &salt_enc, &cred_random);
        assert_eq!(output.unwrap().len(), 64);

        let mut salt_enc = [0x00; 32];
        let cred_random = [0xC9; 32];

        // Test values to check for reproducibility.
        let salt1 = [0x01; 32];
        let salt2 = [0x02; 32];
        let expected_output1 = hmac_256::<Sha256>(&cred_random, &salt1);
        let expected_output2 = hmac_256::<Sha256>(&cred_random, &salt2);

        let salt_enc1 = encrypt_message(&shared_secret_hash, &salt1);
        salt_enc.copy_from_slice(salt_enc1.as_slice());
        let output =
            encrypt_hmac_secret_output(&mut rng, &shared_secret, &salt_enc, &cred_random).unwrap();
        let output_dec = decrypt_message(&shared_secret_hash, &output);
        assert_eq!(&output_dec, &expected_output1);

        let salt_enc2 = &encrypt_message(&shared_secret_hash, &salt2);
        salt_enc.copy_from_slice(salt_enc2.as_slice());
        let output =
            encrypt_hmac_secret_output(&mut rng, &shared_secret, &salt_enc, &cred_random).unwrap();
        let output_dec = decrypt_message(&shared_secret_hash, &output);
        assert_eq!(&output_dec, &expected_output2);

        let mut salt_enc = [0x00; 64];
        let mut salt12 = [0x00; 64];
        salt12[..32].copy_from_slice(&salt1);
        salt12[32..].copy_from_slice(&salt2);
        let salt_enc12 = encrypt_message(&shared_secret_hash, &salt12);
        salt_enc.copy_from_slice(salt_enc12.as_slice());
        let output =
            encrypt_hmac_secret_output(&mut rng, &shared_secret, &salt_enc, &cred_random).unwrap();
        let output_dec = decrypt_message(&shared_secret_hash, &output);
        assert_eq!(&output_dec[..32], &expected_output1);
        assert_eq!(&output_dec[32..], &expected_output2);

        let mut salt_enc = [0x00; 64];
        let mut salt02 = [0x00; 64];
        salt02[32..].copy_from_slice(&salt2);
        let salt_enc02 = encrypt_message(&shared_secret_hash, &salt02);
        salt_enc.copy_from_slice(salt_enc02.as_slice());
        let output =
            encrypt_hmac_secret_output(&mut rng, &shared_secret, &salt_enc, &cred_random).unwrap();
        let output_dec = decrypt_message(&shared_secret_hash, &output);
        assert_eq!(&output_dec[32..], &expected_output2);

        let mut salt_enc = [0x00; 64];
        let mut salt10 = [0x00; 64];
        salt10[..32].copy_from_slice(&salt1);
        let salt_enc10 = encrypt_message(&shared_secret_hash, &salt10);
        salt_enc.copy_from_slice(salt_enc10.as_slice());
        let output =
            encrypt_hmac_secret_output(&mut rng, &shared_secret, &salt_enc, &cred_random).unwrap();
        let output_dec = decrypt_message(&shared_secret_hash, &output);
        assert_eq!(&output_dec[..32], &expected_output1);
    }

    #[test]
    fn test_has_permission() {
        let mut rng = ThreadRng256 {};
        let mut client_pin = ClientPin::new(&mut rng);
        client_pin.permissions = 0x7F;
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(client_pin.has_permission(permission), Ok(()));
        }
        client_pin.permissions = 0x00;
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(
                client_pin.has_permission(permission),
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
            );
        }
    }

    #[test]
    fn test_has_no_rp_id_permission() {
        let mut rng = ThreadRng256 {};
        let mut client_pin = ClientPin::new(&mut rng);
        assert_eq!(client_pin.has_no_rp_id_permission(), Ok(()));
        assert_eq!(client_pin.permissions_rp_id, None);
        client_pin.permissions_rp_id = Some("example.com".to_string());
        assert_eq!(
            client_pin.has_no_rp_id_permission(),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_has_no_or_rp_id_permission() {
        let mut rng = ThreadRng256 {};
        let mut client_pin = ClientPin::new(&mut rng);
        assert_eq!(client_pin.has_no_or_rp_id_permission("example.com"), Ok(()));
        assert_eq!(client_pin.permissions_rp_id, None);
        client_pin.permissions_rp_id = Some("example.com".to_string());
        assert_eq!(client_pin.has_no_or_rp_id_permission("example.com"), Ok(()));
        assert_eq!(
            client_pin.has_no_or_rp_id_permission("another.example.com"),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_has_no_or_rp_id_hash_permission() {
        let mut rng = ThreadRng256 {};
        let mut client_pin = ClientPin::new(&mut rng);
        let rp_id_hash = Sha256::hash(b"example.com");
        assert_eq!(
            client_pin.has_no_or_rp_id_hash_permission(&rp_id_hash),
            Ok(())
        );
        assert_eq!(client_pin.permissions_rp_id, None);
        client_pin.permissions_rp_id = Some("example.com".to_string());
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
        let mut rng = ThreadRng256 {};
        let mut client_pin = ClientPin::new(&mut rng);
        assert_eq!(client_pin.ensure_rp_id_permission("example.com"), Ok(()));
        assert_eq!(
            client_pin.permissions_rp_id,
            Some(String::from("example.com"))
        );
        assert_eq!(client_pin.ensure_rp_id_permission("example.com"), Ok(()));
        assert_eq!(
            client_pin.ensure_rp_id_permission("counter-example.com"),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}
