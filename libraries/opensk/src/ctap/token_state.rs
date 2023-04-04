// Copyright 2021 Google LLC
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

use crate::api::clock::Clock;
use crate::api::crypto::sha256::Sha256;
use crate::ctap::client_pin::PinPermission;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::env::{Env, Sha};
use alloc::string::String;

/// Timeout for auth tokens.
///
/// This usage time limit is correct for USB, BLE, and internal.
/// NFC only allows 19.8 seconds.
/// TODO(#15) multiplex over transports, add NFC
const INITIAL_USAGE_TIME_LIMIT_MS: usize = 30000;

/// Implements pinUvAuthToken state from section 6.5.2.1.
///
/// The userPresent flag is omitted as the only way to set it to true is
/// built-in user verification. Therefore, we never cache user presence.
///
/// This implementation does not use a rolling timer.
pub struct PinUvAuthTokenState<E: Env> {
    // Relies on the fact that all permissions are represented by powers of two.
    permissions_set: u8,
    permissions_rp_id: Option<String>,
    usage_timer: <E::Clock as Clock>::Timer,
    user_verified: bool,
    in_use: bool,
}

impl<E: Env> PinUvAuthTokenState<E> {
    /// Creates a pinUvAuthToken state without permissions.
    pub fn new() -> Self {
        PinUvAuthTokenState {
            permissions_set: 0,
            permissions_rp_id: None,
            usage_timer: <E::Clock as Clock>::Timer::default(),
            user_verified: false,
            in_use: false,
        }
    }

    /// Returns whether the pinUvAuthToken is active.
    pub fn is_in_use(&self) -> bool {
        self.in_use
    }

    /// Checks if the permission is granted.
    pub fn has_permission(&self, permission: PinPermission) -> Result<(), Ctap2StatusCode> {
        if permission as u8 & self.permissions_set != 0 {
            Ok(())
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    /// Checks if there is no associated permissions RPID.
    pub fn has_no_permissions_rp_id(&self) -> Result<(), Ctap2StatusCode> {
        if self.permissions_rp_id.is_some() {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }
        Ok(())
    }

    /// Checks if the permissions RPID is associated.
    pub fn has_permissions_rp_id(&self, rp_id: &str) -> Result<(), Ctap2StatusCode> {
        match &self.permissions_rp_id {
            Some(p) if rp_id == p => Ok(()),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID),
        }
    }

    /// Checks if the permissions RPID's association matches the hash.
    pub fn has_permissions_rp_id_hash(&self, rp_id_hash: &[u8]) -> Result<(), Ctap2StatusCode> {
        match &self.permissions_rp_id {
            Some(p) if rp_id_hash == Sha::<E>::digest(p.as_bytes()) => Ok(()),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID),
        }
    }

    /// Sets the permissions, represented as bits in a byte.
    pub fn set_permissions(&mut self, permissions: u8) {
        self.permissions_set = permissions;
    }

    /// Sets the permissions RPID.
    pub fn set_permissions_rp_id(&mut self, permissions_rp_id: Option<String>) {
        self.permissions_rp_id = permissions_rp_id;
    }

    /// Sets the default permissions.
    ///
    /// Allows MakeCredential and GetAssertion, without specifying a RP ID.
    pub fn set_default_permissions(&mut self) {
        self.set_permissions(0x03);
        self.set_permissions_rp_id(None);
    }

    /// Starts the timer for pinUvAuthToken usage.
    pub fn begin_using_pin_uv_auth_token(&mut self, env: &mut E) {
        self.user_verified = true;
        self.usage_timer = env.clock().make_timer(INITIAL_USAGE_TIME_LIMIT_MS);
        self.in_use = true;
    }

    /// Updates the usage timer, and disables the pinUvAuthToken on timeout.
    pub fn pin_uv_auth_token_usage_timer_observer(&mut self, env: &mut E) {
        if !self.in_use {
            return;
        }
        if env.clock().is_elapsed(&self.usage_timer) {
            self.stop_using_pin_uv_auth_token();
        }
    }

    /// Returns whether the user is verified.
    pub fn get_user_verified_flag_value(&self) -> bool {
        self.in_use && self.user_verified
    }

    /// Consumes the user verification.
    pub fn clear_user_verified_flag(&mut self) {
        self.user_verified = false;
    }

    /// Clears all permissions except Large Blob Write.
    pub fn clear_pin_uv_auth_token_permissions_except_lbw(&mut self) {
        self.permissions_set &= PinPermission::LargeBlobWrite as u8;
    }

    /// Resets to the initial state.
    pub fn stop_using_pin_uv_auth_token(&mut self) {
        self.permissions_rp_id = None;
        self.permissions_set = 0;
        self.usage_timer = <E::Clock as Clock>::Timer::default();
        self.user_verified = false;
        self.in_use = false;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::test::TestEnv;
    use enum_iterator::IntoEnumIterator;

    #[test]
    fn test_observer() {
        let mut env = TestEnv::default();
        let mut token_state = PinUvAuthTokenState::<TestEnv>::new();
        token_state.begin_using_pin_uv_auth_token(&mut env);
        assert!(token_state.is_in_use());
        env.clock().advance(100);
        token_state.pin_uv_auth_token_usage_timer_observer(&mut env);
        assert!(token_state.is_in_use());
        env.clock().advance(INITIAL_USAGE_TIME_LIMIT_MS);
        token_state.pin_uv_auth_token_usage_timer_observer(&mut env);
        assert!(!token_state.is_in_use());
    }

    #[test]
    fn test_stop() {
        let mut env = TestEnv::default();
        let mut token_state = PinUvAuthTokenState::<TestEnv>::new();
        token_state.begin_using_pin_uv_auth_token(&mut env);
        assert!(token_state.is_in_use());
        token_state.stop_using_pin_uv_auth_token();
        assert!(!token_state.is_in_use());
    }

    #[test]
    fn test_permissions() {
        let mut token_state = PinUvAuthTokenState::<TestEnv>::new();
        token_state.set_permissions(0xFF);
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(token_state.has_permission(permission), Ok(()));
        }
        token_state.clear_pin_uv_auth_token_permissions_except_lbw();
        assert_eq!(
            token_state.has_permission(PinPermission::CredentialManagement),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            token_state.has_permission(PinPermission::LargeBlobWrite),
            Ok(())
        );
        token_state.stop_using_pin_uv_auth_token();
        for permission in PinPermission::into_enum_iter() {
            assert_eq!(
                token_state.has_permission(permission),
                Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
            );
        }
    }

    #[test]
    fn test_permissions_rp_id_none() {
        let mut token_state = PinUvAuthTokenState::<TestEnv>::new();
        let example_hash = Sha::<TestEnv>::digest(b"example.com");
        token_state.set_permissions_rp_id(None);
        assert_eq!(token_state.has_no_permissions_rp_id(), Ok(()));
        assert_eq!(
            token_state.has_permissions_rp_id("example.com"),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            token_state.has_permissions_rp_id_hash(&example_hash),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_permissions_rp_id_some() {
        let mut token_state = PinUvAuthTokenState::<TestEnv>::new();
        let example_hash = Sha::<TestEnv>::digest(b"example.com");
        token_state.set_permissions_rp_id(Some(String::from("example.com")));

        assert_eq!(
            token_state.has_no_permissions_rp_id(),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(token_state.has_permissions_rp_id("example.com"), Ok(()));
        assert_eq!(
            token_state.has_permissions_rp_id("another.example.com"),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            token_state.has_permissions_rp_id_hash(&example_hash),
            Ok(())
        );
        assert_eq!(
            token_state.has_permissions_rp_id_hash(&[0x1D; 32]),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );

        token_state.stop_using_pin_uv_auth_token();
        assert_eq!(
            token_state.has_permissions_rp_id("example.com"),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            token_state.has_permissions_rp_id_hash(&example_hash),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    #[test]
    fn test_user_verified_flag() {
        let mut env = TestEnv::default();
        let mut token_state = PinUvAuthTokenState::<TestEnv>::new();
        assert!(!token_state.get_user_verified_flag_value());
        token_state.begin_using_pin_uv_auth_token(&mut env);
        assert!(token_state.get_user_verified_flag_value());
        token_state.clear_user_verified_flag();
        assert!(!token_state.get_user_verified_flag_value());
        token_state.begin_using_pin_uv_auth_token(&mut env);
        assert!(token_state.get_user_verified_flag_value());
        token_state.stop_using_pin_uv_auth_token();
        assert!(!token_state.get_user_verified_flag_value());
    }
}
