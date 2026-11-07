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

use super::super::pin_protocol::authenticate_pin_uv_auth_token;
use super::*;
use crate::api::key_store::{self, PinInfo};
use crate::ctap::CredentialSource;
use crate::env::test::TestEnv;
use std::cell::Cell;
use std::rc::Rc;

struct Proof(Rc<Cell<usize>>);
impl Drop for Proof {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
struct Hardware {
    hash: [u8; 16],
    verifies: usize,
    changes: usize,
    drops: Rc<Cell<usize>>,
    fail_change: bool,
}
impl key_store::KeyStore for Hardware {
    type VerifiedPin = Proof;
    fn init(&mut self) -> Result<(), key_store::Error> {
        Ok(())
    }
    fn wrap_credential(&mut self, _: CredentialSource) -> Result<Vec<u8>, key_store::Error> {
        unimplemented!()
    }
    fn unwrap_credential(
        &mut self,
        _: &[u8],
        _: &[u8],
    ) -> Result<Option<CredentialSource>, key_store::Error> {
        unimplemented!()
    }
    fn cred_random(&mut self, _: bool) -> Result<Secret<[u8; 32]>, key_store::Error> {
        unimplemented!()
    }
    fn pin_info(&mut self) -> CtapResult<Option<PinInfo>> {
        Ok(Some(PinInfo {
            code_point_length: 4,
        }))
    }
    fn verify_pin(&mut self, candidate: &[u8; 16]) -> CtapResult<VerificationResult<Proof>> {
        self.verifies += 1;
        Ok(if candidate == &self.hash {
            VerificationResult::Accepted(Proof(self.drops.clone()))
        } else {
            VerificationResult::Rejected
        })
    }
    fn initialize_pin(&mut self, _: &[u8; 16], _: u8) -> CtapResult<()> {
        unimplemented!()
    }
    fn change_pin(&mut self, _proof: Proof, hash: &[u8; 16], _: u8) -> CtapResult<()> {
        self.changes += 1;
        if self.fail_change {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        self.hash = *hash;
        Ok(())
    }
    fn reset(&mut self) -> Result<(), key_store::Error> {
        Ok(())
    }
}
struct HardwareEnv {
    inner: TestEnv,
    hardware: Hardware,
}
impl Env for HardwareEnv {
    type Rng = <TestEnv as Env>::Rng;
    type UserPresence = <TestEnv as Env>::UserPresence;
    type Persist = <TestEnv as Env>::Persist;
    type KeyStore = Hardware;
    type Write = <TestEnv as Env>::Write;
    type Customization = <TestEnv as Env>::Customization;
    type HidConnection = <TestEnv as Env>::HidConnection;
    type Clock = <TestEnv as Env>::Clock;
    type Crypto = <TestEnv as Env>::Crypto;
    #[cfg(feature = "fingerprint")]
    type Fingerprint = <TestEnv as Env>::Fingerprint;
    fn rng(&mut self) -> &mut Self::Rng {
        self.inner.rng()
    }
    fn user_presence(&mut self) -> &mut Self::UserPresence {
        self.inner.user_presence()
    }
    fn persist(&mut self) -> &mut Self::Persist {
        self.inner.persist()
    }
    fn key_store(&mut self) -> &mut Self::KeyStore {
        &mut self.hardware
    }
    fn clock(&mut self) -> &mut Self::Clock {
        self.inner.clock()
    }
    #[cfg(feature = "fingerprint")]
    fn fingerprint(&mut self) -> &mut Self::Fingerprint {
        self.inner.fingerprint()
    }
    fn write(&mut self) -> Self::Write {
        self.inner.write()
    }
    fn customization(&self) -> &Self::Customization {
        self.inner.customization()
    }
    fn hid_connection(&mut self) -> &mut Self::HidConnection {
        self.inner.hid_connection()
    }
    fn boots_after_soft_reset(&self) -> bool {
        self.inner.boots_after_soft_reset()
    }
}

#[test]
fn owned_hardware_proof_is_consumed_or_dropped() {
    let drops = Rc::new(Cell::new(0));
    let mut env = HardwareEnv {
        inner: TestEnv::default(),
        hardware: Hardware {
            hash: Sha::<HardwareEnv>::digest(b"1234")[..16]
                .try_into()
                .unwrap(),
            verifies: 0,
            changes: 0,
            drops: drops.clone(),
            fail_change: false,
        },
    };
    let protocol = PinUvAuthProtocol::V2;
    let key = EcdhSk::<HardwareEnv>::random(env.rng());
    let mut client =
        ClientPin::<HardwareEnv>::new_test(&mut env, key, [0x91; PIN_TOKEN_LENGTH], protocol);
    let agreement = client.get_pin_protocol(protocol).get_public_key();
    let shared = client
        .get_pin_protocol(protocol)
        .decapsulate(agreement.clone(), protocol)
        .unwrap();
    let mut padded = [0u8; 64];
    padded[..4].copy_from_slice(b"5678");
    let new_pin_enc = shared.encrypt(&mut env, &padded).unwrap();
    let pin_hash_enc = shared
        .encrypt(&mut env, &Sha::<HardwareEnv>::digest(b"1234")[..16])
        .unwrap();
    let mut auth = new_pin_enc.clone();
    auth.extend(&pin_hash_enc);
    let params = AuthenticatorClientPinParameters {
        pin_uv_auth_protocol: protocol,
        sub_command: ClientPinSubCommand::ChangePin,
        key_agreement: Some(agreement),
        pin_uv_auth_param: Some(shared.authenticate(&auth)),
        new_pin_enc: Some(new_pin_enc),
        pin_hash_enc: Some(pin_hash_enc),
        permissions: None,
        permissions_rp_id: None,
    };
    let channel = Channel::MainHid([0x12, 0x34, 0x56, 0x78]);
    let message = [0x42; 32];
    let old_auth = authenticate_pin_uv_auth_token(&[0x91; PIN_TOKEN_LENGTH], &message, protocol);
    assert_eq!(
        client.verify_pin_uv_auth_token(&env, &message, &old_auth, protocol),
        Ok(())
    );
    env.hardware.fail_change = true;
    assert_eq!(
        client.process_command(&mut env, params.clone(), channel),
        Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    );
    assert_eq!(
        (env.hardware.verifies, env.hardware.changes, drops.get()),
        (1, 1, 1)
    );
    assert!(
        client
            .verify_pin_uv_auth_token(&env, &message, &old_auth, protocol)
            .is_err()
    );
    #[cfg(feature = "config_command")]
    let mut attempts = 2;
    #[cfg(not(feature = "config_command"))]
    let attempts = 2;
    #[cfg(feature = "config_command")]
    {
        env.persist().force_pin_change().unwrap();
        let mut same = params.clone();
        padded[..4].copy_from_slice(b"1234");
        same.new_pin_enc = Some(shared.encrypt(&mut env, &padded).unwrap());
        let mut authenticated = same.new_pin_enc.clone().unwrap();
        authenticated.extend(same.pin_hash_enc.as_ref().unwrap());
        same.pin_uv_auth_param = Some(shared.authenticate(&authenticated));
        assert_eq!(
            client.process_command(&mut env, same, channel),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION)
        );
        assert_eq!(
            (env.hardware.verifies, env.hardware.changes, drops.get()),
            (2, 1, 2)
        );
        env.persist()
            .remove(crate::api::persist::keys::FORCE_PIN_CHANGE)
            .unwrap();
        attempts += 1;
    }
    env.hardware.fail_change = false;
    assert_eq!(
        client.process_command(&mut env, params, channel),
        Ok(ResponseData::AuthenticatorClientPin(None))
    );
    assert_eq!(
        (env.hardware.verifies, env.hardware.changes, drops.get()),
        (attempts, 2, attempts)
    );
    assert!(
        env.persist()
            .find(crate::api::persist::keys::PIN_PROPERTIES)
            .unwrap()
            .is_none()
    );
    assert_eq!(env.hardware.hash, Sha::<HardwareEnv>::digest(b"5678")[..16]);
}
