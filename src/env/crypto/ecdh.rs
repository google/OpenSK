// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use opensk::api::crypto::EC_FIELD_SIZE;
use opensk::api::crypto::ecdh::{self, Ecdh};
use opensk::api::rng::Rng;
use wasefire::crypto::ecdh::{P256, Private, Public, Shared};

use crate::env::WasefireEnv;

impl Ecdh for WasefireEnv {
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type SharedSecret = SharedSecret;
}

pub(crate) struct SecretKey(Private<P256>);
pub(crate) struct PublicKey(Public<P256>);
pub(crate) struct SharedSecret(Shared<P256>);

impl ecdh::SecretKey for SecretKey {
    type PublicKey = PublicKey;
    type SharedSecret = SharedSecret;

    fn random(_rng: &mut impl Rng) -> Self {
        // TODO: Use the rng argument.
        SecretKey(Private::generate().unwrap())
    }

    fn public_key(&self) -> Self::PublicKey {
        PublicKey(self.0.public().unwrap())
    }

    fn diffie_hellman(&self, public: &Self::PublicKey) -> Self::SharedSecret {
        SharedSecret(Shared::new(&self.0, &public.0).unwrap())
    }
}

impl ecdh::PublicKey for PublicKey {
    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], y: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        Some(PublicKey(Public::import(x, y).ok()?))
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        self.0.export(x, y).unwrap();
    }
}

impl ecdh::SharedSecret for SharedSecret {
    fn raw_secret_bytes(&self, secret: &mut [u8; EC_FIELD_SIZE]) {
        self.0.export(secret).unwrap();
    }
}
