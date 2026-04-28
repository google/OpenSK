// Copyright 2025 Google LLC
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

use alloc::vec::Vec;

use opensk::api::crypto::EC_FIELD_SIZE;
use opensk::api::crypto::ec_signing::{Ed25519, EdPublicKey, EdSecretKey, EdSignature};
use opensk::api::rng::Rng;
use wasefire::crypto::ed25519::{Private, Public};

use crate::env::WasefireEnv;

impl Ed25519 for WasefireEnv {
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type Signature = Signature;
}

pub(crate) struct SecretKey(Private);
pub(crate) struct PublicKey(Public);
pub(crate) struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl EdSecretKey for SecretKey {
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn random(_rng: &mut impl Rng) -> Self {
        // TODO: Use the rng argument.
        SecretKey(Private::generate().unwrap())
    }

    fn public_key(&self) -> Self::PublicKey {
        PublicKey(self.0.public().unwrap())
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let mut signature = Signature {
            r: [0; 32],
            s: [0; 32],
        };
        self.0
            .sign(message, &mut signature.r, &mut signature.s)
            .unwrap();
        signature
    }

    fn export(&self) -> Vec<u8> {
        self.0.export().unwrap().into_vec()
    }

    fn import(bytes: &[u8]) -> Option<Self> {
        Some(SecretKey(Private::import(bytes).ok()?))
    }
}

impl EdPublicKey for PublicKey {
    type Signature = Signature;

    fn to_slice(&self, x: &mut [u8; EC_FIELD_SIZE]) {
        self.0.export(x).unwrap();
    }
}

impl EdSignature for Signature {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.r);
        bytes.extend_from_slice(&self.s);
        bytes
    }
}
