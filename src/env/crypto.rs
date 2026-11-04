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

use alloc::vec::Vec;
use opensk::api::crypto::Crypto;
use opensk::api::crypto::ec_signing::EcSignature;
#[cfg(feature = "ed25519")]
use opensk::api::crypto::ec_signing::EdSignature;
use opensk::api::private_key::PrivateKey;
use opensk::ctap::data_formats::SignatureAlgorithm;
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};

use crate::env::WasefireEnv;

mod aes256;
mod ecdh;
mod ecdsa;
#[cfg(feature = "ed25519")]
mod ed25519;
mod hkdf256;
mod hmac256;
mod sha256;

pub(super) fn generate_private_key(
    algorithm: SignatureAlgorithm,
) -> CtapResult<PrivateKey<WasefireEnv>> {
    match algorithm {
        SignatureAlgorithm::Es256 => ecdsa::SecretKey::generate().map(PrivateKey::Ecdsa),
        #[cfg(feature = "ed25519")]
        SignatureAlgorithm::Eddsa => ed25519::SecretKey::generate().map(PrivateKey::Ed25519),
        SignatureAlgorithm::Unknown => Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM),
    }
}

pub(super) fn sign(key: &PrivateKey<WasefireEnv>, message: &[u8]) -> CtapResult<Vec<u8>> {
    match key {
        PrivateKey::Ecdsa(key) => Ok(key.try_sign(message)?.to_der()),
        #[cfg(feature = "ed25519")]
        PrivateKey::Ed25519(key) => Ok(key.try_sign(message)?.to_bytes()),
    }
}

impl Crypto for WasefireEnv {
    type Aes256 = aes256::Impl;
    type Ecdh = Self;
    type Ecdsa = Self;
    #[cfg(feature = "ed25519")]
    type Ed25519 = Self;
    type Sha256 = sha256::Impl;
    type Hmac256 = Self;
    type Hkdf256 = Self;
}
