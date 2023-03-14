// Copyright 2023 Google LLC
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

use alloc::vec::Vec;
use opensk::api::crypto::{ecdh, ecdsa, Crypto, EC_FIELD_BYTE_SIZE, EC_SIGNATURE_SIZE};
use rng256::Rng256;

pub struct TockCrypto;
pub struct TockEcdh;
pub struct TockEcdsa;

impl Crypto for TockCrypto {
    type Ecdh = TockEcdh;
    type Ecdsa = TockEcdsa;
}

impl ecdh::Ecdh for TockEcdh {
    type SecretKey = TockEcdhSecretKey;
    type PublicKey = TockEcdhPublicKey;
    type SharedSecret = TockEcdhSharedSecret;
}

pub struct TockEcdhSecretKey {
    sec_key: crypto::ecdh::SecKey,
}

impl ecdh::SecretKey for TockEcdhSecretKey {
    type PublicKey = TockEcdhPublicKey;
    type SharedSecret = TockEcdhSharedSecret;

    fn random(rng: &mut impl Rng256) -> Self {
        let sec_key = crypto::ecdh::SecKey::gensk(rng);
        Self { sec_key }
    }

    fn public_key(&self) -> Self::PublicKey {
        let pub_key = self.sec_key.genpk();
        TockEcdhPublicKey { pub_key }
    }

    fn diffie_hellman(&self, public_key: &TockEcdhPublicKey) -> Self::SharedSecret {
        let shared_secret = self.sec_key.exchange_x(&public_key.pub_key);
        TockEcdhSharedSecret { shared_secret }
    }
}

pub struct TockEcdhPublicKey {
    pub_key: crypto::ecdh::PubKey,
}

impl ecdh::PublicKey for TockEcdhPublicKey {
    fn from_coordinates(
        x: &[u8; EC_FIELD_BYTE_SIZE],
        y: &[u8; EC_FIELD_BYTE_SIZE],
    ) -> Option<Self> {
        crypto::ecdh::PubKey::from_coordinates(x, y).map(|k| Self { pub_key: k })
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_BYTE_SIZE], y: &mut [u8; EC_FIELD_BYTE_SIZE]) {
        self.pub_key.to_coordinates(x, y);
    }
}

pub struct TockEcdhSharedSecret {
    shared_secret: [u8; EC_FIELD_BYTE_SIZE],
}

impl ecdh::SharedSecret for TockEcdhSharedSecret {
    fn raw_secret_bytes(&self) -> [u8; EC_FIELD_BYTE_SIZE] {
        self.shared_secret
    }
}

impl ecdsa::Ecdsa for TockEcdsa {
    type SecretKey = TockEcdsaSecretKey;
    type PublicKey = TockEcdsaPublicKey;
    type Signature = TockEcdsaSignature;
}

pub struct TockEcdsaSecretKey {
    sec_key: crypto::ecdsa::SecKey,
}

impl ecdsa::SecretKey for TockEcdsaSecretKey {
    type PublicKey = TockEcdsaPublicKey;
    type Signature = TockEcdsaSignature;

    fn random(rng: &mut impl Rng256) -> Self {
        let sec_key = crypto::ecdsa::SecKey::gensk(rng);
        Self { sec_key }
    }

    fn from_slice(bytes: &[u8; EC_FIELD_BYTE_SIZE]) -> Option<Self> {
        crypto::ecdsa::SecKey::from_bytes(bytes).map(|k| Self { sec_key: k })
    }

    fn public_key(&self) -> Self::PublicKey {
        let pub_key = self.sec_key.genpk();
        TockEcdsaPublicKey { pub_key }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = self.sec_key.sign_rfc6979::<crypto::sha256::Sha256>(message);
        TockEcdsaSignature { signature }
    }

    fn to_slice(&self, bytes: &mut [u8; EC_FIELD_BYTE_SIZE]) {
        self.sec_key.to_bytes(bytes);
    }
}

pub struct TockEcdsaPublicKey {
    pub_key: crypto::ecdsa::PubKey,
}

impl ecdsa::PublicKey for TockEcdsaPublicKey {
    type Signature = TockEcdsaSignature;

    fn from_coordinates(
        x: &[u8; EC_FIELD_BYTE_SIZE],
        y: &[u8; EC_FIELD_BYTE_SIZE],
    ) -> Option<Self> {
        crypto::ecdsa::PubKey::from_coordinates(x, y).map(|k| Self { pub_key: k })
    }

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.pub_key
            .verify_vartime::<crypto::sha256::Sha256>(message, &signature.signature)
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_BYTE_SIZE], y: &mut [u8; EC_FIELD_BYTE_SIZE]) {
        self.pub_key.to_coordinates(x, y);
    }
}

pub struct TockEcdsaSignature {
    signature: crypto::ecdsa::Signature,
}

impl ecdsa::Signature for TockEcdsaSignature {
    fn from_slice(bytes: &[u8; EC_SIGNATURE_SIZE]) -> Option<Self> {
        crypto::ecdsa::Signature::from_bytes(bytes).map(|s| TockEcdsaSignature { signature: s })
    }

    fn to_der(&self) -> Vec<u8> {
        self.signature.to_asn1_der()
    }
}
