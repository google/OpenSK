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

use super::EC_FIELD_SIZE;
use crate::api::rng::Rng;

/// Container for all ECDH cryptographic material.
pub trait Ecdh {
    type SecretKey: SecretKey<PublicKey = Self::PublicKey, SharedSecret = Self::SharedSecret>;
    type PublicKey: PublicKey;
    type SharedSecret: SharedSecret;
}

/// ECDH ephemeral key.
pub trait SecretKey {
    type PublicKey: PublicKey;
    type SharedSecret: SharedSecret;

    /// Generates a new random secret key.
    fn random(rng: &mut impl Rng) -> Self;

    /// Computes the corresponding public key for this private key.
    fn public_key(&self) -> Self::PublicKey;

    /// Computes the shared secret when using Elliptic-curve Diffie–Hellman.
    fn diffie_hellman(&self, public_key: &Self::PublicKey) -> Self::SharedSecret;
}

/// ECDH public key.
pub trait PublicKey: Sized {
    /// Creates a public key from its coordinates.
    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], y: &[u8; EC_FIELD_SIZE]) -> Option<Self>;

    /// Writes the public key coordinates into the passed in parameters.
    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]);
}

/// ECDH shared secret.
pub trait SharedSecret {
    /// Exports the x component of the point computed by Diffie–Hellman.
    fn raw_secret_bytes(&self, secret: &mut [u8; EC_FIELD_SIZE]);
}
