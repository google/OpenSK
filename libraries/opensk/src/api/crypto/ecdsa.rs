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

use super::{EC_FIELD_BYTE_SIZE, EC_SIGNATURE_SIZE};
use alloc::vec::Vec;
use rng256::Rng256;

/// Container for all ECDSA cryptographic material.
pub trait Ecdsa {
    type SecretKey: SecretKey<PublicKey = Self::PublicKey, Signature = Self::Signature>;
    type PublicKey: PublicKey<Signature = Self::Signature>;
    type Signature: Signature;
}

/// ECDSA signing key.
pub trait SecretKey: Sized {
    type PublicKey: PublicKey;
    type Signature: Signature;

    /// Generates a new random secret key.
    fn random(rng: &mut impl Rng256) -> Self;

    /// Creates a signing key from its representation in bytes.
    fn from_slice(bytes: &[u8; EC_FIELD_BYTE_SIZE]) -> Option<Self>;

    /// Computes the corresponding public key for this private key.
    fn public_key(&self) -> Self::PublicKey;

    /// Signs the message.
    ///
    /// For hashing, SHA256 is used implicitly.
    fn sign(&self, message: &[u8]) -> Self::Signature;

    /// Writes the signing key bytes into the passed in parameter.
    fn to_slice(&self, bytes: &mut [u8; EC_FIELD_BYTE_SIZE]);
}

/// ECDSA verifying key.
pub trait PublicKey: Sized {
    type Signature: Signature;

    /// Creates a public key from its coordinates.
    fn from_coordinates(x: &[u8; EC_FIELD_BYTE_SIZE], y: &[u8; EC_FIELD_BYTE_SIZE])
        -> Option<Self>;

    /// Verifies if the signature matches the message.
    ///
    /// For hashing, SHA256 is used implicitly.
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool;

    /// Writes the public key coordinates into the passed in parameters.
    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_BYTE_SIZE], y: &mut [u8; EC_FIELD_BYTE_SIZE]);
}

/// ECDSA signature.
pub trait Signature: Sized {
    /// Creates a signature from its affine coordinates, represented as concatenated bytes.
    fn from_slice(bytes: &[u8; EC_SIGNATURE_SIZE]) -> Option<Self>;

    /// Encodes the signatures as ASN1 DER.
    fn to_der(&self) -> Vec<u8>;
}
