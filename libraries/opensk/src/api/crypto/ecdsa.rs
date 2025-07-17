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

use super::{EC_FIELD_SIZE, EC_SIGNATURE_SIZE, HASH_SIZE};
use crate::api::rng::Rng;
use alloc::vec::Vec;

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
    fn random(rng: &mut impl Rng) -> Self;

    /// Computes the corresponding public key for this private key.
    fn public_key(&self) -> Self::PublicKey;

    /// Signs the message.
    ///
    /// For hashing, SHA256 is used implicitly.
    fn sign(&self, message: &[u8]) -> Self::Signature;

    /// Returns the wrapped signing key.
    ///
    /// If you have access to a hardware module that securly wraps key material, the returned data
    /// should not allow reconstructing the private key outside of the cryptography hardware.
    ///
    /// If you return the plain private key bytes, the key material is not exposed outside of the
    /// security key. However, the data is present in plain text in memory and storage, and will
    /// not be zeroized immediately after usage.
    fn export(&self) -> Vec<u8>;

    /// Creates a signing key from its wrapped representation.
    ///
    /// Returns None if the given bytes do not represent a wrapped secret key.
    fn import(bytes: &[u8]) -> Option<Self>;
}

/// ECDSA verifying key.
pub trait PublicKey: Sized {
    type Signature: Signature;

    /// Creates a public key from its coordinates.
    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], y: &[u8; EC_FIELD_SIZE]) -> Option<Self>;

    /// Verifies if the signature matches the message.
    ///
    /// For hashing, SHA256 is used implicitly.
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool;

    /// Verifies if the signature matches the hash of the message.
    ///
    /// Prehash is the SHA256 of the signed message.
    fn verify_prehash(&self, prehash: &[u8; HASH_SIZE], signature: &Self::Signature) -> bool;

    /// Writes the public key coordinates into the passed in parameters.
    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]);
}

/// ECDSA signature.
pub trait Signature: Sized {
    /// Creates a signature from its affine coordinates, represented as concatenated bytes.
    fn from_slice(bytes: &[u8; EC_SIGNATURE_SIZE]) -> Option<Self>;

    /// Writes the signature bytes into the passed in parameter.
    fn to_slice(&self, bytes: &mut [u8; EC_SIGNATURE_SIZE]);

    /// Encodes the signatures as ASN1 DER.
    fn to_der(&self) -> Vec<u8>;
}
