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

use super::{EC_FIELD_SIZE, EC_SIGNATURE_SIZE};
use crate::api::rng::Rng;
use alloc::vec::Vec;

/// Container for all ECDSA cryptographic material.
pub trait EcSigning {
    type SecretKey: SecretKey<PublicKey = Self::PublicKey, Signature = Self::Signature>;
    type PublicKey: PublicKey<Signature = Self::Signature>;
    type Signature: Signature;
}

/// Elliptic curve signing key.
pub trait SecretKey: Sized {
    type PublicKey: PublicKey;
    type Signature: Signature;

    /// Generates a new random secret key.
    fn random(rng: &mut impl Rng) -> Self;

    /// Computes the corresponding public key for this private key.
    fn public_key(&self) -> Self::PublicKey;

    /// Signs the message.
    fn sign(&self, message: &[u8]) -> Self::Signature;

    /// Returns the wrapped signing key.
    ///
    /// The returned representation needs to be deterministic. If you call this function twice for
    /// the same private key, the return value has to stay the same.
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

/// Elliptic curve verifying key.
pub trait PublicKey: Sized {
    type Signature: Signature;

    /// Writes the public key coordinates into the passed in parameters.
    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]);
}

/// Elliptic curve signature.
pub trait Signature: Sized {
    /// Writes the signature bytes into the passed in parameter.
    fn to_slice(&self, bytes: &mut [u8; EC_SIGNATURE_SIZE]);

    /// Encodes the signatures as ASN1 DER.
    fn to_der(&self) -> Vec<u8>;
}
