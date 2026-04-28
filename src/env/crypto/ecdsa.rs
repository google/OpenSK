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

use opensk::api::crypto::EC_FIELD_SIZE;
use opensk::api::crypto::ec_signing::{EcPublicKey, EcSecretKey, EcSignature, Ecdsa};
use opensk::api::rng::Rng;
use wasefire::crypto::ecdsa::{P256, Private, Public};

use crate::env::WasefireEnv;

impl Ecdsa for WasefireEnv {
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type Signature = Signature;
}

pub(crate) struct SecretKey(Private<P256>);
pub(crate) struct PublicKey(Public<P256>);
pub(crate) struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl EcSecretKey for SecretKey {
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

impl EcPublicKey for PublicKey {
    type Signature = Signature;

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        self.0.export(x, y).unwrap();
    }
}

impl EcSignature for Signature {
    fn to_der(&self) -> Vec<u8> {
        let r = der_int(&self.r);
        let s = der_int(&self.s);
        let mut der = Vec::with_capacity(72);
        der.extend([0x30, (2 + r.len() + 2 + s.len()) as u8]); // seq
        der.extend([0x02, r.len() as u8]); // int
        der.extend(r);
        der.extend([0x02, s.len() as u8]); // int
        der.extend(s);
        der
    }
}

fn der_int(x: &[u8; 32]) -> Vec<u8> {
    let i = x.iter().position(|&x| x != 0).unwrap_or(x.len());
    let mut r = Vec::new();
    if x.get(i).is_none_or(|x| x & 0x80 != 0) {
        r.push(0);
    }
    r.extend_from_slice(&x[i..]);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_int_ok() {
        #[track_caller]
        fn test(x: &[u8; 32], r: &[u8]) {
            assert_eq!(der_int(x), r);
        }
        test(&[0; 32], &[0]);
        test(
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01",
            &[1],
        );
        test(
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f",
            &[0x7f],
        );
        test(
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80",
            &[0, 0x80],
        );
        test(
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff",
            &[0, 0xff],
        );
        test(
            b"\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        );
        test(
            b"\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"\0\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        );
    }
}
