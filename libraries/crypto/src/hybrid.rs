// Copyright 2021-2022 Google LLC
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

use super::ecdsa;
use alloc::vec::Vec;

// A label generated uniformly at random from the output space of SHA256.
const LABEL: [u8; 32] = [
    43, 253, 32, 250, 19, 51, 24, 237, 138, 49, 47, 182, 4, 194, 133, 183, 177, 218, 115, 58, 92,
    117, 45, 172, 156, 5, 214, 176, 248, 103, 55, 216,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecKey {
    dilithium_seed: [u8; dilithium::params::SEEDBYTES],
    ecdsa_sk: ecdsa::SecKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubKey {
    pub dilithium_pk: dilithium::sign::PubKey,
    pub ecdsa_pk: ecdsa::PubKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub dilithium_sign: Vec<u8>,
    pub ecdsa_sign: ecdsa::Signature,
}

fn ecdsa_input(msg: &[u8]) -> Vec<u8> {
    let mut input = LABEL.to_vec();
    input.extend(msg);
    return input;
}

fn dilithium_input(msg: &[u8], ecdsa_sign: &ecdsa::Signature) -> Vec<u8> {
    let mut input = LABEL.to_vec();
    input.extend(msg);
    input.extend(ecdsa_sign.to_asn1_der());
    return input;
}

impl SecKey {
    pub const BYTES_LENGTH: usize = 32 + dilithium::params::SEEDBYTES;
    pub fn gensk<R>(rng: &mut R) -> SecKey
    where
        R: rng256::Rng256,
    {
        let mut seed = [0u8; dilithium::params::SEEDBYTES];
        rng.fill_bytes(&mut seed);
        SecKey {
            dilithium_seed: seed,
            ecdsa_sk: ecdsa::SecKey::gensk(rng),
        }
    }

    pub fn gensk_with_pk<R>(rng: &mut R) -> (SecKey, PubKey)
    where
        R: rng256::Rng256,
    {
        let mut seed = [0u8; dilithium::params::SEEDBYTES];
        rng.fill_bytes(&mut seed);
        let (_, dilithium_pk) = dilithium::sign::SecKey::gensk_with_pk_from_seed(&seed);
        let ecdsa_sk = ecdsa::SecKey::gensk(rng);
        let ecdsa_pk = ecdsa_sk.genpk();
        let sk = SecKey {
            dilithium_seed: seed,
            ecdsa_sk,
        };
        let pk = PubKey {
            dilithium_pk,
            ecdsa_pk,
        };
        (sk, pk)
    }

    pub fn genpk(&self) -> PubKey {
        let (_, dilithium_pk) =
            dilithium::sign::SecKey::gensk_with_pk_from_seed(&self.dilithium_seed);
        PubKey {
            dilithium_pk,
            ecdsa_pk: self.ecdsa_sk.genpk(),
        }
    }

    pub fn sign_rfc6979<H>(&self, msg: &[u8]) -> Signature
    where
        H: super::Hash256 + super::HashBlockSize64Bytes,
    {
        let ecdsa_sign = self.ecdsa_sk.sign_rfc6979::<H>(&ecdsa_input(&msg));
        let dilithium_sk = dilithium::sign::SecKey::gensk_from_seed(&self.dilithium_seed);
        // This wastes some stack, we could revert the Dilithium API to take a &mut [u8].
        let dilithium_sign = dilithium_sk
            .sign(&dilithium_input(&msg, &ecdsa_sign))
            .to_vec();

        return Signature {
            ecdsa_sign,
            dilithium_sign,
        };
    }

    pub fn from_bytes(bytes: &[u8; SecKey::BYTES_LENGTH]) -> Option<SecKey> {
        let ecdsa_bytes = array_ref!(bytes, 0, 32);
        let ecdsa_sk = ecdsa::SecKey::from_bytes(&ecdsa_bytes)?;

        let dilithium_seed = array_ref!(bytes, 32, dilithium::params::SEEDBYTES).clone();

        return Some(SecKey {
            ecdsa_sk,
            dilithium_seed,
        });
    }

    pub fn to_bytes(&self, bytes: &mut [u8; SecKey::BYTES_LENGTH]) {
        let mut ecdsa_bytes = array_mut_ref!(bytes, 0, 32);
        self.ecdsa_sk.to_bytes(&mut ecdsa_bytes);
        let dilithium_bytes = array_mut_ref!(bytes, 32, dilithium::params::SEEDBYTES);
        dilithium_bytes.copy_from_slice(&self.dilithium_seed);
    }
}

impl PubKey {
    pub const BYTES_LENGTH: usize = 2 * ecdsa::NBYTES + dilithium::params::PK_SIZE_PACKED;

    pub fn from_bytes(bytes: &[u8; PubKey::BYTES_LENGTH]) -> Option<PubKey> {
        let ecdsa_x_bytes = array_ref!(bytes, 0, ecdsa::NBYTES);
        let ecdsa_y_bytes = array_ref!(bytes, ecdsa::NBYTES, ecdsa::NBYTES);

        let ecdsa_pk = ecdsa::PubKey::from_coordinates(&ecdsa_x_bytes, &ecdsa_y_bytes)?;

        let dilithium_bytes = array_ref!(
            bytes,
            ecdsa::NBYTES + ecdsa::NBYTES,
            dilithium::params::PK_SIZE_PACKED
        )
        .clone();
        let dilithium_pk = dilithium::sign::PubKey::from_bytes(&dilithium_bytes);

        Some(PubKey {
            ecdsa_pk,
            dilithium_pk,
        })
    }

    pub fn to_bytes(&self, bytes: &mut [u8; PubKey::BYTES_LENGTH]) {
        let mut ecdsa_x_bytes = [0; ecdsa::NBYTES];
        let mut ecdsa_y_bytes = [0; ecdsa::NBYTES];
        self.ecdsa_pk
            .to_coordinates(&mut ecdsa_x_bytes, &mut ecdsa_y_bytes);
        array_mut_ref!(bytes, 0, ecdsa::NBYTES).clone_from(&ecdsa_x_bytes);
        array_mut_ref!(bytes, ecdsa::NBYTES, ecdsa::NBYTES).clone_from(&ecdsa_y_bytes);
        let mut dilithium_bytes = array_mut_ref!(
            bytes,
            ecdsa::NBYTES + ecdsa::NBYTES,
            dilithium::params::PK_SIZE_PACKED
        );
        self.dilithium_pk.to_bytes(&mut dilithium_bytes);
    }

    pub fn verify_vartime<H>(&self, msg: &[u8], sign: &Signature) -> bool
    where
        H: super::Hash256,
    {
        return self
            .ecdsa_pk
            .verify_hash_vartime(&H::hash(&ecdsa_input(&msg)), &sign.ecdsa_sign)
            && self.dilithium_pk.verify(
                &dilithium_input(&msg, &sign.ecdsa_sign),
                array_ref!(sign.dilithium_sign, 0, dilithium::params::SIG_SIZE_PACKED),
            );
    }
}

impl Signature {
    pub const BYTES_LENGTH: usize = 64 + dilithium::params::SIG_SIZE_PACKED;

    /// Converts a signature into the CBOR required byte array representation.
    ///
    /// This operation consumes the signature to efficiently use memory.
    pub fn to_asn1_der(self) -> Vec<u8> {
        let mut bytes = self.ecdsa_sign.to_asn1_der();
        bytes.reserve_exact(dilithium::params::SIG_SIZE_PACKED);
        bytes.extend(self.dilithium_sign.into_iter());
        bytes
    }
}

#[cfg(test)]
mod test {
    extern crate rng256;
    use super::super::sha256::Sha256;
    use super::*;
    use rng256::Rng256;

    pub const ITERATIONS: u32 = 500;

    #[test]
    fn test_hybrid_seckey_to_bytes_from_bytes() {
        let mut rng = rng256::ThreadRng256 {};
        for _ in 0..ITERATIONS {
            let sk = SecKey::gensk(&mut rng);
            let mut bytes = [0; SecKey::BYTES_LENGTH];
            sk.to_bytes(&mut bytes);
            let decoded_sk = SecKey::from_bytes(&bytes);
            assert_eq!(decoded_sk, Some(sk));
        }
    }

    #[test]
    fn test_hybrid_pubkey_to_bytes_from_bytes() {
        let mut rng = rng256::ThreadRng256 {};
        for _ in 0..ITERATIONS {
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            let mut bytes = [0; PubKey::BYTES_LENGTH];
            pk.to_bytes(&mut bytes);
            let decoded_pk = PubKey::from_bytes(&bytes);
            assert_eq!(decoded_pk, Some(pk));
        }
    }

    #[test]
    fn test_hybrid_sign_rfc6979_verify_vartime() {
        let mut rng = rng256::ThreadRng256 {};
        for _ in 0..ITERATIONS {
            let msg = rng.gen_uniform_u8x32();
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            let sign = sk.sign_rfc6979::<Sha256>(&msg);
            assert!(pk.verify_vartime::<Sha256>(&msg, &sign));
        }
    }
}
