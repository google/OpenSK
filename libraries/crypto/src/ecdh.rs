// Copyright 2019 Google LLC
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

use super::ec::exponent256::NonZeroExponentP256;
use super::ec::int256;
use super::ec::int256::Int256;
use super::ec::point::PointP256;
use super::rng256::Rng256;
use super::sha256::Sha256;
use super::Hash256;

pub const NBYTES: usize = int256::NBYTES;

pub struct SecKey {
    a: NonZeroExponentP256,
}

#[cfg_attr(feature = "derive_debug", derive(Clone, PartialEq, Debug))]
pub struct PubKey {
    p: PointP256,
}

impl SecKey {
    pub fn gensk<R>(rng: &mut R) -> SecKey
    where
        R: Rng256,
    {
        SecKey {
            a: NonZeroExponentP256::gen_uniform(rng),
        }
    }

    pub fn genpk(&self) -> PubKey {
        PubKey {
            p: PointP256::base_point_mul(self.a.as_exponent()),
        }
    }

    fn exchange_raw(&self, other: &PubKey) -> PointP256 {
        // At this point, the PubKey type guarantees that other.p is a valid point on the curve.
        // It's the responsibility of the caller to handle errors when converting serialized bytes
        // to a PubKey.
        other.p.mul(self.a.as_exponent())
        // TODO: Do we need to check that the exchanged point is not infinite, and if yes handle
        // the error? The following argument should be reviewed:
        //
        // In principle this isn't needed on the P-256 curve, which has a prime order and a
        // cofactor of 1.
        //
        // Some pointers on this:
        // - https://www.secg.org/sec1-v2.pdf
    }

    // DH key agreement method defined in the FIDO2 specification, Section 5.5.4. "Getting
    // sharedSecret from Authenticator"
    pub fn exchange_x_sha256(&self, other: &PubKey) -> [u8; 32] {
        let p = self.exchange_raw(other);
        let mut x: [u8; 32] = [Default::default(); 32];
        p.getx().to_int().to_bin(&mut x);
        Sha256::hash(&x)
    }
}

impl PubKey {
    #[cfg(test)]
    fn from_bytes_uncompressed(bytes: &[u8]) -> Option<PubKey> {
        PointP256::from_bytes_uncompressed_vartime(bytes).map(|p| PubKey { p })
    }

    #[cfg(test)]
    fn to_bytes_uncompressed(&self, bytes: &mut [u8; 65]) {
        self.p.to_bytes_uncompressed(bytes);
    }

    pub fn from_coordinates(x: &[u8; NBYTES], y: &[u8; NBYTES]) -> Option<PubKey> {
        PointP256::new_checked_vartime(Int256::from_bin(x), Int256::from_bin(y))
            .map(|p| PubKey { p })
    }

    pub fn to_coordinates(&self, x: &mut [u8; NBYTES], y: &mut [u8; NBYTES]) {
        self.p.getx().to_int().to_bin(x);
        self.p.gety().to_int().to_bin(y);
    }
}

#[cfg(test)]
mod test {
    use super::super::rng256::ThreadRng256;
    use super::*;

    // Run more test iterations in release mode, as the code should be faster.
    #[cfg(not(debug_assertions))]
    const ITERATIONS: u32 = 10000;
    #[cfg(debug_assertions)]
    const ITERATIONS: u32 = 500;

    /** Test that key generation creates valid keys **/
    #[test]
    fn test_gen_pub_is_valid_random() {
        let mut rng = ThreadRng256 {};

        for _ in 0..ITERATIONS {
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            assert!(pk.p.is_valid_vartime());
        }
    }

    /** Test that the exchanged key is the same on both sides **/
    #[test]
    fn test_exchange_x_sha256_is_symmetric() {
        let mut rng = ThreadRng256 {};

        for _ in 0..ITERATIONS {
            let sk_a = SecKey::gensk(&mut rng);
            let pk_a = sk_a.genpk();
            let sk_b = SecKey::gensk(&mut rng);
            let pk_b = sk_b.genpk();
            assert_eq!(sk_a.exchange_x_sha256(&pk_b), sk_b.exchange_x_sha256(&pk_a));
        }
    }

    #[test]
    fn test_exchange_x_sha256_bytes_is_symmetric() {
        let mut rng = ThreadRng256 {};

        for _ in 0..ITERATIONS {
            let sk_a = SecKey::gensk(&mut rng);
            let mut pk_bytes_a = [Default::default(); 65];
            sk_a.genpk().to_bytes_uncompressed(&mut pk_bytes_a);

            let sk_b = SecKey::gensk(&mut rng);
            let mut pk_bytes_b = [Default::default(); 65];
            sk_b.genpk().to_bytes_uncompressed(&mut pk_bytes_b);

            let pk_a = PubKey::from_bytes_uncompressed(&pk_bytes_a).unwrap();
            let pk_b = PubKey::from_bytes_uncompressed(&pk_bytes_b).unwrap();
            assert_eq!(sk_a.exchange_x_sha256(&pk_b), sk_b.exchange_x_sha256(&pk_a));
        }
    }

    // TODO: tests with invalid public shares.
}
