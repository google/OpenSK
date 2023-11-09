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
use rand_core::RngCore;
use zeroize::Zeroize;

pub const NBYTES: usize = int256::NBYTES;

/// A private key for ECDH.
///
/// Never call zeroize explicitly, to not invalidate any invariants.
#[derive(Zeroize)]
pub struct SecKey {
    a: NonZeroExponentP256,
}

/// A public key for ECDH.
///
/// Never call zeroize explicitly, to not invalidate any invariants.
#[derive(Clone, Debug, PartialEq, Zeroize)]
pub struct PubKey {
    p: PointP256,
}

impl SecKey {
    pub fn gensk<R>(rng: &mut R) -> SecKey
    where
        R: RngCore,
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

    /// Performs the handshake using the Diffie Hellman key agreement.
    ///
    /// This function generates the Z in the PIN protocol v1 specification.
    /// https://drafts.fidoalliance.org/fido-2/stable-links-to-latest/fido-client-to-authenticator-protocol.html#pinProto1
    pub fn exchange_x(&self, other: &PubKey) -> [u8; 32] {
        let p = self.exchange_raw(other);
        let mut x: [u8; 32] = [Default::default(); 32];
        p.getx().to_int().to_bin(&mut x);
        x
    }

    /// Creates a private key from the exponent's bytes, or None if checks fail.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<SecKey> {
        let a = NonZeroExponentP256::from_int_checked(Int256::from_bin(bytes));
        // The branching here is fine because all this reveals is whether the key was invalid.
        if bool::from(a.is_none()) {
            return None;
        }
        let a = a.unwrap();
        Some(SecKey { a })
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

    /// Creates a new PubKey from its coordinates on the elliptic curve.
    pub fn from_coordinates(x: &[u8; NBYTES], y: &[u8; NBYTES]) -> Option<PubKey> {
        PointP256::new_checked_vartime(Int256::from_bin(x), Int256::from_bin(y))
            .map(|p| PubKey { p })
    }

    /// Writes the coordinates into the passed in arrays.
    pub fn to_coordinates(&self, x: &mut [u8; NBYTES], y: &mut [u8; NBYTES]) {
        self.p.getx().to_int().to_bin(x);
        self.p.gety().to_int().to_bin(y);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    // Run more test iterations in release mode, as the code should be faster.
    #[cfg(not(debug_assertions))]
    const ITERATIONS: u32 = 10000;
    #[cfg(debug_assertions)]
    const ITERATIONS: u32 = 500;

    /** Test that key generation creates valid keys **/
    #[test]
    fn test_gen_pub_is_valid_random() {
        let mut rng = OsRng::default();

        for _ in 0..ITERATIONS {
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            assert!(pk.p.is_valid_vartime());
        }
    }

    /** Test that the exchanged key is the same on both sides **/
    #[test]
    fn test_exchange_x_is_symmetric() {
        let mut rng = OsRng::default();

        for _ in 0..ITERATIONS {
            let sk_a = SecKey::gensk(&mut rng);
            let pk_a = sk_a.genpk();
            let sk_b = SecKey::gensk(&mut rng);
            let pk_b = sk_b.genpk();
            assert_eq!(sk_a.exchange_x(&pk_b), sk_b.exchange_x(&pk_a));
        }
    }

    #[test]
    fn test_exchange_x_bytes_is_symmetric() {
        let mut rng = OsRng::default();

        for _ in 0..ITERATIONS {
            let sk_a = SecKey::gensk(&mut rng);
            let mut pk_bytes_a = [Default::default(); 65];
            sk_a.genpk().to_bytes_uncompressed(&mut pk_bytes_a);

            let sk_b = SecKey::gensk(&mut rng);
            let mut pk_bytes_b = [Default::default(); 65];
            sk_b.genpk().to_bytes_uncompressed(&mut pk_bytes_b);

            let pk_a = PubKey::from_bytes_uncompressed(&pk_bytes_a).unwrap();
            let pk_b = PubKey::from_bytes_uncompressed(&pk_bytes_b).unwrap();
            assert_eq!(sk_a.exchange_x(&pk_b), sk_b.exchange_x(&pk_a));
        }
    }

    // TODO: tests with invalid public shares.
}
