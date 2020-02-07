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

use super::ec::exponent256::{ExponentP256, NonZeroExponentP256};
use super::ec::int256;
use super::ec::int256::Int256;
use super::ec::point::PointP256;
use super::hmac::hmac_256;
use super::rng256::Rng256;
use super::{Hash256, HashBlockSize64Bytes};
use alloc::vec::Vec;
use core::marker::PhantomData;

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "derive_debug", derive(Debug))]
pub struct SecKey {
    k: NonZeroExponentP256,
}

pub struct Signature {
    r: NonZeroExponentP256,
    s: NonZeroExponentP256,
}

pub struct PubKey {
    p: PointP256,
}

impl SecKey {
    pub fn gensk<R>(rng: &mut R) -> SecKey
    where
        R: Rng256,
    {
        SecKey {
            k: NonZeroExponentP256::gen_uniform(rng),
        }
    }

    pub fn genpk(&self) -> PubKey {
        PubKey {
            p: PointP256::base_point_mul(self.k.as_exponent()),
        }
    }

    // ECDSA signature based on a RNG to generate a suitable randomization parameter.
    // Under the hood, rejection sampling is used to make sure that the randomization parameter is
    // uniformly distributed.
    // The provided RNG must be cryptographically secure; otherwise this method is insecure.
    pub fn sign_rng<H, R>(&self, msg: &[u8], rng: &mut R) -> Signature
    where
        H: Hash256,
        R: Rng256,
    {
        let m = ExponentP256::modn(Int256::from_bin(&H::hash(msg)));

        loop {
            let k = NonZeroExponentP256::gen_uniform(rng);
            if let Some(sign) = self.try_sign(&k, &m) {
                return sign;
            }
        }
    }

    // Deterministic ECDSA signature based on RFC 6979 to generate a suitable randomization
    // parameter.
    pub fn sign_rfc6979<H>(&self, msg: &[u8]) -> Signature
    where
        H: Hash256 + HashBlockSize64Bytes,
    {
        let m = ExponentP256::modn(Int256::from_bin(&H::hash(msg)));

        let mut rfc_6979 = Rfc6979::<H>::new(self, &msg);
        loop {
            let k = NonZeroExponentP256::from_int_checked(rfc_6979.next());
            // The branching here is fine. By design the algorithm of RFC 6976 has a running time
            // that depends on the sequence of generated k.
            if bool::from(k.is_none()) {
                continue;
            }
            let k = k.unwrap();

            if let Some(sign) = self.try_sign(&k, &m) {
                return sign;
            }
        }
    }

    // Try signing a curve element given a randomization parameter k. If no signature can be
    // obtained from this k, None is returned and the caller should try again with another value.
    fn try_sign(&self, k: &NonZeroExponentP256, msg: &ExponentP256) -> Option<Signature> {
        let r = ExponentP256::modn(PointP256::base_point_mul(k.as_exponent()).getx().to_int());
        // The branching here is fine because all this reveals is that k generated an unsuitable r.
        let r = r.non_zero();
        if bool::from(r.is_none()) {
            return None;
        }
        let r = r.unwrap();

        let (s, top) = &(&r * &self.k).to_int() + &msg.to_int();
        let s = k.inv().as_exponent().mul_top(&s, top);

        // The branching here is fine because all this reveals is that k generated an unsuitable s.
        let s = s.non_zero();
        if bool::from(s.is_none()) {
            return None;
        }
        let s = s.unwrap();

        Some(Signature { r, s })
    }

    #[cfg(test)]
    pub fn get_k_rfc6979<H>(&self, msg: &[u8]) -> NonZeroExponentP256
    where
        H: Hash256 + HashBlockSize64Bytes,
    {
        let m = ExponentP256::modn(Int256::from_bin(&H::hash(msg)));

        let mut rfc_6979 = Rfc6979::<H>::new(self, &msg);
        loop {
            let k = NonZeroExponentP256::from_int_checked(rfc_6979.next());
            if bool::from(k.is_none()) {
                continue;
            }
            let k = k.unwrap();
            if self.try_sign(&k, &m).is_some() {
                return k;
            }
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Option<SecKey> {
        let k = NonZeroExponentP256::from_int_checked(Int256::from_bin(bytes));
        // The branching here is fine because all this reveals is whether the key was invalid.
        if bool::from(k.is_none()) {
            return None;
        }
        let k = k.unwrap();
        Some(SecKey { k })
    }

    pub fn to_bytes(&self, bytes: &mut [u8; 32]) {
        self.k.to_int().to_bin(bytes);
    }
}

impl Signature {
    pub fn to_asn1_der(&self) -> Vec<u8> {
        const DER_INTEGER_TYPE: u8 = 0x02;
        const DER_DEF_LENGTH_SEQUENCE: u8 = 0x30;

        let r_encoding = self.r.to_int().to_minimal_encoding();
        let s_encoding = self.s.to_int().to_minimal_encoding();
        // We rely on the encoding to be short enough such that
        // sum of lengths + 4 still fits into 7 bits.
        #[cfg(test)]
        assert!(r_encoding.len() <= 33);
        #[cfg(test)]
        assert!(s_encoding.len() <= 33);
        // The ASN1 of a signature is a two member sequence. Its length is the
        // sum of the integer encoding lengths and 2 header bytes per integer.
        let mut encoding = vec![
            DER_DEF_LENGTH_SEQUENCE,
            (r_encoding.len() + s_encoding.len() + 4) as u8,
        ];
        encoding.push(DER_INTEGER_TYPE);
        encoding.push(r_encoding.len() as u8);
        encoding.extend(r_encoding);
        encoding.push(DER_INTEGER_TYPE);
        encoding.push(s_encoding.len() as u8);
        encoding.extend(s_encoding);
        encoding
    }

    #[cfg(feature = "std")]
    pub fn from_bytes(bytes: &[u8]) -> Option<Signature> {
        if bytes.len() != 64 {
            None
        } else {
            let r =
                NonZeroExponentP256::from_int_checked(Int256::from_bin(array_ref![bytes, 0, 32]));
            let s =
                NonZeroExponentP256::from_int_checked(Int256::from_bin(array_ref![bytes, 32, 32]));
            if bool::from(r.is_none()) || bool::from(s.is_none()) {
                return None;
            }
            let r = r.unwrap();
            let s = s.unwrap();
            Some(Signature { r, s })
        }
    }

    #[cfg(test)]
    fn to_bytes(&self, bytes: &mut [u8; 64]) {
        self.r.to_int().to_bin(array_mut_ref![bytes, 0, 32]);
        self.s.to_int().to_bin(array_mut_ref![bytes, 32, 32]);
    }
}

impl PubKey {
    pub const ES256_ALGORITHM: i64 = -7;
    #[cfg(feature = "with_ctap1")]
    const UNCOMPRESSED_LENGTH: usize = 1 + 2 * int256::NBYTES;

    #[cfg(feature = "std")]
    pub fn from_bytes_uncompressed(bytes: &[u8]) -> Option<PubKey> {
        PointP256::from_bytes_uncompressed_vartime(bytes).map(|p| PubKey { p })
    }

    #[cfg(test)]
    fn to_bytes_uncompressed(&self, bytes: &mut [u8; 65]) {
        self.p.to_bytes_uncompressed(bytes);
    }

    #[cfg(feature = "with_ctap1")]
    pub fn to_uncompressed(&self) -> [u8; PubKey::UNCOMPRESSED_LENGTH] {
        // Formatting according to:
        // https://tools.ietf.org/id/draft-jivsov-ecc-compact-05.html#overview
        const B0_BYTE_MARKER: u8 = 0x04;
        let mut representation = [0; PubKey::UNCOMPRESSED_LENGTH];
        let (marker, x, y) =
            mut_array_refs![&mut representation, 1, int256::NBYTES, int256::NBYTES];
        marker[0] = B0_BYTE_MARKER;
        self.p.getx().to_int().to_bin(x);
        self.p.gety().to_int().to_bin(y);
        representation
    }

    // Encodes the key according to CBOR Object Signing and Encryption, defined in RFC 8152.
    pub fn to_cose_key(&self) -> Option<Vec<u8>> {
        const EC2_KEY_TYPE: i64 = 2;
        const P_256_CURVE: i64 = 1;
        let mut x_bytes = vec![0; int256::NBYTES];
        self.p
            .getx()
            .to_int()
            .to_bin(array_mut_ref![x_bytes.as_mut_slice(), 0, int256::NBYTES]);
        let x_byte_cbor: cbor::Value = cbor_bytes!(x_bytes);
        let mut y_bytes = vec![0; int256::NBYTES];
        self.p
            .gety()
            .to_int()
            .to_bin(array_mut_ref![y_bytes.as_mut_slice(), 0, int256::NBYTES]);
        let y_byte_cbor: cbor::Value = cbor_bytes!(y_bytes);
        let cbor_value = cbor_map_options! {
            1 => EC2_KEY_TYPE,
            3 => PubKey::ES256_ALGORITHM,
            -1 => P_256_CURVE,
            -2 => x_byte_cbor,
            -3 => y_byte_cbor,
        };
        let mut encoded_key = Vec::new();
        if cbor::write(cbor_value, &mut encoded_key) {
            Some(encoded_key)
        } else {
            None
        }
    }

    #[cfg(feature = "std")]
    pub fn verify_vartime<H>(&self, msg: &[u8], sign: &Signature) -> bool
    where
        H: Hash256,
    {
        let m = ExponentP256::modn(Int256::from_bin(&H::hash(msg)));

        let v = sign.s.inv();
        let u = &m * v.as_exponent();
        let v = &sign.r * &v;

        let u = self.p.points_mul(&u, v.as_exponent()).getx();

        ExponentP256::modn(u.to_int()) == *sign.r.as_exponent()
    }
}

struct Rfc6979<H>
where
    H: Hash256 + HashBlockSize64Bytes,
{
    k: [u8; 32],
    v: [u8; 32],
    hash_marker: PhantomData<H>,
}

impl<H> Rfc6979<H>
where
    H: Hash256 + HashBlockSize64Bytes,
{
    pub fn new(sk: &SecKey, msg: &[u8]) -> Rfc6979<H> {
        let h1 = H::hash(msg);
        let v = [0x01; 32];
        let k = [0x00; 32];

        let mut contents = [0; 3 * 32 + 1];
        let (contents_v, marker, contents_k, contents_h1) =
            mut_array_refs![&mut contents, 32, 1, 32, 32];
        contents_v.copy_from_slice(&v);
        marker[0] = 0x00;
        Int256::to_bin(&sk.k.to_int(), contents_k);
        Int256::to_bin(&Int256::from_bin(&h1).modd(&Int256::N), contents_h1);

        let k = hmac_256::<H>(&k, &contents);
        let v = hmac_256::<H>(&k, &v);

        let (contents_v, marker, _) = mut_array_refs![&mut contents, 32, 1, 64];
        contents_v.copy_from_slice(&v);
        marker[0] = 0x01;

        let k = hmac_256::<H>(&k, &contents);
        let v = hmac_256::<H>(&k, &v);

        Rfc6979 {
            k,
            v,
            hash_marker: PhantomData,
        }
    }

    fn next(&mut self) -> Int256 {
        // Note: at this step, the logic from RFC 6979 is simplified, because the HMAC produces 256
        // bits and we need 256 bits.
        let t = hmac_256::<H>(&self.k, &self.v);
        let result = Int256::from_bin(&t);

        let mut v1 = [0; 33];
        v1[..32].copy_from_slice(&self.v);
        v1[32] = 0x00;
        self.k = hmac_256::<H>(&self.k, &v1);
        self.v = hmac_256::<H>(&self.k, &self.v);

        result
    }
}

#[cfg(test)]
mod test {
    use super::super::rng256::ThreadRng256;
    use super::super::sha256::Sha256;
    use super::*;
    extern crate hex;
    extern crate ring;
    extern crate untrusted;

    // Run more test iterations in release mode, as the code should be faster.
    #[cfg(not(debug_assertions))]
    const ITERATIONS: u32 = 10000;
    #[cfg(debug_assertions)]
    const ITERATIONS: u32 = 500;

    /** Test that key generation creates valid keys **/
    #[test]
    fn test_genpk_is_valid_random() {
        let mut rng = ThreadRng256 {};

        for _ in 0..ITERATIONS {
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            assert!(pk.p.is_valid_vartime());
        }
    }

    /** Serialization **/
    #[test]
    fn test_seckey_to_bytes_from_bytes() {
        let mut rng = ThreadRng256 {};

        for _ in 0..ITERATIONS {
            let sk = SecKey::gensk(&mut rng);
            let mut bytes = [0; 32];
            sk.to_bytes(&mut bytes);
            let decoded_sk = SecKey::from_bytes(&bytes);
            assert_eq!(decoded_sk, Some(sk));
        }
    }

    #[test]
    fn test_seckey_from_bytes_zero() {
        // Zero is not a valid exponent for a secret key.
        let bytes = [0; 32];
        let sk = SecKey::from_bytes(&bytes);
        assert!(sk.is_none());
    }

    #[test]
    fn test_seckey_from_bytes_n() {
        let mut bytes = [0; 32];
        Int256::N.to_bin(&mut bytes);
        let sk = SecKey::from_bytes(&bytes);
        assert!(sk.is_none());
    }

    #[test]
    fn test_seckey_from_bytes_ge_n() {
        let bytes = [0xFF; 32];
        let sk = SecKey::from_bytes(&bytes);
        assert!(sk.is_none());
    }

    /** Test vectors from RFC6979 **/
    fn int256_from_hex(x: &str) -> Int256 {
        let bytes = hex::decode(x).unwrap();
        assert_eq!(bytes.len(), 32);
        Int256::from_bin(array_ref![bytes.as_slice(), 0, 32])
    }

    // Test vectors from RFC6979, Section A.2.5.
    const RFC6979_X: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    const RFC6979_UX: &str = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    const RFC6979_UY: &str = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";

    #[test]
    fn test_rfc6979_keypair() {
        let sk = SecKey {
            k: NonZeroExponentP256::from_int_checked(int256_from_hex(RFC6979_X)).unwrap(),
        };
        let pk = sk.genpk();
        assert_eq!(pk.p.getx().to_int(), int256_from_hex(RFC6979_UX));
        assert_eq!(pk.p.gety().to_int(), int256_from_hex(RFC6979_UY));
    }

    fn test_rfc6979(msg: &str, k: &str, r: &str, s: &str) {
        let sk = SecKey {
            k: NonZeroExponentP256::from_int_checked(int256_from_hex(RFC6979_X)).unwrap(),
        };
        assert_eq!(
            sk.get_k_rfc6979::<Sha256>(msg.as_bytes()).to_int(),
            int256_from_hex(k)
        );
        let sign = sk.sign_rfc6979::<Sha256>(msg.as_bytes());
        assert_eq!(sign.r.to_int(), int256_from_hex(r));
        assert_eq!(sign.s.to_int(), int256_from_hex(s));
    }

    #[test]
    fn test_rfc6979_sample() {
        let msg = "sample";
        let k = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";
        let r = "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716";
        let s = "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
        test_rfc6979(msg, k, r, s);
    }

    #[test]
    fn test_rfc6979_test() {
        let msg = "test";
        let k = "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0";
        let r = "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367";
        let s = "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083";
        test_rfc6979(msg, k, r, s);
    }

    /** Tests that sign and verify are consistent **/
    // Test that signed messages are correctly verified.
    #[test]
    fn test_sign_rfc6979_verify_random() {
        let mut rng = ThreadRng256 {};

        for _ in 0..ITERATIONS {
            let msg = rng.gen_uniform_u8x32();
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            let sign = sk.sign_rfc6979::<Sha256>(&msg);
            assert!(pk.verify_vartime::<Sha256>(&msg, &sign));
        }
    }

    // Test that signed messages are correctly verified.
    #[test]
    fn test_sign_verify_random() {
        let mut rng = ThreadRng256 {};

        for _ in 0..ITERATIONS {
            let msg = rng.gen_uniform_u8x32();
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            let sign = sk.sign_rng::<Sha256, _>(&msg, &mut rng);
            assert!(pk.verify_vartime::<Sha256>(&msg, &sign));
        }
    }

    /** Tests that this code is compatible with the ring crate **/
    // Test that the ring crate works properly.
    #[test]
    fn test_ring_sign_ring_verify() {
        use ring::rand::SecureRandom;
        use ring::signature::{KeyPair, VerificationAlgorithm};

        let ring_rng = ring::rand::SystemRandom::new();

        for _ in 0..ITERATIONS {
            let mut msg_bytes: [u8; 64] = [Default::default(); 64];
            ring_rng.fill(&mut msg_bytes).unwrap();

            let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &ring_rng,
            )
            .unwrap();
            let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8_bytes.as_ref(),
            )
            .unwrap();
            let public_key_bytes = key_pair.public_key().as_ref();

            let sig = key_pair.sign(&ring_rng, &msg_bytes).unwrap();
            let sig_bytes = sig.as_ref();

            assert!(ring::signature::ECDSA_P256_SHA256_FIXED
                .verify(
                    untrusted::Input::from(public_key_bytes),
                    untrusted::Input::from(&msg_bytes),
                    untrusted::Input::from(sig_bytes)
                )
                .is_ok());
        }
    }

    // Test that messages signed by the ring crate are correctly verified by this code.
    #[test]
    fn test_ring_sign_self_verify() {
        use ring::rand::SecureRandom;
        use ring::signature::KeyPair;

        let ring_rng = ring::rand::SystemRandom::new();

        for _ in 0..ITERATIONS {
            let mut msg_bytes: [u8; 64] = [Default::default(); 64];
            ring_rng.fill(&mut msg_bytes).unwrap();

            let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &ring_rng,
            )
            .unwrap();
            let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8_bytes.as_ref(),
            )
            .unwrap();
            let public_key_bytes = key_pair.public_key().as_ref();

            let sig = key_pair.sign(&ring_rng, &msg_bytes).unwrap();
            let sig_bytes = sig.as_ref();

            let pk = PubKey::from_bytes_uncompressed(public_key_bytes).unwrap();
            let sign = Signature::from_bytes(sig_bytes).unwrap();
            assert!(pk.verify_vartime::<Sha256>(&msg_bytes, &sign));
        }
    }

    // Test that messages signed by this code are correctly verified by the ring crate.
    #[test]
    fn test_self_sign_ring_verify() {
        use ring::signature::VerificationAlgorithm;

        let mut rng = ThreadRng256 {};

        for _ in 0..ITERATIONS {
            let msg_bytes = rng.gen_uniform_u8x32();
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            let sign = sk.sign_rng::<Sha256, _>(&msg_bytes, &mut rng);

            let mut public_key_bytes: [u8; 65] = [Default::default(); 65];
            pk.to_bytes_uncompressed(&mut public_key_bytes);
            let mut sig_bytes: [u8; 64] = [Default::default(); 64];
            sign.to_bytes(&mut sig_bytes);

            assert!(ring::signature::ECDSA_P256_SHA256_FIXED
                .verify(
                    untrusted::Input::from(&public_key_bytes),
                    untrusted::Input::from(&msg_bytes),
                    untrusted::Input::from(&sig_bytes)
                )
                .is_ok());
        }
    }

    #[test]
    fn test_signature_to_asn1_der_short_encodings() {
        let r_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        let r = NonZeroExponentP256::from_int_checked(Int256::from_bin(&r_bytes)).unwrap();
        let s_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xFF,
        ];
        let s = NonZeroExponentP256::from_int_checked(Int256::from_bin(&s_bytes)).unwrap();
        let signature = Signature { r, s };
        let expected_encoding = vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0xFF];

        assert_eq!(signature.to_asn1_der(), expected_encoding);
    }

    #[test]
    fn test_signature_to_asn1_der_long_encodings() {
        let r_bytes = [
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA,
        ];
        let r = NonZeroExponentP256::from_int_checked(Int256::from_bin(&r_bytes)).unwrap();
        let s_bytes = [
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB,
        ];
        let s = NonZeroExponentP256::from_int_checked(Int256::from_bin(&s_bytes)).unwrap();
        let signature = Signature { r, s };
        let expected_encoding = vec![
            0x30, 0x46, 0x02, 0x21, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x02, 0x21, 0x00, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB,
        ];

        assert_eq!(signature.to_asn1_der(), expected_encoding);
    }

    // TODO: Test edge-cases and compare the behavior with ring.
    // - Invalid public key (at infinity, values not less than the prime p), but ring doesn't
    // directly exposes key validation in its API.
}
