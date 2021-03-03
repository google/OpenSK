// Copyright 2021 Google LLC
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

use super::hmac::hmac_256;
use super::{Hash256, HashBlockSize64Bytes};

const HASH_SIZE: usize = 32;

/// Computes the HKDF with empty salt and 256 bit (one block) output.
///
/// # Arguments
///
/// * `ikm` - Input keying material
/// * `info` - Optional context and application specific information
///
/// This implementation is equivalent to the below hkdf, with `salt` set to the
/// default block of zeros and the output length l as 32.
pub fn hkdf_empty_salt_256<H>(ikm: &[u8], info: &[u8]) -> [u8; HASH_SIZE]
where
    H: Hash256 + HashBlockSize64Bytes,
{
    // Salt is a zero block here.
    let prk = hmac_256::<H>(&[0; HASH_SIZE], ikm);
    // l is implicitly the block size, so we iterate exactly once.
    let mut t = info.to_vec();
    t.push(1);
    hmac_256::<H>(&prk, t.as_slice())
}

/// Computes the HKDF.
///
/// # Arguments
///
/// * `salt` - Optional salt value (a non-secret random value)
/// * `ikm` - Input keying material
/// * `l` - Length of output keying material in octets
/// * `info` - Optional context and application specific information
///
/// Defined in RFC: https://tools.ietf.org/html/rfc5869
///
/// `salt` and `info` can be be empty. `salt` then defaults to one block of
/// zeros of size `HASH_SIZE`. Argument order is taken from:
/// https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#pinProto2
#[cfg(test)]
pub fn hkdf<H>(salt: &[u8], ikm: &[u8], l: u8, info: &[u8]) -> Vec<u8>
where
    H: Hash256 + HashBlockSize64Bytes,
{
    let prk = if salt.is_empty() {
        hmac_256::<H>(&[0; HASH_SIZE], ikm)
    } else {
        hmac_256::<H>(salt, ikm)
    };
    let mut t = vec![];
    let mut okm = vec![];
    for i in 0..(l as usize + HASH_SIZE - 1) / HASH_SIZE {
        t.extend_from_slice(info);
        t.push((i + 1) as u8);
        t = hmac_256::<H>(&prk, t.as_slice()).to_vec();
        okm.extend_from_slice(t.as_slice());
    }
    okm.truncate(l as usize);
    okm
}

#[cfg(test)]
mod test {
    use super::super::sha256::Sha256;
    use super::*;
    use arrayref::array_ref;

    #[test]
    fn test_hkdf_sha256_vectors() {
        // Test vectors taken from https://tools.ietf.org/html/rfc5869.
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let l = 42;
        let okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();
        assert_eq!(
            hkdf::<Sha256>(salt.as_slice(), ikm.as_slice(), l, info.as_slice()),
            okm
        );

        let ikm = hex::decode(
            "000102030405060708090a0b0c0d0e0f\
                                101112131415161718191a1b1c1d1e1f\
                                202122232425262728292a2b2c2d2e2f\
                                303132333435363738393a3b3c3d3e3f\
                                404142434445464748494a4b4c4d4e4f",
        )
        .unwrap();
        let salt = hex::decode(
            "606162636465666768696a6b6c6d6e6f\
                               707172737475767778797a7b7c7d7e7f\
                               808182838485868788898a8b8c8d8e8f\
                               909192939495969798999a9b9c9d9e9f\
                               a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        )
        .unwrap();
        let info = hex::decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
                               c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                               d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
                               e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                               f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .unwrap();
        let l = 82;
        let okm = hex::decode(
            "b11e398dc80327a1c8e7f78c596a4934\
                              4f012eda2d4efad8a050cc4c19afa97c\
                              59045a99cac7827271cb41c65e590e09\
                              da3275600c2f09b8367793a9aca3db71\
                              cc30c58179ec3e87c14c01d5c1f3434f\
                              1d87",
        )
        .unwrap();
        assert_eq!(
            hkdf::<Sha256>(salt.as_slice(), ikm.as_slice(), l, info.as_slice()),
            okm
        );

        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("").unwrap();
        let info = hex::decode("").unwrap();
        let l = 42;
        let okm = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )
        .unwrap();
        assert_eq!(
            hkdf::<Sha256>(salt.as_slice(), ikm.as_slice(), l, info.as_slice()),
            okm
        );
    }

    #[test]
    fn test_hkdf_empty_salt_256_sha256_vectors() {
        // Test vectors generated by pycryptodome using:
        // HKDF(b'0', 32, b'', SHA256, context=b'\x00').hex()
        let test_okms = [
            hex::decode("f9be72116cb97f41828210289caafeabde1f3dfb9723bf43538ab18f3666783a")
                .unwrap(),
            hex::decode("f50f964f5b94d62fd1da9356ab8662b0a0f5b8e36e277178b69b6ffecf50cf44")
                .unwrap(),
            hex::decode("fc8772ceb5592d67442dcb4353cdd28519e82d6e55b4cf664b5685252c2d2998")
                .unwrap(),
            hex::decode("62831b924839a180f53be5461eeea1b89dc21779f50142b5a54df0f0cc86d61a")
                .unwrap(),
            hex::decode("6991f00a12946a4e3b8315cdcf0132c2ca508fd17b769f08d1454d92d33733e0")
                .unwrap(),
            hex::decode("0f9bb7dddd1ec61f91d8c4f5369b5870f9d44c4ceabccca1b83f06fec115e4e3")
                .unwrap(),
            hex::decode("235367e2ab6cca2aba1a666825458dba6b272a215a2537c05feebe4b80dab709")
                .unwrap(),
            hex::decode("96e8edad661da48d1a133b38c255d33e05555bc9aa442579dea1cd8d8b8d2aef")
                .unwrap(),
        ];
        for (i, okm) in test_okms.iter().enumerate() {
            // String of number i.
            let ikm = i.to_string();
            // Byte i.
            let info = [i as u8];
            assert_eq!(
                &hkdf_empty_salt_256::<Sha256>(&ikm.as_bytes(), &info[..]),
                array_ref!(okm, 0, 32)
            );
        }
    }

    #[test]
    fn test_hkdf_length() {
        let salt = [];
        let mut input = Vec::new();
        for l in 0..128 {
            assert_eq!(
                hkdf::<Sha256>(&salt, input.as_slice(), l, input.as_slice()).len(),
                l as usize
            );
            input.push(b'A');
        }
    }

    #[test]
    fn test_hkdf_empty_salt() {
        let salt = [];
        let mut input = Vec::new();
        for l in 0..128 {
            assert_eq!(
                hkdf::<Sha256>(&salt, input.as_slice(), l, input.as_slice()),
                hkdf::<Sha256>(&[0; 32], input.as_slice(), l, input.as_slice())
            );
            input.push(b'A');
        }
    }

    #[test]
    fn test_hkdf_compare_implementations() {
        let salt = [];
        let l = 32;

        let mut input = Vec::new();
        for _ in 0..128 {
            assert_eq!(
                hkdf::<Sha256>(&salt, input.as_slice(), l, input.as_slice()),
                hkdf_empty_salt_256::<Sha256>(input.as_slice(), input.as_slice())
            );
            input.push(b'A');
        }
    }
}
