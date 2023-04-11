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
use super::Hash256;

const HASH_SIZE: usize = 32;

/// Computes the HKDF with the given salt and 256 bit (one block) output.
///
/// # Arguments
///
/// * `ikm` - Input keying material
/// * `salt` - Byte string that acts as a key
/// * `info` - Optional context and application specific information
///
/// This implementation is equivalent to a standard HKD, with `salt` fixed at a length of
/// 32 byte and the output length l as 32.
pub fn hkdf_256<H>(ikm: &[u8], salt: &[u8; HASH_SIZE], info: &[u8]) -> [u8; HASH_SIZE]
where
    H: Hash256,
{
    let prk = hmac_256::<H>(salt, ikm);
    // l is implicitly the block size, so we iterate exactly once.
    let mut t = info.to_vec();
    t.push(1);
    hmac_256::<H>(&prk, t.as_slice())
}

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
    H: Hash256,
{
    // Salt is a zero block here.
    hkdf_256::<H>(ikm, &[0; HASH_SIZE], info)
}

#[cfg(test)]
mod test {
    use super::super::sha256::Sha256;
    use super::*;
    use arrayref::array_ref;

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
    fn test_hkdf_256_sha256_vectors() {
        // Test vectors generated as above, but with salt:
        let test_okms = [
            hex::decode("f9be72116cb97f41828210289caafeabde1f3dfb9723bf43538ab18f3666783a")
                .unwrap(),
            hex::decode("a2480a09c7349d76e459f98a8259da40544bfbd2930d357a0f3250ade0acf941")
                .unwrap(),
            hex::decode("3904f7bf3615df9512fc6b1af651ed69b43f7fad424f9c718aaab63f377a36b9")
                .unwrap(),
            hex::decode("a0027dcffb27d356317199c6e65f153a9286ba114aee2d3cf45bdba83cb7c065")
                .unwrap(),
            hex::decode("786d1f89f54668bac443cc6a8887c95d6fbde07702cb4c16d76c452e87c50f79")
                .unwrap(),
            hex::decode("8e9a5bdf362c5aec2c31a742dfebd0b7b56e16ab8408d9d0609a4fad06446875")
                .unwrap(),
            hex::decode("4a35d3d7c80ff4fab65f7e30d6b305fc7bb39ffe905aabedd6593354f86177b6")
                .unwrap(),
            hex::decode("b1121deabd8b4308f3805cda8af991ee976bd8e413bcb6a8dd3fc26ebe2312d2")
                .unwrap(),
        ];
        for (i, okm) in test_okms.iter().enumerate() {
            // String of number i.
            let ikm = i.to_string();
            // Bytestring of byte i.
            let salt = [i as u8; 32];
            // Byte i.
            let info = [i as u8];
            assert_eq!(
                &hkdf_256::<Sha256>(&ikm.as_bytes(), &salt, &info[..]),
                array_ref!(okm, 0, 32)
            );
        }
    }
}
