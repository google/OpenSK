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

use super::{Hash256, HashBlockSize64Bytes};
use byteorder::{BigEndian, ByteOrder};
use core::num::Wrapping;

const BLOCK_SIZE: usize = 64;

pub struct Sha256 {
    state: [Wrapping<u32>; 8],
    block: [u8; BLOCK_SIZE],
    total_len: usize,
}

impl Hash256 for Sha256 {
    fn new() -> Self {
        Sha256 {
            state: Sha256::H,
            block: [0; BLOCK_SIZE],
            total_len: 0,
        }
    }

    fn update(&mut self, mut contents: &[u8]) {
        let cursor_in_block = self.total_len % BLOCK_SIZE;
        let left_in_block = BLOCK_SIZE - cursor_in_block;

        // Increment the total length before we mutate the contents slice.
        self.total_len += contents.len();

        if contents.len() < left_in_block {
            // The contents don't fill the current block. Simply copy the bytes.
            self.block[cursor_in_block..(cursor_in_block + contents.len())]
                .copy_from_slice(contents);
        } else {
            // First, fill and process the current block.
            let (this_block, rest) = contents.split_at(left_in_block);
            self.block[cursor_in_block..].copy_from_slice(this_block);
            Sha256::hash_block(&mut self.state, &self.block);
            contents = rest;

            // Process full blocks.
            while contents.len() >= 64 {
                let (block, rest) = contents.split_at(64);
                Sha256::hash_block(&mut self.state, array_ref![block, 0, 64]);
                contents = rest;
            }

            // Copy the last block for further processing.
            self.block[..contents.len()].copy_from_slice(contents);
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        // Last block and padding.
        let cursor_in_block = self.total_len % BLOCK_SIZE;
        self.block[cursor_in_block] = 0x80;
        // Clear the rest of the block.
        for byte in self.block[(cursor_in_block + 1)..].iter_mut() {
            *byte = 0;
        }

        if cursor_in_block >= 56 {
            // Padding doesn't fit in this block, so we first hash this block and then hash a
            // padding block.
            Sha256::hash_block(&mut self.state, &self.block);
            // Clear buffer for the padding block.
            for byte in self.block.iter_mut() {
                *byte = 0;
            }
        }

        // The last 8 bytes of the last block contain the length of the contents. It must be
        // expressed in bits, whereas `total_len` is in bytes.
        BigEndian::write_u64(array_mut_ref![self.block, 56, 8], self.total_len as u64 * 8);
        Sha256::hash_block(&mut self.state, &self.block);

        // Encode the state's 32-bit words into bytes, using big-endian.
        let mut result: [u8; 32] = [0; 32];
        for i in 0..8 {
            BigEndian::write_u32(array_mut_ref![result, 4 * i, 4], self.state[i].0);
        }
        result
    }
}

impl HashBlockSize64Bytes for Sha256 {
    type State = [Wrapping<u32>; 8];

    #[allow(clippy::many_single_char_names)]
    fn hash_block(state: &mut Self::State, block: &[u8; 64]) {
        let mut w: [Wrapping<u32>; 64] = [Wrapping(0); 64];

        // Read the block as big-endian 32-bit words.
        for (i, item) in w.iter_mut().take(16).enumerate() {
            *item = Wrapping(BigEndian::read_u32(array_ref![block, 4 * i, 4]));
        }

        for i in 16..64 {
            w[i] = w[i - 16] + Sha256::ssig0(w[i - 15]) + w[i - 7] + Sha256::ssig1(w[i - 2]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for (i, item) in w.iter().enumerate() {
            let tmp1 =
                h + Sha256::bsig1(e) + Sha256::choice(e, f, g) + Wrapping(Sha256::K[i]) + *item;
            let tmp2 = Sha256::bsig0(a) + Sha256::majority(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + tmp1;
            d = c;
            c = b;
            b = a;
            a = tmp1 + tmp2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
}

impl Sha256 {
    // SHA-256 constants.
    #[allow(clippy::unreadable_literal)]
    const H: [Wrapping<u32>; 8] = [
        Wrapping(0x6a09e667),
        Wrapping(0xbb67ae85),
        Wrapping(0x3c6ef372),
        Wrapping(0xa54ff53a),
        Wrapping(0x510e527f),
        Wrapping(0x9b05688c),
        Wrapping(0x1f83d9ab),
        Wrapping(0x5be0cd19),
    ];

    #[allow(clippy::unreadable_literal)]
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    // SHA-256 helper functions.
    #[inline(always)]
    fn choice(e: Wrapping<u32>, f: Wrapping<u32>, g: Wrapping<u32>) -> Wrapping<u32> {
        (e & f) ^ (!e & g)
    }

    #[inline(always)]
    fn majority(a: Wrapping<u32>, b: Wrapping<u32>, c: Wrapping<u32>) -> Wrapping<u32> {
        (a & b) ^ (a & c) ^ (b & c)
    }

    #[inline(always)]
    fn bsig0(x: Wrapping<u32>) -> Wrapping<u32> {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn bsig1(x: Wrapping<u32>) -> Wrapping<u32> {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn ssig0(x: Wrapping<u32>) -> Wrapping<u32> {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn ssig1(x: Wrapping<u32>) -> Wrapping<u32> {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    extern crate hex;

    #[test]
    fn test_choice() {
        assert_eq!(
            Sha256::choice(
                Wrapping(0b00001111),
                Wrapping(0b00110011),
                Wrapping(0b01010101)
            ),
            Wrapping(0b01010011)
        );
    }

    #[test]
    fn test_majority() {
        assert_eq!(
            Sha256::majority(
                Wrapping(0b00001111),
                Wrapping(0b00110011),
                Wrapping(0b01010101)
            ),
            Wrapping(0b00010111)
        );
    }

    #[test]
    fn test_hash_empty() {
        assert_eq!(
            Sha256::hash(&[]),
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_update_for_various_splits() {
        // Test vector generated with the following Python script:
        //
        // import hashlib
        // print(hashlib.sha256('A' * 512).hexdigest())
        //
        let input = vec![b'A'; 512];
        let hash = hex::decode("32beecb58a128af8248504600bd203dcc676adf41045300485655e6b8780a01d")
            .unwrap();

        for i in 0..512 {
            for j in i..512 {
                let mut h = Sha256::new();
                h.update(&input[..i]);
                h.update(&input[i..j]);
                h.update(&input[j..]);
                assert_eq!(h.finalize(), hash.as_slice());
            }
        }
    }

    #[test]
    fn test_hash_for_various_lengths() {
        // This test makes sure that the padding is implemented properly.
        //
        // Test vectors generated with the following Python script:
        //
        // import hashlib
        // for n in range(128):
        //     print('b"' + hashlib.sha256('A' * n).hexdigest() + '",')
        //
        let hashes: [&[u8; 64]; 128] = [
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            b"559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",
            b"58bb119c35513a451d24dc20ef0e9031ec85b35bfc919d263e7e5d9868909cb5",
            b"cb1ad2119d8fafb69566510ee712661f9f14b83385006ef92aec47f523a38358",
            b"63c1dd951ffedf6f7fd968ad4efa39b8ed584f162f46e715114ee184f8de9201",
            b"11770b3ea657fe68cba19675143e4715c8de9d763d3c21a85af6b7513d43997d",
            b"69dc6c3210e25e62c5938ff4e841e81ce3c7d2cde583553478a77d7fcb389f30",
            b"0f0cf9286f065a2f38e3c4e4886578e35af4050c108e507998a05888c98667ea",
            b"c34ab6abb7b2bb595bc25c3b388c872fd1d575819a8f55cc689510285e212385",
            b"e5f9176ecd90317cf2d4673926c9db65475b0b58e7f468586ddaef280a98cdbd",
            b"1d65bf29403e4fb1767522a107c827b8884d16640cf0e3b18c4c1dd107e0d49d",
            b"dd20088919031875b7bcca29995545dd40ca994be0558183f9b942b51b3b2249",
            b"0592cedeabbf836d8d1c7456417c7653ac208f71e904d3d0ab37faf711021aff",
            b"3461164897596e65b79bc0b7bee8cc7685487e37f52ecf0b34c000329675b859",
            b"14f99c4b0a6493e3a3f52022cd75276b4cff9a7c8eef74793267f687b600af96",
            b"6f9f84c09a5950e1ea7888f17922a69e5292dcbcb1e682ddfc977a9b4ea1a8c0",
            b"991204fba2b6216d476282d375ab88d20e6108d109aecded97ef424ddd114706",
            b"444074d5328d52b4e0036d37b1b6ea0a9fe3b0c96872d1157fbf01b6fdb2ce8d",
            b"d273c6b6de3f5260e123348e0feb270126fa06e164bb82818df7c71b30ab0ef5",
            b"234b7f9389f9b521f407805760775940d79a48188338d02a1fe654e826a83f69",
            b"edfcaac579024f574adbcaa3c13e4fd2b7f1797826afe679f2144af2cb5c062d",
            b"f48de1653fdfa9b637b7fb4da9c169a1f2be6a1ec001e3d2cca44c669a693ecf",
            b"8a5bdb4cc15164126c6ef2668de9dd240d299ce6397a42c95a9411b93d080ed8",
            b"1786ac1492c6c922c2734e4d3d8e9b030cfba291a72bc135989c49fc31171ac2",
            b"1bda9f0aed80857d43c9329457f28b1ca29f736a0c539901e1ba16a909eb07b4",
            b"6724431fc312ba42c98b38b8595a49749419526aa89722c77a85c6c813dfdb5a",
            b"06f469c97c14e84c74853bb96aa79305eb4f6635291bf1202c4fdadb82706204",
            b"568f214d529544bf4430513c2993495a5b434611533c63d1cf095b51c5e1f8af",
            b"c84f7630cbe823fc4d80f605b98294592f15b14db1f78d6f18e686c1f8cb5ded",
            b"a7951e0ca2e9612a985a36747309822a67a9b8c1a5abd848c03e82216c85f1b3",
            b"37b9403cf88cc2639d0a118d757a43a0ff6d4871823707ab6a8bb56bc68e8e79",
            b"55ee740f58335c97d42c32125218eb7c325fbe34206912f1aa7af7fd6580c9a1",
            b"22a48051594c1949deed7040850c1f0f8764537f5191be56732d16a54c1d8153",
            b"5d873590851b7b00b60490c8e6966b3409c385adcc9590d801f0e03e268b5ba5",
            b"1e98a405718c430a4067d75125015a947a971449bc433b078418438c48bc6046",
            b"015c50632207f69408c05d20e36facfad9bde74c727f933023f54cd6e8b87372",
            b"a3b99d59dbb025726312e812c2821cfbe55189f515414bdabd5e3d284c8ad6f9",
            b"7d24c321bfb2a5b6d2c7a3c2948855cef421d08352dc296ed95c6f645fcce441",
            b"876fc5bf6bde065afea543aceb645ce17ffe3c9d8df9c6073ab31f3a562f4257",
            b"b9b515854e040b8de31d85d597aba28db4467fd0a7d6eb77a31005f4a67a8fb3",
            b"f0a2fb80ac0699075fb6c7b0ee2bcc204a1d909ee3149571216ec9cc1d4b9f8e",
            b"b78244167af116f2b3597b4a81421bd2b28f3d8bf616025a5ae424f689fd7632",
            b"d85ce644bf4e82cee032eaa5c3d9030a090276d9bae3703112bdfc6f8fdde307",
            b"0f007385b6f9d4b7eeb2748605afe1a984a0a3bfa3f014d09e2a784ce9e5cd1a",
            b"b06b3f20c246db70a136e3ae4787d0df96db4f693d215c21883d3c19700fb276",
            b"ac752ced452069c55c7567a0717b87615824c568dc98c8626ac85fc34b234c3b",
            b"91a07088de2d0fe9f31567b05d290e65feb06758d000ec463f7f5a6e82ce00a5",
            b"abf6c5d1b6512e188f1da6a72e974f7b98b5bac62453f1748c8f9ab180803fdb",
            b"4739dcdbab0c377161c539af55d47c5c90c87807d0728aabe91697b66e29096c",
            b"ff85f0693c8e6bbeeaa1f90c32e1159b9b545d830ffe58cd80cb94d9d8140d21",
            b"509ddb85fdf92f197d32570c005cdcb6dffa398f088bd1a013459f6fb1f730ef",
            b"1d31616e307323bd80775ae7483fce654a3b65bced7134c22e179a2e25155009",
            b"3e1ae21112ec8fad05e3676e1940da52d56771162142aac4d73743e7df70b686",
            b"5f2671f97427c8873e5af72686d244e4c8126a4f618983bae880a48a834a0607",
            b"2d0009d7df28cdc6b5a4c36063d97415a8fe99515317458fcb0b0e2a821dbcb9",
            b"8963cc0afd622cc7574ac2011f93a3059b3d65548a77542a1559e3d202e6ab00",
            b"6ea719cefa4b31862035a7fa606b7cc3602f46231117d135cc7119b3c1412314",
            b"a00df74fbdadd9eb0e7742a019e5b2d77374de5417eba5b7a0730a60cce5e7bf",
            b"cee244d999f8cf49f2a4ee4d89695130c9c95c33538cedf0306881ebd42714d2",
            b"5b29354ee33cba5b924ded5e3c873a76e1d12527d824ace01ff9683d24e06816",
            b"c5fb235befd875b915fa6c4702a7abb93cacf3d7c414b71cbeff9e1b0a9fbd41",
            b"0ae45129ef1edf64309559f6cb7bb0af16eff14ad82f24d55fa029c1b4144078",
            b"5a2aafcacb9828e41fb7c8f8098952638645874b3a8ca45d2523fb2d5fc7166d",
            b"1b58d00f5b1fbd2a1884d666a2be33c2fa7463dff32cd60ef200c0f750a6b70f",
            b"d53eda7a637c99cc7fb566d96e9fa109bf15c478410a3f5eb4d4c4e26cd081f6",
            b"836203944f4c0280461ad73d31457c22ba19d1d99e232dc231000085899e00a2",
            b"fd8afe9151793a84a21af054ba985d1486a705561e2a50d4a50f814664f5e806",
            b"f495547fca5a5a2c40dccebefe40160efb8bc2888e8afef712b096b5f2585b44",
            b"ba31b89f9486439fdf551f597fede0c10260f9b404866dba4a6555375f486359",
            b"46f23cc7ccba8af67978bea568e63cd045be72aba974132b1b14cc59277329f1",
            b"01d3a187638cc1a7740a74fbeb57aa2648dbdec42d497321912bf393d283ccd1",
            b"96b437b3df7c62fc877a121b087899f5e36a58f6d87ba52d997e92bb016aa575",
            b"6a6d691ac9ba70955046757cd685b6257773ff3ad93f43d4d4812c5b106f4b5b",
            b"beb869adc22a7e8fbd5af12cbf3ad36dd92dca6ebf52ef3441ed6cd0dff24dc6",
            b"0f40cb2f3661d73dfaec511e8ebea082fb1f77db45bf8c9ba7c9708da6ba6301",
            b"ddd5d1ecc7af6a5b0d18e0825004d3bc9d52e2cdf14bc00c7474f16941a64acc",
            b"6a10b9a8a33d7814ce73679ace5c43657aa6d63169ce215fd85177c77a94147d",
            b"9d887d47c78267827dac4afb2cbdcc593d1b89c1d0c1f22c3800cae7916962cd",
            b"e45ca598e970afb0f1f57bd34e87065839d2fac524421048fbec489f68e1fd0d",
            b"1581baebc5f9dcfd89c658b3c3303203fc0e2f93e3f9e0b593d8b2b8112c6eda",
            b"d9b1f3e2c6d528668a73f22575c44ed9f98d9c684964761b621417efd80d7a60",
            b"9feacd760dfda20e5e0accf9ddeb8b5c01276a56dc3518046a26f5276fe15041",
            b"6aacf5279e24979684fab16fb5495c3ac1dfcf7138b0825376af83473d07cae9",
            b"cd2f0deb953014ee400eddef094602d9676e0fd2269d22818f0d5bc198d44d8d",
            b"ff9265df14681e44d170fd2b10c6cdf3991f731601d6b89cafe39691d3b42559",
            b"6c99e32b005a3a4956b9406ab15411e666c7f67982db170ae1fb111ec634b9c4",
            b"e1659ad54063a379f77fee108a376a6a7d5ae3d0c437bf847203963bd0078dfc",
            b"572d07a66fccf05d5f73c913552e12d9ffb39a15d01a8fd48cd6aaaab86f4f14",
            b"ca97d312ef8551820844548f300f9528f27d53f6ad3910ed2709f2b35c9591f3",
            b"97654dc78f4f7d4cec4b4870e6ee0a87abacc89337ed0629e2e511e4466df56d",
            b"fde923c1ed5e5cd32c629bdf341db32c0f72ba8f1e2afd9c194e87e0e3d9da5f",
            b"d6624a66f3bcc4adef8a17abf9eeb1fbf23746165b2f90f9cb3a679a58e4958e",
            b"8676909e9578a790f84be31fe94f4d22488f912b754ee816ba0a5c4a392305a5",
            b"57f65fd8a95ff738b95dba0f1606025535e34591f1b58b00d33958093808360c",
            b"f6afcaf794fe0e04d6ec18bbde55412a60c0c5ef55e75223b817e97f208bbccc",
            b"6121f27b52c1f17ddce365143ba58a720fa303707faa32a4e5e89029f34ac618",
            b"69d62c062d67d8d2ce9068c1898fb9746c911839aa88ad1628d090f4c8e47f05",
            b"eb9f8b69313e19e14b1043b3cac05d18d40321536ad485be8145007aefa9295d",
            b"b1cfb0f511886ca07ade919740ca95e1b3d998ba7cb66ba2badd53be28f5f509",
            b"d0118863549f990558685da9090ca8eae8c809c5545c4aa85f8e5eec413b2555",
            b"d82c6aa133a0fc25b087f46ad7ed2a3042772e612e015571e61753ff55ba6da8",
            b"aac76dab773c00c8ad4bb128147945c70798eae5a2511fef01e853c6e3051ab9",
            b"ccd77d7adb6178ee3e3560ba4583044a36b296257ae4c5cfead96d46af31fccd",
            b"3c4f48a886b2de7e908d6a626074e7515265cc9d1188c161cf159fd376d3d5f8",
            b"7f9578a31905e95a16cc9d3e7b57dc3158a23dccf359a1f2cf09e73eb13e5cde",
            b"770492ebaee89a20d19f9972c3e3d0c7d51c9baaedf06fdfe9a7b69da3394779",
            b"893785aaddea396621c31dc5d465e2775cbc6b7423dc3498e80aa5da7a6a819d",
            b"1b2b69fbec485ef3f347ee6dc9c87d73505e45b5c9b02599b823ac94f5d642a1",
            b"724b4b3d3e8ac7588561ca00eec11693f6b85c03bb6b1302d458a7a4ce4b39e4",
            b"6a30ef4094128b6fa463b70cb21d141da92711d80ea94c9b73fb8a0471cc49a9",
            b"50968cf735e3f6a47834ae3745816234f72fd156aef1bec4b6a7d3a3151773bc",
            b"3ed01dd816dc93ea2d445681df11aa24e9fd1441de429eb0ee7816ccc09a2b7a",
            b"64bdc48c731313c7b37c1f1d13d6265ac7a2604ff630b50f591a86e610cb3005",
            b"96666c386cf99a74ec9eb55a5545aa90a3e53a8bbbe74cd3334b32d4968a3214",
            b"33555a41335654a29d5b7799bf180915e09095d21991dacf071583957b9e3f35",
            b"ffd391d554ce0672ae818a149dd55325f4cb933c97017b8148934474355d5a88",
            b"cf2050114ccaefd8a0ea6cf31d85e0232eadc8fd61277ff16496d2234b55c7d7",
            b"e42142b4243d5a2c59a2977d0385d49eab288085f8d38ead3ae5d87145c562ec",
            b"3bb810492422cc5c7466d86dcd8095b0d87e97634656a3fa5fe2270a2244c16b",
            b"17d2f0f7197a6612e311d141781f2b9539c4aef7affd729246c401890e000dde",
            b"a4f4256159ea6fb23b27eb8c5eb9cfb9083475985f355a85c78de8f2fef2b3ac",
            b"a36c4cf85204c67047c00d5dcc16677978839af0f0fde7ff973c98b66e244552",
            b"4a596559f450ce5e3a777d952d8d2ed8611e9f3facc8400483371f6eadc4bdb2",
            b"64855e54c94d14ab53afc6109d3c0033c665fab85b57c0e7d4e8da55b3b26952",
            b"a2ee2228d4798988ce3ac273c0cd8b9bbc4e3e58413eb22dfbe6395758659a2b",
            b"35c28ee2e25f5ad70384f1ca9723f520c955fb5fe9f2e56b9dc809479a9ca8cc",
            b"da3f6a7f55f821760330dd14495e68e7d153b05e472d38459d4728d63ad9df26",
            b"026134f6117e45a37c5c2dc2f330bdd274c6dc087526b91ecec4d6dac9bb7346",
        ];

        let mut input = Vec::new();
        for i in 0..128 {
            assert_eq!(
                Sha256::hash(&input),
                hex::decode(hashes[i] as &[u8]).unwrap().as_slice()
            );
            input.push(b'A');
        }
    }

    // TODO: more tests
}
