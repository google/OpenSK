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
use subtle::ConstantTimeEq;

const BLOCK_SIZE: usize = 64;
const HASH_SIZE: usize = 32;

pub fn verify_hmac_256<H>(key: &[u8], contents: &[u8], mac: &[u8; HASH_SIZE]) -> bool
where
    H: Hash256 + HashBlockSize64Bytes,
{
    let expected_mac = hmac_256::<H>(key, contents);
    bool::from(expected_mac.ct_eq(mac))
}

// FIDO2's PIN verification is just matching the first 16 bytes of the HMAC
// against the pin ¯\_(ツ)_/¯
pub fn verify_hmac_256_first_128bits<H>(key: &[u8], contents: &[u8], pin: &[u8; 16]) -> bool
where
    H: Hash256 + HashBlockSize64Bytes,
{
    let expected_mac = hmac_256::<H>(key, contents);
    bool::from(array_ref![expected_mac, 0, 16].ct_eq(pin))
}

pub fn hmac_256<H>(key: &[u8], contents: &[u8]) -> [u8; HASH_SIZE]
where
    H: Hash256 + HashBlockSize64Bytes,
{
    let mut ipad: [u8; BLOCK_SIZE] = [0x36; BLOCK_SIZE];
    let mut opad: [u8; BLOCK_SIZE] = [0x5c; BLOCK_SIZE];
    if key.len() <= BLOCK_SIZE {
        xor_pads(&mut ipad, &mut opad, key);
    } else {
        xor_pads(&mut ipad, &mut opad, &H::hash(key));
    }

    let mut ihasher = H::new();
    ihasher.update(&ipad);
    ihasher.update(contents);
    let ihash = ihasher.finalize();

    let mut ohasher = H::new();
    ohasher.update(&opad);
    ohasher.update(&ihash);

    ohasher.finalize()
}

fn xor_pads(ipad: &mut [u8; BLOCK_SIZE], opad: &mut [u8; BLOCK_SIZE], key: &[u8]) {
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
}

#[cfg(test)]
mod test {
    use super::super::sha256::Sha256;
    use super::*;
    extern crate hex;

    #[test]
    fn test_verify_hmac_valid() {
        // Test for various lengths of the key and contents.
        for len in 0..128 {
            let key = vec![0; len];
            let contents = vec![0; len];
            let mac = hmac_256::<Sha256>(&key, &contents);
            assert!(verify_hmac_256::<Sha256>(&key, &contents, &mac));
        }
    }

    #[test]
    fn test_verify_hmac_invalid() {
        // Test for various lengths of the key and contents.
        for len in 0..128 {
            let key = vec![0; len];
            let contents = vec![0; len];
            let mac = hmac_256::<Sha256>(&key, &contents);

            // Check that invalid MACs don't verify, by changing any byte of the valid MAC.
            for i in 0..HASH_SIZE {
                let mut bad_mac = mac;
                bad_mac[i] ^= 0x01;
                assert!(!verify_hmac_256::<Sha256>(&key, &contents, &bad_mac));
            }
        }
    }

    #[test]
    fn test_hmac_sha256_empty() {
        let mut buf = [0; 96];
        buf[..64].copy_from_slice(&[0x5c; 64]);
        buf[64..].copy_from_slice(&Sha256::hash(&[0x36; 64]));
        assert_eq!(hmac_256::<Sha256>(&[], &[]), Sha256::hash(&buf));
    }

    #[test]
    fn test_hmac_sha256_examples() {
        assert_eq!(
            hmac_256::<Sha256>(&[], &[]),
            hex::decode("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad")
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            hmac_256::<Sha256>(b"key", b"The quick brown fox jumps over the lazy dog"),
            hex::decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_hash_sha256_for_various_lengths() {
        // This test makes sure that the key hashing and hash padding are implemented properly.
        //
        // Test vectors generated with the following Python script:
        //
        // import hashlib
        // import hmac
        // for n in range(128):
        //     print('b"' + hmac.new('A' * n, 'A' * n, hashlib.sha256).hexdigest() + '",')
        //
        let hashes: [&[u8; 64]; 128] = [
            b"b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
            b"ff333794c5afd126a4e75aef1a35595a846e9e1d4053017d78d7aa3d8373182a",
            b"7c1d0c177d40e7fa03cd1fa9cfc314888985aecde8f586edfb05e71e5f109c20",
            b"8f7afbaef39ad155ba09bcbb386a08257731fc06fb2c1d3cff451af5386c0e7d",
            b"a4dbd2915084ba3bed9306ba674c1eb22fae1dffd971c95b62ab17f0711480cd",
            b"f59d521db107b4265d995f197b189de468b984816d2a01dc8ca3fcfc24d6ff37",
            b"29e0656a90f3975e41c8b7e55d225353c3bb8bc0b36328c8066a61763df70b83",
            b"25a85cdd13b683f3cac732fa1f19757afffe7013ddbea6e441af883379bf4232",
            b"5d0b0812ecb57fb4be7f29a8978cc4f2c35b32417cc9854e2702f7fb08f6d84d",
            b"d5e12df428ebd9d991a280c714c9197b977520a7fea87200177cf03618868cb3",
            b"fa311e0cd19106ab33f8ee84cafdc2f03be787679c1fe7b6e64df2b2e7466ca2",
            b"9a481f04a2f40d561e8e6c4850498699b36e915993153e9f9b5a4485cb0541b1",
            b"c8ae9a117e3a5c9125cc21c7f9df09de50de1a6846caf13586d1e5efdfcc1ce6",
            b"5ef3a488aaffb5db9173ef59e65c2dd27f4cd1a10e1b464ef5bf82d2e35eddd5",
            b"e5753e8febbb38a97c1dfee23a6103fc58416b7172bab834fe5684b00800abd5",
            b"0ed714c729a3db2ffde2c4ccb9f5da498c5a73a2c7010d463a7b5da8d18127aa",
            b"950918cfdb0cb20f327ba0b5095d53c0befb66b9f639d389020453fcf18e8c40",
            b"699470b9775ec45e9024394e7ebb16463534ed7a617bafddca11a3a0e61a3694",
            b"95e8c0520fc4dc4c85e00e3868c16ab22a82e8c71ca8ea329ae1ecef0ee3968a",
            b"7964fba6a123164167cbf51dc2c53948e13b2fee67d09f532e8b7bc56447c091",
            b"c7d07a5f715b3ea44c258de03f2000ba79a44dd8213feb6e6006e1c3becbedff",
            b"3eb1a7bf7e4f5c2d9b8cc12667ada8d7773cb9e9424104a30063778567df9422",
            b"19cc344ad67db96ea936ef15cc751b29fa0409f5c9894d2cfeb100d604653ffc",
            b"91001e472df16d68ee8033cd13d76a26543ccdfe1426cc6e969759b05ee7d115",
            b"65f1f4670f8537f37263dabedce049b0e7d1e71f741781413cc2d5c81ecd6ac3",
            b"0cf5de0ada8b717296a34fc386a8b77f60b607a48a899bee37650891a616dae7",
            b"de3d56f0c83c992163aac087c999ed8eb5a039f21b0536a1967e747868dafd56",
            b"0bc3fd1d46d2dc4e2d357d1f6b437d168051d6f19975223505fc2d0abddc3faa",
            b"1e30596f4144ca58f3e306548cd079cc92a51ab825a4ad3246393c22283af640",
            b"c2fbc726bf3eb7f0216c7e1d5f5b475a93b033b3f901a4a4dca6bbefc65b68b2",
            b"1c4ef56d530bb8b627df49ea7b31cf9520e067a2fd0c671896103e146dd4564a",
            b"9aeed0f7808bd6c13ce54aa5724484f41bd7cbb5e39fd1d7730befbbf056a957",
            b"e58aa85e83553b7fec841cbaf42cede943b6b7ded22661cd3b1867effe91b745",
            b"790fc5689193ac57c97dd25729003f2a0d8d3e5f9d2a39e007b794282a51cd3e",
            b"be067b95a45cdc0060d2c3757597d8d9b858128435e93346c28ce2e82a68e951",
            b"8734f497f5cd2c8667c7d8e1c2328e7e11fa80fc26c7d933937490d37718871f",
            b"e8a2d0e77dfad5b046bcff0340a975300b051a21ac403dd802348511a80ba8c8",
            b"4afec38787117ab6e71c34a4be7575643d8e74fc16b9d5666157fd9aee0f6e86",
            b"ac8b2831d636384d1d3ff5dd77b249860bd88d5aa9af3e1d4ee70be2a1b03db9",
            b"e92e1ab3934d3ed2073973204aaba03de3bc4e864cc74677b560c42971b26ab1",
            b"312effff0c19cf410b9e227654211133f29276c781baadbe00a1e8319e06e361",
            b"d46158da3c64439f8f176fd5e3d5ac59dcaa6c0835715c5ef30abedf34b13c59",
            b"693d18266ec508515b9a3839e5336918d41ec7891feadd684b49c03093bd2061",
            b"440b6a14be7bc2a1ec475a197fe4bea720d1214883e4d1e2029cf0f75fcdba29",
            b"ca8e30319508df21a851a06f543f59bf6fd3b241e5a52b36fb674b0d9d5e8f67",
            b"fa4f327635ff5c7051d6968daf5ffcc827bbd0da1e1c56d59918895bc418be98",
            b"0e6d0dd75bc42aa6e245a212ff027bc701a7ef61179b335365a29f545bcf45e0",
            b"57a08bef7822c2111ac79062240e725611322543f10758763c1c6467021c4fe7",
            b"29768d5fb640a46e0129303128669eb3c7fb357ef1c49506f6300cc8e451d5e2",
            b"009a868f1065ccb4227dc28084484263495ad90378dc928fc61d361eef2d072e",
            b"6808e39e343af0fd53309fc02b05da1a0e68b87d5cd434e94521c635a78d7fdb",
            b"8fe1668eba03be5444e0956396ac9d81ac1c4a7beb6a01151ad679f5ca0cd206",
            b"01f41c1cc6d9d260ec3d938d681fc476415aae96a318862a492ba1a56f1b0a88",
            b"3100bc758eeccb959376b334f999a2b4e5fcced5b5d4956510a86b654f1f0c04",
            b"6225330aedced9909d4a190dba55e807624f44e7c6e0c50cac5e4ccf8e2e0029",
            b"783111276f7218e3e525c83cdf117e2d5ce251f6a04beabb65ef565f513a9301",
            b"4b365ab05720ad517f46df03ff441f9e0769a2ce5279663b7d90eb7d980625ef",
            b"52431871c39a881c63df82860e32ccf05c1addbc630aaa580733f2e6a2fff5a6",
            b"f017486486b0e308a10862e910f22545c29670daa26bf0c6791827a7f9f625a4",
            b"85efd1eface951759a4642e882d0ef8d0be58afd483e0945d03a7a35fac789ac",
            b"880872df19c7ff14105ba59cebc07d9e9d7e67f4896a14acae5346c66c6ce2da",
            b"85ba2aa3634c619d604a964d62ae3c97f9eba7fcb7e4db2ebfa2bd23338c2d60",
            b"5aa9736d405016676878fcc63e84b286cfbc843799ea786d089b2200281d5a5c",
            b"30f43d84f3d5ffac60323a126fe321c6cc1e9c440249a8d69abe172494cba7ae",
            b"7dce62ce40f8f4cda666341730e7dfcde8839eed4236c58ae273e6687d229d85",
            b"83d670a41779f63fad0ece766a19920e0cfdd9d02f5a5900c888de21f6ae0526",
            b"bb2acf0d6d39e58b09204dedcc2fe68ad829ba471a077e6e03246d8a0b0c0858",
            b"1f94db9ee970a9fcc9089865eb2aa485765345f6d4de54815507ce363bc20711",
            b"b4bceedc935c574935117f7ad280a7d858da7ca5a6b0920b4975111206fcac77",
            b"b9da394c337e9aa150c12e54c574978773ff953270f5aefde88a766e9874c260",
            b"1769fcb5d31c8c09868e4e3dcd9db92b4cccefb5660e72bfc52159fda9da8518",
            b"d8ceb568f85e30cb48cabf8e84d577369033511cbbdac6a7996cf9f397c2e203",
            b"64c35795b87cbb02afcdc6a5e6bacb10d98cdd1bd810ccf12c847fbdcf4d2634",
            b"76ccd4e2b71a826128b60bc9fe33613d82f0ae1f57fa192f107ed54d25a842e0",
            b"095450e0f61a4201bb2197371247bb7ced09056d86e901202ecc561c3568e032",
            b"0e928f8e201fd3019f11037bf164cc3d719ecf08e6eac985f429702c41f25d0a",
            b"135f37174ff19409cef67f3263511ed9286901090eec2b54d9444036308a72cf",
            b"51eafe6978c32396022a31230b8b9120ac7bd79ad7a3303e6b6979063275c9b8",
            b"fd2fb9443156429b2bc042248bf022f18ee6ed11fefea222893c49e8fef6a17e",
            b"ed9a240e63644aa55c71fb339d79e1a38de71002c30baf14af38359c513de2e0",
            b"c925e74d4740558277a55fe57ba88ed05ce8f5d5c35c19e7228adc09351ecfa4",
            b"cd99660a7c2aded095152bc6d5fa160077355819fbf421acb95ab39ad8c27862",
            b"42cf7593a535a1e79299c2839f4e0ffba5b429cb0df6c77d3fe86b6a1535d505",
            b"348c6014dcb0cd583862c09ad24aa5d93e81e2f6ca4b04f4e77e50067f34e625",
            b"8b00c1d89bd10b24bda2c8f6e45c4112112baacab29d0330b377d811a7b0184e",
            b"dfe3960732f8e5958085a581859f6ccf40169df965bb8ff5feb4b0229a02c6f8",
            b"de0aa4189c97d17df38c0ea3bc9376287076939afd515336d5d7d851f81f2517",
            b"543190454858ff5396a1de3f753f84bdd2869fd2b59e3a89f090ce06bd94d626",
            b"541ddbe00a0237c5c8bd043e6cced9ce78209dd83b057272cd46c2cc2f39a88c",
            b"11c82017445f7e295d4c734a40cf28793df855dd321d507d4a0f3e212293ca2b",
            b"cda1ecd6ca2f3858352985b4833170589e17e1f7f464e279cc78051911b8e8d3",
            b"5feb471949318b26898b3339ac7a66e464a752223cf764aa0af9292fe087c39a",
            b"eb48e5de63ecd22f7b305c7e74ce8cc714ab858cf834cf485727868e017e473e",
            b"03428482b5208a35032777c7d628a6c8f3b07c5c87c641ddfb3adf46ffefe449",
            b"a8e0cd1dfcf6e1a29ba032d3889fca2f25e3fad1a9b1c36e4978e48945b06092",
            b"6cf4280b75da3bb22ddee9a9a3fdd1d0cd04627c00f73b608e44be9ce84869db",
            b"9fa7648f23c405938b6fb8eaf6a24c476dafd05625a9a8f6c52e1abb9d432a76",
            b"2906f0a6276e9a1ba4fbca2f335d9f7d3c331684814ac5407145d86891ba37f7",
            b"1b667ee18a909e3f828f2bd6a162e3aa1361f3801b7cbc863b1b54a1ccfbf580",
            b"a75e75962b3f950f7718839ef06cc09112806dbf88b142e369cf1ef99069c226",
            b"71b2e2f6d66f13b919a842843b201c25249ff4b4caa4c7ab079b2980de8a18f6",
            b"c4a9e73df196f876f5a3af1c8836504ee61daac5d9e15cc043a511310c22ddd8",
            b"88e3303a6a2ab03430652fea942ae7cd96618fae4addcf8e92989d542777e496",
            b"9a727095299564e2f5e1598f1a4095a2a000cb9196fe4eb13447932af777be3c",
            b"5643a1c72b189d462236a43afc7d0b9504cbf81b4fa9a6c9cca49bd50da299df",
            b"caebc47e2204fe19e757372c2e0469a34051415a09c927e63be7747903d80af5",
            b"e5c9fd4bd27e7a55958cb5f66ff88baf80ab40d9690e81a9cf03ada5bd08cd44",
            b"dc606eb9a631ca3f080f6d6f610444201608f47b5b49c75c2c0ec03ba9000009",
            b"bce230b32a7dc676fb98a4a3d41c4171e9e173e840b92c194fb1dc4accc079b9",
            b"51542ff3b57cd2ff6b1542649f7a44dbed32194b98c3af32b6ff3eefe6b490cf",
            b"703f5dea8c9e3ed75c691fc17699b9648a65a331add554fa3613ddcb7267565a",
            b"d74f9f60763467ce0b35ced0630ecf58605da0ca49e058de21524b5c532b5de8",
            b"e9dacaf1fefaad6d9d372affab8fb5216004fb3fa7a9b86b25ecd00e583c22a5",
            b"abe2c75f1ac881b743da99c543506c4b7532f3fc445fa8cbf1df22689770d66a",
            b"7be506d2fd6dc79f0b14ddfff0147c79d78d99140547efcd03d0a73819b84c5a",
            b"78dbc5c946ee8aa147ccfa8b5d9231c95c4257d8c79bd219ab95d53303367309",
            b"1d75ee600f2ba216d211189493d793aa610aa57ccbfc4d9a7f44194e7166a062",
            b"368a4d0ae1b139d71f35ba5f917a7ad4c18e6aa51b095cb135193dcd09e299b4",
            b"a9d3202db927be8f0d15d2dfb83ea09db32fec3b1fc10a6acfb91da8c3c5eaf3",
            b"c2284f8efeee554cc29a8802aadd7cd88e84561d353282ee31322ed497a3336c",
            b"7695648a111e2ea51013f03c9de91d81a2435a7777f303e51d027750f8381680",
            b"719fc44e0f64f7da9ac5d33d9ca912fdc839bb4535c66a21f0804f2cdf800666",
            b"6940c082413b0c1ced6f9cb6583588c472ff72b48b00a4fb6d2710d7ac4dad99",
            b"af1f26fcf070d9f5926dd41db3c09ec6b4c3f2208775cf983330cd0ff5aa239e",
            b"ae50df4404a7f46146d8112bfb1cde876e591abe5ef1640e27c4d178a84b6335",
            b"50f91f48df7f0f96af954be7e1b518bac537173cea38be300d98761da1d9b10f",
            b"9c9aee382b3e3417e87352bdcb48837e88335e9dd0112fc22ecf61e766a6ac43",
            b"d53cee1696c613f988520cf9c923c7cb6e6933b4faf57e640867d5f45a0f2569",
        ];

        let mut input = Vec::new();
        for i in 0..128 {
            assert_eq!(
                hmac_256::<Sha256>(&input, &input),
                hex::decode(hashes[i] as &[u8]).unwrap().as_slice()
            );
            input.push(b'A');
        }
    }

    // TODO: more tests
}
