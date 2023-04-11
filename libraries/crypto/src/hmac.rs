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

use super::Hash256;
use arrayref::array_ref;
use subtle::ConstantTimeEq;

const BLOCK_SIZE: usize = 64;
const HASH_SIZE: usize = 32;
const KEY_SIZE: usize = 32;

pub fn verify_hmac_256<H>(key: &[u8; KEY_SIZE], contents: &[u8], mac: &[u8; HASH_SIZE]) -> bool
where
    H: Hash256,
{
    let mut expected_mac = [0; HASH_SIZE];
    hmac_256::<H>(key, contents, &mut expected_mac);
    bool::from(expected_mac.ct_eq(mac))
}

// FIDO2's PIN verification is just matching the first 16 bytes of the HMAC
// against the pin ¯\_(ツ)_/¯
pub fn verify_hmac_256_first_128bits<H>(
    key: &[u8; KEY_SIZE],
    contents: &[u8],
    pin: &[u8; 16],
) -> bool
where
    H: Hash256,
{
    let mut expected_mac = [0; HASH_SIZE];
    hmac_256::<H>(key, contents, &mut expected_mac);
    bool::from(array_ref![expected_mac, 0, 16].ct_eq(pin))
}

pub fn hmac_256<H>(key: &[u8; KEY_SIZE], contents: &[u8], output: &mut [u8; HASH_SIZE])
where
    H: Hash256,
{
    H::hmac_mut(key, contents, output)
}

pub(crate) fn software_hmac_256<H>(
    key: &[u8; KEY_SIZE],
    contents: &[u8],
    output: &mut [u8; HASH_SIZE],
) where
    H: Hash256,
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
    let mut ihash = [0; HASH_SIZE];
    ihasher.finalize(&mut ihash);

    let mut ohasher = H::new();
    ohasher.update(&opad);
    ohasher.update(&ihash);
    ohasher.finalize(output);
}

fn xor_pads(ipad: &mut [u8; BLOCK_SIZE], opad: &mut [u8; BLOCK_SIZE], key: &[u8; KEY_SIZE]) {
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
}

#[cfg(test)]
mod test {
    use super::super::sha256::Sha256;
    use super::*;

    #[test]
    fn test_verify_hmac_valid() {
        // Test for various lengths of the contents.
        for len in 0..128 {
            let key = [0; KEY_SIZE];
            let contents = vec![0; len];
            let mut mac = [0; HASH_SIZE];
            hmac_256::<Sha256>(&key, &contents, &mut mac);
            assert!(verify_hmac_256::<Sha256>(&key, &contents, &mac));
        }
    }

    #[test]
    fn test_verify_hmac_invalid() {
        // Test for various lengths of the contents.
        for len in 0..128 {
            let key = [0; KEY_SIZE];
            let contents = vec![0; len];
            let mut mac = [0; HASH_SIZE];
            hmac_256::<Sha256>(&key, &contents, &mut mac);

            // Check that invalid MACs don't verify, by changing any byte of the valid MAC.
            for i in 0..HASH_SIZE {
                let mut bad_mac = mac;
                bad_mac[i] ^= 0x01;
                assert!(!verify_hmac_256::<Sha256>(&key, &contents, &bad_mac));
            }
        }
    }

    #[test]
    fn test_hmac_sha256_examples() {
        let key = [0; KEY_SIZE];
        let mut mac = [0; HASH_SIZE];
        hmac_256::<Sha256>(&key, &[], &mut mac);
        assert_eq!(
            mac,
            hex::decode("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad")
                .unwrap()
                .as_slice()
        );
        hmac_256::<Sha256>(
            &key,
            b"The quick brown fox jumps over the lazy dog",
            &mut mac,
        );
        assert_eq!(
            mac,
            hex::decode("fb011e6154a19b9a4c767373c305275a5a69e8b68b0b4c9200c383dced19a416")
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
        //     print('b"' + hmac.new(b'A' * 32, b'A' * n, hashlib.sha256).hexdigest() + '",')
        //
        let hashes: [&[u8; 64]; 128] = [
            b"595a67cdd155b156011323818105d3d30cf8f6aad916685c0b2d1d7b7678b728",
            b"bfa8ad8ba9fe1e03dd80d3f3d782a9f5b66c387619e0dd836f4ea6187324ea66",
            b"7c5e78ab04692eec81140cdaebeb53f2caeda32815e34de8f92ea85c1a716b83",
            b"79f8fe074d9aa04e8e1aaaaa9170f8f990fa008db94d9a81e796904e4a4b69f3",
            b"6177f1d2208d33a3f255d569dc5e3388909376e291d574db4b2fe22dfc5b0027",
            b"57e164845ea82912bc162a99adf7c010d416a57cb619d79b1a916904c934b4c8",
            b"5a76f2ace99b5a61418f986e96c695179c4f02f44e00b0bba2a09daa7b53a4ab",
            b"ab392ef07ec6cdc33c86676cf58760087e136dad0ba6d3490c58e7797e313a88",
            b"018c06f8a2377d97ec955c6c2f06c937e66f97bec3101c40f039f8a1832fadc3",
            b"ef423b7ad8137e4e473252975570733cc6eb2780a4ca257cca7b592742548fe3",
            b"fed8c0e7daee2292841e2868a64e298a58f2438a9a14040999f0634cdb084c5f",
            b"4d645a6631328b2b09e7f50b4ee2e5630bec786e156ea6a2b827332d320e8f4b",
            b"b45d9d059b2b298b417bac0fa77ad66a8e771ada054b7131469c949550ded9be",
            b"47f6a1af667d49804b2f5917eb8b7de5cdb245670b6b9ad2ed9b2a21c2dbf0f7",
            b"dde1e7b53136a4bf72ed8640f4384805e923028da301b313f9aa475a6a1d38ca",
            b"fd53a20c62b18dccd079779f4fd2abefdf212838d68999140e0335d0500da3d9",
            b"1afdf50cc2c65a4eb6f643e8107dd4e06defde40d495b68783fa2d8b41f291d3",
            b"9d2b266b013dae3e0eb83be634fe0095eed403518d4bcff69e050cb59a20e0c9",
            b"d4ac6b4df53b7d0848a9d17984c555cf660482c3c1e86f5662279b108a0831f1",
            b"d1c3bc071da981b822b428771b7c21dc47d3cd868a5058a5e7d463c2fedc457e",
            b"dfe01e48ce8ae53b04c17b48287501b1e8e85f23c1d1a77e0000967dae16926c",
            b"ce31a2972842dc9d28c8c4e10963280bebb468fa14739d2d09d9063018521bb0",
            b"3390e5ea00fc447a1ba27784dfbc30cf62dc6fbd3af2347b85efa9ecf086db41",
            b"3f4f678e5b5d6b5ec5d8afe53da6904eb9e755e20a685eafcf163ea703043a7f",
            b"2fbd3730b3c5d0c647940f1405ee3761fdd9adb2ed10dd40524454bc1c5af019",
            b"fa675e4ea585f8c96c5ded7651d6d3a80c26161c28c73bf94cc2b93e43413658",
            b"0667a9ea56759ed908dd9e1ac46a8221abebb95f29b0749fd555707181a4af16",
            b"9dd330116d5750abfdfc7cee9f65db0360a94bf0d10fbe55d572e4f55c4c7cea",
            b"afd9c1e6ba141502a100311eb5a25f5078baa2bc9fbccb1fe3b0fc6daebfc6d3",
            b"bc2610c0e8c11dab2bf62ea2613265e9821d762e037bc6dd9ea4fd7955c88205",
            b"ab982b8c3395535f0835e0b212c20b67cc914db4e72c10f5b6214602d9a88a1d",
            b"8ebf970da05e08f54a39ecccf2d6afcf497c79c42c8a7c9c49d30f3316ff1581",
            b"e58aa85e83553b7fec841cbaf42cede943b6b7ded22661cd3b1867effe91b745",
            b"e4d991ec7a6e440b4ba447533f3154aaf4b98970aab17e51abbfc77ac6a9534e",
            b"c6c63e02951aa085d146efe270b4ebfc76bcd02a78086cbc236d04a08226c0a1",
            b"2891cc2b22d90da4dc2d7c4c8261d0419c39af278837b51b31a03d7433e9fefb",
            b"6a0c557d141cc6e2b3584d72dadeeae7ffdeb26661239715f414ea4d5bcbea61",
            b"ca82fea127dd876b595fd0ba90b2a38316946f65f05459091ddff1e9b7a5ee42",
            b"17c7b6db39bffa4600b0b4d3e14b2a664ae706a2ecfdaec5dbc2d3e07066ab6b",
            b"f65b1220142355c27df2a1e0f6f9755f7eb708646bad3b901b93d7fb32c8854f",
            b"2fe2e14d87053873cfa2f366320a62e1bdd3b3a56bec8939ac354b3ca2122719",
            b"909bbb93030313552e70abe519508bac3b5da2e04a7e87fa9bd74ca50bf3ff95",
            b"bc89b946a874fc3bdfcc70b01459e34eeaa1fe3ca50283be8678e06a98686ba8",
            b"de2468c21ca31e3e13e8a0cc685c7d52a73e22c90a6af72d572624277190e2ea",
            b"129379e4a0436dc85dab57fae14cb67cdbb808f911439a76de2ed987c7ed192a",
            b"d475c697a8792de00daa493eb24708ebc058686ace04e7406b7ff351dd4f2f01",
            b"728d210061d0e057d56bff712b9540f9d2c453f8766ad8990ae114f5527840b7",
            b"b0afbb7f1cc27233f08d74d06dbd1d85d3c68dd608dd4bcfea59c17a4cfa8002",
            b"077264c42786ba2803fa0d1b91eb45cd0cda3cfc28d3e12724050a7f0c236f43",
            b"727f3497843430636157f3d8b158a1a95318e9a85a98c50e549c1f17dc915d50",
            b"e17d3f5bfc328ab0ba2a0fc433f2bf46f8b28aa20d171f0de76f61c7741a1edd",
            b"80f61fc10cecc7a0ddb3e8e73f3c8900db0f1e9a45feba67e94e648353613cd3",
            b"6e84e742f4f0aa32da9034f404a609a490b6756e90deb3f6a6697e60698575e5",
            b"6ff3cdb270fe53f835d7be0320954d75125532f7774c5f3d515a5235f1e4cb77",
            b"b839681cadf03857f44d2b75d1ea702335b7fccd391ba48b6895b8859017eb40",
            b"404de6d3cdff8254b92a00a2b053ff4fd054e44447822c4865803a810301e1d4",
            b"759ce4ff23e6f79957fc53c9ea7b014dd8874e6daab3751b81c80ccf7208cce0",
            b"861c419860787f09021fdda2a66023662c9d27b00efb3c637f0dd2da709d5cfe",
            b"cac14f0cbe893fa214646e5b33d110318dcc9bf39789df7c7dbb86b7adf49d23",
            b"b2ed80ab57e54e7d68f40085adc346e01cc80d43d4c38efdbf99e646752a3e34",
            b"ea9e89716c7d62a0467db829f95e35171c414fc6a62e4ecb84086b137c0c87fe",
            b"a745acf53cb1efcfaae1d54a41a9b7109ce40e45b66899f43e84582a7d382652",
            b"96f4eff4f9a556509efc5a5fe6aa7e76abfd322a04096dee1013582a4f50e9c3",
            b"8d5cb04fe1685f1adca6db900744ce95496a69250d5e902526f113adde4230d7",
            b"787139d46676f1e9ba999008b747d6100d4d2d43c4a03da55b70c96e0e5a2b82",
            b"72e1658437cc6640b8a2107a0d0025ee2a9efeeec4ce0fa54f8aee27b500a90c",
            b"9715f4cd4c2612088a688a3c74c4743f567e1b10697a89832edee851167109a5",
            b"acf69295af3cbb198fab03ba0ceb0d6bd9f7592551d93ed025203f4b1125f5d2",
            b"79bab68ef25af25bd903fecc691ad03a3f5011b38876cc576f8bbac72648a675",
            b"078f2cd62dfc38eae5e5b4f31a6f226b53326a5e6e879190a5761375858e40b5",
            b"ad7b8a91191ca66df520104bf694f6300e02a3217f06524c5f5f2314259b688e",
            b"743810642997b9c59e254d9c26e0c419a94b9ede285c282e09a2544c24678c7c",
            b"731845f6bc49160f38bd15d50b5e8e9fabb015b6d47faafb701c68c39add3192",
            b"2f48b9d618f0ee7edb50b095e76dd1b69c2c12e77036ee76b1ac3fbf08f93bde",
            b"3c7a74c98330454f0c16b35697c81e33ac5c2c75404dde607f5ee9d43775201b",
            b"a36bd2c560abac0f80a261c30ac0e51ffb953daf616a2063fab57d140866a7f3",
            b"ba8fa68ef326ca68e30e55dfd10a706f8cb9dc159562e5e34529075215e78f3c",
            b"1a6e95178d9d86cdad770c5b17dbbe833bcd7c61701cec5938c6838dc77a988d",
            b"8a51d9eb445154c95c9274bc664f3db10b336fa3b1ea7f0a83e057444235db91",
            b"b89372d7f8f5595033a0758eb6442f136d0e66943b28717e9f851d72a69f60a3",
            b"165ed7cd7a3cf8304c861ccd5b5218a419d677bf5c54ae9ad41e0f8be76b83c7",
            b"9df5023a48caf3eead86b65b302ef412d2eeefdbbd1e764cd0e920086498cda8",
            b"0873f1f4f4c02e6a0edb9efa1129afb05660aaa83b24f99032553d8b9843a52c",
            b"5444a87785495cfe0d355c7a7f1836d4199b823d9d907c414b6be9b379638490",
            b"7a4c2867b2da2f2f24285f4ee2af2f553b0be7c82d67ab147513e66f185b0b6f",
            b"a21e41f5dbc69c6135def7f16694a6ac3a18d4063004084c52fee187501310e2",
            b"25e316dcedb6d826fd0c37d2376b8fbfbe95f20b3fcbd255985a0c3a63d05099",
            b"e2b71db388fdb675739b84791b432783f9bd4127d15692af80febec991c3ba90",
            b"f73cd2ba0a6cea09bc8c67fb39d4c66096bc26087ab2c8713944e61f167a4dff",
            b"2b3da7f3a41dd9a3d205278c0e5a5c2870f231129bdb249e0a4858996c446de2",
            b"ab0128c1519894e37dd0e69f5503149d17e94a1c0da830f988a206f02d7572ff",
            b"c3ca55ac522cdf4f92bdf57851f88ec257612e3a2b8639b06fb067fb7b1d6ec6",
            b"f7012c61df429af15f4f450d78c6d384345b1317a8a7befe1ec32bc31e169f0b",
            b"608679c2a6724c47a5341bb4775687492b5f17f3e6bbbf0f928d4f840ff487e3",
            b"1c55e5588e2f46291bf19b93c2f54f8e0f1ec1dc01c25dbb30102ce5d97048a8",
            b"90fccc4c44f678f30e8ea525ff1c63bac72e1ff237ef0e5a5e86be51c172d9cf",
            b"2a2f95fa5d73cd8f0fc9383c8a7d709099f0afbf710b26a96982e040927d79dc",
            b"479bdb6e248e3d9049a1eaaf8014c132c90b086b42d5d552e8fd03c6d0663420",
            b"ab7ccfcb8f819dae979872ce6f2592f3d8286940673367e127207fc4cc4a1f75",
            b"2f94d599f7ade79ca64fede6125f3fbf179a0da35fdfbed722a8771ff89b8f72",
            b"ab3b6c4946c6726cfed836d7675c63d015805727ae6c28deccd7fb42a44fddcd",
            b"d7e20cb59054732eb500d97417c24a08a67dbe5cbe3754cc2bd172b97c524986",
            b"710bc8668e43f019926f063a311d20e9bd50a17eb957098535115aded9a98b47",
            b"c08d6dccc3d600106fe28a2a4460c47b7c07e89ce6a1eb5d50835da1c38be9eb",
            b"01ce3c0fa8a4c5dc09301605e9e35fb33cbec95b05d28c9e49f0ec2606cfa89d",
            b"007dc1f7341d657df8cd8534b20d6ef5dd1692ccaf139e4b4efc63f832fca8ab",
            b"646a9a878f54c25af962493b1ad029995300d27343f682a2cee20273070dba27",
            b"73afb6201bb8c76183a43d0ed528fd2b150834def3a5b7ae4f225399b35ece3b",
            b"ba3a060e0e8b8b3052d18bba4db50ec8efb0b4d292d98c150bee71fdcf7d1998",
            b"c8c7db9ee462f60d656b32b7f61e95aa241f82333e8fc6a5b6444bf6650a3f30",
            b"5f50baf9b5454484eae8149100fdbd8442583a37ab2f0482c0ccff1fa37a33a1",
            b"4b784ddc1420627929f964e6dee12c1bbefb38c9cfaadf23bedf3a5ae0485ca5",
            b"5d415fb628585f178cdbdb055c37115094701466d0bbf5c7ecd180c51901d53c",
            b"82d3a99503290b09b3e592585e1e645a6adad45e5c6686a2614e498e2a10cecf",
            b"89eb30892cda11de7b05e43eac51aeae3f8f0df1f9c87be908a98ef50e1f9cb4",
            b"d7eebda26d41e3fe126aa37e430aef38f0a845029e83bc65a9b058a82d8d4977",
            b"5eaacda4a7f19c5a1098a3ed77ac4a7bf392e9e75b2e42f494466c31fbd3a0a9",
            b"ef660208fb6a737f66ad34d6265e15e85c757a82386927ec9b706efe157e1cb9",
            b"73c2b6e65017b32e45584adc1c4c6bdb0f7a0ca3d244519f0fc25c8f0a751e29",
            b"422eda482fe7068ff4127d2d5380a6a78901024284a78ea2a8d8ef32a9ee4771",
            b"b806ee79d7b4056f5e5b34d125c5b2af9048c353628fea3b6695bda1ec48ee9b",
            b"99028cba5d078e7189034725092f5a09f193fe2ab39f949e5c0d2ea19c635283",
            b"b58bb0c9281e7a07505ddc822d5c956f13bff612b6e18eef83c8833755bcd648",
            b"d48b15936aeab4dc79807591759a3c73143a22f1c0318b6d59b641522aeec5ef",
            b"96eadb7be9c75902be80616521e48ce906bb4c56586b9b8bb9736f4542f8ab4f",
            b"a72c6ab48bbd76d235c44984f77ad480c67cde8d4ab65fbf08f326e098855ec8",
            b"49664a5bc96cc6d02eb00f3d7a40872cd355860a11baa28b69383bbbcdbf8deb",
            b"cc912109318ac8e0a78a6c8d67805094f060cd410df843b7fe69f5b187439dbc",
        ];

        let mut input = Vec::new();
        let key = [b'A'; KEY_SIZE];
        let mut mac = [0; HASH_SIZE];
        for i in 0..128 {
            hmac_256::<Sha256>(&key, &input, &mut mac);
            assert_eq!(mac, hex::decode(hashes[i] as &[u8]).unwrap().as_slice());
            input.push(b'A');
        }
    }

    // TODO: more tests
}
