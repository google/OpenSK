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

use super::montgomery::{Montgomery, NLIMBS};

pub const PRECOMPUTED: [[[Montgomery; 2]; 15]; 2] = [
    [
        [
            Montgomery::new(PRECOMPUTED_LIMBS[0]),
            Montgomery::new(PRECOMPUTED_LIMBS[1]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[2]),
            Montgomery::new(PRECOMPUTED_LIMBS[3]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[4]),
            Montgomery::new(PRECOMPUTED_LIMBS[5]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[6]),
            Montgomery::new(PRECOMPUTED_LIMBS[7]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[8]),
            Montgomery::new(PRECOMPUTED_LIMBS[9]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[10]),
            Montgomery::new(PRECOMPUTED_LIMBS[11]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[12]),
            Montgomery::new(PRECOMPUTED_LIMBS[13]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[14]),
            Montgomery::new(PRECOMPUTED_LIMBS[15]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[16]),
            Montgomery::new(PRECOMPUTED_LIMBS[17]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[18]),
            Montgomery::new(PRECOMPUTED_LIMBS[19]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[20]),
            Montgomery::new(PRECOMPUTED_LIMBS[21]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[22]),
            Montgomery::new(PRECOMPUTED_LIMBS[23]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[24]),
            Montgomery::new(PRECOMPUTED_LIMBS[25]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[26]),
            Montgomery::new(PRECOMPUTED_LIMBS[27]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[28]),
            Montgomery::new(PRECOMPUTED_LIMBS[29]),
        ],
    ],
    [
        [
            Montgomery::new(PRECOMPUTED_LIMBS[30]),
            Montgomery::new(PRECOMPUTED_LIMBS[31]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[32]),
            Montgomery::new(PRECOMPUTED_LIMBS[33]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[34]),
            Montgomery::new(PRECOMPUTED_LIMBS[35]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[36]),
            Montgomery::new(PRECOMPUTED_LIMBS[37]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[38]),
            Montgomery::new(PRECOMPUTED_LIMBS[39]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[40]),
            Montgomery::new(PRECOMPUTED_LIMBS[41]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[42]),
            Montgomery::new(PRECOMPUTED_LIMBS[43]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[44]),
            Montgomery::new(PRECOMPUTED_LIMBS[45]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[46]),
            Montgomery::new(PRECOMPUTED_LIMBS[47]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[48]),
            Montgomery::new(PRECOMPUTED_LIMBS[49]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[50]),
            Montgomery::new(PRECOMPUTED_LIMBS[51]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[52]),
            Montgomery::new(PRECOMPUTED_LIMBS[53]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[54]),
            Montgomery::new(PRECOMPUTED_LIMBS[55]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[56]),
            Montgomery::new(PRECOMPUTED_LIMBS[57]),
        ],
        [
            Montgomery::new(PRECOMPUTED_LIMBS[58]),
            Montgomery::new(PRECOMPUTED_LIMBS[59]),
        ],
    ],
];

#[rustfmt::skip]
#[allow(clippy::unreadable_literal)]
const PRECOMPUTED_LIMBS: [[u32; NLIMBS]; 60] = [
[0x11522878, 0x0e730d41, 0x0db60179, 0x04afe2ff, 0x12883add, 0x0caddd88, 0x119e7edc, 0x0d4a6eab, 0x03120bee],
[0x1d2aac15, 0x0f25357c, 0x19e45cdd, 0x05c721d0, 0x1992c5a5, 0x0a237487, 0x0154ba21, 0x014b10bb, 0x00ae3fe3],
[0x0d41a576, 0x0922fc51, 0x0234994f, 0x060b60d3, 0x164586ae, 0x0ce95f18, 0x1fe49073, 0x03fa36cc, 0x05ebcd2c],
[0x0b402f2f, 0x015c70bf, 0x1561925c, 0x05a26704, 0x0da91e90, 0x0cdc1c7f, 0x1ea12446, 0x0e1ade1e, 0x0ec91f22],
[0x026f7778, 0x0566847e, 0x0a0bec9e, 0x0234f453, 0x1a31f21a, 0x0d85e75c, 0x056c7109, 0x0a267a00, 0x0b57c050],
[0x0098fb57, 0x0aa837cc, 0x060c0792, 0x0cfa5e19, 0x061bab9e, 0x0589e39b, 0x00a324c5, 0x07d6dee7, 0x02976e4b],
[0x1fc4124a, 0x0a8c244b, 0x1ce86762, 0x0cd61c7e, 0x1831c8e0, 0x075774e1, 0x1d96a5a9, 0x0843a649, 0x0c3ab0fa],
[0x06e2e7d5, 0x07673a2a, 0x178b65e8, 0x04003e9b, 0x1a1f11c2, 0x007816ea, 0x0f643e11, 0x058c43df, 0x0f423fc2],
[0x19633ffa, 0x0891f2b2, 0x123c231c, 0x046add8c, 0x054700dd, 0x059e2b17, 0x172db40f, 0x083e277d, 0x0b0dd609],
[0x0fd1da12, 0x035c6e52, 0x19ede20c, 0x0d19e0c0, 0x097d0f40, 0x0b015b19, 0x0449e3f5, 0x00e10c9e, 0x033ab581],
[0x056a67ab, 0x0577734d, 0x1dddc062, 0x0c57b10d, 0x0149b39d, 0x026a9e7b, 0x0c35df9f, 0x048764cd, 0x076dbcca],
[0x0ca4b366, 0x0e9303ab, 0x1a7480e7, 0x057e9e81, 0x1e13eb50, 0x0f466cf3, 0x06f16b20, 0x04ba3173, 0x0c168c33],
[0x15cb5439, 0x06a38e11, 0x073658bd, 0x0b29564f, 0x03f6dc5b, 0x0053b97e, 0x1322c4c0, 0x065dd7ff, 0x03a1e4f6],
[0x14e614aa, 0x09246317, 0x1bc83aca, 0x0ad97eed, 0x0d38ce4a, 0x0f82b006, 0x0341f077, 0x0a6add89, 0x04894acd],
[0x09f162d5, 0x0f8410ef, 0x1b266a56, 0x00d7f223, 0x03e0cb92, 0x0e39b672, 0x06a2901a, 0x069a8556, 0x0007e7c0],
[0x09b7d8d3, 0x00309a80, 0x1ad05f7f, 0x0c2fb5dd, 0x0cbfd41d, 0x09ceb638, 0x1051825c, 0x0da0cf5b, 0x0812e881],
[0x06f35669, 0x06a56f2c, 0x1df8d184, 0x00345820, 0x1477d477, 0x01645db1, 0x0be80c51, 0x0c22be3e, 0x0e35e65a],
[0x1aeb7aa0, 0x0c375315, 0x0f67bc99, 0x07fdd7b9, 0x191fc1be, 0x0061235d, 0x02c184e9, 0x01c5a839, 0x047a1e26],
[0x0b7cb456, 0x093e225d, 0x14f3c6ed, 0x0ccc1ac9, 0x17fe37f3, 0x04988989, 0x1a90c502, 0x02f32042, 0x0a17769b],
[0x0afd8c7c, 0x08191c6e, 0x1dcdb237, 0x016200c0, 0x107b32a1, 0x066c08db, 0x10d06a02, 0x0003fc93, 0x05620023],
[0x16722b27, 0x068b5c59, 0x0270fcfc, 0x0fad0ecc, 0x0e5de1c2, 0x0eab466b, 0x02fc513c, 0x0407f75c, 0x0baab133],
[0x09705fe9, 0x0b88b8e7, 0x0734c993, 0x01e1ff8f, 0x19156970, 0x0abd0f00, 0x10469ea7, 0x03293ac0, 0x0cdc98aa],
[0x01d843fd, 0x0e14bfe8, 0x15be825f, 0x008b5212, 0x0eb3fb67, 0x081cbd29, 0x0bc62f16, 0x02b6fcc7, 0x0f5a4e29],
[0x13560b66, 0x0c0b6ac2, 0x051ae690, 0x0d41e271, 0x0f3e9bd4, 0x01d70aab, 0x01029f72, 0x073e1c35, 0x0ee70fbc],
[0x0ad81baf, 0x09ecc49a, 0x086c741e, 0x0fe6be30, 0x176752e7, 0x0023d416, 0x1f83de85, 0x027de188, 0x066f70b8],
[0x181cd51f, 0x096b6e4c, 0x188f2335, 0x0a5df759, 0x17a77eb6, 0x0feb0e73, 0x154ae914, 0x02f3ec51, 0x03826b59],
[0x0b91f17d, 0x01c72949, 0x1362bf0a, 0x0e23fddf, 0x0a5614b0, 0x000f7d8f, 0x00079061, 0x0823d9d2, 0x08213f39],
[0x1128ae0b, 0x0d095d05, 0x0b85c0c2, 0x01ecb2ef, 0x024ddc84, 0x0e35e901, 0x18411a4a, 0x0f5ddc3d, 0x03786689],
[0x052260e8, 0x05ae3564, 0x0542b10d, 0x08d93a45, 0x19952aa4, 0x0996cc41, 0x1051a729, 0x04be3499, 0x052b23aa],
[0x109f307e, 0x06f5b6bb, 0x1f84e1e7, 0x077a0cfa, 0x10c4df3f, 0x025a02ea, 0x0b048035, 0x0e31de66, 0x0c6ecaa3],
[0x028ea335, 0x02886024, 0x1372f020, 0x00f55d35, 0x15e4684c, 0x0f2a9e17, 0x1a4a7529, 0x0cb7beb1, 0x0b2a78a1],
[0x1ab21f1f, 0x06361ccf, 0x06c9179d, 0x0b135627, 0x1267b974, 0x04408bad, 0x1cbff658, 0x0e3d6511, 0x00c7d76f],
[0x01cc7a69, 0x0e7ee31b, 0x054fab4f, 0x002b914f, 0x1ad27a30, 0x0cd3579e, 0x0c50124c, 0x050daa90, 0x00b13f72],
[0x0b06aa75, 0x070f5cc6, 0x1649e5aa, 0x084a5312, 0x0329043c, 0x041c4011, 0x13d32411, 0x0b04a838, 0x0d760d2d],
[0x1713b532, 0x0baa0c03, 0x084022ab, 0x06bcf5c1, 0x02f45379, 0x018ae070, 0x18c9e11e, 0x020bca9a, 0x066f496b],
[0x03eef294, 0x067500d2, 0x0d7f613c, 0x002dbbeb, 0x0b741038, 0x0e04133f, 0x1582968d, 0x0be985f7, 0x01acbc1a],
[0x1a6a939f, 0x033e50f6, 0x0d665ed4, 0x0b4b7bd6, 0x1e5a3799, 0x06b33847, 0x17fa56ff, 0x065ef930, 0x0021dc4a],
[0x02b37659, 0x0450fe17, 0x0b357b65, 0x0df5efac, 0x15397bef, 0x09d35a7f, 0x112ac15f, 0x0624e62e, 0x0a90ae2f],
[0x107eecd2, 0x01f69bbe, 0x077d6bce, 0x05741394, 0x13c684fc, 0x0950c910, 0x0725522b, 0x0dc78583, 0x040eeabb],
[0x1fde328a, 0x0bd61d96, 0x0d28c387, 0x09e77d89, 0x12550c40, 0x0759cb7d, 0x0367ef34, 0x0ae2a960, 0x091b8bdc],
[0x093462a9, 0x00f469ef, 0x0b2e9aef, 0x0d2ca771, 0x054e1f42, 0x007aaa49, 0x06316abb, 0x02413c8e, 0x05425bf9],
[0x1bed3e3a, 0x0f272274, 0x1f5e7326, 0x06416517, 0x0ea27072, 0x09cedea7, 0x006e7633, 0x07c91952, 0x0d806dce],
[0x08e2a7e1, 0x0e421e1a, 0x0418c9e1, 0x01dbc890, 0x1b395c36, 0x0a1dc175, 0x1dc4ef73, 0x08956f34, 0x0e4b5cf2],
[0x1b0d3a18, 0x03194a36, 0x06c2641f, 0x0e44124c, 0x0a2f4eaa, 0x0a8c25ba, 0x0f927ed7, 0x0627b614, 0x07371cca],
[0x0ba16694, 0x0417bc03, 0x07c0a7e3, 0x09c35c19, 0x1168a205, 0x08b6b00d, 0x10e3edc9, 0x09c19bf2, 0x05882229],
[0x1b2b4162, 0x0a5cef1a, 0x1543622b, 0x09bd433e, 0x0364e04d, 0x07480792, 0x05c9b5b3, 0x0e85ff25, 0x0408ef57],
[0x1814cfa4, 0x0121b41b, 0x0d248a0f, 0x03b05222, 0x039bb16a, 0x0c75966d, 0x0a038113, 0x0a4a1769, 0x011fbc6c],
[0x0917e50e, 0x0eec3da8, 0x169d6eac, 0x010c1699, 0x0a416153, 0x0f724912, 0x15cd60b7, 0x04acbad9, 0x05efc5fa],
[0x0f150ed7, 0x00122b51, 0x1104b40a, 0x0cb7f442, 0x0fbb28ff, 0x06ac53ca, 0x196142cc, 0x07bf0fa9, 0x00957651],
[0x04e0f215, 0x0ed439f8, 0x03f46bd5, 0x05ace82f, 0x110916b6, 0x006db078, 0x0ffd7d57, 0x0f2ecaac, 0x0ca86dec],
[0x15d6b2da, 0x0965ecc9, 0x1c92b4c2, 0x001f3811, 0x1cb080f5, 0x02d8b804, 0x19d1c12d, 0x0f20bd46, 0x01951fa7],
[0x0a3656c3, 0x0523a425, 0x0fcd0692, 0x0d44ddc8, 0x131f0f5b, 0x0af80e4a, 0x0cd9fc74, 0x099bb618, 0x02db944c],
[0x0a673090, 0x01c210e1, 0x178c8d23, 0x01474383, 0x10b8743d, 0x0985a55b, 0x02e74779, 0x00576138, 0x09587927],
[0x133130fa, 0x0be05516, 0x09f4d619, 0x0bb62570, 0x099ec591, 0x0d9468fe, 0x1d07782d, 0x0fc72e0b, 0x0701b298],
[0x1863863b, 0x085954b8, 0x121a0c36, 0x09e7fedf, 0x0f64b429, 0x09b9d71e, 0x14e2f5d8, 0x0f858d3a, 0x0942eea8],
[0x0da5b765, 0x06edafff, 0x0a9d18cc, 0x0c65e4ba, 0x1c747e86, 0x0e4ea915, 0x1981d7a1, 0x08395659, 0x052ed4e2],
[0x087d43b7, 0x037ab11b, 0x19d292ce, 0x0f8d4692, 0x18c3053f, 0x08863e13, 0x04c146c0, 0x06bdf55a, 0x04e4457d],
[0x16152289, 0x0ac78ec2, 0x1a59c5a2, 0x02028b97, 0x071c2d01, 0x0295851f, 0x0404747b, 0x0878558d, 0x07d29aa4],
[0x13d8341f, 0x08daefd7, 0x139c972d, 0x06b7ea75, 0x0d4a9dde, 0x0ff163d8, 0x081d55d7, 0x0a5bef68, 0x0b7b30d8],
[0x0be73d6f, 0x0aa88141, 0x0d976c81, 0x07e7a9cc, 0x18beb771, 0x0d773cbd, 0x13f51951, 0x09d0c177, 0x01c49a78],
];

#[cfg(test)]
mod test {
    use super::super::montgomery::{BOTTOM_28_BITS, BOTTOM_29_BITS};
    use super::super::point::test::{power_of_two, precomputed};
    use super::super::point::PointProjective;
    use super::*;

    #[test]
    fn test_precomputed_bits() {
        for x in PRECOMPUTED_LIMBS.iter() {
            for (i, &limb) in x.iter().enumerate() {
                if i & 1 == 0 {
                    assert_eq!(limb & BOTTOM_29_BITS, limb);
                } else {
                    assert_eq!(limb & BOTTOM_28_BITS, limb);
                }
            }
        }
    }

    #[test]
    fn test_precomputed_powers_of_g_are_correct() {
        let gen = PointProjective::from_affine(&precomputed(0, 0));
        let g32 = power_of_two(gen, 32);
        let g64 = power_of_two(gen, 64);
        let g96 = power_of_two(gen, 96);
        let g128 = power_of_two(gen, 128);
        let g160 = power_of_two(gen, 160);
        let g192 = power_of_two(gen, 192);
        let g224 = power_of_two(gen, 224);

        assert_eq!(
            PointProjective::from_affine(&precomputed(0, 0b0001 - 1)),
            gen
        );
        assert_eq!(
            PointProjective::from_affine(&precomputed(0, 0b0010 - 1)),
            g64
        );
        assert_eq!(
            PointProjective::from_affine(&precomputed(0, 0b0100 - 1)),
            g128
        );
        assert_eq!(
            PointProjective::from_affine(&precomputed(0, 0b1000 - 1)),
            g192
        );
        assert_eq!(
            PointProjective::from_affine(&precomputed(1, 0b0001 - 1)),
            g32
        );
        assert_eq!(
            PointProjective::from_affine(&precomputed(1, 0b0010 - 1)),
            g96
        );
        assert_eq!(
            PointProjective::from_affine(&precomputed(1, 0b0100 - 1)),
            g160
        );
        assert_eq!(
            PointProjective::from_affine(&precomputed(1, 0b1000 - 1)),
            g224
        );
    }

    #[test]
    fn test_precomputed_table_0_is_correct() {
        let gen = PointProjective::from_affine(&precomputed(0, 0));
        let g64 = power_of_two(gen, 64);
        let g128 = power_of_two(gen, 128);
        let g192 = power_of_two(gen, 192);

        for i in 1..16 {
            let mut x = PointProjective::INFINITY;
            if i & 1 != 0 {
                x = &x + &gen;
            }
            if i & 2 != 0 {
                x = &x + &g64;
            }
            if i & 4 != 0 {
                x = &x + &g128;
            }
            if i & 8 != 0 {
                x = &x + &g192;
            }
            assert_eq!(PointProjective::from_affine(&precomputed(0, i - 1)), x);
        }
    }

    #[test]
    fn test_precomputed_table_1_is_correct() {
        let gen = PointProjective::from_affine(&precomputed(0, 0));
        let g32 = power_of_two(gen, 32);
        let g96 = power_of_two(gen, 96);
        let g160 = power_of_two(gen, 160);
        let g224 = power_of_two(gen, 224);

        for i in 1..16 {
            let mut x = PointProjective::INFINITY;
            if i & 1 != 0 {
                x = &x + &g32;
            }
            if i & 2 != 0 {
                x = &x + &g96;
            }
            if i & 4 != 0 {
                x = &x + &g160;
            }
            if i & 8 != 0 {
                x = &x + &g224;
            }
            assert_eq!(PointProjective::from_affine(&precomputed(1, i - 1)), x);
        }
    }
}
