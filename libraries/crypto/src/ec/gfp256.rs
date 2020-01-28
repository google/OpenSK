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

use super::int256::{Digit, Int256};
use core::ops::Mul;
use subtle::Choice;

// A field element on the elliptic curve, that is an element modulo the prime P.
// This is the format used to serialize coordinates of points on the curve.
// This implements enough methods to validate points and to convert them to/from the Montgomery
// form, which is more convenient to operate on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GFP256 {
    int: Int256,
}

impl GFP256 {
    pub const ZERO: GFP256 = GFP256 { int: Int256::ZERO };
    pub const ONE: GFP256 = GFP256 { int: Int256::ONE };
    pub const B: GFP256 = GFP256 { int: Int256::B };
    pub const R: GFP256 = GFP256 { int: Int256::R };
    pub const R_INV: GFP256 = GFP256 { int: Int256::R_INV };

    /** Constructors **/
    pub fn from_int_checked(int: Int256) -> Option<GFP256> {
        if bool::from(int.ct_lt(&Int256::P)) {
            Some(GFP256 { int })
        } else {
            None
        }
    }

    /** Helpful getters **/
    pub fn to_int(self) -> Int256 {
        self.int
    }

    fn is_zero(&self) -> Choice {
        self.int.is_zero()
    }

    /** Arithmetic **/
    pub fn mul_top(&self, other: &Int256, other_top: Digit) -> GFP256 {
        GFP256 {
            int: Int256::modmul_top(&self.int, other, other_top, &Int256::P),
        }
    }

    /** Point validation **/
    // Verify that all of the following are true:
    // * y^2 == x^3 - 3x + b mod p
    // * 0 < x < p
    // * 0 < y < p
    //
    // Not constant time.
    pub fn is_valid_point_vartime(x: &GFP256, y: &GFP256) -> bool {
        if bool::from(x.is_zero()) || bool::from(y.is_zero()) {
            return false;
        }

        // y^2
        let y2 = y * y;

        // x^3
        let x2 = x * x;
        let x3 = &x2 * x;

        // x^3 - 3x + b
        let mut xx = x3;
        xx = xx.sub_vartime(x);
        xx = xx.sub_vartime(x);
        xx = xx.sub_vartime(x);
        xx = xx.add_vartime(&GFP256::B);

        xx == y2
    }

    /** Arithmetic operators **/
    fn add_vartime(self, other: &GFP256) -> GFP256 {
        GFP256 {
            int: Int256::modadd_vartime(&self.int, &other.int, &Int256::P),
        }
    }

    fn sub_vartime(self, other: &GFP256) -> GFP256 {
        GFP256 {
            int: Int256::modsub_vartime(&self.int, &other.int, &Int256::P),
        }
    }
}

/** Arithmetic operators **/
impl Mul for &GFP256 {
    type Output = GFP256;

    fn mul(self, other: &GFP256) -> GFP256 {
        GFP256 {
            int: Int256::modmul(&self.int, &other.int, &Int256::P),
        }
    }
}

#[cfg(feature = "derive_debug")]
impl core::fmt::Debug for GFP256 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "GFP256::{:?}", self.int)
    }
}

#[cfg(test)]
mod test {
    use super::super::montgomery::Montgomery;
    use super::*;
    use core::ops::{Add, Sub};

    const P_MIN_1_INT: Int256 = Int256::new([
        0xfffffffe, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
        0xffffffff,
    ]);

    fn get_test_values() -> Vec<GFP256> {
        let mut values: Vec<GFP256> = Montgomery::PRECOMPUTED
            .iter()
            .flatten()
            .flatten()
            .map(|x| x.montgomery_to_field())
            .collect();
        values.extend(
            super::super::int256::test::get_1bit_one_test_values()
                .iter()
                .filter_map(|&x| GFP256::from_int_checked(x)),
        );
        values.extend(
            super::super::int256::test::get_1bit_zero_test_values()
                .iter()
                .filter_map(|&x| GFP256::from_int_checked(x)),
        );
        values.push(GFP256::ZERO);
        values.push(GFP256::ONE);
        values.push(GFP256::B);
        values
    }

    /** Arithmetic operators, only for tests as these are not constant time **/
    impl Add for &GFP256 {
        type Output = GFP256;

        fn add(self, other: &GFP256) -> GFP256 {
            self.add_vartime(other)
        }
    }

    impl Sub for &GFP256 {
        type Output = GFP256;

        fn sub(self, other: &GFP256) -> GFP256 {
            self.sub_vartime(other)
        }
    }

    /** Constructors **/
    #[test]
    fn test_from_int_checked() {
        assert_eq!(
            GFP256::from_int_checked(Int256::ZERO),
            Some(GFP256 { int: Int256::ZERO })
        );
        assert_eq!(
            GFP256::from_int_checked(Int256::ONE),
            Some(GFP256 { int: Int256::ONE })
        );
        assert_eq!(
            GFP256::from_int_checked(P_MIN_1_INT),
            Some(GFP256 { int: P_MIN_1_INT })
        );
        assert_eq!(GFP256::from_int_checked(Int256::P), None);
    }

    /** Point validation **/
    // See point.rs

    /** Arithmetic operators **/
    // Due to the 3 nested loops, this test is super slow with debug assertions enabled.
    #[cfg(not(debug_assertions))]
    #[test]
    fn test_add_is_associative() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                for z in &get_test_values() {
                    assert_eq!(&(x + y) + z, x + &(y + z));
                }
            }
        }
    }

    #[test]
    fn test_add_is_commutative() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                assert_eq!(x + y, y + x);
            }
        }
    }

    #[test]
    fn test_add_sub() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                assert_eq!(&(x - y) + y, *x);
                assert_eq!(&(x + y) - y, *x);
            }
        }
    }

    // Due to the 3 nested loops, this test is super slow with debug assertions enabled.
    #[cfg(not(debug_assertions))]
    #[test]
    fn test_mul_is_associative() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                for z in &get_test_values() {
                    assert_eq!(&(x * y) * z, x * &(y * z));
                }
            }
        }
    }

    #[test]
    fn test_mul_is_commutative() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                assert_eq!(x * y, y * x);
            }
        }
    }

    // Due to the 3 nested loops, this test is super slow with debug assertions enabled.
    #[cfg(not(debug_assertions))]
    #[test]
    fn test_mul_is_distributive() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                for z in &get_test_values() {
                    assert_eq!(&(x + y) * z, &(x * z) + &(y * z));
                }
            }
        }
    }
}
