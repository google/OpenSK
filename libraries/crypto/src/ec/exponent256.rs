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

use super::super::rng256::Rng256;
use super::int256::{Digit, Int256};
use core::ops::Mul;
use subtle::{self, Choice, ConditionallySelectable, CtOption};

// An exponent on the elliptic curve, that is an element modulo the curve order N.
#[derive(Clone, Copy, PartialEq, Eq)]
// TODO: remove this Default once https://github.com/dalek-cryptography/subtle/issues/63 is
// resolved.
#[derive(Default)]
#[cfg_attr(feature = "derive_debug", derive(Debug))]
pub struct ExponentP256 {
    int: Int256,
}

impl ConditionallySelectable for ExponentP256 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            int: Int256::conditional_select(&a.int, &b.int, choice),
        }
    }
}

impl ExponentP256 {
    /** Constructors **/
    pub fn from_int_checked(int: Int256) -> CtOption<ExponentP256> {
        CtOption::new(ExponentP256 { int }, int.ct_lt(&Int256::N))
    }

    #[cfg(test)]
    // Normally the ExponentP256 type guarantees that its values stay in [0, N[ because N is the
    // curve order and therefore exponents >= N are equivalent to their reduction modulo N.
    // This unsafe function is only used in tests to check that N is indeed the curve order.
    pub unsafe fn from_int_unchecked(int: Int256) -> ExponentP256 {
        ExponentP256 { int }
    }

    pub fn modn(int: Int256) -> ExponentP256 {
        ExponentP256 {
            int: int.modd(&Int256::N),
        }
    }

    /** Helpful getters **/
    pub fn bit(&self, i: usize) -> Digit {
        self.int.bit(i)
    }

    pub fn to_int(self) -> Int256 {
        self.int
    }

    pub fn is_zero(&self) -> subtle::Choice {
        self.int.is_zero()
    }

    pub fn non_zero(self) -> CtOption<NonZeroExponentP256> {
        CtOption::new(NonZeroExponentP256 { e: self }, !self.is_zero())
    }

    /** Arithmetic **/
    pub fn mul_top(&self, other: &Int256, other_top: Digit) -> ExponentP256 {
        ExponentP256 {
            int: Int256::modmul_top(&self.int, other, other_top, &Int256::N),
        }
    }
}

/** Arithmetic operators **/
impl Mul for &ExponentP256 {
    type Output = ExponentP256;

    fn mul(self, other: &ExponentP256) -> ExponentP256 {
        ExponentP256 {
            int: Int256::modmul(&self.int, &other.int, &Int256::N),
        }
    }
}

// A non-zero exponent on the elliptic curve.
#[derive(Clone, Copy, PartialEq, Eq)]
// TODO: remove this Default once https://github.com/dalek-cryptography/subtle/issues/63 is
// resolved.
#[derive(Default)]
#[cfg_attr(feature = "derive_debug", derive(Debug))]
pub struct NonZeroExponentP256 {
    e: ExponentP256,
}

impl ConditionallySelectable for NonZeroExponentP256 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            e: ExponentP256::conditional_select(&a.e, &b.e, choice),
        }
    }
}

impl NonZeroExponentP256 {
    /** RNG **/
    // Generates a uniformly distributed element 0 < k < N
    pub fn gen_uniform<R>(r: &mut R) -> NonZeroExponentP256
    where
        R: Rng256,
    {
        loop {
            let x = Int256::gen_uniform_256(r);
            if bool::from(Int256::N_MIN_2.ct_lt(&x)) {
                continue;
            }
            // At this point, x <= n - 2.
            // We add 1 so that 0 < result < n.
            return NonZeroExponentP256 {
                e: ExponentP256 { int: (&x + 1).0 },
            };
        }
    }

    /** Constructors **/
    pub fn from_int_checked(int: Int256) -> CtOption<NonZeroExponentP256> {
        ExponentP256::from_int_checked(int)
            .and_then(|e| CtOption::new(NonZeroExponentP256 { e }, !e.is_zero()))
    }

    /** Helpful getters **/
    pub fn to_int(self) -> Int256 {
        self.e.to_int()
    }

    pub fn as_exponent(&self) -> &ExponentP256 {
        &self.e
    }

    /** Arithmetic **/
    // Compute the inverse modulo N. This uses Fermat's little theorem for constant-timeness.
    pub fn inv(&self) -> NonZeroExponentP256 {
        NonZeroExponentP256 {
            e: ExponentP256 {
                int: self.e.int.modpow(&Int256::N_MIN_2, &Int256::N),
            },
        }
    }

    #[cfg(test)]
    fn inv_vartime(&self) -> NonZeroExponentP256 {
        NonZeroExponentP256 {
            e: ExponentP256 {
                int: self.e.int.modinv_vartime(&Int256::N),
            },
        }
    }
}

/** Arithmetic operators **/
impl Mul for &NonZeroExponentP256 {
    type Output = NonZeroExponentP256;

    // The product of two non-zero elements is also non-zero, because the curve order N is prime.
    fn mul(self, other: &NonZeroExponentP256) -> NonZeroExponentP256 {
        NonZeroExponentP256 {
            e: &self.e * &other.e,
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::super::montgomery::Montgomery;
    use super::*;
    use crate::util::ToOption;

    const ZERO: ExponentP256 = ExponentP256 { int: Int256::ZERO };
    const ONE: NonZeroExponentP256 = NonZeroExponentP256 {
        e: ExponentP256 { int: Int256::ONE },
    };
    const N_MIN_1_INT: Int256 = Int256::new([
        0xfc632550, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0x00000000,
        0xffffffff,
    ]);
    const N_MIN_1: NonZeroExponentP256 = NonZeroExponentP256 {
        e: ExponentP256 { int: N_MIN_1_INT },
    };

    fn get_nonzero_test_values() -> Vec<NonZeroExponentP256> {
        let mut values: Vec<NonZeroExponentP256> = Montgomery::PRECOMPUTED
            .iter()
            .flatten()
            .flatten()
            .map(|x| {
                ExponentP256::modn(x.montgomery_to_field().to_int())
                    .non_zero()
                    .unwrap()
            })
            .collect();
        values.extend(
            super::super::int256::test::get_nonzero_test_values()
                .iter()
                .filter_map(|&x| {
                    let y = ExponentP256::modn(x).non_zero();
                    if bool::from(y.is_some()) {
                        Some(y.unwrap())
                    } else {
                        None
                    }
                }),
        );
        values.push(ONE);
        values
    }

    pub fn get_test_values() -> Vec<ExponentP256> {
        let mut values: Vec<ExponentP256> = get_nonzero_test_values()
            .iter()
            .map(|x| *x.as_exponent())
            .collect();
        values.push(ZERO);
        values
    }

    /** Constructors **/
    #[test]
    fn test_from_int_checked() {
        assert_eq!(
            ExponentP256::from_int_checked(Int256::ZERO).to_option(),
            Some(ExponentP256 { int: Int256::ZERO })
        );
        assert_eq!(
            ExponentP256::from_int_checked(Int256::ONE).to_option(),
            Some(ExponentP256 { int: Int256::ONE })
        );
        assert_eq!(
            ExponentP256::from_int_checked(N_MIN_1_INT).to_option(),
            Some(ExponentP256 { int: N_MIN_1_INT })
        );
        assert_eq!(ExponentP256::from_int_checked(Int256::N).to_option(), None);
    }

    #[test]
    fn test_modn() {
        assert_eq!(
            ExponentP256::modn(Int256::ZERO),
            ExponentP256 { int: Int256::ZERO }
        );
        assert_eq!(
            ExponentP256::modn(Int256::ONE),
            ExponentP256 { int: Int256::ONE }
        );
        assert_eq!(
            ExponentP256::modn(N_MIN_1_INT),
            ExponentP256 { int: N_MIN_1_INT }
        );
        assert_eq!(
            ExponentP256::modn(Int256::N),
            ExponentP256 { int: Int256::ZERO }
        );
    }

    /** Arithmetic operations: inverse **/
    #[test]
    fn test_inv_is_inv_vartime() {
        for x in &get_nonzero_test_values() {
            assert_eq!(x.inv(), x.inv_vartime());
        }
    }

    #[test]
    fn test_self_times_inv_is_one() {
        for x in &get_nonzero_test_values() {
            assert_eq!(x * &x.inv(), ONE);
        }
    }

    #[test]
    fn test_inv_inv() {
        for x in get_nonzero_test_values() {
            assert_eq!(x.inv().inv(), x);
        }
    }

    #[test]
    fn test_well_known_inverses() {
        assert_eq!(ONE.inv(), ONE);
        assert_eq!(N_MIN_1.inv(), N_MIN_1);
    }

    /** RNG **/
    // Mock rng that samples through a list of values, then panics.
    struct StressTestingRng {
        values: Vec<Int256>,
        index: usize,
    }

    impl StressTestingRng {
        pub fn new(values: Vec<Int256>) -> StressTestingRng {
            StressTestingRng { values, index: 0 }
        }
    }

    impl Rng256 for StressTestingRng {
        // This function is unused, as we redefine gen_uniform_u32x8.
        fn gen_uniform_u8x32(&mut self) -> [u8; 32] {
            unreachable!()
        }

        fn gen_uniform_u32x8(&mut self) -> [u32; 8] {
            let result = self.values[self.index].digits();
            self.index += 1;
            result
        }
    }

    #[test]
    fn test_uniform_non_zero_is_below_n() {
        let mut rng = StressTestingRng::new(vec![
            Int256::new([
                0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                0xffffffff,
            ]),
            Int256::N,
            N_MIN_1.to_int(),
            Int256::N_MIN_2,
        ]);

        assert_eq!(NonZeroExponentP256::gen_uniform(&mut rng), N_MIN_1);
    }

    #[test]
    fn test_uniform_n_is_above_zero() {
        let mut rng = StressTestingRng::new(vec![Int256::ZERO]);

        assert_eq!(NonZeroExponentP256::gen_uniform(&mut rng), ONE);
    }
}
