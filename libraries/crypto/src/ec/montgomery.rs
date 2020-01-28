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

use super::gfp256::GFP256;
use super::int256::Int256;
use super::precomputed;
use core::ops::{Add, Mul, Sub};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

pub const NLIMBS: usize = 9;
pub const BOTTOM_28_BITS: u32 = 0x0fff_ffff;
pub const BOTTOM_29_BITS: u32 = 0x1fff_ffff;

/** Field element on the secp256r1 curve, represented in Montgomery form **/
#[derive(Clone, Copy)]
pub struct Montgomery {
    // The 9 limbs use 28 or 29 bits, alternatively: even limbs use 29 bits, odd limbs use 28 bits.
    // The Montgomery form stores a field element x as (x * 2^257) mod P.
    pub limbs: [u32; NLIMBS],
}

impl ConditionallySelectable for Montgomery {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0; NLIMBS];
        for (i, limb) in limbs.iter_mut().enumerate() {
            *limb = u32::conditional_select(&a.limbs[i], &b.limbs[i], choice);
        }
        Self { limbs }
    }
}

#[allow(clippy::unreadable_literal)]
impl Montgomery {
    /** Constants for the secp256r1 field **/
    pub const ZERO: Montgomery = Montgomery {
        limbs: [
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000,
        ],
    };
    pub const ONE: Montgomery = Montgomery {
        limbs: [
            0x00000002, 0x00000000, 0x00000000, 0x0ffff800, 0x1fffffff, 0x0fffffff, 0x1fbfffff,
            0x01ffffff, 0x00000000,
        ],
    };
    pub const A: Montgomery = Montgomery {
        limbs: [
            0x1ffffff8, 0x0fffffff, 0x1fffffff, 0x10001fff, 0x1fffffff, 0x0fffffff, 0x20ffffff,
            0x07ffffff, 0x1fffffff,
        ],
    };
    pub const B: Montgomery = Montgomery {
        limbs: [
            0x13897bbf, 0x09cdf622, 0x043090d8, 0x002e67c4, 0x176b5678, 0x02afdc84, 0x0d196888,
            0x0b090e90, 0x0b8600c3,
        ],
    };
    pub const THREE_B: Montgomery = Montgomery {
        limbs: [
            0x1a9c733f, 0x0d69e267, 0x0c91b289, 0x108b2f4c, 0x26420367, 0x180f958d, 0x270c3997,
            0x031b2bb0, 0x0292024b,
        ],
    };
    const P: Montgomery = Montgomery {
        limbs: [
            0x1fffffff, 0x0fffffff, 0x1fffffff, 0x000003ff, 0x00000000, 0x00000000, 0x00200000,
            0x0f000000, 0x0fffffff,
        ],
    };
    const TWO_P: Montgomery = Montgomery {
        limbs: [
            0x1ffffffe, 0x0fffffff, 0x1fffffff, 0x000007ff, 0x00000000, 0x00000000, 0x00400000,
            0x0e000000, 0x1fffffff,
        ],
    };
    // A constant equal to 0 mod p. This is used to implement substraction arithmetic.
    const ZERO31: Montgomery = Montgomery {
        limbs: [
            (1 << 31) - (1 << 3),
            (1 << 30) - (1 << 2),
            (1 << 31) - (1 << 2),
            (1 << 30) + (1 << 13) - (1 << 2),
            (1 << 31) - (1 << 2),
            (1 << 30) - (1 << 2),
            (1 << 31) + (1 << 24) - (1 << 2),
            (1 << 30) - (1 << 27) - (1 << 2),
            (1 << 31) - (1 << 2),
        ],
    };

    /** Precomputed multiples of the base point of the elliptic curve **/
    pub const fn new(limbs: [u32; NLIMBS]) -> Montgomery {
        Montgomery { limbs }
    }

    // This contains two tables of 15 points, each represented by its x and y coordinates in
    // Montgomery form.
    pub const PRECOMPUTED: [[[Montgomery; 2]; 15]; 2] = precomputed::PRECOMPUTED;

    /** Conversion to/from Montgomery form **/
    pub fn field_to_montgomery(gf: &GFP256) -> Montgomery {
        let mut limbs = [0; NLIMBS];

        let mut shifted = (gf * &GFP256::R).to_int();
        for (i, limb) in limbs.iter_mut().enumerate() {
            if i & 1 == 0 {
                *limb = shifted.digit(0) & BOTTOM_29_BITS;
                shifted = shifted.shr(29);
            } else {
                *limb = shifted.digit(0) & BOTTOM_28_BITS;
                shifted = shifted.shr(28);
            }
        }

        Montgomery { limbs }
    }

    pub fn montgomery_to_field(&self) -> GFP256 {
        let (mut result, _) = Int256::ZERO.add(self.limbs[NLIMBS - 1]);
        let mut top = 0;

        for j in 0..=(NLIMBS - 2) {
            let i = NLIMBS - 2 - j;

            let shift = if i & 1 == 0 { 29 } else { 28 };
            let (tmp, top1) = result.shl(shift);

            let (r, top2) = tmp.add(self.limbs[i]);
            result = r;
            top = top1 | top2;
        }

        GFP256::R_INV.mul_top(&result, top)
    }

    /** Useful getters **/
    #[inline(always)]
    fn get64(&self, i: usize) -> u64 {
        self.limbs[i] as u64
    }

    /** Advanced arithmetic **/
    // Squaring.
    pub fn square(&self) -> Montgomery {
        let mut big_limbs: [u64; 17] = [0; 17];

        big_limbs[0] = self.get64(0) * self.get64(0);
        big_limbs[1] = self.get64(0) * (self.get64(1) << 1);
        big_limbs[2] = self.get64(0) * (self.get64(2) << 1) + self.get64(1) * (self.get64(1) << 1);
        big_limbs[3] = self.get64(0) * (self.get64(3) << 1) + self.get64(1) * (self.get64(2) << 1);
        big_limbs[4] = self.get64(0) * (self.get64(4) << 1)
            + self.get64(1) * (self.get64(3) << 2)
            + self.get64(2) * self.get64(2);
        big_limbs[5] = self.get64(0) * (self.get64(5) << 1)
            + self.get64(1) * (self.get64(4) << 1)
            + self.get64(2) * (self.get64(3) << 1);
        big_limbs[6] = self.get64(0) * (self.get64(6) << 1)
            + self.get64(1) * (self.get64(5) << 2)
            + self.get64(2) * (self.get64(4) << 1)
            + self.get64(3) * (self.get64(3) << 1);
        big_limbs[7] = self.get64(0) * (self.get64(7) << 1)
            + self.get64(1) * (self.get64(6) << 1)
            + self.get64(2) * (self.get64(5) << 1)
            + self.get64(3) * (self.get64(4) << 1);
        big_limbs[8] = self.get64(0) * (self.get64(8) << 1)
            + self.get64(1) * (self.get64(7) << 2)
            + self.get64(2) * (self.get64(6) << 1)
            + self.get64(3) * (self.get64(5) << 2)
            + self.get64(4) * self.get64(4);
        big_limbs[9] = self.get64(1) * (self.get64(8) << 1)
            + self.get64(2) * (self.get64(7) << 1)
            + self.get64(3) * (self.get64(6) << 1)
            + self.get64(4) * (self.get64(5) << 1);
        big_limbs[10] = self.get64(2) * (self.get64(8) << 1)
            + self.get64(3) * (self.get64(7) << 2)
            + self.get64(4) * (self.get64(6) << 1)
            + self.get64(5) * (self.get64(5) << 1);
        big_limbs[11] = self.get64(3) * (self.get64(8) << 1)
            + self.get64(4) * (self.get64(7) << 1)
            + self.get64(5) * (self.get64(6) << 1);
        big_limbs[12] = self.get64(4) * (self.get64(8) << 1)
            + self.get64(5) * (self.get64(7) << 2)
            + self.get64(6) * self.get64(6);
        big_limbs[13] = self.get64(5) * (self.get64(8) << 1) + self.get64(6) * (self.get64(7) << 1);
        big_limbs[14] = self.get64(6) * (self.get64(8) << 1) + self.get64(7) * (self.get64(7) << 1);
        big_limbs[15] = self.get64(7) * (self.get64(8) << 1);
        big_limbs[16] = self.get64(8) * self.get64(8);

        Montgomery::reduce_degree(&big_limbs)
    }

    // Modular inverse.
    pub fn inv(&self) -> Montgomery {
        let mut tmp = self.square();
        tmp = &tmp * self;
        let e2 = tmp; // 2^2 - 2^0

        tmp = tmp.square();
        tmp = tmp.square();
        tmp = &tmp * &e2;
        let e4 = tmp; // 2^4 - 2^0

        for _ in 0..4 {
            tmp = tmp.square();
        }
        tmp = &tmp * &e4;
        let e8 = tmp; // 2^8 - 2^0

        for _ in 0..8 {
            tmp = tmp.square();
        }
        tmp = &tmp * &e8;
        let e16 = tmp; // 2^16 - 2^0

        for _ in 0..16 {
            tmp = tmp.square();
        }
        tmp = &tmp * &e16;
        let e32 = tmp; // 2^32 - 2^0

        for _ in 0..32 {
            tmp = tmp.square();
        }
        let e64 = tmp; // 2^64 - 2^32
        tmp = &tmp * self;

        for _ in 0..192 {
            tmp = tmp.square();
        } // 2^256 - 2^224 + 2^192

        // 2^64 - 2^0
        let mut tmp2 = &e64 * &e32;
        for _ in 0..16 {
            tmp2 = tmp2.square();
        }
        // 2^80 - 2^0
        tmp2 = &tmp2 * &e16;
        for _ in 0..8 {
            tmp2 = tmp2.square();
        }
        // 2^88 - 2^0
        tmp2 = &tmp2 * &e8;
        for _ in 0..4 {
            tmp2 = tmp2.square();
        }
        // 2^92 - 2^0
        tmp2 = &tmp2 * &e4;
        tmp2 = tmp2.square();
        tmp2 = tmp2.square();
        // 2^94 - 2^0
        tmp2 = &tmp2 * &e2;
        tmp2 = tmp2.square();
        tmp2 = tmp2.square();
        // 2^96 - 3
        tmp2 = &tmp2 * self;

        // 2^256 - 2^224 + 2^192 + 2^96 - 3
        &tmp2 * &tmp
    }

    // Multiplication by 2.
    pub fn mul_scalar2(&mut self) {
        let mut carry = 0;

        let mut i = 0;
        loop {
            let next_carry = self.limbs[i] >> 28;
            self.limbs[i] <<= 1;
            self.limbs[i] &= BOTTOM_29_BITS;
            self.limbs[i] += carry;
            carry = next_carry + (self.limbs[i] >> 29);
            self.limbs[i] &= BOTTOM_29_BITS;

            i += 1;
            if i == NLIMBS {
                break;
            }

            let next_carry = self.limbs[i] >> 27;
            self.limbs[i] <<= 1;
            self.limbs[i] &= BOTTOM_28_BITS;
            self.limbs[i] += carry;
            carry = next_carry + (self.limbs[i] >> 28);
            self.limbs[i] &= BOTTOM_28_BITS;

            i += 1;
        }

        self.reduce_carry(carry);
    }

    // Multiplication by 3.
    pub fn mul_scalar3(&mut self) {
        let mut carry = 0;

        let mut i = 0;
        loop {
            self.limbs[i] *= 3;
            self.limbs[i] += carry;
            carry = self.limbs[i] >> 29;
            self.limbs[i] &= BOTTOM_29_BITS;

            i += 1;
            if i == NLIMBS {
                break;
            }

            self.limbs[i] *= 3;
            self.limbs[i] += carry;
            carry = self.limbs[i] >> 28;
            self.limbs[i] &= BOTTOM_28_BITS;

            i += 1;
        }

        self.reduce_carry(carry);
    }

    // Multiplication by 4.
    pub fn mul_scalar4(&mut self) {
        let mut carry = 0;

        let mut i = 0;
        loop {
            let next_carry = self.limbs[i] >> 27;
            self.limbs[i] <<= 2;
            self.limbs[i] &= BOTTOM_29_BITS;
            self.limbs[i] += carry;
            carry = next_carry + (self.limbs[i] >> 29);
            self.limbs[i] &= BOTTOM_29_BITS;

            i += 1;
            if i == NLIMBS {
                break;
            }

            let next_carry = self.limbs[i] >> 26;
            self.limbs[i] <<= 2;
            self.limbs[i] &= BOTTOM_28_BITS;
            self.limbs[i] += carry;
            carry = next_carry + (self.limbs[i] >> 28);
            self.limbs[i] &= BOTTOM_28_BITS;

            i += 1;
        }

        self.reduce_carry(carry);
    }

    // Multiplication by 8.
    pub fn mul_scalar8(&mut self) {
        let mut carry = 0;

        let mut i = 0;
        loop {
            let next_carry = self.limbs[i] >> 26;
            self.limbs[i] <<= 3;
            self.limbs[i] &= BOTTOM_29_BITS;
            self.limbs[i] += carry;
            carry = next_carry + (self.limbs[i] >> 29);
            self.limbs[i] &= BOTTOM_29_BITS;

            i += 1;
            if i == NLIMBS {
                break;
            }

            let next_carry = self.limbs[i] >> 25;
            self.limbs[i] <<= 3;
            self.limbs[i] &= BOTTOM_28_BITS;
            self.limbs[i] += carry;
            carry = next_carry + (self.limbs[i] >> 28);
            self.limbs[i] &= BOTTOM_28_BITS;

            i += 1;
        }

        self.reduce_carry(carry);
    }

    /** Comparison **/
    pub fn is_zero_vartime(&self) -> bool {
        // Reduce to a minimal form.
        let tmp = self.reduced_vartime();

        tmp.limbs == Montgomery::ZERO.limbs
            || tmp.limbs == Montgomery::P.limbs
            || tmp.limbs == Montgomery::TWO_P.limbs
    }

    fn reduced_vartime(&self) -> Montgomery {
        let mut reduced = *self;

        // Reduce to a minimal form.
        loop {
            let mut carry = 0;
            let mut i = 0;
            loop {
                reduced.limbs[i] += carry;
                carry = reduced.limbs[i] >> 29;
                reduced.limbs[i] &= BOTTOM_29_BITS;

                i += 1;
                if i == NLIMBS {
                    break;
                }

                reduced.limbs[i] += carry;
                carry = reduced.limbs[i] >> 28;
                reduced.limbs[i] &= BOTTOM_28_BITS;

                i += 1;
            }

            if carry == 0 {
                break;
            }
            reduced.reduce_carry(carry);
        }

        reduced
    }

    /** Reduction of saturated limbs **/
    // Adds a multiple of p in order to cancel |carry|, which is a term at 2**257.
    // On entry: carry < 2**3, self[0,2,...] < 2**29, self[1,3,...] < 2**28.
    // On exit: self[0,2,..] < 2**30, self[1,3,...] < 2**29.
    fn reduce_carry(&mut self, carry: u32) {
        let carry_choice = carry.ct_eq(&0);
        self.limbs[0] += carry << 1;
        self.limbs[3] += u32::conditional_select(&0x10000000, &0, carry_choice);
        self.limbs[3] -= carry << 11;
        self.limbs[4] += u32::conditional_select(&(0x20000000 - 1), &0, carry_choice);
        self.limbs[5] += u32::conditional_select(&(0x10000000 - 1), &0, carry_choice);
        self.limbs[6] += u32::conditional_select(&(0x20000000 - 1), &0, carry_choice);
        self.limbs[6] -= carry << 22;
        self.limbs[7] += carry << 25;
        self.limbs[7] -= u32::conditional_select(&1, &0, carry_choice);
    }

    // Reduce the output of a multiplication or squaring.
    fn reduce_degree(big_limbs: &[u64; 17]) -> Montgomery {
        let mut limbs: [u32; 18] = Montgomery::propagate_carry(big_limbs);
        Montgomery::eliminate_terms(&mut limbs);
        Montgomery::compact_limbs(limbs)
    }

    // Helper function for reduce_degree().
    // Converts 17 saturated 64-bit limbs to 18 unsaturated limbs of 28 or 29 bits.
    fn propagate_carry(big_limbs: &[u64; 17]) -> [u32; 18] {
        let mut limbs: [u32; 18] = [0; 18];

        limbs[0] = (big_limbs[0] as u32) & BOTTOM_29_BITS;
        limbs[1] = (big_limbs[0] as u32) >> 29;
        limbs[1] |= (((big_limbs[0] >> 32) as u32) << 3) & BOTTOM_28_BITS;
        limbs[1] += (big_limbs[1] as u32) & BOTTOM_28_BITS;
        let mut carry = limbs[1] >> 28;
        limbs[1] &= BOTTOM_28_BITS;

        let mut i = 2;
        loop {
            limbs[i] = ((big_limbs[i - 2] >> 32) as u32) >> 25;
            limbs[i] += (big_limbs[i - 1] as u32) >> 28;
            limbs[i] += (((big_limbs[i - 1] >> 32) as u32) << 4) & BOTTOM_29_BITS;
            limbs[i] += (big_limbs[i] as u32) & BOTTOM_29_BITS;
            limbs[i] += carry;
            carry = limbs[i] >> 29;
            limbs[i] &= BOTTOM_29_BITS;

            i += 1;
            if i == 17 {
                break;
            }

            limbs[i] = ((big_limbs[i - 2] >> 32) as u32) >> 25;
            limbs[i] += (big_limbs[i - 1] as u32) >> 29;
            limbs[i] += (((big_limbs[i - 1] >> 32) as u32) << 3) & BOTTOM_28_BITS;
            limbs[i] += (big_limbs[i] as u32) & BOTTOM_28_BITS;
            limbs[i] += carry;
            carry = limbs[i] >> 28;
            limbs[i] &= BOTTOM_28_BITS;

            i += 1;
        }
        limbs[17] = ((big_limbs[15] >> 32) as u32) >> 25;
        limbs[17] += (big_limbs[16] as u32) >> 29;
        limbs[17] += ((big_limbs[16] >> 32) as u32) << 3;
        limbs[17] += carry;

        limbs
    }

    // Helper function for reduce_degree().
    // Montgomery elimination of terms.
    fn eliminate_terms(limbs: &mut [u32; 18]) {
        let mut i = 0;
        loop {
            limbs[i + 1] += limbs[i] >> 29;
            let x = limbs[i] & BOTTOM_29_BITS;
            let choice = x.ct_eq(&0);
            limbs[i] = 0;

            limbs[i + 3] += (x << 10) & BOTTOM_28_BITS;
            limbs[i + 4] += x >> 18;

            limbs[i + 6] += (x << 21) & BOTTOM_29_BITS;
            limbs[i + 7] += x >> 8;

            limbs[i + 7] += u32::conditional_select(&0x10000000, &0, choice);
            limbs[i + 8] += u32::conditional_select(&x.wrapping_sub(1), &0, choice);
            limbs[i + 7] -= (x << 24) & BOTTOM_28_BITS;
            limbs[i + 8] -= x >> 4;

            limbs[i + 8] += u32::conditional_select(&0x20000000, &0, choice);
            limbs[i + 8] -= x;
            limbs[i + 8] += (x << 28) & BOTTOM_29_BITS;
            limbs[i + 9] = limbs[i + 9].wrapping_add(u32::conditional_select(
                &(x >> 1).wrapping_sub(1),
                &0,
                choice,
            ));

            if i + 1 == NLIMBS {
                break;
            }

            limbs[i + 2] += limbs[i + 1] >> 28;
            let x = limbs[i + 1] & BOTTOM_28_BITS;
            let choice = x.ct_eq(&0);
            limbs[i + 1] = 0;

            limbs[i + 4] += (x << 11) & BOTTOM_29_BITS;
            limbs[i + 5] += x >> 18;

            limbs[i + 7] += (x << 21) & BOTTOM_28_BITS;
            limbs[i + 8] += x >> 7;

            limbs[i + 8] += u32::conditional_select(&0x20000000, &0, choice);
            limbs[i + 9] += u32::conditional_select(&x.wrapping_sub(1), &0, choice);
            limbs[i + 8] -= (x << 25) & BOTTOM_29_BITS;
            limbs[i + 9] -= x >> 4;

            limbs[i + 9] += u32::conditional_select(&0x10000000, &0, choice);
            limbs[i + 9] -= x;
            limbs[i + 10] += u32::conditional_select(&x.wrapping_sub(1), &0, choice);

            i += 2;
        }
    }

    // Helper function for reduce_degree().
    // Extract the final limbs from Montgomery-eliminated terms.
    fn compact_limbs(tmp: [u32; 18]) -> Montgomery {
        let mut limbs = [0; NLIMBS];
        let mut carry = 0;
        let mut i = 0;
        loop {
            limbs[i] = tmp[i + 9];
            limbs[i] += carry;
            limbs[i] += (tmp[i + 10] << 28) & BOTTOM_29_BITS;
            carry = limbs[i] >> 29;
            limbs[i] &= BOTTOM_29_BITS;

            i += 1;

            limbs[i] = tmp[i + 9] >> 1;
            limbs[i] += carry;
            carry = limbs[i] >> 28;
            limbs[i] &= BOTTOM_28_BITS;

            i += 1;
            if i == 8 {
                break;
            }
        }

        limbs[8] = tmp[17];
        limbs[8] = limbs[8].wrapping_add(carry);
        carry = limbs[8] >> 29;
        limbs[8] &= BOTTOM_29_BITS;

        let mut result = Montgomery { limbs };
        result.reduce_carry(carry);
        result
    }
}

/** Arithmetic operators **/
// Clippy warns when it sees a subtraction being done in Add implementation
// which here is completely fine.
#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for &Montgomery {
    type Output = Montgomery;

    fn add(self, other: &Montgomery) -> Montgomery {
        let mut carry = 0;
        let mut limbs = [0; NLIMBS];

        let mut i = 0;
        loop {
            limbs[i] = self.limbs[i] + other.limbs[i];
            limbs[i] += carry;
            carry = limbs[i] >> 29;
            limbs[i] &= BOTTOM_29_BITS;

            i += 1;
            if i == NLIMBS {
                break;
            }

            limbs[i] = self.limbs[i] + other.limbs[i];
            limbs[i] += carry;
            carry = limbs[i] >> 28;
            limbs[i] &= BOTTOM_28_BITS;

            i += 1;
        }

        let mut result = Montgomery { limbs };
        result.reduce_carry(carry);
        result
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
// Clippy warns when it sees an addition being done in Sub implementation
// which here is completely fine.
impl Sub for &Montgomery {
    type Output = Montgomery;

    fn sub(self, other: &Montgomery) -> Montgomery {
        let mut carry = 0;
        let mut limbs = [0; NLIMBS];

        let mut i = 0;
        loop {
            limbs[i] = self.limbs[i] + (Montgomery::ZERO31.limbs[i] - other.limbs[i]);
            limbs[i] += carry;
            carry = limbs[i] >> 29;
            limbs[i] &= BOTTOM_29_BITS;

            i += 1;
            if i == NLIMBS {
                break;
            }

            limbs[i] = self.limbs[i] + (Montgomery::ZERO31.limbs[i] - other.limbs[i]);
            limbs[i] += carry;
            carry = limbs[i] >> 28;
            limbs[i] &= BOTTOM_28_BITS;

            i += 1;
        }

        let mut result = Montgomery { limbs };
        result.reduce_carry(carry);
        result
    }
}

impl Mul for &Montgomery {
    type Output = Montgomery;

    fn mul(self, other: &Montgomery) -> Montgomery {
        let mut big_limbs: [u64; 17] = [0; 17];

        big_limbs[0] = self.get64(0) * other.get64(0);
        big_limbs[1] = self.get64(0) * other.get64(1) + self.get64(1) * other.get64(0);
        big_limbs[2] = self.get64(0) * other.get64(2)
            + self.get64(1) * (other.get64(1) << 1)
            + self.get64(2) * other.get64(0);
        big_limbs[3] = self.get64(0) * other.get64(3)
            + self.get64(1) * other.get64(2)
            + self.get64(2) * other.get64(1)
            + self.get64(3) * other.get64(0);
        big_limbs[4] = self.get64(0) * other.get64(4)
            + self.get64(1) * (other.get64(3) << 1)
            + self.get64(2) * other.get64(2)
            + self.get64(3) * (other.get64(1) << 1)
            + self.get64(4) * other.get64(0);
        big_limbs[5] = self.get64(0) * other.get64(5)
            + self.get64(1) * other.get64(4)
            + self.get64(2) * other.get64(3)
            + self.get64(3) * other.get64(2)
            + self.get64(4) * other.get64(1)
            + self.get64(5) * other.get64(0);
        big_limbs[6] = self.get64(0) * other.get64(6)
            + self.get64(1) * (other.get64(5) << 1)
            + self.get64(2) * other.get64(4)
            + self.get64(3) * (other.get64(3) << 1)
            + self.get64(4) * other.get64(2)
            + self.get64(5) * (other.get64(1) << 1)
            + self.get64(6) * other.get64(0);
        big_limbs[7] = self.get64(0) * other.get64(7)
            + self.get64(1) * other.get64(6)
            + self.get64(2) * other.get64(5)
            + self.get64(3) * other.get64(4)
            + self.get64(4) * other.get64(3)
            + self.get64(5) * other.get64(2)
            + self.get64(6) * other.get64(1)
            + self.get64(7) * other.get64(0);
        big_limbs[8] = self.get64(0) * other.get64(8)
            + self.get64(1) * (other.get64(7) << 1)
            + self.get64(2) * other.get64(6)
            + self.get64(3) * (other.get64(5) << 1)
            + self.get64(4) * other.get64(4)
            + self.get64(5) * (other.get64(3) << 1)
            + self.get64(6) * other.get64(2)
            + self.get64(7) * (other.get64(1) << 1)
            + self.get64(8) * other.get64(0);
        big_limbs[9] = self.get64(1) * other.get64(8)
            + self.get64(2) * other.get64(7)
            + self.get64(3) * other.get64(6)
            + self.get64(4) * other.get64(5)
            + self.get64(5) * other.get64(4)
            + self.get64(6) * other.get64(3)
            + self.get64(7) * other.get64(2)
            + self.get64(8) * other.get64(1);
        big_limbs[10] = self.get64(2) * other.get64(8)
            + self.get64(3) * (other.get64(7) << 1)
            + self.get64(4) * other.get64(6)
            + self.get64(5) * (other.get64(5) << 1)
            + self.get64(6) * other.get64(4)
            + self.get64(7) * (other.get64(3) << 1)
            + self.get64(8) * other.get64(2);
        big_limbs[11] = self.get64(3) * other.get64(8)
            + self.get64(4) * other.get64(7)
            + self.get64(5) * other.get64(6)
            + self.get64(6) * other.get64(5)
            + self.get64(7) * other.get64(4)
            + self.get64(8) * other.get64(3);
        big_limbs[12] = self.get64(4) * other.get64(8)
            + self.get64(5) * (other.get64(7) << 1)
            + self.get64(6) * other.get64(6)
            + self.get64(7) * (other.get64(5) << 1)
            + self.get64(8) * other.get64(4);
        big_limbs[13] = self.get64(5) * other.get64(8)
            + self.get64(6) * other.get64(7)
            + self.get64(7) * other.get64(6)
            + self.get64(8) * other.get64(5);
        big_limbs[14] = self.get64(6) * other.get64(8)
            + self.get64(7) * (other.get64(7) << 1)
            + self.get64(8) * other.get64(6);
        big_limbs[15] = self.get64(7) * other.get64(8) + self.get64(8) * other.get64(7);
        big_limbs[16] = self.get64(8) * other.get64(8);

        Montgomery::reduce_degree(&big_limbs)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    impl PartialEq for Montgomery {
        fn eq(&self, other: &Montgomery) -> bool {
            (self - other).is_zero_vartime()
        }
    }

    impl core::fmt::Debug for Montgomery {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "Montgomery {{ limbs: {:08x?} }}", self.limbs)
        }
    }

    pub fn get_nonzero_test_values() -> Vec<Montgomery> {
        let mut values: Vec<Montgomery> = Montgomery::PRECOMPUTED
            .iter()
            .flatten()
            .flatten()
            .cloned()
            .collect();
        values.push(Montgomery::ONE);
        values.push(Montgomery::A);
        values.push(Montgomery::B);
        values.push(Montgomery::THREE_B);
        // TODO: Add more test values.
        values
    }

    fn get_test_values() -> Vec<Montgomery> {
        let mut values = get_nonzero_test_values();
        values.push(Montgomery::ZERO);
        values
    }

    /** Constants for the secp256r1 field **/
    #[test]
    fn test_zero31_is_zero_mod_p() {
        assert!(Montgomery::ZERO31.is_zero_vartime());
    }

    #[test]
    fn test_2p() {
        assert_eq!(
            Montgomery::TWO_P.limbs,
            (&Montgomery::P + &Montgomery::P).limbs
        );
    }

    #[test]
    fn test_a() {
        // a == -3
        let mut a = GFP256::ZERO;
        a = &a - &GFP256::ONE;
        a = &a - &GFP256::ONE;
        a = &a - &GFP256::ONE;
        assert_eq!(Montgomery::A, Montgomery::field_to_montgomery(&a));
    }

    #[test]
    fn test_b() {
        assert_eq!(Montgomery::B, Montgomery::field_to_montgomery(&GFP256::B));
    }

    #[test]
    fn test_3b() {
        let mut b3 = GFP256::B;
        b3 = &b3 + &GFP256::B;
        b3 = &b3 + &GFP256::B;
        assert_eq!(Montgomery::THREE_B, Montgomery::field_to_montgomery(&b3));
    }

    /** Conversion to/from Montgomery form **/
    #[test]
    fn test_conversion_round_trip() {
        for x in get_test_values() {
            assert_eq!(x, Montgomery::field_to_montgomery(&x.montgomery_to_field()));
        }
    }

    #[test]
    fn test_conversion_for_constants() {
        assert_eq!(
            Montgomery::ZERO.limbs,
            Montgomery::field_to_montgomery(&GFP256::ZERO).limbs
        );
        assert_eq!(
            Montgomery::ONE.limbs,
            Montgomery::field_to_montgomery(&GFP256::ONE).limbs
        );
    }

    /** Constant-time helpers **/

    /** Arithmetic operators **/
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

    /** Advanced arithmetic **/
    #[test]
    fn test_square_is_mul_self() {
        for x in &get_test_values() {
            let multiplied = x * x;
            let squared = x.square();
            assert_eq!(multiplied, squared);
        }
    }

    #[test]
    fn test_self_times_inv_is_one() {
        for x in &get_nonzero_test_values() {
            let inv = x.inv();
            let product = x * &inv;
            assert_eq!(product, Montgomery::ONE);
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
        assert_eq!(Montgomery::ONE.inv(), Montgomery::ONE);
        let p_min_1 = &Montgomery::P - &Montgomery::ONE;
        assert_eq!(p_min_1.inv(), p_min_1);
    }

    #[test]
    fn test_mul_scalar2_from_add() {
        for x in get_test_values() {
            let mut multiplied = x;
            multiplied.mul_scalar2();

            let added = &x + &x;

            assert_eq!(multiplied, added);
        }
    }

    #[test]
    fn test_mul_scalar2_from_mul() {
        let two = &Montgomery::ONE + &Montgomery::ONE;

        for x in get_test_values() {
            let mut multiplied = x;
            multiplied.mul_scalar2();

            assert_eq!(multiplied, &x * &two);
        }
    }

    #[test]
    fn test_mul_scalar3_from_add() {
        for x in get_test_values() {
            let mut multiplied = x;
            multiplied.mul_scalar3();

            let mut added = x;
            for _ in 0..2 {
                added = &added + &x;
            }

            assert_eq!(multiplied, added);
        }
    }

    #[test]
    fn test_mul_scalar3_from_mul() {
        let mut three = Montgomery::ONE;
        for _ in 0..2 {
            three = &three + &Montgomery::ONE;
        }

        for x in get_test_values() {
            let mut multiplied = x;
            multiplied.mul_scalar3();

            assert_eq!(multiplied, &x * &three);
        }
    }

    #[test]
    fn test_mul_scalar4_from_add() {
        for x in get_test_values() {
            let mut multiplied = x;
            multiplied.mul_scalar4();

            let mut added = x;
            for _ in 0..3 {
                added = &added + &x;
            }

            assert_eq!(multiplied, added);
        }
    }

    #[test]
    fn test_mul_scalar4_from_mul() {
        let mut four = Montgomery::ONE;
        for _ in 0..3 {
            four = &four + &Montgomery::ONE;
        }

        for x in get_test_values() {
            let mut multiplied = x;
            multiplied.mul_scalar4();

            assert_eq!(multiplied, &x * &four);
        }
    }

    #[test]
    fn test_mul_scalar8_from_add() {
        for x in get_test_values() {
            let mut multiplied = x;
            multiplied.mul_scalar8();

            let mut added = x;
            for _ in 0..7 {
                added = &added + &x;
            }

            assert_eq!(multiplied, added);
        }
    }

    #[test]
    fn test_mul_scalar8_from_mul() {
        let mut eight = Montgomery::ONE;
        for _ in 0..7 {
            eight = &eight + &Montgomery::ONE;
        }

        for x in get_test_values() {
            let mut multiplied = x;
            multiplied.mul_scalar8();

            assert_eq!(multiplied, &x * &eight);
        }
    }

    /** Comparison **/
    #[test]
    fn test_is_zero() {
        assert!(Montgomery::ZERO.is_zero_vartime());
        for x in get_nonzero_test_values() {
            assert!(!x.is_zero_vartime());
        }
    }

    /** Reduction of saturated limbs **/
    #[test]
    fn test_reduced_carry_is_one() {
        let mut x = Montgomery::ZERO;
        x.reduce_carry(1);
        assert_eq!(x.limbs, Montgomery::ONE.limbs);
    }

    #[test]
    fn test_reduce_carry_works_until_8() {
        let mut reduced = Montgomery::ZERO;
        for i in 0..8 {
            let mut x = Montgomery::ZERO;
            x.reduce_carry(i);
            assert_eq!(x.limbs, reduced.limbs);
            reduced = &reduced + &Montgomery::ONE;
        }
    }

    #[test]
    fn test_reduce_no_carry_is_noop() {
        for x in get_test_values() {
            let mut y = x;
            y.reduce_carry(0);
            assert_eq!(y.limbs, x.limbs);
        }
    }

    #[test]
    fn test_reduce_degree() {
        // TODO: Add a meaningful test for this.
    }
}
