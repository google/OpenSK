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
use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::ops::{Add, AddAssign, Sub, SubAssign};
use subtle::{self, Choice, ConditionallySelectable, ConstantTimeEq};

const BITS_PER_DIGIT: usize = 32;
const BYTES_PER_DIGIT: usize = BITS_PER_DIGIT >> 3;
const NDIGITS: usize = 8;
pub const NBYTES: usize = NDIGITS * BYTES_PER_DIGIT;

pub type Digit = u32;
type DoubleDigit = u64;
type SignedDoubleDigit = i64;

#[derive(Clone, Copy, PartialEq, Eq)]
// TODO: remove this Default once https://github.com/dalek-cryptography/subtle/issues/63 is
// resolved.
#[derive(Default)]
pub struct Int256 {
    digits: [Digit; NDIGITS],
}

impl ConditionallySelectable for Int256 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut digits = [0; NDIGITS];
        for (i, digit) in digits.iter_mut().enumerate() {
            *digit = Digit::conditional_select(&a.digits[i], &b.digits[i], choice);
        }
        Self { digits }
    }
}

/** Arithmetic operations on the secp256r1 field, where elements are represented as 8 digits of
 * 32 bits. **/
#[allow(clippy::unreadable_literal)]
impl Int256 {
    /** Constants for the secp256r1 curve. **/
    // Curve order (prime)
    pub const N: Int256 = Int256 {
        digits: [
            0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0x00000000,
            0xffffffff,
        ],
    };
    // Curve order - 2
    pub const N_MIN_2: Int256 = Int256 {
        digits: [
            0xfc63254f, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0x00000000,
            0xffffffff,
        ],
    };
    // Curve field size
    pub const P: Int256 = Int256 {
        digits: [
            0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
            0xffffffff,
        ],
    };
    // Curve b
    pub const B: Int256 = Int256 {
        digits: [
            0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0, 0x769886bc, 0xb3ebbd55, 0xaa3a93e7,
            0x5ac635d8,
        ],
    };
    // 2^257 mod P
    pub const R: Int256 = Int256 {
        digits: [
            0x00000002, 0x00000000, 0x00000000, 0xfffffffe, 0xffffffff, 0xffffffff, 0xfffffffd,
            0x00000001,
        ],
    };
    // 1 / 2^257 mod P
    pub const R_INV: Int256 = Int256 {
        digits: [
            0x80000000, 0x00000001, 0xffffffff, 0x00000000, 0x80000001, 0xfffffffe, 0x00000001,
            0x7fffffff,
        ],
    };

    pub const ZERO: Int256 = Int256 { digits: [0; 8] };
    pub const ONE: Int256 = Int256 {
        digits: [1, 0, 0, 0, 0, 0, 0, 0],
    };

    #[cfg(test)]
    pub const fn new(digits: [Digit; NDIGITS]) -> Int256 {
        Int256 { digits }
    }

    #[cfg(test)]
    pub fn digits(self) -> [Digit; NDIGITS] {
        self.digits
    }

    #[cfg(test)]
    fn hamming_weight(&self) -> u32 {
        self.digits.iter().map(|d| d.count_ones()).sum()
    }

    /** RNG **/
    // Generates a uniformly distributed integer 0 <= x < 2^256
    pub fn gen_uniform_256<R>(r: &mut R) -> Int256
    where
        R: Rng256,
    {
        Int256 {
            digits: r.gen_uniform_u32x8(),
        }
    }

    /** Serialization **/
    pub fn from_bin(src: &[u8; NBYTES]) -> Int256 {
        let mut digits = [0; NDIGITS];
        for i in 0..NDIGITS {
            digits[NDIGITS - 1 - i] = BigEndian::read_u32(array_ref![src, 4 * i, 4]);
        }
        Int256 { digits }
    }

    pub fn to_bin(&self, dst: &mut [u8; NBYTES]) {
        for i in 0..NDIGITS {
            BigEndian::write_u32(array_mut_ref![dst, 4 * i, 4], self.digits[NDIGITS - 1 - i]);
        }
    }

    pub fn to_minimal_encoding(self) -> Vec<u8> {
        let mut bytes_buffer = [0; NBYTES];
        self.to_bin(&mut bytes_buffer);
        match bytes_buffer.iter().position(|x| *x != 0) {
            Some(pos) => {
                let mut encoding = vec![];
                if bytes_buffer[pos] & 0x80 == 0x80 {
                    encoding.push(0x00);
                }
                encoding.extend_from_slice(&bytes_buffer[pos..]);
                encoding
            }
            None => vec![0x00],
        }
    }

    /** Useful getters **/
    #[inline(always)]
    pub fn digit(&self, i: usize) -> Digit {
        self.digits[i]
    }

    pub fn bit(&self, i: usize) -> Digit {
        let digit = i / BITS_PER_DIGIT;
        let bit = i & (BITS_PER_DIGIT - 1);
        (self.digits[digit] >> bit) & 1
    }

    pub fn is_zero(&self) -> subtle::Choice {
        // Best effort constant-time comparison, assuming the compiler doesn't optimize that.
        Choice::from(
            self.digits
                .iter()
                .fold(1u8, |acc, x| acc & x.ct_eq(&0).unwrap_u8()),
        )
    }

    // Helper function to implement variable-time modular inverse.
    #[cfg(test)]
    fn is_even(&self) -> bool {
        self.digits[0] & 1 == 0
    }

    #[cfg(test)]
    fn count_ones(&self) -> u32 {
        self.digits.iter().map(|x| x.count_ones()).sum()
    }

    /** Arithmetic operations: bit shifts **/
    // Shift left by n bits, and return the result as well as the top digit that was shifted out.
    // This is valid only for 0 < n < BITS_PER_DIGIT
    pub fn shl(&self, n: usize) -> (Int256, Digit) {
        let mut digits = [0; NDIGITS];
        digits[0] = self.digits[0] << n;
        #[allow(clippy::needless_range_loop)]
        for i in 1..NDIGITS {
            digits[i] = (self.digits[i] << n) | (self.digits[i - 1] >> (BITS_PER_DIGIT - n));
        }

        (
            Int256 { digits },
            self.digits[NDIGITS - 1] >> (BITS_PER_DIGIT - n),
        )
    }

    // Shift right by n bits.
    // This is valid only for 0 < n < BITS_PER_DIGIT
    pub fn shr(&self, n: usize) -> Int256 {
        let mut digits = [0; NDIGITS];
        #[allow(clippy::needless_range_loop)]
        for i in 0..(NDIGITS - 1) {
            digits[i] = (self.digits[i] >> n) | (self.digits[i + 1] << (BITS_PER_DIGIT - n));
        }
        digits[NDIGITS - 1] = self.digits[NDIGITS - 1] >> n;

        Int256 { digits }
    }

    // Helper function to implement variable-time modular inverse.
    // Shift right by 1 bit, pushing highbit at the top.
    #[cfg(test)]
    fn shr1(&self, highbit: Digit) -> Int256 {
        let mut digits = [0; NDIGITS];
        for i in 0..(NDIGITS - 1) {
            digits[i] = (self.digits[i] >> 1) | (self.digits[i + 1] << (BITS_PER_DIGIT - 1));
        }
        digits[NDIGITS - 1] = (self.digits[NDIGITS - 1] >> 1) | (highbit << (BITS_PER_DIGIT - 1));

        Int256 { digits }
    }

    /** Arithmetic operations: addition/substraction **/
    // Reduction modulo modd.
    pub fn modd(&self, modd: &Int256) -> Int256 {
        let mut digits = self.digits;
        let choice = Int256::sub_conditional(&mut digits, modd, 0, Choice::from(1u8));
        Int256::add_conditional(&mut digits, modd, 0, choice);
        Int256 { digits }
    }

    // Computes: dst[], top += if choice { mod[] } else { 0 }
    // Returns: new top digit
    fn add_conditional(
        dst: &mut [Digit; NDIGITS],
        modd: &Int256,
        top: Digit,
        choice: Choice,
    ) -> Digit {
        let mut carry: DoubleDigit = 0;

        for (i, digit) in dst.iter_mut().enumerate() {
            carry += *digit as DoubleDigit;
            carry += u32::conditional_select(&0, &modd.digits[i], choice) as DoubleDigit;
            *digit = carry as Digit;
            carry >>= BITS_PER_DIGIT;
        }

        (carry as Digit) + top
    }

    // Computes: dst[], top -= if choice { mod[] } else { 0 }
    // Returns: new top digit
    fn sub_conditional(
        dst: &mut [Digit; NDIGITS],
        modd: &Int256,
        top: Digit,
        choice: Choice,
    ) -> Choice {
        let mut borrow: SignedDoubleDigit = 0;

        for (i, digit) in dst.iter_mut().enumerate() {
            borrow += *digit as SignedDoubleDigit;
            borrow -= u32::conditional_select(&0, &modd.digits[i], choice) as SignedDoubleDigit;
            *digit = borrow as Digit;
            borrow >>= BITS_PER_DIGIT;
        }

        ((borrow + (top as SignedDoubleDigit)) as Digit).ct_eq(&!0)
    }

    /** Modular arithmetic operations **/
    // Modular addition.
    pub fn modadd_vartime(&self, other: &Int256, modd: &Int256) -> Int256 {
        let (sum, carry) = (self as &Int256) + other;
        let tmp = if carry != 0 { (&sum - modd).0 } else { sum };

        // At this point, the sum can be >= modd, even without carry.
        // We substract modd to handle this case.
        tmp.modsub_vartime(modd, modd)
    }

    // Modular substraction.
    pub fn modsub_vartime(&self, other: &Int256, modd: &Int256) -> Int256 {
        let (diff, borrow) = (self as &Int256) - other;
        if borrow != 0 {
            (&diff + modd).0
        } else {
            diff
        }
    }

    // Requires: the most-significant word of the modulus is 0xffffffff.
    // Computes: a * b modulo modd.
    pub fn modmul(a: &Int256, b: &Int256, modd: &Int256) -> Int256 {
        Int256::modmul_top(a, b, 0, modd)
    }

    // Requires: the most-significant word of the modulus is 0xffffffff.
    // Computes: a * (b, top_b) modulo modd.
    pub fn modmul_top(a: &Int256, b: &Int256, top_b: Digit, modd: &Int256) -> Int256 {
        let mut tmp = [0; NDIGITS * 2 + 1];
        let mut top = 0;

        // Multiply/add into tmp.
        for i in 0..NDIGITS {
            if i != 0 {
                tmp[i + NDIGITS - 1] = top;
            }
            top = Int256::mul_add(array_mut_ref![tmp, i, NDIGITS], a, b.digits[i]);
        }

        tmp[2 * NDIGITS - 1] = top;
        top = Int256::mul_add(array_mut_ref![tmp, NDIGITS, NDIGITS], a, top_b);

        // Reduce tmp, digit by digit.
        for j in 0..=NDIGITS {
            let i = NDIGITS - j;

            // Estimate the reducer as top * modd, because the most significant word of modd is
            // 0xffffffff.
            let mut reducer = Int256::ZERO;
            let top_reducer = Int256::mul_add(&mut reducer.digits, modd, top);
            top = Int256::sub_top(array_mut_ref![tmp, i, NDIGITS], &reducer, top, top_reducer);

            #[cfg(test)]
            assert!(top <= 1);

            let _top =
                Int256::sub_conditional(array_mut_ref![tmp, i, NDIGITS], modd, top, top.ct_eq(&1));

            #[cfg(test)]
            assert_eq!(bool::from(_top), false);

            top = tmp[i + NDIGITS - 1];
        }

        let choice =
            Int256::sub_conditional(array_mut_ref![tmp, 0, NDIGITS], modd, 0, Choice::from(1u8));
        Int256::add_conditional(array_mut_ref![tmp, 0, NDIGITS], modd, 0, choice);

        Int256 {
            digits: *array_ref![tmp, 0, NDIGITS],
        }
    }

    // Helper function to implement modular multiplication.
    // Computes: dst[] += src[] * factor
    // Returns: carry digit
    fn mul_add(dst: &mut [Digit; NDIGITS], src: &Int256, factor: Digit) -> Digit {
        let mut carry: DoubleDigit = 0;

        for (i, digit) in dst.iter_mut().enumerate() {
            carry += *digit as DoubleDigit;
            carry += (src.digits[i] as DoubleDigit) * (factor as DoubleDigit);
            *digit = carry as Digit;
            carry >>= BITS_PER_DIGIT;
        }

        carry as Digit
    }

    // Helper function to implement modular multiplication.
    // Computes: dst[], top -= src[], src_top
    // Returns: borrow digit (new top)
    fn sub_top(dst: &mut [Digit; NDIGITS], src: &Int256, top: Digit, src_top: Digit) -> Digit {
        let mut borrow: SignedDoubleDigit = 0;

        for (i, digit) in dst.iter_mut().enumerate() {
            borrow += *digit as SignedDoubleDigit;
            borrow -= src.digits[i] as SignedDoubleDigit;
            *digit = borrow as Digit;
            borrow >>= BITS_PER_DIGIT;
        }

        borrow += top as SignedDoubleDigit;
        borrow -= src_top as SignedDoubleDigit;

        #[cfg(test)]
        assert_eq!(borrow >> BITS_PER_DIGIT, 0);

        borrow as Digit
    }

    /** Constant-time helpers **/
    // Helper function to implement constant-time modular inverse.
    // Best-effort constant time function that computes:
    // if idx == 0 {
    //     *tbl0 = Int256::ONE
    // } else {
    //     *tbl0 = tbl[idx - 1]
    // }
    fn set_zero_to_idx(tbl0: &mut Int256, tbl: &[Int256; 15], idx: u32) {
        *tbl0 = Int256::ONE;
        for i in 1u32..16 {
            tbl0.conditional_assign(&tbl[(i - 1) as usize], i.ct_eq(&idx));
        }
    }

    /** Arithmetic operations: modular exponentiation **/
    pub fn modpow(&self, power: &Int256, modd: &Int256) -> Int256 {
        let mut tbl0 = Int256::ZERO;
        let mut tbl = [Int256::ZERO; 15];
        // tbl[i-1] = self^i
        tbl[0] = *self;
        for i in 1..15 {
            tbl[i] = Int256::modmul(&tbl[i - 1], self, modd);
        }

        let mut result = Int256::ONE;
        for j in (0..256).step_by(4) {
            let i = 256 - j;
            result = Int256::modmul(&result, &result, modd);
            result = Int256::modmul(&result, &result, modd);
            result = Int256::modmul(&result, &result, modd);
            result = Int256::modmul(&result, &result, modd);

            let idx = power.bit(i - 1) << 3
                | power.bit(i - 2) << 2
                | power.bit(i - 3) << 1
                | power.bit(i - 4);

            Int256::set_zero_to_idx(&mut tbl0, &tbl, idx); // tbl0 = tbl[idx-1];
            tbl0 = Int256::modmul(&tbl0, &result, modd);
            result.conditional_assign(&tbl0, !idx.ct_eq(&0));
        }

        result
    }

    /** Arithmetic operations: modular inverse **/
    // Variable time function to compute modular inverse. This uses Euclid's theorem.
    #[cfg(test)]
    #[allow(clippy::many_single_char_names)]
    pub fn modinv_vartime(&self, modd: &Int256) -> Int256 {
        let mut r = Int256::ZERO;
        let mut s = Int256::ONE;
        let mut u = *modd;
        let mut v = *self;

        loop {
            if u.is_even() {
                u = u.shr1(0);
                if r.is_even() {
                    r = r.shr1(0);
                } else {
                    let (rr, highbit) = &r + modd;
                    r = rr.shr1(highbit);
                }
            } else if v.is_even() {
                v = v.shr1(0);
                if s.is_even() {
                    s = s.shr1(0);
                } else {
                    let (ss, highbit) = &s + modd;
                    s = ss.shr1(highbit);
                }
            } else {
                let (w, borrow) = &v - &u;
                if borrow == 0 {
                    v = w;
                    let (ss, borrow) = &s - &r;
                    s = if borrow != 0 { (&ss + modd).0 } else { ss };
                    if bool::from(v.is_zero()) {
                        break;
                    }
                } else {
                    u = (&u - &v).0;
                    let (rr, borrow) = &r - &s;
                    r = if borrow != 0 { (&rr + modd).0 } else { rr };
                }
            }
        }

        r.modd(modd)
    }

    /** Comparison between field elements. **/
    // Best-effort constant-time less-than operation.
    // FIXME: This code is currently required because subtle only supports constant-time equality
    // comparisons. This should be removed once
    // https://github.com/dalek-cryptography/subtle/issues/61 is fixed
    pub fn ct_lt(&self, other: &Int256) -> Choice {
        let mut borrow: SignedDoubleDigit = 0;

        for i in 0..NDIGITS {
            // The following statement updates the borrow according to this table.
            // +-------------------------------------+----------------+------------------+
            // | self.digits[i].cmp(other.digits[i]) | borrow += ?    | resulting borrow |
            // +-------------------------------------+----------------+------------------+
            // | Less                                | ffffffff_xx... | ffffffff_yy...   |
            // | Equal                               | 0              | unchanged        |
            // | Greater                             | 00000000_xx... | 00000000_yy...   |
            // +-------------------------------------+----------------+------------------+
            borrow +=
                (self.digits[i] as SignedDoubleDigit) - (other.digits[i] as SignedDoubleDigit);
            // This is a signed shift. After this operation, the borrow can take two values:
            // - 00...00 (so far, self >= other)
            // - ff...ff (so far, self < other)
            borrow >>= BITS_PER_DIGIT;
        }

        Choice::from((borrow & 1) as u8)
    }

    // Best-effort constant time comparison.
    // * 0  = equal
    // * 1  = self > other
    // * -1 = self < other
    #[cfg(test)]
    pub fn compare(&self, other: &Int256) -> u32 {
        let mut borrow: SignedDoubleDigit = 0;
        let mut notzero: Digit = 0;

        for i in 0..NDIGITS {
            borrow +=
                (self.digits[i] as SignedDoubleDigit) - (other.digits[i] as SignedDoubleDigit);
            notzero |= (borrow as Digit != 0) as Digit;
            borrow >>= BITS_PER_DIGIT;
        }

        (borrow as Digit) | notzero
    }

    #[cfg(test)]
    fn compare_vartime(&self, other: &Int256) -> u32 {
        use core::cmp::Ordering;

        for i in 0..NDIGITS {
            match self.digits[NDIGITS - i - 1].cmp(&other.digits[NDIGITS - i - 1]) {
                Ordering::Equal => continue,
                Ordering::Greater => return 1,
                Ordering::Less => return 0xffffffff,
            }
        }
        0
    }
}

/** Addition with carry **/
impl Add for &Int256 {
    type Output = (Int256, Digit);

    // Returns sum and carry (0 or 1).
    fn add(self, other: &Int256) -> (Int256, Digit) {
        let mut digits = [0; NDIGITS];
        let mut carry: DoubleDigit = 0;

        for (i, digit) in digits.iter_mut().enumerate() {
            carry += (self.digits[i] as DoubleDigit) + (other.digits[i] as DoubleDigit);
            *digit = carry as Digit;
            carry >>= BITS_PER_DIGIT;
        }

        (Int256 { digits }, carry as Digit)
    }
}

impl AddAssign<&Int256> for Int256 {
    // Adds to self, ignoring carry.
    fn add_assign(&mut self, other: &Int256) {
        let mut carry: DoubleDigit = 0;
        for i in 0..NDIGITS {
            carry += (self.digits[i] as DoubleDigit) + (other.digits[i] as DoubleDigit);
            self.digits[i] = carry as Digit;
            carry >>= BITS_PER_DIGIT;
        }
    }
}

impl Add<Digit> for &Int256 {
    type Output = (Int256, Digit);

    // Returns sum and carry (0 or 1).
    fn add(self, digit: Digit) -> (Int256, Digit) {
        let mut digits = [0; NDIGITS];
        let mut carry = digit as DoubleDigit;

        for (i, digit) in digits.iter_mut().enumerate() {
            carry += self.digits[i] as DoubleDigit;
            *digit = carry as Digit;
            carry >>= BITS_PER_DIGIT;
        }

        (Int256 { digits }, carry as Digit)
    }
}

/** Substraction with borrow **/
impl Sub for &Int256 {
    type Output = (Int256, Digit);

    // Returns difference and borrow (0 or -1).
    fn sub(self, other: &Int256) -> (Int256, Digit) {
        let mut digits = [0; NDIGITS];
        let mut borrow: SignedDoubleDigit = 0;

        for (i, digit) in digits.iter_mut().enumerate() {
            borrow +=
                (self.digits[i] as SignedDoubleDigit) - (other.digits[i] as SignedDoubleDigit);
            *digit = borrow as Digit;
            borrow >>= BITS_PER_DIGIT;
        }

        (Int256 { digits }, borrow as Digit)
    }
}

impl SubAssign<&Int256> for Int256 {
    // Substract from self, ignoring carry.
    fn sub_assign(&mut self, other: &Int256) {
        let mut borrow: SignedDoubleDigit = 0;
        for i in 0..NDIGITS {
            borrow +=
                (self.digits[i] as SignedDoubleDigit) - (other.digits[i] as SignedDoubleDigit);
            self.digits[i] = borrow as Digit;
            borrow >>= BITS_PER_DIGIT;
        }
    }
}

#[cfg(feature = "derive_debug")]
impl core::fmt::Debug for Int256 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Int256 {{ digits: {:08x?} }}", self.digits)
    }
}

#[cfg(test)]
pub mod test {
    use super::super::montgomery::Montgomery;
    use super::*;

    /** Extra constants for tests **/
    const TWO: Int256 = Int256 {
        digits: [2, 0, 0, 0, 0, 0, 0, 0],
    };
    const P_MIN_1: Int256 = Int256 {
        digits: [
            0xfffffffe, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
            0xffffffff,
        ],
    };
    const P_MIN_2: Int256 = Int256 {
        digits: [
            0xfffffffd, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
            0xffffffff,
        ],
    };

    // Generate all 256-bit integers that have exactly one bit set to 1.
    pub fn get_1bit_one_test_values() -> Vec<Int256> {
        let mut values = Vec::new();
        for &byte in &[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80] {
            for &int in &[byte, byte << 8, byte << 16, byte << 24] {
                values.push(Int256 {
                    digits: [int, 0, 0, 0, 0, 0, 0, 0],
                });
                values.push(Int256 {
                    digits: [0, int, 0, 0, 0, 0, 0, 0],
                });
                values.push(Int256 {
                    digits: [0, 0, int, 0, 0, 0, 0, 0],
                });
                values.push(Int256 {
                    digits: [0, 0, 0, int, 0, 0, 0, 0],
                });
                values.push(Int256 {
                    digits: [0, 0, 0, 0, int, 0, 0, 0],
                });
                values.push(Int256 {
                    digits: [0, 0, 0, 0, 0, int, 0, 0],
                });
                values.push(Int256 {
                    digits: [0, 0, 0, 0, 0, 0, int, 0],
                });
                values.push(Int256 {
                    digits: [0, 0, 0, 0, 0, 0, 0, int],
                });
            }
        }
        values
    }

    // Generate all 256-bit integers that have exactly one bit set to 0.
    pub fn get_1bit_zero_test_values() -> Vec<Int256> {
        let values: Vec<Int256> = get_1bit_one_test_values()
            .iter()
            .map(|x| {
                let mut digits = [Default::default(); NDIGITS];
                for i in 0..NDIGITS {
                    digits[i] = !x.digits[i];
                }
                Int256 { digits }
            })
            .collect();
        values
    }

    pub fn get_nonzero_test_values() -> Vec<Int256> {
        let mut values: Vec<Int256> = Montgomery::PRECOMPUTED
            .iter()
            .flatten()
            .flatten()
            .map(|x| x.montgomery_to_field().to_int())
            .collect();
        values.append(&mut get_1bit_one_test_values());
        values.append(&mut get_1bit_zero_test_values());
        values.push(Int256::B);
        values.push(P_MIN_1);
        values.push(P_MIN_2);
        values
    }

    fn get_test_values() -> Vec<Int256> {
        let mut values = get_nonzero_test_values();
        values.push(Int256::ZERO);
        values
    }

    #[test]
    fn test_1bit_one() {
        let values = get_1bit_one_test_values();
        assert_eq!(values.len(), 256);
        for x in &values {
            assert_eq!(x.hamming_weight(), 1);
        }
    }

    #[test]
    fn test_1bit_zero() {
        let values = get_1bit_zero_test_values();
        assert_eq!(values.len(), 256);
        for x in &values {
            assert_eq!(x.hamming_weight(), 255);
        }
    }

    /** Serialization **/
    #[test]
    fn test_to_bin_from_bin() {
        for &x in &get_test_values() {
            let mut buf = [Default::default(); NBYTES];
            x.to_bin(&mut buf);
            assert_eq!(Int256::from_bin(&buf), x);
        }
    }

    #[test]
    fn test_minimal_encoding_zero() {
        let test_int = Int256::ZERO;
        let expected_encoding = vec![0x00];

        assert_eq!(test_int.to_minimal_encoding(), expected_encoding);
    }

    #[test]
    fn test_minimal_encoding_one() {
        let test_int = Int256::ONE;
        let expected_encoding = vec![0x01];

        assert_eq!(test_int.to_minimal_encoding(), expected_encoding);
    }

    #[test]
    fn test_minimal_encoding_one_full_byte() {
        let bytes = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xFF,
        ];
        let test_int = Int256::from_bin(&bytes);
        let expected_encoding = vec![0x00, 0xFF];

        assert_eq!(test_int.to_minimal_encoding(), expected_encoding);
    }

    #[test]
    fn test_minimal_encoding_most_bytes_full() {
        let bytes = [
            0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let test_int = Int256::from_bin(&bytes);
        let expected_encoding = bytes.to_vec();

        assert_eq!(test_int.to_minimal_encoding(), expected_encoding);
    }

    #[test]
    fn test_minimal_encoding_no_leading_byte() {
        let bytes = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let test_int = Int256::from_bin(&bytes);
        let expected_encoding = bytes.to_vec();

        assert_eq!(test_int.to_minimal_encoding(), expected_encoding);
    }

    #[test]
    fn test_minimal_encoding_with_leading_byte() {
        let bytes = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let test_int = Int256::from_bin(&bytes);
        let mut expected_encoding = vec![0x00];
        expected_encoding.extend(&bytes);

        assert_eq!(test_int.to_minimal_encoding(), expected_encoding);
    }

    #[test]
    fn test_from_bin_is_big_endian_bits_with_little_endian_words() {
        let buf = b"\x01\x23\x45\x67\x89\xab\xcd\xef\
                    \x12\x34\x56\x78\x9a\xbc\xde\xf0\
                    \x23\x45\x67\x89\xab\xcd\xef\x01\
                    \x34\x56\x78\x9a\xbc\xde\xf0\x12";
        assert_eq!(
            Int256::from_bin(&buf),
            Int256 {
                digits: [
                    0xbcdef012, 0x3456789a, 0xabcdef01, 0x23456789, 0x9abcdef0, 0x12345678,
                    0x89abcdef, 0x01234567,
                ]
            }
        );
    }

    /** Useful getters **/
    #[test]
    fn test_is_zero() {
        assert!(bool::from(Int256::ZERO.is_zero()));
        for x in get_nonzero_test_values() {
            assert!(!bool::from(x.is_zero()));
        }
    }

    #[test]
    fn test_is_even() {
        assert!(Int256::ZERO.is_even());
        assert!(!Int256::ONE.is_even());
        assert!(TWO.is_even());
        assert!(!Int256::N.is_even());
        assert!(!Int256::P.is_even());
        assert!(!Int256::B.is_even());
    }

    /** Arithmetic operations: bit shifts **/
    #[test]
    fn test_shift_zero() {
        for i in 1..BITS_PER_DIGIT {
            assert_eq!(Int256::ZERO.shl(i), (Int256::ZERO, 0));
        }
        for i in 1..BITS_PER_DIGIT {
            assert_eq!(Int256::ZERO.shr(i), Int256::ZERO);
        }
    }

    #[test]
    fn test_shifts() {
        let mut a = Int256::ONE;

        // Shift left.
        for i in 0..255 {
            assert_eq!(a.bit(i), 1);
            assert!(!bool::from(a.is_zero()));
            let (shifted, carry) = a.shl(1);
            assert_eq!(carry, 0);
            a = shifted;
            assert_eq!(a.bit(i), 0);
            assert_eq!(a.count_ones(), 1);
        }

        assert_eq!(a.bit(255), 1);
        assert!(!bool::from(a.is_zero()));
        let (shifted, carry) = a.shl(1);
        assert_eq!(carry, 1);
        assert_eq!(shifted.bit(255), 0);
        assert!(bool::from(shifted.is_zero()));

        // Shift right.
        for i in (1..256).rev() {
            assert_eq!(a.bit(i), 1);
            assert!(!bool::from(a.is_zero()));
            a = a.shr(1);
            assert_eq!(a.bit(i), 0);
            assert_eq!(a.count_ones(), 1);
        }

        assert_eq!(a.bit(0), 1);
        assert!(!bool::from(a.is_zero()));
        a = a.shr(1);
        assert_eq!(a.bit(0), 0);
        assert!(bool::from(a.is_zero()));
    }

    #[test]
    fn test_shl_shr1() {
        for x in &get_test_values() {
            let (shifted, carry) = x.shl(1);
            assert_eq!(&shifted.shr1(carry), x);
        }
    }

    #[test]
    fn test_shr1_is_shr_one() {
        for x in &get_test_values() {
            assert_eq!(x.shr(1), x.shr1(0));
        }
        for x in &get_test_values() {
            let mut y = *x;
            for i in 1..BITS_PER_DIGIT {
                y = y.shr1(0);
                assert_eq!(x.shr(i), y);
            }
        }
    }

    /** Constant-time helpers **/
    #[test]
    fn test_set_zero_to_idx() {
        let mut tbl = [Int256::ZERO; 15];
        for (i, x) in tbl.iter_mut().enumerate() {
            *x = Int256 {
                digits: [i as u32; NDIGITS],
            };
        }

        for i in 0..16 {
            let mut tbl0 = Int256::ZERO;
            Int256::set_zero_to_idx(&mut tbl0, &tbl, i as u32);
            if i == 0 {
                assert_eq!(tbl0, Int256::ONE);
            } else {
                assert_eq!(tbl0, tbl[i - 1]);
            }
        }
    }

    /** Arithmetic: constant-time conditional addition/substraction **/
    #[test]
    fn test_add_conditional() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                let mut z = *x;
                let carry = Int256::add_conditional(&mut z.digits, y, 0, Choice::from(0u8));
                assert_eq!(carry, 0);
                assert_eq!(z, *x);
                let carry = Int256::add_conditional(&mut z.digits, y, 0, Choice::from(1u8));
                assert_eq!((z, carry), x + y);
            }
        }
    }

    #[test]
    fn test_sub_conditional() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                let mut z = *x;
                let borrow = Int256::sub_conditional(&mut z.digits, y, 0, Choice::from(0u8));
                assert_eq!(bool::from(borrow), false);
                assert_eq!(z, *x);
                let borrow = Int256::sub_conditional(&mut z.digits, y, 0, Choice::from(1u8));
                assert_eq!((z, Digit::conditional_select(&0, &!0, borrow)), x - y);
            }
        }
    }

    /** Arithmetic operators **/
    #[test]
    fn test_add_sub() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                let (sum, carry) = x + y;
                let (diff, borrow) = &sum - y;
                assert_eq!(diff, *x);
                assert_eq!(carry.wrapping_add(borrow), 0);
            }
        }
    }

    #[test]
    fn test_sub_add() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                let (diff, borrow) = x - y;
                let (sum, carry) = &diff + y;
                assert_eq!(sum, *x);
                assert_eq!(carry.wrapping_add(borrow), 0);
            }
        }
    }

    /** Arithmetic: modular exponentiation **/
    #[test]
    fn test_modpow() {
        const MODULUS: Int256 = Int256::P;
        for x in &get_test_values() {
            let mut result = Int256::ONE;
            let mut power = Int256::ZERO;

            // This test is super slow with debug assertions enabled.
            #[cfg(not(debug_assertions))]
            const ITERATIONS: u32 = 100;
            #[cfg(debug_assertions)]
            const ITERATIONS: u32 = 5;

            for _ in 0..ITERATIONS {
                assert_eq!(x.modpow(&power, &MODULUS), result);
                result = Int256::modmul(&result, x, &MODULUS);
                power += &Int256::ONE;
            }
        }
    }

    #[test]
    fn test_self_times_modinv_is_one() {
        const MODULUS: Int256 = Int256::P;
        for x in &get_nonzero_test_values() {
            let inv = x.modinv_vartime(&MODULUS);
            let product = Int256::modmul(&x, &inv, &MODULUS);
            assert_eq!(product, Int256::ONE);
        }
    }

    #[test]
    fn test_modinv_modinv() {
        const MODULUS: Int256 = Int256::P;
        for &x in &get_nonzero_test_values() {
            // By construction, this test only works if x is less than the modulus.
            if x.compare(&MODULUS) != 0xffffffff {
                continue;
            }
            assert_eq!(x.modinv_vartime(&MODULUS).modinv_vartime(&MODULUS), x);
        }
    }

    /** Other arithmetic **/
    #[test]
    fn test_add_digit() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                for &digit in &y.digits {
                    assert_eq!(
                        x + digit,
                        x + &Int256 {
                            digits: [digit, 0, 0, 0, 0, 0, 0, 0]
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn test_add_assign() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                let mut z = *x;
                z += y;
                assert_eq!(z, (x + y).0);
            }
        }
    }

    #[test]
    fn test_sub_assign() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                let mut z = *x;
                z -= y;
                assert_eq!(z, (x - y).0);
            }
        }
    }

    #[test]
    fn test_mul_add() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                let mut result = *x;
                let mut carries = 0;

                // This test is super slow with debug assertions enabled.
                #[cfg(not(debug_assertions))]
                const ITERATIONS: u32 = 1000;
                #[cfg(debug_assertions)]
                const ITERATIONS: u32 = 5;

                for factor in 0..ITERATIONS {
                    let mut z = *x;
                    let ma_carry = Int256::mul_add(&mut z.digits, y, factor);
                    assert_eq!(ma_carry, carries);
                    assert_eq!(z, result);

                    let (sum, carry) = &result + y;
                    result = sum;
                    carries += carry;
                }
            }
        }
    }

    /** Comparison between field elements. **/
    #[test]
    fn test_compare() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                let cmp = x.compare(y);
                assert!(cmp == 0 || cmp == 1 || cmp == 0xffffffff);
                assert_eq!(cmp, x.compare_vartime(y));
            }
        }
    }

    #[test]
    fn test_compare_is_reflexive() {
        for x in &get_test_values() {
            assert_eq!(x.compare(x), 0);
        }
    }

    #[test]
    fn test_compare_is_antisymetric() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                let a = x.compare(y);
                let b = y.compare(x);
                assert_eq!(a.wrapping_add(b), 0);
            }
        }
    }

    #[test]
    fn test_lt() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                let ct_lt = bool::from(x.ct_lt(y));
                let lt = x.compare_vartime(y) == 0xffffffff;
                assert_eq!(ct_lt, lt);
            }
        }
    }

    #[test]
    fn test_lt_is_antireflexive() {
        for x in &get_test_values() {
            assert!(!bool::from(x.ct_lt(x)));
        }
    }

    #[test]
    fn test_lt_is_antisymetric() {
        for x in &get_test_values() {
            for y in &get_test_values() {
                let a = x.ct_lt(y).unwrap_u8();
                let b = y.ct_lt(x).unwrap_u8();
                let c = (x == y) as u8;
                assert_eq!(a + b + c, 1);
            }
        }
    }

    // TODO: more tests
}
