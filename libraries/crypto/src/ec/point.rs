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

use super::exponent256::ExponentP256;
use super::gfp256::GFP256;
use super::int256::Int256;
use super::montgomery::Montgomery;
use core::ops::Add;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

// A point on the elliptic curve is represented by two field elements.
// The "direct" representation with GFP256 (integer modulo p) is used for serialization of public
// keys.
#[derive(Clone, Copy)]
pub struct PointP256 {
    x: GFP256,
    y: GFP256,
}

impl PointP256 {
    // The point at infinity.
    // Although this point is not "valid" on the curve (as it doesn't have an order of N), it is
    // useful for tests.
    #[cfg(test)]
    const INFINITY: PointP256 = PointP256 {
        x: GFP256::ZERO,
        y: GFP256::ZERO,
    };

    /** Serialization **/
    // This uses uncompressed point format from "SEC 1: Elliptic Curve Cryptography" ("Standards for
    // Efficient Cryptography").
    #[cfg(feature = "std")]
    pub fn from_bytes_uncompressed_vartime(bytes: &[u8]) -> Option<PointP256> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            None
        } else {
            PointP256::new_checked_vartime(
                Int256::from_bin(array_ref![bytes, 1, 32]),
                Int256::from_bin(array_ref![bytes, 33, 32]),
            )
        }
    }

    #[cfg(test)]
    pub fn to_bytes_uncompressed(&self, bytes: &mut [u8; 65]) {
        bytes[0] = 0x04;
        self.x.to_int().to_bin(array_mut_ref![bytes, 1, 32]);
        self.y.to_int().to_bin(array_mut_ref![bytes, 33, 32]);
    }

    /** Constructors **/
    pub fn new_checked_vartime(x: Int256, y: Int256) -> Option<PointP256> {
        let gfx = GFP256::from_int_checked(x)?;
        let gfy = GFP256::from_int_checked(y)?;
        if GFP256::is_valid_point_vartime(&gfx, &gfy) {
            Some(PointP256 { x: gfx, y: gfy })
        } else {
            None
        }
    }

    fn from_projective(point: &PointProjective) -> PointP256 {
        PointP256::from_affine(&point.to_affine())
    }

    fn from_affine(affine: &PointAffine) -> PointP256 {
        PointP256 {
            x: affine.x.montgomery_to_field(),
            y: affine.y.montgomery_to_field(),
        }
    }

    fn to_affine(&self) -> PointAffine {
        PointAffine {
            x: Montgomery::field_to_montgomery(&self.x),
            y: Montgomery::field_to_montgomery(&self.y),
        }
    }

    /** Useful getters **/
    #[cfg(test)]
    pub fn is_valid_vartime(&self) -> bool {
        GFP256::is_valid_point_vartime(&self.x, &self.y)
    }

    pub fn getx(self) -> GFP256 {
        self.x
    }

    pub fn gety(self) -> GFP256 {
        self.y
    }

    /** Arithmetic **/
    pub fn base_point_mul(n: &ExponentP256) -> PointP256 {
        let point = PointProjective::scalar_base_mul(n);
        PointP256::from_projective(&point)
    }

    pub fn mul(&self, n: &ExponentP256) -> PointP256 {
        let p = self.to_affine();
        let point = p.scalar_mul(n);
        PointP256::from_projective(&point)
    }

    // Computes n1*G + n2*self
    #[cfg(feature = "std")]
    pub fn points_mul(&self, n1: &ExponentP256, n2: &ExponentP256) -> PointP256 {
        let p = self.to_affine();
        let p1 = PointProjective::scalar_base_mul(n1);
        let p2 = p.scalar_mul(n2);

        let point = &p1 + &p2;
        PointP256::from_projective(&point)
    }
}

// A point on the elliptic curve in projective form.
// This uses Montgomery representation for field elements.
// This is in projective coordinates, i.e. it represents the point { x: x / z, y: y / z }.
// This representation is more convenient to implement complete formulas for elliptic curve
// arithmetic.
#[derive(Clone, Copy)]
pub struct PointProjective {
    x: Montgomery,
    y: Montgomery,
    z: Montgomery,
}

impl ConditionallySelectable for PointProjective {
    #[allow(clippy::many_single_char_names)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let x = Montgomery::conditional_select(&a.x, &b.x, choice);
        let y = Montgomery::conditional_select(&a.y, &b.y, choice);
        let z = Montgomery::conditional_select(&a.z, &b.z, choice);
        Self { x, y, z }
    }
}

// Equivalent to PointProjective { x, y, z: 1 }
#[derive(Clone, Copy)]
pub struct PointAffine {
    x: Montgomery,
    y: Montgomery,
}

impl PointProjective {
    #[cfg(test)]
    pub const INFINITY: PointProjective = PointProjective {
        x: Montgomery::ZERO,
        y: Montgomery::ONE,
        z: Montgomery::ZERO,
    };

    /** Constructors **/
    pub fn from_affine(point: &PointAffine) -> PointProjective {
        PointProjective {
            x: point.x,
            y: point.y,
            z: Montgomery::ONE,
        }
    }

    #[cfg(test)]
    // Construct a point in projective coordinates, with a given z value.
    // This point is equivalent to { x, y, z: 1 }
    pub fn from_affine_shuffled(point: &PointAffine, z: Montgomery) -> PointProjective {
        PointProjective {
            x: &point.x * &z,
            y: &point.y * &z,
            z,
        }
    }

    fn to_affine(&self) -> PointAffine {
        let zinv = self.z.inv();
        let x = &self.x * &zinv;
        let y = &self.y * &zinv;
        PointAffine { x, y }
    }

    /** Constant-time helpers **/
    fn select_point(table: &[PointProjective; 15], index: u32) -> PointProjective {
        let mut point = PointProjective {
            x: Montgomery::ZERO,
            y: Montgomery::ZERO,
            z: Montgomery::ZERO,
        };

        for i in 0..15 {
            let choice = (i + 1).ct_eq(&index);
            point.conditional_assign(&table[i as usize], choice);
        }

        point
    }

    /** Arithmetic **/
    // Complete formula from https://eprint.iacr.org/2015/1060.pdf, Algorithm 5.
    fn add_mixed(&self, other: &PointAffine) -> PointProjective {
        // Steps 1-2 (same as add).
        let mut t0 = &self.x * &other.x;
        let t1 = &self.y * &other.y;
        let mut t2 = self.z;

        // Steps 3-7 (same as add).
        let t3 = &self.x + &self.y;
        let t4 = &other.x + &other.y;
        let t3 = &t3 * &t4;
        let t4 = &t0 + &t1;
        let t3 = &t3 - &t4;

        // Steps 8-11 (add_mixed optimization).
        let t4 = &other.y * &self.z;
        let t4 = &t4 + &self.y;
        let y = &other.x * &self.z;
        let y = &y + &self.x;

        // Steps 12-17 (same as add).
        let z = &Montgomery::B * &t2;
        let mut x = &y - &z;
        x.mul_scalar3(); // 14-15
        let z = &t1 - &x;
        let x = &t1 + &x;

        // Steps 18-22 (same as add).
        let y = &Montgomery::B * &y;
        t2.mul_scalar3(); // 19-20
        let y = &y - &t2;
        let mut y = &y - &t0;

        // Steps 23-27 (same as add).
        y.mul_scalar3(); // 23-24
        t0.mul_scalar3(); // 25-26
        let t0 = &t0 - &t2;

        // Steps 28-36 (same as add).
        let t1 = &t4 * &y;
        let t2 = &t0 * &y;
        let y = &x * &z;
        let y = &y + &t2;
        let x = &t3 * &x;
        let x = &x - &t1;
        let z = &t4 * &z;
        let t1 = &t3 * &t0;
        let z = &z + &t1;

        PointProjective { x, y, z }
    }

    // Complete formula from https://eprint.iacr.org/2015/1060.pdf, Algorithm 6.
    fn double(&self) -> PointProjective {
        // Steps 1-3 (same as add).
        let mut t0 = self.x.square();
        let t1 = self.y.square();
        let mut t2 = self.z.square();

        // Steps 4-7.
        let mut t3 = &self.x * &self.y;
        t3.mul_scalar2();
        let mut z = &self.x * &self.z;
        z.mul_scalar2();

        // Steps 8-13 (same as add).
        let y = &Montgomery::B * &t2;
        let mut y = &y - &z;
        y.mul_scalar3(); // 10-11
        let x = &t1 - &y;
        let y = &t1 + &y;

        // Steps 14-15.
        let y = &x * &y;
        let x = &x * &t3;

        // Steps 16-20 (same as add).
        t2.mul_scalar3(); // 16-17
        let z = &Montgomery::B * &z;
        let z = &z - &t2;
        let mut z = &z - &t0;

        // Steps 21-26 (same as add).
        z.mul_scalar3(); // 21-22
        t0.mul_scalar3(); // 23-24
        let t0 = &t0 - &t2;

        // Steps 27-34.
        let t0 = &t0 * &z;
        let y = &y + &t0;
        let mut t0 = &self.y * &self.z;
        t0.mul_scalar2();
        let z = &t0 * &z;
        let x = &x - &z;
        let mut z = &t0 * &t1;
        z.mul_scalar4(); // 33-34

        PointProjective { x, y, z }
    }

    // Compute scalar*G
    fn scalar_base_mul(scalar: &ExponentP256) -> PointProjective {
        let mut n = PointProjective {
            x: Montgomery::ZERO,
            y: Montgomery::ZERO,
            z: Montgomery::ZERO,
        };
        let mut choice_n_is_inf = Choice::from(1u8);

        for i in 0..32 {
            if i != 0 {
                n = n.double();
            }

            for table_offset in 0..2 {
                let j = 32 * table_offset;
                let bit0 = scalar.bit(31 - i + j);
                let bit1 = scalar.bit(95 - i + j);
                let bit2 = scalar.bit(159 - i + j);
                let bit3 = scalar.bit(223 - i + j);
                let index = bit0 | (bit1 << 1) | (bit2 << 2) | (bit3 << 3);

                let p = PointAffine::select_point(&Montgomery::PRECOMPUTED[table_offset], index);
                let t = n.add_mixed(&p);

                n.conditional_assign(&PointProjective::from_affine(&p), choice_n_is_inf);

                let choice_p_is_inf = index.ct_eq(&0);
                n.conditional_assign(&t, !(choice_p_is_inf | choice_n_is_inf));

                choice_n_is_inf &= choice_p_is_inf;
            }
        }

        n
    }

    // Complete formula from https://eprint.iacr.org/2015/1060.pdf, Algorithm 1.
    #[cfg(test)]
    fn add_complete_general(self, other: &PointProjective) -> PointProjective {
        // Steps 1-3.
        let t0 = &self.x * &other.x;
        let t1 = &self.y * &other.y;
        let t2 = &self.z * &other.z;

        // Steps 4-8.
        let t3 = &self.x + &self.y;
        let t4 = &other.x + &other.y;
        let t3 = &t3 * &t4;
        let t4 = &t0 + &t1;
        let t3 = &t3 - &t4;

        // Steps 9-13.
        let t4 = &self.x + &self.z;
        let t5 = &other.x + &other.z;
        let t4 = &t4 * &t5;
        let t5 = &t0 + &t2;
        let t4 = &t4 - &t5;

        // Steps 14-18.
        let t5 = &self.y + &self.z;
        let x = &other.y + &other.z;
        let t5 = &t5 * &x;
        let x = &t1 + &t2;
        let t5 = &t5 - &x;

        // Steps 19-24.
        let z = &Montgomery::A * &t4;
        let x = &Montgomery::THREE_B * &t2;
        let z = &x + &z;
        let x = &t1 - &z;
        let z = &t1 + &z;
        let y = &x * &z;

        // Steps 25-34.
        let t1 = &t0 + &t0;
        let t1 = &t1 + &t0;
        let t2 = &Montgomery::A * &t2;
        let t4 = &Montgomery::THREE_B * &t4;
        let t1 = &t1 + &t2;
        let t2 = &t0 - &t2;
        let t2 = &Montgomery::A * &t2;
        let t4 = &t4 + &t2;
        let t0 = &t1 * &t4;
        let y = &y + &t0;

        // Steps 35-37.
        let t0 = &t5 * &t4;
        let x = &t3 * &x;
        let x = &x - &t0;

        // Steps 38-40.
        let t0 = &t3 * &t1;
        let z = &t5 * &z;
        let z = &z + &t0;

        PointProjective { x, y, z }
    }
}

impl PointAffine {
    /** Constant-time helpers **/
    fn select_point(table: &[[Montgomery; 2]; 15], index: u32) -> PointAffine {
        let mut x = Montgomery::ZERO;
        let mut y = Montgomery::ZERO;

        for i in 0..15 {
            let choice = (i + 1).ct_eq(&index);
            x.conditional_assign(&table[i as usize][0], choice);
            y.conditional_assign(&table[i as usize][1], choice);
        }

        PointAffine { x, y }
    }

    /** Arithmetic **/
    fn scalar_mul(&self, scalar: &ExponentP256) -> PointProjective {
        let mut precomp = [PointProjective {
            x: Montgomery::ZERO,
            y: Montgomery::ZERO,
            z: Montgomery::ZERO,
        }; 15];

        precomp[0] = PointProjective::from_affine(self);

        for i in (1..15).step_by(2) {
            precomp[i] = precomp[i >> 1].double();
            precomp[i + 1] = precomp[i].add_mixed(self);
        }

        let mut n = PointProjective {
            x: Montgomery::ZERO,
            y: Montgomery::ZERO,
            z: Montgomery::ZERO,
        };
        let mut choice_n_is_inf = Choice::from(1u8);

        for i in (0..256).step_by(4) {
            if i != 0 {
                n = n.double();
                n = n.double();
                n = n.double();
                n = n.double();
            }
            let index = scalar.bit(255 - i) << 3
                | scalar.bit(255 - i - 1) << 2
                | scalar.bit(255 - i - 2) << 1
                | scalar.bit(255 - i - 3);

            let p = PointProjective::select_point(&precomp, index);
            let t = n.add(&p);

            n.conditional_assign(&p, choice_n_is_inf);

            let choice_p_is_inf = index.ct_eq(&0);
            n.conditional_assign(&t, !(choice_p_is_inf | choice_n_is_inf));

            choice_n_is_inf &= choice_p_is_inf;
        }

        n
    }
}

/** Arithmetic operators **/
#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for &PointProjective {
    type Output = PointProjective;

    // Complete formula from https://eprint.iacr.org/2015/1060.pdf, Algorithm 4.
    fn add(self, other: &PointProjective) -> PointProjective {
        // Steps 1-3.
        let mut t0 = &self.x * &other.x;
        let t1 = &self.y * &other.y;
        let mut t2 = &self.z * &other.z;

        // Steps 4-8.
        let t3 = &self.x + &self.y;
        let t4 = &other.x + &other.y;
        let t3 = &t3 * &t4;
        let t4 = &t0 + &t1;
        let t3 = &t3 - &t4;

        // Steps 9-13.
        let t4 = &self.y + &self.z;
        let x = &other.y + &other.z;
        let t4 = &t4 * &x;
        let x = &t1 + &t2;
        let t4 = &t4 - &x;

        // Steps 14-18.
        let x = &self.x + &self.z;
        let y = &other.x + &other.z;
        let x = &x * &y;
        let y = &t0 + &t2;
        let y = &x - &y;

        // Steps 19-24.
        let z = &Montgomery::B * &t2;
        let mut x = &y - &z;
        x.mul_scalar3(); // 21-22
        let z = &t1 - &x;
        let x = &t1 + &x;

        // Steps 25-29.
        let y = &Montgomery::B * &y;
        t2.mul_scalar3(); // 26-27
        let y = &y - &t2;
        let mut y = &y - &t0;

        // Steps 30-34.
        y.mul_scalar3(); // 30-31
        t0.mul_scalar3(); // 32-33
        let t0 = &t0 - &t2;

        // Steps 35-43.
        let t1 = &t4 * &y;
        let t2 = &t0 * &y;
        let y = &x * &z;
        let y = &y + &t2;
        let x = &t3 * &x;
        let x = &x - &t1;
        let z = &t4 * &z;
        let t1 = &t3 * &t0;
        let z = &z + &t1;

        PointProjective { x, y, z }
    }
}

#[cfg(feature = "derive_debug")]
impl core::fmt::Debug for PointP256 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("PointP256")
            .field("x", &self.x)
            .field("y", &self.y)
            .finish()
    }
}

#[cfg(feature = "derive_debug")]
impl PartialEq for PointP256 {
    fn eq(&self, other: &PointP256) -> bool {
        self.x == other.x && self.y == other.y
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    impl PartialEq for PointAffine {
        fn eq(&self, other: &PointAffine) -> bool {
            self.x == other.x && self.y == other.y
        }
    }

    impl core::fmt::Debug for PointAffine {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            f.debug_struct("PointAffine")
                .field("x", &self.x)
                .field("y", &self.y)
                .finish()
        }
    }

    impl PartialEq for PointProjective {
        fn eq(&self, other: &PointProjective) -> bool {
            self.to_affine() == other.to_affine()
        }
    }

    impl core::fmt::Debug for PointProjective {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            f.debug_struct("PointProjective")
                .field("x", &self.x)
                .field("y", &self.y)
                .field("z", &self.z)
                .finish()
        }
    }

    pub fn precomputed(i: usize, j: usize) -> PointAffine {
        PointAffine {
            x: Montgomery::PRECOMPUTED[i][j][0],
            y: Montgomery::PRECOMPUTED[i][j][1],
        }
    }

    fn get_test_values_affine() -> Vec<PointAffine> {
        let mut values = Vec::new();
        for table in 0..2 {
            for index in 0..15 {
                values.push(precomputed(table, index));
            }
        }
        values
    }

    fn get_test_values_projective() -> Vec<PointProjective> {
        let mut values: Vec<_> = get_test_values_affine()
            .iter()
            .map(|p| PointProjective::from_affine(p))
            .collect();
        values.push(PointProjective::INFINITY);
        values
    }

    fn get_test_values() -> Vec<PointP256> {
        get_test_values_affine()
            .iter()
            .map(|p| PointP256::from_affine(p))
            .collect()
    }

    /** Serialization **/
    #[test]
    fn test_to_bytes_from_bytes() {
        for &x in &get_test_values() {
            let mut buf = [Default::default(); 65];
            x.to_bytes_uncompressed(&mut buf);
            assert_eq!(PointP256::from_bytes_uncompressed_vartime(&buf), Some(x));
        }
    }

    #[test]
    fn test_from_bytes_infinity_is_invalid() {
        let mut buf = [0; 65];
        buf[0] = 0x04;
        assert_eq!(PointP256::from_bytes_uncompressed_vartime(&buf), None);
    }

    /** Conversion between point types **/
    #[test]
    fn test_convert_p256_affine() {
        for x in &get_test_values_affine() {
            assert_eq!(PointP256::from_affine(x).to_affine(), *x);
        }
    }

    #[test]
    fn test_convert_projective_affine() {
        for x in &get_test_values_affine() {
            assert_eq!(PointProjective::from_affine(x).to_affine(), *x);
        }
    }

    #[test]
    fn test_projective_shuffle() {
        for x in &get_test_values_affine() {
            for &shuffle in &super::super::montgomery::test::get_nonzero_test_values() {
                assert_eq!(
                    PointProjective::from_affine_shuffled(x, shuffle).to_affine(),
                    *x
                );
            }
        }
    }

    /** Point validation **/
    // Edge cases generated with the following Sage script.
    //
    // ```
    // k = GF(2^256 - 2^224 + 2^192 + 2^96 - 1, 't');
    // R = PolynomialRing(k, 'u');
    // u = R.gen()
    // b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    //
    // def print_point(x, y):
    //     print "x = 0x%x" % x
    //     print "y = 0x%x" % y
    //     print "x^3 - 3*x + b = 0x%x" % (x^3 - 3*x + b)
    //     print "y^2 = 0x%x" % y^2
    //
    // def find_point_at_x(x):
    //     f = x^3 - 3*x + b - u^2
    //     r = f.roots()
    //     if len(r) > 0:
    //         y = r[0][0]
    //         print_point(x, y)
    //
    // def find_point_at_y(y):
    //     f = u^3 - 3*u + b - y^2
    //     r = f.roots()
    //     if len(r) > 0:
    //         x = r[0][0]
    //         print_point(x, y)
    //
    // ITERATIONS = 16
    //
    // print "*" * 40
    // print "Small x"
    // print "*" * 40
    // for i in range(ITERATIONS):
    //     x = k(i)
    //     find_point_at_x(x)
    //
    // print "*" * 40
    // print "Small y"
    // print "*" * 40
    // for i in range(ITERATIONS):
    //     y = k(i)
    //     find_point_at_y(y)
    //
    // print "*" * 40
    // print "High-weight x"
    // print "*" * 40
    // for i in range(ITERATIONS):
    //     x = k(2^255 - 1 - 2^i)
    //     find_point_at_x(x)
    //
    // print "*" * 40
    // print "High-weight y"
    // print "*" * 40
    // for i in range(ITERATIONS):
    //     y = k(2^255 - 1 - 2^i)
    //     find_point_at_y(y)
    // ```
    #[rustfmt::skip]
    const POINTS_SMALL_X: &[[[u32; 8]; 2]] = &[
[
  [0x00000005, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
  [0xcdb70433, 0xccbea3f7, 0x9b265c3a, 0xee35afc4, 0x667e8521, 0x016ec431, 0x55a7e7fa, 0xba6dbc45],
],
[
  [0x00000006, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
  [0x7d7ddc34, 0xddf2aed7, 0xf0183f16, 0x232efd48, 0xcc8dffb8, 0xb9967a1a, 0xabdaf53e, 0xc94db3d2],
],
[
  [0x00000008, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
  [0x636041b3, 0x2242d085, 0xd631ff69, 0x27249b16, 0x3f37f6a6, 0xd624d1d2, 0xca290db0, 0xb706288a],
],
[
  [0x00000009, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
  [0x8fe7b297, 0xdb1812e4, 0x3c63a432, 0xfbc52276, 0xd33315cb, 0xcaaa94f7, 0x2caf2e23, 0x8e14e843],
],
[
  [0x0000000c, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
  [0xb2b74387, 0x6abbc3b4, 0x9de5be82, 0xc726c883, 0x6c4b6500, 0xc653e363, 0xcb0680c1, 0x93fbd29a],
],
    ];
    #[rustfmt::skip]
    const POINTS_SMALL_Y: &[[[u32; 8]; 2]] = &[
[
  [0x0069d2c7, 0x875d877f, 0x7b70f611, 0x6375e8a9, 0x95dbac0d, 0x10db6dd0, 0xab9c6e9e, 0x8d0177eb],
  [0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
],
[
  [0x7607ce12, 0xc9fe1bd7, 0x8b283fbb, 0x53eb03e0, 0xddcaac96, 0xa62f56d3, 0xc6825c8a, 0xcfe9c22c],
  [0x00000004, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
],
[
  [0xde8de1d7, 0xb176f692, 0x841022ca, 0x4cffaf35, 0xeb345f84, 0x0a92738c, 0x46cd60d8, 0xd7325d76],
  [0x00000005, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
],
[
  [0x87914a78, 0x077d5a71, 0x8e3dc5b2, 0x979131e2, 0x97d7ab3f, 0x731dbdaf, 0x1da31d68, 0x9b21c2de],
  [0x00000006, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
],
[
  [0xd56ac453, 0xd7acceae, 0xc6693e4f, 0xcffa296d, 0xe4df51fc, 0x564d94b7, 0xbc9f7da8, 0xb2ed6eac],
  [0x00000007, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
],
    ];
    #[rustfmt::skip]
    const POINTS_HIGH_WEIGHT: &[[[u32; 8]; 2]] = &[
// High-weight x coordinate.
[
  [0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xefffffff],
  [0xf0e94c90, 0x722ff8d6, 0x66ebf289, 0x9b17896c, 0x334f0e43, 0xc4e1c5d1, 0x1ea63e81, 0xa120f8da],
],
[
  [0xfffffffd, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xefffffff],
  [0x5ad8aa4b, 0x717d6de4, 0x2af77820, 0x04ce8429, 0xefb80898, 0xd004a68e, 0xe4b30001, 0x887ce5d3],
],
// High-weight y coordinate.
[
  [0x98619b11, 0xae2e447c, 0x02bcee26, 0x1fcb1b9b, 0xed3ee2d9, 0xefb6ff97, 0x77ee5948, 0xe063d049],
  [0xfffffffd, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xefffffff],
],
[
  [0xcaf4e99c, 0x494eac75, 0x3237de43, 0x695ba4d4, 0x68339d6f, 0xbca064f3, 0x4910c02a, 0xaefca662],
  [0xfffffffb, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xefffffff],
],
    ];

    #[test]
    fn test_zero_x_point() {
        // Even though this point verifies the equation y^2 = x^3 - 3x + b, none of the (x, y)
        // coordinates is allowed to be zero.
        #[rustfmt::skip]
        let x = Int256::new(
            [0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000]
        );
        #[rustfmt::skip]
        let y = Int256::new(
            [0xe8b06c0b, 0xd7407a95, 0xe25178e8, 0xabe3d50d, 0x7b5f9449, 0xdbcc42a2, 0xf1d07c29, 0x99b7a386]
        );
        assert!(PointP256::new_checked_vartime(x, y).is_none());
    }

    #[test]
    fn test_small_x_points() {
        for p in POINTS_SMALL_X {
            let x = Int256::new(p[0]);
            let y = Int256::new(p[1]);
            // These points are valid.
            assert!(PointP256::new_checked_vartime(x, y).is_some());
            // Adding p to the x coordinate doesn't invalidate the equation y^2 = x^3 - 3x + b (as
            // we work in GF(p)), however the coordinates must be serialized in a canonical form
            // modulo p.
            assert!(PointP256::new_checked_vartime((&x + &Int256::P).0, y).is_none());
        }
    }

    #[test]
    fn test_small_y_points() {
        for p in POINTS_SMALL_Y {
            let x = Int256::new(p[0]);
            let y = Int256::new(p[1]);
            // These points are valid.
            assert!(PointP256::new_checked_vartime(x, y).is_some());
            // Adding p to the y coordinate doesn't invalidate the equation y^2 = x^3 - 3x + b (as
            // we work in GF(p)), however the coordinates must be serialized in a canonical form
            // modulo p.
            assert!(PointP256::new_checked_vartime(x, (&y + &Int256::P).0).is_none());
        }
    }

    #[test]
    fn test_high_weight_points() {
        // These points are all valid, with one coordinate of high Hamming weight. This is a sanity
        // check that arithmetic works on such high weight values.
        for p in POINTS_HIGH_WEIGHT {
            let x = Int256::new(p[0]);
            let y = Int256::new(p[1]);
            assert!(PointP256::new_checked_vartime(x, y).is_some());
        }
    }

    #[test]
    fn test_infinity_is_invalid() {
        assert!(PointP256::new_checked_vartime(
            PointP256::INFINITY.x.to_int(),
            PointP256::INFINITY.y.to_int()
        )
        .is_none());
    }

    /** Constant-time helpers **/
    #[test]
    fn test_select_point_projective() {
        let mut table = Vec::new();
        for i in 0..15 {
            table.push(PointProjective::from_affine(&precomputed(0, i)));
        }

        assert_eq!(
            PointProjective::select_point(array_ref![table, 0, 15], 0),
            PointProjective {
                x: Montgomery::ZERO,
                y: Montgomery::ZERO,
                z: Montgomery::ZERO,
            }
        );
        for index in 1..16 {
            assert_eq!(
                PointProjective::select_point(array_ref![table, 0, 15], index as u32),
                table[index - 1]
            );
        }
    }

    #[test]
    fn test_select_point_affine() {
        let table = &Montgomery::PRECOMPUTED[0];

        assert_eq!(
            PointAffine::select_point(table, 0),
            PointAffine {
                x: Montgomery::ZERO,
                y: Montgomery::ZERO,
            }
        );
        for index in 1..16 {
            assert_eq!(
                PointAffine::select_point(table, index as u32),
                precomputed(0, index - 1)
            );
        }
    }

    /** Arithmetic operators **/
    #[test]
    fn test_add_is_add_complete_general() {
        for x in &get_test_values_projective() {
            for y in &get_test_values_projective() {
                let left = x.add_complete_general(y);
                let right = x + y;
                assert_eq!(left, right);
            }
        }
    }

    // Due to the 3 nested loops, this test is super slow with debug assertions enabled.
    #[cfg(not(debug_assertions))]
    #[test]
    fn test_add_is_associative() {
        for x in &get_test_values_projective() {
            for y in &get_test_values_projective() {
                for z in &get_test_values_projective() {
                    // (x + y) + z
                    let left = &(x + y) + z;
                    // x + (y + z)
                    let right = x + &(y + z);
                    assert_eq!(left, right);
                }
            }
        }
    }

    #[test]
    fn test_add_is_commutative() {
        for x in &get_test_values_projective() {
            for y in &get_test_values_projective() {
                assert_eq!(x + y, y + x);
            }
        }
    }

    #[test]
    fn test_add_mixed() {
        for x in &get_test_values_projective() {
            for y in &get_test_values_affine() {
                assert_eq!(x.add_mixed(y), x + &PointProjective::from_affine(y));
            }
        }
    }

    #[test]
    fn test_double() {
        for x in &get_test_values_projective() {
            println!("doubling {:?}", x);
            assert_eq!(x.double(), x + x);
        }
    }

    #[test]
    fn test_add_infinity() {
        for &x in &get_test_values_projective() {
            assert_eq!(&x + &PointProjective::INFINITY, x);
        }
    }

    #[test]
    fn test_add_mixed_infinity() {
        for x in &get_test_values_affine() {
            assert_eq!(
                PointProjective::INFINITY.add_mixed(x),
                PointProjective::from_affine(x)
            );
        }
    }

    #[test]
    fn test_double_infinity() {
        assert_eq!(
            PointProjective::INFINITY.double(),
            PointProjective::INFINITY
        );
    }

    #[test]
    fn test_generator_is_valid_point() {
        let gen = precomputed(0, 0);
        assert!(PointP256::from_affine(&gen).is_valid_vartime());
    }

    #[test]
    fn test_generator_has_correct_order() {
        let gen = precomputed(0, 0);
        // Normally the ExponentP256 type guarantees that its values stay in [0, N[ because N is
        // the curve order and therefore exponents >= N are equivalent to their reduction modulo N.
        // In this test we check that N is indeed the curve order and therefore we need an unsafe
        // block to construct an exponent of N.
        let order = unsafe { ExponentP256::from_int_unchecked(Int256::N) };
        assert_eq!(
            PointP256::from_projective(&gen.scalar_mul(&order)),
            PointP256::INFINITY
        );
    }

    #[test]
    fn test_scalar_base_mul_is_scalar_mul_generator() {
        let gen = precomputed(0, 0);
        // TODO: more scalars
        for scalar in &super::super::exponent256::test::get_test_values() {
            assert_eq!(
                PointProjective::scalar_base_mul(scalar),
                gen.scalar_mul(scalar)
            );
        }
    }

    #[test]
    fn test_base_point_mul_is_mul_generator() {
        let gen = precomputed(0, 0);
        // TODO: more scalars
        for scalar in &super::super::exponent256::test::get_test_values() {
            assert_eq!(
                PointP256::base_point_mul(scalar),
                PointP256::from_affine(&gen).mul(scalar)
            );
        }
    }

    // Helper function to compute the point 2^power * p.
    pub fn power_of_two(mut p: PointProjective, power: usize) -> PointProjective {
        for _ in 0..power {
            p = p.double();
        }
        p
    }

    // TODO: more tests
}
