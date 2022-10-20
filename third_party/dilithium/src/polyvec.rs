#![allow(dead_code)]

use params::{K, L, N};
use poly::{self, Poly};

macro_rules! polyvec {
    ( $polyvec:ident, $len:expr ) => {
        #[derive(Copy, Clone)]
        pub struct $polyvec(pub [Poly; $len]);

        impl $polyvec {
            pub fn reduce(&mut self) {
                self.0.iter_mut().for_each(poly::reduce)
            }

            pub fn caddq(&mut self) {
                self.0.iter_mut().for_each(poly::caddq)
            }

            pub fn freeze(&mut self) {
                self.0.iter_mut().for_each(poly::freeze)
            }

            pub fn with_add(&mut self, u: &Self, v: &Self) {
                for i in 0..$len {
                    poly::add(&mut self[i], &u[i], &v[i]);
                }
            }

            pub fn add_assign(&mut self, u: &Self) {
                for i in 0..$len {
                    poly::add_assign(&mut self[i], &u[i]);
                }
            }

            pub fn with_sub(&mut self, u: &Self, v: &Self) {
                for i in 0..$len {
                    poly::sub(&mut self[i], &u[i], &v[i]);
                }
            }

            pub fn shift_left(&mut self) {
                self.0.iter_mut().for_each(|p| poly::shift_left(p));
            }

            pub fn ntt(&mut self) {
                self.0.iter_mut().for_each(poly::ntt);
            }

            pub fn invntt_montgomery(&mut self) {
                self.0.iter_mut().for_each(poly::invntt_montgomery)
            }

            pub fn chknorm(&self, bound: i32) -> bool {
                self.0
                    .iter()
                    .map(|p| poly::chknorm(p, bound))
                    .fold(false, |x, y| x | y)
            }
        }

        impl ::core::ops::Index<usize> for $polyvec {
            type Output = Poly;

            #[inline(always)]
            fn index(&self, i: usize) -> &Self::Output {
                self.0.index(i)
            }
        }

        impl ::core::ops::IndexMut<usize> for $polyvec {
            #[inline(always)]
            fn index_mut(&mut self, i: usize) -> &mut Self::Output {
                self.0.index_mut(i)
            }
        }

        impl ::core::cmp::PartialEq for $polyvec {
            fn eq(&self, other: &Self) -> bool {
                self.0
                    .iter()
                    .zip(&other.0)
                    .flat_map(|(x, y)| x.iter().zip(y.iter()))
                    .all(|(x, y)| x == y)
            }
        }

        impl Eq for $polyvec {}

        impl Default for $polyvec {
            fn default() -> Self {
                $polyvec([[0; N]; $len])
            }
        }
    };
}

polyvec!(PolyVecL, L);
polyvec!(PolyVecK, K);

pub fn pointwise_acc_invmontgomery(w: &mut Poly, u: &PolyVecL, v: &PolyVecL) {
    let mut t = [0; N];

    poly::pointwise_invmontgomery(w, &u[0], &v[0]);

    for i in 1..L {
        poly::pointwise_invmontgomery(&mut t, &u[i], &v[i]);
        poly::add_assign(w, &t);
    }
}

/// Computes a partial result of the dot product `w = u * v`.
///
/// # Arguments
/// * `w` - the output polynomial, which will contain the partial result
/// * `u_component` - the polynomial `u[i]`
/// * `v_component` - the polynomial `v[i]`
/// * `i` - the index
pub fn pointwise_acc_invmontgomery_componentwise(
    w: &mut Poly,
    u_component: &Poly,
    v_component: &Poly,
    i: usize,
) {
    if i == 0 {
        poly::pointwise_invmontgomery(w, &u_component, &v_component);
        return;
    }

    let mut t = [0; N];
    poly::pointwise_invmontgomery(&mut t, &u_component, &v_component);
    poly::add_assign(w, &t);
}

impl PolyVecK {
    pub fn power2round(&self, v0: &mut Self, v1: &mut Self) {
        for i in 0..K {
            poly::power2round(&self[i], &mut v0[i], &mut v1[i]);
        }
    }

    pub fn power2round_remainder(&self, v0: &mut Self) {
        for i in 0..K {
            v0[i] = poly::power2round_remainder(&self[i]);
        }
    }

    pub fn decompose(&self, v0: &mut Self, v1: &mut Self) {
        for i in 0..K {
            poly::decompose(&self[i], &mut v0[i], &mut v1[i]);
        }
    }
}

pub fn make_hint(u: &PolyVecK, v: &PolyVecK, h: &mut PolyVecK) -> usize {
    let mut s = 0;
    for i in 0..K {
        s += poly::make_hint(&u[i], &v[i], &mut h[i]);
    }
    s
}

pub fn use_hint(w: &mut PolyVecK, u: &PolyVecK, h: &PolyVecK) {
    for i in 0..K {
        poly::use_hint(&mut w[i], &u[i], &h[i]);
    }
}
