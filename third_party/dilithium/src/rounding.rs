use params::{D, GAMMA2, Q};

/// Returns the remainder and the quotient of `a` divided by `2^{D-1}`.
///
/// For a finite field element `a`, computes `a0` and `a1` such that
/// `a mod Q = a1*2^D + a0` with `-2^{D-1} < a0 <= 2^{D-1}`.
///
/// # Arguments
///
/// * `a` - a number assumed to be a standard representative modulo `Q`.
pub fn power2round(a: i32) -> (i32, i32) {
    let a1: i32 = (a + (1 << (D - 1)) - 1) >> D;
    let a0: i32 = a - (a1 << D);

    (a0, a1)
}

/// Computes the high bits and low bits of `a`.
///
/// For a finite field element `a`, computes the high and the low bits `a1`
/// and respectively `a0`, such that `a mod Q = a1*ALPHA + a0`
/// with `-ALPHA/2 < a0 <= ALPHA/2`.
/// Exception: If `a1 = (Q-1)/ALPHA`, `a0` is set to 0.
///
/// # Arguments
///
/// * `a` - a number assumed to be a standard representative modulo `Q`.
pub fn decompose(a: i32) -> (i32, i32) {
    let mut a1: i32 = (a + 127) >> 7;
    if GAMMA2 == (Q - 1) / 32 {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else if GAMMA2 == (Q - 1) / 88 {
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }

    let mut a0: i32 = a - a1 * 2 * GAMMA2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;

    (a0, a1)
}

/// Computes the hint bit.
///
/// The hint bit indicates whether the low bits `a0` overflow into the
/// the high bits `a1`.
///
/// # Arguments
///
/// * `a0` - a number representing the low bits of some element `a`
/// * `a1` - a number representing the high bits of the same element `a`
pub fn make_hint(a0: i32, a1: i32) -> u32 {
    if a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0) {
        1
    } else {
        0
    }
}

/// Uses the given hint to correct the high bits of a.
///
/// # Arguments
///
/// * `a` - the number to be corrected
/// * `hint` - a value 0 or 1
pub fn use_hint(a: i32, hint: u32) -> i32 {
    let (a0, a1) = decompose(a);

    if hint == 0 {
        a1
    } else if GAMMA2 == (Q - 1) / 32 {
        if a0 > 0 {
            (a1 + 1) & 15
        } else {
            (a1 - 1) & 15
        }
    } else {
        if a0 > 0 {
            if a1 == 43 {
                0
            } else {
                a1 + 1
            }
        } else {
            if a1 == 0 {
                43
            } else {
                a1 - 1
            }
        }
    }
}
