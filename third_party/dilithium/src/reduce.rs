use params::{Q, QINV};

/// Returns a value between `-Q` and `Q` that is equivalent to `a`.
///
/// For a finite field element `a` with `-2^{31}*Q <= a <= Q*2^31`,
/// computes `r` equivalent to `a*2^{-32} (mod Q)` such that `-Q < r < Q`.
///
/// # Arguments
///
/// * `a` - a number between `2^{31}*Q` and `Q*2^31`.
pub fn montgomery_reduce(a: i64) -> i32 {
    let mut t: i32 = (((a as i32) as i64) * (QINV as i64)) as i32;
    t = ((a - (t as i64) * (Q as i64)) >> 32) as i32;
    t
}

/// Returns a value between `-6283009` and `6283007` that is equivalent to `a`.
///
/// For a finite field element `a` with `a <= 2^{31} - 2^{22} - 1`,
/// computes `r` equivalent to `a (mod Q)` such that
/// `-6283009 <= r <= 6283007`.
///
/// # Arguments
///
/// * `a` - a number between `2^{31}*Q` and `Q*2^31`.
pub fn reduce32(a: i32) -> i32 {
    let mut t: i32 = (a + (1 << 22)) >> 23;
    t = a - t * Q;
    t
}

/// Adds `Q` if the input finite field element is negative.
///
/// # Arguments
///
/// * `a` - a number.
pub fn caddq(a: i32) -> i32 {
    let mut t = a;
    t += (a >> 31) & Q;
    t
}

/// Computes the standard representative `r = a mod Q`.
///
/// # Arguments
///
/// * `a` - a number.
pub fn freeze(a: i32) -> i32 {
    let a = reduce32(a);
    let a = caddq(a);
    a
}
