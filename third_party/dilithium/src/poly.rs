use byteorder::{ByteOrder, LittleEndian};
pub use ntt::{invntt_frominvmont as invntt_montgomery, ntt};
use params::{
    CRHBYTES, D, ETA, GAMMA1, GAMMA2, N, POLETA_SIZE_PACKED, POLT1_SIZE_PACKED, POLW1_SIZE_PACKED,
    POLZ_SIZE_PACKED, Q, SEEDBYTES, TAU,
};
use reduce::{caddq as xcaddq, freeze as xfreeze, montgomery_reduce, reduce32};
use rounding;

pub type Poly = [i32; N];

/// Reduces the coefficients of the polynomial `a` to [-6283009,6283007].
///
/// # Arguments
///
/// * `a` - a polynomial
pub fn reduce(a: &mut Poly) {
    for i in 0..N {
        a[i] = reduce32(a[i]);
    }
}

/// Adds `Q` to every negative coefficient in `a`.
///
/// # Arguments
///
/// * `a` - a polynomial
pub fn caddq(a: &mut Poly) {
    for i in 0..N {
        a[i] = xcaddq(a[i]);
    }
}

/// For every coefficient `x` in `a`, computes `x mod Q`.
///
/// # Arguments
///
/// * `a` - a polynomial
pub fn freeze(a: &mut Poly) {
    for i in 0..N {
        a[i] = xfreeze(a[i]);
    }
}

/// Computes `c = a + b`, where `c`, `a`, and `b` are polynomials.
///
/// # Arguments
///
/// * `a` - a polynomial
pub fn add(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c[i] = a[i] + b[i];
    }
}

/// Computes `c = c + a`, where `c`, and `a` are polynomials.
///
/// # Arguments
///
/// * `a` - a polynomial
pub fn add_assign(c: &mut Poly, a: &Poly) {
    for i in 0..N {
        c[i] += a[i];
    }
}

/// Computes `c = a - b`, where `c`, `a` and `b` are polynomials.
///
/// # Arguments
///
/// * `a` - a polynomial
pub fn sub(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c[i] = a[i] - b[i];
    }
}

/// Multiplies the polynomial `a` by `2^D` without modular reduction.
///
/// # Arguments
///
/// * `a` - a polynomial with coefficients smaller than  than 2^{31-D}
///         in absolute value
pub fn shift_left(a: &mut Poly) {
    for i in 0..N {
        a[i] <<= D;
    }
}

/// Computes `c = a * b` in NTT domain representation.
///
/// # Arguments
///
/// * `c` - the output polynomial, in NTT domain representation
/// * `a` - a polynomial in NTT domain representation
/// * `b` - a polynomial in NTT domain representation
pub fn pointwise_invmontgomery(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c[i] = montgomery_reduce((a[i] as i64) * (b[i] as i64));
    }
}

/// Returns `c = a * b` in standard representation.
///
/// # Arguments
///
/// * `a` - a polynomial in NTT domain representation
/// * `b` - a polynomial in NTT domain representation
pub fn multiply(a: &Poly, b: &Poly) -> Poly {
    let mut c = [0; N];
    pointwise_invmontgomery(&mut c, a, b);
    invntt_montgomery(&mut c);
    reduce(&mut c);
    c
}

/// Decomposes a into the quotient and remainder of its division with `2^{D-1}`.
///
/// For every coefficient `c` of the polynomial `a`, computes `c0`, `c1`
/// such that `c mod Q = c1 * 2^D + c0`, with `-2^{D-1} < c0 <= 2^{D-1}`.
///
/// # Arguments
///
/// * `a` - a polynomial in standard representation (not NTT)
/// * `a0` - output polynomial representing the remainder (coefficients `c0`)
/// * `a1` - output polynomial representing the quotient (coefficients `c1`)
pub fn power2round(a: &Poly, a0: &mut Poly, a1: &mut Poly) {
    for i in 0..N {
        let (x, y) = rounding::power2round(a[i]);
        a0[i] = x;
        a1[i] = y;
    }
}

/// Obtains the remainder of dividing `a` with `2^{D-1}`.
///
/// For every coefficient `c` of the polynomial a, computes `c0`, `c1`
/// such that `c mod Q = c1 * 2^D + c0`, with `-2^{D-1} < c0 <= 2^{D-1}`.
///
/// # Arguments
///
/// * `a` - a polynomial in standard representation (not NTT)
/// * `a0` - output polynomial representing the remainder (coefficients `c0`)
pub fn power2round_remainder(a: &Poly) -> Poly {
    let mut remainder = [0; N];
    for i in 0..N {
        let (x, _) = rounding::power2round(a[i]);
        remainder[i] = x;
    }
    remainder
}

/// Obtains the quotient of dividing `a` with `2^{D-1}`.
///
/// For every coefficient `c` of the polynomial `a`, computes `c0, c1`
/// such that `c mod Q = c1 * 2^D + c0`, with `-2^{D-1} < c0 <= 2^{D-1}`.
///
/// # Arguments
///
/// * `a` - a polynomial in standard representation (not NTT)
/// * `a1` - output polynomial representing the quotient (coefficients `c1`)
pub fn power2round_quotient(a: &Poly) -> Poly {
    let mut quotient = [0; N];
    for i in 0..N {
        let (_, y) = rounding::power2round(a[i]);
        quotient[i] = y;
    }
    quotient
}

/// Obtains the high bits and the low bits of `a`.
///
/// For every coefficient `c` of the input polynomial `a`, computes its
/// high bits `c1` and low bits `c0` such that `c mod Q = c1*ALPHA + c0`,
/// where -ALPHA/2 < c0 <= ALPHA/2.
/// Exception: if `c1 = (Q-1)/ALPHA`, `c1` is set to 0 and `c0 = c mod Q - Q`.
///
/// # Arguments
///
/// * `a` - a polynomial in standard representation (not NTT)
/// * `a0` - output polynomial representing `a`'s low bits (coefficients `c0`)
/// * `a1` - output polynomial representing `a`'s high bits (coefficients `c1`)
pub fn decompose(a: &Poly, a0: &mut Poly, a1: &mut Poly) {
    for i in 0..N {
        let (x, y) = rounding::decompose(a[i]);
        a0[i] = x; // low bits
        a1[i] = y; // high bits
    }
}

/// Returns a polynomial whose coefficients are the high bits of `a`.
///
/// For every coefficient `c` of the input polynomial a, computes its
/// high bits `c1` and low bits `c0` such that `c mod Q = c1*ALPHA + c0`,
/// where `-ALPHA/2 < c0 <= ALPHA/2`.
/// Exception: if `c1 = (Q-1)/ALPHA`, `c1` is set to 0 and `c0 = c mod Q - Q`.
///
/// # Arguments
///
/// * `a` - a polynomial in standard representation (not NTT)
#[cfg(feature = "optimize_stack")]
pub fn high_bits(a: &Poly) -> Poly {
    let mut high_bits: Poly = [0; N];
    for i in 0..N {
        let (_x, y) = rounding::decompose(a[i]);
        high_bits[i] = y;
    }
    return high_bits;
}

/// Returns a polynomial whose coefficients are the low bits of `a`.
///
/// For every coefficient `c` of the input polynomial `a`, computes its
/// high bits `c1` and low bits `c0` such that `c mod Q = c1*ALPHA + c0`,
/// where `-ALPHA/2 < c0 <= ALPHA/2`.
/// Exception: if `c1 = (Q-1)/ALPHA`, `c1` is set to 0 and `c0 = c mod Q - Q`.
///
/// # Arguments
///
/// * `a` - a polynomial in standard representation (not NTT)
#[cfg(feature = "optimize_stack")]
pub fn low_bits(a: &Poly) -> Poly {
    let mut low_bits: Poly = [0; N];
    for i in 0..N {
        let (x, _y) = rounding::decompose(a[i]);
        low_bits[i] = x;
    }
    return low_bits;
}

/// Makes the hint used to obtain `a` from an approximate result `b`.
///
/// Given a polynomial of low bits `a`, and a polynomial of high bits `b`,
/// computes the hint polynomial `h`. The coefficient of `h` indicate
/// whether the low bits of the corresponding coefficient of the input
/// polynomial `a` overflow into the high bits (`b`).
///
/// # Arguments
///
/// * `a` - a polynomial
/// * `b` - a polynomial
/// * `h` - the output polynomial
pub fn make_hint(a: &Poly, b: &Poly, h: &mut Poly) -> usize {
    let mut s = 0;

    for i in 0..N {
        h[i] = rounding::make_hint(a[i], b[i]) as i32;
        s += h[i] as usize;
    }

    s
}

/// Uses a hint polynomial `h` to correct the high bits of a polynomial `b`.
///
/// # Arguments
///
/// * `a` - the output corrected polynomial
/// * `b` - a polynomial
/// * `h` - the hint polynomial: containing values 0 or 1
pub fn use_hint(a: &mut Poly, b: &Poly, h: &Poly) {
    for i in 0..N {
        a[i] = rounding::use_hint(b[i], h[i] as u32);
    }
}

/// Checks if the infinity norm of a polynomial `a` against a given bound `b`.
///
/// The input coefficients must be reduced by `reduce32()`.
///
/// # Arguments
///
/// * `a` - a polynomial
/// * `b` - the bound.
pub fn chknorm(a: &Poly, b: i32) -> bool {
    if b > (Q - 1) / 8 {
        return true;
    }

    // It is ok to leak which coefficient violates the bound since
    // the probability for each coefficient is independent of secret
    // data but we must not leak the sign of the centralized representative.
    for i in 0..N {
        let mut t: i32 = a[i] >> 31;
        t = a[i] - (t & 2 * a[i]);

        if t >= b {
            return true;
        }
    }
    return false;
}

/// Samples a polynomial with random coefficients in `[0, Q - 1]`.
///
/// The sampling is done by performing rejection sampling on the output stream
/// of `SHAKE256(seed|nonce)`.
///
/// # Arguments
///
/// * `a` - the output polynomial
/// * `seed` - an array of random bytes
/// * `nonce` - a number.
pub fn uniform(a: &mut Poly, seed: &[u8; SEEDBYTES], nonce: u16) {
    use digest::{ExtendableOutput, Input, XofReader};
    use sha3::Shake128;

    fn rej_uniform(a: &mut [i32], i_start: usize, buf: &[u8], buf_len: usize) -> usize {
        let mut ctr = 0usize;
        let mut pos = 0usize;
        let mut t: u32;

        let len = a.len() - i_start;

        while ctr < len && pos + 3 <= buf_len {
            t = buf[pos] as u32;
            pos += 1;
            t |= (buf[pos] as u32) << 8;
            pos += 1;
            t |= (buf[pos] as u32) << 16;
            pos += 1;
            t &= 0x7FFFFF;
            if t < (Q as u32) {
                a[i_start + ctr] = t as i32;
                ctr += 1;
            }
        }

        ctr
    }

    let mut hasher = Shake128::default();
    hasher.process(seed);

    let nonce0 = (nonce & ((1 << 8) - 1)) as u8;
    let nonce1 = (nonce >> 8) as u8;
    hasher.process(&[nonce0, nonce1]);

    const STREAM128_BLOCKBYTES: usize = 168;
    const POLY_UNIFORM_NBLOCKS: usize = (768 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES;
    let mut buf_len = POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES;
    let mut buf = [0u8; POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES + 2];

    let mut xof = hasher.xof_result();
    xof.read(&mut buf[..buf_len]);

    let mut ctr = rej_uniform(a, 0, &buf, buf_len);

    while ctr < N {
        let off = buf_len % 3;
        for i in 0..off {
            buf[i] = buf[buf_len - off + i];
        }
        for i in 0..STREAM128_BLOCKBYTES {
            buf[off + i] = 0;
        }
        xof.read(&mut buf[off..off + STREAM128_BLOCKBYTES]);

        buf_len = STREAM128_BLOCKBYTES + off;

        ctr += rej_uniform(a, ctr, &buf, buf_len);
    }
}

/// Samples a polynomial with random coefficients in `[-ETA, ETA]`.
///
/// The sampling is done by performing rejection sampling on the output stream
/// of `SHAKE256(seed|nonce)`.
///
/// # Arguments
///
/// * `a` - the output polynomial
/// * `seed` - an array of random bytes
/// * `nonce` - a number.
pub fn uniform_eta(a: &mut Poly, seed: &[u8; CRHBYTES], nonce: u16) {
    use digest::{ExtendableOutput, Input, XofReader};
    use sha3::Shake256;

    const STREAM256_BLOCKBYTES: usize = 136;

    const POLY_UNIFORM_ETA_NBLOCKS: usize = match ETA {
        2 => (136 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES,
        _ => (227 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES,
    };

    fn rej_eta(a: &mut [i32], a_start: usize, buf: &[u8], buf_len: usize) -> usize {
        let mut ctr = 0;
        let mut pos = 0;

        while a_start + ctr < a.len() && pos < buf_len {
            let mut t0 = (buf[pos] as u32) & 0x0F;
            let mut t1 = (buf[pos] as u32) >> 4;
            pos += 1;

            if ETA == 2 {
                if t0 < 15 {
                    t0 = t0 - (205 * t0 >> 10) * 5;
                    a[a_start + ctr] = 2 - (t0 as i32);
                    ctr += 1;
                }
                if t1 < 15 && a_start + ctr < a.len() {
                    t1 = t1 - (205 * t1 >> 10) * 5;
                    a[a_start + ctr] = 2 - (t1 as i32);
                    ctr += 1;
                }
            } else if ETA == 4 {
                if t0 < 9 {
                    a[a_start + ctr] = 4 - (t0 as i32);
                    ctr += 1;
                }
                if t1 < 9 && a_start + ctr < a.len() {
                    a[a_start + ctr] = 4 - (t1 as i32);
                    ctr += 1;
                }
            }
        }

        ctr
    }

    let buf_len = POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES;
    let mut buf = [0u8; POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES];

    let mut hasher = Shake256::default();
    hasher.process(seed);
    let nonce0 = (nonce & ((1 << 8) - 1)) as u8;
    let nonce1 = (nonce >> 8) as u8;
    hasher.process(&[nonce0, nonce1]);
    let mut xof = hasher.xof_result();
    xof.read(&mut buf[..buf_len]);

    let mut ctr = rej_eta(a, 0, &buf, buf_len);

    while ctr < N {
        xof.read(&mut buf[..STREAM256_BLOCKBYTES]);
        ctr += rej_eta(a, ctr, &buf, STREAM256_BLOCKBYTES);
    }
}

/// Samples a polynomial with random coefficients in `[-(GAMMA1 - 1), GAMMA1]`.
///
/// The sampling is done by unpacking the first `POLZ_SIZE_PACKED` bytes in the
/// output stream of `SHAKE256(seed|nonce)`.
///
/// # Arguments
///
/// * `a` - the output polynomial
/// * `seed` - an array of random bytes
/// * `nonce` - a number.
pub fn uniform_gamma1m1(a: &mut Poly, seed: &[u8; CRHBYTES], nonce: u16) {
    use digest::{ExtendableOutput, Input, XofReader};
    use sha3::Shake256;
    const SHAKE256_RATE: usize = 136;

    let mut outbuf = [0; 5 * SHAKE256_RATE];
    let mut nonce_bytes = [0; 2];
    LittleEndian::write_u16(&mut nonce_bytes, nonce);

    let mut hasher = Shake256::default();
    hasher.process(seed);
    hasher.process(&nonce_bytes);

    let mut xof = hasher.xof_result();
    xof.read(&mut outbuf);

    z_unpack(a, array_ref!(&outbuf, 0, POLZ_SIZE_PACKED));
}

/// Returns a polynomial with coefficients in {0, -1, 1}.
///
/// Returns a polynomial sampled with `TAU` nonzero coefficients in
/// {-1, 1} and `N - TAU` zero coefficients using the output stream
/// of `SHAKE256(seed)`.
/// More details can be found in the paper, in section 2.3.
/// <https://eprint.iacr.org/2017/633.pdf>
///
/// # Arguments
///
/// * `seed` - an array of bytes
pub fn build_challenge_from_seed(seed: &[u8; SEEDBYTES]) -> Poly {
    use digest::{ExtendableOutput, Input, XofReader};
    use sha3::Shake256;
    const SHAKE256_RATE: usize = 136;

    let mut outbuf = [0u8; SHAKE256_RATE];

    let mut hasher = Shake256::default();
    hasher.process(seed);
    let mut xof = hasher.xof_result();
    xof.read(&mut outbuf);

    let mut signs: u64 = 0;
    for i in 0..8 {
        signs |= (outbuf[i] as u64) << 8 * i;
    }

    let mut pos = 8;
    let mut c = [0i32; N];
    for i in (N - TAU)..N {
        let b = loop {
            if pos >= SHAKE256_RATE {
                xof.read(&mut outbuf);
                pos = 0;
            }

            let b = outbuf[pos] as usize;
            pos += 1;
            if b <= i {
                break b;
            }
        };

        c[i] = c[b];
        c[b] = 1i32 - (2 * (signs & 1) as i32);
        signs >>= 1;
    }

    c
}

/// Bit-packs a polynomial with coefficients in `[-ETA, ETA]`.
///
/// # Arguments
///
/// * `r` - the output array, which will contain the polynomial's encoding
/// * `a` - the polynomial to encode
#[inline]
pub fn eta_pack(r: &mut [u8; POLETA_SIZE_PACKED], a: &Poly) {
    if ETA == 2 {
        let mut t = [0u8; 8];
        for i in 0..(N / 8) {
            for j in 0..8 {
                t[j] = (ETA - a[8 * i + j]) as u8;
            }

            r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
            r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
            r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
        }
    } else {
        let mut t = [0u8; 2];
        for i in 0..(N / 2) {
            t[0] = (ETA - a[2 * i + 0]) as u8;
            t[1] = (ETA - a[2 * i + 1]) as u8;
            r[i] = t[0] | (t[1] << 4);
        }
    }
}

/// Unpacks a polynomial with coefficients in `[-ETA, ETA]`.
///
/// # Arguments
///
/// * `r` - the output decoded polynomial
/// * `a` - the polynomial's encoding
#[inline]
pub fn eta_unpack(r: &mut Poly, a: &[u8; POLETA_SIZE_PACKED]) {
    if ETA == 2 {
        for i in 0..(N / 8) {
            r[8 * i + 0] = ((a[3 * i + 0] as i32) >> 0) & 7;
            r[8 * i + 1] = ((a[3 * i + 0] as i32) >> 3) & 7;
            r[8 * i + 2] = (((a[3 * i + 0] as i32) >> 6) | ((a[3 * i + 1] as i32) << 2)) & 7;
            r[8 * i + 3] = ((a[3 * i + 1] as i32) >> 1) & 7;
            r[8 * i + 4] = ((a[3 * i + 1] as i32) >> 4) & 7;
            r[8 * i + 5] = (((a[3 * i + 1] as i32) >> 7) | ((a[3 * i + 2] as i32) << 1)) & 7;
            r[8 * i + 6] = ((a[3 * i + 2] as i32) >> 2) & 7;
            r[8 * i + 7] = ((a[3 * i + 2] as i32) >> 5) & 7;

            for j in 0..8 {
                r[8 * i + j] = ETA - r[8 * i + j];
            }
        }
    } else {
        for i in 0..(N / 2) {
            r[2 * i + 0] = (a[i] as i32) & 0x0F;
            r[2 * i + 1] = (a[i] as i32) >> 4;
            r[2 * i + 0] = ETA - r[2 * i + 0];
            r[2 * i + 1] = ETA - r[2 * i + 1];
        }
    }
}

/// Bit-packs a polynomial with coefficients fitting in 10 bits.
///
/// # Arguments
///
/// * `r` - the output array, which will contain the polynomial's encoding
/// * `a` - the polynomial to encode
#[inline]
pub fn t1_pack(r: &mut [u8; POLT1_SIZE_PACKED], a: &Poly) {
    for i in 0..(N / 4) {
        r[5 * i + 0] = (a[4 * i + 0] >> 0) as u8;
        r[5 * i + 1] = ((a[4 * i + 0] >> 8) | (a[4 * i + 1] << 2)) as u8;
        r[5 * i + 2] = ((a[4 * i + 1] >> 6) | (a[4 * i + 2] << 4)) as u8;
        r[5 * i + 3] = ((a[4 * i + 2] >> 4) | (a[4 * i + 3] << 6)) as u8;
        r[5 * i + 4] = (a[4 * i + 3] >> 2) as u8;
    }
}

/// Unpacks a polynomial with coefficients fitting in 10 bits.
///
/// # Arguments
///
/// * `r` - the output decoded polynomial
/// * `a` - the polynomial's encoding
#[inline]
pub fn t1_unpack(r: &mut Poly, a: &[u8; POLT1_SIZE_PACKED]) {
    for i in 0..(N / 4) {
        r[4 * i + 0] =
            ((((a[5 * i + 0] >> 0) as u32) | ((a[5 * i + 1] as u32) << 8)) & 0x3FF) as i32;
        r[4 * i + 1] =
            ((((a[5 * i + 1] >> 2) as u32) | ((a[5 * i + 2] as u32) << 6)) & 0x3FF) as i32;
        r[4 * i + 2] =
            ((((a[5 * i + 2] >> 4) as u32) | ((a[5 * i + 3] as u32) << 4)) & 0x3FF) as i32;
        r[4 * i + 3] =
            ((((a[5 * i + 3] >> 6) as u32) | ((a[5 * i + 4] as u32) << 2)) & 0x3FF) as i32;
    }
}

/// Packs a polynomial with coefficients in `[-(GAMMA1 - 1), GAMMA1]`.
///
/// # Arguments
///
/// * `r` - the output array, which will contain the polynomial's encoding
/// * `a` - the polynomial to encode
#[inline]
pub fn z_pack(r: &mut [u8; POLZ_SIZE_PACKED], a: &Poly) {
    let mut t = [0u32; 4];

    if GAMMA1 == (1 << 17) {
        for i in 0..(N / 4) {
            for j in 0..4 {
                t[j] = (GAMMA1 - a[4 * i + j]) as u32;
            }

            r[9 * i + 0] = t[0] as u8;
            r[9 * i + 1] = (t[0] >> 8) as u8;
            r[9 * i + 2] = (t[0] >> 16) as u8;
            r[9 * i + 2] |= (t[1] << 2) as u8;
            r[9 * i + 3] = (t[1] >> 6) as u8;
            r[9 * i + 4] = (t[1] >> 14) as u8;
            r[9 * i + 4] |= (t[2] << 4) as u8;
            r[9 * i + 5] = (t[2] >> 4) as u8;
            r[9 * i + 6] = (t[2] >> 12) as u8;
            r[9 * i + 6] |= (t[3] << 6) as u8;
            r[9 * i + 7] = (t[3] >> 2) as u8;
            r[9 * i + 8] = (t[3] >> 10) as u8;
        }
    } else if GAMMA1 == (1 << 19) {
        for i in 0..(N / 2) {
            t[0] = (GAMMA1 - a[2 * i + 0]) as u32;
            t[1] = (GAMMA1 - a[2 * i + 1]) as u32;

            r[5 * i + 0] = t[0] as u8;
            r[5 * i + 1] = (t[0] >> 8) as u8;
            r[5 * i + 2] = (t[0] >> 16) as u8;
            r[5 * i + 2] |= (t[1] << 4) as u8;
            r[5 * i + 3] = (t[1] >> 4) as u8;
            r[5 * i + 4] = (t[1] >> 12) as u8;
        }
    }
}

/// Unpacks a polynomial with coefficients in `[-(GAMMA1 - 1), GAMMA1]`.
///
/// # Arguments
///
/// * `r` - the output decoded polynomial
/// * `a` - the polynomial's encoding
#[inline]
pub fn z_unpack(r: &mut Poly, a: &[u8; POLZ_SIZE_PACKED]) {
    if GAMMA1 == (1 << 17) {
        for i in 0..(N / 4) {
            r[4 * i + 0] = a[9 * i + 0] as i32;
            r[4 * i + 0] |= (a[9 * i + 1] as i32) << 8;
            r[4 * i + 0] |= (a[9 * i + 2] as i32) << 16;
            r[4 * i + 0] &= 0x3FFFF;

            r[4 * i + 1] = (a[9 * i + 2] >> 2) as i32;
            r[4 * i + 1] |= (a[9 * i + 3] as i32) << 6;
            r[4 * i + 1] |= (a[9 * i + 4] as i32) << 14;
            r[4 * i + 1] &= 0x3FFFF;

            r[4 * i + 2] = (a[9 * i + 4] >> 4) as i32;
            r[4 * i + 2] |= (a[9 * i + 5] as i32) << 4;
            r[4 * i + 2] |= (a[9 * i + 6] as i32) << 12;
            r[4 * i + 2] &= 0x3FFFF;

            r[4 * i + 3] = (a[9 * i + 6] >> 6) as i32;
            r[4 * i + 3] |= (a[9 * i + 7] as i32) << 2;
            r[4 * i + 3] |= (a[9 * i + 8] as i32) << 10;
            r[4 * i + 3] &= 0x3FFFF;

            for j in 0..4 {
                r[4 * i + j] = GAMMA1 - r[4 * i + j];
            }
        }
    } else if GAMMA1 == (1 << 19) {
        for i in 0..(N / 2) {
            r[2 * i + 0] = a[5 * i + 0] as i32;
            r[2 * i + 0] |= (a[5 * i + 1] as i32) << 8;
            r[2 * i + 0] |= (a[5 * i + 2] as i32) << 16;
            r[2 * i + 0] &= 0xFFFFF;

            r[2 * i + 1] = (a[5 * i + 2] >> 4) as i32;
            r[2 * i + 1] |= (a[5 * i + 3] as i32) << 4;
            r[2 * i + 1] |= (a[5 * i + 4] as i32) << 12;
            r[2 * i + 0] &= 0xFFFFF;

            r[2 * i + 0] = GAMMA1 - r[2 * i + 0];
            r[2 * i + 1] = GAMMA1 - r[2 * i + 1];
        }
    }
}

/// Bit-packs a polynomial with coefficients in `[0,15]` or `[0,43]`.
///
/// # Arguments
///
/// * `r` - the output array, which will contain the polynomial's encoding
/// * `a` - the polynomial to encode
#[inline]
pub fn w1_pack(r: &mut [u8; POLW1_SIZE_PACKED], a: &Poly) {
    if GAMMA2 == (Q - 1) / 88 {
        for i in 0..(N / 4) {
            r[3 * i + 0] = a[4 * i + 0] as u8;
            r[3 * i + 0] |= (a[4 * i + 1] << 6) as u8;
            r[3 * i + 1] = (a[4 * i + 1] >> 2) as u8;
            r[3 * i + 1] |= (a[4 * i + 2] << 4) as u8;
            r[3 * i + 2] = (a[4 * i + 2] >> 4) as u8;
            r[3 * i + 2] |= (a[4 * i + 3] << 2) as u8;
        }
    } else if GAMMA2 == (Q - 1) / 32 {
        for i in 0..(N / 2) {
            r[i] = (a[2 * i + 0] | (a[2 * i + 1] << 4)) as u8;
        }
    }
}

/// Bit-packs a polynomial `t0` with coefficients in `[-2^{D-1}, 2^{D-1}]`.
///
/// # Arguments
///
/// * `r` - the output array, which will contain the polynomial's encoding
/// * `a` - the polynomial to encode
#[inline]
pub fn t0_pack(r: &mut [u8], a: &Poly) {
    let mut t = [0u32; 8];
    for i in 0..(N / 8) {
        for j in 0..8 {
            t[j] = ((1 << (D - 1) as u32) - a[8 * i + j]) as u32;
        }

        r[13 * i + 0] = (t[0]) as u8;
        r[13 * i + 1] = (t[0] >> 8) as u8;
        r[13 * i + 1] |= (t[1] << 5) as u8;
        r[13 * i + 2] = (t[1] >> 3) as u8;
        r[13 * i + 3] = (t[1] >> 11) as u8;
        r[13 * i + 3] |= (t[2] << 2) as u8;
        r[13 * i + 4] = (t[2] >> 6) as u8;
        r[13 * i + 4] |= (t[3] << 7) as u8;
        r[13 * i + 5] = (t[3] >> 1) as u8;
        r[13 * i + 6] = (t[3] >> 9) as u8;
        r[13 * i + 6] |= (t[4] << 4) as u8;
        r[13 * i + 7] = (t[4] >> 4) as u8;
        r[13 * i + 8] = (t[4] >> 12) as u8;
        r[13 * i + 8] |= (t[5] << 1) as u8;
        r[13 * i + 9] = (t[5] >> 7) as u8;
        r[13 * i + 9] |= (t[6] << 6) as u8;
        r[13 * i + 10] = (t[6] >> 2) as u8;
        r[13 * i + 11] = (t[6] >> 10) as u8;
        r[13 * i + 11] |= (t[7] << 3) as u8;
        r[13 * i + 12] = (t[7] >> 5) as u8;
    }
}
