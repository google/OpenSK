extern crate rng256;

use super::*;
use params::{N, Q};
use poly::Poly;

const NTESTS: usize = 10000;

fn poly_naivemul(c: &mut Poly, a: &Poly, b: &Poly) {
    let mut r = [0; 2 * N];

    for i in 0..N {
        for j in 0..N {
            r[i + j] += (((a[i] as i64) * (b[j] as i64)) % (Q as i64)) as i32;
        }
    }

    for i in N..(2 * N) {
        r[i - N] = (r[i - N] - r[i]) % Q;
    }

    c.copy_from_slice(&r[..N]);
}

#[test]
fn test_mul() {
    use self::rng256::Rng256;

    let mut rndbuf = [0; 32];
    let mut c = [0; N];
    let (mut c1, mut c2) = ([0; N], [0; N]);
    let (mut a, mut b) = ([0; N], [0; N]);

    let mut rng = rng256::ThreadRng256 {};

    for _ in 0..NTESTS {
        rng.fill_bytes(&mut rndbuf);
        poly::uniform(&mut a, &rndbuf, 0);
        rng.fill_bytes(&mut rndbuf);
        poly::uniform(&mut b, &rndbuf, 0);

        c.copy_from_slice(&a[..N]);
        poly::ntt(&mut c);
        for j in 0..N {
            c[j] = ((c[j] as i64) * -114592 % (Q as i64)) as i32;
        }
        poly::invntt_montgomery(&mut c);

        for j in 0..N {
            assert_eq!((c[j] - a[j]) % Q, 0);
        }

        poly_naivemul(&mut c1, &a, &b);

        poly::ntt(&mut a);
        poly::ntt(&mut b);
        poly::pointwise_invmontgomery(&mut c2, &a, &b);
        poly::invntt_montgomery(&mut c2);

        for j in 0..N {
            assert_eq!((c1[j] - c2[j]) % Q, 0);
        }
    }
}
