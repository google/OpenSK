// TODO(dianamin): Try moving Polys on the heap using boxing.
// TODO(dianamin): Remove ": Poly" where it is not necessary.
// TODO(dianamin): Add a function that replaces let x: Poly = [0; N]

use packing;
use params::{
    BETA, CRHBYTES, GAMMA1, GAMMA2, K, L, N, OMEGA, PK_SIZE_PACKED, POLETA_SIZE_PACKED,
    POLT0_SIZE_PACKED, POLT1_SIZE_PACKED, POLW1_SIZE_PACKED, SEEDBYTES, SIG_SIZE_PACKED,
    SK_SIZE_PACKED, SK_SIZE_PACKED_ORIGINAL,
};
use poly::{self, Poly};
use polyvec::{self, PolyVecK, PolyVecL};

use digest::{ExtendableOutput, Input, XofReader};
use sha3::Shake256;

/// Helper function used both when signing and verifying.
///
/// Expands `A[i][j]` from the randomness seed `rho`.
///
/// # Arguments
///
/// * `rho` - an array of random bytes
/// * `i` - the index of the row
/// * `j` - the index of the column
/// * `mat_component` - the output polynomial representing `A[i][j]`
fn expand_mat_component(rho: &[u8; SEEDBYTES], i: usize, j: usize, mat_component: &mut Poly) {
    poly::uniform(mat_component, rho, ((i << 8) + j) as u16);
}

/// Helper function used when signing in optimized speed mode.
///
/// Expands the matrix `A` from the randomness seed `rho`.
///
/// # Arguments
///
/// * `rho` - an array of random bytes
/// * `mat` - a matrix of polynomials of `K` rows and `L` columns.
#[cfg(not(feature = "optimize_stack"))]
fn expand_mat(rho: &[u8; SEEDBYTES], mat: &mut [PolyVecL; K]) {
    for i in 0..K {
        for j in 0..L {
            expand_mat_component(rho, i, j, &mut mat[i][j]);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecKey {
    rho: [u8; SEEDBYTES],
    key: [u8; SEEDBYTES],
    tr: [u8; SEEDBYTES],
    s1_packed: [[u8; POLETA_SIZE_PACKED]; L],
    s2_packed: [[u8; POLETA_SIZE_PACKED]; K],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubKey {
    pub rho: [u8; SEEDBYTES],
    pub t1_packed: [[u8; POLT1_SIZE_PACKED]; K],
}

impl Default for SecKey {
    fn default() -> SecKey {
        SecKey {
            rho: [0; SEEDBYTES],
            key: [0; SEEDBYTES],
            tr: [0; SEEDBYTES],
            s1_packed: [[0; POLETA_SIZE_PACKED]; L],
            s2_packed: [[0; POLETA_SIZE_PACKED]; K],
        }
    }
}

impl SecKey {
    /// Encodes the secret key to an array of bytes.
    ///
    /// Fills the bytes array as follows:
    /// `rho || key || tr || encodings of s1 || encodings of s2`
    ///
    /// # Arguments
    ///
    /// * `bytes` - an array of bytes where the encoding will be stored.
    pub fn to_bytes(&self, bytes: &mut [u8; SK_SIZE_PACKED]) {
        let mut offset = 0;
        let mut push = |data: &[u8]| {
            bytes[offset..][..data.len()].copy_from_slice(data);
            offset += data.len();
        };

        push(&self.rho);
        push(&self.key);
        push(&self.tr);
        for i in 0..L {
            push(&self.s1_packed[i]);
        }
        for i in 0..K {
            push(&self.s2_packed[i]);
        }
    }

    /// Encodes the secret key to an array of bytes that includes `t0`.
    ///
    /// Fills the bytes array as follows:
    /// `rho || key || tr || encodings of s1 || encodings of s2 ||
    /// encodings of t0`
    ///
    /// # Arguments
    ///
    /// * `bytes` - an array of bytes where the encoding will be stored.
    pub fn to_bytes_original(&self, bytes: &mut [u8; SK_SIZE_PACKED_ORIGINAL]) {
        self.to_bytes(array_mut_ref!(bytes, 0, SK_SIZE_PACKED));

        let mut offset = SK_SIZE_PACKED;
        let mut push = |data: &[u8]| {
            bytes[offset..][..data.len()].copy_from_slice(data);
            offset += data.len();
        };

        #[cfg(feature = "optimize_stack")]
        {
            for i in 0..K {
                let t0_component = poly::power2round_remainder(&self.compute_t_component(i));

                let mut t0_bytes = [0u8; POLT0_SIZE_PACKED];
                poly::t0_pack(&mut t0_bytes, &t0_component);
                push(&t0_bytes);
            }
        }
        #[cfg(not(feature = "optimize_stack"))]
        {
            let mut mat = [PolyVecL::default(); K];
            expand_mat(&self.rho, &mut mat);
            let mut s1 = self.compute_s1();
            s1.ntt();
            let s2 = self.compute_s2();

            for i in 0..K {
                let t0_component =
                    poly::power2round_remainder(&self.compute_t_component(&mat, &s1, &s2, i));

                let mut t0_bytes = [0u8; POLT0_SIZE_PACKED];
                poly::t0_pack(&mut t0_bytes, &t0_component);
                push(&t0_bytes);
            }
        }
    }

    /// Decodes the secret key from an array of bytes.
    ///
    /// Extracts the fields from an array with the following shape:
    /// `rho || key || tr || encodings of s1 || encodings of s2`
    ///
    /// # Arguments
    ///
    /// * `bytes` - an array of byres representing the secret key's encoding.
    pub fn from_bytes(bytes: &[u8; SK_SIZE_PACKED]) -> SecKey {
        let mut offset = 0;
        let mut pull = |data: &mut [u8]| {
            data.copy_from_slice(&bytes[offset..][..data.len()]);
            offset += data.len();
        };

        let mut sk = SecKey::default();

        pull(&mut sk.rho);
        pull(&mut sk.key);
        pull(&mut sk.tr);

        for i in 0..L {
            pull(&mut sk.s1_packed[i]);
        }
        for i in 0..K {
            pull(&mut sk.s2_packed[i]);
        }

        sk
    }

    /// Decodes the secret key from an array of bytes that includes `t0`.
    ///
    /// Extracts the fields from an array with the following shape:
    /// `rho || key || tr || encodings of s1 || encodings of s2 || encodings of t0`,
    /// which is the original shape of the secret key in Dilithium.
    /// In our implementation, the encodings of `t0` are removed.
    ///
    /// # Arguments
    ///
    /// * `bytes` - an array of byres representing the secret key's encoding.
    pub fn from_bytes_original(bytes: &[u8; SK_SIZE_PACKED_ORIGINAL]) -> SecKey {
        Self::from_bytes(array_ref!(&bytes, 0, SK_SIZE_PACKED))
    }

    /// Returns the public key.
    pub fn genpk(&self) -> PubKey {
        let mut pk = PubKey::default();
        pk.rho = self.rho.clone();

        // Compute t = A * s1 + s2
        // And extract t1: the quotient of t / 2^D

        #[cfg(feature = "optimize_stack")]
        {
            for i in 0..K {
                let t1_component = poly::power2round_quotient(&self.compute_t_component(i));
                poly::t1_pack(&mut pk.t1_packed[i], &t1_component);
            }
        }

        #[cfg(not(feature = "optimize_stack"))]
        {
            let mut mat = [PolyVecL::default(); K];
            expand_mat(&self.rho, &mut mat);

            let mut s1 = self.compute_s1();
            s1.ntt();
            let s2 = self.compute_s2();
            for i in 0..K {
                let t1_component =
                    poly::power2round_quotient(&self.compute_t_component(&mat, &s1, &s2, i));
                poly::t1_pack(&mut pk.t1_packed[i], &t1_component);
            }
        }

        pk
    }

    /// Generates a new secret key.
    ///
    /// # Arguments
    ///
    /// * `rng` - random number generator.
    pub fn gensk(rng: &mut impl rng256::Rng256) -> Self {
        let (sk, _) = Self::gensk_with_pk(rng);
        sk
    }

    /// Generates a new secret key and a new public key.
    ///
    /// # Arguments
    ///
    /// * `rng` - random number generator.
    pub fn gensk_with_pk(rng: &mut impl rng256::Rng256) -> (Self, PubKey) {
        let mut seed = [0u8; SEEDBYTES];
        rng.fill_bytes(&mut seed);
        Self::gensk_with_pk_from_seed(&seed)
    }

    /// Generates a new secret key from a given random seed.
    ///
    /// # Arguments
    ///
    /// * `seedbuff` - a random seed.
    pub fn gensk_from_seed(seed: &[u8; SEEDBYTES]) -> Self {
        let (sk, _) = Self::gensk_with_pk_from_seed(&seed);
        sk
    }

    /// Generates a new secret key and public key from a given random seed.
    ///
    /// # Arguments
    ///
    /// * `seedbuff` - a random seed.
    pub fn gensk_with_pk_from_seed(seed: &[u8; SEEDBYTES]) -> (Self, PubKey) {
        let mut sk = SecKey::default();
        let mut pk = PubKey::default();

        // Expand 32 bytes of randomness into rho, rhoprime and key.
        let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
        seedbuf[..SEEDBYTES].copy_from_slice(seed);
        shake256!(&mut seedbuf; &seedbuf[..SEEDBYTES]);
        sk.rho.clone_from(array_ref!(seedbuf, 0, SEEDBYTES));
        sk.key
            .clone_from(array_ref!(seedbuf, SEEDBYTES + CRHBYTES, SEEDBYTES));
        let rhoprime = array_ref!(seedbuf, SEEDBYTES, CRHBYTES);
        let mut nonce = 0;

        pk.rho = sk.rho;

        // In the optimized stack mode, we store as few variables as possible.
        // Because of that, some of the variables will be recomputed.
        #[cfg(feature = "optimize_stack")]
        {
            // Expand the short vector s1 from rhoprime and store the encoding
            //  of each s1[i] in the secret key.
            for i in 0..L {
                let mut s1_component: Poly = [0; N];
                poly::uniform_eta(&mut s1_component, rhoprime, nonce);
                poly::eta_pack(&mut sk.s1_packed[i], &s1_component);
                nonce += 1;
            }

            // Expand the short vector s2 from rhoprime and store the encoding
            // of each s2[i] in the secret key.
            for i in 0..K {
                let mut s2_component: Poly = [0; N];
                poly::uniform_eta(&mut s2_component, rhoprime, nonce);
                poly::eta_pack(&mut sk.s2_packed[i], &s2_component);
                nonce += 1;
            }

            // Computes t1: the quotient of t (= A * s1 + s2) / 2^D.
            for i in 0..K {
                let t1_component = poly::power2round_quotient(&sk.compute_t_component(i));
                poly::t1_pack(&mut pk.t1_packed[i], &t1_component);
            }
        }

        // In the optimized speed mode, the variables are computed and stored.
        #[cfg(not(feature = "optimize_stack"))]
        {
            // Expand the short vector s1 from rhoprime and store the encoding
            //  of each s1[i] in the secret key.
            let mut s1 = PolyVecL::default();
            for i in 0..L {
                poly::uniform_eta(&mut s1[i], rhoprime, nonce);
                poly::eta_pack(&mut sk.s1_packed[i], &s1[i]);
                nonce += 1;
            }

            // Expand the short vector s2 from rhoprime and store the encoding
            // of each s2[i] in the secret key.
            let mut s2 = PolyVecK::default();
            for i in 0..K {
                poly::uniform_eta(&mut s2[i], rhoprime, nonce);
                poly::eta_pack(&mut sk.s2_packed[i], &s2[i]);
                nonce += 1;
            }

            // Computes t1: the quotient of t (= A * s1 + s2) / 2^D.
            let mut mat = [PolyVecL::default(); K];
            expand_mat(&sk.rho, &mut mat);
            s1.ntt();
            for i in 0..K {
                let t1_component =
                    poly::power2round_quotient(&sk.compute_t_component(&mat, &s1, &s2, i));
                poly::t1_pack(&mut pk.t1_packed[i], &t1_component);
            }
        }

        // Compute tr = CRH(rho || encodings of t1)
        let mut hasher = Shake256::default();
        hasher.process(&sk.rho);
        for i in 0..K {
            hasher.process(&pk.t1_packed[i]);
        }

        let mut xof = hasher.xof_result();
        xof.read(&mut sk.tr);

        (sk, pk)
    }

    /// Returns a random polynomial `y[i]`.
    ///
    /// Computes the `i`-th component of `y`, where:
    /// - `y` is a vector of polynomials 'sampled' when signing using
    /// `rhoprime` (based on`key`, `mu`, `nonce`)
    ///
    /// # Arguments
    ///
    /// * `rhoprime` - an array of bytes obrained as `SHA256(key || mu)`
    /// * `nonce` - current count of the attempts to sign the given message
    /// * `i` - the index of the `y` component to be computed
    fn compute_y_component(&self, rhoprime: &[u8; CRHBYTES], nonce: u16, i: u16) -> Poly {
        let mut y_component: Poly = [0; N];
        // y[i]: poly_uniform_gamma1(&y->vec[i], seed, L*nonce + i);
        let nonce = (L as u16 * nonce + i) as u16;
        poly::uniform_gamma1m1(&mut y_component, rhoprime, nonce);
        y_component
    }

    /// Returns a random vector of `L` polynomials `y`.
    ///
    /// Computes the polynomial of vectors `y`, where:
    /// - `y` is a vector of polynomials 'sampled' when signing using
    /// `rhoprime` (based on`key`, `mu`, `nonce`)
    ///
    /// # Arguments
    ///
    /// * `rhoprime` - an array of bytes obrained as `SHA256(key || mu)`
    /// * `nonce` - current count of the attempts to sign the given message
    #[cfg(not(feature = "optimize_stack"))]
    fn compute_y(&self, rhoprime: &[u8; CRHBYTES], nonce: u16) -> PolyVecL {
        let mut y = PolyVecL::default();
        for i in 0..L {
            y[i] = self.compute_y_component(rhoprime, nonce, i as u16)
        }
        y
    }

    /// Returns the `i`-th component of `w =  A * y`.
    ///
    /// Here:
    /// - `A` is a matrix (part of the key): expanded from `rho`
    /// - `y` is a vector of polynomials 'sampled' when signing using `rhoprime`
    ///
    /// Note that here `A` and `y` get recomputed in order to minimize the
    /// stack usage.
    ///
    /// # Arguments
    ///
    /// * `rhoprime` - an array of bytes obrained as `SHA256(key || mu)`
    /// * `nonce` - current count of the attempts to sign the given message
    /// * `i` - the index of the `w` component to be computed
    #[cfg(feature = "optimize_stack")]
    fn compute_w_component(&self, rhoprime: &[u8; CRHBYTES], nonce: u16, i: usize) -> Poly {
        let mut w_component: Poly = [0; N];

        // w[i] = sum_j of A[i][j] * y[j]
        for j in 0..L {
            let mut y_component = self.compute_y_component(rhoprime, nonce, j as u16);
            // nonce = nonce + 1;
            poly::ntt(&mut y_component);

            // Expand the matrix and matrix-vector multiplication
            let mut mat_component: Poly = [0; N];
            expand_mat_component(&self.rho, i, j, &mut mat_component);
            polyvec::pointwise_acc_invmontgomery_componentwise(
                &mut w_component,
                &mat_component,
                &y_component,
                j,
            );
        }
        poly::reduce(&mut w_component);
        poly::invntt_montgomery(&mut w_component);
        poly::caddq(&mut w_component);
        return w_component;
    }

    /// Returns the vector of `K` polynomials `w =  A * y`.
    ///
    /// Here:
    /// - `A` is a matrix (part of the key): expanded from `rho`
    /// - `y` is a vector of polynomials 'sampled' when signing using `rhoprime`
    ///
    /// In order to optimize the speed, we take `A` and `y` as parameters.
    ///
    /// # Arguments
    ///
    /// * `mat` - the matrix `A`
    /// * `y` - the vector of polynomials `y`
    #[cfg(not(feature = "optimize_stack"))]
    fn compute_w(&self, mat: &[PolyVecL; K], y: &PolyVecL) -> PolyVecK {
        let mut w = PolyVecK::default();
        let mut yhat = y.clone();
        yhat.ntt();
        for i in 0..K {
            polyvec::pointwise_acc_invmontgomery(&mut w[i], &mat[i], &yhat);
        }

        w.reduce();
        w.invntt_montgomery();
        w.caddq();

        w
    }

    /// Returns t[i], where `t = A * s1 + s2`, when optimizing stack usage.
    ///
    /// Here:
    /// - `A` is a matrix (part of the key): expanded from `rho`
    /// - `s1` is a vector of polynomials (part of the key)
    /// - `s2` is a vector of polynomials (part of the key)
    ///
    /// Note that this function recomputes `A`, `s1`, and `s2` in order to
    /// optimize the stack usage.
    ///
    /// # Arguments
    /// * `i` - the index of the `t` component to be computed
    #[cfg(feature = "optimize_stack")]
    fn compute_t_component(&self, i: usize) -> Poly {
        let mut t_component: Poly = [0; N];
        // Sample the matrix A and compute t[i] = sum_j A[i][j] * s1[j]
        for j in 0..L {
            // Resample s1[j]
            let mut s1_component = self.compute_s1_component(j);
            poly::ntt(&mut s1_component);

            let mut mat_component: Poly = [0; N];
            expand_mat_component(&self.rho, i, j, &mut mat_component);

            polyvec::pointwise_acc_invmontgomery_componentwise(
                &mut t_component,
                &mat_component,
                &s1_component,
                j,
            );
        }

        poly::reduce(&mut t_component);
        poly::invntt_montgomery(&mut t_component);

        // Unpack s2[i], compute t[i] = sum_j A[i][j] * s1[j] + s2[i]
        {
            let s2_component = self.compute_s2_component(i);
            poly::add_assign(&mut t_component, &s2_component);
        }
        poly::caddq(&mut t_component);

        t_component
    }

    /// Returns t[i], where `t = A * s1 + s2`, when optimizing speed.
    ///
    /// Here:
    /// - `A` is a matrix (part of the key): expanded from `rho`
    /// - `s1` is a vector of polynomials (part of the key)
    /// - `s2` is a vector of polynomials (part of the key)
    ///
    /// In order to optimize the speed, we take `A`, `s1` and `s2` as
    /// parameters.
    ///
    /// # Arguments
    /// * `mat` - the matrix `A`
    /// * `s1` - a vector of `L` polynomials in NTT format
    /// * `s2` - a vector of `K` polynomials in standard format
    /// * `i` - the index of the `t` component to be computed
    #[cfg(not(feature = "optimize_stack"))]
    fn compute_t_component(
        &self,
        mat: &[PolyVecL; K],
        s1: &PolyVecL,
        s2: &PolyVecK,
        i: usize,
    ) -> Poly {
        let mut t_component: Poly = [0; N];

        polyvec::pointwise_acc_invmontgomery(&mut t_component, &mat[i], &s1);
        poly::reduce(&mut t_component);
        poly::invntt_montgomery(&mut t_component);
        poly::add_assign(&mut t_component, &s2[i]);
        poly::caddq(&mut t_component);

        t_component
    }

    /// Returns the the vector of `K` polynomials `t = A * s1 + s2`.
    ///
    /// Here:
    /// - `A` is a matrix (part of the key): expanded from `rho`
    /// - `s1` is a vector of polynomials (part of the key)
    /// - `s2` is a vector of polynomials (part of the key)
    ///
    /// In order to optimize the speed, we take `A`, `s1` and `s2` as
    /// parameters.
    ///
    /// # Arguments
    /// * `mat` - the matrix `A`
    /// * `s1` - a vector of `L` polynomials in NTT format
    /// * `s2` - a vector of `K` polynomials in standard format
    #[cfg(not(feature = "optimize_stack"))]
    fn compute_t(&self, mat: &[PolyVecL; K], s1: &PolyVecL, s2: &PolyVecK) -> PolyVecK {
        let mut t = PolyVecK::default();

        for i in 0..K {
            t[i] = self.compute_t_component(mat, s1, s2, i);
        }

        t
    }

    /// Returns the seed for generating the challenge polynomial.
    ///
    /// The seed is obtained as `SHA256(mu || encodings of 'commit' w1)`, where:
    /// - `w1` contains the high bits of `w = A * y`
    /// - `A` is a matrix (part of the key): expanded from `rho`
    /// - `y` is a vector of polynomials 'sampled' when signing using `rhoprime`.
    ///
    /// In order to optimize the stack usage, this function recomputes `w`.
    ///
    /// # Arguments
    ///
    /// * `mu` - array of bytes containing the hashed input message
    /// * `rhoprime` - an array of bytes obrained as `SHA256(key || mu)`
    /// * `nonce` - current count of the attempts to sign the given message
    #[cfg(feature = "optimize_stack")]
    fn compute_c_seed(
        &self,
        mu: &[u8; CRHBYTES],
        rhoprime: &[u8; CRHBYTES],
        nonce: u16,
    ) -> [u8; SEEDBYTES] {
        let mut hasher = Shake256::default();
        hasher.process(mu);
        for i in 0..K {
            let w1_component = {
                let w_component = self.compute_w_component(rhoprime, nonce, i);
                poly::high_bits(&w_component)
            };
            let mut pack = [0; POLW1_SIZE_PACKED];
            poly::w1_pack(&mut pack, &w1_component);
            hasher.process(&pack);
        }

        let mut xof = hasher.xof_result();
        let mut seed = [0u8; SEEDBYTES];
        xof.read(&mut seed);
        seed
    }

    /// Returns the seed for generating the challenge polynomial.
    ///
    /// The seed is obtained as `SHA256(mu || encodings of 'commit' w1)`, where:
    /// - `w1` contains the high bits of `w = A * y`
    /// - `A` is a matrix (part of the key): expanded from `rho`
    /// - `y` is a vector of polynomials 'sampled' when signing using `rhoprime`.
    ///
    /// In order to optimize the speed, we take `w1` as a parameter.
    ///
    /// # Arguments
    ///
    /// * `mu` - array of bytes containing the hashed input message
    /// * `w1` - an array of `K` polynomials.
    #[cfg(not(feature = "optimize_stack"))]
    fn compute_c_seed(&self, mu: &[u8; CRHBYTES], w1: &PolyVecK) -> [u8; SEEDBYTES] {
        let mut hasher = Shake256::default();
        hasher.process(mu);
        for i in 0..K {
            let mut pack = [0; POLW1_SIZE_PACKED];
            poly::w1_pack(&mut pack, &w1[i]);
            hasher.process(&pack);
        }

        let mut xof = hasher.xof_result();
        let mut seed = [0u8; SEEDBYTES];
        xof.read(&mut seed);
        seed
    }

    /// Returns the `i`-th component of `s1` (part of the sk).
    ///
    /// # Arguments
    /// * `i` - the index of the `s1` component to be computed
    fn compute_s1_component(&self, i: usize) -> Poly {
        let mut s1_component = [0; N];
        poly::eta_unpack(&mut s1_component, &self.s1_packed[i]);
        s1_component
    }

    /// Returns the vector of `L` polynomials `s1` (part of sk).
    #[cfg(not(feature = "optimize_stack"))]
    fn compute_s1(&self) -> PolyVecL {
        let mut s1 = PolyVecL::default();

        for i in 0..L {
            s1[i] = self.compute_s1_component(i);
        }

        s1
    }

    /// Returns the `i`-th component of `s2` (part of the sk).
    ///
    /// # Arguments
    /// * `i` - the index of the `s1` component to be computed
    fn compute_s2_component(&self, i: usize) -> Poly {
        let mut s2_component = [0; N];
        poly::eta_unpack(&mut s2_component, &self.s2_packed[i]);
        s2_component
    }

    /// Returns the vector of `K` polynomials `s2` (part of sk).
    #[cfg(not(feature = "optimize_stack"))]
    fn compute_s2(&self) -> PolyVecK {
        let mut s2 = PolyVecK::default();
        for i in 0..K {
            s2[i] = self.compute_s2_component(i);
        }
        s2
    }

    /// Returns the `i`-th component of `z = y + c * s1`.
    ///
    /// Here:
    /// - `y` is a vector of polynomials 'sampled' when signing using `rhoprime`
    /// - `c` is the challenge polynomial based on `H(mu || 'commit' w1)`
    /// - `s1` is part of the secret key
    ///
    /// Note that this function recomputes s1 and y in order to optimize the
    /// stack usage.
    ///
    /// # Arguments
    ///
    /// * `rhoprime` - an array of bytes obrained as `SHA256(key || mu)`
    /// * `c` - a polynomial in NTT format
    /// * `nonce` - current count of the attempts to sign the given message
    /// * `i` - the index of the `z` component to be computed
    #[cfg(feature = "optimize_stack")]
    fn compute_z_component(
        &self,
        rhoprime: &[u8; CRHBYTES],
        c: &Poly,
        nonce: u16,
        i: usize,
    ) -> Option<Poly> {
        let mut z_component: Poly;
        // Compute c * s1.
        {
            let mut s1_component = self.compute_s1_component(i);
            poly::ntt(&mut s1_component);
            z_component = poly::multiply(&c, &s1_component);
        }

        // Sample a component of the intermediate vector y and compute c * s1 + y.
        {
            let y_component = self.compute_y_component(rhoprime, nonce, i as u16);
            poly::add_assign(&mut z_component, &y_component);
        }
        poly::reduce(&mut z_component);

        // Reject if z reveals secret.
        if poly::chknorm(&z_component, GAMMA1 - BETA) {
            None
        } else {
            Some(z_component)
        }
    }

    /// Returns the vector of `L` polynomials `z = c * s1 + y`.
    ///
    /// Here:
    /// - `y` is a vector of polynomials 'sampled' when signing using `rhoprime`
    /// - `c` is the challenge polynomial based on `H(mu || 'commit' w1)`
    /// - `s1` is part of the secret key
    ///
    /// In order to optimize the speed, we take `s1` and `y` as parameters
    /// instead of recomputing them.
    ///
    /// # Arguments
    ///
    /// * `c` - a polynomial in NTT format
    /// * `s1` - a vector of `L` polynomials in NTT format
    /// * `y` - a vector of `L` polynomials in standard format
    #[cfg(not(feature = "optimize_stack"))]
    fn compute_z(&self, c: &Poly, s1: &PolyVecL, y: &PolyVecL) -> Option<PolyVecL> {
        let mut z = PolyVecL::default();
        for i in 0..L {
            z[i] = poly::multiply(&c, &s1[i]);
        }

        z.add_assign(y);
        z.reduce();
        if z.chknorm(GAMMA1 - BETA) {
            None
        } else {
            Some(z)
        }
    }

    /// Returns the `i`-th component of `w0cs2 = w0 - c * s2`.
    ///
    /// Here:
    /// - `w0` contains the low bits of `w = A * y`
    /// - `c` is the challenge polynomial based on `H(mu || 'commit' w1)`
    /// - `s2` is part of the secret key
    ///
    /// Note that this function recomputes s2 to minimize the stack usage.
    ///
    /// # Arguments
    ///
    /// * `rhoprime` - an array of bytes obrained as `SHA256(key || mu)`
    /// * `c` - a polynomial in NTT format
    /// * `nonce` - current count of the attempts to sign the given message
    /// * `i` - the index of the `w0cs2` component to be computed
    #[cfg(feature = "optimize_stack")]
    fn compute_w0cs2_component(&self, w_component: &Poly, c: &Poly, i: usize) -> Option<Poly> {
        let mut w0cs2_component: Poly = [0; N];
        {
            // c * s2
            let cs2_component: Poly;
            {
                let mut s2_component = self.compute_s2_component(i);
                poly::ntt(&mut s2_component);
                cs2_component = poly::multiply(&c, &s2_component);
            }

            // w0cs2 = w0 - cs2 = w0 - c * s2
            {
                let w0_component = poly::low_bits(&w_component);
                poly::sub(&mut w0cs2_component, &w0_component, &cs2_component);
            }

            poly::reduce(&mut w0cs2_component);
        }

        // Reject the attempt if the norm of w0cs2 is too high.
        if poly::chknorm(&w0cs2_component, GAMMA2 - BETA) {
            None
        } else {
            Some(w0cs2_component)
        }
    }

    /// Returns the vector of `K` polynomials `w0cs2 = w0 - c * s2`.
    ///
    /// Here:
    /// - `w0` contains the low bits of `w = A * y`
    /// - `c` is the challenge polynomial based on `H(mu || 'commit' w1)`
    /// - `s2` is part of the secret key
    ///
    /// In order to optimize the speed, we take `w0` and `s2` as parameters
    /// instead of recomputing them.
    ///
    /// # Arguments
    ///
    /// * `w0` - an array of `K` polynomials
    /// * `c` - a polynomial in NTT format
    /// * `s2` - a vector of K polynomials in NTT format
    #[cfg(not(feature = "optimize_stack"))]
    fn compute_w0cs2(&self, w0: &PolyVecK, c: &Poly, s2: &PolyVecK) -> Option<PolyVecK> {
        // Compute c * s2
        let mut cs2 = PolyVecK::default();
        for i in 0..K {
            cs2[i] = poly::multiply(&c, &s2[i]);
        }

        // Compute w0 - cs2
        let mut w0cs2 = PolyVecK::default();
        w0cs2.with_sub(&w0, &cs2);
        w0cs2.reduce();

        if w0cs2.chknorm(GAMMA2 - BETA) {
            None
        } else {
            Some(w0cs2)
        }
    }

    /// Returns the i-th component of `ct0 = c * t0`.
    ///
    /// Here:
    /// - `c` is the challenge polynomial based on `H(mu || 'commit' w1)`
    /// - `t0` is `t mod 2^D`, where `t = A * s1 + s2`
    ///
    /// Note that this function recomputes `A`, `s1`, and `s2`, in order to
    /// minimize the stack usage.
    ///
    /// # Arguments
    ///
    /// * `c` - a polynomial in NTT format
    /// * `i` - the index of the `ct0` component to be computed
    #[cfg(feature = "optimize_stack")]
    fn compute_ct0_component(&self, c: &Poly, i: usize) -> Option<Poly> {
        let ct0_component: Poly;
        {
            let mut t0_component = poly::power2round_remainder(&self.compute_t_component(i));
            poly::ntt(&mut t0_component);
            ct0_component = poly::multiply(&c, &t0_component);
        }

        if poly::chknorm(&ct0_component, GAMMA2) {
            None
        } else {
            Some(ct0_component)
        }
    }

    /// Returns the vector of `K` polynomials `ct0 = c * t0`.
    ///
    /// Here:
    /// - `c` is the challenge polynomial based on `H(mu || 'commit' w1)`
    /// - `t0` is `t mod 2^D`, where `t = A * s1 + s2`
    ///
    /// This function takes `A`, `s1` and `s2` as parameters in order to
    /// compute `t` with optimize speed.
    ///
    /// # Arguments
    /// * `c` - a polynomial in NTT format
    /// * `mat` - the matrix `A`
    /// * `s1` - a vector of `L` polynomials in NTT format
    /// * `s2` - a vector of `K` polynomials
    #[cfg(not(feature = "optimize_stack"))]
    fn compute_ct0(
        &self,
        c: &Poly,
        mat: &[PolyVecL; K],
        s1: &PolyVecL,
        s2: &PolyVecK,
    ) -> Option<PolyVecK> {
        let t = self.compute_t(mat, s1, s2);
        let mut t0 = PolyVecK::default();
        t.power2round_remainder(&mut t0);
        t0.ntt();
        let mut ct0 = PolyVecK::default();
        for i in 0..K {
            ct0[i] = poly::multiply(&c, &t0[i]);
        }

        ct0.reduce();
        if ct0.chknorm(GAMMA2) {
            None
        } else {
            Some(ct0)
        }
    }

    /// Attempts to compute a signature with the given parameters.
    ///
    /// The signature is computed deterministically using:
    /// - `mu`(the hashed message)
    /// - the `nonce`
    ///
    /// This function aims to minimize the stack usage, at the cost of speed.
    ///
    /// # Arguments
    ///
    /// * `mu` - array containing the hashed input message
    /// * `nonce` - current count of the attempts to sign the given message
    #[cfg(feature = "optimize_stack")]
    fn try_sign_with_nonce(
        &self,
        mu: &[u8; CRHBYTES],
        nonce: u16,
    ) -> Option<[u8; SIG_SIZE_PACKED]> {
        let mut sig = [0; SIG_SIZE_PACKED];

        let mut rhoprime = [0u8; CRHBYTES];
        shake256!(&mut rhoprime; &self.key, mu);

        let c_seed = self.compute_c_seed(mu, &rhoprime, nonce);
        let mut chat: Poly = poly::build_challenge_from_seed(&c_seed);
        packing::sign::pack_c(&mut sig, &c_seed);
        poly::ntt(&mut chat);

        let mut hint = 0;
        let mut hint_non_zero_coeff_index = 0;

        for i in 0..K {
            // The verifier needs the hint for the difference between
            // tmp = w0 - c * s2 + c * t0 and w1 to recompute w.
            let mut h_component: Poly = [0; N];
            {
                // Recompute the i-th component of w1: the high bits of w = A * y
                let w_component: Poly = self.compute_w_component(&rhoprime, nonce, i);

                // Compute i-th component of w0cs2 = w0 - c * s2, where w0 = the low bits of w
                let w0cs2_component: Poly = self.compute_w0cs2_component(&w_component, &chat, i)?;

                let mut tmp_component: Poly = [0; N];
                {
                    // Compute the i-th component of ct0 = c * t0
                    let ct0_component: Poly = self.compute_ct0_component(&chat, i)?;
                    poly::add(&mut tmp_component, &w0cs2_component, &ct0_component);
                }

                let w1_component = poly::high_bits(&w_component);

                hint += poly::make_hint(&tmp_component, &w1_component, &mut h_component);
            }

            if hint > OMEGA {
                return None;
            }

            packing::sign::pack_h_component(
                &mut sig,
                &h_component,
                i,
                &mut hint_non_zero_coeff_index,
            );
        }

        // Computing z = y + cs1
        for i in 0..L {
            let z_component: Poly = self.compute_z_component(&rhoprime, &chat, nonce, i)?;
            packing::sign::pack_z_component(&mut sig, &z_component, i);
        }

        Some(sig)
    }

    /// Attempts to compute a signature with the given parameters.
    ///
    /// The signature is computed deterministically using:
    /// - `mu`(the hashed message)
    /// - the `nonce`
    ///
    /// This function aims to minimize the speed, at the cost of stack usage.
    ///
    /// # Arguments
    ///
    /// * `mu` - array containing the hashed input message
    /// * `nonce` - current count of the attempts to sign the given message
    #[cfg(not(feature = "optimize_stack"))]
    fn try_sign_with_nonce(
        &self,
        mu: &[u8; CRHBYTES],
        nonce: u16,
    ) -> Option<[u8; SIG_SIZE_PACKED]> {
        let mut rhoprime = [0u8; CRHBYTES];
        shake256!(&mut rhoprime; &self.key, mu);

        let mut sig = [0; SIG_SIZE_PACKED];

        // Sample intermediate vector
        let y = self.compute_y(&rhoprime, nonce);

        // Matrix-vector multiplication
        let mut mat = [PolyVecL::default(); K];
        expand_mat(&self.rho, &mut mat);

        let w = self.compute_w(&mat, &y);

        // Decompose w and call the random oracle
        let (mut w0, mut w1) = (PolyVecK::default(), PolyVecK::default());
        w.decompose(&mut w0, &mut w1);

        // Compute challenge
        let c_seed = self.compute_c_seed(mu, &w1);
        packing::sign::pack_c(&mut sig, &c_seed);
        let mut c: Poly = poly::build_challenge_from_seed(&c_seed);
        poly::ntt(&mut c);

        // Compute z, reject if it reveals secret
        let mut s1 = self.compute_s1();
        s1.ntt();
        let z = self.compute_z(&c, &s1, &y)?;
        packing::sign::pack_z(&mut sig, &z);

        // Compute ct0 = c * t0
        let mut s2 = self.compute_s2();
        let ct0 = self.compute_ct0(&c, &mat, &s1, &s2)?;

        // Compute w0 - c * s2, reject if w1 can not be computed from it
        s2.ntt();
        let w0cs2 = self.compute_w0cs2(&w0, &c, &s2)?;

        // The verifier needs the hint for the difference between
        // tmp = w0 - c * s2 + c * t0 and w1 to recompute w.
        let mut tmp = PolyVecK::default();
        tmp.with_add(&w0cs2, &ct0);
        let mut h = PolyVecK::default();
        let hint = polyvec::make_hint(&tmp, &w1, &mut h);
        if hint > OMEGA {
            return None;
        };
        packing::sign::pack_h(&mut sig, &h);

        return Some(sig);
    }

    /// Returns a signature for the given message.
    ///
    /// # Arguments
    ///
    /// * `m` - the message to be signed.
    pub fn sign(&self, m: &[u8]) -> [u8; SIG_SIZE_PACKED] {
        // Compute CRH(tr, msg)
        let mut mu = [0u8; CRHBYTES];
        shake256!(&mut mu; &self.tr, m);

        let mut nonce = 0;

        // The probability that multiple iterations are needed is very low.
        // More details can be found in section 3.2:
        // https://eprint.iacr.org/2017/633.pdf
        // TODO(dianamin): Add an artificial break after some number of iterations.
        loop {
            match self.try_sign_with_nonce(&mu, nonce) {
                Some(sig) => break sig,
                None => nonce = nonce + 1 as u16,
            }
        }
    }
}

impl Default for PubKey {
    fn default() -> PubKey {
        PubKey {
            rho: [0; SEEDBYTES],
            t1_packed: [[0; POLT1_SIZE_PACKED]; K],
        }
    }
}

impl PubKey {
    /// Encodes the public key into an array of bytes.
    ///
    /// Fills the bytes array as follows:
    /// `rho || encodings of t1`
    ///
    /// # Arguments
    ///
    /// * `bytes` - an array of bytes where the encoding will be stored.
    pub fn to_bytes(&self, bytes: &mut [u8; PK_SIZE_PACKED]) {
        let mut offset = 0;
        let mut push = |data: &[u8]| {
            bytes[offset..][..data.len()].copy_from_slice(data);
            offset += data.len();
        };

        push(&self.rho);
        for i in 0..K {
            push(&self.t1_packed[i]);
        }
    }

    /// Decodes the public key from an array of bytes.
    ///
    /// Extracts the fields from a bytes array with the following shape:
    /// `rho || encodings of t1`
    ///
    /// # Arguments
    ///
    /// * `bytes` - the array of bytes containing the encoding.
    pub fn from_bytes(bytes: &[u8; PK_SIZE_PACKED]) -> PubKey {
        let mut offset = 0;
        let mut pull = |data: &mut [u8]| {
            data.copy_from_slice(&bytes[offset..][..data.len()]);
            offset += data.len();
        };

        let mut pk = PubKey::default();
        pull(&mut pk.rho);
        for i in 0..K {
            pull(&mut pk.t1_packed[i]);
        }
        pk
    }

    /// Computes the seed needed to generate c: `SHA256(mu || encodings of w1)`.
    ///
    /// # Arguments
    ///
    /// * `mu` - the hashed message
    /// * `w1` - a vector of `K` polynomials
    fn compute_c_seed(&self, mu: &[u8; CRHBYTES], w1: &PolyVecK) -> [u8; SEEDBYTES] {
        let mut outbuf = [0u8; SEEDBYTES];
        let mut w1pack = [0u8; K * POLW1_SIZE_PACKED];
        for (i, pack) in w1pack.chunks_mut(POLW1_SIZE_PACKED).enumerate() {
            let pack = array_mut_ref!(pack, 0, POLW1_SIZE_PACKED);
            poly::w1_pack(pack, &w1[i]);
        }
        let mut hasher = Shake256::default();
        hasher.process(mu);
        hasher.process(&w1pack);
        let mut xof = hasher.xof_result();
        xof.read(&mut outbuf);

        outbuf
    }

    // TODO(dianamin): Refactor this function.
    /// Verifies the given signature for the given message.
    ///
    /// # Arguments
    ///
    /// * `m` - the message
    /// * `sig` - the signature to be verified
    pub fn verify(&self, m: &[u8], sig: &[u8; SIG_SIZE_PACKED]) -> bool {
        let mut pk = [0; PK_SIZE_PACKED];
        self.to_bytes(&mut pk);
        let (mut rho, mut mu) = ([0; SEEDBYTES], [0; CRHBYTES]);

        let mut c = [0u8; SEEDBYTES];
        let mut z = PolyVecL::default();
        let (mut t1, mut w1, mut h) = Default::default();
        let (mut tmp1, mut tmp2) = (PolyVecK::default(), PolyVecK::default());

        packing::pk::unpack(&pk, &mut rho, &mut t1);
        let r = packing::sign::unpack(sig, &mut c, &mut z, &mut h);

        if !r {
            return false;
        };
        if z.chknorm(GAMMA1 - BETA) {
            return false;
        };

        // Compute CRH(CRH(rho, t1), msg)
        shake256!(&mut mu[0..SEEDBYTES]; &pk);
        shake256!(&mut mu[0..CRHBYTES]; &mu[0..SEEDBYTES], m);

        // Expand matrix and matrix-vector multiplication; compute Az - c2^dt1
        z.ntt();
        for i in 0..K {
            for j in 0..L {
                let mut mat_component: Poly = [0; N];
                expand_mat_component(&self.rho, i, j, &mut mat_component);
                polyvec::pointwise_acc_invmontgomery_componentwise(
                    &mut tmp1[i],
                    &mat_component,
                    &z[j],
                    j,
                );
            }
        }

        let cp = poly::build_challenge_from_seed(&c);
        let mut chat = cp.clone();
        poly::ntt(&mut chat);
        t1.shift_left();
        t1.ntt();
        for i in 0..K {
            poly::pointwise_invmontgomery(&mut tmp2[i], &chat, &t1[i]);
        }

        let mut tmp = PolyVecK::default();
        tmp.with_sub(&tmp1, &tmp2);
        tmp.reduce();
        tmp.invntt_montgomery();

        // Reconstruct w1
        tmp.caddq();
        polyvec::use_hint(&mut w1, &tmp, &h);

        // Call random oracle and verify challenge
        let c2 = self.compute_c_seed(&mu, &w1);

        for i in 0..SEEDBYTES {
            if c[i] != c2[i] {
                return false;
            }
        }

        true
    }
}
