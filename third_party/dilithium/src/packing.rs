use params::{
    K, L, N, OMEGA, PK_SIZE_PACKED, POLT1_SIZE_PACKED, POLZ_SIZE_PACKED, SEEDBYTES, SIG_SIZE_PACKED,
};
use poly::{self, Poly};
use polyvec::{PolyVecK, PolyVecL};

pub mod pk {
    use super::*;

    /// Decodes a public key with the shape: `pk || rho || encodings of t1`.
    ///
    /// # Arguments
    ///
    /// * `pk` - the encoded public key
    /// * `rho` - output array for the randomness seed `rho`
    /// * `t1` - output PolyVecK for the vector of polynomials `t1`
    pub fn unpack(pk: &[u8; PK_SIZE_PACKED], rho: &mut [u8; SEEDBYTES], t1: &mut PolyVecK) {
        let (rho_bytes, t1s_bytes) = array_refs!(pk, SEEDBYTES, POLT1_SIZE_PACKED * K);

        rho.clone_from(rho_bytes);
        for i in 0..K {
            let t1_bytes = array_ref!(t1s_bytes, i * POLT1_SIZE_PACKED, POLT1_SIZE_PACKED);
            poly::t1_unpack(&mut t1[i], t1_bytes);
        }
    }
}

// Encodes and Decodes a signature with the shape:
// c_seed || encodings of z || encodings of h
pub mod sign {
    use super::*;

    /// Encodes an array used to obtain the challenge `c`.
    ///
    /// # Arguments
    ///
    /// * `sig` - the output array representing the encoded signature
    /// * `c_seed` - array to be encoded
    pub fn pack_c(sign: &mut [u8; SIG_SIZE_PACKED], c_seed: &[u8; SEEDBYTES]) {
        let c_bytes = array_mut_ref!(sign, 0, SEEDBYTES);
        for i in 0..SEEDBYTES {
            c_bytes[i] = c_seed[i];
        }
    }

    /// Encodes `z[i]`, where z is a vector of `L` polynomials.
    ///
    /// # Arguments
    ///
    /// * `sig` - output array representing the encoded signature
    /// * `z_component` - polynomial representing `z[i]`
    /// * `i` - the index of the component to be encoded
    pub fn pack_z_component(sign: &mut [u8; SIG_SIZE_PACKED], z_component: &Poly, i: usize) {
        let z_bytes = array_mut_ref!(sign, SEEDBYTES + i * POLZ_SIZE_PACKED, POLZ_SIZE_PACKED);
        poly::z_pack(z_bytes, &z_component);
    }

    /// Encodes `z`, where `z` is a vector of `L` polynomials.
    ///
    /// # Arguments
    ///
    /// * `sig` - output array representing the encoded signature
    /// * `z` - vector of `L` polynomials`
    #[cfg(not(feature = "optimize_stack"))]
    pub fn pack_z(sign: &mut [u8; SIG_SIZE_PACKED], z: &PolyVecL) {
        for i in 0..L {
            pack_z_component(sign, &z[i], i);
        }
    }

    /// Encodes `h[i]`, where `h` is a vector of `K` polynomials.
    ///
    /// # Arguments
    ///
    /// * `sig` - output array representing the encoded signature
    /// * `h_component` - polynomial representing `h[i]`
    /// * `i` - the index of the component to be encoded
    /// * `non_zero_coeff_index` - the index returned when encoding
    ///                            `h[i - 1]` (0 if `i` = 0)
    pub fn pack_h_component(
        sign: &mut [u8; SIG_SIZE_PACKED],
        h_component: &Poly,
        i: usize,
        non_zero_coeff_index: &mut usize,
    ) {
        let h_bytes = array_mut_ref!(sign, SEEDBYTES + POLZ_SIZE_PACKED * L, OMEGA + K);

        for j in 0..N {
            if h_component[j] != 0 {
                h_bytes[*non_zero_coeff_index] = j as u8;
                *non_zero_coeff_index += 1;
            }
        }
        h_bytes[OMEGA + i] = *non_zero_coeff_index as u8;
    }

    /// Encodes `h`, where `h` is a vector of `K` polynomials.
    ///
    /// # Arguments
    ///
    /// * `sig` - output array representing the encoded signature
    /// * `h` - vector of `K` polynomials.
    #[cfg(not(feature = "optimize_stack"))]
    pub fn pack_h(sign: &mut [u8; SIG_SIZE_PACKED], h: &PolyVecK) {
        let mut non_zero_coeff_index = 0;
        for i in 0..K {
            pack_h_component(sign, &h[i], i, &mut non_zero_coeff_index);
        }
    }

    /// Decodes the components of the signature.
    ///
    /// The values are written into the output arguments `c_seed`,
    /// `z`, and `h` from `sig`.
    ///
    /// # Arguments
    ///
    /// * `sig` - the encoded signature
    /// * `c_seed` - output array for the seed used to compute the challenge
    /// * `z` - output PolyVecL for the vector of polynomials `z`
    /// * `h` - output PolyVecK for the vector of polynomials `h`
    pub fn unpack(
        sign: &[u8; SIG_SIZE_PACKED],
        c_seed: &mut [u8; SEEDBYTES],
        z: &mut PolyVecL,
        h: &mut PolyVecK,
    ) -> bool {
        let (c_bytes, z_bytes, h_bytes) =
            array_refs!(sign, SEEDBYTES, POLZ_SIZE_PACKED * L, OMEGA + K);

        for i in 0..SEEDBYTES {
            c_seed[i] = c_bytes[i];
        }

        for i in 0..L {
            let z_bytes = array_ref!(z_bytes, i * POLZ_SIZE_PACKED, POLZ_SIZE_PACKED);
            poly::z_unpack(&mut z[i], z_bytes);
        }

        // Decode h
        let mut k = 0;
        for i in 0..K {
            if (h_bytes[OMEGA + i] as usize) < k || (h_bytes[OMEGA + i] as usize) > OMEGA {
                return false;
            }

            for j in k..(h_bytes[OMEGA + i] as usize) {
                // Coefficients are ordered for strong unforgeability
                if j > k && h_bytes[j] <= h_bytes[j - 1] {
                    return false;
                }

                h[i][h_bytes[j] as usize] = 1;
            }
            k = h_bytes[OMEGA + i] as usize;
        }
        // Extra indices are zero for strong unforgeability
        if h_bytes[k..OMEGA].iter().any(|&v| v != 0) {
            return false;
        }

        true
    }
}
