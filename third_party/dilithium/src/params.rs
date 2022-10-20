#![cfg_attr(feature = "cargo-clippy", allow(unreadable_literal))]

pub const SEEDBYTES: usize = 32;
pub const CRHBYTES: usize = 64;
pub const N: usize = 256;
pub const Q: i32 = 8380417;
pub const D: usize = 13;
pub const ROOT_OF_UNITY: usize = 1753;

#[cfg(feature = "dilithium2")]
mod mode {
    use super::Q;
    pub const K: usize = 4;
    pub const L: usize = 4;
    pub const ETA: i32 = 2;
    pub const TAU: usize = 39;
    pub const BETA: i32 = 78;
    pub const GAMMA1: i32 = 1 << 17;
    pub const GAMMA2: i32 = (Q - 1) / 88;
    pub const OMEGA: usize = 80;

    pub const POLZ_SIZE_PACKED: usize = 576;
    pub const POLW1_SIZE_PACKED: usize = 192;
    pub const POLETA_SIZE_PACKED: usize = 96;
}

#[cfg(feature = "dilithium3")]
mod mode {
    use super::Q;
    pub const K: usize = 6;
    pub const L: usize = 5;
    pub const ETA: i32 = 4;
    pub const TAU: usize = 49;
    pub const BETA: i32 = 196;
    pub const GAMMA1: i32 = 1 << 19;
    pub const GAMMA2: i32 = (Q - 1) / 32;
    pub const OMEGA: usize = 55;

    pub const POLZ_SIZE_PACKED: usize = 640;
    pub const POLW1_SIZE_PACKED: usize = 128;
    pub const POLETA_SIZE_PACKED: usize = 128;
}

#[cfg(feature = "dilithium5")]
mod mode {
    use super::Q;
    pub const K: usize = 8;
    pub const L: usize = 7;
    pub const ETA: i32 = 2;
    pub const TAU: usize = 60;
    pub const BETA: i32 = 120;
    pub const GAMMA1: i32 = 1 << 19;
    pub const GAMMA2: i32 = (Q - 1) / 32;
    pub const OMEGA: usize = 75;

    pub const POLZ_SIZE_PACKED: usize = 640;
    pub const POLW1_SIZE_PACKED: usize = 128;
    pub const POLETA_SIZE_PACKED: usize = 96;
}

pub use self::mode::*;

pub const POLT1_SIZE_PACKED: usize = 320;
pub const POLT0_SIZE_PACKED: usize = 416;

pub const PK_SIZE_PACKED: usize = SEEDBYTES + K * POLT1_SIZE_PACKED;
pub const SK_SIZE_PACKED: usize = 3 * SEEDBYTES + (L + K) * POLETA_SIZE_PACKED;
pub const SK_SIZE_PACKED_ORIGINAL: usize =
    3 * SEEDBYTES + (L + K) * POLETA_SIZE_PACKED + K * POLT0_SIZE_PACKED;
pub const SIG_SIZE_PACKED: usize = L * POLZ_SIZE_PACKED + (OMEGA + K) + SEEDBYTES;

pub const PUBLICKEYBYTES: usize = PK_SIZE_PACKED;
pub const SECRETKEYBYTES: usize = SK_SIZE_PACKED;
pub const BYTES: usize = SIG_SIZE_PACKED;

/// `MONT = 2^32 mod Q`
pub const MONT: i64 = -4186625;
pub const QINV: isize = 58728449;
