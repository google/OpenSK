#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate core;

#[macro_use]
extern crate arrayref;
extern crate byteorder;
extern crate digest;
extern crate itertools;
extern crate sha3;

#[macro_use]
mod utils;
mod ntt;
mod packing;
pub mod params;
mod poly;
mod polyvec;
mod reduce;
mod rounding;
pub mod sign;

#[cfg(test)]
mod test_mul;
