#![cfg_attr(not(feature = "std"), no_std)]
#![feature(alloc_error_handler)]

#[cfg(not(feature = "std"))]
mod allocator;
#[cfg(not(feature = "std"))]
mod panic_handler;
#[cfg(not(feature = "std"))]
mod util;
