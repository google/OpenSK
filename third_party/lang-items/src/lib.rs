#![cfg_attr(not(feature = "std"), no_std)]
#![feature(alloc_error_handler)]

#[cfg(not(feature = "std"))]
mod allocator;
#[cfg(not(feature = "std"))]
mod panic_handler;
#[cfg(not(feature = "std"))]
mod util;

#[cfg(feature = "std")]
#[no_mangle]
unsafe fn libtock_alloc_init(_app_heap_bottom: *mut u8, _app_heap_size: usize) {
    // Stub so that the symbol is present.
    unimplemented!()
}
