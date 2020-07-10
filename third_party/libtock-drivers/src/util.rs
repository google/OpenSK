use libtock_core::syscalls;

pub fn yieldk_for<F: Fn() -> bool>(cond: F) {
    while !cond() {
        unsafe {
            syscalls::raw::yieldk();
        }
    }
}
