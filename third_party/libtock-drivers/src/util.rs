use libtock_platform::Syscalls;

pub struct Util<S: Syscalls>(S);

impl<S: Syscalls> Util<S> {
    // Yielding manually is discouraged as it conflicts with Rust's safety guarantees.
    // If you need to wait for a condition, use futures::wait_until and .await.
    pub fn yieldk_for<F: Fn() -> bool>(cond: F) {
        while !cond() {
            S::yield_wait();
        }
    }
}
