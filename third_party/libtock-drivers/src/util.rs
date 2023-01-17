use libtock_platform::Syscalls;

pub struct Util<S: Syscalls>(S);

impl<S: Syscalls> Util<S> {
    // Changelog
    // syscalls::yieldk_for is no longer available
    // Yielding manually is discouraged as it conflicts with Rust's safety guarantees. If you need to wait for a condition, use futures::wait_until and .await.
    pub fn yieldk_for<F: Fn() -> bool>(cond: F) {
        while !cond() {
            S::yield_wait();
        }
    }
}
