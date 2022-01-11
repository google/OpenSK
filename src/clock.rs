#[cfg(not(feature = "std"))]
use alloc::fmt;
use embedded_time::duration::Milliseconds;
pub use embedded_time::Clock;
#[cfg(not(feature = "std"))]
use libtock_drivers::result::FlexUnwrap;

#[cfg(not(feature = "std"))]
pub struct LibtockClock<const CLOCK_FREQUENCY: u32>(libtock_drivers::timer::Timer<'static>);
#[cfg(not(feature = "std"))]
impl<const CLOCK_FREQUENCY: u32> LibtockClock<CLOCK_FREQUENCY> {
    pub fn new() -> Self {
        let boxed_cb = alloc::boxed::Box::new(libtock_drivers::timer::with_callback(|_, _| {}));
        let timer = alloc::boxed::Box::leak(boxed_cb).init().flex_unwrap();
        Self(timer)
    }
}
#[cfg(not(feature = "std"))]
impl<const CLOCK_FREQUENCY: u32> fmt::Debug for LibtockClock<CLOCK_FREQUENCY> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LibtockClock")
            .field("CLOCK_FREQUENCY", &CLOCK_FREQUENCY)
            .finish()
    }
}

const KEEPALIVE_DELAY_MS: ClockInt = 100;
pub const KEEPALIVE_DELAY: Milliseconds<ClockInt> = Milliseconds(KEEPALIVE_DELAY_MS);

#[cfg(target_pointer_width = "32")]
pub type ClockInt = u32;
#[cfg(target_pointer_width = "64")]
pub type ClockInt = u64;

#[cfg(not(feature = "std"))]
impl<const CLOCK_FREQUENCY: u32> embedded_time::Clock for LibtockClock<CLOCK_FREQUENCY> {
    // TODO: Implement and use a 24-bits TimeInt for Nordic
    type T = ClockInt;

    const SCALING_FACTOR: embedded_time::fraction::Fraction =
        <embedded_time::fraction::Fraction>::new(1, CLOCK_FREQUENCY);

    fn try_now(&self) -> Result<embedded_time::Instant<Self>, embedded_time::clock::Error> {
        let timer = &self.0;
        let now = timer.get_current_clock().flex_unwrap();
        Ok(embedded_time::Instant::new(now.num_ticks() as Self::T))
    }
}

#[cfg(not(feature = "std"))]
pub type CtapClock = LibtockClock<32768>;
#[cfg(feature = "std")]
pub type CtapClock = TestClock;

pub fn new_clock() -> CtapClock {
    CtapClock::new()
}

pub type CtapInstant = embedded_time::Instant<CtapClock>;

#[cfg(feature = "std")]
pub const TEST_CLOCK_FREQUENCY_HZ: u32 = 32768;

#[cfg(feature = "std")]
#[derive(Default, Clone, Copy, Debug)]
pub struct TestClock;
#[cfg(feature = "std")]
impl TestClock {
    pub fn new() -> Self {
        TestClock
    }
}

#[cfg(feature = "std")]
impl embedded_time::Clock for TestClock {
    type T = u64;
    const SCALING_FACTOR: embedded_time::fraction::Fraction =
        <embedded_time::fraction::Fraction>::new(1, TEST_CLOCK_FREQUENCY_HZ);

    fn try_now(&self) -> Result<embedded_time::Instant<Self>, embedded_time::clock::Error> {
        Ok(embedded_time::Instant::new(0))
    }
}
