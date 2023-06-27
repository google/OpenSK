//! The alarm driver
//!
//! # Example
//! ```
//! // Wait for timeout
//! Alarm::sleep(Alarm::Milliseconds(2500));
//! ```
//!
//! Adapted from the [libtock-rs](https://github.com/tock/libtock-rs/blob/master/apis/alarm/src/lib.rs) alarm driver interface

use crate::result::{OtherError, TockResult};
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Sub};
use libtock_alarm::{Hz, Alarm, Milliseconds, Convert};
use libtock_platform as platform;
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use platform::share::Handle;
use platform::subscribe::OneId;
use platform::{Subscribe, Upcall};

pub struct Timer<S: Syscalls, C: platform::subscribe::Config = DefaultConfig> {
    clock_frequency: Hz,
    s: PhantomData<S>,
    c: PhantomData<C>,
}

pub struct WithCallback<S: Syscalls, C: platform::subscribe::Config, CB: Fn(ClockValue)> {
    callback: CB,
    clock_frequency: Hz,
    s: PhantomData<S>,
    c: PhantomData<C>,
}

pub fn with_callback<S: Syscalls, C: platform::subscribe::Config, CB: Fn(ClockValue)>(
    callback: CB,
) -> TimerUpcallConsumer<S, C, CB> {
    TimerUpcallConsumer {
        data: WithCallback {
            callback,
            clock_frequency: Hz(0),
            s: PhantomData,
            c: PhantomData,
        },
    }
}

pub struct TimerUpcallConsumer<S: Syscalls, C: platform::subscribe::Config, CB: Fn(ClockValue)> {
    data: WithCallback<S, C, CB>,
}

impl<S: Syscalls, C: platform::subscribe::Config, CB: Fn(ClockValue)>
    Upcall<OneId<DRIVER_NUM, { subscribe::CALLBACK }>> for TimerUpcallConsumer<S, C, CB>
{
    fn upcall(&self, expired_tick_val: u32, _ref_tick: u32, _: u32) {
        (self.data.callback)(ClockValue::new(
            expired_tick_val as isize,
            self.data.clock_frequency,
        ))
    }
}

impl<S: Syscalls, C: platform::subscribe::Config, CB: Fn(ClockValue)>
    TimerUpcallConsumer<S, C, CB>
{
    /// Initializes the data of the containing [WithCallback], i.e. number of notifications, clock frequency.
    pub fn init(&mut self) -> TockResult<Timer<S, C>> {
        // Check if the alarm driver works.
        S::command(DRIVER_NUM, command::DRIVER_CHECK, 0, 0).to_result::<(), ErrorCode>()?;
        // Alarm driver only returns success as only a single concurrent timer is supported.

        let clock_frequency = Alarm::<S>::get_frequency()?;

        if clock_frequency.0 < 1_000 {
            // The alarm's frequency must be at least 1 kHz.
            return Err(OtherError::TimerDriverErroneousClockFrequency.into());
        }

        Ok(Timer {
            clock_frequency,
            c: PhantomData,
            s: PhantomData,
        })
    }

    /// Enables the timer by subscribing for the countdown.
    /// This needs to be a separate method as it needs to be called in the same `share::scope`
    pub fn enable<'share, 'a: 'share>(
        &'a self,
        handle: Handle<Subscribe<'share, S, DRIVER_NUM, { subscribe::CALLBACK }>>,
    ) -> Result<(), ErrorCode> {
        // Register the upcall for the timer.
        S::subscribe::<_, _, C, DRIVER_NUM, { subscribe::CALLBACK }>(handle, self)
    }
}

impl<S: Syscalls, C: platform::subscribe::Config> Default for Timer<S, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls, C: platform::subscribe::Config> Timer<S, C> {
    pub fn new() -> Self {
        let clock_frequency = Alarm::<S, C>::get_frequency().unwrap();

        Self {
            clock_frequency,
            s: PhantomData,
            c: PhantomData,
        }
    }

    pub fn get_ticks() -> TockResult<u32> {
        Ok(S::command(DRIVER_NUM, command::TIME, 0, 0).to_result::<u32, ErrorCode>()?)
    }

    /// Returns the clock frequency of the timer.
    pub fn clock_frequency(&self) -> Hz {
        self.clock_frequency
    }

    /// Returns the current counter tick value.
    pub fn get_current_counter_ticks(&self) -> TockResult<ClockValue> {
        Ok(ClockValue {
            num_ticks: Self::get_ticks()? as isize,
            clock_frequency: self.clock_frequency(),
        })
    }

    /// Stops the currently active alarm.
    pub fn stop_alarm(&mut self) -> TockResult<()> {
        S::unsubscribe(DRIVER_NUM, subscribe::CALLBACK);
        S::command(DRIVER_NUM, command::STOP, 0, 0).to_result::<(), ErrorCode>()?;

        Ok(())
    }

    pub fn set_alarm(&mut self, duration: Duration<isize>) -> TockResult<()> {
        let freq = self.clock_frequency;
        let duration_ms = duration.ms() as u32;
        let ticks = Milliseconds(duration_ms).to_ticks(freq);

        S::command(DRIVER_NUM, command::SET_RELATIVE, ticks.0, 0)
            .to_result::<u32, ErrorCode>()
            .map(|_when| ())?;

        Ok(())
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ClockValue {
    num_ticks: isize,
    clock_frequency: Hz,
}

impl ClockValue {
    pub const fn new(num_ticks: isize, clock_hz: Hz) -> ClockValue {
        ClockValue {
            num_ticks,
            clock_frequency: clock_hz,
        }
    }

    pub fn num_ticks(&self) -> isize {
        self.num_ticks
    }

    // Computes (value * factor) / divisor, even when value * factor >= isize::MAX.
    fn scale_int(value: isize, factor: isize, divisor: isize) -> isize {
        // As long as isize is not i64, this should be fine. If not, this is an alternative:
        // factor * (value / divisor) + ((value % divisor) * factor) / divisor
        ((value as i64 * factor as i64) / divisor as i64) as isize
    }

    pub fn ms(&self) -> isize {
        ClockValue::scale_int(self.num_ticks, 1000, self.clock_frequency.0 as isize)
    }

    pub fn ms_f64(&self) -> f64 {
        1000.0 * (self.num_ticks as f64) / (self.clock_frequency.0 as f64)
    }

    pub fn wrapping_add(self, duration: Duration<isize>) -> ClockValue {
        // This is a precision preserving formula for scaling an isize.
        let duration_ticks =
            ClockValue::scale_int(duration.ms, self.clock_frequency.0 as isize, 1000);
        ClockValue {
            num_ticks: self.num_ticks.wrapping_add(duration_ticks),
            clock_frequency: self.clock_frequency,
        }
    }

    pub fn wrapping_sub(self, other: ClockValue) -> Option<Duration<isize>> {
        if self.clock_frequency == other.clock_frequency {
            let clock_duration = ClockValue {
                num_ticks: self.num_ticks - other.num_ticks,
                clock_frequency: self.clock_frequency,
            };
            Some(Duration::from_ms(clock_duration.ms()))
        } else {
            None
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration<T> {
    ms: T,
}

impl<T> Duration<T> {
    pub const fn from_ms(ms: T) -> Duration<T> {
        Duration { ms }
    }
}

impl<T> Duration<T>
where
    T: Copy,
{
    pub fn ms(&self) -> T {
        self.ms
    }
}

impl<T> Sub for Duration<T>
where
    T: Sub<Output = T>,
{
    type Output = Duration<T>;

    fn sub(self, other: Duration<T>) -> Duration<T> {
        Duration {
            ms: self.ms - other.ms,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Timestamp<T> {
    ms: T,
}

impl<T> Timestamp<T> {
    pub const fn from_ms(ms: T) -> Timestamp<T> {
        Timestamp { ms }
    }
}

impl<T> Timestamp<T>
where
    T: Copy,
{
    pub fn ms(&self) -> T {
        self.ms
    }
}

impl Timestamp<isize> {
    pub fn from_clock_value(value: ClockValue) -> Timestamp<isize> {
        Timestamp { ms: value.ms() }
    }
}

impl Timestamp<f64> {
    pub fn from_clock_value(value: ClockValue) -> Timestamp<f64> {
        Timestamp { ms: value.ms_f64() }
    }
}

impl<T> Sub for Timestamp<T>
where
    T: Sub<Output = T>,
{
    type Output = Duration<T>;

    fn sub(self, other: Timestamp<T>) -> Duration<T> {
        Duration::from_ms(self.ms - other.ms)
    }
}

impl<T> Add<Duration<T>> for Timestamp<T>
where
    T: Copy + Add<Output = T>,
{
    type Output = Timestamp<T>;

    fn add(self, duration: Duration<T>) -> Timestamp<T> {
        Timestamp {
            ms: self.ms + duration.ms(),
        }
    }
}

impl<T> AddAssign<Duration<T>> for Timestamp<T>
where
    T: Copy + AddAssign,
{
    fn add_assign(&mut self, duration: Duration<T>) {
        self.ms += duration.ms();
    }
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

pub const DRIVER_NUM: u32 = 0;

// Command IDs
#[allow(unused)]
mod command {
    pub const DRIVER_CHECK: u32 = 0;
    pub const FREQUENCY: u32 = 1;
    pub const TIME: u32 = 2;
    pub const STOP: u32 = 3;

    pub const SET_RELATIVE: u32 = 5;
    pub const SET_ABSOLUTE: u32 = 6;
}

#[allow(unused)]
pub mod subscribe {
    pub const CALLBACK: u32 = 0;
}
