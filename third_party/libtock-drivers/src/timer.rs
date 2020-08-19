use crate::result::{FlexUnwrap, OtherError, TockError, TockResult};
use crate::util;
use core::cell::Cell;
use core::isize;
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Sub};
use libtock_core::callback::{CallbackSubscription, Consumer};
use libtock_core::result::{CommandError, EALREADY};
use libtock_core::syscalls;

const DRIVER_NUMBER: usize = 0x00000;

mod command_nr {
    pub const IS_DRIVER_AVAILABLE: usize = 0;
    pub const GET_CLOCK_FREQUENCY: usize = 1;
    pub const GET_CLOCK_VALUE: usize = 2;
    pub const STOP_ALARM: usize = 3;
    pub const SET_ALARM: usize = 4;
}

mod subscribe_nr {
    pub const SUBSCRIBE_CALLBACK: usize = 0;
}

pub fn sleep(duration: Duration<isize>) -> TockResult<()> {
    let expired = Cell::new(false);
    let mut with_callback = with_callback(|_, _| expired.set(true));

    let mut timer = with_callback.init().flex_unwrap();
    let timer_alarm = timer.set_alarm(duration).flex_unwrap();

    util::yieldk_for(|| expired.get());

    match timer.stop_alarm(timer_alarm) {
        Ok(())
        | Err(TockError::Command(CommandError {
            return_code: EALREADY,
            ..
        })) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn with_callback<CB>(callback: CB) -> WithCallback<'static, CB> {
    WithCallback {
        callback,
        clock_frequency: ClockFrequency { hz: 0 },
        phantom: PhantomData,
    }
}

pub struct WithCallback<'a, CB> {
    callback: CB,
    clock_frequency: ClockFrequency,
    phantom: PhantomData<&'a mut ()>,
}

struct TimerEventConsumer;

impl<CB: FnMut(ClockValue, Alarm)> Consumer<WithCallback<'_, CB>> for TimerEventConsumer {
    fn consume(data: &mut WithCallback<CB>, clock_value: usize, alarm_id: usize, _: usize) {
        (data.callback)(
            ClockValue {
                num_ticks: clock_value as isize,
                clock_frequency: data.clock_frequency,
            },
            Alarm { alarm_id },
        );
    }
}

impl<'a, CB: FnMut(ClockValue, Alarm)> WithCallback<'a, CB> {
    pub fn init(&'a mut self) -> TockResult<Timer<'a>> {
        let num_notifications =
            syscalls::command(DRIVER_NUMBER, command_nr::IS_DRIVER_AVAILABLE, 0, 0)?;

        let clock_frequency =
            syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_FREQUENCY, 0, 0)?;

        if clock_frequency == 0 {
            return Err(OtherError::TimerDriverErroneousClockFrequency.into());
        }

        let clock_frequency = ClockFrequency {
            hz: clock_frequency,
        };

        let subscription = syscalls::subscribe::<TimerEventConsumer, _>(
            DRIVER_NUMBER,
            subscribe_nr::SUBSCRIBE_CALLBACK,
            self,
        )?;

        Ok(Timer {
            num_notifications,
            clock_frequency,
            subscription,
        })
    }
}

pub struct Timer<'a> {
    num_notifications: usize,
    clock_frequency: ClockFrequency,
    #[allow(dead_code)] // Used in drop
    subscription: CallbackSubscription<'a>,
}

impl<'a> Timer<'a> {
    pub fn num_notifications(&self) -> usize {
        self.num_notifications
    }

    pub fn clock_frequency(&self) -> ClockFrequency {
        self.clock_frequency
    }

    pub fn get_current_clock(&self) -> TockResult<ClockValue> {
        Ok(ClockValue {
            num_ticks: syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_VALUE, 0, 0)?
                as isize,
            clock_frequency: self.clock_frequency,
        })
    }

    pub fn stop_alarm(&mut self, alarm: Alarm) -> TockResult<()> {
        syscalls::command(DRIVER_NUMBER, command_nr::STOP_ALARM, alarm.alarm_id, 0)?;
        Ok(())
    }

    pub fn set_alarm(&mut self, duration: Duration<isize>) -> TockResult<Alarm> {
        let now = self.get_current_clock()?;
        let freq = self.clock_frequency.hz();
        let duration_ms = duration.ms() as usize;
        let ticks = match duration_ms.checked_mul(freq) {
            Some(x) => x / 1000,
            None => {
                // Divide the largest of the two operands by 1000, to improve precision of the
                // result.
                if duration_ms > freq {
                    match (duration_ms / 1000).checked_mul(freq) {
                        Some(y) => y,
                        None => return Err(OtherError::TimerDriverDurationOutOfRange.into()),
                    }
                } else {
                    match (freq / 1000).checked_mul(duration_ms) {
                        Some(y) => y,
                        None => return Err(OtherError::TimerDriverDurationOutOfRange.into()),
                    }
                }
            }
        };
        let alarm_instant = now.num_ticks() as usize + ticks;

        let alarm_id = syscalls::command(DRIVER_NUMBER, command_nr::SET_ALARM, alarm_instant, 0)?;

        Ok(Alarm { alarm_id })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ClockFrequency {
    hz: usize,
}

impl ClockFrequency {
    pub fn hz(&self) -> usize {
        self.hz
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ClockValue {
    num_ticks: isize,
    clock_frequency: ClockFrequency,
}

impl ClockValue {
    pub const fn new(num_ticks: isize, clock_hz: usize) -> ClockValue {
        ClockValue {
            num_ticks,
            clock_frequency: ClockFrequency { hz: clock_hz },
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
        ClockValue::scale_int(self.num_ticks, 1000, self.clock_frequency.hz() as isize)
    }

    pub fn ms_f64(&self) -> f64 {
        1000.0 * (self.num_ticks as f64) / (self.clock_frequency.hz() as f64)
    }

    pub fn wrapping_add(self, duration: Duration<isize>) -> ClockValue {
        // This is a precision preserving formula for scaling an isize.
        let duration_ticks =
            ClockValue::scale_int(duration.ms, self.clock_frequency.hz() as isize, 1000);
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

pub struct Alarm {
    alarm_id: usize,
}

impl Alarm {
    pub fn alarm_id(&self) -> usize {
        self.alarm_id
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
