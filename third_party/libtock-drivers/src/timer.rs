//! Async timer driver. Can be used for (non-busy)  sleeping.

use crate::callback::CallbackSubscription;
use crate::callback::Consumer;
use crate::futures;
use crate::result::OtherError;
use crate::result::TockError;
use crate::result::TockResult;
use crate::result::EALREADY;
use crate::syscalls;
use core::cell::Cell;
use core::isize;
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Sub};

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

#[derive(Copy, Clone, Debug)]
pub struct ClockFrequency {
    hz: usize,
}

impl ClockFrequency {
    pub fn hz(self) -> usize {
        self.hz
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ClockValue {
    num_ticks: isize,
    clock_frequency: ClockFrequency,
}

impl ClockValue {
    pub fn num_ticks(self) -> isize {
        self.num_ticks
    }

    pub fn ms(self) -> isize {
        if self.num_ticks.abs() < isize::MAX / 1000 {
            (1000 * self.num_ticks) / self.clock_frequency.hz() as isize
        } else {
            1000 * (self.num_ticks / self.clock_frequency.hz() as isize)
        }
    }

    pub fn ms_f64(self) -> f64 {
        1000.0 * (self.num_ticks as f64) / (self.clock_frequency.hz() as f64)
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

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub(crate) struct ActiveTimer {
    instant: u32,
    set_at: u32,
}

/// Context for the time driver.
/// You can create a context as follows:
/// ```no_run
/// # use libtock::result::TockResult;
/// # async fn doc() -> TockResult<()> {
/// let mut drivers = libtock::retrieve_drivers()?;
/// let mut timer_context = drivers.timer;
/// # Ok(())
/// # }
/// ```
#[non_exhaustive]
pub struct DriverContext {
    pub(crate) active_timer: Cell<Option<ActiveTimer>>,
}

impl DriverContext {
    /// Create a driver timer from a context.
    pub fn create_timer_driver(&mut self) -> TimerDriver {
        TimerDriver {
            callback: Callback,
            context: self,
        }
    }

    pub fn with_callback<CB>(&mut self, callback: CB) -> WithCallback<CB> {
        WithCallback {
            callback,
            clock_frequency: ClockFrequency { hz: 0 },
            phantom: PhantomData,
        }
    }
}

/// Timer driver instance. You can create a TimerDriver from a DriverContext as follows:
/// ```no_run
/// # use libtock::result::TockResult;
/// # async fn doc() -> TockResult<()> {
/// # let mut drivers = libtock::retrieve_drivers()?;
/// # let mut timer_context = drivers.timer;
/// let mut timer_driver = timer_context.create_timer_driver();
/// let timer_driver = timer_driver.activate()?;
/// # Ok(())
/// # }
/// ```
pub struct TimerDriver<'a> {
    callback: Callback,
    context: &'a DriverContext,
}

struct Callback;

struct ParallelTimerConsumer;

impl<'a> Consumer<Callback> for ParallelTimerConsumer {
    fn consume(_: &mut Callback, _: usize, _: usize, _: usize) {}
}

/// Activated time driver. Updates current time in the context and manages
/// active alarms.
/// Example usage (sleep for 1 second):
/// ```no_run
/// # use libtock::result::TockResult;
/// # use libtock::timer::Duration;
/// # async fn doc() -> TockResult<()> {
/// # let mut drivers = libtock::retrieve_drivers()?;
/// # let mut timer_driver = drivers.timer.create_timer_driver();
/// let timer_driver = timer_driver.activate()?;
/// timer_driver.sleep(Duration::from_ms(1000)).await?;
/// # Ok(())
/// # }
/// ```
pub struct ParallelSleepDriver<'a> {
    _callback_subscription: CallbackSubscription<'a>,
    context: &'a DriverContext,
}

impl<'a> TimerDriver<'a> {
    /// Activate the timer driver, will return a ParallelSleepDriver which
    /// can used to sleep.
    pub fn activate(&'a mut self) -> TockResult<ParallelSleepDriver<'a>> {
        let subscription = syscalls::subscribe::<ParallelTimerConsumer, _>(
            DRIVER_NUMBER,
            subscribe_nr::SUBSCRIBE_CALLBACK,
            &mut self.callback,
        )?;
        let driver = ParallelSleepDriver {
            _callback_subscription: subscription,
            context: &self.context,
        };
        Ok(driver)
    }
}

impl<'a> ParallelSleepDriver<'a> {
    /// Sleep for the given duration
    pub async fn sleep(&self, duration: Duration<usize>) -> TockResult<()> {
        let now = get_current_ticks()?;
        let freq = get_clock_frequency()?;
        let alarm_instant = Self::compute_alarm_instant(duration.ms, now, freq)?;
        let this_alarm = ActiveTimer {
            instant: alarm_instant as u32,
            set_at: now as u32,
        };

        let suspended_timer: Cell<Option<ActiveTimer>> = Cell::new(None);

        futures::wait_until(|| {
            self.activate_current_timer(this_alarm, &suspended_timer)
                .unwrap_or(false)
        })
        .await;

        Ok(())
    }

    fn activate_timer(&self, timer: ActiveTimer) -> TockResult<()> {
        set_alarm_at(timer.instant as usize)?;
        let now = get_current_ticks()?;
        if !is_over(timer, now as u32) {
            self.context.active_timer.set(Some(timer));
        } else {
            self.wakeup_soon()?;
        }
        Ok(())
    }

    fn wakeup_soon(&self) -> TockResult<()> {
        self.context.active_timer.set(None);

        for i in 0.. {
            let now = get_current_ticks()?;

            let next_timer = ActiveTimer {
                instant: now as u32 + i,
                set_at: now as u32,
            };
            set_alarm_at(next_timer.instant as usize)?;
            let now = get_current_ticks()?;
            if !is_over(next_timer, now as u32) {
                break;
            } else {
                stop_alarm_at(next_timer.instant as usize)?;
            }
        }
        Ok(())
    }

    fn compute_alarm_instant(
        duration_ms: usize,
        num_ticks: usize,
        freq: usize,
    ) -> TockResult<usize> {
        let ticks = match duration_ms.checked_mul(freq) {
            Some(x) => x / 1000,
            None => {
                // Divide the largest of the two operands by 1000, to improve precision of the
                // result.
                if duration_ms > freq {
                    match (duration_ms / 1000).checked_mul(freq) {
                        Some(y) => y,
                        None => {
                            return Err(TockError::Other(OtherError::TimerDriverDurationOutOfRange))
                        }
                    }
                } else {
                    match (freq / 1000).checked_mul(duration_ms) {
                        Some(y) => y,
                        None => {
                            return Err(TockError::Other(OtherError::TimerDriverDurationOutOfRange))
                        }
                    }
                }
            }
        };
        let alarm_instant = num_ticks + ticks;
        Ok(alarm_instant)
    }

    fn activate_current_timer(
        &self,
        this_alarm: ActiveTimer,
        suspended_timer: &Cell<Option<ActiveTimer>>,
    ) -> TockResult<bool> {
        let now = get_current_ticks()?;

        if let Some(active) = self.context.active_timer.get() {
            if left_is_later(active, this_alarm) {
                suspended_timer.set(Some(active));
                self.activate_timer(this_alarm)?;
            }
        } else {
            self.activate_timer(this_alarm)?;
        }
        if is_over(this_alarm, now as u32) {
            if let Some(paused) = suspended_timer.get() {
                self.activate_timer(paused)?;
            } else {
                self.context.active_timer.set(None);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn get_current_ticks() -> TockResult<usize> {
    syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_VALUE, 0, 0).map_err(|err| err.into())
}
fn set_alarm_at(instant: usize) -> TockResult<()> {
    syscalls::command(DRIVER_NUMBER, command_nr::SET_ALARM, instant, 0)
        .map(|_| ())
        .map_err(|err| err.into())
}

fn stop_alarm_at(instant: usize) -> TockResult<()> {
    match syscalls::command(DRIVER_NUMBER, command_nr::STOP_ALARM, instant, 0) {
        Ok(_) => Ok(()),
        Err(error) => match error.return_code {
            EALREADY => Ok(()),
            _ => Err(TockError::Command(error)),
        },
    }
}

fn get_clock_frequency() -> TockResult<usize> {
    syscalls::command(DRIVER_NUMBER, command_nr::GET_CLOCK_FREQUENCY, 0, 0)
        .map_err(|err| err.into())
}

fn is_over(timer: ActiveTimer, now: u32) -> bool {
    now.wrapping_sub(timer.set_at) >= timer.instant.wrapping_sub(timer.set_at)
}

fn left_is_later(alarm_1: ActiveTimer, alarm_2: ActiveTimer) -> bool {
    if alarm_1.set_at <= alarm_1.instant && alarm_2.set_at <= alarm_2.instant {
        return alarm_1.instant > alarm_2.instant;
    }
    if alarm_1.set_at <= alarm_1.instant && alarm_2.set_at >= alarm_2.instant {
        return false;
    }
    if alarm_1.set_at >= alarm_1.instant && alarm_2.set_at <= alarm_2.instant {
        return true;
    }
    if alarm_1.set_at >= alarm_1.instant && alarm_2.set_at >= alarm_2.instant {
        return alarm_1.instant > alarm_2.instant;
    }
    false
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    pub fn duration_bigger_than_frequency() {
        let x = ParallelSleepDriver::compute_alarm_instant(10000, 0, 1000)
            .ok()
            .unwrap();
        assert_eq!(x, 10000);
    }

    #[test]
    pub fn frequency_bigger_than_duration() {
        let x = ParallelSleepDriver::compute_alarm_instant(1000, 0, 10000)
            .ok()
            .unwrap();
        assert_eq!(x, 10000);
    }

    #[test]
    pub fn fails_if_duration_is_too_large() {
        let x =
            ParallelSleepDriver::compute_alarm_instant(core::usize::MAX, 0, core::usize::MAX - 1);
        assert!(x.is_err());
    }

    #[test]
    pub fn fails_if_frequency_is_too_large() {
        let x =
            ParallelSleepDriver::compute_alarm_instant(core::usize::MAX - 1, 0, core::usize::MAX);
        assert!(x.is_err());
    }

    #[test]
    pub fn alarm_before_systick_wrap_expired() {
        assert_eq!(
            super::is_over(
                super::ActiveTimer {
                    instant: 2u32,
                    set_at: 1u32
                },
                3u32
            ),
            true
        );
    }

    #[test]
    pub fn alarm_before_systick_wrap_not_expired() {
        assert_eq!(
            super::is_over(
                super::ActiveTimer {
                    instant: 3u32,
                    set_at: 1u32
                },
                2u32
            ),
            false
        );
    }

    #[test]
    pub fn alarm_after_systick_wrap_expired() {
        assert_eq!(
            super::is_over(
                super::ActiveTimer {
                    instant: 1u32,
                    set_at: 3u32
                },
                2u32
            ),
            true
        );
    }

    #[test]
    pub fn alarm_after_systick_wrap_time_before_systick_wrap_not_expired() {
        assert_eq!(
            super::is_over(
                super::ActiveTimer {
                    instant: 1u32,
                    set_at: 3u32
                },
                4u32
            ),
            false
        );
    }

    #[test]
    pub fn alarm_after_systick_wrap_time_after_systick_wrap_not_expired() {
        assert_eq!(
            super::is_over(
                super::ActiveTimer {
                    instant: 1u32,
                    set_at: 3u32
                },
                0u32
            ),
            false
        );
    }

    #[test]
    pub fn left_later_than_the_other_both_not_wrapped() {
        let later = super::ActiveTimer {
            instant: 3u32,
            set_at: 1u32,
        };
        let earlier = super::ActiveTimer {
            instant: 2u32,
            set_at: 1u32,
        };
        assert_eq!(super::left_is_later(later, earlier), true);
    }

    #[test]
    pub fn right_later_than_the_other_both_not_wrapped() {
        let later = super::ActiveTimer {
            instant: 2u32,
            set_at: 1u32,
        };
        let earlier = super::ActiveTimer {
            instant: 3u32,
            set_at: 1u32,
        };
        assert_eq!(super::left_is_later(later, earlier), false);
    }

    #[test]
    pub fn left_later_left_wrapped() {
        let later = super::ActiveTimer {
            instant: 1u32,
            set_at: 3u32,
        };
        let earlier = super::ActiveTimer {
            instant: 2u32,
            set_at: 1u32,
        };
        assert_eq!(super::left_is_later(later, earlier), true);
    }

    #[test]
    pub fn right_later_right_wrapped() {
        let later = super::ActiveTimer {
            instant: 3u32,
            set_at: 1u32,
        };
        let earlier = super::ActiveTimer {
            instant: 1u32,
            set_at: 3u32,
        };
        assert_eq!(super::left_is_later(later, earlier), false);
    }

    #[test]
    pub fn left_later_both_wrapped() {
        let later = super::ActiveTimer {
            instant: 2u32,
            set_at: 3u32,
        };
        let earlier = super::ActiveTimer {
            instant: 1u32,
            set_at: 3u32,
        };
        assert_eq!(super::left_is_later(later, earlier), true);
    }

    #[test]
    pub fn right_later_both_wrapped() {
        let later = super::ActiveTimer {
            instant: 1u32,
            set_at: 3u32,
        };
        let earlier = super::ActiveTimer {
            instant: 2u32,
            set_at: 3u32,
        };
        assert_eq!(super::left_is_later(later, earlier), false);
    }

    #[test]
    pub fn inequality_is_strict() {
        let later = super::ActiveTimer {
            instant: 2u32,
            set_at: 1u32,
        };
        let earlier = super::ActiveTimer {
            instant: 2u32,
            set_at: 1u32,
        };
        assert_eq!(super::left_is_later(later, earlier), false);
    }

    #[test]
    pub fn inequality_is_strict_wrapped() {
        let later = super::ActiveTimer {
            instant: 1u32,
            set_at: 2u32,
        };
        let earlier = super::ActiveTimer {
            instant: 1u32,
            set_at: 2u32,
        };
        assert_eq!(super::left_is_later(later, earlier), false);
    }
}
