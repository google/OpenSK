use crate::result::OutOfRangeError;
use crate::result::TockResult;
use crate::syscalls::command;
use core::marker::PhantomData;

const DRIVER_NUMBER: usize = 0x00002;

mod command_nr {
    pub const COUNT: usize = 0;
    pub const ON: usize = 1;
    pub const OFF: usize = 2;
    pub const TOGGLE: usize = 3;
}

#[non_exhaustive]
pub struct LedsDriverFactory;

impl LedsDriverFactory {
    pub fn init_driver(&mut self) -> TockResult<LedsDriver> {
        let driver = LedsDriver {
            num_leds: command(DRIVER_NUMBER, command_nr::COUNT, 0, 0)?,
            lifetime: PhantomData,
        };
        Ok(driver)
    }
}

pub struct LedsDriver<'a> {
    num_leds: usize,
    lifetime: PhantomData<&'a ()>,
}

impl<'a> LedsDriver<'a> {
    pub fn num_leds(&self) -> usize {
        self.num_leds
    }

    pub fn leds(&self) -> Leds {
        Leds {
            num_leds: self.num_leds,
            curr_led: 0,
            lifetime: PhantomData,
        }
    }

    /// Returns the led at 0-based index `led_num`
    pub fn get(&self, led_num: usize) -> Result<Led, OutOfRangeError> {
        if led_num < self.num_leds {
            Ok(Led {
                led_num,
                lifetime: PhantomData,
            })
        } else {
            Err(OutOfRangeError)
        }
    }
}

pub struct Leds<'a> {
    num_leds: usize,
    curr_led: usize,
    lifetime: PhantomData<&'a ()>,
}

impl<'a> Iterator for Leds<'a> {
    type Item = Led<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr_led < self.num_leds {
            let item = Led {
                led_num: self.curr_led,
                lifetime: PhantomData,
            };
            self.curr_led += 1;
            Some(item)
        } else {
            None
        }
    }
}

pub struct Led<'a> {
    led_num: usize,
    lifetime: PhantomData<&'a ()>,
}

impl<'a> Led<'a> {
    pub fn led_num(&self) -> usize {
        self.led_num
    }

    pub fn set(&self, state: impl Into<LedState>) -> TockResult<()> {
        match state.into() {
            LedState::On => self.on(),
            LedState::Off => self.off(),
        }
    }

    pub fn on(&self) -> TockResult<()> {
        command(DRIVER_NUMBER, command_nr::ON, self.led_num, 0)?;
        Ok(())
    }

    pub fn off(&self) -> TockResult<()> {
        command(DRIVER_NUMBER, command_nr::OFF, self.led_num, 0)?;
        Ok(())
    }

    pub fn toggle(&self) -> TockResult<()> {
        command(DRIVER_NUMBER, command_nr::TOGGLE, self.led_num, 0)?;
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LedState {
    On,
    Off,
}

impl From<bool> for LedState {
    fn from(from_value: bool) -> Self {
        if from_value {
            LedState::On
        } else {
            LedState::Off
        }
    }
}

#[cfg(test)]
mod test {
    use super::command_nr;
    use super::DRIVER_NUMBER;
    use crate::result::TockResult;
    use crate::syscalls;
    use crate::syscalls::raw::Event;

    #[test]
    pub fn single_led_can_be_enabled() {
        let events = syscalls::raw::run_recording_events::<TockResult<()>, _>(|next_return| {
            let mut drivers = unsafe { crate::drivers::retrieve_drivers_unsafe() };

            next_return.set(1);

            let leds_driver = drivers.leds.init_driver()?;
            next_return.set(0);

            let led = leds_driver.get(0)?;
            led.on()?;
            Ok(())
        });
        assert_eq!(
            events,
            vec![
                Event::Command(DRIVER_NUMBER, command_nr::COUNT, 0, 0),
                Event::Command(DRIVER_NUMBER, command_nr::ON, 0, 0),
            ]
        );
    }
}
