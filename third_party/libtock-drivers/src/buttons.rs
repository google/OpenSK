use crate::callback::CallbackSubscription;
use crate::callback::Consumer;
use crate::result::OtherError;
use crate::result::OutOfRangeError;
use crate::result::TockResult;
use crate::syscalls;
use core::marker::PhantomData;

const DRIVER_NUMBER: usize = 0x00003;

mod command_nr {
    pub const COUNT: usize = 0;
    pub const ENABLE_INTERRUPT: usize = 1;
    pub const DISABLE_INTERRUPT: usize = 2;
    pub const READ: usize = 3;
}

mod subscribe_nr {
    pub const SUBSCRIBE_CALLBACK: usize = 0;
}

#[non_exhaustive]
pub struct ButtonsDriverFactory;

impl ButtonsDriverFactory {
    pub fn init_driver(&mut self) -> TockResult<ButtonsDriver> {
        let buttons_driver = ButtonsDriver {
            num_buttons: syscalls::command(DRIVER_NUMBER, command_nr::COUNT, 0, 0)?,
            lifetime: PhantomData,
        };
        Ok(buttons_driver)
    }
}

pub struct ButtonsDriver<'a> {
    num_buttons: usize,
    lifetime: PhantomData<&'a ()>,
}

impl<'a> ButtonsDriver<'a> {
    pub fn num_buttons(&self) -> usize {
        self.num_buttons
    }

    /// Returns the button at 0-based index `button_num`
    pub fn get(&self, button_num: usize) -> Result<Button, OutOfRangeError> {
        if button_num < self.num_buttons {
            Ok(Button {
                button_num,
                lifetime: PhantomData,
            })
        } else {
            Err(OutOfRangeError)
        }
    }

    pub fn buttons(&self) -> Buttons {
        Buttons {
            num_buttons: self.num_buttons,
            curr_button: 0,
            lifetime: PhantomData,
        }
    }

    pub fn subscribe<CB: Fn(usize, ButtonState)>(
        &self,
        callback: &'a mut CB,
    ) -> TockResult<CallbackSubscription> {
        syscalls::subscribe::<ButtonsEventConsumer, _>(
            DRIVER_NUMBER,
            subscribe_nr::SUBSCRIBE_CALLBACK,
            callback,
        )
        .map_err(Into::into)
    }
}

struct ButtonsEventConsumer;

impl<CB: Fn(usize, ButtonState)> Consumer<CB> for ButtonsEventConsumer {
    fn consume(callback: &mut CB, button_num: usize, button_state: usize, _: usize) {
        let button_state = match button_state {
            0 => ButtonState::Released,
            1 => ButtonState::Pressed,
            _ => return,
        };
        callback(button_num, button_state);
    }
}

pub struct Buttons<'a> {
    num_buttons: usize,
    curr_button: usize,
    lifetime: PhantomData<&'a ()>,
}

impl<'a> Iterator for Buttons<'a> {
    type Item = Button<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr_button < self.num_buttons {
            let item = Button {
                button_num: self.curr_button,
                lifetime: PhantomData,
            };
            self.curr_button += 1;
            Some(item)
        } else {
            None
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ButtonState {
    Pressed,
    Released,
}

impl From<ButtonState> for bool {
    fn from(button_state: ButtonState) -> Self {
        match button_state {
            ButtonState::Released => false,
            ButtonState::Pressed => true,
        }
    }
}

pub struct Button<'a> {
    button_num: usize,
    lifetime: PhantomData<&'a ()>,
}

impl<'a> Button<'a> {
    pub fn button_num(&self) -> usize {
        self.button_num
    }

    pub fn read(&self) -> TockResult<ButtonState> {
        let button_state = syscalls::command(DRIVER_NUMBER, command_nr::READ, self.button_num, 0)?;
        match button_state {
            0 => Ok(ButtonState::Released),
            1 => Ok(ButtonState::Pressed),
            _ => Err(OtherError::ButtonsDriverInvalidState.into()),
        }
    }

    pub fn enable_interrupt(&self) -> TockResult<()> {
        syscalls::command(
            DRIVER_NUMBER,
            command_nr::ENABLE_INTERRUPT,
            self.button_num,
            0,
        )?;
        Ok(())
    }

    pub fn disable_interrupt(&self) -> TockResult<()> {
        syscalls::command(
            DRIVER_NUMBER,
            command_nr::DISABLE_INTERRUPT,
            self.button_num,
            0,
        )?;
        Ok(())
    }
}
