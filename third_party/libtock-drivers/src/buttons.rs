use crate::result::{OtherError, TockResult};
use core::marker::PhantomData;
use libtock_core::callback::{CallbackSubscription, Consumer};
use libtock_core::syscalls;

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

pub fn with_callback<CB>(callback: CB) -> WithCallback<CB> {
    WithCallback { callback }
}

pub struct WithCallback<CB> {
    callback: CB,
}

struct ButtonConsumer;

impl<CB: FnMut(usize, ButtonState)> Consumer<WithCallback<CB>> for ButtonConsumer {
    fn consume(data: &mut WithCallback<CB>, button_num: usize, state: usize, _: usize) {
        (data.callback)(button_num, state.into());
    }
}

impl<CB: FnMut(usize, ButtonState)> WithCallback<CB> {
    pub fn init(&mut self) -> TockResult<Buttons> {
        let count = syscalls::command(DRIVER_NUMBER, command_nr::COUNT, 0, 0)?;

        let subscription = syscalls::subscribe::<ButtonConsumer, _>(
            DRIVER_NUMBER,
            subscribe_nr::SUBSCRIBE_CALLBACK,
            self,
        )?;

        Ok(Buttons {
            count: count as usize,
            subscription,
        })
    }
}

pub struct Buttons<'a> {
    count: usize,
    #[allow(dead_code)] // Used in drop
    subscription: CallbackSubscription<'a>,
}

#[derive(Copy, Clone, Debug)]
pub enum ButtonsError {
    NotSupported,
    SubscriptionFailed,
}

impl<'a> Buttons<'a> {
    pub fn iter_mut(&mut self) -> ButtonIter {
        ButtonIter {
            curr_button: 0,
            button_count: self.count,
            lifetime: PhantomData,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum ButtonState {
    Pressed,
    Released,
}

impl From<usize> for ButtonState {
    fn from(state: usize) -> ButtonState {
        match state {
            0 => ButtonState::Released,
            1 => ButtonState::Pressed,
            _ => unreachable!(),
        }
    }
}

impl<'a, 'b> IntoIterator for &'b mut Buttons<'a> {
    type Item = ButtonHandle<'b>;
    type IntoIter = ButtonIter<'b>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

pub struct ButtonIter<'a> {
    curr_button: usize,
    button_count: usize,
    lifetime: PhantomData<&'a ()>,
}

impl<'a> Iterator for ButtonIter<'a> {
    type Item = ButtonHandle<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr_button < self.button_count {
            let item = ButtonHandle {
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

pub struct ButtonHandle<'a> {
    button_num: usize,
    lifetime: PhantomData<&'a ()>,
}

impl<'a> ButtonHandle<'a> {
    pub fn enable(&mut self) -> TockResult<Button> {
        syscalls::command(
            DRIVER_NUMBER,
            command_nr::ENABLE_INTERRUPT,
            self.button_num,
            0,
        )?;

        Ok(Button { handle: self })
    }

    pub fn disable(&mut self) -> TockResult<()> {
        syscalls::command(
            DRIVER_NUMBER,
            command_nr::DISABLE_INTERRUPT,
            self.button_num,
            0,
        )?;

        Ok(())
    }
}

pub struct Button<'a> {
    handle: &'a ButtonHandle<'a>,
}

#[derive(Copy, Clone, Debug)]
pub enum ButtonError {
    ActivationFailed,
}

impl<'a> Button<'a> {
    pub fn read(&self) -> TockResult<ButtonState> {
        let button_state =
            syscalls::command(DRIVER_NUMBER, command_nr::READ, self.handle.button_num, 0)?;
        match button_state {
            0 => Ok(ButtonState::Released),
            1 => Ok(ButtonState::Pressed),
            _ => Err(OtherError::ButtonsDriverInvalidState.into()),
        }
    }
}
