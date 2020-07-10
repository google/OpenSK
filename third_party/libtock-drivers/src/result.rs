use core::fmt;

pub use libtock_core::result::*;

pub type TockResult<T> = Result<T, TockError>;

// We sometimes need to handle errors in a `TockResult` by calling `unwrap`. However,
// `Result::unwrap` requires that the error type implements `core::fmt::Debug`. Under the hood,
// this requires dynamic dispatch, which has non-negligible overhead on code size. Therefore errors
// don't derive from `Debug` in libtock-rs.
//
// Instead one can call `.ok().unwrap()` which relies on `Option::unwrap` and doesn't require any
// debugging of the error type.
//
// This trait allows to flexibly use `Result::unwrap` or `Option::unwrap` and is configured to do
// so depending on the `debug_ctap` feature.
pub trait FlexUnwrap<T> {
    fn flex_unwrap(self) -> T;
}

impl<T> FlexUnwrap<T> for TockResult<T> {
    #[cfg(feature = "debug_ctap")]
    fn flex_unwrap(self) -> T {
        self.unwrap()
    }

    #[cfg(not(feature = "debug_ctap"))]
    fn flex_unwrap(self) -> T {
        self.ok().unwrap()
    }
}

#[derive(Copy, Clone)]
pub enum TockError {
    Subscribe(SubscribeError),
    Command(CommandError),
    Allow(AllowError),
    Format,
    Other(OtherError),
}

#[cfg(feature = "debug_ctap")]
impl core::fmt::Debug for TockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TockError::Subscribe(SubscribeError {
                driver_number,
                subscribe_number,
                return_code,
            }) => f
                .debug_struct("SubscribeError")
                .field("driver", driver_number)
                .field("subscribe", subscribe_number)
                .field("return_code", return_code)
                .finish(),
            TockError::Command(CommandError {
                driver_number,
                command_number,
                arg1,
                arg2,
                return_code,
            }) => f
                .debug_struct("CommandError")
                .field("driver", driver_number)
                .field("command", command_number)
                .field("arg1", arg1)
                .field("arg2", arg2)
                .field("return_code", return_code)
                .finish(),
            TockError::Allow(AllowError {
                driver_number,
                allow_number,
                return_code,
            }) => f
                .debug_struct("AllowError")
                .field("driver", driver_number)
                .field("allow", allow_number)
                .field("return_code", return_code)
                .finish(),
            TockError::Format => f.write_str("TockError::Format"),
            TockError::Other(e) => e.fmt(f),
        }
    }
}

impl From<SubscribeError> for TockError {
    fn from(subscribe_error: SubscribeError) -> Self {
        TockError::Subscribe(subscribe_error)
    }
}

impl From<CommandError> for TockError {
    fn from(command_error: CommandError) -> Self {
        TockError::Command(command_error)
    }
}

impl From<AllowError> for TockError {
    fn from(allow_error: AllowError) -> Self {
        TockError::Allow(allow_error)
    }
}

impl From<fmt::Error> for TockError {
    fn from(fmt::Error: fmt::Error) -> Self {
        TockError::Format
    }
}

#[derive(Copy, Clone)]
#[cfg_attr(feature = "debug_ctap", derive(Debug))]
pub enum OtherError {
    ButtonsDriverInvalidState,
    GpioDriverInvalidState,
    TimerDriverDurationOutOfRange,
    TimerDriverErroneousClockFrequency,
    DriversAlreadyTaken,
    OutOfRange,
}

impl From<OtherError> for TockError {
    fn from(other: OtherError) -> Self {
        TockError::Other(other)
    }
}

pub struct OutOfRangeError;

impl From<OutOfRangeError> for TockError {
    fn from(_: OutOfRangeError) -> Self {
        TockError::Other(OtherError::OutOfRange)
    }
}
