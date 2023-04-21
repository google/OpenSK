use core::fmt;

use libtock_platform::ErrorCode;

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
    #[track_caller]
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
    Command(ErrorCode),
    Format,
    Other(OtherError),
}

#[cfg(feature = "debug_ctap")]
impl core::fmt::Debug for TockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TockError::Command(error_code) => {
                f.write_fmt(format_args!("CommandError: {:?}", error_code))
            }
            TockError::Format => f.write_str("TockError::Format"),
            TockError::Other(e) => f.write_fmt(format_args!("OtherError: {:?}", e)),
        }
    }
}

impl From<ErrorCode> for TockError {
    fn from(command_error: ErrorCode) -> Self {
        TockError::Command(command_error)
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
