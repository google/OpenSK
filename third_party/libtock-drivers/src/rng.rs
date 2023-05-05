//! Userspace interface for easy access to the random number generator

use crate::util::Util;
use core::cell::Cell;
use core::convert::TryInto;
use libtock_platform as platform;
use libtock_platform::{share, AllowRw, DefaultConfig, Subscribe, Syscalls};
use platform::ErrorCode;

/// Driver number for the random number generator
const DRIVER_NUMBER: u32 = 0x40001;

mod command_nr {
    pub const REQUEST_RNG: u32 = 1;
}

mod subscribe_nr {
    pub const BUFFER_FILLED: u32 = 0;
}

mod allow_nr {
    pub const SHARE_BUFFER: u32 = 0;
}

/// System call configuration trait for `Rng`
pub trait Config: platform::allow_rw::Config + platform::subscribe::Config {}

impl<T: platform::allow_rw::Config + platform::subscribe::Config> Config for T {}

pub struct Rng<S: Syscalls, C: Config = DefaultConfig>(S, C);

impl<S: Syscalls, C: Config> Rng<S, C> {
    pub fn fill_buffer(buf: &mut [u8]) -> bool {
        let buf_len = buf.len();
        let is_filled = Cell::new(false);

        share::scope::<
            (
                AllowRw<_, DRIVER_NUMBER, { allow_nr::SHARE_BUFFER }>,
                Subscribe<_, DRIVER_NUMBER, { subscribe_nr::BUFFER_FILLED }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow_rw, subscribe) = handle.split();
            let result = S::allow_rw::<C, DRIVER_NUMBER, { allow_nr::SHARE_BUFFER }>(allow_rw, buf);
            if result.is_err() {
                return false;
            }

            // Automatically sets `is_filled` to true as soon as the buffer is filled.
            let subscription =
                S::subscribe::<_, _, C, DRIVER_NUMBER, { subscribe_nr::BUFFER_FILLED }>(
                    subscribe, &is_filled,
                );
            if subscription.is_err() {
                return false;
            }

            // Requests the random number generator to fill the buffer.
            let result_code: Result<(), ErrorCode> = S::command(
                DRIVER_NUMBER,
                command_nr::REQUEST_RNG,
                buf_len.try_into().unwrap(),
                0,
            )
            .to_result();
            if result_code.is_err() {
                return false;
            }

            // Yields until the buffer is filled.
            Util::<S>::yieldk_for(|| is_filled.get());

            true
        })
    }
}
