use crate::result::TockResult;
use libtock_core::syscalls;

const DRIVER_NUMBER: usize = 0x00008;

mod command_nr {
    pub const AVAILABLE: usize = 0;
    pub const PROTECT: usize = 1;
}

pub fn is_available() -> TockResult<()> {
    syscalls::command(DRIVER_NUMBER, command_nr::AVAILABLE, 0, 0)?;
    Ok(())
}

pub fn protect() -> TockResult<()> {
    syscalls::command(DRIVER_NUMBER, command_nr::PROTECT, 0, 0)?;
    Ok(())
}
