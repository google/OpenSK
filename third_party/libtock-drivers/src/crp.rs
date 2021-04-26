use crate::result::TockResult;
use libtock_core::syscalls;

const DRIVER_NUMBER: usize = 0x00008;

mod command_nr {
    pub const AVAILABLE: usize = 0;
    pub const GET_PROTECTION: usize = 1;
    pub const SET_PROTECTION: usize = 2;
}

#[derive(PartialOrd, PartialEq)]
pub enum ProtectionLevel {
    /// Unsupported feature
    Unknown = 0,
    /// This should be the factory default for the chip.
    NoProtection = 1,
    /// At this level, only JTAG/SWD are disabled but other debugging
    /// features may still be enabled.
    JtagDisabled = 2,
    /// This is the maximum level of protection the chip supports.
    /// At this level, JTAG and all other features are expected to be
    /// disabled and only a full chip erase may allow to recover from
    /// that state.
    FullyLocked = 0xff,
}

impl From<usize> for ProtectionLevel {
    fn from(value: usize) -> Self {
        match value {
            1 => ProtectionLevel::NoProtection,
            2 => ProtectionLevel::JtagDisabled,
            0xff => ProtectionLevel::FullyLocked,
            _ => ProtectionLevel::Unknown,
        }
    }
}

pub fn is_available() -> TockResult<()> {
    syscalls::command(DRIVER_NUMBER, command_nr::AVAILABLE, 0, 0)?;
    Ok(())
}

pub fn get_protection() -> TockResult<ProtectionLevel> {
    let current_level = syscalls::command(DRIVER_NUMBER, command_nr::GET_PROTECTION, 0, 0)?;
    Ok(current_level.into())
}

pub fn set_protection(level: ProtectionLevel) -> TockResult<()> {
    syscalls::command(DRIVER_NUMBER, command_nr::SET_PROTECTION, level as usize, 0)?;
    Ok(())
}
