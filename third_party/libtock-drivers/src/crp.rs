use crate::result::TockResult;
use libtock_platform as platform;
use libtock_platform::{DefaultConfig, Syscalls};
use platform::ErrorCode;

const DRIVER_NUMBER: u32 = 0x00008;

mod command_nr {
    pub const AVAILABLE: u32 = 0;
    pub const GET_PROTECTION: u32 = 1;
    pub const SET_PROTECTION: u32 = 2;
}

#[derive(PartialOrd, PartialEq, Eq)]
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

pub struct Crp<S: Syscalls, C: platform::subscribe::Config = DefaultConfig>(S, C);

impl From<u32> for ProtectionLevel {
    fn from(value: u32) -> Self {
        match value {
            1 => ProtectionLevel::NoProtection,
            2 => ProtectionLevel::JtagDisabled,
            0xff => ProtectionLevel::FullyLocked,
            _ => ProtectionLevel::Unknown,
        }
    }
}

impl<S: Syscalls, C: platform::subscribe::Config> Crp<S, C> {
    pub fn is_available() -> TockResult<()> {
        S::command(DRIVER_NUMBER, command_nr::AVAILABLE, 0, 0).to_result::<(), ErrorCode>()?;

        Ok(())
    }

    pub fn get_protection() -> TockResult<ProtectionLevel> {
        let protection_level = S::command(DRIVER_NUMBER, command_nr::GET_PROTECTION, 0, 0)
            .to_result::<u32, ErrorCode>()?;

        Ok(protection_level.into())
    }

    pub fn set_protection(level: ProtectionLevel) -> TockResult<()> {
        S::command(DRIVER_NUMBER, command_nr::SET_PROTECTION, level as u32, 0)
            .to_result::<(), ErrorCode>()?;

        Ok(())
    }
}
