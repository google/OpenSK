use crate::api::firmware_protection::FirmwareProtection;
use crate::api::upgrade_storage::UpgradeStorage;
use crate::ctap::hid::ChannelID;
use crate::ctap::status_code::Ctap2StatusCode;
use crypto::rng256::Rng256;
use persistent_store::{Storage, StorageResult};

#[cfg(feature = "std")]
pub mod test;
pub mod tock;

pub trait UserPresence {
    /// Blocks for user presence.
    ///
    /// Returns an error in case of timeout or keepalive error.
    fn check(&mut self, cid: ChannelID) -> Result<(), Ctap2StatusCode>;
}

/// Describes what CTAP needs to function.
pub trait Env {
    type Rng: Rng256;
    type UserPresence: UserPresence;
    type Storage: Storage;
    type UpgradeStorage: UpgradeStorage;
    type FirmwareProtection: FirmwareProtection;
    type Write: core::fmt::Write;

    fn rng(&mut self) -> &mut Self::Rng;
    fn user_presence(&mut self) -> &mut Self::UserPresence;

    /// Returns the unique storage instance.
    ///
    /// This function is called at most once. Implementation may panic if called more than once.
    fn storage(&mut self) -> StorageResult<Self::Storage>;

    /// Returns the unique upgrade storage instance.
    ///
    /// This function is called at most once. Implementation may panic if called more than once.
    fn upgrade_storage(&mut self) -> StorageResult<Self::UpgradeStorage>;

    fn firmware_protection(&mut self) -> &mut Self::FirmwareProtection;

    /// Creates a write instance for debugging.
    ///
    /// This API doesn't return a reference such that drop may flush. This matches the Tock
    /// environment. Non-Tock embedded environments should use the defmt feature (to be implemented
    /// using the defmt crate) and ignore this API. Non-embedded environments may either use this
    /// API or use the log feature (to be implemented using the log crate).
    fn write(&mut self) -> Self::Write;
}
