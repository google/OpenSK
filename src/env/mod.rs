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
    fn check(&self, cid: ChannelID) -> Result<(), Ctap2StatusCode>;
}

/// Describes what CTAP needs to function.
pub trait Env {
    type Rng: Rng256;
    type UserPresence: UserPresence;
    type Storage: Storage;
    type UpgradeStorage: UpgradeStorage;
    type FirmwareProtection: FirmwareProtection;

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
}
