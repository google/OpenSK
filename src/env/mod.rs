use crate::api::customization::Customization;
use crate::api::firmware_protection::FirmwareProtection;
use crate::api::upgrade_storage::UpgradeStorage;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::Channel;
use crypto::rng256::Rng256;
use persistent_store::{Storage, Store};

#[cfg(feature = "std")]
pub mod test;
pub mod tock;

pub trait UserPresence {
    /// Blocks for user presence.
    ///
    /// Returns an error in case of timeout or keepalive error.
    fn check(&mut self, channel: Channel) -> Result<(), Ctap2StatusCode>;
}

/// Describes what CTAP needs to function.
pub trait Env {
    type Rng: Rng256;
    type UserPresence: UserPresence;
    type Storage: Storage;
    type UpgradeStorage: UpgradeStorage;
    type FirmwareProtection: FirmwareProtection;
    type Write: core::fmt::Write;
    type Customization: Customization;

    fn rng(&mut self) -> &mut Self::Rng;
    fn user_presence(&mut self) -> &mut Self::UserPresence;
    fn store(&mut self) -> &mut Store<Self::Storage>;

    /// Returns the upgrade storage instance.
    ///
    /// Upgrade storage is optional, so implementations may return `None`. However, implementations
    /// should either always return `None` or always return `Some`.
    fn upgrade_storage(&mut self) -> Option<&mut Self::UpgradeStorage>;

    fn firmware_protection(&mut self) -> &mut Self::FirmwareProtection;

    /// Creates a write instance for debugging.
    ///
    /// This API doesn't return a reference such that drop may flush. This matches the Tock
    /// environment. Non-Tock embedded environments should use the defmt feature (to be implemented
    /// using the defmt crate) and ignore this API. Non-embedded environments may either use this
    /// API or use the log feature (to be implemented using the log crate).
    fn write(&mut self) -> Self::Write;

    fn customization(&self) -> &Self::Customization;
}
