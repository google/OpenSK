use crate::api::customization::Customization;
use crate::api::firmware_protection::FirmwareProtection;
use crate::api::upgrade_storage::UpgradeStorage;
use crate::clock::CtapDuration;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::Channel;
use persistent_store::{Storage, Store};
use rng256::Rng256;

#[cfg(feature = "std")]
pub mod test;
pub mod tock;

pub enum SendOrRecvStatus {
    Timeout,
    Sent,
    Received,
}

pub struct SendOrRecvError;

pub type SendOrRecvResult = Result<SendOrRecvStatus, SendOrRecvError>;

pub trait CtapHidChannel {
    fn send_or_recv_with_timeout(
        &mut self,
        buf: &mut [u8; 64],
        timeout: CtapDuration,
    ) -> SendOrRecvResult;
}

pub enum UserPresenceStatus {
    Confirmed,
    Declined,
    Timeout,
}

pub type UserPresenceResult = Result<UserPresenceStatus, Ctap2StatusCode>;

pub trait UserPresence {
    /// Called at the beginning of user presence checking process.
    fn user_presence_check_init(&mut self, _channel: Channel) {}

    /// Implements a wait for user presence confirmation or rejection.
    fn wait_for_user_presence_with_timeout(
        &mut self,
        _channel: Channel,
        _timeout: CtapDuration,
    ) -> UserPresenceResult {
        Ok(UserPresenceStatus::Confirmed)
    }

    /// Called at the end of user presence checking process.
    fn user_presence_check_complete(&mut self, _result: &UserPresenceResult) {}

    /// Short-circuit implementation for fast user presence checking.
    ///
    /// Default algorithm for user presence checking waits for user action, while sending keepalive
    /// packets to the user agent. Implementations may use this function to override this behavior
    /// and return Some(Result<...>) to pass it immediately to the caller wanting to check user
    /// presence.
    fn quick_check(&mut self, _channel: Channel) -> Option<Result<(), Ctap2StatusCode>> {
        None
    }
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
    type CtapHidChannel: CtapHidChannel;

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

    /// I/O channel for sending packets implementing CTAP HID protocol.
    fn main_hid_channel(&mut self) -> &mut Self::CtapHidChannel;

    /// I/O channel for sending packets implementing vendor extensions to CTAP HID protocol.
    #[cfg(feature = "vendor_hid")]
    fn vendor_hid_channel(&mut self) -> &mut Self::CtapHidChannel;
}
