use crate::ctap::hid::ChannelID;
use crate::ctap::status_code::Ctap2StatusCode;
use crypto::rng256::Rng256;

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

    fn rng(&mut self) -> &mut Self::Rng;
    fn user_presence(&mut self) -> &mut Self::UserPresence;
}
