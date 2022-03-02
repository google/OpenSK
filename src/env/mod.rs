use crate::ctap::hid::ChannelID;
use crate::ctap::status_code::Ctap2StatusCode;
use crypto::rng256::Rng256;

#[cfg(feature = "std")]
pub mod test;

pub trait UserPresence {
    fn check(&self, cid: ChannelID) -> Result<(), Ctap2StatusCode>;
}

pub trait Env {
    type Rng: Rng256;
    type UserPresence: UserPresence;

    fn rng(&mut self) -> &mut Self::Rng;
    fn user_presence(&mut self) -> &mut Self::UserPresence;
}
