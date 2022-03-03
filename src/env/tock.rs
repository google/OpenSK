use crypto::rng256::TockRng256;

use crate::ctap::hid::ChannelID;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::env::{Env, UserPresence};

pub struct TockEnv<CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>> {
    rng: TockRng256,
    check_user_presence: CheckUserPresence,
}

impl<CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>> TockEnv<CheckUserPresence> {
    pub fn new(check_user_presence: CheckUserPresence) -> Self {
        let rng = TockRng256 {};
        TockEnv {
            rng,
            check_user_presence,
        }
    }
}

impl<CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>> UserPresence
    for TockEnv<CheckUserPresence>
{
    fn check(&self, cid: ChannelID) -> Result<(), Ctap2StatusCode> {
        (self.check_user_presence)(cid)
    }
}

impl<CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>> Env
    for TockEnv<CheckUserPresence>
{
    type Rng = TockRng256;
    type UserPresence = Self;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        self
    }
}
