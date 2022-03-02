use crate::ctap::hid::ChannelID;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::env::{Env, UserPresence};
use crypto::rng256::ThreadRng256;

pub struct TestEnv {
    rng: ThreadRng256,
    user_presence: TestUserPresence,
}

pub struct TestUserPresence {
    check: Box<dyn Fn(ChannelID) -> Result<(), Ctap2StatusCode>>,
}

impl TestEnv {
    pub fn new() -> Self {
        let rng = ThreadRng256 {};
        let user_presence = TestUserPresence {
            check: Box::new(|_| Ok(())),
        };
        TestEnv { rng, user_presence }
    }
}

impl TestUserPresence {
    pub fn set(&mut self, check: impl Fn(ChannelID) -> Result<(), Ctap2StatusCode> + 'static) {
        self.check = Box::new(check);
    }
}

impl UserPresence for TestUserPresence {
    fn check(&self, cid: ChannelID) -> Result<(), Ctap2StatusCode> {
        (self.check)(cid)
    }
}

impl Env for TestEnv {
    type Rng = ThreadRng256;
    type UserPresence = TestUserPresence;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        &mut self.user_presence
    }
}
