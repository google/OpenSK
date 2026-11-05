// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use opensk::api::customization::{CustomizationImpl, DEFAULT_CUSTOMIZATION};
use opensk::ctap::status_code::Ctap2StatusCode;
use opensk::env::Env;
use wasefire::Error;
use wasefire::error::Space;

mod clock;
mod crypto;
#[cfg(feature = "fingerprint")]
mod fingerprint;
pub(crate) mod hid_connection;
pub(crate) mod persist;
mod rng;
mod user_presence;
mod vendor;
mod write;

pub(crate) fn init() -> WasefireEnv {
    WasefireEnv {
        customization: DEFAULT_CUSTOMIZATION,
        user_presence: user_presence::init(),
        #[cfg(feature = "fingerprint")]
        fingerprint: fingerprint::init(),
    }
}

pub(crate) struct WasefireEnv {
    customization: CustomizationImpl,
    user_presence: user_presence::Impl,
    #[cfg(feature = "fingerprint")]
    fingerprint: fingerprint::Impl,
}

impl Env for WasefireEnv {
    type Rng = Self;
    type UserPresence = user_presence::Impl;
    type Persist = Self;
    type KeyStore = Self;
    type Write = write::Impl;
    type Customization = CustomizationImpl;
    type HidConnection = Self;
    type Clock = Self;
    type Crypto = Self;
    #[cfg(feature = "fingerprint")]
    type Fingerprint = fingerprint::Impl;

    fn rng(&mut self) -> &mut Self::Rng {
        self
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        &mut self.user_presence
    }

    fn persist(&mut self) -> &mut Self::Persist {
        self
    }

    fn key_store(&mut self) -> &mut Self::KeyStore {
        self
    }

    fn clock(&mut self) -> &mut Self::Clock {
        self
    }

    #[cfg(feature = "fingerprint")]
    fn fingerprint(&mut self) -> &mut Self::Fingerprint {
        &mut self.fingerprint
    }

    fn write(&mut self) -> Self::Write {
        write::Impl::default()
    }

    fn customization(&self) -> &Self::Customization {
        &self.customization
    }

    fn hid_connection(&mut self) -> &mut Self::HidConnection {
        self
    }

    fn boots_after_soft_reset(&self) -> bool {
        // TODO: The applet needs to know if the platform did a cold boot.
        false
    }

    fn process_vendor_command(
        &mut self,
        bytes: &[u8],
        channel: opensk::ctap::Channel,
    ) -> Option<alloc::vec::Vec<u8>> {
        vendor::process_vendor_command(self, bytes, channel)
    }
}

impl opensk::api::key_store::Helper for WasefireEnv {}

fn convert_error(error: Error) -> Ctap2StatusCode {
    match Space::try_from(error.space()) {
        Ok(Space::User | Space::Internal) => Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR,
        Ok(Space::World) => Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE,
        _ => Ctap2StatusCode::CTAP1_ERR_OTHER,
    }
}
