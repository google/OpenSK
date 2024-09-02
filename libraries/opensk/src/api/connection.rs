// Copyright 2022-2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::ctap::status_code::{Ctap2StatusCode, CtapResult};
use core::convert::TryFrom;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbEndpoint {
    MainHid = 1,
    #[cfg(feature = "vendor_hid")]
    VendorHid = 2,
}

impl TryFrom<usize> for UsbEndpoint {
    type Error = Ctap2StatusCode;

    fn try_from(endpoint_num: usize) -> CtapResult<Self> {
        match endpoint_num {
            1 => Ok(UsbEndpoint::MainHid),
            #[cfg(feature = "vendor_hid")]
            2 => Ok(UsbEndpoint::VendorHid),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE),
        }
    }
}

pub enum RecvStatus {
    Timeout,
    Received(UsbEndpoint),
}

pub trait HidConnection {
    fn send(&mut self, buf: &[u8; 64], endpoint: UsbEndpoint) -> CtapResult<()>;
    fn recv(&mut self, buf: &mut [u8; 64], timeout_ms: usize) -> CtapResult<RecvStatus>;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_endpoint_num() {
        assert_eq!(UsbEndpoint::try_from(1), Ok(UsbEndpoint::MainHid));
        #[cfg(feature = "vendor_hid")]
        assert_eq!(UsbEndpoint::try_from(2), Ok(UsbEndpoint::VendorHid));
        assert_eq!(
            UsbEndpoint::try_from(3),
            Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE)
        );
    }
}
