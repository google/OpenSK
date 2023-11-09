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

use core::convert::TryFrom;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UsbEndpoint {
    MainHid = 1,
    #[cfg(feature = "vendor_hid")]
    VendorHid = 2,
}

impl TryFrom<usize> for UsbEndpoint {
    type Error = SendOrRecvError;

    fn try_from(endpoint_num: usize) -> Result<Self, SendOrRecvError> {
        match endpoint_num {
            1 => Ok(UsbEndpoint::MainHid),
            #[cfg(feature = "vendor_hid")]
            2 => Ok(UsbEndpoint::VendorHid),
            _ => Err(SendOrRecvError),
        }
    }
}

pub enum SendOrRecvStatus {
    Timeout,
    Sent,
    Received(UsbEndpoint),
}

pub struct SendOrRecvError;

pub type SendOrRecvResult = Result<SendOrRecvStatus, SendOrRecvError>;

pub trait HidConnection {
    fn send_and_maybe_recv(&mut self, buf: &mut [u8; 64], timeout_ms: usize) -> SendOrRecvResult;
}
