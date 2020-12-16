// Copyright 2019 Google LLC
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

#[allow(unused_imports)]
use crate::timer::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SendOrRecvStatus {
    Error,
    Sent,
    Received,
    ReceivedBytes(usize),
}

pub trait Transport {
    fn setup(&self) -> bool;
    fn recv(&self, buf: &mut [u8]) -> bool;
    fn send(&self, buf: &mut [u8]) -> bool;
    fn send_or_recv(&self, buf: &mut [u8]) -> SendOrRecvStatus;
    fn recv_with_timeout(
        &self,
        buf: &mut [u8],
        timeout_delay: Duration<isize>,
    ) -> Option<SendOrRecvStatus>;
    fn send_or_recv_with_timeout(
        &self,
        buf: &mut [u8],
        timeout_delay: Duration<isize>,
    ) -> Option<SendOrRecvStatus>;
    fn recv_with_timeout_detail(
        &self,
        buf: &mut [u8],
        timeout_delay: Duration<isize>,
    ) -> Option<SendOrRecvStatus>;
    fn send_or_recv_with_timeout_detail(
        &self,
        buf: &mut [u8],
        timeout_delay: Duration<isize>,
    ) -> Option<SendOrRecvStatus>;
}

pub fn initialize_transport<T: Transport>(t: T) -> bool {
    t.setup()
}

pub fn recv_with_timeout<T: Transport>(
    t: T,
    buf: &mut [u8],
    timeout_delay: Duration<isize>,
) -> Option<SendOrRecvStatus> {
    t.recv_with_timeout(buf, timeout_delay)
}

pub fn send_or_recv_with_timeout<T: Transport>(
    t: T,
    buf: &mut [u8],
    timeout_delay: Duration<isize>,
) -> Option<SendOrRecvStatus> {
    t.recv_with_timeout_detail(buf, timeout_delay)
}
