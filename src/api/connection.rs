// Copyright 2022 Google LLC
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

use crate::clock::ClockInt;
use embedded_time::duration::Milliseconds;

pub enum SendOrRecvStatus {
    Timeout,
    Sent,
    Received,
}

pub struct SendOrRecvError;

pub type SendOrRecvResult = Result<SendOrRecvStatus, SendOrRecvError>;

pub trait HidConnection {
    fn send_or_recv_with_timeout(
        &mut self,
        buf: &mut [u8; 64],
        timeout: Milliseconds<ClockInt>,
    ) -> SendOrRecvResult;
}
