// Copyright 2025 Google LLC
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

use alloc::vec::Vec;

use opensk::api::fingerprint::{
    Ctap2EnrollFeedback, Fingerprint, FingerprintCheckError, FingerprintKind,
};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use wasefire::error::{Code, Space};
use wasefire::fingerprint::matcher::{
    Enroll, EnrollProgress, Identify, IdentifyResult, delete_template,
};
use wasefire::timer::Timeout;
use wasefire::{Error, scheduling};

pub(crate) fn init() -> Impl {
    Impl(State::Idle)
}

pub(crate) struct Impl(State);

#[derive(Default)]
enum State {
    #[default]
    Idle,
    Enroll(EnrollState),
    Identify(IdentifyState),
}

struct EnrollState {
    enroll: Enroll,
    detected: usize,
}

struct IdentifyState {
    identify: Identify,
}

impl Impl {
    fn ensure_idle(&self) -> CtapResult<()> {
        match self.0 {
            State::Idle => Ok(()),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    fn take_enroll(&mut self) -> Option<EnrollState> {
        wasefire_common::take_if(&mut self.0, |x| match x {
            State::Enroll(x) => Ok(x),
            x => Err(x),
        })
    }

    fn take_identify(&mut self) -> Option<IdentifyState> {
        wasefire_common::take_if(&mut self.0, |x| match x {
            State::Identify(x) => Ok(x),
            x => Err(x),
        })
    }
}

impl Fingerprint for Impl {
    fn prepare_enrollment(&mut self) -> CtapResult<()> {
        self.ensure_idle()?;
        let state = EnrollState {
            enroll: Enroll::new().map_err(convert)?,
            detected: 0,
        };
        self.0 = State::Enroll(state);
        Ok(())
    }

    fn capture_sample(
        &mut self,
        timeout_ms: Option<usize>,
    ) -> CtapResult<(Ctap2EnrollFeedback, usize, Option<Vec<u8>>)> {
        let State::Enroll(state) = &mut self.0 else {
            return Err(Ctap2StatusCode::CTAP2_ERR_NO_OPERATIONS);
        };
        let timeout = timeout_ms.map(Timeout::new_ms);
        scheduling::wait_until(|| match state.enroll.progress() {
            None => true,
            _ if timeout.as_ref().is_some_and(|x| x.is_over()) => true,
            Some(EnrollProgress { detected, .. }) => state.detected < detected,
        });
        match state.enroll.progress() {
            None => {
                let state = self
                    .take_enroll()
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                let template_id = state.enroll.result().map_err(convert)?;
                Ok((Ctap2EnrollFeedback::FpGood, 0, Some(template_id.into_vec())))
            }
            Some(EnrollProgress {
                detected,
                remaining,
            }) if state.detected < detected => {
                state.detected = detected;
                Ok((Ctap2EnrollFeedback::FpGood, remaining.unwrap_or(1), None))
            }
            Some(EnrollProgress { remaining, .. }) => Ok((
                Ctap2EnrollFeedback::NoUserActivity,
                remaining.unwrap_or(1),
                None,
            )),
        }
    }

    fn cancel_enrollment(&mut self) -> CtapResult<()> {
        let state = self
            .take_enroll()
            .ok_or(Ctap2StatusCode::CTAP2_ERR_NO_OPERATIONS)?;
        state.enroll.abort().map_err(convert)
    }

    fn remove_enrollment(&mut self, template_id: &[u8]) -> CtapResult<()> {
        delete_template(Some(template_id)).map_err(convert)
    }

    fn check_fingerprint_init(&mut self) -> CtapResult<()> {
        self.ensure_idle()?;
        let state = IdentifyState {
            identify: Identify::new(None).map_err(convert)?,
        };
        self.0 = State::Identify(state);
        Ok(())
    }

    fn check_fingerprint(&mut self, timeout_ms: usize) -> Result<(), FingerprintCheckError> {
        let State::Identify(state) = &mut self.0 else {
            return Err(FingerprintCheckError::Other);
        };
        let timeout = Timeout::new_ms(timeout_ms);
        scheduling::wait_until(|| state.identify.is_done() || timeout.is_over());
        if state.identify.is_done() {
            let state = self.take_identify().ok_or(FingerprintCheckError::Other)?;
            match state
                .identify
                .result()
                .map_err(|_| FingerprintCheckError::Other)?
            {
                IdentifyResult::NoMatch => Err(FingerprintCheckError::NoMatch),
                IdentifyResult::Match { .. } => Ok(()),
            }
        } else {
            Err(FingerprintCheckError::Timeout)
        }
    }

    fn check_fingerprint_complete(&mut self) -> CtapResult<()> {
        Ok(())
    }

    fn fingerprint_kind(&self) -> FingerprintKind {
        FingerprintKind::Touch
    }

    fn max_capture_samples_required_for_enroll(&self) -> usize {
        30
    }
}

fn convert(error: Error) -> Ctap2StatusCode {
    match (Space::try_from(error.space()), Code::try_from(error.code())) {
        (_, Ok(Code::NotEnough)) => Ctap2StatusCode::CTAP2_ERR_FP_DATABASE_FULL,
        (Ok(Space::User | Space::Internal), _) => Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR,
        (Ok(Space::World), _) => Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE,
        _ => Ctap2StatusCode::CTAP1_ERR_OTHER,
    }
}
