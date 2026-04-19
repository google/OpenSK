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

use alloc::boxed::Box;
use alloc::vec::Vec;

use opensk::api::persist::{Persist, PersistIter};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use wasefire::error::{Code, Error, Space};

use crate::env::WasefireEnv;

#[cfg(feature = "ctap1")]
pub(crate) fn init(ctap: &mut opensk::Ctap<WasefireEnv>) {
    use opensk::api::persist::Attestation;
    use opensk::api::persist::AttestationId::Batch;
    use opensk::env::Env;
    use wasefire::crypto::ecdsa::{P256, Private};

    if ctap
        .env()
        .persist()
        .get_attestation(Batch)
        .unwrap()
        .is_some()
    {
        return;
    }
    let private = Private::<P256>::generate().unwrap();
    let wrapped_private_key = private.export().unwrap().into_vec();
    // It seems like nobody checks the certificate.
    let attestation = Attestation {
        wrapped_private_key,
        certificate: Vec::new(),
    };
    ctap.env()
        .persist()
        .set_attestation(Batch, Some(&attestation))
        .unwrap();
}

impl Persist for WasefireEnv {
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        Ok(wasefire::store::find(key)
            .map_err(convert)?
            .map(|x| x.into_vec()))
    }

    fn insert(&mut self, key: usize, value: &[u8]) -> CtapResult<()> {
        wasefire::store::insert(key, value).map_err(convert)
    }

    fn remove(&mut self, key: usize) -> CtapResult<()> {
        wasefire::store::remove(key).map_err(convert)
    }

    fn iter(&self) -> CtapResult<PersistIter<'_>> {
        let keys = wasefire::store::keys().map_err(convert)?;
        Ok(Box::new(keys.into_iter().map(|x| Ok(x as usize))))
    }
}

fn convert(error: Error) -> Ctap2StatusCode {
    match (Space::try_from(error.space()), Code::try_from(error.code())) {
        (_, Ok(Code::NotEnough)) => Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL,
        (Ok(Space::User | Space::Internal), _) => Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR,
        (Ok(Space::World), _) => Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE,
        _ => Ctap2StatusCode::CTAP1_ERR_OTHER,
    }
}
