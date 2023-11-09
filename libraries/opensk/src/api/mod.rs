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

//! APIs for the environment.
//!
//! The [environment](crate::env::Env) is split into components. Each component has an API described
//! by a trait. This module gathers the API of those components.

pub mod attestation_store;
pub mod clock;
pub mod connection;
pub mod crypto;
pub mod customization;
pub mod firmware_protection;
pub mod key_store;
pub mod private_key;
pub mod rng;
pub mod user_presence;
