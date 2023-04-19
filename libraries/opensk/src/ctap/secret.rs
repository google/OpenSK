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

//! Provides secret handling support.
//!
//! This module provides the `Secret<T>` type to store secrets of type `T` while minimizing the
//! amount of time the secret is present in RAM. This type ensures that:
//! - The secret only lives in one place. It is not implicitly copied (or equivalently moved).
//! - The secret is zeroed out (using the `zeroize` crate) after usage.
//!
//! It is possible to escape those principles:
//! - By using functions containing the sequence of words "expose secret" in their name.
//! - By explicitly cloning or copying the secret.
//!
//! We don't use the secrecy crate because the SecretBox is incorrect and it doesn't provide a
//! mutable version of ExposeSecret.
//!
//! Also note that eventually, we may use some Randomize trait instead of Zeroize, to prevent
//! side-channels.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Defines a secret that is zeroized on Drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret<T: Zeroize + ?Sized>(Box<T>);

impl<T: Zeroize> Secret<T> {
    /// Imports an already exposed secret.
    ///
    /// This is provided for convenience and should be avoided when possible. The expected usage is
    /// to create a default secret, then write its content in place.
    pub fn from_exposed_secret(secret: T) -> Self {
        Self(Box::new(secret))
    }
}

impl Secret<[u8]> {
    pub fn new(len: usize) -> Self {
        Self(vec![0; len].into_boxed_slice())
    }

    /// Extracts the secret as a Vec.
    ///
    /// This means that the secret won't be zeroed-out on Drop.
    pub fn expose_secret_to_vec(mut self) -> Vec<u8> {
        core::mem::take(&mut self.0).into()
    }
}

impl<T: Default + Zeroize> Default for Secret<T> {
    fn default() -> Self {
        Secret(Box::default())
    }
}

impl<T: Zeroize + ?Sized> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + ?Sized> Deref for Secret<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<T: Zeroize + ?Sized> DerefMut for Secret<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}
