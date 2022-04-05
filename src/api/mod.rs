//! APIs for the environment.
//!
//! The [environment](crate::env::Env) is split into components. Each component has an API described
//! by a trait. This module gathers the API of those components.

pub mod firmware_protection;
pub mod upgrade_storage;
pub mod clock;
