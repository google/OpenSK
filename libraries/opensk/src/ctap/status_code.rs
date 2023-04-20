// Copyright 2019-2021 Google LLC
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

use crate::api::user_presence::UserPresenceError;
use crate::api::{attestation_store, key_store};

// CTAP specification (version 20190130) section 6.3
// For now, only the CTAP2 codes are here, the CTAP1 are not included.
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Ctap2StatusCode {
    CTAP2_OK = 0x00,
    CTAP1_ERR_INVALID_COMMAND = 0x01,
    CTAP1_ERR_INVALID_PARAMETER = 0x02,
    CTAP1_ERR_INVALID_LENGTH = 0x03,
    CTAP1_ERR_INVALID_SEQ = 0x04,
    CTAP1_ERR_TIMEOUT = 0x05,
    CTAP1_ERR_CHANNEL_BUSY = 0x06,
    CTAP1_ERR_LOCK_REQUIRED = 0x0A,
    CTAP1_ERR_INVALID_CHANNEL = 0x0B,
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11,
    CTAP2_ERR_INVALID_CBOR = 0x12,
    CTAP2_ERR_MISSING_PARAMETER = 0x14,
    CTAP2_ERR_LIMIT_EXCEEDED = 0x15,
    CTAP2_ERR_FP_DATABASE_FULL = 0x17,
    CTAP2_ERR_LARGE_BLOB_STORAGE_FULL = 0x18,
    CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19,
    CTAP2_ERR_PROCESSING = 0x21,
    CTAP2_ERR_INVALID_CREDENTIAL = 0x22,
    CTAP2_ERR_USER_ACTION_PENDING = 0x23,
    CTAP2_ERR_OPERATION_PENDING = 0x24,
    CTAP2_ERR_NO_OPERATIONS = 0x25,
    CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26,
    CTAP2_ERR_OPERATION_DENIED = 0x27,
    CTAP2_ERR_KEY_STORE_FULL = 0x28,
    CTAP2_ERR_NO_OPERATION_PENDING = 0x2A,
    CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B,
    CTAP2_ERR_INVALID_OPTION = 0x2C,
    CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D,
    CTAP2_ERR_NO_CREDENTIALS = 0x2E,
    CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F,
    CTAP2_ERR_NOT_ALLOWED = 0x30,
    CTAP2_ERR_PIN_INVALID = 0x31,
    CTAP2_ERR_PIN_BLOCKED = 0x32,
    CTAP2_ERR_PIN_AUTH_INVALID = 0x33,
    CTAP2_ERR_PIN_AUTH_BLOCKED = 0x34,
    CTAP2_ERR_PIN_NOT_SET = 0x35,
    CTAP2_ERR_PUAT_REQUIRED = 0x36,
    CTAP2_ERR_PIN_POLICY_VIOLATION = 0x37,
    CTAP2_ERR_PIN_TOKEN_EXPIRED = 0x38,
    CTAP2_ERR_REQUEST_TOO_LARGE = 0x39,
    CTAP2_ERR_ACTION_TIMEOUT = 0x3A,
    CTAP2_ERR_UP_REQUIRED = 0x3B,
    CTAP2_ERR_UV_BLOCKED = 0x3C,
    CTAP2_ERR_INTEGRITY_FAILURE = 0x3D,
    CTAP2_ERR_INVALID_SUBCOMMAND = 0x3E,
    CTAP2_ERR_UV_INVALID = 0x3F,
    CTAP2_ERR_UNAUTHORIZED_PERMISSION = 0x40,
    CTAP1_ERR_OTHER = 0x7F,
    _CTAP2_ERR_SPEC_LAST = 0xDF,
    _CTAP2_ERR_EXTENSION_FIRST = 0xE0,
    _CTAP2_ERR_EXTENSION_LAST = 0xEF,
    _CTAP2_ERR_VENDOR_FIRST = 0xF0,
    /// An internal invariant is broken.
    ///
    /// This type of error is unexpected and the current state is undefined.
    CTAP2_ERR_VENDOR_INTERNAL_ERROR = 0xF2,

    /// The hardware is malfunctioning.
    ///
    /// It may be possible that some of those errors are actually internal errors.
    CTAP2_ERR_VENDOR_HARDWARE_FAILURE = 0xF3,
    _CTAP2_ERR_VENDOR_LAST = 0xFF,
}

impl From<UserPresenceError> for Ctap2StatusCode {
    fn from(user_presence_error: UserPresenceError) -> Self {
        match user_presence_error {
            UserPresenceError::Timeout => Self::CTAP2_ERR_USER_ACTION_TIMEOUT,
            UserPresenceError::Declined => Self::CTAP2_ERR_OPERATION_DENIED,
            UserPresenceError::Canceled => Self::CTAP2_ERR_KEEPALIVE_CANCEL,
            UserPresenceError::Fail => Self::CTAP2_ERR_VENDOR_HARDWARE_FAILURE,
        }
    }
}

impl From<key_store::Error> for Ctap2StatusCode {
    fn from(_: key_store::Error) -> Self {
        Self::CTAP2_ERR_VENDOR_INTERNAL_ERROR
    }
}

impl From<attestation_store::Error> for Ctap2StatusCode {
    fn from(error: attestation_store::Error) -> Self {
        use attestation_store::Error;
        match error {
            Error::Storage => Self::CTAP2_ERR_VENDOR_HARDWARE_FAILURE,
            Error::Internal => Self::CTAP2_ERR_VENDOR_INTERNAL_ERROR,
            Error::NoSupport => Self::CTAP2_ERR_VENDOR_INTERNAL_ERROR,
        }
    }
}
