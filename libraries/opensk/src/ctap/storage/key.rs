// Copyright 2019-2020 Google LLC
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

/// Number of keys that persist the CTAP reset command.
pub const NUM_PERSISTENT_KEYS: usize = 20;

/// Defines a key given its name and value or range of values.
macro_rules! make_key {
    ($(#[$doc: meta])* $name: ident = $key: literal..$end: literal) => {
        $(#[$doc])* pub const $name: core::ops::Range<usize> = $key..$end;
    };
    ($(#[$doc: meta])* $name: ident = $key: literal) => {
        $(#[$doc])* pub const $name: usize = $key;
    };
}

/// Returns the range of values of a key given its value description.
#[cfg(test)]
macro_rules! make_range {
    ($key: literal..$end: literal) => {
        $key..$end
    };
    ($key: literal) => {
        $key..$key + 1
    };
}

/// Helper to define keys as a partial partition of a range.
macro_rules! make_partition {
        ($range: expr,
         $(
             $(#[$doc: meta])*
             $name: ident = $key: literal $(.. $end: literal)?;
         )*) => {
            $(
                make_key!($(#[$doc])* $name = $key $(.. $end)?);
            )*
            #[cfg(test)]
            const KEY_RANGE: core::ops::Range<usize> = $range;
            #[cfg(test)]
            const ALL_KEYS: &[core::ops::Range<usize>] = &[$(make_range!($key $(.. $end)?)),*];
        };
    }

make_partition! {
    // We reserve 0 and 2048+ for possible migration purposes. We add persistent entries starting
    // from 1 and going up. We add non-persistent entries starting from 2047 and going down. This
    // way, we don't commit to a fixed number of persistent keys.
    1..2048,

    // WARNING: Keys should not be deleted but prefixed with `_` to avoid accidentally reusing them.

    /// Reserved for the attestation store implementation of the environment.
    _RESERVED_ATTESTATION_STORE = 1..3;

    /// Used for the AAGUID before, but deprecated.
    _AAGUID = 3;

    // This is the persistent key limit:
    // - When adding a (persistent) key above this message, make sure its value is smaller than
    //   NUM_PERSISTENT_KEYS.
    // - When adding a (non-persistent) key below this message, make sure its value is bigger or
    //   equal than NUM_PERSISTENT_KEYS.

    /// Reserved for future credential-related objects.
    ///
    /// In particular, additional credentials could be added there by reducing the lower bound of
    /// the credential range below as well as the upper bound of this range in a similar manner.
    _RESERVED_CREDENTIALS = 1000..1700;

    /// The credentials.
    ///
    /// Depending on `Customization::max_supported_resident_keys()`, only a prefix of those keys is used.
    /// Each board may configure `Customization::max_supported_resident_keys()` depending on the
    /// storage size.
    CREDENTIALS = 1700..2000;

    /// Storage for the serialized large blob array.
    ///
    /// The stored large blob can be too big for one key, so it has to be sharded.
    LARGE_BLOB_SHARDS = 2000..2004;

    /// If this entry exists and is empty, alwaysUv is enabled.
    ALWAYS_UV = 2038;

    /// If this entry exists and is empty, enterprise attestation is enabled.
    #[cfg(feature = "config_command")]
    ENTERPRISE_ATTESTATION = 2039;

    /// If this entry exists and is empty, the PIN needs to be changed.
    FORCE_PIN_CHANGE = 2040;

    /// The secret of the CredRandom feature.
    _CRED_RANDOM_SECRET = 2041;

    /// List of RP IDs allowed to read the minimum PIN length.
    MIN_PIN_LENGTH_RP_IDS = 2042;

    /// The minimum PIN length.
    ///
    /// If the entry is absent, the minimum PIN length is `Customization::default_min_pin_length()`.
    MIN_PIN_LENGTH = 2043;

    /// The number of PIN retries.
    ///
    /// If the entry is absent, the number of PIN retries is `Customization::max_pin_retries()`.
    PIN_RETRIES = 2044;

    /// The PIN hash and length.
    ///
    /// If the entry is absent, there is no PIN set. The first byte represents
    /// the length, the following are an array with the hash.
    PIN_PROPERTIES = 2045;

    /// Reserved for the key store implementation of the environment.
    _RESERVED_KEY_STORE = 2046;

    /// The global signature counter.
    ///
    /// If the entry is absent, the counter is 0.
    GLOBAL_SIGNATURE_COUNTER = 2047;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::customization::Customization;
    use crate::env::test::TestEnv;
    use crate::env::Env;

    #[test]
    fn enough_credentials() {
        let env = TestEnv::default();
        assert!(
            env.customization().max_supported_resident_keys()
                <= CREDENTIALS.end - CREDENTIALS.start
        );
    }

    #[test]
    fn keys_are_disjoint() {
        // Check that keys are in the range.
        for keys in ALL_KEYS {
            assert!(KEY_RANGE.start <= keys.start && keys.end <= KEY_RANGE.end);
        }
        // Check that keys are assigned at most once, essentially partitioning the range.
        for key in KEY_RANGE {
            assert!(ALL_KEYS.iter().filter(|keys| keys.contains(&key)).count() <= 1);
        }
    }
}
