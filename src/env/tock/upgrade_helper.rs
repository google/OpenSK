// Copyright 2019-2023 Google LLC
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

// For compiling with std outside of tests.
#![cfg_attr(feature = "std", allow(dead_code))]

#[cfg(feature = "std")]
use crate::env::tock::buffer_upgrade_storage::BufferUpgradeStorage;
#[cfg(not(feature = "std"))]
use crate::env::tock::storage::TockUpgradeStorage;
use arrayref::array_ref;
use byteorder::{ByteOrder, LittleEndian};
use libtock_platform as platform;
use libtock_platform::Syscalls;
use opensk::api::crypto::ecdsa::{PublicKey as _, Signature as _};
use opensk::env::{EcdsaPk, EcdsaSignature, Env};
use persistent_store::{StorageError, StorageResult};

pub const METADATA_SIGN_OFFSET: usize = 0x800;

/// Parses the metadata of an upgrade, and checks its correctness.
///
/// The metadata is a page starting with:
/// - 32 B upgrade hash (SHA256)
/// - 64 B signature,
/// that are not signed over. The second part is included in the signature with
/// -  8 B version and
/// -  4 B partition address in little endian encoding
/// written at METADATA_SIGN_OFFSET.
///
/// Checks signature correctness against the hash, and whether the partition offset matches.
/// Whether the hash matches the partition content is not tested here!
pub fn check_metadata<
    E: Env,
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config,
>(
    #[cfg(not(feature = "std"))] upgrade_locations: &TockUpgradeStorage<S, C>,
    #[cfg(feature = "std")] upgrade_locations: &BufferUpgradeStorage<S, C>,
    public_key_bytes: &[u8],
    metadata: &[u8],
) -> StorageResult<()> {
    const METADATA_LEN: usize = 0x1000;
    if metadata.len() != METADATA_LEN {
        return Err(StorageError::CustomError);
    }

    let version = parse_metadata_version(metadata);
    if version < upgrade_locations.running_firmware_version() {
        return Err(StorageError::CustomError);
    }

    let metadata_address = LittleEndian::read_u32(&metadata[METADATA_SIGN_OFFSET + 8..][..4]);
    if metadata_address != upgrade_locations.bundle_identifier() {
        return Err(StorageError::CustomError);
    }

    verify_signature::<E>(
        array_ref!(metadata, 32, 64),
        public_key_bytes,
        parse_metadata_hash(metadata),
    )?;
    Ok(())
}

/// Parses the metadata, returns the hash.
pub fn parse_metadata_hash(data: &[u8]) -> &[u8; 32] {
    array_ref!(data, 0, 32)
}

/// Parses the metadata, returns the firmware version.
pub fn parse_metadata_version(data: &[u8]) -> u64 {
    LittleEndian::read_u64(&data[METADATA_SIGN_OFFSET..][..8])
}

/// Verifies the signature over the given hash.
///
/// The public key is COSE encoded, and the hash is a SHA256.
fn verify_signature<E: Env>(
    signature_bytes: &[u8; 64],
    public_key_bytes: &[u8],
    signed_hash: &[u8; 32],
) -> StorageResult<()> {
    let signature =
        EcdsaSignature::<E>::from_slice(signature_bytes).ok_or(StorageError::CustomError)?;
    if public_key_bytes.len() != 65 || public_key_bytes[0] != 0x04 {
        return Err(StorageError::CustomError);
    }
    let x = array_ref!(public_key_bytes, 1, 32);
    let y = array_ref!(public_key_bytes, 33, 32);
    let public_key = EcdsaPk::<E>::from_coordinates(x, y).ok_or(StorageError::CustomError)?;
    if !public_key.verify_prehash(signed_hash, &signature) {
        return Err(StorageError::CustomError);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use arrayref::mut_array_refs;
    use libtock_unittest::fake::Syscalls;
    use opensk::api::crypto::ecdsa::SecretKey as _;
    use opensk::api::crypto::sha256::Sha256;
    use opensk::api::crypto::{EC_FIELD_SIZE, EC_SIGNATURE_SIZE};
    use opensk::env::test::TestEnv;
    use opensk::env::{EcdsaSk, Sha};
    use platform::DefaultConfig;

    fn to_uncompressed(public_key: &EcdsaPk<TestEnv>) -> [u8; 1 + 2 * EC_FIELD_SIZE] {
        // Formatting according to:
        // https://tools.ietf.org/id/draft-jivsov-ecc-compact-05.html#overview
        const B0_BYTE_MARKER: u8 = 0x04;
        let mut representation = [0; 1 + 2 * EC_FIELD_SIZE];
        #[allow(clippy::ptr_offset_with_cast)]
        let (marker, x, y) = mut_array_refs![&mut representation, 1, EC_FIELD_SIZE, EC_FIELD_SIZE];
        marker[0] = B0_BYTE_MARKER;
        public_key.to_coordinates(x, y);
        representation
    }

    #[test]
    fn test_check_metadata() {
        let mut env = TestEnv::default();
        let private_key = EcdsaSk::<TestEnv>::random(env.rng());
        let upgrade_locations = BufferUpgradeStorage::new().unwrap();

        const METADATA_LEN: usize = 0x1000;
        const METADATA_SIGN_OFFSET: usize = 0x800;
        let mut metadata = vec![0xFF; METADATA_LEN];
        LittleEndian::write_u32(&mut metadata[METADATA_SIGN_OFFSET + 8..][..4], 0x60000);

        let mut signed_over_data = metadata[METADATA_SIGN_OFFSET..].to_vec();
        signed_over_data.extend(&[0xFF; 0x20000]);
        let signed_hash = Sha::<TestEnv>::digest(&signed_over_data);

        metadata[..32].copy_from_slice(&signed_hash);
        let signature = private_key.sign(&signed_over_data);
        let mut signature_bytes = [0; EC_SIGNATURE_SIZE];
        signature.to_slice(&mut signature_bytes);
        metadata[32..96].copy_from_slice(&signature_bytes);

        let public_key = private_key.public_key();
        let public_key_bytes = to_uncompressed(&public_key);

        assert_eq!(
            check_metadata::<TestEnv, Syscalls, DefaultConfig>(
                &upgrade_locations,
                &public_key_bytes,
                &metadata
            ),
            Ok(())
        );

        // Manipulating the partition address fails.
        metadata[METADATA_SIGN_OFFSET + 8] = 0x88;
        assert_eq!(
            check_metadata::<TestEnv, Syscalls, DefaultConfig>(
                &upgrade_locations,
                &public_key_bytes,
                &metadata
            ),
            Err(StorageError::CustomError)
        );
        metadata[METADATA_SIGN_OFFSET + 8] = 0x00;
        // Wrong metadata length fails.
        assert_eq!(
            check_metadata::<TestEnv, Syscalls, DefaultConfig>(
                &upgrade_locations,
                &public_key_bytes,
                &metadata[..METADATA_LEN - 1]
            ),
            Err(StorageError::CustomError)
        );
        // Manipulating the hash fails.
        metadata[0] ^= 0x01;
        assert_eq!(
            check_metadata::<TestEnv, Syscalls, DefaultConfig>(
                &upgrade_locations,
                &public_key_bytes,
                &metadata
            ),
            Err(StorageError::CustomError)
        );
        metadata[0] ^= 0x01;
        // Manipulating the signature fails.
        metadata[32] ^= 0x01;
        assert_eq!(
            check_metadata::<TestEnv, Syscalls, DefaultConfig>(
                &upgrade_locations,
                &public_key_bytes,
                &metadata
            ),
            Err(StorageError::CustomError)
        );
    }

    #[test]
    fn test_verify_signature() {
        let mut env = TestEnv::default();
        let private_key = EcdsaSk::<TestEnv>::random(env.rng());
        let message = [0x44; 64];
        let signed_hash = Sha::<TestEnv>::digest(&message);
        let signature = private_key.sign(&message);

        let mut signature_bytes = [0; EC_SIGNATURE_SIZE];
        signature.to_slice(&mut signature_bytes);

        let public_key = private_key.public_key();
        let mut public_key_bytes = to_uncompressed(&public_key);

        assert_eq!(
            verify_signature::<TestEnv>(&signature_bytes, &public_key_bytes, &signed_hash),
            Ok(())
        );
        assert_eq!(
            verify_signature::<TestEnv>(&signature_bytes, &public_key_bytes, &[0x55; 32]),
            Err(StorageError::CustomError)
        );
        public_key_bytes[0] ^= 0x01;
        assert_eq!(
            verify_signature::<TestEnv>(&signature_bytes, &public_key_bytes, &signed_hash),
            Err(StorageError::CustomError)
        );
        public_key_bytes[0] ^= 0x01;
        signature_bytes[0] ^= 0x01;
        assert_eq!(
            verify_signature::<TestEnv>(&signature_bytes, &public_key_bytes, &signed_hash),
            Err(StorageError::CustomError)
        );
    }
}
