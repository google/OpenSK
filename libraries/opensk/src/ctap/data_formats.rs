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

use super::status_code::Ctap2StatusCode;
use crate::api::crypto::{ecdh, ecdsa, EC_FIELD_SIZE};
use crate::api::private_key::PrivateKey;
use crate::env::{AesKey, Env};
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use arrayref::array_ref;
use core::convert::TryFrom;
#[cfg(test)]
use enum_iterator::IntoEnumIterator;
use sk_cbor as cbor;
use sk_cbor::{cbor_array_vec, cbor_map, cbor_map_options, destructure_cbor_map};

// Used as the identifier for ECDSA in assertion signatures and COSE.
pub const ES256_ALGORITHM: i64 = -7;
#[cfg(feature = "ed25519")]
pub const EDDSA_ALGORITHM: i64 = -8;

// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrpentity
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct PublicKeyCredentialRpEntity {
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub rp_icon: Option<String>,
}

impl TryFrom<cbor::Value> for PublicKeyCredentialRpEntity {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                "id" => rp_id,
                "icon" => rp_icon,
                "name" => rp_name,
            } = extract_map(cbor_value)?;
        }

        let rp_id = extract_text_string(ok_or_missing(rp_id)?)?;
        let rp_name = rp_name.map(extract_text_string).transpose()?;
        let rp_icon = rp_icon.map(extract_text_string).transpose()?;

        Ok(Self {
            rp_id,
            rp_name,
            rp_icon,
        })
    }
}

impl From<PublicKeyCredentialRpEntity> for cbor::Value {
    fn from(entity: PublicKeyCredentialRpEntity) -> Self {
        cbor_map_options! {
            "id" => entity.rp_id,
            "icon" => entity.rp_icon,
            "name" => entity.rp_name,
        }
    }
}

// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialuserentity
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct PublicKeyCredentialUserEntity {
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub user_icon: Option<String>,
}

impl TryFrom<cbor::Value> for PublicKeyCredentialUserEntity {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                "id" => user_id,
                "icon" => user_icon,
                "name" => user_name,
                "displayName" => user_display_name,
            } = extract_map(cbor_value)?;
        }

        let user_id = extract_byte_string(ok_or_missing(user_id)?)?;
        let user_name = user_name.map(extract_text_string).transpose()?;
        let user_display_name = user_display_name.map(extract_text_string).transpose()?;
        let user_icon = user_icon.map(extract_text_string).transpose()?;

        Ok(Self {
            user_id,
            user_name,
            user_display_name,
            user_icon,
        })
    }
}

impl From<PublicKeyCredentialUserEntity> for cbor::Value {
    fn from(entity: PublicKeyCredentialUserEntity) -> Self {
        cbor_map_options! {
            "id" => entity.user_id,
            "icon" => entity.user_icon,
            "name" => entity.user_name,
            "displayName" => entity.user_display_name,
        }
    }
}

// https://www.w3.org/TR/webauthn/#enumdef-publickeycredentialtype
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub enum PublicKeyCredentialType {
    PublicKey,
    // This is the default for all strings not covered above.
    // Unknown types should be ignored, instead of returning errors.
    Unknown,
}

impl From<PublicKeyCredentialType> for cbor::Value {
    fn from(cred_type: PublicKeyCredentialType) -> Self {
        match cred_type {
            PublicKeyCredentialType::PublicKey => "public-key",
            // We should never create this credential type.
            PublicKeyCredentialType::Unknown => "unknown",
        }
        .into()
    }
}

impl TryFrom<cbor::Value> for PublicKeyCredentialType {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        let cred_type_string = extract_text_string(cbor_value)?;
        match &cred_type_string[..] {
            "public-key" => Ok(PublicKeyCredentialType::PublicKey),
            _ => Ok(PublicKeyCredentialType::Unknown),
        }
    }
}

// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialparameters
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct PublicKeyCredentialParameter {
    pub cred_type: PublicKeyCredentialType,
    pub alg: SignatureAlgorithm,
}

impl TryFrom<cbor::Value> for PublicKeyCredentialParameter {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                "alg" => alg,
                "type" => cred_type,
            } = extract_map(cbor_value)?;
        }

        let cred_type = PublicKeyCredentialType::try_from(ok_or_missing(cred_type)?)?;
        let alg = SignatureAlgorithm::try_from(ok_or_missing(alg)?)?;
        Ok(Self { cred_type, alg })
    }
}

impl From<PublicKeyCredentialParameter> for cbor::Value {
    fn from(cred_param: PublicKeyCredentialParameter) -> Self {
        cbor_map_options! {
            "alg" => cred_param.alg,
            "type" => cred_param.cred_type,
        }
    }
}

// https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(IntoEnumIterator))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub enum AuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    Internal,
}

impl From<AuthenticatorTransport> for cbor::Value {
    fn from(transport: AuthenticatorTransport) -> Self {
        match transport {
            AuthenticatorTransport::Usb => "usb",
            AuthenticatorTransport::Nfc => "nfc",
            AuthenticatorTransport::Ble => "ble",
            AuthenticatorTransport::Internal => "internal",
        }
        .into()
    }
}

impl TryFrom<cbor::Value> for AuthenticatorTransport {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        let transport_string = extract_text_string(cbor_value)?;
        match &transport_string[..] {
            "usb" => Ok(AuthenticatorTransport::Usb),
            "nfc" => Ok(AuthenticatorTransport::Nfc),
            "ble" => Ok(AuthenticatorTransport::Ble),
            "internal" => Ok(AuthenticatorTransport::Internal),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
        }
    }
}

// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct PublicKeyCredentialDescriptor {
    pub key_type: PublicKeyCredentialType,
    pub key_id: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

impl TryFrom<cbor::Value> for PublicKeyCredentialDescriptor {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                "id" => key_id,
                "type" => key_type,
                "transports" => transports,
            } = extract_map(cbor_value)?;
        }

        let key_type = PublicKeyCredentialType::try_from(ok_or_missing(key_type)?)?;
        let key_id = extract_byte_string(ok_or_missing(key_id)?)?;
        let transports = match transports {
            Some(exclude_entry) => {
                let transport_vec = extract_array(exclude_entry)?;
                let transports = transport_vec
                    .into_iter()
                    .map(AuthenticatorTransport::try_from)
                    .collect::<Result<Vec<AuthenticatorTransport>, Ctap2StatusCode>>()?;
                Some(transports)
            }
            None => None,
        };

        Ok(Self {
            key_type,
            key_id,
            transports,
        })
    }
}

impl From<PublicKeyCredentialDescriptor> for cbor::Value {
    fn from(desc: PublicKeyCredentialDescriptor) -> Self {
        cbor_map_options! {
            "id" => desc.key_id,
            "type" => desc.key_type,
            "transports" => desc.transports.map(|vec| cbor_array_vec!(vec)),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct MakeCredentialExtensions {
    pub hmac_secret: bool,
    pub cred_protect: Option<CredentialProtectionPolicy>,
    pub min_pin_length: bool,
    pub cred_blob: Option<Vec<u8>>,
    pub large_blob_key: Option<bool>,
}

impl TryFrom<cbor::Value> for MakeCredentialExtensions {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                "credBlob" => cred_blob,
                "credProtect" => cred_protect,
                "hmac-secret" => hmac_secret,
                "largeBlobKey" => large_blob_key,
                "minPinLength" => min_pin_length,
            } = extract_map(cbor_value)?;
        }

        let hmac_secret = hmac_secret.map_or(Ok(false), extract_bool)?;
        let cred_protect = cred_protect
            .map(CredentialProtectionPolicy::try_from)
            .transpose()?;
        let min_pin_length = min_pin_length.map_or(Ok(false), extract_bool)?;
        let cred_blob = cred_blob.map(extract_byte_string).transpose()?;
        let large_blob_key = large_blob_key.map(extract_bool).transpose()?;
        if let Some(large_blob_key) = large_blob_key {
            if !large_blob_key {
                return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
            }
        }
        Ok(Self {
            hmac_secret,
            cred_protect,
            min_pin_length,
            cred_blob,
            large_blob_key,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct GetAssertionExtensions {
    pub hmac_secret: Option<GetAssertionHmacSecretInput>,
    pub cred_blob: bool,
    pub large_blob_key: Option<bool>,
}

impl TryFrom<cbor::Value> for GetAssertionExtensions {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                "credBlob" => cred_blob,
                "hmac-secret" => hmac_secret,
                "largeBlobKey" => large_blob_key,
            } = extract_map(cbor_value)?;
        }

        let hmac_secret = hmac_secret
            .map(GetAssertionHmacSecretInput::try_from)
            .transpose()?;
        let cred_blob = cred_blob.map_or(Ok(false), extract_bool)?;
        let large_blob_key = large_blob_key.map(extract_bool).transpose()?;
        if let Some(large_blob_key) = large_blob_key {
            if !large_blob_key {
                return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
            }
        }
        Ok(Self {
            hmac_secret,
            cred_blob,
            large_blob_key,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct GetAssertionHmacSecretInput {
    pub key_agreement: CoseKey,
    pub salt_enc: Vec<u8>,
    pub salt_auth: Vec<u8>,
    pub pin_uv_auth_protocol: PinUvAuthProtocol,
}

impl TryFrom<cbor::Value> for GetAssertionHmacSecretInput {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                1 => key_agreement,
                2 => salt_enc,
                3 => salt_auth,
                4 => pin_uv_auth_protocol,
            } = extract_map(cbor_value)?;
        }

        let key_agreement = CoseKey::try_from(ok_or_missing(key_agreement)?)?;
        let salt_enc = extract_byte_string(ok_or_missing(salt_enc)?)?;
        let salt_auth = extract_byte_string(ok_or_missing(salt_auth)?)?;
        let pin_uv_auth_protocol =
            pin_uv_auth_protocol.map_or(Ok(PinUvAuthProtocol::V1), PinUvAuthProtocol::try_from)?;
        Ok(Self {
            key_agreement,
            salt_enc,
            salt_auth,
            pin_uv_auth_protocol,
        })
    }
}

// Even though options are optional, we can use the default if not present.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct MakeCredentialOptions {
    pub rk: bool,
    pub uv: bool,
}

impl TryFrom<cbor::Value> for MakeCredentialOptions {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                "rk" => rk,
                "up" => up,
                "uv" => uv,
            } = extract_map(cbor_value)?;
        }

        let rk = match rk {
            Some(options_entry) => extract_bool(options_entry)?,
            None => false,
        };
        // In CTAP2.0, the up option is supposed to always fail when present.
        if let Some(options_entry) = up {
            if !extract_bool(options_entry)? {
                return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
            }
        }
        let uv = match uv {
            Some(options_entry) => extract_bool(options_entry)?,
            None => false,
        };
        Ok(Self { rk, uv })
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct GetAssertionOptions {
    pub up: bool,
    pub uv: bool,
}

impl Default for GetAssertionOptions {
    fn default() -> Self {
        GetAssertionOptions {
            up: true,
            uv: false,
        }
    }
}

impl TryFrom<cbor::Value> for GetAssertionOptions {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                "rk" => rk,
                "up" => up,
                "uv" => uv,
            } = extract_map(cbor_value)?;
        }

        if let Some(options_entry) = rk {
            // This is only for returning the correct status code.
            extract_bool(options_entry)?;
            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
        }
        let up = match up {
            Some(options_entry) => extract_bool(options_entry)?,
            None => true,
        };
        let uv = match uv {
            Some(options_entry) => extract_bool(options_entry)?,
            None => false,
        };
        Ok(Self { up, uv })
    }
}

// https://www.w3.org/TR/webauthn/#packed-attestation
#[derive(Debug, PartialEq, Eq)]
pub struct PackedAttestationStatement {
    pub alg: i64,
    pub sig: Vec<u8>,
    pub x5c: Option<Vec<Vec<u8>>>,
    pub ecdaa_key_id: Option<Vec<u8>>,
}

impl From<PackedAttestationStatement> for cbor::Value {
    fn from(att_stmt: PackedAttestationStatement) -> Self {
        cbor_map_options! {
            "alg" => att_stmt.alg,
            "sig" => att_stmt.sig,
            "x5c" => att_stmt.x5c.map(|x| cbor_array_vec!(x)),
            "ecdaaKeyId" => att_stmt.ecdaa_key_id,
        }
    }
}

/// Signature algorithm identifier, as specified for COSE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub enum SignatureAlgorithm {
    Es256 = ES256_ALGORITHM as isize,
    #[cfg(feature = "ed25519")]
    Eddsa = EDDSA_ALGORITHM as isize,
    // This is the default for all numbers not covered above.
    // Unknown types should be ignored, instead of returning errors.
    Unknown = 0,
}

impl From<SignatureAlgorithm> for cbor::Value {
    fn from(alg: SignatureAlgorithm) -> Self {
        (alg as i64).into()
    }
}

impl From<i64> for SignatureAlgorithm {
    fn from(int: i64) -> Self {
        match int {
            ES256_ALGORITHM => SignatureAlgorithm::Es256,
            #[cfg(feature = "ed25519")]
            EDDSA_ALGORITHM => SignatureAlgorithm::Eddsa,
            _ => SignatureAlgorithm::Unknown,
        }
    }
}

impl TryFrom<cbor::Value> for SignatureAlgorithm {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        extract_integer(cbor_value).map(SignatureAlgorithm::from)
    }
}

/// The credProtect extension's policies for resident credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
#[cfg_attr(test, derive(IntoEnumIterator))]
#[allow(clippy::enum_variant_names)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub enum CredentialProtectionPolicy {
    /// The credential is always discoverable, as if it had no protection level.
    UserVerificationOptional = 0x01,
    /// The credential is discoverable with
    /// - an allowList,
    /// - an excludeList,
    /// - user verification.
    UserVerificationOptionalWithCredentialIdList = 0x02,
    /// The credentials is discoverable with user verification only.
    UserVerificationRequired = 0x03,
}

impl From<CredentialProtectionPolicy> for cbor::Value {
    fn from(policy: CredentialProtectionPolicy) -> Self {
        (policy as i64).into()
    }
}

impl TryFrom<cbor::Value> for CredentialProtectionPolicy {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        match extract_integer(cbor_value)? {
            0x01 => Ok(CredentialProtectionPolicy::UserVerificationOptional),
            0x02 => Ok(CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList),
            0x03 => Ok(CredentialProtectionPolicy::UserVerificationRequired),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
        }
    }
}

// https://www.w3.org/TR/webauthn/#public-key-credential-source
//
// Note that we only use the WebAuthn definition as an example. This data-structure is not specified
// by FIDO. In particular we may choose how we serialize and deserialize it.
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PublicKeyCredentialSource {
    pub key_type: PublicKeyCredentialType,
    pub credential_id: Vec<u8>,
    pub private_key: PrivateKey,
    pub rp_id: String,
    pub user_handle: Vec<u8>, // not optional, but nullable
    pub user_display_name: Option<String>,
    pub cred_protect_policy: Option<CredentialProtectionPolicy>,
    pub creation_order: u64,
    pub user_name: Option<String>,
    pub user_icon: Option<String>,
    pub cred_blob: Option<Vec<u8>>,
    pub large_blob_key: Option<Vec<u8>>,
}

// We serialize credentials for the persistent storage using CBOR maps. Each field of a credential
// is associated with a unique tag, implemented with a CBOR unsigned key.
enum PublicKeyCredentialSourceField {
    CredentialId = 0,
    RpId = 2,
    UserHandle = 3,
    UserDisplayName = 4,
    CredProtectPolicy = 6,
    CreationOrder = 7,
    UserName = 8,
    UserIcon = 9,
    CredBlob = 10,
    LargeBlobKey = 11,
    PrivateKey = 12,
    // When a field is removed, its tag should be reserved and not used for new fields. We document
    // those reserved tags below.
    // Reserved tags:
    // - EcdsaPrivateKey = 1,
    // - CredRandom = 5,
}

impl From<PublicKeyCredentialSourceField> for cbor::Value {
    fn from(field: PublicKeyCredentialSourceField) -> cbor::Value {
        (field as u64).into()
    }
}

impl PublicKeyCredentialSource {
    // Relying parties do not need to provide the credential ID in an allow_list if true.
    pub fn is_discoverable(&self) -> bool {
        self.cred_protect_policy.is_none()
            || self.cred_protect_policy
                == Some(CredentialProtectionPolicy::UserVerificationOptional)
    }

    pub fn to_cbor<E: Env>(
        self,
        rng: &mut E::Rng,
        wrap_key: &AesKey<E>,
    ) -> Result<cbor::Value, Ctap2StatusCode> {
        Ok(cbor_map_options! {
            PublicKeyCredentialSourceField::CredentialId => Some(self.credential_id),
            PublicKeyCredentialSourceField::RpId => Some(self.rp_id),
            PublicKeyCredentialSourceField::UserHandle => Some(self.user_handle),
            PublicKeyCredentialSourceField::UserDisplayName => self.user_display_name,
            PublicKeyCredentialSourceField::CredProtectPolicy => self.cred_protect_policy,
            PublicKeyCredentialSourceField::CreationOrder => self.creation_order,
            PublicKeyCredentialSourceField::UserName => self.user_name,
            PublicKeyCredentialSourceField::UserIcon => self.user_icon,
            PublicKeyCredentialSourceField::CredBlob => self.cred_blob,
            PublicKeyCredentialSourceField::LargeBlobKey => self.large_blob_key,
            PublicKeyCredentialSourceField::PrivateKey => self.private_key.to_cbor::<E>(rng, wrap_key)?,
        })
    }

    pub fn from_cbor<E: Env>(
        wrap_key: &AesKey<E>,
        cbor_value: cbor::Value,
    ) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                PublicKeyCredentialSourceField::CredentialId => credential_id,
                PublicKeyCredentialSourceField::RpId => rp_id,
                PublicKeyCredentialSourceField::UserHandle => user_handle,
                PublicKeyCredentialSourceField::UserDisplayName => user_display_name,
                PublicKeyCredentialSourceField::CredProtectPolicy => cred_protect_policy,
                PublicKeyCredentialSourceField::CreationOrder => creation_order,
                PublicKeyCredentialSourceField::UserName => user_name,
                PublicKeyCredentialSourceField::UserIcon => user_icon,
                PublicKeyCredentialSourceField::CredBlob => cred_blob,
                PublicKeyCredentialSourceField::LargeBlobKey => large_blob_key,
                PublicKeyCredentialSourceField::PrivateKey => private_key,
            } = extract_map(cbor_value)?;
        }

        let credential_id = extract_byte_string(ok_or_missing(credential_id)?)?;
        let rp_id = extract_text_string(ok_or_missing(rp_id)?)?;
        let user_handle = extract_byte_string(ok_or_missing(user_handle)?)?;
        let user_display_name = user_display_name.map(extract_text_string).transpose()?;
        let cred_protect_policy = cred_protect_policy
            .map(CredentialProtectionPolicy::try_from)
            .transpose()?;
        let creation_order = creation_order.map_or(Ok(0), extract_unsigned)?;
        let user_name = user_name.map(extract_text_string).transpose()?;
        let user_icon = user_icon.map(extract_text_string).transpose()?;
        let cred_blob = cred_blob.map(extract_byte_string).transpose()?;
        let large_blob_key = large_blob_key.map(extract_byte_string).transpose()?;
        let private_key = PrivateKey::from_cbor::<E>(wrap_key, ok_or_missing(private_key)?)?;

        // We don't return whether there were unknown fields in the CBOR value. This means that
        // deserialization is not injective. In particular deserialization is only an inverse of
        // serialization at a given version of OpenSK. This is not a problem because:
        // 1. When a field is deprecated, its tag is reserved and never reused in future versions,
        //    including to be reintroduced with the same semantics. In other words, removing a field
        //    is permanent.
        // 2. OpenSK is never used with a more recent version of the storage. In particular, OpenSK
        //    is never rolled-back.
        // As a consequence, the unknown fields are only reserved fields and don't need to be
        // preserved.
        Ok(PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key,
            rp_id,
            user_handle,
            user_display_name,
            cred_protect_policy,
            creation_order,
            user_name,
            user_icon,
            cred_blob,
            large_blob_key,
        })
    }
}

// The COSE key is used for both ECDH and ECDSA public keys for transmission.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct CoseKey {
    x_bytes: [u8; EC_FIELD_SIZE],
    y_bytes: [u8; EC_FIELD_SIZE],
    algorithm: i64,
    key_type: i64,
    curve: i64,
}

impl CoseKey {
    // This is the algorithm specifier for ECDH.
    // CTAP requests -25 which represents ECDH-ES + HKDF-256 here:
    // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    const ECDH_ALGORITHM: i64 = -25;
    // The parameter behind map key 1.
    const EC2_KEY_TYPE: i64 = 2;
    #[cfg(feature = "ed25519")]
    const OKP_KEY_TYPE: i64 = 1;
    // The parameter behind map key -1.
    const P_256_CURVE: i64 = 1;
    #[cfg(feature = "ed25519")]
    const ED25519_CURVE: i64 = 6;

    pub fn from_ecdh_public_key(pk: impl ecdh::PublicKey) -> Self {
        let mut x_bytes = [0; EC_FIELD_SIZE];
        let mut y_bytes = [0; EC_FIELD_SIZE];
        pk.to_coordinates(&mut x_bytes, &mut y_bytes);
        CoseKey {
            x_bytes,
            y_bytes,
            algorithm: CoseKey::ECDH_ALGORITHM,
            key_type: CoseKey::EC2_KEY_TYPE,
            curve: CoseKey::P_256_CURVE,
        }
    }

    pub fn from_ecdsa_public_key(pk: impl ecdsa::PublicKey) -> Self {
        let mut x_bytes = [0; EC_FIELD_SIZE];
        let mut y_bytes = [0; EC_FIELD_SIZE];
        pk.to_coordinates(&mut x_bytes, &mut y_bytes);
        CoseKey {
            x_bytes,
            y_bytes,
            algorithm: ES256_ALGORITHM,
            key_type: CoseKey::EC2_KEY_TYPE,
            curve: CoseKey::P_256_CURVE,
        }
    }

    /// Returns the x and y coordinates, if the key is an ECDH public key.
    pub fn try_into_ecdh_coordinates(
        self,
    ) -> Result<([u8; EC_FIELD_SIZE], [u8; EC_FIELD_SIZE]), Ctap2StatusCode> {
        let CoseKey {
            x_bytes,
            y_bytes,
            algorithm,
            key_type,
            curve,
        } = self;

        // Since algorithm can be used for different COSE key types, we check
        // whether the current type is correct for ECDH. For an OpenSSH bugfix,
        // the algorithm ES256_ALGORITHM is allowed here too.
        // https://github.com/google/OpenSK/issues/90
        if algorithm != CoseKey::ECDH_ALGORITHM && algorithm != ES256_ALGORITHM {
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }
        if key_type != CoseKey::EC2_KEY_TYPE || curve != CoseKey::P_256_CURVE {
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }
        Ok((x_bytes, y_bytes))
    }

    #[cfg(test)]
    pub fn example_ecdh_pubkey() -> Self {
        let x_bytes = [
            0x74, 0x4A, 0x48, 0xA0, 0xDC, 0x56, 0x9A, 0x42, 0x0B, 0x3F, 0x58, 0xBF, 0xD8, 0xD9,
            0x62, 0xCF, 0x3A, 0xEA, 0xB1, 0x5A, 0x32, 0x03, 0xC1, 0xA4, 0x23, 0x8B, 0x57, 0x75,
            0x74, 0xA4, 0x29, 0x50,
        ];
        let y_bytes = [
            0xCD, 0x93, 0x26, 0x4A, 0xAF, 0x2A, 0xBA, 0xD1, 0x09, 0x3D, 0x2E, 0xD6, 0x8C, 0xC0,
            0x59, 0xB1, 0xD9, 0xAB, 0xD7, 0x81, 0x71, 0x60, 0x35, 0xFE, 0xFF, 0xE8, 0xE1, 0x94,
            0x05, 0x60, 0xA0, 0xBC,
        ];
        CoseKey {
            x_bytes,
            y_bytes,
            algorithm: CoseKey::ECDH_ALGORITHM,
            key_type: CoseKey::EC2_KEY_TYPE,
            curve: CoseKey::P_256_CURVE,
        }
    }
}

// This conversion accepts both ECDH and ECDSA.
impl TryFrom<cbor::Value> for CoseKey {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                // This is sorted correctly, negative encoding is bigger.
                1 => key_type,
                3 => algorithm,
                -1 => curve,
                -2 => x_bytes,
                -3 => y_bytes,
            } = extract_map(cbor_value)?;
        }

        let algorithm = extract_integer(ok_or_missing(algorithm)?)?;
        if algorithm != CoseKey::ECDH_ALGORITHM && algorithm != ES256_ALGORITHM {
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        };
        let x_bytes = extract_byte_string(ok_or_missing(x_bytes)?)?;
        if x_bytes.len() != EC_FIELD_SIZE {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        let y_bytes = extract_byte_string(ok_or_missing(y_bytes)?)?;
        if y_bytes.len() != EC_FIELD_SIZE {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        let curve = extract_integer(ok_or_missing(curve)?)?;
        if curve != CoseKey::P_256_CURVE {
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }
        let key_type = extract_integer(ok_or_missing(key_type)?)?;
        if key_type != CoseKey::EC2_KEY_TYPE {
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }

        Ok(CoseKey {
            x_bytes: *array_ref![x_bytes.as_slice(), 0, EC_FIELD_SIZE],
            y_bytes: *array_ref![y_bytes.as_slice(), 0, EC_FIELD_SIZE],
            algorithm,
            key_type,
            curve,
        })
    }
}

impl From<CoseKey> for cbor::Value {
    fn from(cose_key: CoseKey) -> Self {
        let CoseKey {
            x_bytes,
            y_bytes,
            algorithm,
            key_type,
            curve,
        } = cose_key;

        cbor_map! {
            1 => key_type,
            3 => algorithm,
            -1 => curve,
            -2 => x_bytes,
            -3 => y_bytes,
        }
    }
}

#[cfg(feature = "ed25519")]
impl From<ed25519_compact::PublicKey> for CoseKey {
    fn from(pk: ed25519_compact::PublicKey) -> Self {
        CoseKey {
            x_bytes: *pk,
            y_bytes: [0u8; 32],
            key_type: CoseKey::OKP_KEY_TYPE,
            curve: CoseKey::ED25519_CURVE,
            algorithm: EDDSA_ALGORITHM,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub enum PinUvAuthProtocol {
    V1 = 1,
    V2 = 2,
}

impl TryFrom<cbor::Value> for PinUvAuthProtocol {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        match extract_unsigned(cbor_value)? {
            1 => Ok(PinUvAuthProtocol::V1),
            2 => Ok(PinUvAuthProtocol::V2),
            _ => Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(IntoEnumIterator))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub enum ClientPinSubCommand {
    GetPinRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUvRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

impl From<ClientPinSubCommand> for cbor::Value {
    fn from(subcommand: ClientPinSubCommand) -> Self {
        (subcommand as u64).into()
    }
}

impl TryFrom<cbor::Value> for ClientPinSubCommand {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        let subcommand_int = extract_unsigned(cbor_value)?;
        match subcommand_int {
            0x01 => Ok(ClientPinSubCommand::GetPinRetries),
            0x02 => Ok(ClientPinSubCommand::GetKeyAgreement),
            0x03 => Ok(ClientPinSubCommand::SetPin),
            0x04 => Ok(ClientPinSubCommand::ChangePin),
            0x05 => Ok(ClientPinSubCommand::GetPinToken),
            0x06 => Ok(ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions),
            0x07 => Ok(ClientPinSubCommand::GetUvRetries),
            0x09 => Ok(ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(IntoEnumIterator))]
pub enum ConfigSubCommand {
    EnableEnterpriseAttestation = 0x01,
    ToggleAlwaysUv = 0x02,
    SetMinPinLength = 0x03,
    VendorPrototype = 0xFF,
}

impl From<ConfigSubCommand> for cbor::Value {
    fn from(subcommand: ConfigSubCommand) -> Self {
        (subcommand as u64).into()
    }
}

impl TryFrom<cbor::Value> for ConfigSubCommand {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        let subcommand_int = extract_unsigned(cbor_value)?;
        match subcommand_int {
            0x01 => Ok(ConfigSubCommand::EnableEnterpriseAttestation),
            0x02 => Ok(ConfigSubCommand::ToggleAlwaysUv),
            0x03 => Ok(ConfigSubCommand::SetMinPinLength),
            0xFF => Ok(ConfigSubCommand::VendorPrototype),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigSubCommandParams {
    SetMinPinLength(SetMinPinLengthParams),
}

impl From<ConfigSubCommandParams> for cbor::Value {
    fn from(params: ConfigSubCommandParams) -> Self {
        match params {
            ConfigSubCommandParams::SetMinPinLength(set_min_pin_length_params) => {
                set_min_pin_length_params.into()
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetMinPinLengthParams {
    pub new_min_pin_length: Option<u8>,
    pub min_pin_length_rp_ids: Option<Vec<String>>,
    pub force_change_pin: Option<bool>,
}

impl TryFrom<cbor::Value> for SetMinPinLengthParams {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                0x01 => new_min_pin_length,
                0x02 => min_pin_length_rp_ids,
                0x03 => force_change_pin,
            } = extract_map(cbor_value)?;
        }

        let new_min_pin_length = new_min_pin_length
            .map(extract_unsigned)
            .transpose()?
            .map(u8::try_from)
            .transpose()
            .map_err(|_| Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION)?;
        let min_pin_length_rp_ids = match min_pin_length_rp_ids {
            Some(entry) => Some(
                extract_array(entry)?
                    .into_iter()
                    .map(extract_text_string)
                    .collect::<Result<Vec<String>, Ctap2StatusCode>>()?,
            ),
            None => None,
        };
        let force_change_pin = force_change_pin.map(extract_bool).transpose()?;

        Ok(Self {
            new_min_pin_length,
            min_pin_length_rp_ids,
            force_change_pin,
        })
    }
}

impl From<SetMinPinLengthParams> for cbor::Value {
    fn from(params: SetMinPinLengthParams) -> Self {
        cbor_map_options! {
            0x01 => params.new_min_pin_length.map(|u| u as u64),
            0x02 => params.min_pin_length_rp_ids.map(|vec| cbor_array_vec!(vec)),
            0x03 => params.force_change_pin,
        }
    }
}

/// The level of enterprise attestation allowed in MakeCredential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub enum EnterpriseAttestationMode {
    /// Enterprise attestation is restricted to a list of RP IDs. Add your
    /// enterprises domain, e.g. "example.com", to the list below.
    VendorFacilitated = 0x01,
    /// All relying parties can request an enterprise attestation. The authenticator
    /// trusts the platform to filter requests.
    PlatformManaged = 0x02,
}

impl TryFrom<u64> for EnterpriseAttestationMode {
    type Error = Ctap2StatusCode;

    fn try_from(value: u64) -> Result<Self, Ctap2StatusCode> {
        match value {
            1 => Ok(EnterpriseAttestationMode::VendorFacilitated),
            2 => Ok(EnterpriseAttestationMode::PlatformManaged),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(IntoEnumIterator))]
pub enum CredentialManagementSubCommand {
    GetCredsMetadata = 0x01,
    EnumerateRpsBegin = 0x02,
    EnumerateRpsGetNextRp = 0x03,
    EnumerateCredentialsBegin = 0x04,
    EnumerateCredentialsGetNextCredential = 0x05,
    DeleteCredential = 0x06,
    UpdateUserInformation = 0x07,
}

impl From<CredentialManagementSubCommand> for cbor::Value {
    fn from(subcommand: CredentialManagementSubCommand) -> Self {
        (subcommand as u64).into()
    }
}

impl TryFrom<cbor::Value> for CredentialManagementSubCommand {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        let subcommand_int = extract_unsigned(cbor_value)?;
        match subcommand_int {
            0x01 => Ok(CredentialManagementSubCommand::GetCredsMetadata),
            0x02 => Ok(CredentialManagementSubCommand::EnumerateRpsBegin),
            0x03 => Ok(CredentialManagementSubCommand::EnumerateRpsGetNextRp),
            0x04 => Ok(CredentialManagementSubCommand::EnumerateCredentialsBegin),
            0x05 => Ok(CredentialManagementSubCommand::EnumerateCredentialsGetNextCredential),
            0x06 => Ok(CredentialManagementSubCommand::DeleteCredential),
            0x07 => Ok(CredentialManagementSubCommand::UpdateUserInformation),
            _ => Err(Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialManagementSubCommandParameters {
    pub rp_id_hash: Option<Vec<u8>>,
    pub credential_id: Option<PublicKeyCredentialDescriptor>,
    pub user: Option<PublicKeyCredentialUserEntity>,
}

impl TryFrom<cbor::Value> for CredentialManagementSubCommandParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                0x01 => rp_id_hash,
                0x02 => credential_id,
                0x03 => user,
            } = extract_map(cbor_value)?;
        }

        let rp_id_hash = rp_id_hash.map(extract_byte_string).transpose()?;
        let credential_id = credential_id
            .map(PublicKeyCredentialDescriptor::try_from)
            .transpose()?;
        let user = user
            .map(PublicKeyCredentialUserEntity::try_from)
            .transpose()?;
        Ok(Self {
            rp_id_hash,
            credential_id,
            user,
        })
    }
}

impl From<CredentialManagementSubCommandParameters> for cbor::Value {
    fn from(sub_command_params: CredentialManagementSubCommandParameters) -> Self {
        cbor_map_options! {
            0x01 => sub_command_params.rp_id_hash,
            0x02 => sub_command_params.credential_id,
            0x03 => sub_command_params.user,
        }
    }
}

fn ok_or_cbor_type<T>(value_option: Option<T>) -> Result<T, Ctap2StatusCode> {
    value_option.ok_or(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
}

pub fn extract_unsigned(cbor_value: cbor::Value) -> Result<u64, Ctap2StatusCode> {
    ok_or_cbor_type(cbor_value.extract_unsigned())
}

pub fn extract_integer(cbor_value: cbor::Value) -> Result<i64, Ctap2StatusCode> {
    ok_or_cbor_type(cbor_value.extract_integer())
}

pub fn extract_byte_string(cbor_value: cbor::Value) -> Result<Vec<u8>, Ctap2StatusCode> {
    ok_or_cbor_type(cbor_value.extract_byte_string())
}

pub fn extract_text_string(cbor_value: cbor::Value) -> Result<String, Ctap2StatusCode> {
    ok_or_cbor_type(cbor_value.extract_text_string())
}

pub fn extract_array(cbor_value: cbor::Value) -> Result<Vec<cbor::Value>, Ctap2StatusCode> {
    ok_or_cbor_type(cbor_value.extract_array())
}

pub fn extract_map(
    cbor_value: cbor::Value,
) -> Result<Vec<(cbor::Value, cbor::Value)>, Ctap2StatusCode> {
    ok_or_cbor_type(cbor_value.extract_map())
}

pub fn extract_bool(cbor_value: cbor::Value) -> Result<bool, Ctap2StatusCode> {
    ok_or_cbor_type(cbor_value.extract_bool())
}

pub fn ok_or_missing<T>(value_option: Option<T>) -> Result<T, Ctap2StatusCode> {
    value_option.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
}

#[cfg(test)]
mod test {
    use self::Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    use super::*;
    use crate::api::crypto::ecdh::PublicKey as _;
    use crate::api::crypto::ecdsa::PublicKey as _;
    use crate::api::key_store::KeyStore;
    use crate::api::rng::Rng;
    use crate::env::test::TestEnv;
    use crate::env::{EcdhPk, EcdsaPk, Env};
    use cbor::{
        cbor_array, cbor_bool, cbor_bytes, cbor_bytes_lit, cbor_false, cbor_int, cbor_null,
        cbor_text, cbor_unsigned,
    };

    #[test]
    fn test_extract_unsigned() {
        assert_eq!(extract_unsigned(cbor_int!(123)), Ok(123));
        assert_eq!(
            extract_unsigned(cbor_bool!(true)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_unsigned(cbor_text!("foo")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_unsigned(cbor_bytes_lit!(b"bar")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_unsigned(cbor_array![]),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_unsigned(cbor_map! {}),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
    }

    #[test]
    fn test_extract_unsigned_limits() {
        assert_eq!(
            extract_unsigned(cbor_unsigned!(std::u64::MAX)),
            Ok(std::u64::MAX)
        );
        assert_eq!(
            extract_unsigned(cbor_unsigned!((std::i64::MAX as u64) + 1)),
            Ok((std::i64::MAX as u64) + 1)
        );
        assert_eq!(
            extract_unsigned(cbor_int!(std::i64::MAX)),
            Ok(std::i64::MAX as u64)
        );
        assert_eq!(extract_unsigned(cbor_int!(123)), Ok(123));
        assert_eq!(extract_unsigned(cbor_int!(1)), Ok(1));
        assert_eq!(extract_unsigned(cbor_int!(0)), Ok(0));
        assert_eq!(
            extract_unsigned(cbor_int!(-1)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_unsigned(cbor_int!(-123)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_unsigned(cbor_int!(std::i64::MIN)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
    }

    #[test]
    fn test_extract_integer() {
        assert_eq!(extract_integer(cbor_int!(123)), Ok(123));
        assert_eq!(extract_integer(cbor_int!(-123)), Ok(-123));
        assert_eq!(
            extract_integer(cbor_bool!(true)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_integer(cbor_text!("foo")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_integer(cbor_bytes_lit!(b"bar")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_integer(cbor_array![]),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_integer(cbor_map! {}),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
    }

    #[test]
    fn test_extract_integer_limits() {
        assert_eq!(
            extract_integer(cbor_unsigned!(std::u64::MAX)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_integer(cbor_unsigned!((std::i64::MAX as u64) + 1)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(extract_integer(cbor_int!(std::i64::MAX)), Ok(std::i64::MAX));
        assert_eq!(extract_integer(cbor_int!(123)), Ok(123));
        assert_eq!(extract_integer(cbor_int!(1)), Ok(1));
        assert_eq!(extract_integer(cbor_int!(0)), Ok(0));
        assert_eq!(extract_integer(cbor_int!(-1)), Ok(-1));
        assert_eq!(extract_integer(cbor_int!(-123)), Ok(-123));
        assert_eq!(extract_integer(cbor_int!(std::i64::MIN)), Ok(std::i64::MIN));
    }

    #[test]
    fn test_extract_byte_string() {
        assert_eq!(
            extract_byte_string(cbor_int!(123)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_byte_string(cbor_bool!(true)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_byte_string(cbor_text!("foo")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(extract_byte_string(cbor_bytes_lit!(b"")), Ok(Vec::new()));
        assert_eq!(
            extract_byte_string(cbor_bytes_lit!(b"bar")),
            Ok(b"bar".to_vec())
        );
        assert_eq!(
            extract_byte_string(cbor_array![]),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_byte_string(cbor_map! {}),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
    }

    #[test]
    fn test_extract_text_string() {
        assert_eq!(
            extract_text_string(cbor_int!(123)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_text_string(cbor_bool!(true)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(extract_text_string(cbor_text!("")), Ok(String::new()));
        assert_eq!(
            extract_text_string(cbor_text!("foo")),
            Ok(String::from("foo"))
        );
        assert_eq!(
            extract_text_string(cbor_bytes_lit!(b"bar")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_text_string(cbor_array![]),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_text_string(cbor_map! {}),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
    }

    #[test]
    fn test_extract_array() {
        assert_eq!(
            extract_array(cbor_int!(123)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_array(cbor_bool!(true)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_array(cbor_text!("foo")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_array(cbor_bytes_lit!(b"bar")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(extract_array(cbor_array![]), Ok(Vec::new()));
        assert_eq!(
            extract_array(cbor_array![
                123,
                cbor_null!(),
                "foo",
                cbor_array![],
                cbor_map! {},
            ]),
            Ok(vec![
                cbor_int!(123),
                cbor_null!(),
                cbor_text!("foo"),
                cbor_array![],
                cbor_map! {},
            ])
        );
        assert_eq!(
            extract_array(cbor_map! {}),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
    }

    #[test]
    fn test_extract_map() {
        assert_eq!(
            extract_map(cbor_int!(123)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_map(cbor_bool!(true)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_map(cbor_text!("foo")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_map(cbor_bytes_lit!(b"bar")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_map(cbor_array![]),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(extract_map(cbor_map! {}), Ok(Vec::new()));
        assert_eq!(
            extract_map(cbor_map! {
                1 => cbor_false!(),
                b"bin" => -42,
                "foo" => b"bar",
            }),
            Ok(vec![
                (cbor_unsigned!(1), cbor_false!()),
                (cbor_bytes_lit!(b"bin"), cbor_int!(-42)),
                (cbor_text!("foo"), cbor_bytes_lit!(b"bar")),
            ])
        );
    }

    #[test]
    fn test_extract_bool() {
        assert_eq!(
            extract_bool(cbor_int!(123)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(extract_bool(cbor_bool!(true)), Ok(true));
        assert_eq!(extract_bool(cbor_bool!(false)), Ok(false));
        assert_eq!(
            extract_bool(cbor_text!("foo")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_bool(cbor_bytes_lit!(b"bar")),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_bool(cbor_array![]),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            extract_bool(cbor_map! {}),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
    }

    #[test]
    fn test_from_public_key_credential_rp_entity() {
        let cbor_rp_entity = cbor_map! {
            "id" => "example.com",
            "icon" => "example.com/icon.png",
            "name" => "Example",
        };
        let rp_entity = PublicKeyCredentialRpEntity::try_from(cbor_rp_entity);
        let expected_rp_entity = PublicKeyCredentialRpEntity {
            rp_id: "example.com".to_string(),
            rp_name: Some("Example".to_string()),
            rp_icon: Some("example.com/icon.png".to_string()),
        };
        assert_eq!(rp_entity, Ok(expected_rp_entity));
    }

    #[test]
    fn test_from_into_public_key_credential_user_entity() {
        let cbor_user_entity = cbor_map! {
            "id" => vec![0x1D, 0x1D, 0x1D, 0x1D],
            "icon" => "example.com/foo/icon.png",
            "name" => "foo",
            "displayName" => "bar",
        };
        let user_entity = PublicKeyCredentialUserEntity::try_from(cbor_user_entity.clone());
        let expected_user_entity = PublicKeyCredentialUserEntity {
            user_id: vec![0x1D, 0x1D, 0x1D, 0x1D],
            user_name: Some("foo".to_string()),
            user_display_name: Some("bar".to_string()),
            user_icon: Some("example.com/foo/icon.png".to_string()),
        };
        assert_eq!(user_entity, Ok(expected_user_entity));
        let created_cbor: cbor::Value = user_entity.unwrap().into();
        assert_eq!(created_cbor, cbor_user_entity);
    }

    #[test]
    fn test_from_into_public_key_credential_type() {
        let cbor_credential_type: cbor::Value = cbor_text!("public-key");
        let credential_type = PublicKeyCredentialType::try_from(cbor_credential_type.clone());
        let expected_credential_type = PublicKeyCredentialType::PublicKey;
        assert_eq!(credential_type, Ok(expected_credential_type));
        let created_cbor: cbor::Value = credential_type.unwrap().into();
        assert_eq!(created_cbor, cbor_credential_type);

        let cbor_unknown_type: cbor::Value = cbor_text!("unknown-type");
        let unknown_type = PublicKeyCredentialType::try_from(cbor_unknown_type);
        let expected_unknown_type = PublicKeyCredentialType::Unknown;
        assert_eq!(unknown_type, Ok(expected_unknown_type));
    }

    #[test]
    fn test_from_into_signature_algorithm_int() {
        let alg_int = SignatureAlgorithm::Es256 as i64;
        let signature_algorithm = SignatureAlgorithm::from(alg_int);
        assert_eq!(signature_algorithm, SignatureAlgorithm::Es256);

        #[cfg(feature = "ed25519")]
        {
            let alg_int = SignatureAlgorithm::Eddsa as i64;
            let signature_algorithm = SignatureAlgorithm::from(alg_int);
            assert_eq!(signature_algorithm, SignatureAlgorithm::Eddsa);
        }

        let unknown_alg_int = -1;
        let unknown_algorithm = SignatureAlgorithm::from(unknown_alg_int);
        assert_eq!(unknown_algorithm, SignatureAlgorithm::Unknown);
    }

    #[test]
    fn test_from_into_signature_algorithm() {
        let cbor_signature_algorithm: cbor::Value = cbor_int!(ES256_ALGORITHM);
        let signature_algorithm = SignatureAlgorithm::try_from(cbor_signature_algorithm.clone());
        let expected_signature_algorithm = SignatureAlgorithm::Es256;
        assert_eq!(signature_algorithm, Ok(expected_signature_algorithm));
        let created_cbor: cbor::Value = signature_algorithm.unwrap().into();
        assert_eq!(created_cbor, cbor_signature_algorithm);

        #[cfg(feature = "ed25519")]
        {
            let cbor_signature_algorithm: cbor::Value = cbor_int!(EDDSA_ALGORITHM);
            let signature_algorithm =
                SignatureAlgorithm::try_from(cbor_signature_algorithm.clone());
            let expected_signature_algorithm = SignatureAlgorithm::Eddsa;
            assert_eq!(signature_algorithm, Ok(expected_signature_algorithm));
            let created_cbor: cbor::Value = signature_algorithm.unwrap().into();
            assert_eq!(created_cbor, cbor_signature_algorithm);
        }

        let cbor_unknown_algorithm: cbor::Value = cbor_int!(-1);
        let unknown_algorithm = SignatureAlgorithm::try_from(cbor_unknown_algorithm);
        let expected_unknown_algorithm = SignatureAlgorithm::Unknown;
        assert_eq!(unknown_algorithm, Ok(expected_unknown_algorithm));
    }

    #[test]
    fn test_cred_protection_policy_order() {
        assert!(
            CredentialProtectionPolicy::UserVerificationOptional
                < CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList
        );
        assert!(
            CredentialProtectionPolicy::UserVerificationOptional
                < CredentialProtectionPolicy::UserVerificationRequired
        );
        assert!(
            CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList
                < CredentialProtectionPolicy::UserVerificationRequired
        );
    }

    #[test]
    fn test_from_into_cred_protection_policy() {
        let cbor_policy: cbor::Value = CredentialProtectionPolicy::UserVerificationOptional.into();
        let policy = CredentialProtectionPolicy::try_from(cbor_policy.clone());
        let expected_policy = CredentialProtectionPolicy::UserVerificationOptional;
        assert_eq!(policy, Ok(expected_policy));
        let created_cbor: cbor::Value = policy.unwrap().into();
        assert_eq!(created_cbor, cbor_policy);

        let cbor_policy_error: cbor::Value = cbor_int!(-1);
        let policy_error = CredentialProtectionPolicy::try_from(cbor_policy_error);
        let expected_error = Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        assert_eq!(policy_error, expected_error);

        for policy in CredentialProtectionPolicy::into_enum_iter() {
            let created_cbor: cbor::Value = policy.into();
            let reconstructed = CredentialProtectionPolicy::try_from(created_cbor).unwrap();
            assert_eq!(policy, reconstructed);
        }
    }

    #[test]
    fn test_from_into_authenticator_transport() {
        let cbor_authenticator_transport: cbor::Value = cbor_text!("usb");
        let authenticator_transport =
            AuthenticatorTransport::try_from(cbor_authenticator_transport.clone());
        let expected_authenticator_transport = AuthenticatorTransport::Usb;
        assert_eq!(
            authenticator_transport,
            Ok(expected_authenticator_transport)
        );
        let created_cbor: cbor::Value = authenticator_transport.unwrap().into();
        assert_eq!(created_cbor, cbor_authenticator_transport);

        for transport in AuthenticatorTransport::into_enum_iter() {
            let created_cbor: cbor::Value = transport.clone().into();
            let reconstructed = AuthenticatorTransport::try_from(created_cbor).unwrap();
            assert_eq!(transport, reconstructed);
        }
    }

    fn test_from_into_public_key_credential_parameter(
        alg_int: i64,
        signature_algorithm: SignatureAlgorithm,
    ) {
        let cbor_credential_parameter = cbor_map! {
            "alg" => alg_int,
            "type" => "public-key",
        };
        let credential_parameter =
            PublicKeyCredentialParameter::try_from(cbor_credential_parameter.clone());
        let expected_credential_parameter = PublicKeyCredentialParameter {
            cred_type: PublicKeyCredentialType::PublicKey,
            alg: signature_algorithm,
        };
        assert_eq!(credential_parameter, Ok(expected_credential_parameter));
        let created_cbor: cbor::Value = credential_parameter.unwrap().into();
        assert_eq!(created_cbor, cbor_credential_parameter);
    }

    #[test]
    fn test_from_into_ecdsa_public_key_credential_parameter() {
        test_from_into_public_key_credential_parameter(ES256_ALGORITHM, SignatureAlgorithm::Es256);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_from_into_ed25519_public_key_credential_parameter() {
        test_from_into_public_key_credential_parameter(EDDSA_ALGORITHM, SignatureAlgorithm::Eddsa);
    }

    #[test]
    fn test_from_into_public_key_credential_descriptor() {
        let cbor_credential_descriptor = cbor_map! {
            "id" => vec![0x2D, 0x2D, 0x2D, 0x2D],
            "type" => "public-key",
            "transports" => cbor_array!["usb"],
        };
        let credential_descriptor =
            PublicKeyCredentialDescriptor::try_from(cbor_credential_descriptor.clone());
        let expected_credential_descriptor = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: vec![0x2D, 0x2D, 0x2D, 0x2D],
            transports: Some(vec![AuthenticatorTransport::Usb]),
        };
        assert_eq!(credential_descriptor, Ok(expected_credential_descriptor));
        let created_cbor: cbor::Value = credential_descriptor.unwrap().into();
        assert_eq!(created_cbor, cbor_credential_descriptor);
    }

    #[test]
    fn test_from_make_credential_extensions() {
        let cbor_extensions = cbor_map! {
            "credBlob" => vec![0xCB],
            "credProtect" => CredentialProtectionPolicy::UserVerificationRequired,
            "hmac-secret" => true,
            "largeBlobKey" => true,
            "minPinLength" => true,
        };
        let extensions = MakeCredentialExtensions::try_from(cbor_extensions);
        let expected_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            cred_protect: Some(CredentialProtectionPolicy::UserVerificationRequired),
            min_pin_length: true,
            cred_blob: Some(vec![0xCB]),
            large_blob_key: Some(true),
        };
        assert_eq!(extensions, Ok(expected_extensions));
    }

    #[test]
    fn test_from_get_assertion_extensions_default_protocol() {
        let cose_key = CoseKey::example_ecdh_pubkey();
        let cbor_extensions = cbor_map! {
            "credBlob" => true,
            "hmac-secret" => cbor_map! {
                1 => cbor::Value::from(cose_key.clone()),
                2 => vec![0x02; 32],
                3 => vec![0x03; 16],
            },
            "largeBlobKey" => true,
        };
        let extensions = GetAssertionExtensions::try_from(cbor_extensions);
        let expected_input = GetAssertionHmacSecretInput {
            key_agreement: cose_key,
            salt_enc: vec![0x02; 32],
            salt_auth: vec![0x03; 16],
            pin_uv_auth_protocol: PinUvAuthProtocol::V1,
        };
        let expected_extensions = GetAssertionExtensions {
            hmac_secret: Some(expected_input),
            cred_blob: true,
            large_blob_key: Some(true),
        };
        assert_eq!(extensions, Ok(expected_extensions));
    }

    #[test]
    fn test_from_get_assertion_extensions_with_protocol() {
        let cose_key = CoseKey::example_ecdh_pubkey();
        let cbor_extensions = cbor_map! {
            "credBlob" => true,
            "hmac-secret" => cbor_map! {
                1 => cbor::Value::from(cose_key.clone()),
                2 => vec![0x02; 32],
                3 => vec![0x03; 16],
                4 => 2,
            },
            "largeBlobKey" => true,
        };
        let extensions = GetAssertionExtensions::try_from(cbor_extensions);
        let expected_input = GetAssertionHmacSecretInput {
            key_agreement: cose_key,
            salt_enc: vec![0x02; 32],
            salt_auth: vec![0x03; 16],
            pin_uv_auth_protocol: PinUvAuthProtocol::V2,
        };
        let expected_extensions = GetAssertionExtensions {
            hmac_secret: Some(expected_input),
            cred_blob: true,
            large_blob_key: Some(true),
        };
        assert_eq!(extensions, Ok(expected_extensions));
        // TODO more tests, check default
    }

    #[test]
    fn test_from_make_credential_options() {
        let cbor_make_options = cbor_map! {
            "rk" => true,
            "uv" => false,
        };
        let make_options = MakeCredentialOptions::try_from(cbor_make_options);
        let expected_make_options = MakeCredentialOptions {
            rk: true,
            uv: false,
        };
        assert_eq!(make_options, Ok(expected_make_options));
    }

    #[test]
    fn test_from_get_assertion_options() {
        let cbor_get_assertion = cbor_map! {
            "up" => true,
            "uv" => false,
        };
        let get_assertion = GetAssertionOptions::try_from(cbor_get_assertion);
        let expected_get_assertion = GetAssertionOptions {
            up: true,
            uv: false,
        };
        assert_eq!(get_assertion, Ok(expected_get_assertion));
    }

    #[test]
    fn test_into_packed_attestation_statement() {
        let certificate = cbor_bytes![vec![0x5C, 0x5C, 0x5C, 0x5C]];
        let cbor_packed_attestation_statement = cbor_map! {
            "alg" => 1,
            "sig" => vec![0x55, 0x55, 0x55, 0x55],
            "x5c" => cbor_array![certificate],
            "ecdaaKeyId" => vec![0xEC, 0xDA, 0x1D],
        };
        let packed_attestation_statement = PackedAttestationStatement {
            alg: 1,
            sig: vec![0x55, 0x55, 0x55, 0x55],
            x5c: Some(vec![vec![0x5C, 0x5C, 0x5C, 0x5C]]),
            ecdaa_key_id: Some(vec![0xEC, 0xDA, 0x1D]),
        };
        let created_cbor: cbor::Value = packed_attestation_statement.into();
        assert_eq!(created_cbor, cbor_packed_attestation_statement);
    }

    #[test]
    fn test_from_into_cose_key_cbor() {
        for algorithm in &[CoseKey::ECDH_ALGORITHM, ES256_ALGORITHM] {
            let cbor_value = cbor_map! {
                1 => CoseKey::EC2_KEY_TYPE,
                3 => algorithm,
                -1 => CoseKey::P_256_CURVE,
                -2 => [0u8; 32],
                -3 => [0u8; 32],
            };
            let cose_key = CoseKey::try_from(cbor_value.clone()).unwrap();
            let created_cbor_value = cbor::Value::from(cose_key);
            assert_eq!(created_cbor_value, cbor_value);
        }
    }

    #[test]
    fn test_cose_key_unknown_algorithm() {
        let cbor_value = cbor_map! {
            1 => CoseKey::EC2_KEY_TYPE,
            // unknown algorithm
            3 => 0,
            -1 => CoseKey::P_256_CURVE,
            -2 => [0u8; 32],
            -3 => [0u8; 32],
        };
        assert_eq!(
            CoseKey::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        );
    }

    #[test]
    fn test_cose_key_unknown_type() {
        let cbor_value = cbor_map! {
            // unknown type
            1 => 0,
            3 => CoseKey::ECDH_ALGORITHM,
            -1 => CoseKey::P_256_CURVE,
            -2 => [0u8; 32],
            -3 => [0u8; 32],
        };
        assert_eq!(
            CoseKey::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        );
    }

    #[test]
    fn test_cose_key_unknown_curve() {
        let cbor_value = cbor_map! {
            1 => CoseKey::EC2_KEY_TYPE,
            3 => CoseKey::ECDH_ALGORITHM,
            // unknown curve
            -1 => 0,
            -2 => [0u8; 32],
            -3 => [0u8; 32],
        };
        assert_eq!(
            CoseKey::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        );
    }

    #[test]
    fn test_cose_key_wrong_length_x() {
        let cbor_value = cbor_map! {
            1 => CoseKey::EC2_KEY_TYPE,
            3 => CoseKey::ECDH_ALGORITHM,
            -1 => CoseKey::P_256_CURVE,
            // wrong length
            -2 => [0u8; 31],
            -3 => [0u8; 32],
        };
        assert_eq!(
            CoseKey::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );
    }

    #[test]
    fn test_cose_key_wrong_length_y() {
        let cbor_value = cbor_map! {
            1 => CoseKey::EC2_KEY_TYPE,
            3 => CoseKey::ECDH_ALGORITHM,
            -1 => CoseKey::P_256_CURVE,
            -2 => [0u8; 32],
            // wrong length
            -3 => [0u8; 33],
        };
        assert_eq!(
            CoseKey::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );
    }

    #[test]
    fn test_from_into_cose_key_ecdh() {
        let cose_key = CoseKey::example_ecdh_pubkey();
        let (x_bytes, y_bytes) = cose_key.clone().try_into_ecdh_coordinates().unwrap();
        let created_pk = EcdhPk::<TestEnv>::from_coordinates(&x_bytes, &y_bytes).unwrap();
        let new_cose_key = CoseKey::from_ecdh_public_key(created_pk);
        assert_eq!(cose_key, new_cose_key);
    }

    #[test]
    fn test_from_cose_key_ecdsa() {
        let x_bytes = [
            0x74, 0x4A, 0x48, 0xA0, 0xDC, 0x56, 0x9A, 0x42, 0x0B, 0x3F, 0x58, 0xBF, 0xD8, 0xD9,
            0x62, 0xCF, 0x3A, 0xEA, 0xB1, 0x5A, 0x32, 0x03, 0xC1, 0xA4, 0x23, 0x8B, 0x57, 0x75,
            0x74, 0xA4, 0x29, 0x50,
        ];
        let y_bytes = [
            0xCD, 0x93, 0x26, 0x4A, 0xAF, 0x2A, 0xBA, 0xD1, 0x09, 0x3D, 0x2E, 0xD6, 0x8C, 0xC0,
            0x59, 0xB1, 0xD9, 0xAB, 0xD7, 0x81, 0x71, 0x60, 0x35, 0xFE, 0xFF, 0xE8, 0xE1, 0x94,
            0x05, 0x60, 0xA0, 0xBC,
        ];
        let created_pk = EcdsaPk::<TestEnv>::from_coordinates(&x_bytes, &y_bytes).unwrap();
        let cose_key = CoseKey::from_ecdsa_public_key(created_pk);
        assert_eq!(cose_key.x_bytes, x_bytes);
        assert_eq!(cose_key.y_bytes, y_bytes);
        assert_eq!(cose_key.algorithm, ES256_ALGORITHM);
    }

    #[test]
    fn test_from_pin_uv_auth_protocol() {
        let cbor_protocol: cbor::Value = cbor_int!(0x01);
        assert_eq!(
            PinUvAuthProtocol::try_from(cbor_protocol),
            Ok(PinUvAuthProtocol::V1)
        );
        let cbor_protocol: cbor::Value = cbor_int!(0x02);
        assert_eq!(
            PinUvAuthProtocol::try_from(cbor_protocol),
            Ok(PinUvAuthProtocol::V2)
        );
        let cbor_protocol: cbor::Value = cbor_int!(0x03);
        assert_eq!(
            PinUvAuthProtocol::try_from(cbor_protocol),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );
    }

    #[test]
    fn test_from_into_client_pin_sub_command() {
        let cbor_sub_command: cbor::Value = cbor_int!(0x01);
        let sub_command = ClientPinSubCommand::try_from(cbor_sub_command.clone());
        let expected_sub_command = ClientPinSubCommand::GetPinRetries;
        assert_eq!(sub_command, Ok(expected_sub_command));
        let created_cbor: cbor::Value = sub_command.unwrap().into();
        assert_eq!(created_cbor, cbor_sub_command);

        for command in ClientPinSubCommand::into_enum_iter() {
            let created_cbor: cbor::Value = command.clone().into();
            let reconstructed = ClientPinSubCommand::try_from(created_cbor).unwrap();
            assert_eq!(command, reconstructed);
        }
    }

    #[test]
    fn test_from_into_config_sub_command() {
        let cbor_sub_command: cbor::Value = cbor_int!(0x01);
        let sub_command = ConfigSubCommand::try_from(cbor_sub_command.clone());
        let expected_sub_command = ConfigSubCommand::EnableEnterpriseAttestation;
        assert_eq!(sub_command, Ok(expected_sub_command));
        let created_cbor: cbor::Value = sub_command.unwrap().into();
        assert_eq!(created_cbor, cbor_sub_command);

        for command in ConfigSubCommand::into_enum_iter() {
            let created_cbor: cbor::Value = command.into();
            let reconstructed = ConfigSubCommand::try_from(created_cbor).unwrap();
            assert_eq!(command, reconstructed);
        }
    }

    #[test]
    fn test_from_set_min_pin_length_params() {
        let params = SetMinPinLengthParams {
            new_min_pin_length: Some(6),
            min_pin_length_rp_ids: Some(vec!["example.com".to_string()]),
            force_change_pin: Some(true),
        };
        let cbor_params = cbor_map! {
            0x01 => 6,
            0x02 => cbor_array!("example.com".to_string()),
            0x03 => true,
        };
        assert_eq!(cbor::Value::from(params.clone()), cbor_params);
        let reconstructed_params = SetMinPinLengthParams::try_from(cbor_params);
        assert_eq!(reconstructed_params, Ok(params));
    }

    #[test]
    fn test_from_config_sub_command_params() {
        let set_min_pin_length_params = SetMinPinLengthParams {
            new_min_pin_length: Some(6),
            min_pin_length_rp_ids: Some(vec!["example.com".to_string()]),
            force_change_pin: Some(true),
        };
        let config_sub_command_params =
            ConfigSubCommandParams::SetMinPinLength(set_min_pin_length_params);
        let cbor_params = cbor_map! {
            0x01 => 6,
            0x02 => cbor_array!("example.com".to_string()),
            0x03 => true,
        };
        assert_eq!(cbor::Value::from(config_sub_command_params), cbor_params);
    }

    #[test]
    fn test_from_enterprise_attestation_mode() {
        assert_eq!(
            EnterpriseAttestationMode::try_from(0),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION),
        );
        assert_eq!(
            EnterpriseAttestationMode::try_from(1),
            Ok(EnterpriseAttestationMode::VendorFacilitated),
        );
        assert_eq!(
            EnterpriseAttestationMode::try_from(2),
            Ok(EnterpriseAttestationMode::PlatformManaged),
        );
        assert_eq!(
            EnterpriseAttestationMode::try_from(3),
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION),
        );
    }

    #[test]
    fn test_from_into_cred_management_sub_command() {
        let cbor_sub_command: cbor::Value = cbor_int!(0x01);
        let sub_command = CredentialManagementSubCommand::try_from(cbor_sub_command.clone());
        let expected_sub_command = CredentialManagementSubCommand::GetCredsMetadata;
        assert_eq!(sub_command, Ok(expected_sub_command));
        let created_cbor: cbor::Value = sub_command.unwrap().into();
        assert_eq!(created_cbor, cbor_sub_command);

        for command in CredentialManagementSubCommand::into_enum_iter() {
            let created_cbor: cbor::Value = command.into();
            let reconstructed = CredentialManagementSubCommand::try_from(created_cbor).unwrap();
            assert_eq!(command, reconstructed);
        }
    }

    #[test]
    fn test_from_into_cred_management_sub_command_params() {
        let credential_id = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: vec![0x2D, 0x2D, 0x2D, 0x2D],
            transports: Some(vec![AuthenticatorTransport::Usb]),
        };
        let user_entity = PublicKeyCredentialUserEntity {
            user_id: vec![0x1D, 0x1D, 0x1D, 0x1D],
            user_name: Some("foo".to_string()),
            user_display_name: Some("bar".to_string()),
            user_icon: Some("example.com/foo/icon.png".to_string()),
        };
        let cbor_sub_command_params = cbor_map! {
            0x01 => vec![0x1D; 32],
            0x02 => credential_id.clone(),
            0x03 => user_entity.clone(),
        };
        let sub_command_params =
            CredentialManagementSubCommandParameters::try_from(cbor_sub_command_params.clone());
        let expected_sub_command_params = CredentialManagementSubCommandParameters {
            rp_id_hash: Some(vec![0x1D; 32]),
            credential_id: Some(credential_id),
            user: Some(user_entity),
        };
        assert_eq!(sub_command_params, Ok(expected_sub_command_params));
        let created_cbor: cbor::Value = sub_command_params.unwrap().into();
        assert_eq!(created_cbor, cbor_sub_command_params);
    }

    #[test]
    fn test_credential_source_cbor_round_trip() {
        let mut env = TestEnv::default();
        let wrap_key = env.key_store().wrap_key::<TestEnv>().unwrap();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: env.rng().gen_uniform_u8x32().to_vec(),
            private_key,
            rp_id: "example.com".to_string(),
            user_handle: b"foo".to_vec(),
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        };

        let cbor_value = credential
            .clone()
            .to_cbor::<TestEnv>(env.rng(), &wrap_key)
            .unwrap();
        assert_eq!(
            PublicKeyCredentialSource::from_cbor::<TestEnv>(&wrap_key, cbor_value),
            Ok(credential.clone())
        );

        let credential = PublicKeyCredentialSource {
            user_display_name: Some("Display Name".to_string()),
            ..credential
        };

        let cbor_value = credential
            .clone()
            .to_cbor::<TestEnv>(env.rng(), &wrap_key)
            .unwrap();
        assert_eq!(
            PublicKeyCredentialSource::from_cbor::<TestEnv>(&wrap_key, cbor_value),
            Ok(credential.clone())
        );

        let credential = PublicKeyCredentialSource {
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationOptional),
            ..credential
        };

        let cbor_value = credential
            .clone()
            .to_cbor::<TestEnv>(env.rng(), &wrap_key)
            .unwrap();
        assert_eq!(
            PublicKeyCredentialSource::from_cbor::<TestEnv>(&wrap_key, cbor_value),
            Ok(credential.clone())
        );

        let credential = PublicKeyCredentialSource {
            user_name: Some("name".to_string()),
            ..credential
        };

        let cbor_value = credential
            .clone()
            .to_cbor::<TestEnv>(env.rng(), &wrap_key)
            .unwrap();
        assert_eq!(
            PublicKeyCredentialSource::from_cbor::<TestEnv>(&wrap_key, cbor_value),
            Ok(credential.clone())
        );

        let credential = PublicKeyCredentialSource {
            user_icon: Some("icon".to_string()),
            ..credential
        };

        let cbor_value = credential
            .clone()
            .to_cbor::<TestEnv>(env.rng(), &wrap_key)
            .unwrap();
        assert_eq!(
            PublicKeyCredentialSource::from_cbor::<TestEnv>(&wrap_key, cbor_value),
            Ok(credential.clone())
        );

        let credential = PublicKeyCredentialSource {
            cred_blob: Some(vec![0xCB]),
            ..credential
        };

        let cbor_value = credential
            .clone()
            .to_cbor::<TestEnv>(env.rng(), &wrap_key)
            .unwrap();
        assert_eq!(
            PublicKeyCredentialSource::from_cbor::<TestEnv>(&wrap_key, cbor_value),
            Ok(credential.clone())
        );

        let credential = PublicKeyCredentialSource {
            large_blob_key: Some(vec![0x1B]),
            ..credential
        };

        let cbor_value = credential
            .clone()
            .to_cbor::<TestEnv>(env.rng(), &wrap_key)
            .unwrap();
        assert_eq!(
            PublicKeyCredentialSource::from_cbor::<TestEnv>(&wrap_key, cbor_value),
            Ok(credential)
        );
    }

    #[test]
    fn test_credential_source_invalid_cbor() {
        let mut env = TestEnv::default();
        let wrap_key = env.key_store().wrap_key::<TestEnv>().unwrap();
        assert!(PublicKeyCredentialSource::from_cbor::<TestEnv>(&wrap_key, cbor_false!()).is_err());
        assert!(
            PublicKeyCredentialSource::from_cbor::<TestEnv>(&wrap_key, cbor_array!(false)).is_err()
        );
        assert!(PublicKeyCredentialSource::from_cbor::<TestEnv>(
            &wrap_key,
            cbor_array!(b"foo".to_vec())
        )
        .is_err());
    }
}
