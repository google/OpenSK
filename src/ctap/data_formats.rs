// Copyright 2019 Google LLC
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
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use arrayref::array_ref;
use cbor::{cbor_array_vec, cbor_bytes_lit, cbor_map_options, destructure_cbor_map};
use core::convert::TryFrom;
use crypto::{ecdh, ecdsa};
#[cfg(test)]
use enum_iterator::IntoEnumIterator;

// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrpentity
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
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

// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialuserentity
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Clone, Debug, PartialEq))]
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
            "name" => entity.user_name,
            "displayName" => entity.user_display_name,
            "icon" => entity.user_icon,
        }
    }
}

// https://www.w3.org/TR/webauthn/#enumdef-publickeycredentialtype
#[derive(Clone, PartialEq)]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
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
#[derive(PartialEq)]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
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
            "type" => cred_param.cred_type,
            "alg" => cred_param.alg,
        }
    }
}

// https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Clone, Debug, PartialEq))]
#[cfg_attr(test, derive(IntoEnumIterator))]
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
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Clone, Debug, PartialEq))]
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
            "type" => desc.key_type,
            "id" => desc.key_id,
            "transports" => desc.transports.map(|vec| cbor_array_vec!(vec)),
        }
    }
}

#[cfg_attr(any(test, feature = "debug_ctap"), derive(Clone, Debug, PartialEq))]
pub struct MakeCredentialExtensions {
    pub hmac_secret: bool,
    pub cred_protect: Option<CredentialProtectionPolicy>,
}

impl TryFrom<cbor::Value> for MakeCredentialExtensions {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                "credProtect" => cred_protect,
                "hmac-secret" => hmac_secret,
            } = extract_map(cbor_value)?;
        }

        let hmac_secret = hmac_secret.map_or(Ok(false), extract_bool)?;
        let cred_protect = cred_protect
            .map(CredentialProtectionPolicy::try_from)
            .transpose()?;
        Ok(Self {
            hmac_secret,
            cred_protect,
        })
    }
}

#[cfg_attr(any(test, feature = "debug_ctap"), derive(Clone, Debug, PartialEq))]
pub struct GetAssertionExtensions {
    pub hmac_secret: Option<GetAssertionHmacSecretInput>,
}

impl TryFrom<cbor::Value> for GetAssertionExtensions {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                "hmac-secret" => hmac_secret,
            } = extract_map(cbor_value)?;
        }

        let hmac_secret = hmac_secret
            .map(GetAssertionHmacSecretInput::try_from)
            .transpose()?;
        Ok(Self { hmac_secret })
    }
}

#[derive(Clone)]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
pub struct GetAssertionHmacSecretInput {
    pub key_agreement: CoseKey,
    pub salt_enc: Vec<u8>,
    pub salt_auth: Vec<u8>,
}

impl TryFrom<cbor::Value> for GetAssertionHmacSecretInput {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                1 => cose_key,
                2 => salt_enc,
                3 => salt_auth,
            } = extract_map(cbor_value)?;
        }

        let cose_key = extract_map(ok_or_missing(cose_key)?)?;
        let salt_enc = extract_byte_string(ok_or_missing(salt_enc)?)?;
        let salt_auth = extract_byte_string(ok_or_missing(salt_auth)?)?;
        Ok(Self {
            key_agreement: CoseKey(cose_key),
            salt_enc,
            salt_auth,
        })
    }
}

// Even though options are optional, we can use the default if not present.
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
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
        if up.is_some() {
            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
        }
        let uv = match uv {
            Some(options_entry) => extract_bool(options_entry)?,
            None => false,
        };
        Ok(Self { rk, uv })
    }
}

#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
pub struct GetAssertionOptions {
    pub up: bool,
    pub uv: bool,
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
#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
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

#[derive(PartialEq)]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
pub enum SignatureAlgorithm {
    ES256 = ecdsa::PubKey::ES256_ALGORITHM as isize,
    // This is the default for all numbers not covered above.
    // Unknown types should be ignored, instead of returning errors.
    Unknown = 0,
}

impl From<SignatureAlgorithm> for cbor::Value {
    fn from(alg: SignatureAlgorithm) -> Self {
        (alg as i64).into()
    }
}

impl TryFrom<cbor::Value> for SignatureAlgorithm {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        match extract_integer(cbor_value)? {
            ecdsa::PubKey::ES256_ALGORITHM => Ok(SignatureAlgorithm::ES256),
            _ => Ok(SignatureAlgorithm::Unknown),
        }
    }
}

#[derive(Clone, Copy, PartialEq, PartialOrd)]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
#[cfg_attr(test, derive(IntoEnumIterator))]
pub enum CredentialProtectionPolicy {
    UserVerificationOptional = 0x01,
    UserVerificationOptionalWithCredentialIdList = 0x02,
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
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug))]
pub struct PublicKeyCredentialSource {
    // TODO function to convert to / from Vec<u8>
    pub key_type: PublicKeyCredentialType,
    pub credential_id: Vec<u8>,
    pub private_key: ecdsa::SecKey, // TODO(kaczmarczyck) open for other algorithms
    pub rp_id: String,
    pub user_handle: Vec<u8>, // not optional, but nullable
    pub user_display_name: Option<String>,
    pub cred_protect_policy: Option<CredentialProtectionPolicy>,
    pub creation_order: u64,
    pub user_name: Option<String>,
    pub user_icon: Option<String>,
}

// We serialize credentials for the persistent storage using CBOR maps. Each field of a credential
// is associated with a unique tag, implemented with a CBOR unsigned key.
enum PublicKeyCredentialSourceField {
    CredentialId = 0,
    PrivateKey = 1,
    RpId = 2,
    UserHandle = 3,
    UserDisplayName = 4,
    CredProtectPolicy = 6,
    CreationOrder = 7,
    UserName = 8,
    UserIcon = 9,
    // When a field is removed, its tag should be reserved and not used for new fields. We document
    // those reserved tags below.
    // Reserved tags:
    // - CredRandom = 5,
}

impl From<PublicKeyCredentialSourceField> for cbor::KeyType {
    fn from(field: PublicKeyCredentialSourceField) -> cbor::KeyType {
        (field as u64).into()
    }
}

impl From<PublicKeyCredentialSource> for cbor::Value {
    fn from(credential: PublicKeyCredentialSource) -> cbor::Value {
        let mut private_key = [0u8; 32];
        credential.private_key.to_bytes(&mut private_key);
        cbor_map_options! {
            PublicKeyCredentialSourceField::CredentialId => Some(credential.credential_id),
            PublicKeyCredentialSourceField::PrivateKey => Some(private_key.to_vec()),
            PublicKeyCredentialSourceField::RpId => Some(credential.rp_id),
            PublicKeyCredentialSourceField::UserHandle => Some(credential.user_handle),
            PublicKeyCredentialSourceField::UserDisplayName => credential.user_display_name,
            PublicKeyCredentialSourceField::CredProtectPolicy => credential.cred_protect_policy,
            PublicKeyCredentialSourceField::CreationOrder => credential.creation_order,
            PublicKeyCredentialSourceField::UserName => credential.user_name,
            PublicKeyCredentialSourceField::UserIcon => credential.user_icon,
        }
    }
}

impl TryFrom<cbor::Value> for PublicKeyCredentialSource {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: cbor::Value) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                PublicKeyCredentialSourceField::CredentialId => credential_id,
                PublicKeyCredentialSourceField::PrivateKey => private_key,
                PublicKeyCredentialSourceField::RpId => rp_id,
                PublicKeyCredentialSourceField::UserHandle => user_handle,
                PublicKeyCredentialSourceField::UserDisplayName => user_display_name,
                PublicKeyCredentialSourceField::CredProtectPolicy => cred_protect_policy,
                PublicKeyCredentialSourceField::CreationOrder => creation_order,
                PublicKeyCredentialSourceField::UserName => user_name,
                PublicKeyCredentialSourceField::UserIcon => user_icon,
            } = extract_map(cbor_value)?;
        }

        let credential_id = extract_byte_string(ok_or_missing(credential_id)?)?;
        let private_key = extract_byte_string(ok_or_missing(private_key)?)?;
        if private_key.len() != 32 {
            return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR);
        }
        let private_key = ecdsa::SecKey::from_bytes(array_ref!(private_key, 0, 32))
            .ok_or(Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)?;
        let rp_id = extract_text_string(ok_or_missing(rp_id)?)?;
        let user_handle = extract_byte_string(ok_or_missing(user_handle)?)?;
        let user_display_name = user_display_name.map(extract_text_string).transpose()?;
        let cred_protect_policy = cred_protect_policy
            .map(CredentialProtectionPolicy::try_from)
            .transpose()?;
        let creation_order = creation_order.map(extract_unsigned).unwrap_or(Ok(0))?;
        let user_name = user_name.map(extract_text_string).transpose()?;
        let user_icon = user_icon.map(extract_text_string).transpose()?;
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
        })
    }
}

impl PublicKeyCredentialSource {
    // Relying parties do not need to provide the credential ID in an allow_list if true.
    pub fn is_discoverable(&self) -> bool {
        self.cred_protect_policy.is_none()
            || self.cred_protect_policy
                == Some(CredentialProtectionPolicy::UserVerificationOptional)
    }
}

// TODO(kaczmarczyck) we could decide to split this data type up
// It depends on the algorithm though, I think.
// So before creating a mess, this is my workaround.
#[derive(Clone)]
#[cfg_attr(any(test, feature = "debug_ctap"), derive(Debug, PartialEq))]
pub struct CoseKey(pub BTreeMap<cbor::KeyType, cbor::Value>);

// This is the algorithm specifier that is supposed to be used in a COSE key
// map. The CTAP specification says -25 which represents ECDH-ES + HKDF-256
// here: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
// In fact, this is just used for compatibility with older specification versions.
const ECDH_ALGORITHM: i64 = -25;
// This is the identifier used by OpenSSH. To be compatible, we accept both.
const ES256_ALGORITHM: i64 = -7;
const EC2_KEY_TYPE: i64 = 2;
const P_256_CURVE: i64 = 1;

impl From<ecdh::PubKey> for CoseKey {
    fn from(pk: ecdh::PubKey) -> Self {
        let mut x_bytes = [0; ecdh::NBYTES];
        let mut y_bytes = [0; ecdh::NBYTES];
        pk.to_coordinates(&mut x_bytes, &mut y_bytes);
        let x_byte_cbor: cbor::Value = cbor_bytes_lit!(&x_bytes);
        let y_byte_cbor: cbor::Value = cbor_bytes_lit!(&y_bytes);
        // TODO(kaczmarczyck) do not write optional parameters, spec is unclear
        let cose_cbor_value = cbor_map_options! {
            1 => EC2_KEY_TYPE,
            3 => ECDH_ALGORITHM,
            -1 => P_256_CURVE,
            -2 => x_byte_cbor,
            -3 => y_byte_cbor,
        };
        if let cbor::Value::Map(cose_map) = cose_cbor_value {
            CoseKey(cose_map)
        } else {
            unreachable!();
        }
    }
}

impl TryFrom<CoseKey> for ecdh::PubKey {
    type Error = Ctap2StatusCode;

    fn try_from(cose_key: CoseKey) -> Result<Self, Ctap2StatusCode> {
        destructure_cbor_map! {
            let {
                1 => key_type,
                3 => algorithm,
                -1 => curve,
                -2 => x_bytes,
                -3 => y_bytes,
            } = cose_key.0;
        }

        let key_type = extract_integer(ok_or_missing(key_type)?)?;
        if key_type != EC2_KEY_TYPE {
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }
        let algorithm = extract_integer(ok_or_missing(algorithm)?)?;
        if algorithm != ECDH_ALGORITHM && algorithm != ES256_ALGORITHM {
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }
        let curve = extract_integer(ok_or_missing(curve)?)?;
        if curve != P_256_CURVE {
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }
        let x_bytes = extract_byte_string(ok_or_missing(x_bytes)?)?;
        if x_bytes.len() != ecdh::NBYTES {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }
        let y_bytes = extract_byte_string(ok_or_missing(y_bytes)?)?;
        if y_bytes.len() != ecdh::NBYTES {
            return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
        }

        let x_array_ref = array_ref![x_bytes.as_slice(), 0, ecdh::NBYTES];
        let y_array_ref = array_ref![y_bytes.as_slice(), 0, ecdh::NBYTES];
        ecdh::PubKey::from_coordinates(x_array_ref, y_array_ref)
            .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
    }
}

#[cfg_attr(any(test, feature = "debug_ctap"), derive(Clone, Debug, PartialEq))]
#[cfg_attr(test, derive(IntoEnumIterator))]
pub enum ClientPinSubCommand {
    GetPinRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    #[cfg(feature = "with_ctap2_1")]
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    #[cfg(feature = "with_ctap2_1")]
    GetUvRetries = 0x07,
    #[cfg(feature = "with_ctap2_1")]
    SetMinPinLength = 0x08,
    #[cfg(feature = "with_ctap2_1")]
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
            #[cfg(feature = "with_ctap2_1")]
            0x06 => Ok(ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions),
            #[cfg(feature = "with_ctap2_1")]
            0x07 => Ok(ClientPinSubCommand::GetUvRetries),
            #[cfg(feature = "with_ctap2_1")]
            0x08 => Ok(ClientPinSubCommand::SetMinPinLength),
            #[cfg(feature = "with_ctap2_1")]
            0x09 => Ok(ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions),
            #[cfg(feature = "with_ctap2_1")]
            _ => Err(Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND),
            #[cfg(not(feature = "with_ctap2_1"))]
            _ => Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER),
        }
    }
}

pub(super) fn extract_unsigned(cbor_value: cbor::Value) -> Result<u64, Ctap2StatusCode> {
    match cbor_value {
        cbor::Value::KeyValue(cbor::KeyType::Unsigned(unsigned)) => Ok(unsigned),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

pub(super) fn extract_integer(cbor_value: cbor::Value) -> Result<i64, Ctap2StatusCode> {
    match cbor_value {
        cbor::Value::KeyValue(cbor::KeyType::Unsigned(unsigned)) => {
            if unsigned <= core::i64::MAX as u64 {
                Ok(unsigned as i64)
            } else {
                Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
            }
        }
        cbor::Value::KeyValue(cbor::KeyType::Negative(signed)) => Ok(signed),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

pub fn extract_byte_string(cbor_value: cbor::Value) -> Result<Vec<u8>, Ctap2StatusCode> {
    match cbor_value {
        cbor::Value::KeyValue(cbor::KeyType::ByteString(byte_string)) => Ok(byte_string),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

pub(super) fn extract_text_string(cbor_value: cbor::Value) -> Result<String, Ctap2StatusCode> {
    match cbor_value {
        cbor::Value::KeyValue(cbor::KeyType::TextString(text_string)) => Ok(text_string),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

pub(super) fn extract_array(cbor_value: cbor::Value) -> Result<Vec<cbor::Value>, Ctap2StatusCode> {
    match cbor_value {
        cbor::Value::Array(array) => Ok(array),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

pub(super) fn extract_map(
    cbor_value: cbor::Value,
) -> Result<BTreeMap<cbor::KeyType, cbor::Value>, Ctap2StatusCode> {
    match cbor_value {
        cbor::Value::Map(map) => Ok(map),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

pub(super) fn extract_bool(cbor_value: cbor::Value) -> Result<bool, Ctap2StatusCode> {
    match cbor_value {
        cbor::Value::Simple(cbor::SimpleValue::FalseValue) => Ok(false),
        cbor::Value::Simple(cbor::SimpleValue::TrueValue) => Ok(true),
        _ => Err(Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

pub(super) fn ok_or_missing<T>(value_option: Option<T>) -> Result<T, Ctap2StatusCode> {
    value_option.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)
}

#[cfg(test)]
mod test {
    use self::Ctap2StatusCode::CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    use super::*;
    use alloc::collections::BTreeMap;
    use cbor::{
        cbor_array, cbor_bool, cbor_bytes, cbor_false, cbor_int, cbor_map, cbor_null, cbor_text,
        cbor_unsigned,
    };
    use crypto::rng256::{Rng256, ThreadRng256};

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
        assert_eq!(extract_map(cbor_map! {}), Ok(BTreeMap::new()));
        assert_eq!(
            extract_map(cbor_map! {
                1 => cbor_false!(),
                "foo" => b"bar",
                b"bin" => -42,
            }),
            Ok([
                (cbor_unsigned!(1), cbor_false!()),
                (cbor_text!("foo"), cbor_bytes_lit!(b"bar")),
                (cbor_bytes_lit!(b"bin"), cbor_int!(-42)),
            ]
            .iter()
            .cloned()
            .collect::<BTreeMap<_, _>>())
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
            "name" => "Example",
            "icon" => "example.com/icon.png",
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
            "name" => "foo",
            "displayName" => "bar",
            "icon" => "example.com/foo/icon.png",
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
    fn test_from_into_signature_algorithm() {
        let cbor_signature_algorithm: cbor::Value = cbor_int!(ecdsa::PubKey::ES256_ALGORITHM);
        let signature_algorithm = SignatureAlgorithm::try_from(cbor_signature_algorithm.clone());
        let expected_signature_algorithm = SignatureAlgorithm::ES256;
        assert_eq!(signature_algorithm, Ok(expected_signature_algorithm));
        let created_cbor: cbor::Value = signature_algorithm.unwrap().into();
        assert_eq!(created_cbor, cbor_signature_algorithm);

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

    #[test]
    fn test_from_into_public_key_credential_parameter() {
        let cbor_credential_parameter = cbor_map! {
            "type" => "public-key",
            "alg" => ecdsa::PubKey::ES256_ALGORITHM,
        };
        let credential_parameter =
            PublicKeyCredentialParameter::try_from(cbor_credential_parameter.clone());
        let expected_credential_parameter = PublicKeyCredentialParameter {
            cred_type: PublicKeyCredentialType::PublicKey,
            alg: SignatureAlgorithm::ES256,
        };
        assert_eq!(credential_parameter, Ok(expected_credential_parameter));
        let created_cbor: cbor::Value = credential_parameter.unwrap().into();
        assert_eq!(created_cbor, cbor_credential_parameter);
    }

    #[test]
    fn test_from_into_public_key_credential_descriptor() {
        let cbor_credential_descriptor = cbor_map! {
            "type" => "public-key",
            "id" => vec![0x2D, 0x2D, 0x2D, 0x2D],
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
            "hmac-secret" => true,
            "credProtect" => CredentialProtectionPolicy::UserVerificationRequired,
        };
        let extensions = MakeCredentialExtensions::try_from(cbor_extensions);
        let expected_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            cred_protect: Some(CredentialProtectionPolicy::UserVerificationRequired),
        };
        assert_eq!(extensions, Ok(expected_extensions));
    }

    #[test]
    fn test_from_get_assertion_extensions() {
        let mut rng = ThreadRng256 {};
        let sk = crypto::ecdh::SecKey::gensk(&mut rng);
        let pk = sk.genpk();
        let cose_key = CoseKey::from(pk);
        let cbor_extensions = cbor_map! {
            "hmac-secret" => cbor_map! {
                1 => cbor::Value::Map(cose_key.0.clone()),
                2 => vec![0x02; 32],
                3 => vec![0x03; 16],
            },
        };
        let extensions = GetAssertionExtensions::try_from(cbor_extensions);
        let expected_input = GetAssertionHmacSecretInput {
            key_agreement: cose_key,
            salt_enc: vec![0x02; 32],
            salt_auth: vec![0x03; 16],
        };
        let expected_extensions = GetAssertionExtensions {
            hmac_secret: Some(expected_input),
        };
        assert_eq!(extensions, Ok(expected_extensions));
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
        let certificate: cbor::values::KeyType = cbor_bytes![vec![0x5C, 0x5C, 0x5C, 0x5C]];
        let cbor_packed_attestation_statement = cbor_map! {
            "alg" => 1,
            "sig" => vec![0x55, 0x55, 0x55, 0x55],
            "x5c" => cbor_array_vec![vec![certificate]],
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
    fn test_from_into_cose_key() {
        let mut rng = ThreadRng256 {};
        let sk = crypto::ecdh::SecKey::gensk(&mut rng);
        let pk = sk.genpk();
        let cose_key = CoseKey::from(pk.clone());
        let created_pk = ecdh::PubKey::try_from(cose_key);
        assert_eq!(created_pk, Ok(pk));
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
    fn test_credential_source_cbor_round_trip() {
        let mut rng = ThreadRng256 {};
        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: rng.gen_uniform_u8x32().to_vec(),
            private_key: crypto::ecdsa::SecKey::gensk(&mut rng),
            rp_id: "example.com".to_string(),
            user_handle: b"foo".to_vec(),
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
        };

        assert_eq!(
            PublicKeyCredentialSource::try_from(cbor::Value::from(credential.clone())),
            Ok(credential.clone())
        );

        let credential = PublicKeyCredentialSource {
            user_display_name: Some("Display Name".to_string()),
            ..credential
        };

        assert_eq!(
            PublicKeyCredentialSource::try_from(cbor::Value::from(credential.clone())),
            Ok(credential.clone())
        );

        let credential = PublicKeyCredentialSource {
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationOptional),
            ..credential
        };

        assert_eq!(
            PublicKeyCredentialSource::try_from(cbor::Value::from(credential.clone())),
            Ok(credential.clone())
        );

        let credential = PublicKeyCredentialSource {
            user_name: Some("name".to_string()),
            ..credential
        };

        assert_eq!(
            PublicKeyCredentialSource::try_from(cbor::Value::from(credential.clone())),
            Ok(credential.clone())
        );

        let credential = PublicKeyCredentialSource {
            user_icon: Some("icon".to_string()),
            ..credential
        };

        assert_eq!(
            PublicKeyCredentialSource::try_from(cbor::Value::from(credential.clone())),
            Ok(credential)
        );
    }

    #[test]
    fn test_credential_source_invalid_cbor() {
        assert!(PublicKeyCredentialSource::try_from(cbor_false!()).is_err());
        assert!(PublicKeyCredentialSource::try_from(cbor_array!(false)).is_err());
        assert!(PublicKeyCredentialSource::try_from(cbor_array!(b"foo".to_vec())).is_err());
    }
}
