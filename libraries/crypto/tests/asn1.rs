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

/// A minimalist parser for ASN.1 encoded ECDSA signatures in DER form.
use arrayref::mut_array_refs;
use crypto::ecdsa;
use std::convert::TryFrom;
use std::io::Read;

#[derive(Debug)]
pub enum Asn1Error {
    IoError(std::io::Error),
    InvalidTagClass,
    InvalidLongFormEncoding,
    ArithmeticOverflow,
    ExpectedSequenceTag(Tag),
    ExpectedIntegerTag(Tag),
    InvalidSequenceLen(usize),
    InvalidIntegerLen(usize),
    UnexpectedTrailingBytes,
    InvalidSignature,
}

impl From<std::io::Error> for Asn1Error {
    fn from(e: std::io::Error) -> Asn1Error {
        Asn1Error::IoError(e)
    }
}

#[derive(PartialEq, Debug)]
pub enum TagClass {
    Universal = 0,
    Application = 1,
    ContextSpecific = 2,
    Private = 3,
}

impl TryFrom<u8> for TagClass {
    type Error = Asn1Error;

    fn try_from(x: u8) -> Result<TagClass, Asn1Error> {
        match x {
            0 => Ok(TagClass::Universal),
            1 => Ok(TagClass::Application),
            2 => Ok(TagClass::ContextSpecific),
            3 => Ok(TagClass::Private),
            _ => Err(Asn1Error::InvalidTagClass),
        }
    }
}

#[allow(dead_code)]
enum UniversalTag {
    Boolean = 1,
    Integer = 2,
    BitString = 3,
    OctetString = 4,
    Null = 5,
    ObjectIdentifier = 6,
    Utf8String = 12,
    Sequence = 16,
    Set = 17,
    PrintableString = 19,
    UtcTime = 23,
    GeneralizedTime = 24,
}

#[derive(Debug)]
pub struct Tag {
    class: TagClass,
    constructed: bool,
    number: u64,
}

impl Tag {
    fn is_sequence(&self) -> bool {
        self.class == TagClass::Universal
            && self.constructed
            && self.number == UniversalTag::Sequence as u64
    }

    fn is_number(&self) -> bool {
        self.class == TagClass::Universal
            && !self.constructed
            && self.number == UniversalTag::Integer as u64
    }

    // Parse an ASN.1 tag encoded in DER form.
    fn parse<R: Read>(input: &mut R) -> Result<Tag, Asn1Error> {
        let mut buf = [0u8; 1];

        input.read_exact(&mut buf)?;
        let mut tag = buf[0];
        let class = TagClass::try_from(tag >> 6)?;
        let constructed = tag & 0x20 != 0;
        tag &= 0x1F;

        if tag < 31 {
            // Short tag number
            let number = tag as u64;
            Ok(Tag {
                class,
                constructed,
                number,
            })
        } else {
            // Long tag number
            let mut number: u64 = 0;
            loop {
                input.read_exact(&mut buf)?;
                let x = buf[0];
                if number == 0 && x == 0 {
                    return Err(Asn1Error::InvalidLongFormEncoding);
                }
                if number >> ((8 * std::mem::size_of::<u64>()) - 7) != 0 {
                    return Err(Asn1Error::ArithmeticOverflow);
                }
                number = (number << 7) | (x & 0x7F) as u64;
                if (x & 0x80) == 0 {
                    if number < 31 {
                        return Err(Asn1Error::InvalidLongFormEncoding);
                    }
                    return Ok(Tag {
                        class,
                        constructed,
                        number,
                    });
                }
            }
        }
    }
}

// Parse an ASN.1 length encoded in DER form.
fn parse_len<R: Read>(input: &mut R) -> Result<usize, Asn1Error> {
    let mut buf = [0u8; 1];

    input.read_exact(&mut buf)?;
    let first_byte = buf[0];
    if (first_byte & 0x80) == 0 {
        // Short form
        Ok(first_byte as usize)
    } else {
        // Long form
        let nbytes = (first_byte & 0x7F) as usize;

        let mut length: usize = 0;
        for _ in 0..nbytes {
            input.read_exact(&mut buf)?;
            let x = buf[0];
            if length == 0 && x == 0 {
                return Err(Asn1Error::InvalidLongFormEncoding);
            }
            if length >> (8 * (std::mem::size_of::<usize>() - 1)) != 0 {
                return Err(Asn1Error::ArithmeticOverflow);
            }
            length = (length << 8) | x as usize;
        }
        if length < 0x80 {
            return Err(Asn1Error::InvalidLongFormEncoding);
        }
        Ok(length)
    }
}

fn parse_coordinate<R: Read>(mut input: R, bytes: &mut [u8; 32]) -> Result<usize, Asn1Error> {
    let tag = Tag::parse(&mut input)?;
    if !tag.is_number() {
        return Err(Asn1Error::ExpectedIntegerTag(tag));
    }
    let len = parse_len(&mut input)?;
    if len > 33 {
        return Err(Asn1Error::InvalidIntegerLen(len));
    }

    let mut buf = vec![0; len];
    input.read_exact(&mut buf)?;

    if len == 33 {
        if buf.remove(0) != 0 {
            return Err(Asn1Error::InvalidIntegerLen(len));
        }
    }

    bytes[(32 - buf.len())..].copy_from_slice(&buf);
    Ok(len)
}

pub fn parse_signature<R: Read>(mut input: R) -> Result<ecdsa::Signature, Asn1Error> {
    let tag = Tag::parse(&mut input)?;
    if !tag.is_sequence() {
        return Err(Asn1Error::ExpectedSequenceTag(tag));
    }
    let len = parse_len(&mut input)?;

    let mut bytes = [0; 64];
    let (xbytes, ybytes) = mut_array_refs![&mut bytes, 32, 32];

    let xlen = parse_coordinate(&mut input, xbytes)?;
    let ylen = parse_coordinate(&mut input, ybytes)?;

    // Each coordinate has, besides (x|y)len bytes of integer, one byte for the tag and one
    // byte for the length (the length is at most 33 and therefore encoded on one byte).
    if len != xlen + ylen + 4 {
        return Err(Asn1Error::InvalidSequenceLen(len));
    }

    // Check for unexpected bytes at the end.
    let is_eof = {
        let mut buf = [0u8; 1];
        match input.read_exact(&mut buf) {
            Ok(_) => false,
            Err(e) => e.kind() == std::io::ErrorKind::UnexpectedEof,
        }
    };
    if !is_eof {
        return Err(Asn1Error::UnexpectedTrailingBytes);
    }

    ecdsa::Signature::from_bytes(&bytes).ok_or(Asn1Error::InvalidSignature)
}
