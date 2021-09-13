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

//! Helps manipulate words as bit fields.
//!
//! This module assumes that `Word` and `Nat` are both represented as `u32`.

use crate::format::Word;
use crate::{Nat, StoreError, StoreResult};

/// Represents a bit field.
///
/// A bit field is a contiguous sequence of bits in a 32-bits word.
///
/// # Invariant
///
/// - The bit field must fit in a 32-bits word: `pos + len < 32`.
pub struct Field {
    /// The position of the bit field.
    pub pos: Nat,

    /// The length of the bit field.
    pub len: Nat,
}

impl Field {
    /// Reads the value of a bit field.
    pub fn get(&self, word: Word) -> Nat {
        (word.0 >> self.pos) & self.mask()
    }

    /// Sets the value of a bit field.
    ///
    /// # Errors
    ///
    /// - The value must fit in the bit field: `num_bits(value) < self.len`.
    /// - The value must only change bits from 1 to 0: `self.get(*word) & value == value`.
    pub fn set(&self, word: &mut Word, value: Nat) -> StoreResult<()> {
        if value & self.mask() != value {
            return Err(StoreError::InvalidStorage);
        }
        let mask = !(self.mask() << self.pos);
        word.0 &= mask | (value << self.pos);
        if self.get(*word) != value {
            return Err(StoreError::InvalidStorage);
        }
        Ok(())
    }

    /// Returns a bit mask the length of the bit field.
    ///
    /// The mask is meant to be applied on a value. It should be shifted to be applied to the bit
    /// field.
    fn mask(&self) -> u32 {
        (1 << self.len) - 1
    }
}

/// Represents a constant bit field.
///
/// # Invariant
///
/// - The value must fit in the bit field: `num_bits(value) <= field.len`.
pub struct ConstField {
    /// The bit field.
    pub field: Field,

    /// The constant value.
    pub value: Nat,
}

impl ConstField {
    /// Checks that the bit field has its value.
    pub fn check(&self, word: Word) -> bool {
        self.field.get(word) == self.value
    }

    /// Sets the bit field to its value.
    pub fn set(&self, word: &mut Word) -> StoreResult<()> {
        self.field.set(word, self.value)
    }
}

/// Represents a single bit.
///
/// # Invariant
///
/// - The bit must fit in a 32-bits word: `pos < 32`.
pub struct Bit {
    /// The position of the bit.
    pub pos: Nat,
}

impl Bit {
    /// Returns whether the value of the bit is zero.
    pub fn get(&self, word: Word) -> bool {
        word.0 & (1 << self.pos) == 0
    }

    /// Sets the value of the bit to zero.
    pub fn set(&self, word: &mut Word) {
        word.0 &= !(1 << self.pos);
    }
}

/// Represents a checksum.
///
/// A checksum is a bit field counting how many bits are set to zero in the word (except in the
/// checksum itself) plus some external increment. It essentially behaves like a bit field storing
/// the external increment.
pub struct Checksum {
    /// The bit field
    pub field: Field,
}

impl Checksum {
    /// Reads the external increment from the checksum.
    ///
    /// # Errors
    ///
    /// Returns `InvalidStorage` if the external increment would be negative.
    pub fn get(&self, word: Word) -> StoreResult<Nat> {
        let checksum = self.field.get(word);
        let zeros = word.0.count_zeros() - (self.field.len - checksum.count_ones());
        checksum
            .checked_sub(zeros)
            .ok_or(StoreError::InvalidStorage)
    }

    /// Sets the checksum to the external increment value.
    ///
    /// # Errors
    ///
    /// - The bits of the checksum bit field should be set to one: `self.field.get(*word) ==
    ///   self.field.mask()`.
    /// - The checksum value should fit in the checksum bit field: `num_bits(word.count_zeros() +
    ///   value) < self.field.len`.
    pub fn set(&self, word: &mut Word, value: Nat) -> StoreResult<()> {
        debug_assert_eq!(self.field.get(*word), self.field.mask());
        self.field.set(word, word.0.count_zeros() + value)
    }
}

/// Tracks the number of bits used so far.
///
/// # Features
///
/// Only available for tests.
#[cfg(any(doc, test))]
pub struct Length {
    /// The position of the next available bit.
    pub pos: Nat,
}

/// Helps defining contiguous bit fields.
///
/// It takes a sequence of bit field descriptors as argument. A bit field descriptor is one of the
/// following:
/// - `$name: Bit,` to define a bit
/// - `$name: Field <= $max,` to define a bit field of minimum length to store `$max`
/// - `$name: Checksum <= $max,` to define a checksum of minimum length to store `$max`
/// - `$name: Length,` to define a length tracker
/// - `$name: ConstField = [$bits],` to define a constant bit field with value `$bits` (a sequence
///   of space-separated bits)
#[cfg_attr(doc, macro_export)] // For `cargo doc` to produce documentation.
macro_rules! bitfield {
    ($($input: tt)*) => {
        bitfield_impl! { []{ pos: 0 }[$($input)*] }
    };
}

macro_rules! bitfield_impl {
    // Main rules:
    // - Input are bit field descriptors
    // - Position is the number of bits used by prior bit fields
    // - Output are the bit field definitions
    ([$($output: tt)*]{ pos: $pos: expr }
     [$(#[$meta: meta])* $name: ident: Bit, $($input: tt)*]) => {
        bitfield_impl! {
            [$($output)* $(#[$meta])* const $name: Bit = Bit { pos: $pos };]
            { pos: $pos + 1 }
            [$($input)*]
        }
    };
    ([$($output: tt)*]{ pos: $pos: expr }
     [$(#[$meta: meta])* $name: ident: Field <= $max: expr, $($input: tt)*]) => {
        bitfield_impl! {
            [$($output)* $(#[$meta])* const $name: Field = Field {
                pos: $pos,
                len: num_bits($max),
            };]
            { pos: $pos + $name.len }
            [$($input)*]
        }
    };
    ([$($output: tt)*]{ pos: $pos: expr }
     [$(#[$meta: meta])* $name: ident: Checksum <= $max: expr, $($input: tt)*]) => {
        bitfield_impl! {
            [$($output)* $(#[$meta])* const $name: Checksum = Checksum {
                field: Field { pos: $pos, len: num_bits($max) }
            };]
            { pos: $pos + $name.field.len }
            [$($input)*]
        }
    };
    ([$($output: tt)*]{ pos: $pos: expr }
     [$(#[$meta: meta])* $name: ident: Length, $($input: tt)*]) => {
        bitfield_impl! {
            [$($output)* $(#[$meta])* const $name: Length = Length { pos: $pos };]
            { pos: $pos }
            [$($input)*]
        }
    };
    ([$($output: tt)*]{ pos: $pos: expr }
     [$(#[$meta: meta])* $name: ident: ConstField = $bits: tt, $($input: tt)*]) => {
        bitfield_impl! {
            Reverse $(#[$meta])* $name []$bits
            [$($output)*]{ pos: $pos }[$($input)*]
        }
    };
    ([$($output: tt)*]{ pos: $pos: expr }[]) => { $($output)* };

    // Auxiliary rules for constant bit fields:
    // - Input is a sequence of bits
    // - Output is the reversed sequence of bits
    (Reverse $(#[$meta: meta])* $name: ident [$($output_bits: tt)*] [$bit: tt $($input_bits: tt)*]
     [$($output: tt)*]{ pos: $pos: expr }[$($input: tt)*]) => {
        bitfield_impl! {
            Reverse $(#[$meta])* $name [$bit $($output_bits)*][$($input_bits)*]
            [$($output)*]{ pos: $pos }[$($input)*]
        }
    };
    (Reverse $(#[$meta: meta])* $name: ident $bits: tt []
     [$($output: tt)*]{ pos: $pos: expr }[$($input: tt)*]) => {
        bitfield_impl! {
            ConstField $(#[$meta])* $name { len: 0, val: 0 }$bits
            [$($output)*]{ pos: $pos }[$($input)*]
        }
    };

    // Auxiliary rules for constant bit fields:
    // - Input is a sequence of bits in reversed order
    // - Output is the constant bit field definition with the sequence of bits as value
    (ConstField $(#[$meta: meta])* $name: ident { len: $len: expr, val: $val: expr }[]
     [$($output: tt)*]{ pos: $pos: expr }[$($input: tt)*]) => {
        bitfield_impl! {
            [$($output)* $(#[$meta])* const $name: ConstField = ConstField {
                field: Field { pos: $pos, len: $len },
                value: $val,
            };]
            { pos: $pos + $name.field.len }
            [$($input)*]
        }
    };
    (ConstField $(#[$meta: meta])* $name: ident { len: $len: expr, val: $val: expr }
     [$bit: tt $($bits: tt)*][$($output: tt)*]{ pos: $pos: expr }[$($input: tt)*]) => {
        bitfield_impl! {
            ConstField $(#[$meta])* $name { len: $len + 1, val: $val * 2 + $bit }[$($bits)*]
            [$($output)*]{ pos: $pos }[$($input)*]
        }
    };
}

/// Counts the number of bits equal to zero in a byte slice.
pub fn count_zeros(slice: &[u8]) -> Nat {
    slice.iter().map(|&x| x.count_zeros()).sum()
}

/// Returns the number of bits necessary to represent a number.
pub const fn num_bits(x: Nat) -> Nat {
    8 * core::mem::size_of::<Nat>() as Nat - x.leading_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_ok() {
        let field = Field { pos: 3, len: 5 };
        assert_eq!(field.get(Word(0x00000000)), 0);
        assert_eq!(field.get(Word(0x00000007)), 0);
        assert_eq!(field.get(Word(0x00000008)), 1);
        assert_eq!(field.get(Word(0x000000f8)), 0x1f);
        assert_eq!(field.get(Word(0x0000ff37)), 6);
        let mut word = Word(0xffffffff);
        field.set(&mut word, 3).unwrap();
        assert_eq!(word, Word(0xffffff1f));
    }

    #[test]
    fn const_field_ok() {
        let field = ConstField {
            field: Field { pos: 3, len: 5 },
            value: 9,
        };
        assert!(!field.check(Word(0x00000000)));
        assert!(!field.check(Word(0x0000ffff)));
        assert!(field.check(Word(0x00000048)));
        assert!(field.check(Word(0x0000ff4f)));
        let mut word = Word(0xffffffff);
        field.set(&mut word).unwrap();
        assert_eq!(word, Word(0xffffff4f));
    }

    #[test]
    fn bit_ok() {
        let bit = Bit { pos: 3 };
        assert!(bit.get(Word(0x00000000)));
        assert!(bit.get(Word(0xfffffff7)));
        assert!(!bit.get(Word(0x00000008)));
        assert!(!bit.get(Word(0xffffffff)));
        let mut word = Word(0xffffffff);
        bit.set(&mut word);
        assert_eq!(word, Word(0xfffffff7));
    }

    #[test]
    fn checksum_ok() {
        let field = Checksum {
            field: Field { pos: 3, len: 5 },
        };
        assert_eq!(field.get(Word(0x00000000)), Err(StoreError::InvalidStorage));
        assert_eq!(field.get(Word(0xffffffff)), Ok(31));
        assert_eq!(field.get(Word(0xffffff07)), Ok(0));
        assert_eq!(field.get(Word(0xffffff0f)), Ok(1));
        assert_eq!(field.get(Word(0x00ffff67)), Ok(4));
        assert_eq!(field.get(Word(0x7fffff07)), Err(StoreError::InvalidStorage));
        let mut word = Word(0x0fffffff);
        field.set(&mut word, 4).unwrap();
        assert_eq!(word, Word(0x0fffff47));
    }

    #[test]
    fn bitfield_ok() {
        bitfield! {
            FIELD: Field <= 127,
            CONST_FIELD: ConstField = [0 1 0 1],
            BIT: Bit,
            CHECKSUM: Checksum <= 58,
            LENGTH: Length,
        }
        assert_eq!(FIELD.pos, 0);
        assert_eq!(FIELD.len, 7);
        assert_eq!(CONST_FIELD.field.pos, 7);
        assert_eq!(CONST_FIELD.field.len, 4);
        assert_eq!(CONST_FIELD.value, 10);
        assert_eq!(BIT.pos, 11);
        assert_eq!(CHECKSUM.field.pos, 12);
        assert_eq!(CHECKSUM.field.len, 6);
        assert_eq!(LENGTH.pos, 18);
    }

    #[test]
    fn count_zeros_ok() {
        assert_eq!(count_zeros(&[0xff, 0xff]), 0);
        assert_eq!(count_zeros(&[0xff, 0xfe]), 1);
        assert_eq!(count_zeros(&[0x7f, 0xff]), 1);
        assert_eq!(count_zeros(&[0x12, 0x48]), 12);
        assert_eq!(count_zeros(&[0x00, 0x00]), 16);
    }

    #[test]
    fn num_bits_ok() {
        assert_eq!(num_bits(0), 0);
        assert_eq!(num_bits(1), 1);
        assert_eq!(num_bits(2), 2);
        assert_eq!(num_bits(3), 2);
        assert_eq!(num_bits(4), 3);
        assert_eq!(num_bits(5), 3);
        assert_eq!(num_bits(8), 4);
        assert_eq!(num_bits(9), 4);
        assert_eq!(num_bits(16), 5);
    }
}
