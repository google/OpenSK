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

// TODO(ia0): Remove when used.
#![allow(dead_code)]

/// Bit-level entropy source based on a byte slice shared reference.
struct Entropy<'a> {
    /// The byte slice shared reference providing the entropy.
    data: &'a [u8],

    /// The bit position in the byte slice of the next entropy bit.
    bit: usize,
}

impl Entropy<'_> {
    /// Creates a bit-level entropy given a byte slice.
    fn new(data: &[u8]) -> Entropy {
        let bit = 0;
        Entropy { data, bit }
    }

    /// Consumes the remaining entropy.
    fn consume_all(&mut self) {
        self.bit = 8 * self.data.len();
    }

    /// Returns whether there is entropy remaining.
    fn is_empty(&self) -> bool {
        assert!(self.bit <= 8 * self.data.len());
        self.bit == 8 * self.data.len()
    }

    /// Reads a bit.
    fn read_bit(&mut self) -> bool {
        if self.is_empty() {
            return false;
        }
        let b = self.bit;
        self.bit += 1;
        self.data[b / 8] & 1 << (b % 8) != 0
    }

    /// Reads a number with a given bit-width.
    ///
    /// # Preconditions
    ///
    /// - The number should fit in the return type: `n <= 8 * size_of::<usize>()`.
    fn read_bits(&mut self, n: usize) -> usize {
        assert!(n <= 8 * std::mem::size_of::<usize>());
        let mut r = 0;
        for i in 0..n {
            r |= (self.read_bit() as usize) << i;
        }
        r
    }

    /// Reads a byte.
    fn read_byte(&mut self) -> u8 {
        self.read_bits(8) as u8
    }

    /// Reads a slice.
    fn read_slice(&mut self, length: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(length);
        for _ in 0..length {
            result.push(self.read_byte());
        }
        result
    }

    /// Reads a bounded number.
    ///
    /// # Preconditions
    ///
    /// - The bounds should be correctly ordered: `min <= max`.
    /// - The upper-bound should not be too large: `max < usize::max_value()`.
    fn read_range(&mut self, min: usize, max: usize) -> usize {
        assert!(min <= max && max < usize::max_value());
        let count = max - min + 1;
        let delta = self.read_bits(num_bits(count - 1)) % count;
        min + delta
    }
}

/// Returns the number of bits necessary to represent a number.
fn num_bits(x: usize) -> usize {
    8 * std::mem::size_of::<usize>() - x.leading_zeros() as usize
}

#[test]
fn num_bits_ok() {
    assert_eq!(num_bits(0), 0);
    assert_eq!(num_bits(1), 1);
    assert_eq!(num_bits(2), 2);
    assert_eq!(num_bits(3), 2);
    assert_eq!(num_bits(4), 3);
    assert_eq!(num_bits(7), 3);
    assert_eq!(num_bits(8), 4);
    assert_eq!(num_bits(15), 4);
    assert_eq!(num_bits(16), 5);
    assert_eq!(
        num_bits(usize::max_value()),
        8 * std::mem::size_of::<usize>()
    );
}

#[test]
fn read_bit_ok() {
    let mut entropy = Entropy::new(&[0b10110010]);
    assert!(!entropy.read_bit());
    assert!(entropy.read_bit());
    assert!(!entropy.read_bit());
    assert!(!entropy.read_bit());
    assert!(entropy.read_bit());
    assert!(entropy.read_bit());
    assert!(!entropy.read_bit());
    assert!(entropy.read_bit());
}

#[test]
fn read_bits_ok() {
    let mut entropy = Entropy::new(&[0x83, 0x92]);
    assert_eq!(entropy.read_bits(4), 0x3);
    assert_eq!(entropy.read_bits(8), 0x28);
    assert_eq!(entropy.read_bits(2), 0b01);
    assert_eq!(entropy.read_bits(2), 0b10);
}

#[test]
fn read_range_ok() {
    let mut entropy = Entropy::new(&[0b00101011]);
    assert_eq!(entropy.read_range(0, 7), 0b011);
    assert_eq!(entropy.read_range(1, 8), 1 + 0b101);
    assert_eq!(entropy.read_range(4, 6), 4 + 0b00);
    let mut entropy = Entropy::new(&[0b00101011]);
    assert_eq!(entropy.read_range(0, 8), 0b1011 % 9);
    assert_eq!(entropy.read_range(3, 15), 3 + 0b0010);
    let mut entropy = Entropy::new(&[0x12, 0x34, 0x56, 0x78]);
    assert_eq!(entropy.read_range(0, usize::max_value() - 1), 0x78563412);
}
