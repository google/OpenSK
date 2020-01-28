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

/// Defines a consecutive sequence of bits.
#[derive(Copy, Clone)]
pub struct BitRange {
    /// The first bit of the sequence.
    pub start: usize,

    /// The length in bits of the sequence.
    pub length: usize,
}

impl BitRange {
    /// Returns the first bit following a bit range.
    pub fn end(self) -> usize {
        self.start + self.length
    }
}

/// Defines a consecutive sequence of bytes.
///
/// The bits in those bytes are ignored which essentially creates a gap in a sequence of bits. The
/// gap is necessarily at byte boundaries. This is used to ignore the user data in an entry
/// essentially providing a view of the entry information (header and footer).
#[derive(Copy, Clone)]
pub struct ByteGap {
    pub start: usize,
    pub length: usize,
}

/// Empty gap. All bits count.
pub const NO_GAP: ByteGap = ByteGap {
    start: 0,
    length: 0,
};

impl ByteGap {
    /// Translates a bit to skip the gap.
    fn shift(self, bit: usize) -> usize {
        if bit < 8 * self.start {
            bit
        } else {
            bit + 8 * self.length
        }
    }
}

/// Returns whether a bit is set in a sequence of bits.
///
/// The sequence of bits is little-endian (both for bytes and bits) and defined by the bits that
/// are in `data` but not in `gap`.
pub fn is_zero(bit: usize, data: &[u8], gap: ByteGap) -> bool {
    let bit = gap.shift(bit);
    debug_assert!(bit < 8 * data.len());
    data[bit / 8] & (1 << (bit % 8)) == 0
}

/// Sets a bit to zero in a sequence of bits.
///
/// The sequence of bits is little-endian (both for bytes and bits) and defined by the bits that
/// are in `data` but not in `gap`.
pub fn set_zero(bit: usize, data: &mut [u8], gap: ByteGap) {
    let bit = gap.shift(bit);
    debug_assert!(bit < 8 * data.len());
    data[bit / 8] &= !(1 << (bit % 8));
}

/// Returns a little-endian value in a sequence of bits.
///
/// The sequence of bits is little-endian (both for bytes and bits) and defined by the bits that
/// are in `data` but not in `gap`. The range of bits where the value is stored in defined by
/// `range`. The value must fit in a `usize`.
pub fn get_range(range: BitRange, data: &[u8], gap: ByteGap) -> usize {
    debug_assert!(range.length <= 8 * core::mem::size_of::<usize>());
    let mut result = 0;
    for i in 0..range.length {
        if !is_zero(range.start + i, data, gap) {
            result |= 1 << i;
        }
    }
    result
}

/// Sets a little-endian value in a sequence of bits.
///
/// The sequence of bits is little-endian (both for bytes and bits) and defined by the bits that
/// are in `data` but not in `gap`. The range of bits where the value is stored in defined by
/// `range`. The bits set to 1 in `value` must also be set to `1` in the sequence of bits.
pub fn set_range(range: BitRange, data: &mut [u8], gap: ByteGap, value: usize) {
    debug_assert!(range.length == 8 * core::mem::size_of::<usize>() || value < 1 << range.length);
    for i in 0..range.length {
        if value & 1 << i == 0 {
            set_zero(range.start + i, data, gap);
        }
    }
}

/// Tests the `is_zero` and `set_zero` pair of functions.
#[test]
fn zero_ok() {
    const GAP: ByteGap = ByteGap {
        start: 2,
        length: 1,
    };
    for i in 0..24 {
        assert!(!is_zero(i, &[0xffu8, 0xff, 0x00, 0xff] as &[u8], GAP));
    }
    // Tests reading and setting a bit. The result should have all bits set to 1 except for the bit
    // to test and the gap.
    fn test(bit: usize, result: &[u8]) {
        assert!(is_zero(bit, result, GAP));
        let mut data = vec![0xff; result.len()];
        // Set the gap bits to 0.
        for i in 0..GAP.length {
            data[GAP.start + i] = 0x00;
        }
        set_zero(bit, &mut data, GAP);
        assert_eq!(data, result);
    }
    test(0, &[0xfe, 0xff, 0x00, 0xff]);
    test(1, &[0xfd, 0xff, 0x00, 0xff]);
    test(2, &[0xfb, 0xff, 0x00, 0xff]);
    test(7, &[0x7f, 0xff, 0x00, 0xff]);
    test(8, &[0xff, 0xfe, 0x00, 0xff]);
    test(15, &[0xff, 0x7f, 0x00, 0xff]);
    test(16, &[0xff, 0xff, 0x00, 0xfe]);
    test(17, &[0xff, 0xff, 0x00, 0xfd]);
    test(23, &[0xff, 0xff, 0x00, 0x7f]);
}

/// Tests the `get_range` and `set_range` pair of functions.
#[test]
fn range_ok() {
    // Tests reading and setting a range. The result should have all bits set to 1 except for the
    // range to test and the gap.
    fn test(start: usize, length: usize, value: usize, result: &[u8], gap: ByteGap) {
        let range = BitRange { start, length };
        assert_eq!(get_range(range, result, gap), value);
        let mut data = vec![0xff; result.len()];
        for i in 0..gap.length {
            data[gap.start + i] = 0x00;
        }
        set_range(range, &mut data, gap, value);
        assert_eq!(data, result);
    }
    test(0, 8, 42, &[42], NO_GAP);
    test(3, 12, 0b11_0101, &[0b1010_1111, 0b1000_0001], NO_GAP);
    test(0, 16, 0x1234, &[0x34, 0x12], NO_GAP);
    test(4, 16, 0x1234, &[0x4f, 0x23, 0xf1], NO_GAP);
    let mut gap = ByteGap {
        start: 1,
        length: 1,
    };
    test(3, 12, 0b11_0101, &[0b1010_1111, 0x00, 0b1000_0001], gap);
    gap.length = 2;
    test(0, 16, 0x1234, &[0x34, 0x00, 0x00, 0x12], gap);
    gap.start = 2;
    gap.length = 1;
    test(4, 16, 0x1234, &[0x4f, 0x23, 0x00, 0xf1], gap);
}
