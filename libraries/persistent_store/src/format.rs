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

// TODO(ia0): Remove when the module is used.
#![allow(dead_code)]

use crate::bitfield::*;
use crate::{Storage, StorageIndex, StoreError, StoreResult};
use alloc::vec::Vec;
use core::cmp::min;

type WORD = u32;

/// Size of a word in bytes.
///
/// Currently, the store only supports storages where a word is 4 bytes.
const WORD_SIZE: usize = core::mem::size_of::<WORD>();

/// Maximum size of a page in bytes.
///
/// Currently, the store only supports storages where pages are between 8 and 1024 [words].
///
/// [words]: constant.WORD_SIZE.html
const MAX_PAGE_SIZE: usize = 4096;

/// Maximum number of erase cycles.
///
/// Currently, the store only supports storages where the maximum number of erase cycles fits on 16
/// bits.
const MAX_ERASE_CYCLE: usize = 65535;

/// Maximum page index.
///
/// Thus the maximum number of pages is one more than this number. Currently, the store only
/// supports storages where the number of pages is between 3 and 64.
const MAX_PAGE_INDEX: usize = 63;

/// Maximum key index.
///
/// Thus the number of keys is one more than this number. Currently, the store only supports 4096
/// keys.
const MAX_KEY_INDEX: usize = 4095;

/// Maximum length in bytes of a user payload.
///
/// Currently, the store only supports values smaller than 1024 bytes.
const MAX_VALUE_LEN: usize = 1023;

/// Maximum number of updates per transaction.
///
/// Currently, the store only supports transactions with at most 31 updates.
const MAX_UPDATES: usize = 31;

/// Maximum number of words per virtual page.
const MAX_VIRT_PAGE_SIZE: usize = div_ceil(MAX_PAGE_SIZE, WORD_SIZE) - CONTENT_WORD;

/// Word with all bits set to one.
const ERASED_WORD: u32 = 0xffffffff;

/// Helpers for a given storage configuration.
#[derive(Clone, Debug)]
pub struct Format {
    /// The size in bytes of a page in the storage.
    ///
    /// # Invariant
    ///
    /// - Words divide a page evenly.
    /// - There are at least 8 words in a page.
    /// - There are at most `MAX_PAGE_SIZE` bytes in a page.
    page_size: usize,

    /// The number of pages in the storage.
    ///
    /// # Invariant
    ///
    /// - There are at least 3 pages.
    /// - There are at most `MAX_PAGE_INDEX + 1` pages.
    num_pages: usize,

    /// The maximum number of times a page can be erased.
    ///
    /// # Invariant
    ///
    /// - A page can be erased at most `MAX_ERASE_CYCLE` times.
    max_page_erases: usize,
}

impl Format {
    /// Extracts the format from a storage.
    ///
    /// Returns `None` if the storage is not [supported].
    ///
    /// [supported]: struct.Format.html#method.is_storage_supported
    pub fn new<S: Storage>(storage: &S) -> Option<Format> {
        if Format::is_storage_supported(storage) {
            Some(Format {
                page_size: storage.page_size(),
                num_pages: storage.num_pages(),
                max_page_erases: storage.max_page_erases(),
            })
        } else {
            None
        }
    }

    /// Returns whether a storage is supported.
    ///
    /// A storage is supported if the following conditions hold:
    /// - The size of a word is 4 bytes.
    /// - The size of a word evenly divides the size of a page.
    /// - A page contains at least 8 words.
    /// - A page contains at most [`MAX_PAGE_SIZE`] bytes.
    /// - There are at least 3 pages.
    /// - There are at most [`MAX_PAGE_INDEX`]` + 1` pages.
    /// - A word can be written at least twice between erase cycles.
    /// - The maximum number of erase cycles is at most [`MAX_ERASE_CYCLE`].
    ///
    /// [`MAX_PAGE_SIZE`]: constant.MAX_PAGE_SIZE.html
    /// [`MAX_PAGE_INDEX`]: constant.MAX_PAGE_INDEX.html
    /// [`MAX_ERASE_CYCLE`]: constant.MAX_ERASE_CYCLE.html
    fn is_storage_supported<S: Storage>(storage: &S) -> bool {
        let word_size = storage.word_size();
        let page_size = storage.page_size();
        let num_pages = storage.num_pages();
        let max_word_writes = storage.max_word_writes();
        let max_page_erases = storage.max_page_erases();
        word_size == 4
            && page_size % word_size == 0
            && (8 * word_size <= page_size && page_size <= MAX_PAGE_SIZE)
            && (3 <= num_pages && num_pages <= MAX_PAGE_INDEX + 1)
            && max_word_writes >= 2
            && max_page_erases <= MAX_ERASE_CYCLE
    }

    /// The size of a word in bytes.
    pub fn word_size(&self) -> usize {
        WORD_SIZE
    }

    /// The size of a page in bytes.
    ///
    /// We have `32 <= self.page_size() <= MAX_PAGE_SIZE` assuming a word is 4 bytes.
    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// The number of pages in the storage, denoted by `N`.
    ///
    /// We have `3 <= N <= MAX_PAGE_INDEX + 1`.
    pub fn num_pages(&self) -> usize {
        self.num_pages
    }

    /// The maximum page index.
    ///
    /// We have `2 <= self.max_page() <= MAX_PAGE_INDEX`.
    pub fn max_page(&self) -> usize {
        self.num_pages - 1
    }

    /// The maximum number of times a page can be erased, denoted by `E`.
    ///
    /// We have `E <= MAX_ERASE_CYCLE`.
    pub fn max_page_erases(&self) -> usize {
        self.max_page_erases
    }

    /// The maximum key.
    pub fn max_key(&self) -> usize {
        MAX_KEY_INDEX
    }

    /// The maximum number of updates per transaction.
    pub fn max_updates(&self) -> usize {
        MAX_UPDATES
    }

    /// The size of a virtual page in words, denoted by `Q`.
    ///
    /// A virtual page is stored in a physical page after the page header.
    ///
    /// We have `6 <= Q <= MAX_VIRT_PAGE_SIZE`.
    pub fn virt_page_size(&self) -> usize {
        self.page_size() / self.word_size() - CONTENT_WORD
    }

    /// The maximum length in bytes of a user payload.
    ///
    /// We have `20 <= self.max_value_len() <= MAX_VALUE_LEN` assuming words are 4 bytes.
    pub fn max_value_len(&self) -> usize {
        min(
            (self.virt_page_size() - 1) * self.word_size(),
            MAX_VALUE_LEN,
        )
    }

    /// The maximum prefix length in words, denoted by `M`.
    ///
    /// A prefix is the first words of a virtual page that belong to the last entry of the previous
    /// virtual page. This happens because entries may overlap up to 2 virtual pages.
    ///
    /// We have `5 <= M < Q`.
    pub fn max_prefix_len(&self) -> usize {
        self.bytes_to_words(self.max_value_len())
    }

    /// The total virtual capacity in words, denoted by `V`.
    ///
    /// We have `V = (N - 1) * (Q - 1) - M`.
    ///
    /// We can show `V >= (N - 2) * (Q - 1)` with the following steps:
    /// - `M <= Q - 1` from `M < Q` from [`M`] definition
    /// - `-M >= -(Q - 1)` from above
    /// - `V >= (N - 1) * (Q - 1) - (Q - 1)` from `V` definition
    ///
    /// [`M`]: struct.Format.html#method.max_prefix_len
    pub fn virt_size(&self) -> usize {
        (self.num_pages() - 1) * (self.virt_page_size() - 1) - self.max_prefix_len()
    }

    /// The total user capacity in words, denoted by `C`.
    ///
    /// We have `C = V - N = (N - 1) * (Q - 2) - M - 1`.
    ///
    /// We can show `C >= (N - 2) * (Q - 2) - 2` with the following steps:
    /// - `V >= (N - 2) * (Q - 1)` from [`V`] definition
    /// - `C >= (N - 2) * (Q - 1) - N` from `C` definition
    /// - `(N - 2) * (Q - 1) - N = (N - 2) * (Q - 2) - 2` by calculus
    ///
    /// [`V`]: struct.Format.html#method.virt_size
    pub fn total_capacity(&self) -> usize {
        // From the virtual capacity, we reserve N - 1 words for `Erase` entries and 1 word for a
        // `Clear` entry.
        self.virt_size() - self.num_pages()
    }

    /// The total virtual lifetime in words, denoted by `L`.
    ///
    /// We have `L = (E * N + N - 1) * Q`.
    pub fn total_lifetime(&self) -> Position {
        Position::new(self, self.max_page_erases(), self.num_pages() - 1, 0)
    }

    /// Returns the word position of the first entry of a page.
    ///
    /// The init info of the page must be provided to know where the first entry of the page
    /// starts.
    pub fn page_head(&self, init: InitInfo, page: usize) -> Position {
        Position::new(self, init.cycle, page, init.prefix)
    }

    /// Returns the storage index of the init info of a page.
    pub fn index_init(&self, page: usize) -> StorageIndex {
        let byte = INIT_WORD * self.word_size();
        StorageIndex { page, byte }
    }

    /// Parses the init info of a page from its storage representation.
    pub fn parse_init(&self, word: WORD) -> StoreResult<WordState<InitInfo>> {
        Ok(if word == ERASED_WORD {
            WordState::Erased
        } else if WORD_CHECKSUM.get(word)? != 0 {
            WordState::Partial
        } else {
            let cycle = INIT_CYCLE.get(word);
            let prefix = INIT_PREFIX.get(word);
            if cycle > self.max_page_erases() || prefix > self.max_prefix_len() {
                return Err(StoreError::InvalidStorage);
            }
            WordState::Valid(InitInfo { cycle, prefix })
        })
    }

    /// Builds the storage representation of an init info.
    pub fn build_init(&self, init: InitInfo) -> [u8; WORD_SIZE] {
        let mut word = ERASED_WORD;
        INIT_CYCLE.set(&mut word, init.cycle);
        INIT_PREFIX.set(&mut word, init.prefix);
        WORD_CHECKSUM.set(&mut word, 0);
        word.to_ne_bytes()
    }

    /// Returns the storage index of the compact info of a page.
    pub fn index_compact(&self, page: usize) -> StorageIndex {
        let byte = COMPACT_WORD * self.word_size();
        StorageIndex { page, byte }
    }

    /// Parses the compact info of a page from its storage representation.
    pub fn parse_compact(&self, word: WORD) -> StoreResult<WordState<CompactInfo>> {
        Ok(if word == ERASED_WORD {
            WordState::Erased
        } else if WORD_CHECKSUM.get(word)? != 0 {
            WordState::Partial
        } else {
            let tail = COMPACT_TAIL.get(word);
            if tail > self.virt_size() + self.max_prefix_len() {
                return Err(StoreError::InvalidStorage);
            }
            WordState::Valid(CompactInfo { tail })
        })
    }

    /// Builds the storage representation of a compact info.
    pub fn build_compact(&self, compact: CompactInfo) -> [u8; WORD_SIZE] {
        let mut word = ERASED_WORD;
        COMPACT_TAIL.set(&mut word, compact.tail);
        WORD_CHECKSUM.set(&mut word, 0);
        word.to_ne_bytes()
    }

    /// Builds the storage representation of an internal entry.
    pub fn build_internal(&self, internal: InternalEntry) -> [u8; WORD_SIZE] {
        let mut word = ERASED_WORD;
        match internal {
            InternalEntry::Erase { page } => {
                ID_ERASE.set(&mut word);
                ERASE_PAGE.set(&mut word, page);
            }
            InternalEntry::Clear { min_key } => {
                ID_CLEAR.set(&mut word);
                CLEAR_MIN_KEY.set(&mut word, min_key);
            }
            InternalEntry::Marker { count } => {
                ID_MARKER.set(&mut word);
                MARKER_COUNT.set(&mut word, count);
            }
            InternalEntry::Remove { key } => {
                ID_REMOVE.set(&mut word);
                REMOVE_KEY.set(&mut word, key);
            }
        }
        WORD_CHECKSUM.set(&mut word, 0);
        word.to_ne_bytes()
    }

    /// Parses the first word of an entry from its storage representation.
    pub fn parse_word(&self, word: WORD) -> StoreResult<WordState<ParsedWord>> {
        let valid = if ID_PADDING.check(word) {
            ParsedWord::Padding(Padding { length: 0 })
        } else if ID_HEADER.check(word) {
            if HEADER_DELETED.get(word) {
                let length = HEADER_LENGTH.get(word);
                if length > self.max_value_len() {
                    return Err(StoreError::InvalidStorage);
                }
                let length = self.bytes_to_words(length);
                ParsedWord::Padding(Padding { length })
            } else {
                let flipped = HEADER_FLIPPED.get(word);
                let length = HEADER_LENGTH.get(word);
                let key = HEADER_KEY.get(word);
                let checksum = HEADER_CHECKSUM.get(word)?;
                ParsedWord::Header(Header {
                    flipped,
                    length,
                    key,
                    checksum,
                })
            }
        } else if ID_ERASE.check(word) {
            let page = ERASE_PAGE.get(word);
            ParsedWord::Internal(InternalEntry::Erase { page })
        } else if ID_CLEAR.check(word) {
            let min_key = CLEAR_MIN_KEY.get(word);
            ParsedWord::Internal(InternalEntry::Clear { min_key })
        } else if ID_MARKER.check(word) {
            let count = MARKER_COUNT.get(word);
            ParsedWord::Internal(InternalEntry::Marker { count })
        } else if ID_REMOVE.check(word) {
            let key = REMOVE_KEY.get(word);
            ParsedWord::Internal(InternalEntry::Remove { key })
        } else if word == ERASED_WORD {
            return Ok(WordState::Erased);
        } else {
            return Ok(WordState::Partial);
        };
        if let ParsedWord::Internal(internal) = &valid {
            if WORD_CHECKSUM.get(word)? != 0 {
                return Ok(WordState::Partial);
            }
            let invalid = match internal {
                InternalEntry::Erase { page } => *page > self.max_page(),
                InternalEntry::Clear { min_key } => *min_key > self.max_key(),
                InternalEntry::Marker { count } => *count > MAX_UPDATES,
                InternalEntry::Remove { key } => *key > self.max_key(),
            };
            if invalid {
                return Err(StoreError::InvalidStorage);
            }
        }
        Ok(WordState::Valid(valid))
    }

    /// Builds the storage representation of a user entry.
    pub fn build_user(&self, key: usize, value: &[u8]) -> Vec<u8> {
        let length = value.len();
        let word_size = self.word_size();
        let footer = self.bytes_to_words(length);
        let mut result = vec![0xff; (1 + footer) * word_size];
        result[word_size..][..length].copy_from_slice(value);
        let mut word = ERASED_WORD;
        ID_HEADER.set(&mut word);
        if footer > 0 && is_erased(&result[footer * word_size..]) {
            HEADER_FLIPPED.set(&mut word);
            *result.last_mut().unwrap() = 0x7f;
        }
        HEADER_LENGTH.set(&mut word, length);
        HEADER_KEY.set(&mut word, key);
        HEADER_CHECKSUM.set(&mut word, count_zeros(&result[footer * word_size..]));
        result[..word_size].copy_from_slice(&word.to_ne_bytes());
        result
    }

    /// Sets the padding bit in the first word of a user entry.
    pub fn set_padding(&self, word: &mut WORD) {
        ID_PADDING.set(word);
    }

    /// Sets the deleted bit in the first word of a user entry.
    pub fn set_deleted(&self, word: &mut WORD) {
        HEADER_DELETED.set(word);
    }

    /// Returns the minimum number of words to represent a given number of bytes.
    ///
    /// Assumes `bytes + self.word_size()` does not overflow.
    pub fn bytes_to_words(&self, bytes: usize) -> usize {
        div_ceil(bytes, self.word_size())
    }
}

/// The word index of the init info in a page.
const INIT_WORD: usize = 0;

/// The word index of the compact info in a page.
const COMPACT_WORD: usize = 1;

/// The word index of the content of a page.
///
/// Since a page is at least 8 words, there is always at least 6 words of content.
const CONTENT_WORD: usize = 2;

/// The checksum for a single word.
///
/// Since checksums are the number of bits set to zero and a word is 32 bits, we need 5 bits to
/// store numbers between 0 and 27 (which is 32 - 5).
const WORD_CHECKSUM: Checksum = Checksum {
    field: Field { pos: 27, len: 5 },
};

// The fields of the init info of a page.
bitfield! {
    /// The number of times the page has been erased.
    INIT_CYCLE: Field <= MAX_ERASE_CYCLE,

    /// The word index of the first entry in this virtual page.
    INIT_PREFIX: Field <= div_ceil(MAX_VALUE_LEN, WORD_SIZE),

    #[cfg(test)]
    LEN_INIT: Length,
}

// The fields of the compact info of a page.
bitfield! {
    /// The distance in words between head and tail at compaction.
    ///
    /// In particular, compaction copies non-deleted user entries from the head to the tail as long
    /// as entries span the page to be compacted.
    COMPACT_TAIL: Field <= MAX_VIRT_PAGE_SIZE * MAX_PAGE_INDEX,

    #[cfg(test)]
    LEN_COMPACT: Length,
}

// Overview of the first word of the different kind of entries.
//
// Each column represents a bit of the word. The first 2 lines give the position in hexadecimal of
// the bit in the word (the exponent of 2 when the word is written in binary). Each entry starts
// with the sequence of bits of its identifier. The dots following the identifier are the number of
// bits necessary to hold the information of the entry (including the checksum). The remaining free
// bits after the dots are not used by the entry.
//
//         0               1
//         0123456789abcdef0123456789abcdef
// padding 0
//  header 10..............................
//   erase 11000...........
//   clear 11001.................
//  marker 11010..........
//  remove 11011.................
//
// NOTE: We could pad the internal entries to the right by extending their identifier. This permits
// to free some space for shorter identifier for future kind of entries.

// The fields of a padding entry.
bitfield! {
    /// The identifier for padding entries.
    ID_PADDING: ConstField = [0],
}

// The fields of a user entry.
bitfield! {
    /// The identifier for user entries.
    ID_HEADER: ConstField = [1 0],

    /// Whether the user entry is deleted.
    HEADER_DELETED: Bit,

    /// Whether the last bit of the user data is flipped.
    HEADER_FLIPPED: Bit,

    /// The length in bytes of the user data.
    // NOTE: It is possible to support values of length 1024 by having a separate kind of entries
    // when the value is empty. We could then subtract one from the length here.
    HEADER_LENGTH: Field <= MAX_VALUE_LEN,

    /// The key of the user entry.
    HEADER_KEY: Field <= MAX_KEY_INDEX,

    /// The checksum of the user entry.
    ///
    /// This counts the number of bits set to zero in both the first and last words of the user
    /// entry, except in the checksum itself. So it needs 6 bits to store numbers between 0 and 58.
    // NOTE: It may be possible to save one bit by storing:
    // - the footer checksum (as a field) if the value is not empty
    // - the header checksum (as a checksum) if the value is empty
    HEADER_CHECKSUM: Checksum <= 58,

    #[cfg(test)]
    LEN_HEADER: Length,
}

// The fields of an erase entry.
bitfield! {
    /// The identifier for erase entries.
    ID_ERASE: ConstField = [1 1 0 0 0],

    /// The page to be erased.
    ERASE_PAGE: Field <= MAX_PAGE_INDEX,

    #[cfg(test)]
    LEN_ERASE: Length,
}

// The fields of a clear entry.
bitfield! {
    /// The identifier for clear entries.
    ID_CLEAR: ConstField = [1 1 0 0 1],

    /// The minimum key to be cleared.
    ///
    /// All entries with a key below this limit are not cleared. All other entries are deleted.
    CLEAR_MIN_KEY: Field <= MAX_KEY_INDEX,

    #[cfg(test)]
    LEN_CLEAR: Length,
}

// The fields of a marker entry.
bitfield! {
    /// The identifier for marker entries.
    ID_MARKER: ConstField = [1 1 0 1 0],

    /// The number of updates in this transaction.
    ///
    /// The update entries follow this marker entry.
    MARKER_COUNT: Field <= MAX_UPDATES,

    #[cfg(test)]
    LEN_MARKER: Length,
}

// The fields of a remove entry.
bitfield! {
    /// The identifier for remove entries.
    ID_REMOVE: ConstField = [1 1 0 1 1],

    /// The key of the user entry to be removed.
    REMOVE_KEY: Field <= MAX_KEY_INDEX,

    #[cfg(test)]
    LEN_REMOVE: Length,
}

/// The position of a word in the virtual storage.
///
/// With the notations defined in `Format`, let:
/// - `w` a virtual word offset in a page which is between `0` and `Q - 1`
/// - `p` a page offset which is between `0` and `N - 1`
/// - `c` the number of erase cycles of a page which is between `0` and `E`
///
/// Then the position of a word is `(c*N + p)*Q + w`. This position monotonically increases and
/// represents the consumed lifetime of the storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position(usize);

impl core::ops::Add<usize> for Position {
    type Output = Position;

    fn add(self, delta: usize) -> Position {
        Position(self.0 + delta)
    }
}

impl core::ops::Sub<Position> for Position {
    type Output = usize;

    fn sub(self, base: Position) -> usize {
        self.0 - base.0
    }
}

impl core::ops::AddAssign<usize> for Position {
    fn add_assign(&mut self, delta: usize) {
        self.0 += delta;
    }
}

impl Position {
    /// Create a word position given its coordinates.
    ///
    /// The coordinates of a word are:
    /// - Its word index in its page.
    /// - Its page index in the storage.
    /// - The number of times that page was erased.
    pub fn new(format: &Format, cycle: usize, page: usize, word: usize) -> Position {
        Position((cycle * format.num_pages() + page) * format.virt_page_size() + word)
    }

    /// Accesses the underlying position as a natural number.
    pub fn get(self) -> usize {
        self.0
    }

    /// Returns the associated storage index.
    pub fn index(self, format: &Format) -> StorageIndex {
        let page = self.page(format);
        let word = CONTENT_WORD + self.word(format);
        let byte = word * format.word_size();
        StorageIndex { page, byte }
    }

    /// Returns the beginning of the current virtual page.
    pub fn page_begin(self, format: &Format) -> Position {
        let virt_page_size = format.virt_page_size();
        Position((self.0 / virt_page_size) * virt_page_size)
    }

    /// Returns the beginning of the next virtual page.
    pub fn next_page(self, format: &Format) -> Position {
        let virt_page_size = format.virt_page_size();
        Position((self.0 / virt_page_size + 1) * virt_page_size)
    }

    /// Returns the number of times the current page was erased.
    pub fn cycle(self, format: &Format) -> usize {
        (self.0 / format.virt_page_size()) / format.num_pages()
    }

    /// Returns the current page index.
    pub fn page(self, format: &Format) -> usize {
        (self.0 / format.virt_page_size()) % format.num_pages()
    }

    /// Returns the current word index in the page.
    pub fn word(self, format: &Format) -> usize {
        self.0 % format.virt_page_size()
    }
}

/// Possible states of some storage representation as a word.
pub enum WordState<T> {
    /// The word is still erased.
    Erased,

    /// The word is partially written.
    Partial,

    /// Holds the decoded version of a valid word.
    Valid(T),
}

/// Information for an initialized page.
pub struct InitInfo {
    /// The number of times this page has been erased.
    pub cycle: usize,

    /// The word index of the first entry in this virtual page.
    pub prefix: usize,
}

/// Information for a page being compacted.
pub struct CompactInfo {
    /// The distance in words between head and tail at compaction.
    pub tail: usize,
}

/// The first word of an entry.
#[derive(Debug)]
pub enum ParsedWord {
    /// Padding entry.
    Padding(Padding),

    /// Header of a user entry.
    Header(Header),

    /// Internal entry.
    Internal(InternalEntry),
}

/// Padding entry.
#[derive(Debug)]
pub struct Padding {
    /// The number of following padding words after the first word of the padding entry.
    pub length: usize,
}

/// Header of a user entry.
#[derive(Debug)]
pub struct Header {
    /// Whether the last bit of the user data is flipped.
    pub flipped: bool,

    /// The length in bytes of the user data.
    pub length: usize,

    /// The key of the user entry.
    pub key: usize,

    /// The checksum of the user entry.
    pub checksum: usize,
}

impl Header {
    /// Checks the validity of a user entry.
    ///
    /// If the user entry has no payload, the `footer` must be set to `None`. Otherwise it should be
    /// the last word of the entry.
    pub fn check(&self, footer: Option<&[u8]>) -> bool {
        footer.map_or(0, count_zeros) == self.checksum
    }
}

/// Internal entry.
#[derive(Debug)]
pub enum InternalEntry {
    /// Indicates that a page should be erased.
    Erase {
        /// The page to be erased.
        page: usize,
    },

    /// Indicates that user entries with high key should be deleted.
    Clear {
        /// The minimum key a user entry should have to be deleted.
        min_key: usize,
    },

    /// Marks the start of a transaction.
    ///
    /// The marker is followed by a given number of updates, which are either user entries or remove
    /// entries.
    Marker {
        /// The number of updates in the transaction.
        count: usize,
    },

    /// Indicates that a user entry should be removed.
    ///
    /// This is only useful (and valid) as part of a transaction, since removing a single entry is
    /// already atomic.
    Remove {
        /// The key of the user entry to be removed.
        key: usize,
    },
}

/// Returns whether a slice has all bits equal to one.
pub fn is_erased(slice: &[u8]) -> bool {
    slice.iter().all(|&x| x == 0xff)
}

/// Divides then takes ceiling.
///
/// Returns `ceil(x / m)` with mathematical notations. Assumes `x + m` does not overflow.
pub const fn div_ceil(x: usize, m: usize) -> usize {
    (x + m - 1) / m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_format() {
        assert_eq!(std::mem::size_of::<Format>(), 24);
    }

    #[test]
    fn checksum_ok() {
        let Field { pos, len } = WORD_CHECKSUM.field;
        // There is enough bits to represents the number of zeros preceding the checksum.
        assert_eq!(len, num_bits(pos));
        // The checksum is the last field of a word.
        assert_eq!(pos + len, 8 * WORD_SIZE);
        // The data of words using the checksum don't overlap the checksum.
        let words = &[
            &LEN_INIT,
            &LEN_COMPACT,
            &LEN_ERASE,
            &LEN_CLEAR,
            &LEN_MARKER,
            &LEN_REMOVE,
        ];
        for word in words {
            assert!(word.pos < pos);
        }
    }

    #[test]
    fn init_ok() {
        assert_eq!(INIT_CYCLE.pos, 0);
        assert_eq!(INIT_CYCLE.len, 16);
        assert_eq!(INIT_PREFIX.pos, 16);
        assert_eq!(INIT_PREFIX.len, 9);
        assert_eq!(LEN_INIT.pos, 25);
    }

    #[test]
    fn compact_ok() {
        assert_eq!(COMPACT_TAIL.pos, 0);
        assert_eq!(COMPACT_TAIL.len, 16);
        assert_eq!(LEN_COMPACT.pos, 16);
    }

    #[test]
    fn header_ok() {
        assert_eq!(ID_HEADER.field.pos, 0);
        assert_eq!(ID_HEADER.field.len, 2);
        assert_eq!(ID_HEADER.value, 0b01);
        assert_eq!(HEADER_DELETED.pos, 2);
        assert_eq!(HEADER_FLIPPED.pos, 3);
        assert_eq!(HEADER_LENGTH.pos, 4);
        assert_eq!(HEADER_LENGTH.len, 10);
        assert_eq!(HEADER_KEY.pos, 14);
        assert_eq!(HEADER_KEY.len, 12);
        assert_eq!(HEADER_CHECKSUM.field.pos, 26);
        assert_eq!(HEADER_CHECKSUM.field.len, 6);
        assert_eq!(LEN_HEADER.pos, 32);
    }

    #[test]
    fn erase_ok() {
        assert_eq!(ID_ERASE.field.pos, 0);
        assert_eq!(ID_ERASE.field.len, 5);
        assert_eq!(ID_ERASE.value, 0b00011);
        assert_eq!(ERASE_PAGE.pos, 5);
        assert_eq!(ERASE_PAGE.len, 6);
        assert_eq!(LEN_ERASE.pos, 11);
    }

    #[test]
    fn clear_ok() {
        assert_eq!(ID_CLEAR.field.pos, 0);
        assert_eq!(ID_CLEAR.field.len, 5);
        assert_eq!(ID_CLEAR.value, 0b10011);
        assert_eq!(CLEAR_MIN_KEY.pos, 5);
        assert_eq!(CLEAR_MIN_KEY.len, 12);
        assert_eq!(LEN_CLEAR.pos, 17);
    }

    #[test]
    fn marker_ok() {
        assert_eq!(ID_MARKER.field.pos, 0);
        assert_eq!(ID_MARKER.field.len, 5);
        assert_eq!(ID_MARKER.value, 0b01011);
        assert_eq!(MARKER_COUNT.pos, 5);
        assert_eq!(MARKER_COUNT.len, 5);
        assert_eq!(LEN_MARKER.pos, 10);
    }

    #[test]
    fn remove_ok() {
        assert_eq!(ID_REMOVE.field.pos, 0);
        assert_eq!(ID_REMOVE.field.len, 5);
        assert_eq!(ID_REMOVE.value, 0b11011);
        assert_eq!(REMOVE_KEY.pos, 5);
        assert_eq!(REMOVE_KEY.len, 12);
        assert_eq!(LEN_REMOVE.pos, 17);
    }

    #[test]
    fn is_erased_ok() {
        assert!(is_erased(&[]));
        assert!(is_erased(&[0xff]));
        assert!(is_erased(&[0xff, 0xff]));
        assert!(!is_erased(&[0x00]));
        assert!(!is_erased(&[0xff, 0xfe]));
        assert!(!is_erased(&[0x7f, 0xff]));
    }

    #[test]
    fn div_ceil_ok() {
        assert_eq!(div_ceil(0, 1), 0);
        assert_eq!(div_ceil(1, 1), 1);
        assert_eq!(div_ceil(2, 1), 2);
        assert_eq!(div_ceil(0, 2), 0);
        assert_eq!(div_ceil(1, 2), 1);
        assert_eq!(div_ceil(2, 2), 1);
        assert_eq!(div_ceil(3, 2), 2);
    }

    #[test]
    fn positions_fit_in_a_word() {
        // All reachable positions are smaller than this value, which is one past the last position.
        // It is simply the total number of virtual words, i.e. the number of words per virtual page
        // times the number of virtual pages times the number of times a virtual page can be used
        // (one more than the number of times it can be erased since we can write before the first
        // erase cycle and after the last erase cycle).
        assert_eq!(
            (MAX_ERASE_CYCLE + 1) * (MAX_PAGE_INDEX + 1) * MAX_VIRT_PAGE_SIZE,
            0xff800000
        );
    }
}
