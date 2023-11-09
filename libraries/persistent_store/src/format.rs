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

//! Storage representation of a store.

#[macro_use]
mod bitfield;

#[cfg(test)]
use self::bitfield::Length;
use self::bitfield::{count_zeros, num_bits, Bit, Checksum, ConstField, Field};
use crate::{usize_to_nat, Nat, Storage, StorageIndex, StoreError, StoreResult, StoreUpdate};
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::cmp::min;
use core::convert::TryFrom;

/// Internal representation of a word in flash.
///
/// Currently, the store only supports storages where a word is 32 bits, i.e. the [word
/// size](Storage::word_size) is 4 bytes.
type WORD = u32;

/// Abstract representation of a word in flash.
///
/// This type is kept abstract to avoid possible confusion with [`Nat`] if they happen to have the
/// same representation. This is because they have different semantics, [`Nat`] represents natural
/// numbers while `Word` represents sequences of bits (and thus has no arithmetic).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Word(WORD);

/// Byte slice representation of a word in flash.
///
/// The slice is in little-endian representation.
pub type WordSlice = [u8; core::mem::size_of::<WORD>()];

impl Word {
    /// Converts a byte slice into a word.
    ///
    /// # Panics
    ///
    /// Panics if `slice.len()` is not [`WORD_SIZE`] bytes.
    pub fn from_slice(slice: &[u8]) -> Word {
        Word(WORD::from_le_bytes(<WordSlice>::try_from(slice).unwrap()))
    }

    /// Converts a word into a byte slice.
    pub fn as_slice(self) -> WordSlice {
        self.0.to_le_bytes()
    }
}

/// Size of a word in bytes.
///
/// Currently, the store only supports storages where the [word size](Storage::word_size) is 4
/// bytes.
const WORD_SIZE: Nat = core::mem::size_of::<WORD>() as Nat;

/// Minimum number of words per page.
///
/// Currently, the store only supports storages where pages have at least 8 [words](WORD_SIZE), i.e.
/// the [page size](Storage::page_size) is at least 32 bytes.
const MIN_PAGE_SIZE: Nat = 8;

/// Maximum size of a page in bytes.
///
/// Currently, the store only supports storages where pages have at most 1024 [words](WORD_SIZE),
/// i.e. the [page size](Storage::page_size) is at most 4096 bytes.
const MAX_PAGE_SIZE: Nat = 4096;

/// Maximum number of erase cycles.
///
/// Currently, the store only supports storages where the [maximum number of erase
/// cycles](Storage::max_page_erases) fits in 16 bits, i.e. it is at most 65535.
const MAX_ERASE_CYCLE: Nat = 65535;

/// Minimum number of pages.
///
/// Currently, the store only supports storages where the [number of pages](Storage::num_pages) is
/// at least 3.
const MIN_NUM_PAGES: Nat = 3;

/// Maximum page index.
///
/// Currently, the store only supports storages where the [number of pages](Storage::num_pages) is
/// at most 64, i.e. the maximum page index is 63.
const MAX_PAGE_INDEX: Nat = 63;

/// Maximum key index.
///
/// Currently, the store only supports 4096 keys, i.e. the maximum key index is 4095.
const MAX_KEY_INDEX: Nat = 4095;

/// Maximum length in bytes of a user payload.
///
/// Currently, the store only supports values at most 1023 bytes long. This may be further reduced
/// depending on the [page size](Storage::page_size), see [`Format::max_value_len`].
const MAX_VALUE_LEN: Nat = 1023;

/// Maximum number of updates per transaction.
///
/// Currently, the store only supports transactions with at most 31 updates.
const MAX_UPDATES: Nat = 31;

/// Maximum number of words per virtual page.
///
/// A virtual page has [`CONTENT_WORD`] less [words](WORD_SIZE) than the storage [page
/// size](Storage::page_size). Those words are used to store the page header. Since a page has at
/// least [8](MIN_PAGE_SIZE) words, a virtual page has at least 6 words.
const MAX_VIRT_PAGE_SIZE: Nat = MAX_PAGE_SIZE / WORD_SIZE - CONTENT_WORD;

/// Word with all bits set to one.
///
/// After a page is erased, all words are equal to this value.
const ERASED_WORD: Word = Word(!(0 as WORD));

/// Helpers for a given storage configuration.
#[derive(Clone, Debug)]
pub struct Format {
    /// The size in bytes of a page in the storage.
    ///
    /// # Invariant
    ///
    /// - [Words](WORD_SIZE) divide a page evenly.
    /// - There are at least [`MIN_PAGE_SIZE`] words in a page.
    /// - There are at most [`MAX_PAGE_SIZE`] bytes in a page.
    page_size: Nat,

    /// The number of pages in the storage.
    ///
    /// # Invariant
    ///
    /// - There are at least [`MIN_NUM_PAGES`] pages.
    /// - There are at most [`MAX_PAGE_INDEX`] + 1 pages.
    num_pages: Nat,

    /// The maximum number of times a page can be erased.
    ///
    /// # Invariant
    ///
    /// - A page can be erased at most [`MAX_ERASE_CYCLE`] times.
    max_page_erases: Nat,
}

impl Format {
    /// Extracts the format from a storage.
    ///
    /// Returns `None` if the storage is not [supported](Format::is_storage_supported).
    pub fn new<S: Storage>(storage: &S) -> Option<Format> {
        if Format::is_storage_supported(storage) {
            Some(Format {
                page_size: usize_to_nat(storage.page_size()),
                num_pages: usize_to_nat(storage.num_pages()),
                max_page_erases: usize_to_nat(storage.max_page_erases()),
            })
        } else {
            None
        }
    }

    /// Returns whether a storage is supported.
    ///
    /// A storage is supported if the following conditions hold:
    /// - The [`Storage::word_size`] is [`WORD_SIZE`] bytes.
    /// - The [`Storage::word_size`] evenly divides the [`Storage::page_size`].
    /// - The [`Storage::page_size`] is between [`MIN_PAGE_SIZE`] words and [`MAX_PAGE_SIZE`] bytes.
    /// - The [`Storage::num_pages`] is between [`MIN_NUM_PAGES`] and [`MAX_PAGE_INDEX`] + 1.
    /// - The [`Storage::max_word_writes`] is at least 2.
    /// - The [`Storage::max_page_erases`] is at most [`MAX_ERASE_CYCLE`].
    fn is_storage_supported<S: Storage>(storage: &S) -> bool {
        let word_size = usize_to_nat(storage.word_size());
        let page_size = usize_to_nat(storage.page_size());
        let num_pages = usize_to_nat(storage.num_pages());
        let max_word_writes = usize_to_nat(storage.max_word_writes());
        let max_page_erases = usize_to_nat(storage.max_page_erases());
        word_size == WORD_SIZE
            && page_size % word_size == 0
            && (MIN_PAGE_SIZE * word_size <= page_size && page_size <= MAX_PAGE_SIZE)
            && (MIN_NUM_PAGES..=MAX_PAGE_INDEX + 1).contains(&num_pages)
            && max_word_writes >= 2
            && max_page_erases <= MAX_ERASE_CYCLE
    }

    /// The size of a word in bytes.
    pub fn word_size(&self) -> Nat {
        WORD_SIZE
    }

    /// The size of a page in bytes.
    ///
    /// This is at least [`MIN_PAGE_SIZE`] [words](WORD_SIZE) and at most [`MAX_PAGE_SIZE`] bytes.
    pub fn page_size(&self) -> Nat {
        self.page_size
    }

    /// The number of pages in the storage, denoted by N.
    ///
    /// We have [`MIN_NUM_PAGES`] ≤ N ≤ [`MAX_PAGE_INDEX`] + 1.
    pub fn num_pages(&self) -> Nat {
        self.num_pages
    }

    /// The maximum page index.
    ///
    /// This is at least [`MIN_NUM_PAGES`] - 1 and at most [`MAX_PAGE_INDEX`].
    pub fn max_page(&self) -> Nat {
        self.num_pages - 1
    }

    /// The maximum number of times a page can be erased, denoted by E.
    ///
    /// We have E ≤ [`MAX_ERASE_CYCLE`].
    pub fn max_page_erases(&self) -> Nat {
        self.max_page_erases
    }

    /// The maximum key.
    pub fn max_key(&self) -> Nat {
        MAX_KEY_INDEX
    }

    /// The maximum number of updates per transaction.
    pub fn max_updates(&self) -> Nat {
        MAX_UPDATES
    }

    /// The size of a virtual page in words, denoted by Q.
    ///
    /// A virtual page is stored in a physical page after the page header.
    ///
    /// We have [`MIN_PAGE_SIZE`] - 2 ≤ Q ≤ [`MAX_VIRT_PAGE_SIZE`].
    pub fn virt_page_size(&self) -> Nat {
        self.page_size() / self.word_size() - CONTENT_WORD
    }

    /// The maximum length in bytes of a user payload.
    ///
    /// This is at least [`MIN_PAGE_SIZE`] - 3 [words](WORD_SIZE) and at most [`MAX_VALUE_LEN`].
    pub fn max_value_len(&self) -> Nat {
        min(
            (self.virt_page_size() - 1) * self.word_size(),
            MAX_VALUE_LEN,
        )
    }

    /// The maximum prefix length in words, denoted by M.
    ///
    /// A prefix is the first words of a virtual page that belong to the last entry of the previous
    /// virtual page. This happens because entries may overlap up to 2 virtual pages.
    ///
    /// We have [`MIN_PAGE_SIZE`] - 3 ≤ M < Q.
    pub fn max_prefix_len(&self) -> Nat {
        self.bytes_to_words(self.max_value_len())
    }

    /// The virtual window size in words, denoted by W.
    ///
    /// This is the span of virtual storage that is accessible. In particular, all store content
    /// fits within this window.
    ///
    /// We have W = (N - 1) × Q - M.
    pub fn window_size(&self) -> Nat {
        (self.num_pages() - 1) * self.virt_page_size() - self.max_prefix_len()
    }

    /// The total virtual capacity in words, denoted by V.
    ///
    /// This is the span of virtual storage after which we trigger a compaction. This is smaller
    /// than the virtual window because compaction may transiently overflow out of this virtual
    /// capacity.
    ///
    /// We have V = W - (N - 1) = (N - 1) × (Q - 1) - M.
    pub fn virt_size(&self) -> Nat {
        (self.num_pages() - 1) * (self.virt_page_size() - 1) - self.max_prefix_len()
    }

    /// The total user capacity in words, denoted by C.
    ///
    /// We have C = V - N = (N - 1) × (Q - 2) - M - 1.
    ///
    /// We can show C ≥ (N - 2) × (Q - 2) - 2 with the following steps:
    /// - M ≤ Q - 1 from M < Q from [M](Format::max_prefix_len)'s definition
    /// - C ≥ (N - 1) × (Q - 2) - (Q - 1) - 1 from C's definition
    /// - C ≥ (N - 2) × (Q - 2) - 2 by calculus
    pub fn total_capacity(&self) -> Nat {
        // From the virtual capacity, we reserve N - 1 words for `Erase` entries and 1 word for a
        // `Clear` entry.
        self.virt_size() - self.num_pages()
    }

    /// The total virtual lifetime in words, denoted by L.
    ///
    /// We have L = (E × N + N - 1) × Q.
    pub fn total_lifetime(&self) -> Position {
        Position::new(self, self.max_page_erases(), self.num_pages() - 1, 0)
    }

    /// Returns the word position of the first entry of a page.
    pub fn page_head(&self, init: InitInfo, page: Nat) -> Position {
        Position::new(self, init.cycle, page, init.prefix)
    }

    /// Returns the storage index of the init info of a page.
    pub fn index_init(&self, page: Nat) -> StorageIndex {
        let byte = INIT_WORD * self.word_size();
        StorageIndex {
            page: page as usize,
            byte: byte as usize,
        }
    }

    /// Parses the init info of a page from its storage representation.
    pub fn parse_init(&self, word: Word) -> StoreResult<WordState<InitInfo>> {
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
    pub fn build_init(&self, init: InitInfo) -> StoreResult<WordSlice> {
        let mut word = ERASED_WORD;
        INIT_CYCLE.set(&mut word, init.cycle)?;
        INIT_PREFIX.set(&mut word, init.prefix)?;
        WORD_CHECKSUM.set(&mut word, 0)?;
        Ok(word.as_slice())
    }

    /// Returns the storage index of the compact info of a page.
    pub fn index_compact(&self, page: Nat) -> StorageIndex {
        let byte = COMPACT_WORD * self.word_size();
        StorageIndex {
            page: page as usize,
            byte: byte as usize,
        }
    }

    /// Parses the compact info of a page from its storage representation.
    pub fn parse_compact(&self, word: Word) -> StoreResult<WordState<CompactInfo>> {
        Ok(if word == ERASED_WORD {
            WordState::Erased
        } else if WORD_CHECKSUM.get(word)? != 0 {
            WordState::Partial
        } else {
            let tail = COMPACT_TAIL.get(word);
            if tail > self.window_size() {
                return Err(StoreError::InvalidStorage);
            }
            WordState::Valid(CompactInfo { tail })
        })
    }

    /// Builds the storage representation of a compact info.
    pub fn build_compact(&self, compact: CompactInfo) -> StoreResult<WordSlice> {
        let mut word = ERASED_WORD;
        COMPACT_TAIL.set(&mut word, compact.tail)?;
        WORD_CHECKSUM.set(&mut word, 0)?;
        Ok(word.as_slice())
    }

    /// Builds the storage representation of an internal entry.
    pub fn build_internal(&self, internal: InternalEntry) -> StoreResult<WordSlice> {
        let mut word = ERASED_WORD;
        match internal {
            InternalEntry::Erase { page } => {
                ID_ERASE.set(&mut word)?;
                ERASE_PAGE.set(&mut word, page)?;
            }
            InternalEntry::Clear { min_key } => {
                ID_CLEAR.set(&mut word)?;
                CLEAR_MIN_KEY.set(&mut word, min_key)?;
            }
            InternalEntry::Marker { count } => {
                ID_MARKER.set(&mut word)?;
                MARKER_COUNT.set(&mut word, count)?;
            }
            InternalEntry::Remove { key } => {
                ID_REMOVE.set(&mut word)?;
                REMOVE_KEY.set(&mut word, key)?;
            }
        }
        WORD_CHECKSUM.set(&mut word, 0)?;
        Ok(word.as_slice())
    }

    /// Parses the first word of an entry from its storage representation.
    pub fn parse_word(&self, word: Word) -> StoreResult<WordState<ParsedWord>> {
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
    pub fn build_user(&self, key: Nat, value: &[u8]) -> StoreResult<Vec<u8>> {
        let length = usize_to_nat(value.len());
        let word_size = self.word_size();
        let footer = self.bytes_to_words(length);
        let mut result = vec![0xff; ((1 + footer) * word_size) as usize];
        result[word_size as usize..][..length as usize].copy_from_slice(value);
        let mut word = ERASED_WORD;
        ID_HEADER.set(&mut word)?;
        if footer > 0 && is_erased(&result[(footer * word_size) as usize..]) {
            HEADER_FLIPPED.set(&mut word);
            *result.last_mut().unwrap() = 0x7f;
        }
        HEADER_LENGTH.set(&mut word, length)?;
        HEADER_KEY.set(&mut word, key)?;
        HEADER_CHECKSUM.set(
            &mut word,
            count_zeros(&result[(footer * word_size) as usize..]),
        )?;
        result[..word_size as usize].copy_from_slice(&word.as_slice());
        Ok(result)
    }

    /// Sets the padding bit in the first word of a user entry.
    pub fn set_padding(&self, word: &mut Word) -> StoreResult<()> {
        ID_PADDING.set(word)
    }

    /// Sets the deleted bit in the first word of a user entry.
    pub fn set_deleted(&self, word: &mut Word) {
        HEADER_DELETED.set(word);
    }

    /// Returns the capacity required by a transaction.
    pub fn transaction_capacity<ByteSlice: Borrow<[u8]>>(
        &self,
        updates: &[StoreUpdate<ByteSlice>],
    ) -> Nat {
        match updates.len() {
            // An empty transaction doesn't consume anything.
            0 => 0,
            // Transactions with a single update are optimized by avoiding a marker entry.
            1 => match &updates[0] {
                StoreUpdate::Insert { value, .. } => self.entry_size(value.borrow()),
                // Transactions with a single update which is a removal don't consume anything.
                StoreUpdate::Remove { .. } => 0,
            },
            // A transaction consumes one word for the marker entry in addition to its updates.
            _ => 1 + updates.iter().map(|x| self.update_capacity(x)).sum::<Nat>(),
        }
    }

    /// Returns the capacity of an update.
    fn update_capacity<ByteSlice: Borrow<[u8]>>(&self, update: &StoreUpdate<ByteSlice>) -> Nat {
        match update {
            StoreUpdate::Insert { value, .. } => self.entry_size(value.borrow()),
            StoreUpdate::Remove { .. } => 1,
        }
    }

    /// Returns the size of a user entry given its value.
    pub fn entry_size(&self, value: &[u8]) -> Nat {
        1 + self.bytes_to_words(usize_to_nat(value.len()))
    }

    /// Checks if a transaction is valid and returns its sorted keys.
    ///
    /// Returns `None` if the transaction is invalid.
    pub fn transaction_valid<ByteSlice: Borrow<[u8]>>(
        &self,
        updates: &[StoreUpdate<ByteSlice>],
    ) -> Option<Vec<Nat>> {
        if usize_to_nat(updates.len()) > self.max_updates() {
            return None;
        }
        let mut sorted_keys = Vec::with_capacity(updates.len());
        for update in updates {
            let key = usize_to_nat(update.key());
            if key > self.max_key() {
                return None;
            }
            if let Some(value) = update.value() {
                if usize_to_nat(value.len()) > self.max_value_len() {
                    return None;
                }
            }
            match sorted_keys.binary_search(&key) {
                Ok(_) => return None,
                Err(pos) => sorted_keys.insert(pos, key),
            }
        }
        Some(sorted_keys)
    }

    /// Returns the minimum number of words to represent a given number of bytes.
    ///
    /// # Preconditions
    ///
    /// - `bytes` + [`Self::word_size`] does not overflow.
    pub fn bytes_to_words(&self, bytes: Nat) -> Nat {
        div_ceil(bytes, self.word_size())
    }
}

/// The word index of the init info in a page.
const INIT_WORD: Nat = 0;

/// The word index of the compact info in a page.
const COMPACT_WORD: Nat = 1;

/// The word index of the content of a page.
///
/// This is also the length in words of the page header.
const CONTENT_WORD: Nat = 2;

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
/// With the notations defined in [`Format`], let:
/// - w denote a word offset in a virtual page, thus between 0 and Q - 1
/// - p denote a page offset, thus between 0 and N - 1
/// - c denote the number of times a page was erased, thus between 0 and E
///
/// The position of a word is (c × N + p) × Q + w. This position monotonically increases and
/// represents the consumed lifetime of the storage.
///
/// This type is kept abstract to avoid possible confusion with [`Nat`] and [`Word`] if they happen
/// to have the same representation. Here is an overview of their semantics:
///
/// | Name       | Semantics                   | Arithmetic operations | Bit-wise operations |
/// | ---------- | --------------------------- | --------------------- | ------------------- |
/// | [`Nat`]    | Natural numbers             | Yes (no overflow)     | No                  |
/// | [`Word`]   | Word in flash               | No                    | Yes                 |
/// | `Position` | Position in virtual storage | Yes (no overflow)     | No                  |
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position(Nat);

impl core::ops::Add<Nat> for Position {
    type Output = Position;

    fn add(self, delta: Nat) -> Position {
        Position(self.0 + delta)
    }
}

impl core::ops::Sub<Position> for Position {
    type Output = Nat;

    fn sub(self, base: Position) -> Nat {
        self.0 - base.0
    }
}

impl core::ops::AddAssign<Nat> for Position {
    fn add_assign(&mut self, delta: Nat) {
        self.0 += delta;
    }
}

impl Position {
    /// Create a word position given its coordinates.
    ///
    /// The coordinates of a word are:
    /// - Its word index in its virtual page.
    /// - Its page index in the storage.
    /// - The number of times its page was erased.
    pub fn new(format: &Format, cycle: Nat, page: Nat, word: Nat) -> Position {
        Position((cycle * format.num_pages() + page) * format.virt_page_size() + word)
    }

    /// Accesses the underlying position as a natural number.
    pub fn get(self) -> Nat {
        self.0
    }

    /// Returns the associated storage index.
    pub fn index(self, format: &Format) -> StorageIndex {
        let page = self.page(format);
        let word = CONTENT_WORD + self.word(format);
        let byte = word * format.word_size();
        StorageIndex {
            page: page as usize,
            byte: byte as usize,
        }
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
    pub fn cycle(self, format: &Format) -> Nat {
        (self.0 / format.virt_page_size()) / format.num_pages()
    }

    /// Returns the current page index.
    pub fn page(self, format: &Format) -> Nat {
        (self.0 / format.virt_page_size()) % format.num_pages()
    }

    /// Returns the current word index in the page.
    pub fn word(self, format: &Format) -> Nat {
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
    pub cycle: Nat,

    /// The word index of the first entry in this virtual page.
    pub prefix: Nat,
}

/// Information for a page being compacted.
pub struct CompactInfo {
    /// The distance in words between head and tail at compaction.
    pub tail: Nat,
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
    pub length: Nat,
}

/// Header of a user entry.
#[derive(Debug)]
pub struct Header {
    /// Whether the last bit of the user data is flipped.
    pub flipped: bool,

    /// The length in bytes of the user data.
    pub length: Nat,

    /// The key of the user entry.
    pub key: Nat,

    /// The checksum of the user entry.
    pub checksum: Nat,
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
        page: Nat,
    },

    /// Indicates that user entries with high key should be deleted.
    Clear {
        /// The minimum key a user entry should have to be deleted.
        min_key: Nat,
    },

    /// Marks the start of a transaction.
    ///
    /// The marker is followed by a given number of updates, which are either user entries or remove
    /// entries.
    Marker {
        /// The number of updates in the transaction.
        count: Nat,
    },

    /// Indicates that a user entry should be removed.
    ///
    /// This is only useful (and valid) as part of a transaction, since removing a single entry is
    /// already atomic.
    Remove {
        /// The key of the user entry to be removed.
        key: Nat,
    },
}

/// Returns whether a slice has all bits equal to one.
pub fn is_erased(slice: &[u8]) -> bool {
    slice.iter().all(|&x| x == 0xff)
}

/// Divides then takes ceiling.
///
/// Returns ⌈x / m⌉, i.e. the lowest natural number r such that r ≥ x / m.
///
/// # Preconditions
///
/// - x + m does not overflow.
const fn div_ceil(x: Nat, m: Nat) -> Nat {
    (x + m - 1) / m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_format() {
        assert_eq!(std::mem::size_of::<Format>(), 12);
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
    fn word_from_slice_ok() {
        assert_eq!(
            Word::from_slice(&[0x04, 0x03, 0x02, 0x01]),
            Word(0x01020304)
        );
        assert_eq!(
            Word::from_slice(&[0x1e, 0x3c, 0x78, 0xf0]),
            Word(0xf0783c1e)
        );
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

    #[test]
    fn position_offsets_fit_in_a_halfword() {
        // The store stores in RAM the entry positions as their offset from the head. Those offsets
        // are represented as u16. The bound below is a large over-approximation of the maximal
        // offset. We first make sure it fits in a u16.
        const MAX_POS: Nat = (MAX_PAGE_INDEX + 1) * MAX_VIRT_PAGE_SIZE;
        assert!(MAX_POS <= u16::MAX as Nat);
        // We also check the actual value for up-to-date documentation, since it's a constant.
        assert_eq!(MAX_POS, 0xff80);
    }
}
