// Copyright 2019-2021 Google LLC
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

// The documentation is easier to read from a browser:
// - Run: cargo doc --document-private-items --features=std
// - Open: target/doc/persistent_store/index.html

//! Store abstraction for flash storage
//!
//! # Specification
//!
//! The [store](Store) provides a partial function from keys to values on top of a
//! [storage](Storage) interface. The store total [capacity](Store::capacity) depends on the size of
//! the storage. Store [updates](StoreUpdate) may be bundled in [transactions](Store::transaction).
//! Mutable operations are atomic, including when interrupted.
//!
//! The store is flash-efficient in the sense that it uses the storage [lifetime](Store::lifetime)
//! efficiently. For each page, all words are written at least once between erase cycles and all
//! erase cycles are used. However, not all written words are user content: Lifetime is also
//! consumed with metadata and compaction.
//!
//! The store is extendable with other entries than key-values. It is essentially a framework
//! providing access to the storage lifetime. The partial function is simply the most common usage
//! and can be used to encode other usages.
//!
//! ## Definitions
//!
//! An _entry_ is a pair of a key and a value. A _key_ is a number between 0 and
//! [4095](format::MAX_KEY_INDEX). A _value_ is a byte slice with a length between 0 and
//! [1023](format::Format::max_value_len) bytes (for large enough pages).
//!
//! The store provides the following _updates_:
//! -   Given a key and a value, [`StoreUpdate::Insert`] updates the store such that the value is
//!     associated with the key. The values for other keys are left unchanged.
//! -   Given a key, [`StoreUpdate::Remove`] updates the store such that no value is associated with
//!     the key. The values for other keys are left unchanged. Additionally, if there was a value
//!     associated with the key, the value is wiped from the storage (all its bits are set to 0).
//!
//! The store provides the following _read-only operations_:
//! -   [`Store::iter`] iterates through the store returning all entries exactly once. The iteration
//!     order is not specified but stable between mutable operations.
//! -   [`Store::capacity`] returns how many words can be stored before the store is full.
//! -   [`Store::lifetime`] returns how many words can be written before the storage lifetime is
//!     consumed.
//!
//! The store provides the following _mutable operations_:
//! -   Given a set of independent updates, [`Store::transaction`] applies the sequence of updates.
//! -   Given a threshold, [`Store::clear`] removes all entries with a key greater or equal to the
//!     threshold.
//! -   Given a length in words, [`Store::prepare`] makes one step of compaction unless that many
//!     words can be written without compaction. This operation has no effect on the store but may
//!     still mutate its storage. In particular, the store has the same capacity but a possibly
//!     reduced lifetime.
//!
//! A mutable operation is _atomic_ if, when power is lost during the operation, the store is either
//! updated (as if the operation succeeded) or left unchanged (as if the operation did not occur).
//! If the store is left unchanged, lifetime may still be consumed.
//!
//! The store relies on the following _storage interface_:
//! -   It is possible to [read](Storage::read_slice) a byte slice. The slice won't span multiple
//!     pages.
//! -   It is possible to [write](Storage::write_slice) a word slice. The slice won't span multiple
//!     pages.
//! -   It is possible to [erase](Storage::erase_page) a page.
//! -   The pages are sequentially indexed from 0. If the actual underlying storage is segmented,
//!     then the storage layer should translate those indices to actual page addresses.
//!
//! The store has a _total capacity_ of C = (N - 1) × (P - 4) - M - 1 words, where:
//! -   P is the number of words per page
//! -   [N](format::Format::num_pages) is the number of pages
//! -   [M](format::Format::max_prefix_len) is the maximum length in words of a value (256 for large
//!     enough pages)
//!
//! The capacity used by each mutable operation is given below (a transient word only uses capacity
//! during the operation):
//!
//! | Operation/Update        | Used capacity    | Freed capacity    | Transient capacity |
//! | ----------------------- | ---------------- | ----------------- | ------------------ |
//! | [`StoreUpdate::Insert`] | 1 + value length | overwritten entry | 0                  |
//! | [`StoreUpdate::Remove`] | 0                | deleted entry     | see below\*        |
//! | [`Store::transaction`]  | 0 + updates      | 0 + updates       | 1                  |
//! | [`Store::clear`]        | 0                | deleted entries   | 0                  |
//! | [`Store::prepare`]      | 0                | 0                 | 0                  |
//!
//! \*0 if the update is alone in the transaction, otherwise 1.
//!
//! The _total lifetime_ of the store is below L = ((E + 1) × N - 1) × (P - 2) and above L - M
//! words, where E is the maximum number of erase cycles. The lifetime is used when capacity is
//! used, including transiently, as well as when compaction occurs. Compaction frequency and
//! lifetime consumption are positively correlated to the store load factor (the ratio of used
//! capacity to total capacity).
//!
//! It is possible to approximate the cost of transient words in terms of capacity: L transient
//! words are equivalent to C - x words of capacity where x is the average capacity (including
//! transient) of operations.
//!
//! ## Preconditions
//!
//! The following assumptions need to hold, or the store may behave in unexpected ways:
//! -   A word can be written [twice](Storage::max_word_writes) between erase cycles.
//! -   A page can be erased [E](Storage::max_page_erases) times after the first boot of the store.
//! -   When power is lost while writing a slice or erasing a page, the next read returns a slice
//!     where a subset (possibly none or all) of the bits that should have been modified have been
//!     modified.
//! -   Reading a slice is deterministic. When power is lost while writing a slice or erasing a
//!     slice (erasing a page containing that slice), reading that slice repeatedly returns the same
//!     result (until it is overwritten or its page is erased).
//! -   To decide whether a page has been erased, it is enough to test if all its bits are equal
//!     to 1.
//! -   When power is lost while writing a slice or erasing a page, that operation does not count
//!     towards the limits. However, completing that write or erase operation would count towards
//!     the limits, as if the number of writes per word and number of erase cycles could be
//!     fractional.
//! -   The storage is only modified by the store. Note that completely erasing the storage is
//!     supported, essentially losing all content and lifetime tracking. It is preferred to use
//!     [`Store::clear`] with a threshold of 0 to keep the lifetime tracking.
//!
//! The store properties may still hold outside some of those assumptions, but with an increasing
//! chance of failure.
//!
//! # Implementation
//!
//! We define the following constants:
//! -   [E](format::Format::max_page_erases) ≤ [65535](format::MAX_ERASE_CYCLE) the number of times
//!     a page can be erased.
//! -   3 ≤ [N](format::Format::num_pages) < 64 the number of pages in the storage.
//! -   8 ≤ P ≤ 1024 the number of words in a page.
//! -   [Q](format::Format::virt_page_size) = P - 2 the number of words in a virtual page.
//! -   [M](format::Format::max_prefix_len) = min(Q - 1, 256) the maximum length in words of a
//!     value.
//! -   [V](format::Format::virt_size) = (N - 1) × (Q - 1) - M the virtual capacity.
//! -   [C](format::Format::total_capacity) = V - N the user capacity.
//!
//! We build a virtual storage from the physical storage using the first 2 words of each page:
//! -   The first word contains the number of times the page has been erased.
//! -   The second word contains the starting word to which this page is being moved during
//!     compaction.
//!
//! The virtual storage has a length of (E + 1) × N × Q words and represents the lifetime of the
//! store. (We reserve the last Q + M words to support adding emergency lifetime.) This virtual
//! storage has a linear address space.
//!
//! We define a set of overlapping windows of N × Q words at each Q-aligned boundary. We call i the
//! window spanning from i × Q to (i + N) × Q. Only those windows actually exist in the underlying
//! storage. We use compaction to shift the current window from i to i + 1, preserving the content
//! of the store.
//!
//! For a given state of the virtual storage, we define h\_i as the position of the first entry of
//! the window i. We call it the head of the window i. Because entries are at most M + 1 words, they
//! can overlap on the next page only by M words. So we have i × Q ≤ h_i ≤ i × Q + M . Since there
//! are no entries before the first page, we have h\_0 = 0.
//!
//! We define t\_i as one past the last entry of the window i. If there are no entries in that
//! window, we have t\_i = h\_i. We call t\_i the tail of the window i. We define the compaction
//! invariant as t\_i - h\_i ≤ V.
//!
//! We define |x| as the capacity used before position x. We have |x| ≤ x. We define the capacity
//! invariant as |t\_i| - |h\_i| ≤ C.
//!
//! Using this virtual storage, entries are appended to the tail as long as there is both virtual
//! capacity to preserve the compaction invariant and capacity to preserve the capacity invariant.
//! When virtual capacity runs out, the first page of the window is compacted and the window is
//! shifted.
//!
//! Entries are identified by a prefix of bits. The prefix has to contain at least one bit set to
//! zero to differentiate from the tail. Entries can be one of:
//! -   [Padding](format::ID_PADDING): A word whose first bit is set to zero. The rest is arbitrary.
//!     This entry is used to mark words partially written after an interrupted operation as padding
//!     such that they are ignored by future operations.
//! -   [Header](format::ID_HEADER): A word whose second bit is set to zero. It contains the
//!     following fields:
//!     -   A [bit](format::HEADER_DELETED) indicating whether the entry is deleted.
//!     -   A [bit](format::HEADER_FLIPPED) indicating whether the value is word-aligned and has all
//!         bits set to 1 in its last word. The last word of an entry is used to detect that an
//!         entry has been fully written. As such it must contain at least one bit equal to zero.
//!     -   The [key](format::HEADER_KEY) of the entry.
//!     -   The [length](format::HEADER_LENGTH) in bytes of the value. The value follows the header.
//!         The entry is word-aligned if the value is not.
//!     -   The [checksum](format::HEADER_CHECKSUM) of the first and last word of the entry.
//! -   [Erase](format::ID_ERASE): A word used during compaction. It contains the
//!     [page](format::ERASE_PAGE) to be erased and a [checksum](format::WORD_CHECKSUM).
//! -   [Clear](format::ID_CLEAR): A word used during the clear operation. It contains the
//!     [threshold](format::CLEAR_MIN_KEY) and a [checksum](format::WORD_CHECKSUM).
//! -   [Marker](format::ID_MARKER): A word used during a transaction. It contains the [number of
//!     updates](format::MARKER_COUNT) following the marker and a [checksum](format::WORD_CHECKSUM).
//! -   [Remove](format::ID_REMOVE): A word used inside a transaction. It contains the
//!     [key](format::REMOVE_KEY) of the entry to be removed and a
//!     [checksum](format::WORD_CHECKSUM).
//!
//! Checksums are the number of bits equal to 0.
//!
//! # Proofs
//!
//! ## Compaction
//!
//! It should always be possible to fully compact the store, after what the remaining capacity
//! should be available in the current window (restoring the compaction invariant). We consider all
//! notations on the virtual storage after the full compaction. We will use the |x| notation
//! although we update the state of the virtual storage. This is fine because compaction doesn't
//! change the status of an existing word.
//!
//! We want to show that the next N - 1 compactions won't move the tail past the last page of their
//! window, with I the initial window:
//!
//! |                  |            |   |                     |
//! | ----------------:| ----------:|:-:|:------------------- |
//! | ∀(1 ≤ i ≤ N - 1) | t\_{I + i} | ≤ | (I + i + N - 1) × Q |
//!
//! We assume i between 1 and N - 1.
//!
//! One step of compaction advances the tail by how many words were used in the first page of the
//! window with the last entry possibly overlapping on the next page.
//!
//! |    |            |   |                                      |
//! | --:| ----------:|:-:|:------------------------------------ |
//! | ∀j | t\_{j + 1} | = | t\_j + \|h\_{j + 1}\| - \|h\_j\| + 1 |
//!
//! By induction, we have:
//!
//! |            |   |                                      |
//! | ----------:|:-:|:------------------------------------ |
//! | t\_{I + i} | ≤ | t\_I + \|h\_{I + i}\| - \|h\_I\| + i |
//!
//! We have the following properties:
//!
//! |                           |   |                   |
//! | -------------------------:|:-:|:----------------- |
//! | t\_I                      | ≤ | h\_I + V          |
//! | \|h\_{I + i}\| - \|h\_I\| | ≤ | h\_{I + i} - h\_I |
//! | h\_{I + i}                | ≤ | (I + i) × Q + M   |
//!
//! Replacing into our previous equality, we can conclude:
//!
//! |            |   |                                             |
//! | ----------:|:-:| ------------------------------------------- |
//! | t\_{I + i} | = | t_I + \|h_{I + i}\| - \|h_I\| + i           |
//! |            | ≤ | h\_I + V + (I + i) * Q + M - h\_I + i       |
//! |            | = | (N - 1) × (Q - 1) - M + (I + i) × Q + M + i |
//! |            | = | (N - 1) × (Q - 1) + (I + i) × Q + i         |
//! |            | = | (I + i + N - 1) × Q + i - (N - 1)           |
//! |            | ≤ | (I + i + N - 1) × Q                         |
//!
//! We also want to show that after N - 1 compactions, the remaining capacity is available without
//! compaction.
//!
//! |   |                                               |                                   |
//! | -:| --------------------------------------------- | --------------------------------- |
//! |   | V - (t\_{I + N - 1} - h\_{I + N - 1})         | The available words in the window |
//! | ≥ | C - (\|t\_{I + N - 1}\| - \|h\_{I + N - 1}\|) | The remaining capacity            |
//! | + | 1                                             | Reserved for clear                |
//!
//! We can replace the definition of C and simplify:
//!
//! |     |                                       |   |                                                       |
//! | ---:| -------------------------------------:|:-:|:----------------------------------------------------- |
//! |     | V - (t\_{I + N - 1} - h\_{I + N - 1}) | ≥ | V - N - (\|t\_{I + N - 1}\| - \|h\_{I + N - 1}\|) + 1 |
//! | iff | t\_{I + N - 1} - h\_{I + N - 1}       | ≤ | \|t\_{I + N - 1}\| - \|h\_{I + N - 1}\| + N - 1       |
//!
//! We have the following properties:
//!
//!
//! |                                         |   |                                              |        |
//! | ---------------------------------------:|:-:|:-------------------------------------------- |:------ |
//! | t\_{I + N - 1}                          | = | t\_I + \|h\_{I + N - 1}\| - \|h\_I\| + N - 1 |        |
//! | \|t\_{I + N - 1}\| - \|h\_{I + N - 1}\| | = | \|t\_I\| - \|h\_I\|   | Compaction preserves capacity |
//! | \|h\_{I + N - 1}\| - \|t\_I\|           | ≤ | h\_{I + N - 1} - t\_I |                               |
//!
//! From which we conclude:
//!
//! |     |                                 |   |                                                 |
//! | ---:| -------------------------------:|:-:|:----------------------------------------------- |
//! |     | t\_{I + N - 1} - h\_{I + N - 1} | ≤ | \|t\_{I + N - 1}\| - \|h\_{I + N - 1}\| + N - 1 |
//! | iff | t\_I + \|h\_{I + N - 1}\| - \|h\_I\| + N - 1 - h\_{I + N - 1} | ≤ | \|t\_I\| - \|h\_I\| + N - 1 |
//! | iff | t\_I + \|h\_{I + N - 1}\| - h\_{I + N - 1}                    | ≤ | \|t\_I\| |
//! | iff | \|h\_{I + N - 1}\| - \|t\_I\|                                 | ≤ | h\_{I + N - 1} - t\_I |
//!
//!
//! ## Checksum
//!
//! The main property we want is that all partially written/erased words are either the initial
//! word, the final word, or invalid.
//!
//! We say that a bit sequence `TARGET` is reachable from a bit sequence `SOURCE` if both have the
//! same length and `SOURCE & TARGET == TARGET` where `&` is the bitwise AND operation on bit
//! sequences of that length. In other words, when `SOURCE` has a bit equal to 0 then `TARGET` also
//! has that bit equal to 0.
//!
//! The only written entries start with `101` or `110` and are written from an erased word. Marking
//! an entry as padding or deleted is a single bit operation, so the property trivially holds. For
//! those cases, the proof relies on the fact that there is exactly one bit equal to 0 in the 3
//! first bits. Either the 3 first bits are still `111` in which case we expect the remaining bits
//! to be equal to 1. Otherwise we can use the checksum of the given type of entry because those 2
//! types of entries are not reachable from each other. Here is a visualization of the partitioning
//! based on the first 3 bits:
//!
//! | First 3 bits | Description        | How to check                 |
//! | ------------:| ------------------ | ---------------------------- |
//! | `111`        | Erased word        | All bits set to `1`          |
//! | `101`        | User entry         | Contains a checksum          |
//! | `110`        | Internal entry     | Contains a checksum          |
//! | `100`        | Deleted user entry | No check, atomically written |
//! | `0??`        | Padding entry      | No check, atomically written |
//!
//! To show that valid entries of a given type are not reachable from each other, we show 3 lemmas:
//!
//! 1.  A bit sequence is not reachable from another if its number of bits equal to 0 is smaller.
//! 2.  A bit sequence is not reachable from another if they have the same number of bits equals to
//!     0 and are different.
//! 3.  A bit sequence is not reachable from another if it is bigger when they are interpreted as
//!     numbers in binary representation.
//!
//! From those lemmas we consider the 2 cases. If both entries have the same number of bits equal to
//! 0, they are either equal or not reachable from each other because of the second lemma. If they
//! don't have the same number of bits equal to 0, then the one with less bits equal to 0 is not
//! reachable from the other because of the first lemma and the one with more bits equal to 0 is not
//! reachable from the other because of the third lemma and the definition of the checksum.
//!
//! # Fuzzing
//!
//! For any sequence of operations and interruptions starting from an erased storage, the store is
//! checked against its model and some internal invariant at each step.
//!
//! For any sequence of operations and interruptions starting from an arbitrary storage, the store
//! is checked not to crash.

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(try_trait)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
mod buffer;
#[cfg(feature = "std")]
mod driver;
mod format;
pub mod fragment;
#[cfg(feature = "std")]
mod model;
mod storage;
mod store;
#[cfg(test)]
mod test;

#[cfg(feature = "std")]
pub use self::buffer::{BufferCorruptFunction, BufferOptions, BufferStorage};
#[cfg(feature = "std")]
pub use self::driver::{
    StoreDriver, StoreDriverOff, StoreDriverOn, StoreInterruption, StoreInvariant,
};
#[cfg(feature = "std")]
pub use self::model::{StoreModel, StoreOperation};
pub use self::storage::{Storage, StorageError, StorageIndex, StorageResult};
pub use self::store::{
    Store, StoreError, StoreHandle, StoreIter, StoreRatio, StoreResult, StoreUpdate,
};

/// Internal representation of natural numbers.
///
/// In Rust natural numbers are represented as `usize`. However, internally we represent them as
/// `u32`. This is done to preserve semantics across different targets. This is useful when tests
/// run with `usize = u64` while the actual target has `usize = u32`.
///
/// To avoid too many conversions between `usize` and `Nat` which are necessary when interfacing
/// with Rust, `usize` is used instead of `Nat` in code meant only for tests.
///
/// Currently, the store only supports targets with `usize = u32`.
// Make sure production builds have `usize = 32`.
#[cfg(any(target_pointer_width = "32", feature = "std"))]
type Nat = u32;

/// Returns the internal representation of a Rust natural number.
///
/// # Panics
///
/// Panics if the conversion overflows.
fn usize_to_nat(x: usize) -> Nat {
    use core::convert::TryFrom;
    Nat::try_from(x).unwrap()
}
