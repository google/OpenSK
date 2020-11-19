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

//! Helpers to compute and display fuzzing coverage statistics.
//!
//! This is not used during actual fuzzing, only when replaying a corpus to compute statistics.

use crate::histogram::{bucket_from_width, Histogram};
use std::collections::HashMap;
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};

/// Statistics for each fuzzing run.
#[derive(Copy, Clone, PartialEq, Eq, Hash, EnumIter, EnumString, Display)]
pub enum StatKey {
    /// The available entropy in bytes.
    Entropy,

    /// The size of a page in bytes.
    PageSize,

    /// The number of pages.
    NumPages,

    /// The maximum number times a page can be erased.
    MaxPageErases,

    /// The dirty length of the initial storage in bytes.
    ///
    /// This is the length of the prefix of the storage that is written using entropy before the
    /// store is initialized. This permits to check the store against an invalid storage: it should
    /// not crash but may misbehave.
    DirtyLength,

    /// The number of used erase cycles of the initial storage.
    ///
    /// This permits to check the store as if it already consumed lifetime. In particular it permits
    /// to check the store when lifetime is almost out.
    InitCycles,

    /// The number of words written during fuzzing.
    ///
    /// This permits to get an idea of how much lifetime was exercised during fuzzing.
    UsedLifetime,

    /// Whether the store reached the end of the lifetime during fuzzing.
    FinishedLifetime,

    /// The number of times the store was fully compacted.
    ///
    /// The store is considered fully compacted when all pages have been compacted once. So each
    /// page has been compacted at least that number of times.
    NumCompactions,

    /// The number of times the store was powered on.
    PowerOnCount,

    /// The number of times a transaction was applied.
    TransactionCount,

    /// The number of times a clear operation was applied.
    ClearCount,

    /// The number of times a prepare operation was applied.
    PrepareCount,

    /// The number of times an insert update was applied.
    InsertCount,

    /// The number of times a remove update was applied.
    RemoveCount,

    /// The number of times a store operation was interrupted.
    InterruptionCount,
}

/// Statistics about multiple fuzzing runs.
#[derive(Default)]
pub struct Stats {
    /// Maps each statistics to its histogram.
    stats: HashMap<StatKey, Histogram>,
}

impl Stats {
    /// Adds a measure for a statistics.
    pub fn add(&mut self, key: StatKey, value: usize) {
        self.stats.entry(key).or_default().add(value);
    }

    /// Merges another statistics into this one.
    pub fn merge(&mut self, other: &Stats) {
        for (&key, other) in &other.stats {
            self.stats.entry(key).or_default().merge(other);
        }
    }

    /// Returns the count of a bucket for a given key.
    pub fn get_count(&self, key: StatKey, bucket: usize) -> Option<usize> {
        self.stats.get(&key).and_then(|h| h.get(bucket))
    }

    /// Returns the bit-width of one past the highest non-empty bucket.
    ///
    /// In other words, all non-empty buckets of the histogram have a bit-width smaller than the
    /// returned width.
    fn width_lim(&self) -> usize {
        self.stats
            .values()
            .map(|h| h.width_lim())
            .max()
            .unwrap_or(0)
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let mut matrix: Vec<Vec<String>> = Vec::new();
        let bits = self.width_lim();

        let mut header = Vec::new();
        header.push(String::new());
        for width in 0..bits {
            header.push(format!(" {}", bucket_from_width(width)));
        }
        header.push(" count".into());
        matrix.push(header);

        for key in StatKey::iter() {
            let mut row = Vec::new();
            row.push(format!("{}:", key));
            for width in 0..bits {
                row.push(match self.get_count(key, bucket_from_width(width)) {
                    None => String::new(),
                    Some(x) => format!(" {}", x),
                });
            }
            let count = self.stats.get(&key).map_or(0, |h| h.count());
            row.push(format!(" {}", count));
            matrix.push(row);
        }

        write_matrix(f, matrix)
    }
}

/// Prints a string aligned to the right for a given width.
fn align(f: &mut std::fmt::Formatter, x: &str, n: usize) -> Result<(), std::fmt::Error> {
    for _ in 0..n.saturating_sub(x.len()) {
        write!(f, " ")?;
    }
    write!(f, "{}", x)
}

/// Prints a matrix with columns of minimal width to fit all elements.
fn write_matrix(
    f: &mut std::fmt::Formatter,
    mut m: Vec<Vec<String>>,
) -> Result<(), std::fmt::Error> {
    if m.is_empty() {
        return Ok(());
    }
    let num_cols = m.iter().map(|r| r.len()).max().unwrap();
    let mut col_len = vec![0; num_cols];
    for row in &mut m {
        row.resize(num_cols, String::new());
        for col in 0..num_cols {
            col_len[col] = std::cmp::max(col_len[col], row[col].len());
        }
    }
    for row in m {
        for col in 0..num_cols {
            align(f, &row[col], col_len[col])?;
        }
        writeln!(f)?;
    }
    Ok(())
}
