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

use fuzz_store::{fuzz, StatKey, Stats};
use std::io::{stdout, Read, Write};
use std::path::Path;

fn usage(program: &str) {
    println!(
        r#"Usage: {} {{ [<artifact_file>] | <corpus_directory> <bucket_predicate>.. }}

If <artifact_file> is not provided, it is read from standard input.

When <bucket_predicate>.. are provided, only runs matching all predicates are shown. The format of
each <bucket_predicate> is <bucket_key>=<bucket_value>."#,
        program
    );
}

fn debug(data: &[u8]) {
    println!("{:02x?}", data);
    fuzz(data, true, None);
}

/// Bucket predicate.
struct Predicate {
    /// Bucket key.
    key: StatKey,

    /// Bucket value.
    value: usize,
}

impl std::str::FromStr for Predicate {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let predicate: Vec<&str> = input.split('=').collect();
        if predicate.len() != 2 {
            return Err("Predicate should have exactly one equal sign.".to_string());
        }
        let key = predicate[0]
            .parse()
            .map_err(|_| format!("Predicate key `{}` is not recognized.", predicate[0]))?;
        let value: usize = predicate[1]
            .parse()
            .map_err(|_| format!("Predicate value `{}` is not a number.", predicate[1]))?;
        if value != 0 && !value.is_power_of_two() {
            return Err(format!(
                "Predicate value `{}` is not a bucket.",
                predicate[1]
            ));
        }
        Ok(Predicate { key, value })
    }
}

fn analyze(corpus: &Path, predicates: Vec<Predicate>) {
    let mut stats = Stats::default();
    let mut count = 0;
    let total = std::fs::read_dir(corpus).unwrap().count();
    for entry in std::fs::read_dir(corpus).unwrap() {
        let data = std::fs::read(entry.unwrap().path()).unwrap();
        let mut stat = Stats::default();
        fuzz(&data, false, Some(&mut stat));
        if predicates
            .iter()
            .all(|p| stat.get_count(p.key, p.value).is_some())
        {
            stats.merge(&stat);
        }
        count += 1;
        print!("\u{1b}[K{} / {}\r", count, total);
        stdout().flush().unwrap();
    }
    // NOTE: To avoid reloading the corpus each time we want to check a different filter, we can
    // start an interactive loop here taking filters as input and printing the filtered stats. We
    // would keep all individual stats for each run in a vector.
    print!("{}", stats);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // No arguments reads from stdin.
    if args.len() <= 1 {
        let stdin = std::io::stdin();
        let mut data = Vec::new();
        stdin.lock().read_to_end(&mut data).unwrap();
        return debug(&data);
    }
    let path = Path::new(&args[1]);
    // File argument assumes artifact.
    if path.is_file() && args.len() == 2 {
        return debug(&std::fs::read(path).unwrap());
    }
    // Directory argument assumes corpus.
    if path.is_dir() {
        match args[2..].iter().map(|x| x.parse()).collect() {
            Ok(predicates) => return analyze(path, predicates),
            Err(error) => eprintln!("Error: {}", error),
        }
    }
    usage(&args[0]);
}
