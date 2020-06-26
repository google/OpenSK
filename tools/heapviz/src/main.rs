// Copyright 2020 Google LLC
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

use clap::{App, Arg};
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::thread::sleep;
use std::time::Duration;

/// Configuration, built from CLI parameters.
struct Config {
    /// Handle to the log file containing allocation operations.
    logfile: File,
    /// Number of allocation operations to show per second.
    fps: u64,
}

fn parse_cli() -> Config {
    let matches = App::new("Heap visualizer")
                          .version("0.1")
                          .author("Guillaume Endignoux <guillaumee@google.com>")
                          .about("Tool to visualize heap usage of libtock-rs applications")
                          .arg(Arg::with_name("logfile")
                               .short("f")
                               .long("logfile")
                               .value_name("FILE")
                               .help("Log file containing allocation info (deploy OpenSK with --debug-allocations to obtain it)")
                               .takes_value(true)
                               .required(true))
                          .arg(Arg::with_name("fps")
                               .long("fps")
                               .value_name("FPS")
                               .help("Number of allocation operations to show per second")
                               .takes_value(true)
                               .default_value("20"))
                          .get_matches();

    let logpath = matches.value_of("logfile").unwrap();
    let fps = matches
        .value_of("fps")
        .unwrap()
        .parse::<u64>()
        .expect("The --fps parameter must be an integer");
    let logfile = File::open(logpath).expect("Couldn't open --logfile for reading");

    Config { logfile, fps }
}

/// An allocation or deallocation event.
struct Event {
    /// Whether this even is an allocation (true) or a deallocation (false).
    is_alloc: bool,
    /// The start address of the (de)allocated block, in bytes.
    start: usize,
    /// The length of the (de)allocated block, in bytes.
    len: usize,
}

fn main() {
    let config = parse_cli();

    // The following regex matches lines looking like the following from OpenSK's output. Such lines
    // are printed to the console when the `--debug-allocations` feature is enabled in the deploy
    // script.
    //
    // ```
    // alloc[256, 1] = 0x2002410c (2 ptrs, 384 bytes)
    // dealloc[256, 1] = 0x2002410c (1 ptrs, 512 bytes)
    // ```
    //
    // The two integers between square brackets after the (de)alloc keywords represent the length
    // and alignement of the allocated block, respectively. The integer serialized in hexadecimal
    // after the equal sign represents the starting address of the allocated block. The two
    // integers within parentheses represent statistics about the total number of allocated blocks
    // and the total number of allocated bytes after the (de)allocation operation, respectively.
    //
    // This regex captures three elements, in this order.
    // - The keyword to know whether this operation is an allocation or a deallocation.
    // - The length of the allocated block.
    // - The starting address of the allocated block.
    let re = Regex::new(r"^(alloc|dealloc)\[(\d+), \d+\] = 0x([0-9a-f]+) \(\d+ ptrs, \d+ bytes\)$")
        .unwrap();

    let mut events = Vec::new();
    for line in BufReader::new(config.logfile).lines() {
        if let Some(caps) = re.captures(&line.unwrap()) {
            let typ = caps.get(1).unwrap().as_str();
            let len = caps.get(2).unwrap().as_str().parse::<usize>().unwrap();
            let start = usize::from_str_radix(&caps.get(3).unwrap().as_str(), 16).unwrap();
            events.push(Event {
                is_alloc: typ == "alloc",
                start,
                len,
            });
        }
    }

    let count_alloc = events.iter().filter(|e| e.is_alloc).count();
    let count_dealloc = events.len() - count_alloc;
    let start = events.iter().map(|e| e.start).min().unwrap_or(0);
    let end = events.iter().map(|e| e.start + e.len).max().unwrap_or(0);
    let mut usage = 0;
    let peak = events
        .iter()
        .map(|e| {
            if e.is_alloc {
                usage += e.len;
            } else {
                usage -= e.len;
            }
            usage
        })
        .max()
        .unwrap_or(0);
    let len = end - start;
    println!(
        "Observed {} allocations and {} deallocations",
        count_alloc, count_dealloc
    );
    println!("Start address: {:08x}", start);
    println!("End address: {:08x}", end);
    println!("Peak usage: {0} = {0:08x} bytes", peak);
    println!("Peak consumption: {0} = {0:08x} bytes", len);
    println!("Fragmentation overhead: {0} = {0:08x} bytes", len - peak);

    print!("\nPress ENTER to start the visualization...");
    std::io::stdout().flush().unwrap();
    // Wait for ENTER, by reading a single byte and discarding it.
    let _ = std::io::stdin().lock().read(&mut [0u8]).unwrap();

    let window = ncurses::initscr();
    ncurses::cbreak();
    ncurses::noecho();
    ncurses::intrflush(window, false);
    ncurses::curs_set(ncurses::CURSOR_VISIBILITY::CURSOR_INVISIBLE);

    let width = ncurses::getmaxx(window) as usize;

    for e in events.iter() {
        let position = e.start - start;
        ncurses::wmove(window, (position / width) as i32, (position % width) as i32);

        let mut s = Vec::with_capacity(e.len);
        if e.is_alloc {
            s.resize(e.len, b'#');
        } else {
            s.resize(e.len, b'.');
        }
        ncurses::addstr(std::str::from_utf8(s.as_slice()).unwrap());
        ncurses::refresh();
        sleep(Duration::from_nanos(1_000_000_000 / config.fps));
    }

    ncurses::endwin();
}
