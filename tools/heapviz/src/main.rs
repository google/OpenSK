use regex::Regex;
use std::io::{BufRead, Write};
use std::thread::sleep;
use std::time::Duration;

struct Event {
    is_alloc: bool,
    start: usize,
    len: usize,
}

fn main() {
    let re = Regex::new(r"^(alloc|dealloc)\[(\d+), \d+\] = 0x([0-9a-f]+) \(\d+ ptrs, \d+ bytes\)$")
        .unwrap();

    let mut events = Vec::new();
    for line in std::io::stdin().lock().lines() {
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

    print!("\nLoading visualization");
    for _ in 0..30 {
        print!(".");
        std::io::stdout().flush().unwrap();
        sleep(Duration::from_millis(50));
    }
    println!();

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
        sleep(Duration::from_millis(50));
    }

    ncurses::endwin();
}
