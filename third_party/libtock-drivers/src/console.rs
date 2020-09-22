use crate::util;
use core::cell::Cell;
use core::fmt;
use libtock_core::{callback, syscalls};

const DRIVER_NUMBER: usize = 1;

mod command_nr {
    pub const WRITE: usize = 1;
}

mod subscribe_nr {
    pub const SET_ALARM: usize = 1;
}

mod allow_nr {
    pub const SHARE_BUFFER: usize = 1;
}

pub const BUFFER_SIZE: usize = 1024;

pub struct Console {
    allow_buffer: [u8; BUFFER_SIZE],
    count_pending: usize,
}

impl Console {
    pub fn new() -> Console {
        Console {
            allow_buffer: [0; BUFFER_SIZE],
            count_pending: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.count_pending == 0
    }

    fn is_full(&self) -> bool {
        self.allow_buffer.len() == self.count_pending
    }

    fn available_len(&self) -> usize {
        self.allow_buffer.len() - self.count_pending
    }

    pub fn write<S: AsRef<[u8]>>(&mut self, text: S) {
        let mut not_written_yet = text.as_ref();
        while !not_written_yet.is_empty() {
            let num_bytes_to_print = self.available_len().min(not_written_yet.len());
            self.allow_buffer[self.count_pending..(self.count_pending + num_bytes_to_print)]
                .copy_from_slice(&not_written_yet[..num_bytes_to_print]);
            self.count_pending += num_bytes_to_print;

            if self.is_full() {
                self.flush();
            }

            not_written_yet = &not_written_yet[num_bytes_to_print..];
        }
    }

    pub fn flush(&mut self) {
        if self.is_empty() {
            // Don't trigger any syscall if the buffer is empty.
            return;
        }

        let count = self.count_pending;
        // Clear the buffer even in case of error, to avoid an infinite loop.
        self.count_pending = 0;

        Console::write_unbuffered(&mut self.allow_buffer[..count]);
    }

    pub fn write_unbuffered(buf: &mut [u8]) {
        let count = buf.len();

        let result = syscalls::allow(DRIVER_NUMBER, allow_nr::SHARE_BUFFER, buf);
        if result.is_err() {
            return;
        }

        let is_written = Cell::new(false);
        let mut is_written_alarm = || is_written.set(true);
        let subscription = syscalls::subscribe::<callback::Identity0Consumer, _>(
            DRIVER_NUMBER,
            subscribe_nr::SET_ALARM,
            &mut is_written_alarm,
        );
        if subscription.is_err() {
            return;
        }

        let result_code = syscalls::command(DRIVER_NUMBER, command_nr::WRITE, count, 0);
        if result_code.is_err() {
            return;
        }

        util::yieldk_for(|| is_written.get());
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        self.flush();
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, string: &str) -> Result<(), fmt::Error> {
        self.write(string);
        Ok(())
    }
}
