//! Early console: level-filtered logging into a writer registered by arch
//! boot code (see ADR-001). Safe for concurrent use; guards with a spin Mutex.
#![forbid(unsafe_code)]

use core::fmt;
use spin::Mutex;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Error => "E",
            Level::Warn => "W",
            Level::Info => "I",
        }
    }
}

type WriterFn = fn(&str);

struct Console {
    writer: WriterFn,
    max_level: Level,
}

static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

/// Register the early console writer. Called once by arch boot code
/// (`kernel::boot::early_init`) before any logging.
pub fn init(writer: WriterFn, max_level: Level) {
    *CONSOLE.lock() = Some(Console { writer, max_level });
}

/// Low-level emit; public so the `k*!` macros (which may be re-exported into
/// other crates via `#[macro_export]`) can resolve `$crate::console::emit`.
pub fn emit(level: Level, args: fmt::Arguments<'_>) {
    let guard = CONSOLE.lock();
    let Some(console) = guard.as_ref() else {
        return;
    };
    if level > console.max_level {
        return;
    }
    let mut buf: heapless_buf::Buf = heapless_buf::Buf::new();
    let _ = fmt::write(&mut buf, format_args!("{}: {}\n", level.tag(), args));
    (console.writer)(buf.as_str());
}

mod heapless_buf {
    use core::fmt;

    pub struct Buf {
        buf: [u8; 512],
        len: usize,
    }

    impl Buf {
        pub const fn new() -> Self {
            Self {
                buf: [0; 512],
                len: 0,
            }
        }

        pub fn as_str(&self) -> &str {
            // No unsafe: all writes go through fmt::Write pushing valid UTF-8
            // fragments via str; truncation may split a char, so validate by
            // walking back to a char boundary.
            let mut end = self.len;
            while end > 0 && core::str::from_utf8(&self.buf[..end]).is_err() {
                end -= 1;
            }
            core::str::from_utf8(&self.buf[..end]).unwrap_or_default()
        }
    }

    impl fmt::Write for Buf {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let remaining = self.buf.len() - self.len;
            let n = s.len().min(remaining);
            self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
            Ok(())
        }
    }
}

/// Kernel logging macro family. Usage: `kinfo!("booting: {}", x);`
#[macro_export]
macro_rules! kerror {
    ($($arg:tt)*) => { $crate::console::emit($crate::console::Level::Error, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! kwarn {
    ($($arg:tt)*) => { $crate::console::emit($crate::console::Level::Warn, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! kinfo {
    ($($arg:tt)*) => { $crate::console::emit($crate::console::Level::Info, format_args!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    use std::string::ToString;

    static LAST: Mutex<&'static str> = Mutex::new("");

    fn capture(s: &str) {
        // Test-only sink: leak the string into a 'static slot (tests only).
        *LAST.lock() = leak_str(s);
    }

    fn leak_str(s: &str) -> &'static str {
        // Tests run under std; a small leak per test is acceptable.
        Box::leak(s.to_string().into_boxed_str())
    }

    #[test]
    fn console_behaviour() {
        super::init(capture, Level::Warn);
        crate::kinfo!("hidden");
        assert_eq!(*LAST.lock(), "");
        crate::kwarn!("shown");
        assert_eq!(*LAST.lock(), "W: shown\n");

        // Truncation at buffer end stays valid UTF-8.
        super::init(capture, Level::Info);
        crate::kinfo!("{}", "é".repeat(600));
        let out = *LAST.lock();
        assert!(out.len() <= 512);
        assert!(out.starts_with("I: "));
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }
}
