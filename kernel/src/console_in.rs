//! Console input (v0): IRQ-fed line buffer + reserved notification.
//!
//! The UART RX ISR (hal callback) pushes bytes; on newline (or a full
//! buffer) the completed line becomes available and the reserved console
//! notification (obj 0xD3) is signalled. `sys_recv` on the reserved
//! console-in endpoint cap (obj 0xD2) pops one line — ratified ABI, no new
//! syscalls (kernel/reserved objects, ADR-018 debug-EP pattern).
#![forbid(unsafe_code)]

use spin::Mutex;

/// Reserved kernel object ids (0xD1 = debug EP, ADR-018).
pub const CONSOLE_IN_EP_ID: u64 = 0xD2;
pub const CONSOLE_NOTIFY_ID: u64 = 0xD3;

const LINE_MAX: usize = 128;
const LINES_MAX: usize = 8;

struct State {
    cur: [u8; LINE_MAX],
    cur_len: usize,
    lines: [[u8; LINE_MAX]; LINES_MAX],
    line_lens: [usize; LINES_MAX],
    head: usize,
    count: usize,
    overruns: u64,
}

static STATE: Mutex<State> = Mutex::new(State {
    cur: [0; LINE_MAX],
    cur_len: 0,
    lines: [[0; LINE_MAX]; LINES_MAX],
    line_lens: [0; LINES_MAX],
    head: 0,
    count: 0,
    overruns: 0,
});

fn with_state<T>(f: impl FnOnce(&mut State) -> T) -> Option<T> {
    let mut guard = STATE.lock();
    Some(f(&mut guard))
}

/// Push one RX byte (IRQ context). On `\r`/`\n` (or a full line) the line
/// becomes available and the console notification is signalled.
pub fn push_byte(b: u8) {
    let newline = b == b'\n' || b == b'\r';
    let full = with_state(|s| {
        if s.cur_len >= LINE_MAX {
            true
        } else {
            if !newline {
                s.cur[s.cur_len] = b;
                s.cur_len += 1;
            }
            s.cur_len >= LINE_MAX
        }
    })
    .unwrap_or(false);
    if newline || full {
        commit_line();
    }
}

fn commit_line() {
    // IRQ-CONTEXT SAFETY: no locks are taken here (the interrupted code may
    // hold the SCHED/NOTIFICATION spinlocks — taking them from the IRQ would
    // deadlock on the same CPU). The completed line is marked PENDING; the
    // wakeup signal is deferred to syscall dispatch entry (ADR-038 §deferred).
    with_state(|s| {
        if s.count == LINES_MAX {
            s.overruns += 1; // drop-oldest semantics v0: drop the NEW line
            s.cur_len = 0;
            return;
        }
        let tail = (s.head + s.count) % LINES_MAX;
        s.lines[tail] = s.cur;
        s.line_lens[tail] = s.cur_len;
        s.count += 1;
        s.cur_len = 0;
    });
}

/// True when at least one completed line awaits (deferred-wake check).
pub fn has_pending_line() -> bool {
    with_state(|s| s.count > 0).unwrap_or(false)
}

/// Pop one completed line into `out`; returns the length, or None when the
/// queue is empty.
pub fn pop_line(out: &mut [u8]) -> Option<usize> {
    with_state(|s| {
        if s.count == 0 {
            return None;
        }
        let head = s.head;
        let len = s.line_lens[head].min(out.len());
        out[..len].copy_from_slice(&s.lines[head][..len]);
        s.head = (s.head + 1) % LINES_MAX;
        s.count -= 1;
        Some(len)
    })
    .unwrap_or(None)
}

/// Bytes waiting in completed lines (diagnostics).
pub fn pending_lines() -> usize {
    with_state(|s| s.count).unwrap_or(0)
}

/// Overrun counter (lines dropped because the queue was full).
pub fn overruns() -> u64 {
    with_state(|s| s.overruns).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_commit_and_pop() {
        with_state(|s| {
            *s = State {
                cur: [0; LINE_MAX],
                cur_len: 0,
                lines: [[0; LINE_MAX]; LINES_MAX],
                line_lens: [0; LINES_MAX],
                head: 0,
                count: 0,
                overruns: 0,
            };
        });
        for b in b"hello" {
            push_byte(*b);
        }
        assert_eq!(pending_lines(), 0, "no commit before newline");
        push_byte(b'\n');
        assert_eq!(pending_lines(), 1);
        let mut out = [0u8; LINE_MAX];
        assert_eq!(pop_line(&mut out).unwrap(), 5);
        assert_eq!(&out[..5], b"hello");
        assert_eq!(pop_line(&mut out), None);
    }

    #[test]
    fn full_line_auto_commits() {
        with_state(|s| {
            *s = State {
                cur: [0; LINE_MAX],
                cur_len: 0,
                lines: [[0; LINE_MAX]; LINES_MAX],
                line_lens: [0; LINES_MAX],
                head: 0,
                count: 0,
                overruns: 0,
            };
        });
        for _ in 0..LINE_MAX {
            push_byte(b'x');
        }
        assert_eq!(pending_lines(), 1, "full line auto-commits");
        let mut out = [0u8; LINE_MAX];
        assert_eq!(pop_line(&mut out).unwrap(), LINE_MAX);
    }

    #[test]
    fn fifo_order_and_overrun() {
        with_state(|s| {
            *s = State {
                cur: [0; LINE_MAX],
                cur_len: 0,
                lines: [[0; LINE_MAX]; LINES_MAX],
                line_lens: [0; LINES_MAX],
                head: 0,
                count: 0,
                overruns: 0,
            };
        });
        // Fill the queue exactly, then overflow twice.
        for n in 0..(LINES_MAX + 2) {
            for b in b"line" {
                push_byte(*b);
            }
            push_byte(b'0' + (n % 10) as u8);
            push_byte(b'\n');
        }
        assert_eq!(overruns(), 2, "overflowing lines are dropped");
        assert_eq!(pending_lines(), LINES_MAX);
        // FIFO order preserved: first line is "line0".
        let mut out = [0u8; LINE_MAX];
        let n = pop_line(&mut out).unwrap();
        assert_eq!(&out[..n], b"line0");
    }
}
