//! Program-start arguments: read the crafted initial stack (v0.2 entry
//! contract, `sdk::spawn`).
//!
//! A spawned program's entry stub captures the three header words before any
//! Rust prologue runs (pushes would clobber them) and hands them here:
//!
//! ```text
//! [TOP-8]  = argc
//! [TOP-16] = argv: *const *const u8   (argc pointers, then NULL)
//! [TOP-24] = envp: *const *const u8   (envc pointers, then NULL)
//! ```
//!
//! The arrays and their NUL-terminated strings live in the lower half of the
//! top stack page (below any early push traffic only after the stub lowers
//! `rsp`).

/// Borrowed view of the initial argv/envp arrays.
#[derive(Clone, Copy)]
pub struct Args {
    argc: usize,
    argv: *const *const u8,
    envp: *const *const u8,
}

impl Args {
    /// # Safety
    /// `argc`/`argv`/`envp` must come from the entry stub exactly as the
    /// stack was crafted (see the module docs).
    pub const unsafe fn new(argc: u64, argv: *const *const u8, envp: *const *const u8) -> Self {
        Self {
            argc: argc as usize,
            argv,
            envp,
        }
    }

    pub fn argc(&self) -> usize {
        self.argc
    }

    /// The `i`-th argument as a byte slice (without the NUL).
    pub fn arg(&self, i: usize) -> Option<&[u8]> {
        if i >= self.argc {
            return None;
        }
        Some(unsafe { cstr(*self.argv.add(i)) })
    }

    /// Number of environment entries.
    pub fn envc(&self) -> usize {
        let mut n = 0;
        loop {
            let p = unsafe { *self.envp.add(n) };
            if p.is_null() {
                return n;
            }
            n += 1;
        }
    }

    /// The `i`-th environment entry ("K=V" bytes without the NUL).
    pub fn env(&self, i: usize) -> Option<&[u8]> {
        if i >= self.envc() {
            return None;
        }
        Some(unsafe { cstr(*self.envp.add(i)) })
    }

    /// Parse `argv[0]` as a decimal exit status (the v0 smoke convention).
    pub fn arg0_as_status(&self) -> i32 {
        let Some(a) = self.arg(0) else {
            return -1;
        };
        if a.is_empty() || !a[0].is_ascii_digit() {
            return -2;
        }
        let mut v: i32 = 0;
        for &c in a {
            if !c.is_ascii_digit() {
                break;
            }
            v = v.saturating_mul(10).saturating_add((c - b'0') as i32);
        }
        v
    }
}

/// # Safety
/// `p` must point at a NUL-terminated byte string (or be null, rejected).
unsafe fn cstr(p: *const u8) -> &'static [u8] {
    if p.is_null() {
        return &[];
    }
    let mut n = 0usize;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    unsafe { core::slice::from_raw_parts(p, n) }
}
