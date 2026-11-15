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
#![forbid(unsafe_code)]

use crate::sys::{raw_cstr_from_va, raw_ptr_array_from_va};
use alloc::vec::Vec;

/// Owned view of the initial argv/envp arrays, parsed from the entry stack.
pub struct Args {
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
}

impl Args {
    /// Parse the initial stack pointers into owned string vectors.
    ///
    /// `argc` is the argument count from the stack header.
    /// `argv_va` and `envp_va` are the virtual addresses of the argv/envp
    /// pointer arrays (as captured by the entry stub).
    pub fn new(argc: usize, argv_va: u64, envp_va: u64) -> Self {
        let argv_ptrs = raw_ptr_array_from_va(argv_va, argc).unwrap_or(&[]);
        let mut argv = Vec::with_capacity(argc);
        for &ptr in argv_ptrs {
            if ptr == 0 {
                break;
            }
            argv.push(raw_cstr_from_va(ptr).unwrap_or(&[]).to_vec());
        }

        // envp is NULL-terminated, so we read until we hit a null pointer.
        // We don't know the count in advance, so read a reasonable maximum.
        const MAX_ENVP: usize = 64;
        let envp_ptrs = raw_ptr_array_from_va(envp_va, MAX_ENVP).unwrap_or(&[]);
        let mut envp = Vec::new();
        for &ptr in envp_ptrs {
            if ptr == 0 {
                break;
            }
            envp.push(raw_cstr_from_va(ptr).unwrap_or(&[]).to_vec());
        }

        Self { argv, envp }
    }

    pub fn argc(&self) -> usize {
        self.argv.len()
    }

    /// The `i`-th argument as a byte slice (without the NUL).
    pub fn arg(&self, i: usize) -> Option<&[u8]> {
        self.argv.get(i).map(|v| v.as_slice())
    }

    /// Number of environment entries.
    pub fn envc(&self) -> usize {
        self.envp.len()
    }

    /// The `i`-th environment entry ("K=V" bytes without the NUL).
    pub fn env(&self, i: usize) -> Option<&[u8]> {
        self.envp.get(i).map(|v| v.as_slice())
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
