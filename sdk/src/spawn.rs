//! v0.2 SPAWN payload blob (design §2.6: "argv/env in the arg window").
//!
//! SPAWN carries 3 capability descriptors and `ipc::Message` descriptors
//! overlay the trailing words, so no data words remain: the program path and
//! the argv/env strings travel in the caller's CONNECT **arg window**:
//!
//! ```text
//! [u64 path_span][u64 argv_span][u64 env_span]   (spans: (off << 32) | len)
//! path bytes | argv area (NUL-separated strings) | env area (likewise)
//! ```
//!
//! PS splits the areas on NULs and crafts a real initial stack:
//! `[TOP-8] = argc`, `[TOP-16] = argv*`, `[TOP-24] = envp*`; the pointer
//! arrays and string bytes live in the lower half of the top stack page.
#![forbid(unsafe_code)]

use crate::sys::raw_copy_to_va;

/// Byte offset where the payload areas begin (after the three spans).
pub const BLOB_HEADER: usize = 24;

/// Write the blob into `window_va`. Returns `None` when it does not fit.
pub fn write_spawn_blob(window_va: u64, path: &[u8], argv: &[&[u8]], env: &[&[u8]]) -> Option<()> {
    let argv_len: usize = argv.iter().map(|a| a.len() + 1).sum();
    let env_len: usize = env.iter().map(|e| e.len() + 1).sum();
    let path_off = BLOB_HEADER;
    let argv_off = path_off + path.len();
    let env_off = argv_off + argv_len;
    let end = env_off + env_len;
    if path.is_empty() || end > 4096 {
        return None;
    }
    let path_span = ((path_off as u64) << 32) | path.len() as u64;
    let argv_span = ((argv_off as u64) << 32) | argv_len as u64;
    let env_span = ((env_off as u64) << 32) | env_len as u64;

    // Write the three span headers (8 bytes each)
    raw_copy_to_va(window_va, &path_span.to_le_bytes());
    raw_copy_to_va(window_va + 8, &argv_span.to_le_bytes());
    raw_copy_to_va(window_va + 16, &env_span.to_le_bytes());

    // Write path
    raw_copy_to_va(window_va + path_off as u64, path);

    // Write argv area
    let mut o = argv_off;
    for a in argv {
        raw_copy_to_va(window_va + o as u64, a);
        // Write NUL terminator
        raw_copy_to_va(window_va + o as u64 + a.len() as u64, &[0]);
        o += a.len() + 1;
    }

    // Write env area
    let mut o = env_off;
    for e in env {
        raw_copy_to_va(window_va + o as u64, e);
        raw_copy_to_va(window_va + o as u64 + e.len() as u64, &[0]);
        o += e.len() + 1;
    }

    Some(())
}
