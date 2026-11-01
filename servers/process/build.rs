//! Build script: optionally embeds the v0 spawn payload (`sdk/bin/child`,
//! `CHILD_IMAGE`) into the process server so `SPAWN` can load it without a
//! VFS (design §2.4; real ELF loading arrives with the VFS slice).
//!
//! The pipeline builds `child` first, then `ps` with
//! `CHILD_IMAGE=<path-to-child-elf>`. The path may be absolute or relative to
//! the **workspace root**. Without a valid path, PS compiles with an empty
//! image and replies `ENOSYS` to `SPAWN` (`HAS_CHILD_IMAGE = false`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Resolve `CHILD_IMAGE`. Relative paths are tried against this crate's
/// manifest dir and then upward toward the workspace root (this crate lives
/// at `servers/process`, two levels down).
fn resolve_child_image() -> Option<PathBuf> {
    let raw = env::var("CHILD_IMAGE").ok()?;
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let given = Path::new(&raw);
    let candidates = if given.is_absolute() {
        vec![given.to_path_buf()]
    } else {
        vec![
            manifest.join(given),
            manifest.join("..").join(given),
            manifest.join("../..").join(given),
        ]
    };
    candidates.into_iter().find(|c| c.is_file())
}

fn main() {
    println!("cargo:rerun-if-env-changed=CHILD_IMAGE");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out_dir.join("child_image.rs");

    let code = match resolve_child_image() {
        Some(path) => {
            let path = path.canonicalize().unwrap_or(path);
            println!("cargo:rerun-if-changed={}", path.display());
            let escaped = path
                .display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            format!(
                "pub const HAS_CHILD_IMAGE: bool = true;\n\
                 pub static CHILD_IMAGE: &[u8] = include_bytes!(\"{escaped}\");\n"
            )
        }
        None => "pub const HAS_CHILD_IMAGE: bool = false;\n\
             pub static CHILD_IMAGE: &[u8] = &[];\n"
            .to_string(),
    };
    fs::write(dest, code).expect("write child_image.rs");
}
