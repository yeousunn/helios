//! Build script: optionally embeds the process-server image into the SDK so
//! `sdk/bin/init` can spawn it (ADR-023).
//!
//! The image pipeline builds `ps` first, then builds `init` with
//! `PS_IMAGE=<path-to-ps-elf>`. The path may be absolute or relative to the
//! **workspace root** (the common case: `target/x86_64-unknown-none/release/ps`).
//! Without a valid path, init compiles with an empty image and skips the spawn
//! step (`HAS_PS_IMAGE = false`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Resolve `PS_IMAGE`. Relative paths are tried against this crate's manifest
/// dir and then the workspace root (manifest/..), matching how the pipeline is
/// invoked from the workspace root.
fn resolve_ps_image() -> Option<PathBuf> {
    let raw = env::var("PS_IMAGE").ok()?;
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let given = Path::new(&raw);
    let candidates = if given.is_absolute() {
        vec![given.to_path_buf()]
    } else {
        vec![manifest.join(given), manifest.join("..").join(given)]
    };
    candidates.into_iter().find(|c| c.is_file())
}

fn main() {
    println!("cargo:rerun-if-env-changed=PS_IMAGE");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out_dir.join("ps_image.rs");

    let code = match resolve_ps_image() {
        Some(path) => {
            let path = path.canonicalize().unwrap_or(path);
            println!("cargo:rerun-if-changed={}", path.display());
            let escaped = path
                .display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            format!(
                "pub const HAS_PS_IMAGE: bool = true;\n\
                 pub static PS_IMAGE: &[u8] = include_bytes!(\"{escaped}\");\n"
            )
        }
        None => "pub const HAS_PS_IMAGE: bool = false;\n\
             pub static PS_IMAGE: &[u8] = &[];\n"
            .to_string(),
    };
    fs::write(dest, code).expect("write ps_image.rs");
}
