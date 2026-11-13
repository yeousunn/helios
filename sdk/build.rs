//! Build script: optionally embeds the server images into the SDK so
//! `sdk/bin/init` can spawn them (ADR-023).
//!
//! The image pipeline builds `ps` and `vfs` first, then builds `init` with
//! `PS_IMAGE=<path-to-ps-elf>` / `VFS_IMAGE=<path-to-vfs-elf>`. Paths may be
//! absolute or relative to the **workspace root** (the common case:
//! `target/x86_64-unknown-none/release/ps`). Without a valid path, init
//! compiles with an empty image and skips that spawn step
//! (`HAS_*_IMAGE = false`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Candidate paths for one image env var. Relative paths are tried against
/// this crate's manifest dir and then the workspace root (manifest/..),
/// matching how the pipeline is invoked from the workspace root.
fn candidates(var: &str) -> Vec<PathBuf> {
    let Ok(raw) = env::var(var) else {
        return Vec::new();
    };
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let given = Path::new(&raw);
    if given.is_absolute() {
        vec![given.to_path_buf()]
    } else {
        vec![manifest.join(given), manifest.join("..").join(given)]
    }
}

fn embed(var: &str, const_name: &str, code: &mut String) {
    println!("cargo:rerun-if-env-changed={var}");
    let candidates = candidates(var);
    // Register every candidate as a dependency even when it is absent: the
    // sdk build script runs while building `child` (the first sdk bin), which
    // is BEFORE the server images exist on a fresh build. Without this the
    // cached "no image" output would be reused when `init` is built later and
    // the boot would fail at init's first spawn (board E1).
    for c in &candidates {
        println!("cargo:rerun-if-changed={}", c.display());
    }
    match candidates.into_iter().find(|c| c.is_file()) {
        Some(path) => {
            let path = path.canonicalize().unwrap_or(path);
            let escaped = path
                .display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            code.push_str(&format!(
                "pub const HAS_{const_name}_IMAGE: bool = true;\n\
                 pub static {const_name}_IMAGE: &[u8] = include_bytes!(\"{escaped}\");\n"
            ));
        }
        None => code.push_str(&format!(
            "pub const HAS_{const_name}_IMAGE: bool = false;\n\
             pub static {const_name}_IMAGE: &[u8] = &[];\n"
        )),
    }
}

fn main() {
    let mut code = String::new();
    embed("PS_IMAGE", "PS", &mut code);
    embed("VFS_IMAGE", "VFS", &mut code);
    embed("CONSOLE_IMAGE", "CONSOLE", &mut code);
    embed("AUTH_IMAGE", "AUTH", &mut code);
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    fs::write(out_dir.join("ps_image.rs"), code).expect("write ps_image.rs");
}
