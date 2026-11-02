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

/// Resolve one image env var. Relative paths are tried against this crate's
/// manifest dir and then the workspace root (manifest/..), matching how the
/// pipeline is invoked from the workspace root.
fn resolve_image(var: &str) -> Option<PathBuf> {
    let raw = env::var(var).ok()?;
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let given = Path::new(&raw);
    let candidates = if given.is_absolute() {
        vec![given.to_path_buf()]
    } else {
        vec![manifest.join(given), manifest.join("..").join(given)]
    };
    candidates.into_iter().find(|c| c.is_file())
}

fn embed(var: &str, const_name: &str, code: &mut String) {
    println!("cargo:rerun-if-env-changed={var}");
    match resolve_image(var) {
        Some(path) => {
            let path = path.canonicalize().unwrap_or(path);
            println!("cargo:rerun-if-changed={}", path.display());
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
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    fs::write(out_dir.join("ps_image.rs"), code).expect("write ps_image.rs");
}
