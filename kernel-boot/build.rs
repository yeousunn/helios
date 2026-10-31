//! Build script for the kernel boot binary.
//!
//! - Links with the kernel linker script (multiboot2 header first, 1 MiB base).
//! - Optionally embeds the init userspace image: build `init` first, then
//!   build this crate with `INIT_IMAGE=<path-to-init-elf>` (absolute, or
//!   relative to the workspace root). Without it, the kernel boots to the M1
//!   terminus (clean halt) instead of entering userspace.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Resolve `INIT_IMAGE`: relative paths are tried against this manifest dir,
/// then the workspace root (manifest/..), matching pipeline invocations from
/// the workspace root.
fn resolve_init_image() -> Option<PathBuf> {
    let raw = env::var("INIT_IMAGE").ok()?;
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
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let linker_script = manifest_dir.join("../kernel.ld");
    println!("cargo:rustc-link-arg=-T{}", linker_script.display());

    println!("cargo:rerun-if-env-changed=INIT_IMAGE");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out_dir.join("init_image.rs");
    let code = match resolve_init_image() {
        Some(path) => {
            let path = path.canonicalize().unwrap_or(path);
            println!("cargo:rerun-if-changed={}", path.display());
            let escaped = path
                .display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            format!(
                "pub const HAS_INIT_IMAGE: bool = true;\n\
                 pub static INIT_IMAGE: &[u8] = include_bytes!(\"{escaped}\");\n"
            )
        }
        None => "pub const HAS_INIT_IMAGE: bool = false;\n\
             pub static INIT_IMAGE: &[u8] = &[];\n"
            .to_string(),
    };
    fs::write(dest, code).expect("write init_image.rs");
}
