//! Build script: optionally embeds the v0 spawn payload (`sdk/bin/child`,
//! `CHILD_IMAGE`) into the VFS so its ramfs can serve `/child` — the file PS
//! loads through the VFS when SPAWN carries a program path (design §2.6).
//! Same resolution rules as `servers/process/build.rs`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn resolve_image(var: &str) -> Option<PathBuf> {
    let raw = env::var(var).ok()?;
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

fn emit(env_var: &str, rs_name: &str, out_dir: &Path, dest_name: &str) {
    println!("cargo:rerun-if-env-changed={env_var}");
    let dest = out_dir.join(dest_name);
    let Some(path) = resolve_image(env_var) else {
        fs::write(
            dest,
            format!(
                "pub const HAS_{rs_name}: bool = false;\n\
                 pub static {rs_name}: &[u8] = &[];\n"
            ),
        )
        .expect("write image stub");
        return;
    };
    let path = path.canonicalize().unwrap_or(path);
    println!("cargo:rerun-if-changed={}", path.display());
    let escaped = path
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    fs::write(
        dest,
        format!(
            "pub const HAS_{rs_name}: bool = true;\n\
             pub static {rs_name}: &[u8] = include_bytes!(\"{escaped}\");\n"
        ),
    )
    .expect("write image include");
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    emit("CHILD_IMAGE", "CHILD_IMAGE", &out_dir, "child_image.rs");
    emit("POSIX_IMAGE", "POSIX_IMAGE", &out_dir, "posix_image.rs");
}
