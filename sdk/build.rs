//! Build script: optionally embeds the process-server image into the SDK so
//! `sdk/bin/init` can spawn it (ADR-023).
//!
//! The image pipeline builds `ps` first, then builds `init` with
//! `PS_IMAGE=<path-to-ps-elf>`. Without the variable, init compiles with an
//! empty image and skips the spawn step (`HAS_PS_IMAGE = false`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=PS_IMAGE");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out_dir.join("ps_image.rs");

    let code = match env::var("PS_IMAGE").ok().filter(|p| Path::new(p).is_file()) {
        Some(path) => {
            println!("cargo:rerun-if-changed={path}");
            let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
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
