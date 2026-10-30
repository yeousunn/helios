fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let linker_script = std::path::Path::new(&manifest_dir).join("../kernel.ld");
    println!("cargo:rustc-link-arg=-T{}", linker_script.display());
}
