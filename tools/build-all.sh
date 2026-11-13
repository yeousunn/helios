#!/usr/bin/env bash
#
# tools/build-all.sh - Build every userspace image in dependency order, then
# kernel-boot (release).
#
# Honours CARGO_TARGET_DIR (cargo reads it from the environment automatically)
# and every *_IMAGE variable: after a userspace binary is built it is copied
# to $<BIN_UPPER>_IMAGE when that variable is set (e.g. INIT_IMAGE, PS_IMAGE,
# VFS_IMAGE, AUTH_IMAGE, CONSOLE_IMAGE).
#
# Usage: tools/build-all.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET="${TARGET:-x86_64-unknown-none}"
FEATURES="--features user"

fail() { echo "[build-all] ERROR: $*" >&2; exit 1; }

# Build one userspace binary, then stage it at $<BIN_UPPER>_IMAGE if set.
build_bin() {
    local crate="$1" bin="$2"
    local upper td bin_path image image_var
    upper="$(echo "$bin" | tr '[:lower:]' '[:upper:]')"
    image_var="${upper}_IMAGE"
    image="${!image_var:-}"
    td="${CARGO_TARGET_DIR:-target}"
    bin_path="$td/$TARGET/release/$bin"

    cargo build -p "$crate" --bin "$bin" --target "$TARGET" --release $FEATURES \
        || fail "cargo build -p $crate --bin $bin --release failed"

    if [[ -n "${image:-}" ]]; then
        if [[ "$bin_path" == "$image" ]]; then
            echo "[build-all] $bin already at $image"
        else
            mkdir -p "$(dirname "$image")"
            cp "$bin_path" "$image" || fail "copy $bin -> $image failed"
            echo "[build-all] $bin -> $image"
        fi
    else
        echo "[build-all] $bin -> $bin_path"
    fi
}

echo "[build-all] target=$TARGET target_dir=${CARGO_TARGET_DIR:-target}"

# 1. sdk first — every userspace crate depends on it.
build_bin sdk init
build_bin sdk child

# 2. System servers (depend on sdk + ipc only; no inter-server deps).
build_bin vfs vfs
build_bin auth auth
build_bin process ps
build_bin console console

# 3. Personality layer (depends on sdk).
for bin in posix sh cat login ls echo wc linrun; do
    build_bin personality "$bin"
done

# 4. Kernel last (the `kernel-boot` bin requires the `boot` feature).
cargo build -p kernel-boot --target "$TARGET" --release --features boot \
    || fail "cargo build -p kernel-boot --release --features boot failed"
echo "[build-all] kernel-boot -> ${CARGO_TARGET_DIR:-target}/$TARGET/release/kernel-boot"

echo "[build-all] done"
