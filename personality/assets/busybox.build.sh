#!/bin/sh
# Build personality/assets/busybox — a minimal static x86_64-linux-musl
# busybox for the POSIX/Linux emulation demo (ADR-046, Phase 3 "busybox").
#
# busybox is GPLv2 (see README.md); it is downloaded and built here, not
# vendored as source. The committed asset in this directory is the build
# output this script reproduces.
#
# Usage:
#   busybox.build.sh [OUT]   build into OUT (default: this directory)
#
# Toolchain: zig 0.16.x (`zig cc`, bundled musl) + llvm-strip. The pinned
# version and applet set are below; a different clang builds a working binary
# that is not byte-identical (busybox is not bit-reproducible across clangs).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=${1:-$here}
ZIG=${ZIG:-zig}
BB_VER=${BB_VER:-1.36.1}

command -v "$ZIG" >/dev/null 2>&1 || { echo "zig not found (set ZIG=)" >&2; exit 1; }

# A stripped static binary needs llvm-strip (GNU strip's --remove-section form).
STRIP=${STRIP:-$(command -v llvm-strip || true)}
if [ -z "$STRIP" ]; then
    for c in /opt/homebrew/Cellar/llvm@2*/2*.*/bin/llvm-strip \
             /opt/homebrew/Cellar/llvm/2*.*/bin/llvm-strip \
             /usr/local/opt/llvm/bin/llvm-strip; do
        [ -x "$c" ] && STRIP=$c && break
    done
fi
[ -n "${STRIP:-}" ] && [ -x "$STRIP" ] || { echo "llvm-strip not found (set STRIP=)" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
src="$work/busybox-$BB_VER"

echo "zig:   $($ZIG version)"
echo "strip: $STRIP"
echo "ver:   busybox-$BB_VER"

tarball="$work/busybox.tar.bz2"
url="https://busybox.net/downloads/busybox-$BB_VER.tar.bz2"
( cd "$work" && curl -fsSL -o busybox.tar.bz2 "$url" )
tar -xf "$tarball" -C "$work"

cd "$src"

# allnoconfig, then enable a small, self-contained applet set. Keep this list
# in sync with the inventory table in README.md.
make allnoconfig >/dev/null
python3 - <<'PY'
import re
names = [
    "STATIC",
    "ECHO", "TRUE", "FALSE", "CAT", "HEAD", "PWD", "UNAME", "PRINTF",
    "SEQ", "WC", "LS", "ID", "CUT", "ENV", "TEST", "TEST1", "TEST2",
]
s = open(".config").read()
for n in names:
    s = re.sub(rf"^# CONFIG_{n} is not set", f"CONFIG_{n}=y", s, flags=re.M)
    if f"CONFIG_{n}=" not in s:
        s += f"\nCONFIG_{n}=y\n"
open(".config", "w").write(s)
PY

# scripts/trylink probes link flags by running the compiler; LLD (zig) rejects
# --warn-common, the -Map,<file> comma form and --verbose, and trylink does not
# probe those, so drop them. (Behavior-affecting flags are left untouched.)
sed -i.bak -e 's/ -Wl,--warn-common//g' -e 's/-Wl,--warn-common //g' scripts/trylink
perl -0pi -e 's/echo "-Wl,-Map,\$EXE\.map -Wl,--verbose"/echo ""/' scripts/trylink

export ZIG_GLOBAL_CACHE_DIR="$work/zig-global"
export ZIG_LOCAL_CACHE_DIR="$work/zig-local"
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" \
    CC="$ZIG cc -target x86_64-linux-musl" \
    AR="$ZIG ar" \
    RANLIB="$ZIG ranlib" \
    STRIP="$STRIP" \
    HOSTCC="${HOSTCC:-cc}" \
    >/dev/null

mkdir -p "$out"
cp "$src/busybox" "$out/busybox"
echo "wrote $out/busybox ($(wc -c < "$out/busybox" | tr -d ' ') bytes)"
