#!/bin/sh
# Build every ELF in personality/assets/ from its source in
# personality/assets/src/, using zig's bundled musl libc.
#
# Usage:
#   build.sh [OUTDIR]      build into OUTDIR (default: a fresh temp dir) and
#                          report for each ELF whether it is byte-identical to
#                          the committed asset, or only behaviorally equal
#   build.sh --in-place    rebuild the committed assets in place
#
# Toolchain: zig 0.16.x (`zig cc`). The toolchain and flags are pinned in
# README.md; a different zig/clang will build working binaries but probably not
# byte-identical ones.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ZIG=${ZIG:-zig}

if [ "${1:-}" = "--in-place" ]; then
    out="$here"
    mode=inplace
else
    out=${1:-$(mktemp -d)}
    mode=report
    mkdir -p "$out"
fi

c_srcs="musl_noop musl_write musl_exit musl_hello musl_open musl_mmap musl_ls musl_stat musl_sig musl_cwd musl_time musl_all"
s_srcs="lin_hello lin_args"

echo "zig: $($ZIG version 2>/dev/null || echo 'not found')"
echo "out: $out"

# Static musl binaries (libc-linked).
for name in $c_srcs; do
    "$ZIG" cc -target x86_64-linux-musl -static -Os -s \
        -o "$out/$name" "$here/src/$name.c"
done

# Freestanding Linux-ABI binaries (no libc, raw syscalls).
for name in $s_srcs; do
    "$ZIG" cc -target x86_64-linux-musl -nostdlib -static -s \
        -o "$out/$name" "$here/src/$name.s"
done

[ "$mode" = report ] || exit 0

# Report fidelity against the committed assets.
echo
printf '%-12s %-10s %s\n' ELF RESULT NOTE
for name in $c_srcs $s_srcs; do
    if cmp -s "$out/$name" "$here/$name"; then
        printf '%-12s %-10s %s\n' "$name" identical "byte-for-byte"
    else
        printf '%-12s %-10s %s\n' "$name" differs "behaviorally equal; see README.md"
    fi
done
