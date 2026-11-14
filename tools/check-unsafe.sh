#!/usr/bin/env bash
#
# tools/check-unsafe.sh — PLAN.md §7.1 unsafe allowlist gate.
#
# Fails when `unsafe`, `asm!`, `global_asm!` or `extern "C"` appear outside the
# allowlist:
#   hal/*, kernel-boot/, kernel/src/mem.rs, sdk/src/sys/raw.rs
# Everything else is an exception that must appear in tools/unsafe-baseline.txt
# as "<path> <count>" with a count matching the actual usage exactly. The
# baseline may only shrink (migrations remove entries / lower counts); it may
# never grow.
#
# Exit 0 = clean, exit 1 = violation.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASELINE="tools/unsafe-baseline.txt"

# PLAN.md §7.1: unsafe/asm are allowed only here. Everything else is an
# exception that must appear in the baseline.
ALLOW='^(hal/|kernel-boot/|kernel/src/mem\.rs|sdk/src/sys/raw\.rs)'

# Real usage: `unsafe {`/`unsafe fn`/`unsafe impl`/`unsafe extern`, plus
# `asm!`/`global_asm!`/`extern "C"`. Comments mentioning "unsafe" do not count.
PAT='unsafe[[:space:]]*[\{\(]|unsafe[[:space:]]+fn|unsafe[[:space:]]+impl|unsafe[[:space:]]+extern|global_asm!|asm!|extern "C"'

fail=0
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

while IFS= read -r -d '' f; do
    rel="${f#./}"
    rel="${rel#"$ROOT"/}"
    printf '%s\n' "$rel" | grep -Eq "$ALLOW" && continue
    count=$(grep -cE "$PAT" "$f" 2>/dev/null || true)
    [[ "$count" -gt 0 ]] && printf '%s %s\n' "$rel" "$count" >> "$tmp"
done < <(find . -name '*.rs' -not -path './target/*' -not -path './.git/*' -print0)

[[ -f "$BASELINE" ]] || { echo "[check-unsafe] ERROR: $BASELINE not found" >&2; exit 1; }

# Every actually-used file must be in the baseline with an exact count.
while IFS=' ' read -r path count; do
    [[ -z "$path" ]] && continue
    base_count=$(awk -v p="$path" '$1 == p { print $2; exit }' "$BASELINE")
    if [[ -z "$base_count" ]]; then
        echo "[check-unsafe] ERROR: $path ($count) has unsafe usage outside the allowlist but is not in $BASELINE" >&2
        fail=1
    elif [[ "$base_count" != "$count" ]]; then
        echo "[check-unsafe] ERROR: $path baseline count $base_count != actual $count (baseline may only shrink, counts must match actual usage)" >&2
        fail=1
    fi
done < "$tmp"

if [[ "$fail" -ne 0 ]]; then
    echo "[check-unsafe] FAIL: unsafe/asm/extern-C outside the allowlist without a matching baseline entry" >&2
    exit 1
fi

echo "[check-unsafe] OK: all unsafe/asm/extern-C outside the allowlist is covered by $BASELINE"
exit 0
