#!/usr/bin/env bash
#
# tools/qemu-test.sh — Phase H full-system boot test.
#
# Calls E1 (tools/build-all.sh) to build every userspace image and the
# release kernel, then boots the kernel in QEMU and requires the DONE
# marker plus a clean halt.
#
# Usage:
#   tools/qemu-test.sh [qemu-extra-args...]
#
# Environment:
#   CARGO_TARGET_DIR  build dir passed through to E1/cargo (default: target)
#   SERIAL_LOG        serial (UART) log path (default: <CARGO_TARGET_DIR>/serial.log)
#   KERNEL_ELF        release kernel ELF (default: <CARGO_TARGET_DIR>/x86_64-unknown-none/release/kernel-boot)
#   QEMU              qemu binary (default: qemu-system-x86_64)
#   QEMU_TIMEOUT      seconds (default: 90)
#
# Exit codes (ADR-013/ADR-029):
#   0 — clean boot (DONE marker + clean halt)
#   1 — serial-log check failed / unexpected QEMU status
#   2 — kernel panic (isa-debug-exit value 1)
#   3 — unhandled fault / shutdown (value 2)
#   4 — boot timeout (value 3 or harness kill)
#   255 — QEMU failed to launch
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TD="${CARGO_TARGET_DIR:-target}"
TARGET="${TARGET:-x86_64-unknown-none}"
KERNEL_ELF="${KERNEL_ELF:-$TD/$TARGET/release/kernel-boot}"
SERIAL_LOG="${SERIAL_LOG:-$TD/serial.log}"
QEMU="${QEMU:-qemu-system-x86_64}"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-90}"

fail() { echo "[qemu-test] ERROR: $*" >&2; exit 1; }

# Pick a host-accelerated machine type when available; fall back to TCG.
case "$(uname -m)-$(uname -s)" in
    arm64-Darwin)  QEMU_ACCEL="tcg" ;;
    x86_64-Darwin) QEMU_ACCEL="hvf" ;;
    x86_64-Linux)  QEMU_ACCEL="kvm" ;;
    *)             QEMU_ACCEL="tcg" ;;
esac

# Resolve the timeout binary: gtimeout (GNU coreutils on macOS) preferred.
if command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN=gtimeout;
elif command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN=timeout;
else fail "neither 'timeout' nor 'gtimeout' found on PATH"; fi

echo "[qemu-test] ===== Helios Phase H full-system boot ====="
echo "[qemu-test] workspace root: $ROOT"
echo "[qemu-test] kernel: $KERNEL_ELF"
echo "[qemu-test] serial log: $SERIAL_LOG"
echo "[qemu-test] target dir: $TD"

# 1. Build every userspace image + kernel-boot release (E1).
tools/build-all.sh || fail "E1 (tools/build-all.sh) failed"

# 2. Sanity: kernel ELF must exist.
[[ -f "$KERNEL_ELF" ]] || fail "kernel ELF not found: $KERNEL_ELF (build it first)"

rm -f "$SERIAL_LOG"

echo "[qemu-test] --- QEMU boot: $QEMU (accel=$QEMU_ACCEL) ---"
set +e
"$TIMEOUT_BIN" "${QEMU_TIMEOUT}" "$QEMU" \
    -machine accel="$QEMU_ACCEL" \
    -cpu max \
    -m 256M \
    -kernel "$KERNEL_ELF" \
    -serial file:"$SERIAL_LOG" \
    -display none \
    -no-reboot \
    -device isa-debug-exit,iobase=0x501,iosize=0x02 \
    -nographic \
    "$@" \
    </dev/null >/tmp/helios-qemu-stdout.log 2>/tmp/helios-qemu-stderr.log
qemu_status=$?
set -e

# ADR-013 / ADR-029: isa-debug-exit reports (value << 1) | 1.
#   status 1 = value 0 = clean bring-up halt (success)
case "$qemu_status" in
    1) ci_code=0 ;;   # clean halt
    3) ci_code=2 ;;   # kernel panic
    5) ci_code=3 ;;   # unhandled fault / shutdown
    7) ci_code=4 ;;   # boot timeout
    124) ci_code=4 ;; # harness timeout killed QEMU
    255) ci_code=255 ;; # QEMU failed to launch
    *) ci_code=1 ;;   # unexpected
esac

if [[ "$ci_code" != "0" ]]; then
    echo "[qemu-test] QEMU exited with status $qemu_status (CI code $ci_code)"
    cat /tmp/helios-qemu-stderr.log 2>/dev/null || true
    echo "--- Serial log ---"
    cat "$SERIAL_LOG" 2>/dev/null || true
    exit "$ci_code"
fi

# 3. Require the DONE marker and a clean halt in the serial log.
serial_ok=1
if [[ -f "$SERIAL_LOG" ]]; then
    if grep -aq '494e49540000000f' "$SERIAL_LOG"; then
        echo "[qemu-test] DONE marker (0x494e49540000000f) found in serial log"
    else
        echo "[qemu-test] ERROR: DONE marker not found in serial log" >&2
        serial_ok=0
    fi
    if grep -aq 'clean halt' "$SERIAL_LOG"; then
        echo "[qemu-test] clean halt found in serial log"
    else
        echo "[qemu-test] ERROR: clean halt not found in serial log" >&2
        serial_ok=0
    fi
    echo "--- Serial log (tail) ---"
    tail -5 "$SERIAL_LOG" 2>/dev/null || true
else
    echo "[qemu-test] ERROR: serial log not written: $SERIAL_LOG" >&2
    serial_ok=0
fi

[[ "$serial_ok" == "1" ]] || exit 1

echo "[qemu-test] QEMU exited cleanly (status $qemu_status)"
echo "[qemu-test] ===== done (full-system boot smoke-test complete) ====="
exit 0
