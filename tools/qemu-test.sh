#!/usr/bin/env bash
#
# tools/qemu-test.sh — Phase 0 QEMU bring-up test.
#
# Runs the workspace quality gates and, when QEMU is available, boots an
# x86_64 kernel image capturing the serial (UART) log.
#
# Usage:
#   tools/qemu-test.sh [qemu-extra-args...]
#
# Exit codes (ADR-013):
#   0 — quality gates pass (and QEMU boot, if attempted, succeeded)
#   1 — a quality gate failed
#   2 — QEMU exit code 1 (kernel panic)
#   3 — QEMU exit code 2 (unhandled fault / shutdown)
#   4 — QEMU exit code 3 (boot timeout)
#   5 — QEMU exit code 4 (userspace test process failure)
#   255 — QEMU failed to launch / harness error
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

KERNEL_ELF="${KERNEL_ELF:-target/x86_64-unknown-none/debug/kernel-boot}"
INITRD="${INITRD:-build/initrd.img}"
QEMU_BIN="${QEMU:-qemu-system-x86_64}"
SERIAL_LOG="${SERIAL_LOG:-/tmp/helios-serial.log}"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-30}"

fail() {
    echo "[qemu-test] ERROR: $*" >&2
    exit 1
}

# ADR-013 exit-code mapping: qemu exit status -> CI failure code
qemu_exit_to_ci() {
    case "$1" in
        0) echo 0 ;;   # clean bring-up halt
        1) echo 2 ;;   # kernel panic
        2) echo 3 ;;   # unhandled fault / shutdown
        3) echo 4 ;;   # boot timeout
        4) echo 5 ;;   # userspace test process failure
        255) echo 255 ;; # QEMU failed to launch / harness error
        *) echo 1 ;;   # unexpected qemu exit code
    esac
}

echo "[qemu-test] ===== Helios Phase 0 QEMU bring-up ====="
echo "[qemu-test] workspace root: $ROOT"

# ---------------------------------------------------------------------------
# 1. Quality gates (always run)
# ---------------------------------------------------------------------------

echo "[qemu-test] --- cargo build ---"
cargo build --workspace --exclude kernel-boot || fail "cargo build failed"

echo "[qemu-test] --- cargo build -p kernel-boot --target x86_64-unknown-none ---"
cargo build -p kernel-boot --target x86_64-unknown-none || fail "cargo build -p kernel-boot --target x86_64-unknown-none failed"

echo "[qemu-test] --- cargo clippy -p kernel-boot --target x86_64-unknown-none -- -D warnings ---"
cargo clippy -p kernel-boot --target x86_64-unknown-none -- -D warnings || fail "cargo clippy -p kernel-boot failed"

echo "[qemu-test] --- cargo clippy --workspace --exclude kernel-boot -- -D warnings ---"
cargo clippy --workspace --exclude kernel-boot -- -D warnings || fail "cargo clippy --workspace failed"

echo "[qemu-test] --- cargo fmt --check ---"
cargo fmt --check || fail "cargo fmt --check failed (run 'cargo fmt')"

# ---------------------------------------------------------------------------
# 2. QEMU boot (conditional on QEMU being installed)
# ---------------------------------------------------------------------------

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
    echo
    echo "[qemu-test] WARN: '$QEMU_BIN' not found on PATH."
    echo "[qemu-test]       Install it (e.g. 'brew install qemu' on macOS) to enable boot tests."
    echo "[qemu-test]       Quality gates passed; QEMU boot skipped."
    echo "[qemu-test] ===== done (boot skipped) ====="
    exit 0
fi

if [[ ! -f "$KERNEL_ELF" ]]; then
    echo
    echo "[qemu-test] WARN: '$KERNEL_ELF' not found."
    echo "[qemu-test]       Build it first: cargo build -p kernel-boot --target x86_64-unknown-none"
    echo "[qemu-test]       Quality gates passed; QEMU boot skipped."
    echo "[qemu-test] ===== done (boot skipped) ====="
    exit 0
fi

echo "[qemu-test] --- QEMU boot: $QEMU_BIN ---"

# Pick a host-accelerated machine type when available; fall back to TCG.
# On Apple Silicon (arm64), hvf/kvm are unavailable for x86_64 emulation;
# use TCG (slow but works everywhere).
case "$(uname -m)-$(uname -s)" in
    arm64-Darwin)  QEMU_ACCEL="tcg" ;;
    x86_64-Darwin) QEMU_ACCEL="hvf" ;;
    x86_64-Linux)  QEMU_ACCEL="kvm" ;;
    *)             QEMU_ACCEL="tcg" ;;
esac

# Build initrd if it doesn't exist
if [[ ! -f "$INITRD" ]]; then
    echo "[qemu-test] Building initrd..."
    mkdir -p build
    # Find init and PS binaries
    INIT_ELF="target/x86_64-unknown-none/release/init"
    PS_ELF="target/x86_64-unknown-none/release/ps"
    if [[ -f "$INIT_ELF" ]]; then
        cp "$INIT_ELF" build/init
    fi
    if [[ -f "$PS_ELF" ]]; then
        cp "$PS_ELF" build/ps
    fi
    if [[ -f build/init ]] || [[ -f build/ps ]]; then
        cat build/init build/ps > "$INITRD" 2>/dev/null || true
    fi
fi

# Run QEMU with the kernel image
set +e
if [[ -f "$INITRD" ]]; then
    timeout "${QEMU_TIMEOUT}" "$QEMU_BIN" \
        -machine accel="$QEMU_ACCEL" \
        -cpu max \
        -m 256M \
        -kernel "$KERNEL_ELF" \
        -initrd "$INITRD" \
        -serial file:"$SERIAL_LOG" \
        -display none \
        -no-reboot \
        -device isa-debug-exit,iobase=0x501,iosize=0x02 \
        -nographic \
        ${1+"$@"} \
        >/tmp/helios-qemu-stdout.log 2>/tmp/helios-qemu-stderr.log
else
    timeout "${QEMU_TIMEOUT}" "$QEMU_BIN" \
        -machine accel="$QEMU_ACCEL" \
        -cpu max \
        -m 256M \
        -kernel "$KERNEL_ELF" \
        -serial file:"$SERIAL_LOG" \
        -display none \
        -no-reboot \
        -device isa-debug-exit,iobase=0x501,iosize=0x02 \
        -nographic \
        ${1+"$@"} \
        >/tmp/helios-qemu-stdout.log 2>/tmp/helios-qemu-stderr.log
fi
qemu_status=$?
set -e

ci_code="$(qemu_exit_to_ci "$qemu_status")"
if [[ "$ci_code" != "0" ]]; then
    echo "[qemu-test] QEMU exited with status $qemu_status (CI code $ci_code)"
    cat /tmp/helios-qemu-stderr.log 2>/dev/null || true
    echo "--- Serial log ---"
    cat "$SERIAL_LOG" 2>/dev/null || true
    exit "$ci_code"
fi

echo "[qemu-test] QEMU exited cleanly (status $qemu_status)"
if [[ -f "$SERIAL_LOG" ]]; then
    echo "[qemu-test] Serial log captured at: $SERIAL_LOG"
    echo "--- Serial log contents ---"
    cat "$SERIAL_LOG" 2>/dev/null || true
fi

echo "[qemu-test] ===== done (boot smoke-test complete) ====="
