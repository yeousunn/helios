#!/usr/bin/env bash
#
# tools/bench.sh — M0 gate G3 (PLAN.md §8.1).
#
# Boots the BENCH=1 image (`sdk --bin bench` as the kernel's init image),
# parses the cycle counts the bench program prints on the debug endpoint,
# stores them as `bench/results/<commit>.json`, and with `--compare` fails
# when any metric regressed by more than 5% against the previous result.
#
# To tame run-to-run cycle-count noise (TCG/jitter makes the same HEAD swing
# tens of percent), the image is booted `BENCH_RUNS` times (default 3) and the
# minimum cycle count per metric is used — noise only adds cycles, so the
# minimum is the best estimate of the true cost. Each result record stores the
# QEMU options and a UTC timestamp so regressions can be interpreted against
# the harness conditions that produced them.
#
# Usage:
#   tools/bench.sh               # build, boot (BENCH_RUNS times), measure, store
#   tools/bench.sh --compare     # same, plus fail on >5% regression
#
# Environment: CARGO_TARGET_DIR, TARGET, QEMU, QEMU_TIMEOUT, SERIAL_LOG,
#              BENCH_RUNS   (boots per run, default 3)
#              (same defaults as tools/qemu-test.sh).
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TD="${CARGO_TARGET_DIR:-target}"
TARGET="${TARGET:-x86_64-unknown-none}"
RESULTS_DIR="$ROOT/bench/results"
QEMU="${QEMU:-qemu-system-x86_64}"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-90}"
SERIAL_LOG="${SERIAL_LOG:-$TD/serial.log}"
BENCH_RUNS="${BENCH_RUNS:-5}"

compare=0
[[ "${1:-}" == "--compare" ]] && compare=1
[[ $# -le 1 ]] || { echo "[bench] ERROR: usage: tools/bench.sh [--compare]" >&2; exit 2; }

fail() { echo "[bench] ERROR: $*" >&2; exit 1; }

# Map the low byte of FNV-1a(name) (sent in the debug marker's first word,
# MARK | 0xFE00 | lo) to the benchmark name. All seven low bytes are distinct.
name_for_lo() {
    case "$1" in
        c0) echo call_reply ;;
        12) echo send_recv ;;
        11) echo notification_wake ;;
        0f) echo context_switch_same_as ;;
        18) echo context_switch_diff_as ;;
        41) echo map_4k ;;
        7e) echo unmap_4k ;;
        *)  echo "" ;;
    esac
}

ALL_NAMES="call_reply send_recv notification_wake context_switch_same_as context_switch_diff_as map_4k unmap_4k"

echo "[bench] ===== Helios microbenchmark run (G3) ====="
echo "[bench] target dir: $TD"
echo "[bench] runs per commit: $BENCH_RUNS"

# 1. Build the bench image.
echo "[bench] building sdk --bin bench"
cargo build -p sdk --bin bench --target "$TARGET" --release --features user \
    || fail "cargo build -p sdk --bin bench --release failed"
BENCH_BIN="$TD/$TARGET/release/bench"
[[ -f "$BENCH_BIN" ]] || fail "bench binary not found: $BENCH_BIN"

# 2. Rebuild kernel-boot with the bench binary as its init image, so the
#    kernel stages and enters `bench` exactly like `init`.
echo "[bench] rebuilding kernel-boot with INIT_IMAGE=$BENCH_BIN"
INIT_IMAGE="$BENCH_BIN" cargo build -p kernel-boot --target "$TARGET" --release --features boot \
    || fail "cargo build -p kernel-boot --release --features boot failed"
KERNEL_ELF="$TD/$TARGET/release/kernel-boot"
[[ -f "$KERNEL_ELF" ]] || fail "kernel ELF not found: $KERNEL_ELF"

# 3. Pick a host-accelerated machine type; fall back to TCG.
case "$(uname -m)-$(uname -s)" in
    arm64-Darwin)  QEMU_ACCEL="tcg" ;;
    x86_64-Darwin) QEMU_ACCEL="hvf" ;;
    x86_64-Linux)  QEMU_ACCEL="kvm" ;;
    *)             QEMU_ACCEL="tcg" ;;
esac

if command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN=gtimeout;
elif command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN=timeout;
else fail "neither 'timeout' nor 'gtimeout' found on PATH"; fi

# Harness conditions recorded with every result (noise interpretation).
QEMU_SUMMARY="accel=$QEMU_ACCEL cpu=max m=256M"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

prefix='w=[0x494e49540000fe'

# Boot once, require DONE + clean halt, append "name cycles" lines to stdout.
boot_and_parse() {
    rm -f "$SERIAL_LOG"
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
        </dev/null >/tmp/helios-bench-stdout.log 2>/tmp/helios-bench-stderr.log
    qemu_status=$?
    set -e

    case "$qemu_status" in
        1) ci_code=0 ;;   # clean halt
        3) ci_code=2 ;;   # kernel panic
        5) ci_code=3 ;;   # unhandled fault / shutdown
        7) ci_code=4 ;;   # boot timeout
        124) ci_code=4 ;; # harness timeout
        255) ci_code=255 ;;
        *) ci_code=1 ;;
    esac

    if [[ "$ci_code" != "0" ]]; then
        echo "[bench] QEMU exited with status $qemu_status (CI code $ci_code)"
        cat /tmp/helios-bench-stderr.log 2>/dev/null || true
        echo "--- Serial log ---"
        cat "$SERIAL_LOG" 2>/dev/null || true
        exit "$ci_code"
    fi

    [[ -f "$SERIAL_LOG" ]] || fail "serial log not written: $SERIAL_LOG"
    grep -aq 'clean halt' "$SERIAL_LOG" || fail "clean halt not found in serial log"
    grep -aq '494e49540000000f' "$SERIAL_LOG" || fail "DONE marker not found in serial log"

    grep -a 'userspace\[debug\]:' "$SERIAL_LOG" | grep -F "$prefix" | while IFS= read -r line; do
        rest="${line#*$prefix}"           # <lo> <cycles> 0x0 0x0]
        lo="${rest%% *}"                  # lo byte (e.g. c0)
        rest2="${rest#* }"                # <cycles> 0x0 0x0]
        cyc="${rest2%% *}"                # cycles
        name="$(name_for_lo "$lo")"
        if [[ -z "$name" ]]; then
            echo "[bench] WARN: unknown bench lo byte $lo (cycles $cyc)" >&2
            continue
        fi
        echo "$name $cyc"
    done
}

# 4. Run the bench image BENCH_RUNS times, collecting every reported marker.
TMP_RESULTS="$(mktemp)"
trap 'rm -f "$TMP_RESULTS"' EXIT
: > "$TMP_RESULTS"

for (( run = 1; run <= BENCH_RUNS; run++ )); do
    echo "[bench] --- QEMU boot run $run/$BENCH_RUNS (accel=$QEMU_ACCEL, init=$BENCH_BIN) ---"
    boot_and_parse >> "$TMP_RESULTS"
done
echo "[bench] clean halt + DONE marker confirmed on all $BENCH_RUNS runs"

# 5. Reduce to the minimum cycle count per metric across runs. A benchmark
#    that does not report a result (not yet implemented, or blocked on
#    per-thread stacks) is skipped with a warning; only reported metrics are
#    stored and compared.
declare -a present=()
for name in $ALL_NAMES; do
    best=""
    while IFS=' ' read -r n c; do
        [[ "$n" == "$name" ]] || continue
        c=$(( c ))  # hex "0x.." -> decimal
        if [[ -z "$best" || "$c" -lt "$best" ]]; then best="$c"; fi
    done < "$TMP_RESULTS"
    if [[ -z "$best" ]]; then
        echo "[bench] WARN: no result reported for $name (skipping)" >&2
        continue
    fi
    eval "CYCLES_$name='$best'"
    present+=("$name")
done
[[ "${#present[@]}" -gt 0 ]] || fail "no bench results were reported at all"

# 6. Store results (only metrics that were actually reported).
COMMIT="$(git rev-parse --verify --quiet HEAD 2>/dev/null || echo unknown)"
mkdir -p "$RESULTS_DIR"
{
    echo "{"
    echo "  \"commit\": \"$COMMIT\","
    echo "  \"bin\": \"sdk --bin bench\","
    echo "  \"target\": \"$TARGET\","
    echo "  \"runs\": $BENCH_RUNS,"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"qemu\": \"$QEMU_SUMMARY\","
    echo "  \"cycles\": {"
    first=1
    for name in "${present[@]}"; do
        eval "cyc=\$CYCLES_$name"
        cyc=$(( cyc ))
        if [[ $first -eq 1 ]]; then first=0; else echo ","; fi
        printf '    "%s": %s' "$name" "$cyc"
    done
    echo ""
    echo "  }"
    echo "}"
} > "$RESULTS_DIR/$COMMIT.json"
echo "[bench] results stored: $RESULTS_DIR/$COMMIT.json"
for name in "${present[@]}"; do
    eval "cyc=\$CYCLES_$name"
    echo "[bench]   $name: $cyc cycles (min over $BENCH_RUNS runs)"
done

# 7. --compare: fail on any regression above 5% versus the previous result.
if [[ "$compare" -eq 1 ]]; then
    prev=""
    prev_commit="$(git rev-parse --verify --quiet "HEAD~1" 2>/dev/null || echo unknown)"
    if [[ "$prev_commit" != "unknown" && -f "$RESULTS_DIR/$prev_commit.json" ]]; then
        prev="$RESULTS_DIR/$prev_commit.json"
    else
        shopt -s nullglob
        set -- "$RESULTS_DIR"/*.json
        shopt -u nullglob
        latest=""
        for f in "$@"; do
            [[ "$(basename "$f")" == "$COMMIT.json" ]] && continue
            if [[ -z "$latest" || "$f" -nt "$latest" ]]; then
                latest="$f"
            fi
        done
        prev="$latest"
    fi

    if [[ -z "$prev" ]]; then
        echo "[bench] --compare: no previous result to compare against (skipping)"
        exit 0
    fi

    echo "[bench] --compare: comparing against $prev"
    fail_compare=0
    for name in "${present[@]}"; do
        eval "cur=\$CYCLES_$name"
        prev_val="$(python3 - "$prev" "$name" 2>/dev/null <<'EOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    print(data["cycles"][sys.argv[2]])
except Exception:
    pass
EOF
        )"
        if [[ -z "$prev_val" ]]; then
            echo "[bench]   $name: previous value unavailable"
            continue
        fi
        # regression threshold: current > previous * 1.05 (integer math)
        limit=$(( prev_val * 105 / 100 ))
        if [[ "$cur" -gt "$limit" ]]; then
            echo "[bench]   $name: REGRESSION $prev_val -> $cur cycles (>5%)" >&2
            fail_compare=1
        else
            echo "[bench]   $name: $prev_val -> $cur cycles OK"
        fi
    done
    [[ "$fail_compare" -eq 0 ]] || fail "benchmark regression above 5% vs $prev"
    echo "[bench] --compare: no regression above 5%"
fi

echo "[bench] ===== done ====="
exit 0
