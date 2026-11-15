#!/usr/bin/env bash
#
# tools/verify.sh — supply-chain + formal verification for changed crates.
#
# M1 gate addition (PLAN.md §8.1: "tools/verify.sh — Verus + Kani for changed
# crates"). Runs whatever verification tooling is available in the sandbox:
#   - cargo deny (advisories / licences / sources) — always enforced here.
#   - cargo vet — not installed in the sandbox (~/.cargo is read-only, it
#     cannot be installed); reported as a blocker, not a failure.
#   - Kani / Verus — not installed; reported as a blocker. GLM's Kani
#     harnesses (kernel/src/kani.rs, commit 4b2fcd0) await this wiring.
#
# Exits 0 when the available checks pass. Missing tools are reported but do
# not fail the gate, so the gate stays green until the human owner installs
# cargo-vet / Kani / Verus and this script is wired to run them.
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

have() { command -v "$1" >/dev/null 2>&1; }

echo "[verify] cargo deny check (advisories / licences / sources)"
cargo deny check || { echo "[verify] cargo deny FAILED" >&2; exit 1; }

if have cargo-vet; then
    echo "[verify] cargo vet"
    cargo vet || { echo "[verify] cargo vet FAILED" >&2; exit 1; }
else
    echo "[verify] cargo vet NOT installed — skipping"
    echo "[verify]   blocker: cargo-vet is not installed and ~/.cargo is read-only"
fi

if have kani || have cargo-kani; then
    echo "[verify] Kani tooling present — not yet wired to kernel/src/kani.rs"
else
    echo "[verify] kani NOT installed — skipping"
    echo "[verify]   blocker: Kani is not installed; GLM's Kani harnesses (4b2fcd0)"
    echo "[verify]   await tools/verify.sh wiring once Kani is available"
fi

if have verus; then
    echo "[verify] verus present — not yet wired"
else
    echo "[verify] verus NOT installed — skipping"
fi

echo "[verify] OK — available supply-chain checks passed"
