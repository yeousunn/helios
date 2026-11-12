#!/usr/bin/env bash
# Supervisor loop for one agent: runs one opencode cycle at a time, forever,
# until .agents/STOP or .agents/STOP-<name> exists.
#
# Usage: tools/agents/run-agent.sh nv|glm|ds
set -uo pipefail

NAME="${1:?usage: run-agent.sh nv|glm|ds}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE="$REPO/.agents"
CYCLE_TIMEOUT="${CYCLE_TIMEOUT:-10800}" # 3 hours per cycle

case "$NAME" in
    nv)
        TAG="[NV]"; LABEL="Nemotron"; ROLE="coordinator and worker"
        MODEL="nvidia/nvidia/nemotron-3.5-super-vl-120b-a12b"
        ROLE_NOTE="You are the coordinator. Do the coordinator duties in AGENTS.md section 8 first, keep them short, then work one of your own tasks."
        IDLE_SLEEP=900
        ;;
    glm)
        TAG="[GLM]"; LABEL="GLM"; ROLE="kernel worker"
        MODEL="nvidia/z-ai/glm-5.3-flash"
        ROLE_NOTE="You are a worker. Nemotron [NV] is the coordinator. Work your own tasks in board order."
        IDLE_SLEEP=1200
        ;;
    ds)
        TAG="[DS]"; LABEL="DeepSeek"; ROLE="userspace worker"
        MODEL="nvidia/deepseek-ai/deepseek-v4.1-flash"
        ROLE_NOTE="You are a worker. Nemotron [NV] is the coordinator. Work your own tasks in board order."
        IDLE_SLEEP=1200
        ;;
    *) echo "unknown agent: $NAME" >&2; exit 2 ;;
esac

mkdir -p "$STATE/logs"
export OPENCODE_CONFIG="$STATE/opencode.json"
export CARGO_TARGET_DIR="$STATE/target-$NAME"
REL="$CARGO_TARGET_DIR/x86_64-unknown-none/release"
for img in INIT PS CHILD VFS POSIX CONSOLE AUTH SH CAT LS ECHO WC LINRUN LOGIN; do
    lower="$(echo "$img" | tr '[:upper:]' '[:lower:]')"
    export "${img}_IMAGE=$REL/$lower"
done
export KERNEL_ELF="$REL/kernel-boot"
export SERIAL_LOG="$STATE/serial-$NAME.log"

log() { echo "$(date '+%F %T') $*" | tee -a "$STATE/$NAME.history"; }

fails=0
cycle=0
cd "$REPO" || exit 1
log "supervisor start ($LABEL, $MODEL)"

while true; do
    if [ -f "$STATE/STOP" ] || [ -f "$STATE/STOP-$NAME" ]; then
        log "stop file found, exiting"
        exit 0
    fi

    # AGENTS.md is human-owned (and untracked: the owner's global gitignore
    # excludes it). start.sh saves a copy. Put it back if an agent changed it.
    if [ -f "$STATE/AGENTS.md.saved" ] && ! cmp -s "$STATE/AGENTS.md.saved" "$REPO/AGENTS.md"; then
        log "AGENTS.md was changed in the working tree, restoring the saved copy"
        cp "$STATE/AGENTS.md.saved" "$REPO/AGENTS.md"
    fi

    cycle=$((cycle + 1))
    out="$STATE/logs/$NAME-$(date +%Y%m%d-%H%M%S).log"
    prompt="$(sed -e "s|{{NAME}}|$LABEL|g" -e "s|{{TAG}}|$TAG|g" -e "s|{{ROLE}}|$ROLE|g" \
        -e "s|{{ROLE_NOTE}}|$ROLE_NOTE|g" -e "s|{{TARGET}}|$CARGO_TARGET_DIR|g" \
        -e "s|{{SERIAL}}|$SERIAL_LOG|g" "$STATE/prompt.md")"

    log "cycle $cycle start -> $(basename "$out")"
    gtimeout --kill-after=60 "$CYCLE_TIMEOUT" \
        opencode run -m "$MODEL" --auto --title "$TAG cycle $cycle $(date '+%F %H:%M')" \
        "$prompt" </dev/null >"$out" 2>&1
    rc=$?
    result="$(grep -aoE 'CYCLE-RESULT: [A-Z]+' "$out" | tail -n 1)"
    log "cycle $cycle end rc=$rc ${result:-no-result}"

    case "$result" in
        "CYCLE-RESULT: DONE" | "CYCLE-RESULT: PROGRESS")
            fails=0; sleep 30 ;;
        "CYCLE-RESULT: BLOCKED")
            fails=0; sleep 600 ;;
        "CYCLE-RESULT: IDLE")
            fails=0; sleep "$IDLE_SLEEP" ;;
        *)
            # Crash, timeout, rate limit or a cycle that forgot its result line.
            fails=$((fails + 1))
            delay=$((60 * (1 << (fails > 5 ? 5 : fails))))
            [ "$delay" -gt 1800 ] && delay=1800
            log "no result (failure $fails), backing off ${delay}s"
            sleep "$delay"
            ;;
    esac
done
