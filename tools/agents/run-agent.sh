#!/usr/bin/env bash
# Supervisor loop for one agent. start.sh copies this file into the control
# directory and runs it from there. Each cycle runs one fresh opencode session
# inside the macOS sandbox (sandbox.sb), then audits the commits it made.
# The loop ends when $CTRL/STOP or $CTRL/STOP-<name> exists, or on any
# integrity or ownership violation (fail closed).
#
# Usage: run-agent.sh nv|glm|ds
set -uo pipefail

NAME="${1:?usage: run-agent.sh nv|glm|ds}"
CTRL="${HELIOS_CTRL:-$HOME/.local/state/helios-agents}"
REPO="$(cat "$CTRL/repo-path")"
WORK="$REPO/.agents" # agent-writable: build dirs and serial logs only
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
TAGWORD="$(echo "$NAME" | tr '[:lower:]' '[:upper:]')"

mkdir -p "$CTRL/logs" "$WORK"
export HELIOS_AGENT="$NAME"
export OPENCODE_CONFIG="$CTRL/opencode.json"
export CARGO_TARGET_DIR="$WORK/target-$NAME"
REL="$CARGO_TARGET_DIR/x86_64-unknown-none/release"
for img in INIT PS CHILD VFS POSIX CONSOLE AUTH SH CAT LS ECHO WC LINRUN LOGIN; do
    lower="$(echo "$img" | tr '[:upper:]' '[:lower:]')"
    export "${img}_IMAGE=$REL/$lower"
done
export KERNEL_ELF="$REL/kernel-boot"
export SERIAL_LOG="$WORK/serial-$NAME.log"

log() { echo "$(date '+%F %T') $*" | tee -a "$CTRL/$NAME.history"; }

halt_all() { # reason
    echo "$(date '+%F %T') [$NAME] $1" >>"$CTRL/violations.log"
    log "VIOLATION: $1. Stopping all agents."
    touch "$CTRL/STOP"
    exit 1
}

preflight() {
    [ "$(shasum -a 256 "$REPO/AGENTS.md" | cut -d' ' -f1)" = "$(cat "$CTRL/AGENTS.md.sha256")" ] ||
        halt_all "AGENTS.md differs from the copy recorded by start.sh (re-run start.sh after a human edit)"
    if ! cmp -s "$CTRL/commit-msg" "$REPO/.git/hooks/commit-msg"; then
        log "commit-msg hook missing or changed, reinstalling"
        install -m 0755 "$CTRL/commit-msg" "$REPO/.git/hooks/commit-msg"
    fi
    [ -z "$(git -C "$REPO" config --get core.hooksPath)" ] || halt_all "core.hooksPath is set"
}

audit() { # start-commit
    git -C "$REPO" merge-base --is-ancestor "$1" HEAD || halt_all "history before $1 was rewritten"
    local c subject
    for c in $(git -C "$REPO" rev-list --reverse "$1"..HEAD); do
        subject="$(git -C "$REPO" log -1 --format=%s "$c")"
        case "$subject" in
            "[NV]"* | "[GLM]"* | "[DS]"*) ;;
            *) halt_all "untagged commit $c during a $TAG cycle: $subject" ;;
        esac
        case "$subject" in "$TAG"*) ;; *) continue ;; esac # other agents audit their own
        (cd "$REPO" && env -u HELIOS_AGENT "$CTRL/commit-msg" --audit "$c" 2>>"$CTRL/violations.log") ||
            halt_all "commit $c breaks directory ownership"
    done
}

fails=0
cycle=0
cd "$REPO" || exit 1
log "supervisor start ($LABEL, $MODEL)"

while true; do
    if [ -f "$CTRL/STOP" ] || [ -f "$CTRL/STOP-$NAME" ]; then
        log "stop file found, exiting"
        exit 0
    fi
    preflight
    start="$(git rev-parse HEAD)"

    cycle=$((cycle + 1))
    out="$CTRL/logs/$NAME-$(date +%Y%m%d-%H%M%S).log"
    prompt="$(sed -e "s|{{NAME}}|$LABEL|g" -e "s|{{TAG}}|$TAG|g" -e "s|{{ROLE}}|$ROLE|g" \
        -e "s|{{ROLE_NOTE}}|$ROLE_NOTE|g" -e "s|{{TARGET}}|$CARGO_TARGET_DIR|g" \
        -e "s|{{SERIAL}}|$SERIAL_LOG|g" "$CTRL/prompt.md")"

    log "cycle $cycle start -> $(basename "$out")"
    sandbox-exec -f "$CTRL/sandbox.sb" -D HOME="$HOME" -D REPO="$REPO" -D CTRL="$CTRL" \
        gtimeout --kill-after=60 "$CYCLE_TIMEOUT" \
        opencode run -m "$MODEL" --auto --title "$TAG cycle $cycle $(date '+%F %H:%M')" \
        "$prompt" </dev/null >"$out" 2>&1
    rc=$?
    result="$(grep -aoE 'CYCLE-RESULT: [A-Z]+' "$out" | tail -n 1)"
    log "cycle $cycle end rc=$rc ${result:-no-result} commits=$(git rev-list --count "$start"..HEAD 2>/dev/null)"
    audit "$start"

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
