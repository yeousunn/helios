#!/usr/bin/env bash
# Supervisor loop for one agent. start.sh copies this file into the control
# directory and runs it from there. Each cycle runs one fresh opencode session
# inside the macOS sandbox (sandbox.sb), then audits the commits it made.
# The loop ends when $CTRL/STOP or $CTRL/STOP-<name> exists, or on any
# integrity or ownership violation (fail closed).
#
# Usage: run-agent.sh nv|glm|ds|drv|psx
set -uo pipefail

# The supervisor never runs programs from PATH entries an agent could reach.
# The agent gets the owner's PATH (recorded by start.sh) only inside the
# sandbox, where every directory on it is read-only.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"

NAME="${1:?usage: run-agent.sh nv|glm|ds|drv|psx}"
CTRL="${HELIOS_CTRL:-$HOME/.local/state/helios-agents}"
REPO="$(cat "$CTRL/repo-path")"
AGENT_PATH="$(cat "$CTRL/agent-path")"
OPENCODE_BIN="$(cat "$CTRL/opencode-bin")"
GTIMEOUT_BIN="$(command -v gtimeout)"
TMP_REAL="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
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
    drv)
        TAG="[DRV]"; LABEL="Drivers"; ROLE="drivers and graphics worker"
        MODEL="nvidia/poolside/laguna-xs-2.1"
        ROLE_NOTE="You are a worker. Nemotron [NV] is the coordinator. Work your own tasks in board order."
        IDLE_SLEEP=1200
        ;;
    psx)
        TAG="[PSX]"; LABEL="POSIX"; ROLE="POSIX personality worker"
        MODEL="nvidia/stepfun-ai/step-5-preview"
        ROLE_NOTE="You are a worker. Nemotron [NV] is the coordinator. Work your own tasks in board order."
        IDLE_SLEEP=1200
        ;;
    *) echo "unknown agent: $NAME" >&2; exit 2 ;;
esac

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

# The supervisor's own git calls ignore hooks, fsmonitor and system config,
# so nothing the agent planted in the repo runs with supervisor rights.
export GIT_CONFIG_NOSYSTEM=1
g() { git -C "$REPO" -c core.hooksPath=/dev/null -c core.fsmonitor= "$@"; }

# Per-agent sandbox profile: the base rules plus write access to the agent's
# own directories only. Ownership is enforced by the file system, not by tags.
case "$NAME" in
    glm) OWN_DIRS="kernel kernel-boot caps ipc spec"; OWN_ROOT="kernel.ld" ;;
    ds) OWN_DIRS="servers sdk"; OWN_ROOT="" ;;
    drv) OWN_DIRS="drivers graphics"; OWN_ROOT="" ;;
    psx) OWN_DIRS="personality"; OWN_ROOT="" ;;
    nv) OWN_DIRS="hal tools bench tests .github docs .cargo"
        OWN_ROOT="PLAN.md Cargo.toml .gitignore .gitattributes README.md LICENSE LICENSE-MIT LICENSE-APACHE" ;;
esac
ALL_ROOT="kernel.ld PLAN.md Cargo.toml .gitignore .gitattributes README.md LICENSE LICENSE-MIT LICENSE-APACHE"
re_escape() { printf '%s' "$1" | sed 's/[][\.*^$()+?{}|]/\\&/g'; }

make_profile() {
    local p="$CTRL/sandbox-$NAME.sb" re d f
    re="$(re_escape "$REPO")"
    {
        cat "$CTRL/sandbox.sb"
        # Root-level files (shared TASKS.md and Cargo.lock, and the temp files
        # that in-place editors create next to them). Owned root files are
        # carved out again below.
        echo "(allow file-write* (regex #\"^$re/[^/]+\$\"))"
        echo "(allow file-write* (regex #\"^$re/docs/DECISIONS\\.md[^/]*\$\"))"
        echo "(allow file-write* (subpath \"$REPO/.git\") (subpath \"$WORK/target-$NAME\") (literal \"$WORK/serial-$NAME.log\"))"
        for d in $OWN_DIRS; do echo "(allow file-write* (subpath \"$REPO/$d\"))"; done
        for f in $ALL_ROOT; do
            case " $OWN_ROOT " in *" $f "*) ;; *) echo "(deny file-write* (literal \"$REPO/$f\"))" ;; esac
        done
        # No agent may rename, replace or delete an existing top-level entry
        # (a directory node or a root file) except the shared files and its
        # own root files. Writes inside owned directories stay allowed.
        # Names go into the profile text, so only plain names are accepted;
        # anything else (quotes, brackets, spaces, control characters) could
        # inject sandbox rules, and stops everything instead.
        local e path
        while IFS= read -r -d '' path; do
            e="${path##*/}"
            [[ "$e" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "BADNAME"; break; }
            case " TASKS.md Cargo.lock $OWN_ROOT " in *" $e "*) continue ;; esac
            echo "(deny file-write* (literal \"$REPO/$e\"))"
        done < <(find "$REPO" -mindepth 1 -maxdepth 1 -print0)
        echo "(deny file-write* (literal \"$REPO/AGENTS.md\") (subpath \"$REPO/tools/agents\"))"
        echo "(deny file-write* (literal \"$REPO/.git\") (subpath \"$REPO/.git/hooks\") (subpath \"$REPO/.git/info\")"
        echo "    (literal \"$REPO/.git/config\") (literal \"$REPO/.git/config.worktree\") (literal \"$REPO/.git/commondir\"))"
    } >"$p"
    echo "$p"
}

halt_all() { # reason
    # Reasons can quote commit subjects and file names, which agents control.
    # Strip control characters so nothing can rewrite the owner's terminal.
    local reason
    reason="$(printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177' | cut -c1-300)"
    echo "$(date '+%F %T') [$NAME] $reason" >>"$CTRL/violations.log"
    log "VIOLATION: $reason. Stopping all agents."
    # start.sh refuses to run while HALTED exists, until the owner has looked.
    echo "$(date '+%F %T') [$NAME] $reason (HEAD $(g rev-parse --short HEAD 2>/dev/null))" >>"$CTRL/HALTED"
    touch "$CTRL/STOP"
    exit 1
}

preflight() {
    [ -d "$REPO/.git" ] && [ ! -L "$REPO/.git" ] || halt_all ".git is not a plain directory"
    [ "$(shasum -a 256 "$REPO/AGENTS.md" | cut -d' ' -f1)" = "$(cat "$CTRL/AGENTS.md.sha256")" ] ||
        halt_all "AGENTS.md differs from the copy recorded by start.sh (re-run start.sh after a human edit)"
    if ! cmp -s "$CTRL/commit-msg" "$REPO/.git/hooks/commit-msg"; then
        log "commit-msg hook missing or changed, reinstalling"
        install -m 0755 "$CTRL/commit-msg" "$REPO/.git/hooks/commit-msg"
    fi
    local extra
    extra="$(ls -A "$REPO/.git/hooks" | grep -v -e '\.sample$' -e '^commit-msg$')"
    [ -z "$extra" ] || halt_all "unexpected git hooks: $extra"
    # Plain git here, not g(): g() itself overrides hooksPath.
    [ -z "$(git -C "$REPO" config --get core.hooksPath)" ] || halt_all "core.hooksPath is set, the ownership hook would not run"
    [ "$(g symbolic-ref -q HEAD)" = "refs/heads/main" ] || halt_all "HEAD is not on main"
}

refs_except_main() { g for-each-ref --format='%(refname) %(objectname)' | grep -v '^refs/heads/main '; }

audit() { # start-commit refs-before
    [ "$(g symbolic-ref -q HEAD)" = "refs/heads/main" ] || halt_all "HEAD left main during the cycle"
    [ "$(refs_except_main)" = "$2" ] || halt_all "branches, tags or other refs changed during the cycle"
    g merge-base --is-ancestor "$1" HEAD || halt_all "history before $1 was rewritten"
    [ -z "$(g rev-list --min-parents=2 "$1"..HEAD)" ] || halt_all "merge commit during the cycle"
    local c subject
    # Every new commit, whoever made it: tagged, and touching only files its tag owns.
    for c in $(g rev-list --reverse "$1"..HEAD); do
        subject="$(g log -1 --format=%s "$c")"
        case "$subject" in
            "[NV]"* | "[GLM]"* | "[DS]"* | "[DRV]"* | "[PSX]"*) ;;
            *) halt_all "untagged commit $c during a $TAG cycle: $subject" ;;
        esac
        (cd "$REPO" && env -u HELIOS_AGENT "$CTRL/commit-msg" --audit "$c" 2>>"$CTRL/violations.log") ||
            halt_all "commit $c breaks directory ownership"
    done
    decisions_append_only "$1"
    unsafe_baseline_shrinks "$1"
    worktree_check "$1"
}

# tools/unsafe-baseline.txt lists the files allowed to keep unsafe code outside
# the allowlist, with a count each (PLAN.md 7.1). It may only shrink: no new
# file, no higher count. Lines are "<path> <count>", comments start with '#'.
unsafe_baseline_shrinks() { # start-commit
    local bad
    g cat-file -e "$1:tools/unsafe-baseline.txt" 2>/dev/null || return 0
    bad="$(awk 'FNR == NR { if ($0 !~ /^#/ && NF >= 2) old[$1] = $2; next }
                $0 ~ /^#/ || NF < 2 { next }
                !($1 in old) || $2 + 0 > old[$1] + 0 { print $1 }' \
        <(g cat-file blob "$1:tools/unsafe-baseline.txt") \
        <(g cat-file blob "HEAD:tools/unsafe-baseline.txt" 2>/dev/null))"
    [ -z "$bad" ] || halt_all "tools/unsafe-baseline.txt grew during the cycle: $(echo $bad)"
}

# docs/DECISIONS.md is append-only (AGENTS.md section 4): the file as it was
# before the cycle must still be the exact start of the file at HEAD.
# Compared through pipes, with no temp files: the temp directory is writable by
# every sandboxed agent, so a file there could be swapped mid-check.
decisions_append_only() { # start-commit
    local n
    g cat-file -e "$1:docs/DECISIONS.md" 2>/dev/null || return 0
    n="$(g cat-file -s "$1:docs/DECISIONS.md")"
    if ! cmp -s <(g cat-file blob "$1:docs/DECISIONS.md") \
        <(g cat-file blob "HEAD:docs/DECISIONS.md" 2>/dev/null | head -c "$n"); then
        halt_all "docs/DECISIONS.md was edited above its end during the cycle (append-only)"
    fi
}

blob_or_none() { g rev-parse -q --verify "$1" 2>/dev/null || echo none; }

# Commits built with git plumbing can carry another agent's tag and touch only
# that agent's files, without the sandbox ever letting the forger write those
# files on disk. Whatever chain of commits it uses, the file on disk is left at
# its version from before the cycle while history moved on. An honest change
# never looks like that: its author edited the file on disk first.
worktree_check() { # start-commit
    local p at_start at_head on_disk
    while IFS= read -r -d '' p; do
        case "$p" in TASKS.md | docs/DECISIONS.md | Cargo.lock) continue ;; esac
        at_start="$(blob_or_none "$1:$p")"
        at_head="$(blob_or_none "HEAD:$p")"
        [ "$at_start" != "$at_head" ] || continue
        if [ -f "$REPO/$p" ] && [ ! -L "$REPO/$p" ]; then
            on_disk="$(g hash-object --no-filters -- "$REPO/$p")"
        elif [ -e "$REPO/$p" ] || [ -L "$REPO/$p" ]; then
            halt_all "$p changed during the cycle and is not a regular file on disk"
        else
            on_disk=none
        fi
        if [ "$on_disk" = "$at_start" ]; then
            halt_all "$p changed in history during the cycle, but the file on disk still has its version from before (changed only inside .git)"
        fi
    done < <(g -c core.quotePath=false diff -z --name-only --no-renames "$1" HEAD)
}

if [ "${2:-}" = "--print-profile" ]; then # for testing: write and print the profile, then exit
    cat "$(make_profile)"
    exit 0
fi

fails=0
cycle=0
cd "$REPO" || exit 1
DEFAULT_MODEL="$MODEL"
# The owner can switch an agent's model without a commit by writing one model
# id into $CTRL/model-<name> (outside the sandbox, so agents cannot change it).
# It is read before every cycle. Delete the file to go back to the default.
pick_model() {
    MODEL="$DEFAULT_MODEL"
    [ -f "$CTRL/model-$NAME" ] || return 0
    local m
    m="$(head -n 1 "$CTRL/model-$NAME" | tr -d '[:space:]')"
    if ! printf '%s' "$m" | grep -Eq '^[A-Za-z0-9._/-]+$'; then
        halt_all "$CTRL/model-$NAME does not hold a valid model id"
    fi
    MODEL="$m"
}
pick_model
log "supervisor start ($LABEL, $MODEL)"

while true; do
    if [ -f "$CTRL/STOP" ] || [ -f "$CTRL/STOP-$NAME" ]; then
        log "stop file found, exiting"
        exit 0
    fi
    preflight
    start="$(g rev-parse HEAD)"
    refs_before="$(refs_except_main)"
    profile="$(make_profile)"
    if [ ! -s "$profile" ] || grep -qx 'BADNAME' "$profile"; then
        halt_all "a top-level entry in the repo has a name with characters other than letters, digits, '.', '_' or '-'"
    fi

    pick_model
    cycle=$((cycle + 1))
    out="$CTRL/logs/$NAME-$(date +%Y%m%d-%H%M%S).log"
    prompt="$(sed -e "s|{{NAME}}|$LABEL|g" -e "s|{{TAG}}|$TAG|g" -e "s|{{ROLE}}|$ROLE|g" \
        -e "s|{{ROLE_NOTE}}|$ROLE_NOTE|g" -e "s|{{TARGET}}|$CARGO_TARGET_DIR|g" \
        -e "s|{{SERIAL}}|$SERIAL_LOG|g" "$CTRL/prompt.md")"

    log "cycle $cycle start ($MODEL) -> $(basename "$out")"
    sandbox-exec -f "$profile" -D HOME="$HOME" -D CTRL="$CTRL" -D TMP="$TMP_REAL" \
        "$GTIMEOUT_BIN" --kill-after=60 "$CYCLE_TIMEOUT" \
        /usr/bin/env PATH="$AGENT_PATH" \
        "$OPENCODE_BIN" run -m "$MODEL" --auto --title "$TAG cycle $cycle $(date '+%F %H:%M')" \
        "$prompt" </dev/null >"$out" 2>&1
    rc=$?
    result="$(grep -aoE 'CYCLE-RESULT: [A-Z]+' "$out" | tail -n 1)"
    log "cycle $cycle end rc=$rc ${result:-no-result} commits=$(g rev-list --count "$start"..HEAD 2>/dev/null)"
    audit "$start" "$refs_before"

    case "$result" in
        "CYCLE-RESULT: DONE" | "CYCLE-RESULT: PROGRESS")
            fails=0; sleep 30 ;;
        "CYCLE-RESULT: BLOCKED")
            # Blocked on another agent: wait long enough for that agent to move.
            fails=0; sleep 1800 ;;
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
