#!/usr/bin/env bash
# Start the unattended agents in a tmux session named "helios-agents".
#
#   tools/agents/start.sh            start all three (NV first, then GLM, DS)
#   tools/agents/start.sh glm        start one agent
#
# Control files (config, prompt, sandbox, supervisor, hook, logs) live in
# ~/.local/state/helios-agents, which the sandboxed agents cannot write.
# Build directories and serial logs live in <repo>/.agents.
#
# Stop with tools/agents/stop.sh. Watch with tools/agents/status.sh or
# `tmux attach -t helios-agents`. Stop the agents before you commit yourself:
# the audit treats an untagged commit during a cycle as a violation.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO/tools/agents"
CTRL="${HELIOS_CTRL:-$HOME/.local/state/helios-agents}"
SESSION="helios-agents"
ACK=0
AGENTS=()
for arg in "$@"; do
    case "$arg" in
        --acknowledge) ACK=1 ;;
        *) AGENTS+=("$arg") ;;
    esac
done
[ "${#AGENTS[@]}" -gt 0 ] || AGENTS=(nv glm ds)

# After a violation, the supervisors leave HALTED behind. Look at it first.
if [ -f "$CTRL/HALTED" ]; then
    echo "The agents were stopped by a violation:" >&2
    LC_ALL=C tr -cd '[:print:]\n' <"$CTRL/HALTED" | sed 's/^/  /' >&2
    echo "Details: $CTRL/violations.log" >&2
    if [ "$ACK" != 1 ]; then
        echo "Check the commits named above (git log, git show). When you are satisfied," >&2
        echo "run: tools/agents/start.sh --acknowledge" >&2
        exit 1
    fi
    mv "$CTRL/HALTED" "$CTRL/HALTED.acknowledged-$(date +%Y%m%d-%H%M%S)"
fi

for bin in opencode tmux gtimeout sandbox-exec shasum qemu-system-x86_64 cargo; do
    command -v "$bin" >/dev/null || { echo "missing: $bin" >&2; exit 1; }
done

# Interactive opencode sessions in this repo would fight over the same files.
busy=""
for p in $(pgrep -f '^opencode' || true); do
    cwd="$(lsof -a -p "$p" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')"
    [ "$cwd" = "$REPO" ] && busy="$busy $p"
done
if [ -n "$busy" ] && [ "${FORCE:-0}" != 1 ]; then
    echo "Interactive opencode processes are still open in this repo (pids:$busy)." >&2
    echo "Quit them first, or run with FORCE=1 to start anyway." >&2
    exit 1
fi

# Uncommitted changes are usually an agent's unfinished work from a cycle that
# was stopped. Its owner picks them up next cycle, and the commit hook keeps
# every other agent from committing them. Edits of my own would be committed by
# whichever agent owns the path, so the owner confirms the list first.
if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]; then
    echo "Uncommitted changes in the repo:" >&2
    git -C "$REPO" status --short --untracked-files=no | LC_ALL=C tr -cd '[:print:]\n' >&2
    if [ "${ACCEPT_WIP:-0}" != 1 ]; then
        printf 'The owning agent will continue and commit these. Type yes if none of them are yours: '
        read -r answer </dev/tty
        [ "$answer" = "yes" ] || { echo "nothing started" >&2; exit 1; }
    fi
fi

mkdir -p "$CTRL/logs" "$REPO/.agents"
rm -f "$CTRL/STOP"
for a in "${AGENTS[@]}"; do rm -f "$CTRL/STOP-$a"; done

# Control copies come from the working tree, which the sandbox never lets an
# agent write, and only when it matches HEAD. Agents can write git objects, so
# a forged commit touching tools/agents makes the working tree differ from HEAD
# and stops the start here.
# Compare bytes on disk with the HEAD blobs directly. Agents can write the git
# index (for example an assume-unchanged flag), so git diff is not trusted here.
for f in sandbox.sb opencode.json prompt.md run-agent.sh start.sh stop.sh status.sh hooks/commit-msg; do
    on_disk="$(git -C "$REPO" hash-object --no-filters -- "$SRC/$f")"
    in_head="$(git -C "$REPO" rev-parse -q --verify "HEAD:tools/agents/$f" || echo none)"
    if [ "$on_disk" != "$in_head" ]; then
        echo "tools/agents/$f differs from HEAD. A commit changed the supervisor files" >&2
        echo "without the working tree following, or the file has uncommitted edits." >&2
        echo "Inspect: git log -p -- tools/agents" >&2
        exit 1
    fi
done

# The supervisor runs outside the sandbox, so any change to it since the last
# start must be approved by the owner.
FILES=(sandbox.sb opencode.json prompt.md run-agent.sh hooks/commit-msg)
changed=0
for f in "${FILES[@]}" ; do
    old="$CTRL/approved/$(basename "$f")"
    if [ -f "$old" ] && ! cmp -s "$old" "$SRC/$f"; then changed=1; diff -u "$old" "$SRC/$f" || true; fi
done
if [ -f "$CTRL/approved/AGENTS.md" ] && ! cmp -s "$CTRL/approved/AGENTS.md" "$REPO/AGENTS.md"; then
    changed=1; diff -u "$CTRL/approved/AGENTS.md" "$REPO/AGENTS.md" || true
fi
if [ "$changed" = 1 ] && [ "${ACCEPT_CONTROL_CHANGES:-0}" != 1 ]; then
    printf '\nThe supervisor files or AGENTS.md changed since the last start (diff above).\nType yes to approve: '
    read -r answer </dev/tty
    [ "$answer" = "yes" ] || { echo "not approved, nothing started" >&2; exit 1; }
fi
mkdir -p "$CTRL/approved"
for f in "${FILES[@]}"; do
    cp "$SRC/$f" "$CTRL/$(basename "$f")"
    cp "$SRC/$f" "$CTRL/approved/$(basename "$f")"
done
cp "$REPO/AGENTS.md" "$CTRL/approved/AGENTS.md"
echo "$REPO" >"$CTRL/repo-path"
# The agents run with this PATH, inside the sandbox only. The supervisor itself
# uses a fixed system PATH and calls opencode by absolute path.
echo "$PATH" >"$CTRL/agent-path"
command -v opencode >"$CTRL/opencode-bin"
shasum -a 256 "$REPO/AGENTS.md" | cut -d' ' -f1 >"$CTRL/AGENTS.md.sha256"
chmod 0755 "$CTRL/run-agent.sh" "$CTRL/commit-msg"
install -m 0755 "$CTRL/commit-msg" "$REPO/.git/hooks/commit-msg"

if ! tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux new-session -d -s "$SESSION" -n keepawake -c "$REPO" "caffeinate -dims"
fi

delay=0
for a in "${AGENTS[@]}"; do
    if tmux list-windows -t "$SESSION" -F '#W' | grep -qx "$a"; then
        echo "$a already running"
        continue
    fi
    tmux new-window -d -t "$SESSION" -n "$a" -c "$REPO" \
        "sleep $delay; HELIOS_CTRL='$CTRL' '$CTRL/run-agent.sh' $a; echo '[supervisor exited]'; sleep 86400"
    echo "started $a (after ${delay}s)"
    delay=$((delay + 120))
done

echo "tmux session: $SESSION   control and logs: $CTRL"
