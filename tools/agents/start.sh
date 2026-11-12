#!/usr/bin/env bash
# Start the unattended agents in a tmux session named "helios-agents".
#
#   tools/agents/start.sh            start all three (NV first, then GLM, then DS)
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
if [ $# -gt 0 ]; then AGENTS=("$@"); else AGENTS=(nv glm ds); fi

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

if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]; then
    echo "The repo has uncommitted changes. Commit or discard them first, so no agent" >&2
    echo "commits them under its own tag." >&2
    git -C "$REPO" status --short --untracked-files=no >&2
    exit 1
fi

mkdir -p "$CTRL/logs" "$REPO/.agents"
rm -f "$CTRL/STOP"
for a in "${AGENTS[@]}"; do rm -f "$CTRL/STOP-$a"; done

# Fresh control copies (read-only to the agents through the sandbox), taken
# from the committed version, not the working tree.
for f in sandbox.sb opencode.json prompt.md run-agent.sh hooks/commit-msg; do
    git -C "$REPO" show "HEAD:tools/agents/$f" >"$CTRL/$(basename "$f")"
done
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
