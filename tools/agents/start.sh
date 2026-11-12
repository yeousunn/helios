#!/usr/bin/env bash
# Start the three unattended agents in a tmux session named "helios-agents".
#
#   tools/agents/start.sh            start all three (NV first, then GLM, then DS)
#   tools/agents/start.sh glm        start one agent
#
# Stop with tools/agents/stop.sh. Watch with tools/agents/status.sh or
# `tmux attach -t helios-agents`.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO/tools/agents"
STATE="$REPO/.agents"
SESSION="helios-agents"
if [ $# -gt 0 ]; then AGENTS=("$@"); else AGENTS=(nv glm ds); fi

for bin in opencode tmux gtimeout qemu-system-x86_64 cargo; do
    command -v "$bin" >/dev/null || { echo "missing: $bin" >&2; exit 1; }
done

# Interactive opencode sessions in this repo would fight over the same files.
busy=""
for p in $(pgrep -x opencode || true) $(pgrep -f '^opencode' || true); do
    cwd="$(lsof -a -p "$p" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')"
    [ "$cwd" = "$REPO" ] && busy="$busy $p"
done
if [ -n "$busy" ] && [ "${FORCE:-0}" != 1 ]; then
    echo "Interactive opencode processes are still open in this repo (pids:$busy)." >&2
    echo "Quit them first, or run with FORCE=1 to start anyway." >&2
    exit 1
fi

mkdir -p "$STATE/logs"
rm -f "$STATE/STOP"
for a in "${AGENTS[@]}"; do rm -f "$STATE/STOP-$a"; done

# Run from a copy, so a stray edit in the working tree cannot change a live supervisor.
cp "$SRC/opencode.json" "$SRC/prompt.md" "$SRC/run-agent.sh" "$STATE/"
# The supervisors restore AGENTS.md from this copy if an agent edits it.
cp "$REPO/AGENTS.md" "$STATE/AGENTS.md.saved"
chmod +x "$STATE/run-agent.sh"
# run-agent.sh resolves REPO from its own location, so point the copy at the repo.
sed -i '' "s|^REPO=.*|REPO=\"$REPO\"|" "$STATE/run-agent.sh"

# Ownership hook (AGENTS.md section 1).
install -m 0755 "$SRC/hooks/commit-msg" "$REPO/.git/hooks/commit-msg"

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
        "sleep $delay; $STATE/run-agent.sh $a; echo '[supervisor exited]'; sleep 86400"
    echo "started $a (after ${delay}s)"
    delay=$((delay + 120))
done

echo "tmux session: $SESSION   logs: $STATE/logs   history: $STATE/<agent>.history"
