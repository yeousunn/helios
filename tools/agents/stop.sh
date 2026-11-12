#!/usr/bin/env bash
# Stop the unattended agents.
#
#   tools/agents/stop.sh           graceful: each agent finishes its current cycle, then exits
#   tools/agents/stop.sh glm       graceful, one agent
#   tools/agents/stop.sh --now     kill everything immediately (may leave half-done work)
set -euo pipefail

CTRL="${HELIOS_CTRL:-$HOME/.local/state/helios-agents}"
SESSION="helios-agents"
mkdir -p "$CTRL"

if [ "${1:-}" = "--now" ]; then
    touch "$CTRL/STOP"
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    pkill -f "opencode run -m nvidia/" 2>/dev/null || true
    echo "killed. Check 'git status' for half-done work."
elif [ -n "${1:-}" ]; then
    touch "$CTRL/STOP-$1"
    echo "$1 will stop after its current cycle."
else
    touch "$CTRL/STOP"
    echo "all agents will stop after their current cycle. Then: tmux kill-session -t $SESSION"
fi
