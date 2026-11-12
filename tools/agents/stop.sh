#!/usr/bin/env bash
# Stop the unattended agents.
#
#   tools/agents/stop.sh           graceful: each agent finishes its current cycle, then exits
#   tools/agents/stop.sh glm       graceful, one agent
#   tools/agents/stop.sh --now     kill everything immediately (may leave half-done work)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE="$REPO/.agents"
SESSION="helios-agents"
mkdir -p "$STATE"

if [ "${1:-}" = "--now" ]; then
    touch "$STATE/STOP"
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    pkill -f "opencode run -m nvidia/" 2>/dev/null || true
    echo "killed. Check 'git status' for half-done work."
elif [ -n "${1:-}" ]; then
    touch "$STATE/STOP-$1"
    echo "$1 will stop after its current cycle."
else
    touch "$STATE/STOP"
    echo "all agents will stop after their current cycle. Then: tmux kill-session -t $SESSION"
fi
