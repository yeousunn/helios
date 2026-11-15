#!/usr/bin/env bash
# One-screen view of the unattended agents.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CTRL="${HELIOS_CTRL:-$HOME/.local/state/helios-agents}"
cd "$REPO" || exit 1
# Agents write commit subjects, the board and parts of the logs: print only
# printable characters so nothing they write can drive the terminal.
clean() { LC_ALL=C tr -cd '[:print:]\n'; }

echo "== supervisors"
tmux list-windows -t helios-agents -F '  #W' 2>/dev/null || echo "  not running"
[ -f "$CTRL/STOP" ] && echo "  STOP file present (stopping after current cycles)"
if [ -s "$CTRL/violations.log" ]; then
    echo "== VIOLATIONS ($CTRL/violations.log)"
    tail -n 5 "$CTRL/violations.log" | clean | sed 's/^/  /'
fi

last_gate="$(ls -t "$CTRL/gate" 2>/dev/null | head -n 1)"
if [ -n "$last_gate" ]; then
    echo "== gate (latest run by the supervisor)"
    echo "  ${last_gate:0:9} ${last_gate##*.} ($(date -r "$CTRL/gate/$last_gate" '+%m-%d %H:%M'))"
    [ "${last_gate##*.}" = fail ] && grep -E 'ERROR|FAIL|error(\[|:)' "$CTRL/gate/$last_gate" | clean | head -n 3 | cut -c1-110 | sed 's/^/  /'
fi

for a in nv glm ds drv psx; do
    echo "== $a (last 4 events)"
    tail -n 4 "$CTRL/$a.history" 2>/dev/null | clean | sed 's/^/  /' || echo "  no history"
done

echo "== last commit per agent"
for t in NV GLM DS DRV PSX; do
    printf '  %-5s %s\n' "$t" "$(git log -1 --format='%ad %h %s' --date=format:'%m-%d %H:%M' --grep="^\[$t\]" | clean | cut -c1-100)"
done

echo "== board"
printf '  open %s   claimed %s   done %s\n' \
    "$(grep -c '^- \[ \]' TASKS.md)" "$(grep -c '^- \[~' TASKS.md)" "$(grep -c '^- \[x' TASKS.md)"
grep -E '^- \[~' TASKS.md | clean | cut -c1-110 | sed 's/^/  /'
grep -m1 '^\*\*Milestone:' TASKS.md | clean | cut -c1-110 | sed 's/^/  /'
