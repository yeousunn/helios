#!/usr/bin/env bash
# One-screen view of the unattended agents.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CTRL="${HELIOS_CTRL:-$HOME/.local/state/helios-agents}"
cd "$REPO" || exit 1

echo "== supervisors"
tmux list-windows -t helios-agents -F '  #W' 2>/dev/null || echo "  not running"
[ -f "$CTRL/STOP" ] && echo "  STOP file present (stopping after current cycles)"
if [ -s "$CTRL/violations.log" ]; then
    echo "== VIOLATIONS ($CTRL/violations.log)"
    tail -n 5 "$CTRL/violations.log" | sed 's/^/  /'
fi

for a in nv glm ds; do
    echo "== $a (last 4 events)"
    tail -n 4 "$CTRL/$a.history" 2>/dev/null | sed 's/^/  /' || echo "  no history"
done

echo "== last commit per agent"
for t in NV GLM DS; do
    printf '  %-5s %s\n' "$t" "$(git log -1 --format='%ad %h %s' --date=format:'%m-%d %H:%M' --grep="^\[$t\]" | cut -c1-100)"
done

echo "== board"
printf '  open %s   claimed %s   done %s\n' \
    "$(grep -c '^- \[ \]' TASKS.md)" "$(grep -c '^- \[~' TASKS.md)" "$(grep -c '^- \[x' TASKS.md)"
grep -E '^- \[~' TASKS.md | cut -c1-110 | sed 's/^/  /'
grep -qi 'freeze lifted' docs/DECISIONS.md && echo "  freeze: lifted" || echo "  freeze: active (Phase H)"
