#!/usr/bin/env bash
# Step 1 smoke test: simulates Claude Code PermissionRequest hooks with curl.
# Usage: start db + server first, then: bash scripts/smoke_test.sh
set -euo pipefail
PY=""; for c in python3 python py; do if "$c" -c 'print(1)' >/dev/null 2>&1; then PY=$c; break; fi; done
[ -n "$PY" ] || { echo "no python found"; exit 1; }
BASE="${ACP_BASE:-http://127.0.0.1:8787}"
HDR=()
if [ -n "${ACP_TOKEN:-}" ]; then HDR=(-H "X-ACP-Token: ${ACP_TOKEN}"); fi
SID="smoke-$$"

post() { curl -sS -X POST "$BASE$1" -H 'Content-Type: application/json' ${HDR[@]+"${HDR[@]}"} -d "$2"; }
get()  { curl -sS "$BASE$1" ${HDR[@]+"${HDR[@]}"}; }
perm() { printf '{"session_id":"%s","cwd":"/tmp","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"%s"}}' "$SID" "$1"; }
pass=0; fail=0
check() { # label, haystack, needle
  if printf '%s' "$2" | grep -q "$3"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1 -> $2"; fail=$((fail+1)); fi
}

check "health" "$(get /healthz)" '"ok":true'
check "safe command is auto-allowed" "$(post /hook "$(perm 'ls -la')")" '"behavior":"allow"'
check "rm -rf / is auto-denied"      "$(post /hook "$(perm 'rm -rf /')")" '"behavior":"deny"'
check "force push is auto-denied"    "$(post /hook "$(perm 'git push --force origin main')")" '"behavior":"deny"'

# Unknown command -> pending -> human approves via API -> hook call returns allow.
out_file="$(mktemp)"
post /hook "$(perm 'npm install left-pad')" > "$out_file" &
bg=$!
aid=""
for _ in $(seq 1 20); do
  aid="$(get '/approvals?status=pending' | "$PY" -c 'import sys,json; d=json.load(sys.stdin); print(d[0]["id"] if d else "")')"
  [ -n "$aid" ] && break
  sleep 0.25
done
if [ -z "$aid" ]; then echo "FAIL  pending approval never appeared"; fail=$((fail+1)); kill "$bg" 2>/dev/null || true
else
  check "human approves pending request" "$(post "/approvals/$aid/decide" '{"decision":"allow"}')" '"status":"allowed"'
  wait "$bg"
  check "blocked hook call resumed with allow" "$(cat "$out_file")" '"behavior":"allow"'
fi
rm -f "$out_file"

check "session is tracked" "$(get /sessions)" "$SID"
echo "---- $pass passed, $fail failed"
[ "$fail" -eq 0 ]
