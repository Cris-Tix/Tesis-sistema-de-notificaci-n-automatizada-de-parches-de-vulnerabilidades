#!/usr/bin/env bash
# fix-credential-ids.sh
# Fetches the real Postgres credential UUID from the n8n REST API
# and patches all workflow-*.json files (fixes any current value, not just "1").
#
# Usage (from WSL, inside the project directory):
#   bash fix-credential-ids.sh
#
# Overrides:
#   N8N_URL=http://localhost:5678  bash fix-credential-ids.sh
#   POSTGRES_CRED_ID=<uuid>        bash fix-credential-ids.sh   # skip API call

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKFLOW_DIR="${WORKFLOW_DIR:-$SCRIPT_DIR/workflows}"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"
N8N_URL="${N8N_URL:-http://localhost:5678}"
POSTGRES_CRED_ID="${POSTGRES_CRED_ID:-}"

# ── 1. load .env ──────────────────────────────────────────────────────────────

if [[ -f "$ENV_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*# || -z "${line// }" ]] && continue
        if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            k="${BASH_REMATCH[1]}"
            v="${BASH_REMATCH[2]}"
            v="${v#\"}" ; v="${v%\"}"
            v="${v#\'}" ; v="${v%\'}"
            export "$k=$v"
        fi
    done < "$ENV_FILE"
    echo "Loaded: $ENV_FILE"
else
    echo "Warning: .env not found at $ENV_FILE"
fi

N8N_USER="${N8N_BASIC_AUTH_USER:-}"
N8N_PASS="${N8N_BASIC_AUTH_PASSWORD:-}"

# ── 2. call n8n REST API ──────────────────────────────────────────────────────

TMPFILE="$(mktemp)"
trap 'rm -f "$TMPFILE"' EXIT

if [[ -z "$POSTGRES_CRED_ID" ]]; then
    API_URL="${N8N_URL}/api/v1/credentials"
    echo "Querying $API_URL ..."

    HTTP_STATUS=""

    # Try basic auth first (n8n with N8N_BASIC_AUTH_ACTIVE=true)
    if [[ -n "$N8N_USER" && -n "$N8N_PASS" ]]; then
        HTTP_STATUS="$(curl -s --max-time 10 \
            -u "${N8N_USER}:${N8N_PASS}" \
            -H "Accept: application/json" \
            -o "$TMPFILE" \
            -w "%{http_code}" \
            "$API_URL" 2>/dev/null)" || true
        echo "  basic auth → HTTP $HTTP_STATUS"
    fi

    # If basic auth failed or not configured, try without auth
    if [[ "$HTTP_STATUS" != "200" ]]; then
        HTTP_STATUS="$(curl -s --max-time 10 \
            -H "Accept: application/json" \
            -o "$TMPFILE" \
            -w "%{http_code}" \
            "$API_URL" 2>/dev/null)" || true
        echo "  no auth    → HTTP $HTTP_STATUS"
    fi

    if [[ "$HTTP_STATUS" == "200" ]]; then
        # Parse the response file with Python — no shell escaping issues
        POSTGRES_CRED_ID="$(python3 - "$TMPFILE" <<'PYEOF'
import json, sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

# n8n public API v1: {"data": [...]}  OR  older/internal: [...]
creds = data["data"] if isinstance(data, dict) and "data" in data else data
pg    = [c for c in creds if c.get("type") == "postgres"]

if not pg:
    print("", end="")
    sys.exit(0)

if len(pg) == 1:
    target = pg[0]
else:
    # Prefer credential whose name contains "Postgres"; else take first
    named  = next((c for c in pg if "postgres" in c.get("name","").lower()), None)
    target = named or pg[0]
    sys.stderr.write(f"Multiple Postgres credentials found; using '{target['name']}'\n")
    sys.stderr.write("To use a different one: POSTGRES_CRED_ID=<uuid> bash fix-credential-ids.sh\n")

print(target["id"], end="")
PYEOF
        )" || true

        if [[ -n "$POSTGRES_CRED_ID" ]]; then
            echo "  Credential UUID: $POSTGRES_CRED_ID"
        else
            echo "  API returned 200 but no Postgres credential found."
            echo "  Raw response:"
            cat "$TMPFILE"
        fi

    elif [[ "$HTTP_STATUS" == "401" ]]; then
        echo "  401 Unauthorized. The n8n public API requires an API key."
        echo "  Generate one in: n8n UI → Settings → API → Create an API Key"
        echo "  Then set it in .env:  N8N_API_KEY=<key>"
        echo "  And rerun: N8N_API_KEY=\$N8N_API_KEY bash fix-credential-ids.sh"
    else
        echo "  Unexpected HTTP status: $HTTP_STATUS"
        [[ -s "$TMPFILE" ]] && cat "$TMPFILE"
    fi
fi

# Manual fallback
if [[ -z "$POSTGRES_CRED_ID" ]]; then
    echo ""
    echo "Could not retrieve UUID automatically."
    echo "Get it from the n8n UI:"
    echo "  Settings → Credentials → click 'VulnPatchNotifier Postgres' → copy UUID from the URL"
    echo "  (e.g. http://localhost:5678/credentials/AbCdEf12 → UUID is AbCdEf12)"
    echo ""
    read -rp "Paste Postgres credential UUID: " POSTGRES_CRED_ID
fi

echo ""
echo "UUID to inject: $POSTGRES_CRED_ID"
echo ""

# ── 3. patch workflow JSON files ──────────────────────────────────────────────

python3 - "$WORKFLOW_DIR" "$POSTGRES_CRED_ID" <<'PYEOF'
import re, sys, pathlib

workflow_dir = pathlib.Path(sys.argv[1])
uuid         = sys.argv[2]

# Matches "id": "<anything>" inside a "postgres": { ... } credential block.
# Uses "[^"]*" so it fixes any current value — "1", corrupted strings, etc.
pattern = re.compile(r'("postgres"\s*:\s*\{[\s\S]*?"id"\s*:\s*)"[^"]*"')
repl    = r'\1"' + uuid + r'"'

n_updated = 0
for f in sorted(workflow_dir.glob("workflow-*.json")):
    text     = f.read_text(encoding="utf-8")
    new_text, n = pattern.subn(repl, text)
    if n:
        f.write_text(new_text, encoding="utf-8")
        print(f"  [UPDATED] {f.name}  ({n} replacement(s))")
        n_updated += 1
    else:
        print(f"  [SKIP]    {f.name}  (no postgres credential block found)")

print(f"\nDone — {n_updated} file(s) updated.")
if n_updated:
    print("\nNext steps:")
    print("  1. Re-import each workflow in n8n: Settings → Import workflow.")
    print("  2. Fix the SMTP credential id in workflow-alerts.json the same way:")
    print("     n8n UI → Settings → Credentials → open the SMTP credential → copy UUID from URL")
    print("     Then: SMTP_ID=<uuid> python3 -c \"")
    print("       import re, pathlib")
    print("       p = re.compile(r'(\\\"smtp\\\"\\s*:\\s*\\{[\\s\\S]*?\\\"id\\\"\\s*:\\s*)\\\"[^\\\"]*\\\"')")
    print("       f = pathlib.Path('workflows/workflow-alerts.json')")
    print("       f.write_text(p.sub(r'\\\\1\\\"'+'$SMTP_ID'+'\\\"', f.read_text()))\"")
PYEOF
