#!/usr/bin/env bash
# One-command proof the whole stack is wired correctly, not just "the
# process started": provisions a real noob-orientation-server instance,
# confirms its flag matches the HMAC scheme every box uses, destroys it,
# and confirms the container is actually gone -- not just marked
# destroyed in the DB.
#
# If ORCHESTRATOR_TEST_URL already answers, this talks to that running
# orchestrator. Otherwise it boots a throwaway one against a temporary
# SQLite DB and tears it down again at the end.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BASE_URL="${ORCHESTRATOR_TEST_URL:-http://127.0.0.1:9100}"
BOX_ID="noob-orientation-server"
STARTED_OWN_ORCHESTRATOR=0
ORCHESTRATOR_PID=""
TMP_DB=""

cleanup() {
    if [[ -n "$ORCHESTRATOR_PID" ]]; then
        kill "$ORCHESTRATOR_PID" 2>/dev/null || true
    fi
    [[ -n "$TMP_DB" ]] && rm -f "$TMP_DB"
}
trap cleanup EXIT

fail() {
    echo "RESULT: FAILED -- $1"
    exit 1
}

if ! curl -s -o /dev/null -m 3 "${BASE_URL}/docs"; then
    echo "==> No orchestrator reachable at ${BASE_URL}, starting a throwaway one"
    # Bind to whatever host/port BASE_URL actually names -- not a
    # hardcoded 9100 -- so this also works when ORCHESTRATOR_TEST_URL
    # points somewhere else (confirmed this matters: hardcoding 9100
    # here failed outright with "address already in use" the one time
    # another process already held port 9100 while BASE_URL pointed
    # elsewhere).
    read -r BIND_HOST BIND_PORT <<< "$(python3 -c "
from urllib.parse import urlparse
u = urlparse('${BASE_URL}')
print(u.hostname or '127.0.0.1', u.port or 80)
")"
    TMP_DB="$(mktemp /tmp/health-check-XXXXXX.db)"
    rm -f "$TMP_DB"  # mktemp creates it; sqlite wants to create its own file
    ORCHESTRATOR_DATABASE_URL="sqlite:///${TMP_DB}" \
        .venv/bin/python3 -m uvicorn orchestrator.main:app --host "$BIND_HOST" --port "$BIND_PORT" \
        > /tmp/health-check-orchestrator.log 2>&1 &
    ORCHESTRATOR_PID=$!
    STARTED_OWN_ORCHESTRATOR=1
    for _ in $(seq 1 20); do
        curl -s -o /dev/null -m 1 "${BASE_URL}/docs" && break
        sleep 0.5
    done
    curl -s -o /dev/null -m 3 "${BASE_URL}/docs" || fail "started an orchestrator but it never came up -- see /tmp/health-check-orchestrator.log"
fi

TEAM_SECRET="health-check-$(date +%s)-$$"
TEAM_ID=$((RANDOM + 900000))

echo "==> Provisioning ${BOX_ID} for team ${TEAM_ID}"
RESPONSE="$(curl -s -X POST "${BASE_URL}/instances" -H "Content-Type: application/json" \
    -d "{\"team_id\": ${TEAM_ID}, \"box_id\": \"${BOX_ID}\", \"team_secret\": \"${TEAM_SECRET}\"}")"

INSTANCE_ID="$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('instance_id',''))" 2>/dev/null)"
ENTRY_HOST="$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('entry_host',''))" 2>/dev/null)"
ENTRY_PORT="$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('entry_port',''))" 2>/dev/null)"

[[ -n "$INSTANCE_ID" ]] || fail "provision did not return an instance_id -- raw response: ${RESPONSE}"

echo "==> Checking flag 1 at http://${ENTRY_HOST}:${ENTRY_PORT}/"
PAGE="$(curl -s -m 10 "http://${ENTRY_HOST}:${ENTRY_PORT}/")"
EXPECTED_FLAG="$(python3 -c "
import hashlib, hmac
secret = '${TEAM_SECRET}'
digest = hmac.new(secret.encode(), b'${BOX_ID}:1', hashlib.sha256).hexdigest()
print(f'HLC{{{digest[:10]}}}')
")"

if [[ "$PAGE" != *"$EXPECTED_FLAG"* ]]; then
    curl -s -X DELETE "${BASE_URL}/instances/${INSTANCE_ID}" > /dev/null
    fail "expected flag ${EXPECTED_FLAG} not found on the front door (provisioning works, flag derivation does not match -- check CTF_SECRET wiring)"
fi
echo "    flag matched: ${EXPECTED_FLAG}"

echo "==> Destroying instance ${INSTANCE_ID}"
DELETE_STATUS="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "${BASE_URL}/instances/${INSTANCE_ID}")"
[[ "$DELETE_STATUS" == "204" ]] || fail "DELETE /instances/${INSTANCE_ID} returned HTTP ${DELETE_STATUS}, expected 204"

sleep 1
CONTAINER_NAME="ctf-${BOX_ID}-${TEAM_ID}-orientation-server"
if docker inspect "$CONTAINER_NAME" > /dev/null 2>&1; then
    fail "container ${CONTAINER_NAME} still exists after destroy -- DB says destroyed but the real container is not gone"
fi

echo "RESULT: healthy"
