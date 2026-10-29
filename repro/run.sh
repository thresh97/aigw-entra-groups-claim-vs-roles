#!/usr/bin/env bash
# run.sh: re-run this article's tests. See the README's "Re-run" section.
#   run.sh list                 scenarios, what each changes, how long it takes
#   run.sh check                read-only preflight: tools, env, credentials, versions
#   run.sh <scenario> [--yes]   one scenario; --yes is required for scenarios that change shared state
#   run.sh all [--yes]          every scenario
# Results: repro/results/<date>-<scenario>/{run.log,summary.txt}. Verdict: PASS, CHANGED or ERROR.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
[[ -f $HERE/env ]] || { echo "ERROR: copy env.example to env and fill it in"; exit 2; }
# shellcheck source=/dev/null
source "$HERE/env"

# ---------------------------------------------------------------- framework (keep as is)
OUT= OBS=0 DIFF=0
CLEANUP=()
log()     { echo "$(date -u +%H:%M:%SZ) $*" | tee -a "$OUT/run.log"; }
mask()    { sed -E 's/[A-Za-z0-9+\/_=-]{24,}/<masked>/g'; }          # pipe anything that might carry a secret
fp()      { echo "len $(wc -c < "$1") tail $(tail -c3 "$1") sha $(sha256sum < "$1" | cut -c1-12)"; }  # a secret file, safely
need()    { for v; do [[ -n ${!v:-} ]] || { echo "ERROR: $v is empty in env"; exit 2; }; done; }
on_exit() { CLEANUP+=("$*"); }                                    # registered undo steps run in reverse, even on failure
expect()  { # expect "<what>" "<expected>" "<observed>"
  OBS=$((OBS+1)); if [[ $2 == "$3" ]]; then r=ok; else r=DIFF; DIFF=$((DIFF+1)); fi
  printf '%-4s %s: expected %s, observed %s\n' "$r" "$1" "$2" "$3" | tee -a "$OUT/summary.txt" | tee -a "$OUT/run.log"; }
cleanup() { local i; for ((i=${#CLEANUP[@]}-1; i>=0; i--)); do log "cleanup: ${CLEANUP[i]}"; eval "${CLEANUP[i]}" 2>&1 | mask | tee -a "$OUT/run.log"; done; CLEANUP=(); }
start()   { # start <scenario>
  local d=$HERE/results/$(date -u +%F) s=; for s in "" -b -c -d -e -f -g -h; do [[ -e $d$s-$1 ]] || break; done
  OUT=$d$s-$1; mkdir -p "$OUT"; chmod 700 "$OUT"; : > "$OUT/summary.txt"; OBS=0 DIFF=0
  { echo "scenario: $1"; echo "date: $(date -u +%FT%TZ)"; versions; } >> "$OUT/summary.txt"; trap 'cleanup; finish ERROR' EXIT; }
finish()  { trap - EXIT; cleanup
  local v=${1:-}; [[ -n $v ]] || { ((OBS == 0)) && v=ERROR || { ((DIFF)) && v=CHANGED || v=PASS; }; }
  echo "verdict: $v ($OBS observations, $DIFF differ)" | tee -a "$OUT/summary.txt"; echo "results: $OUT"; }
guard()   { [[ " ${ARGS[*]:-} " == *" --yes "* ]] || { echo "ERROR: $1 changes shared state ($2); re-run with --yes"; exit 2; }; }

# ---------------------------------------------------------------- article-specific
versions() { echo "entra-token-endpoint: v2.0"; }

check() {
  need TENANT_ID PUBLIC_CLIENT_ID API_APP_ID_URI TEST_USER_UPN TEST_USER_PASSWORD_FILE EXPECT_GROUP_COUNT EXPECT_ROLE_COUNT
  [[ -r $TEST_USER_PASSWORD_FILE ]] || { echo "ERROR: cannot read TEST_USER_PASSWORD_FILE"; exit 2; }
  for t in curl jq python3; do command -v "$t" >/dev/null || { echo "ERROR: $t not installed"; exit 2; }; done
  versions; echo "check: ok"; }

claims() { # claims <jwt>: print the payload as JSON
  echo "$1" | cut -d. -f2 | python3 -c '
import sys, base64, json
raw = sys.stdin.read().strip()
print(json.dumps(json.loads(base64.urlsafe_b64decode(raw + "=" * ((4 - len(raw) % 4) % 4)))))'; }

SCENARIOS=(claims)
describe_claims() { echo "claims: sign in a lab user (ROPC, no MFA) for the API scope and compare the groups and roles claims with the expected counts. Changes: nothing. About 1 min."; }
scenario_claims() {
  start claims
  local resp tok c
  resp=$(tr -d '\r\n' < "$TEST_USER_PASSWORD_FILE" | curl -s -X POST "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=password" --data-urlencode "client_id=${PUBLIC_CLIENT_ID}" \
    --data-urlencode "username=${TEST_USER_UPN}" --data-urlencode "password@/dev/stdin" \
    --data-urlencode "scope=openid profile email ${API_APP_ID_URI}/.default")
  tok=$(echo "$resp" | jq -r '.access_token // empty')
  [[ -n $tok ]] || { log "token request failed: $(echo "$resp" | jq -r '.error_description // .error' | mask)"; finish ERROR; return; }
  c=$(claims "$tok")
  echo "$c" | jq '{aud, scp, roles, groups, _claim_names}' > "$OUT/claims.json"
  expect "overage markers (_claim_names)" "absent" "$(echo "$c" | jq -r 'if has("_claim_names") then "present" else "absent" end')"
  expect "number of groups in the groups claim" "$EXPECT_GROUP_COUNT" "$(echo "$c" | jq -r '(.groups // []) | length')"
  expect "number of roles in the roles claim" "$EXPECT_ROLE_COUNT" "$(echo "$c" | jq -r '(.roles // []) | length')"
  finish; }

# ---------------------------------------------------------------- dispatch (keep as is)
cmd=${1:-list}; shift || true; ARGS=("$@")
case $cmd in
  list)  for s in "${SCENARIOS[@]}"; do "describe_$s"; done ;;
  check) check ;;
  all)   for s in "${SCENARIOS[@]}"; do "scenario_$s"; done ;;
  *)     if declare -F "scenario_$cmd" >/dev/null; then "scenario_$cmd"; else sed -n '2,7p' "$0"; exit 2; fi ;;
esac
