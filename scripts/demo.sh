#!/usr/bin/env bash
# HERETIC — real demo against LIVE vulnerable labs (no staging, no fake output).
#
# Reproduce it yourself:
#   docker run -d -p 3000:3000 bkimminich/juice-shop     # OWASP Juice Shop → register 2 users
#   docker run -d -p 5001:5000 erev0s/vampi              # OWASP VAmPI → curl :5001/createdb
#   cp targets/juiceshop/accounts.yaml.example targets/juiceshop/accounts.yaml   # fill creds
#   cp targets/vampi/accounts.yaml.example     targets/vampi/accounts.yaml
#   bash scripts/demo.sh
#
# Deterministic classes only (bola/bfla/data-exposure) — no API key, no network beyond the targets.

set -e
cd "$(dirname "$0")/.."
[ -d .venv ] && source .venv/bin/activate
[ -f .env ] && export "$(grep -v '^#' .env | xargs)" 2>/dev/null || true

pause() { sleep "${1:-1.2}"; }
run()   { echo; echo "\$ $*"; pause 0.8; "$@"; pause 1.6; }

clear
echo "════════════════════════════════════════════════════════════════"
echo "  HERETIC — autonomous business-logic vulnerability agent"
echo "  business-logic bugs your scanner can't touch · ~0 false positives"
echo "════════════════════════════════════════════════════════════════"
pause 1.6

echo; echo "# 1) Offline self-test — precision / recall / FP, no key, no target"
run heretic bench

echo; echo "# 2) LIVE OWASP Juice Shop — IDOR + BFLA + data exposure, one command"
run heretic scan -u http://localhost:3000 \
  --roe targets/juiceshop/roe.yaml \
  --accounts targets/juiceshop/accounts.yaml \
  --classes bola,bfla,excessive_data_exposure --discover --chain

echo; echo "# 3) LIVE OWASP VAmPI — different app, different bugs, same 0-FP Oracle"
run heretic scan -u http://localhost:5001 \
  --roe targets/vampi/roe.yaml \
  --accounts targets/vampi/accounts.yaml \
  --classes bola,excessive_data_exposure,bfla --discover --chain

echo
echo "════════════════════════════════════════════════════════════════"
echo "  Every finding Oracle-proven. Nothing unproven was reported."
echo "  The LLM proposes; deterministic code confirms. That's the moat."
echo "  github.com/SYCO7/heretic"
echo "════════════════════════════════════════════════════════════════"
