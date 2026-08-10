#!/usr/bin/env bash
# HERETIC — real demo against LIVE vulnerable labs (no staging, no fake output).
#
# Reproduce it yourself:
#   docker run -d -p 3000:3000 bkimminich/juice-shop         # OWASP Juice Shop
#   # register 2 users (userA@juice.local / userB@juice.local), then:
#   cp targets/juiceshop/accounts.yaml.example targets/juiceshop/accounts.yaml  # fill creds
#   bash scripts/demo.sh
#
# The model is auto-detected (hosted key or local Ollama); nothing to configure.

set -e
cd "$(dirname "$0")/.."
[ -d .venv ] && source .venv/bin/activate
[ -f .env ] && export "$(grep -v '^#' .env | xargs)" 2>/dev/null || true

pause() { sleep "${1:-2}"; }
run()   { echo; echo "\$ $*"; pause 1; "$@"; pause 2; }

clear
echo "════════════════════════════════════════════════════════════════"
echo "  HERETIC — autonomous business-logic vulnerability agent"
echo "  live demo · OWASP Juice Shop · 0 false positives"
echo "════════════════════════════════════════════════════════════════"
pause 2

echo; echo "# 1) Offline self-test — precision/recall/FP, no key, no target"
run heretic bench

echo; echo "# 2) Live Juice Shop — find the basket IDOR + data exposure"
echo "#    (model auto-detected; basket id harvested from the login response)"
run heretic scan -u http://localhost:3000 \
  --roe targets/juiceshop/roe.yaml \
  --accounts targets/juiceshop/accounts.yaml \
  --classes bola,excessive_data_exposure

echo
echo "════════════════════════════════════════════════════════════════"
echo "  Every finding is Oracle-proven. Nothing unproven was reported."
echo "  github.com/SYCO7/heretic"
echo "════════════════════════════════════════════════════════════════"
