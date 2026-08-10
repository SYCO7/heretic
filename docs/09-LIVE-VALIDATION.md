# 09 — Live Validation (get the real number)

Every metric elsewhere in this repo is measured on an in-process **mock**. This
page is how you produce the number that actually matters: HERETIC's precision /
recall / false-positive rate on a **real vulnerable target** with a **real LLM**.
Until you run this, HERETIC is unproven. This is the finish line for v1.

## 1. Stand up a target (authorized, local)

```bash
# OWASP crAPI — deliberately vulnerable, safe + legal to test locally
git clone https://github.com/OWASP/crAPI && cd crAPI/deploy/docker
docker compose pull && docker compose up -d       # crapi web on http://localhost:8888
# register two users in the crAPI UI: userA@crapi.local / userB@crapi.local
```

Alternative: `bkimminich/juice-shop` (web app) — you'd write a Juice Shop profile
the same way as `targets/crapi/`.

## 2. Point HERETIC at it

```bash
cp targets/crapi/accounts.yaml.example targets/crapi/accounts.yaml
# edit accounts.yaml with the two users you registered
# edit targets/crapi/roe.yaml scope + endpoints to match YOUR crAPI build
```

## 3. Pick a brain (free)

```bash
export NVIDIA_API_KEY=...     # build.nvidia.com  → Nemotron Super (free)
# or GEMINI_API_KEY=...       # aistudio.google.com
# or fully local:  ollama serve && ollama pull nemotron-3-nano   (no key)
```

## 4. Preflight, then run the live check

```bash
heretic doctor --model nemotron-super -u http://localhost:8888
#   ✓ nemotron-super — NVIDIA_API_KEY is set
#   ✓ target http://localhost:8888 — HTTP 200
#   ready.

heretic livecheck \
  --profile targets/crapi \
  -u http://localhost:8888 \
  --model auto \
  --report crapi-findings.html
```

You get the scoreboard — **the real number**:

```
true positives · false positives · false negatives
precision · recall · false-positive rate (gate <10%) · F1
```

`livecheck` exits non-zero if FP-rate ≥ `--max-fp` (default 10%) or recall <
`--min-recall` (default 50%) — so it doubles as a pass/fail gate.

## 5. Then improve the loop

```bash
# log traces, distil a private specialist from what actually worked:
heretic livecheck --profile targets/crapi -u http://localhost:8888 --model nemotron-super
heretic scan ... --model nemotron-super --log run.jsonl        # (scan writes the trace)
heretic export --trace run.jsonl --out data.jsonl --format chat
python finetune/qlora_nemotron_nano.py data.jsonl --gguf       # see finetune/
```

## Honesty checklist

- The `targets/crapi/` profile is a **starter template** — crAPI endpoints differ
  by version. Proxy the traffic (Burp/mitmproxy), confirm the real `list_url` /
  `item_url` / `id_field`, and tune before trusting recall.
- Ground truth (`ground_truth.yaml`) is **your** claim of what should be found —
  keep it honest; a recall number is only as good as the ground truth behind it.
- Publish the exact target build + profile + numbers together, or the benchmark
  means nothing. That transparency is the credibility.
