# HERETIC

![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![tests](https://img.shields.io/badge/tests-100%20passing-brightgreen)
![false--positive rate](https://img.shields.io/badge/FP--rate-0%25-brightgreen)

**Autonomous AI agent that finds business-logic vulnerabilities** — the bug class scanners can't touch and human pentesters still do by hand.

> *Heretic (n.) — one who breaks the sacred rules.* This tool breaks the rules an application *assumes* but never enforces.

HERETIC is a **CLI tool** (like `nmap`, `sqlmap`, `nuclei`) that reasons about an app's *business intent*, then systematically tries to violate it: IDOR/BOLA, price tampering, workflow bypass, mass assignment, coupon abuse, race conditions, auth-flow abuse.

It is **not** another signature scanner. Signature scanners find XSS/SQLi/CVE. HERETIC finds the 70% of critical web bugs that have **no signature** — where the code did exactly what it was told, but what it was told violated the business rules.

```bash
heretic scan -u https://target.local --roe roe.yaml --accounts accounts.yaml
```

---

## See it work — real output, live OWASP Juice Shop

Not a mock-up. This is HERETIC against a live `bkimminich/juice-shop` container (model auto-detected,
basket id harvested from the login response). Reproduce it with [`scripts/demo.sh`](scripts/demo.sh);
the terminal recording is [`docs/demo/heretic-demo.cast`](docs/demo/heretic-demo.cast) (`asciinema play`).

```text
  CONFIRM excessive_data_exposure — basketitem list leaks all users' records
  CONFIRM bfla — admin function /rest/admin/application-configuration is exposed to unauthenticated users
  CONFIRM mass_assignment — registration at /api/Users accepts privileged field 'role'
  CONFIRM price_tamper — /api/BasketItems accepts a negative quantity (-100)
  CONFIRM workflow_bypass — order finalized at /rest/basket/6/checkout without a payment step
────────────────── 7 confirmed · 17 dropped (false positives) ───────────────────
```

Five business-logic classes confirmed on a live app in one command — and **0 false positives**: the 17
"dropped" are candidates the Oracle refused to confirm (SPA catch-alls, public catalogs, the LLM's wrong
guesses). Every confirmation is deterministic and reproducible. On **live crAPI**, with zero config, it
autonomously discovers `/vehicle/{id}/location` and confirms the documented BOLA the same way.

---

## Why this exists

- **70% of critical web vulns are business-logic flaws. No autonomous agent detects them reliably (2026).**
- Every classic tool already has an AI wrapper (nmap, ghidra, volatility, bloodhound, burp...). The wrap game is over.
- The one big **unsolved problem** left is logic. It needs *reasoning about intent* — the thing LLMs are uniquely good at and regex engines never will be.

**The moat is the Oracle** — knowing a logic bug actually happened (no error is thrown, response looks 200 OK). See [`docs/03-ORACLE.md`](docs/03-ORACLE.md).

---

## Docs — read in order

| # | File | What |
|---|------|------|
| 0 | [`docs/00-VISION.md`](docs/00-VISION.md) | Problem, thesis, moat, how it wins |
| 1 | [`docs/01-ARCHITECTURE.md`](docs/01-ARCHITECTURE.md) | Components, data flow, tech stack |
| 2 | [`docs/02-WORKFLOWS.md`](docs/02-WORKFLOWS.md) | Phase workflow + flowcharts (mermaid) |
| 3 | [`docs/03-ORACLE.md`](docs/03-ORACLE.md) | The hard part — verification / false-positive kill |
| 4 | [`docs/04-LLM-BACKENDS.md`](docs/04-LLM-BACKENDS.md) | **Nemotron analysis** + free AI options |
| 5 | [`docs/05-ROADMAP.md`](docs/05-ROADMAP.md) | Milestones, phase plan |
| 6 | [`docs/06-USAGE.md`](docs/06-USAGE.md) | How the user runs it + how it wins |
| 7 | [`docs/07-GUARDRAILS.md`](docs/07-GUARDRAILS.md) | Scope, safety, legal, non-destructive mode |
| 8 | [`docs/08-AI-STACK.md`](docs/08-AI-STACK.md) | **Model stack** — Nemotron, per-phase routing, finetuning, ADK decision |
| 9 | [`docs/09-LIVE-VALIDATION.md`](docs/09-LIVE-VALIDATION.md) | **Get the real number** — run vs crAPI/Juice Shop, score recall/FP |
| 10 | [`docs/10-TECHSTACK.md`](docs/10-TECHSTACK.md) | **Tech stack & design decisions** — every dependency and why |
| ★ | [`docs/LECTURE.md`](docs/LECTURE.md) | **The talk** — present/explain HERETIC end to end (25–35 min) |
| ★ | [`docs/RELEASE.md`](docs/RELEASE.md) | Ship it — GitHub + PyPI + the real demo |

## Code skeleton

```
src/heretic/
├── cli.py              # Typer entrypoint — `heretic scan ...`
├── config.py           # loads roe.yaml + accounts.yaml
├── core/
│   ├── session_mgr.py  # multi-role auth engine (KEY infra)
│   ├── discovery.py    # autonomous endpoint discovery + object inference
│   ├── browser.py      # headless-browser XHR capture (runtime-built URLs)
│   ├── intent_model.py # LLM builds business-intent model
│   ├── hypothesis.py   # generates invariant-violation tests
│   ├── oracle.py       # verifies findings, kills false positives (THE MOAT)
│   ├── exposure.py     # excessive-data-exposure oracle (co-mingled owners)
│   ├── bfla.py         # broken function-level authorization (admin functions)
│   └── chain.py        # combines primitives into higher impact
├── llm/                # pluggable backend: Nemotron / Gemini / Ollama
└── report/             # html / json / md output
```

## Quickstart

```bash
pipx install heretic            # or: pip install -e ".[dev]"   ·   or: docker build -t heretic .
```

**The easy way — connect your app in two prompts. No config files to write:**

```bash
heretic connect                 # enter target URL + 2 users → it auto-detects the login and scans
heretic                         # or the full menu: Connect, Auto, Doctor, Scan, Models, Keys …
```

`connect` **auto-detects the login endpoint + token field** from the credentials you type (handles
OTP / MFA / SSO by letting you paste a bearer token), writes the profile, and runs the scan. The menu
**auto-detects your AI model** — a hosted key (NVIDIA / Gemini / Groq / OpenRouter) or a
local **Ollama** model — and uses the best one. Menu → **Model** to pick another or **pull a bigger
local model**. Add keys in menu → **Keys**. Nothing configured? It still runs BOLA + data-exposure
offline, and `heretic bench` self-tests with no key at all.

**One-command guided scan** (auto-detects the model, discovers the surface, writes an HTML report):

```bash
heretic auto -u https://target.local --profile targets/crapi
```

**Full control (CLI), for scripting / CI** — `--model` defaults to auto-detect:

```bash
heretic scan -u https://target.local --roe roe.yaml --accounts accounts.yaml \
  --discover --chain --iterate 3 --save engagements/run.db --report findings.html

heretic resume --engagement engagements/run.db --report findings.html   # if interrupted
heretic export --trace engagements/run.jsonl --out dataset.jsonl --format chat
```

**Fully private / offline** (nothing leaves the box): pull a local model — `ollama pull qwen2.5:7b` —
and HERETIC auto-selects it, or pick it in the Models menu.

## Status

**M1–M14 built + validated on 3 live targets.** 9 bug classes (BOLA/IDOR, broken function-level auth (BFLA), excessive data exposure,
price tampering, mass assignment, workflow bypass, race/TOCTOU, + chains), 7 oracle types, adversarial hardening, a
benchmark FP-gate, chaining, RAG-lite knowledge, trace logging + distillation export, a
self-improvement memory loop, a feedback loop (`--iterate`: mutate-and-retry failed logic tests),
resumable engagements (`scan --save` / `resume`), a one-command guided flow (`heretic auto`), and an anti-hallucination layer (detects LLM-invented endpoints + ungrounded verdicts and self-corrects).

- **Autonomous discovery** (`--discover` / `--brute` / `--browser`): parses OpenAPI/Swagger, extracts +
  prefix-resolves API routes from SPA JS bundles, optional wordlist brute-force, a headless-browser pass
  (generic form login → drive the SPA → capture runtime XHRs), and **targeted list→detail probing** that
  follows each list with real ids to recover item endpoints and the id field they key on — then *infers*
  BOLA targets with no hand-written `objects:`.
  **🎯 On live crAPI with zero config it discovers `/vehicle/{id}/location`, harvests both users' vehicles,
  and confirms the documented BOLA + chain (3 confirmed / 0 dropped / 0 FP) — fully autonomously.**
- **Offline benchmark:** precision 100% / recall 100% / FP 0% · **100 tests** · `ruff` clean.
- **Live-validated on 3 real targets, 3 different BOLA mechanisms, 0 false positives each:**
  **crAPI** (autonomous discovery → list→detail probing → `/vehicle/{id}/location`),
  **Juice Shop** (login-response id harvest → `/rest/basket/{id}`),
  **VAmPI** (owner-field-aware harvest of a leaky list → `/books/v1/{title}`). Login endpoint + token
  field auto-detected on all three; each run fully autonomous from just a URL + two accounts.

See [`docs/09-LIVE-VALIDATION.md`](docs/09-LIVE-VALIDATION.md) to reproduce the live run.

## Ship it

Publishing to GitHub + PyPI and sharing the real demo: see [`docs/RELEASE.md`](docs/RELEASE.md).
The package builds clean (`python -m build`; `twine check` PASSED) and installs+runs from the wheel.

## License (planned)

Apache-2.0. Lab-first. Authorized testing only — see [`docs/07-GUARDRAILS.md`](docs/07-GUARDRAILS.md).
