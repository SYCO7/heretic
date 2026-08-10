# 05 — Roadmap

Solo, part-time realistic. Each phase ships something usable. Ground truth = **crAPI** and **OWASP Juice Shop** (documented logic bugs to measure against).

## Milestones

### M0 — Scaffold (this repo) — ✅ DONE
- [x] Directory tree, docs, plan, flowcharts
- [x] `pyproject.toml`, CLI skeleton runs (`heretic --help`)
- [x] Config loader parses `roe.yaml` + `accounts.yaml`
- [x] LLM backend interface + working backends (Nemotron/Gemini/Ollama/Groq/OpenRouter + ScriptedLLM)

### M1 — Multi-session + BOLA/IDOR (the beachhead) — ✅ BUILT
**Goal:** autonomously find crAPI's documented BOLA bugs.
- [x] `session_mgr`: hold guest/userA/userB/admin sessions concurrently (login_all)
- [x] Multi-role id harvest → owned-id map (httpx; Playwright browser crawl deferred to M2)
- [x] Differential Oracle (Oracle 2) working end-to-end, with FP controls
      (public-resource + ownership + similarity + rerun)
- [x] Report renders confirmed BOLA with reproducible PoC (table/json/md/html)
- [x] End-to-end test: mock target (vuln+safe+public) → 4 confirmed, 4 dropped, 9/9 tests green
- **Win condition:** catches BOLA, false positives < 20%. On the mock harness the
      safe endpoint (403) and the public resource are both correctly dropped.
- **Next:** validate against a live crAPI instance; confirm recall vs its documented BOLA set.

### M2 — Intent model + more classes — ✅ BUILT
**Goal:** beat Juice Shop logic challenges.
- [x] Pluggable LLM backends wired: Nemotron/Groq/Ollama (OpenAI-compatible) + Gemini + ScriptedLLM (offline)
- [x] Phase-2 intent model (LLM, 1M ctx) → invariants JSON, from observed traffic
- [x] Classes added: price_tamper, mass_assignment, workflow_bypass (LLM hypothesis engine)
- [x] Oracle 1 (invariant assertion — deterministic) for price/mass
- [x] Oracle 3 (state-delta judge, LLM) + refute-or-promote gate for workflow
- [x] Dry-run gate: state-changing classes require `mode: live` + RoE authorization
- [x] Offline end-to-end test (ScriptedLLM + mock, vuln+safe per class): 3 confirmed / 3 dropped; 14/14 tests green
- **Win condition:** solves ≥60% of Juice Shop logic challenges autonomously.
- **Next:** run against a live Nemotron/Gemini backend + real crAPI/Juice Shop; measure recall.

### M3 — Oracle hardening (the moat) — ✅ BUILT
**Goal:** trustworthy output.
- [x] Refute-or-promote adversarial gate — perspective-diverse panel of 3 skeptics for LLM-judged findings
- [x] Deterministic proofs are NOT subject to LLM refutation (a fuzzy model can't veto arithmetic/access-diff)
- [x] Re-run confirmation for read-only tests + standardized proof bundle with a `confidence` score
- [x] Precision/recall/FP benchmark harness vs ground truth (`heretic bench`), with CI FP-gate (exit≠0)
- [x] Built-in offline suite (BOLA+price+mass+workflow, vuln+safe+public): precision 100%, recall 100%, FP-rate 0% on the mock; 20/20 tests green
- **Win condition:** false-positive rate **< 10%** while holding recall — met on the mock harness.
- **Next:** run the harness against live crAPI/Juice Shop with a real LLM backend and publish the real precision/recall numbers.

### M4 — Chaining + races + knowledge — ✅ BUILT
- [x] Chain engine — composes confirmed primitives into higher-impact chains
      (account takeover, financial fraud, bulk exfiltration); grounded → no new FP
- [x] Race-condition / TOCTOU — parallel-fire engine (ThreadPool) + success-count oracle; gated behind live mode
- [x] RAG-lite knowledge base — bundled WSTG/HackTricks/PortSwigger corpus + keyword retriever, grounds the hypothesis prompt (no external vector DB)
- [x] Report polish — `impact` field, confidence column, styled standalone HTML report (severity badges, PoC, chain impact)
- [x] `--chain` CLI flag / RoE `chain: true`; benchmark now scores chains too → 8/8, precision 100%, recall 100%, FP 0%; 26/26 tests green
- **Next:** live LLM + real target validation (the number that matters).

### M5 — Self-improvement + distribution — ✅ BUILT
- [x] Trace store: every verdict logged to JSONL (audit trail + distillation data)
- [x] Dataset exporter (`heretic export`): confirmed traces → Alpaca/chat fine-tune examples for LoRA/distilling a private Nano
- [x] Pattern memory: learns confirmed hypothesis shapes, persists, feeds them back into the hypothesis prompt (self-improvement loop)
- [x] `scan --log/--memory/--chain`; packaging (`pyproject` entry point → `pipx install heretic`)
- [x] Dockerfile, Apache-2.0 LICENSE, GitHub Actions CI running pytest + the `heretic bench` FP-gate, Makefile, README quickstart
- [ ] Optional Textual TUI — deferred (CLI-first; the Rich live view already covers the terminal UX)
- 32 offline tests green.

### M6 — Live validation harness — ✅ BUILT (awaiting a real run)
- [x] `heretic doctor` — preflight: model key(s) present? target reachable? (per-phase for `--model auto`)
- [x] `heretic livecheck --profile <dir> -u <url>` — run a real target, score precision/recall/FP vs ground truth, pass/fail gate
- [x] Target-profile format: `roe.yaml` + `accounts.yaml` + `ground_truth.yaml`
- [x] `targets/crapi/` starter profile + `docs/09-LIVE-VALIDATION.md` runbook
- [x] 7 offline tests (profile scoring, ground-truth loader, doctor checks)
- [x] **✅ FIRST REAL RUN DONE** — live OWASP crAPI + real Nemotron backend: found both documented
      vehicle-location BOLAs + the bulk-exfiltration chain, **precision 100% / recall 100% / FP 0%**.
      HERETIC is no longer mock-only.

### M7 — Usability + robustness — ✅ BUILT
- [x] `heretic auto` — one command, fully guided: preflight → full scan + chains → report (menu option 1)
- [x] Feedback loop `--iterate N` — mutate a failed logic test's input and retry (deterministic, offline)
- [x] Resumable engagements — `scan --save x.db` checkpoints every confirmed finding + done-class to
      SQLite; `heretic resume` reloads, re-runs unfinished classes, and re-chains over the merged set
- [x] `ruff` clean across `src` + `tests`, wired into CI alongside pytest + the FP-gate; 53 tests green
- **Next:** broaden live coverage (Juice Shop logic set), accumulate confirmed traces, then distil a
      private Nano specialist (finetune needs ~hundreds of confirmed examples — see `finetune/`).

### M8 — Autonomous discovery — ✅ BUILT
**Goal:** find the attack surface itself, so BOLA no longer needs a hand-written `objects:` block.
- [x] `core/discovery.py` — read-only, scope-gated Discoverer with three sources:
      OpenAPI/Swagger parse (v2 basePath + v3), light JSON/HATEOAS crawl, and **active object
      inference** (for each `GET /base/{id}`, fetch the sibling list endpoint, inspect the array,
      detect the id field → a ready-to-attack `ObjectSpec`).
- [x] `DiscoverySpec` config + `--discover/--no-discover`; auto-enabled when the RoE has no `objects`;
      `heretic auto` always discovers. Orchestrator **Phase 1b** merges inferred objects + feeds
      discovered endpoints to the intent model.
- [x] Offline proof: mock publishes an OpenAPI doc → discovery infers order/profile/catalog with the
      right id fields and reproduces the **exact 8-finding benchmark with `objects: []`**; 58 tests green.
- **Honest limit (M8):** discovery needs a readable spec or JSON/HATEOAS links. Spec-less SPAs need
      the M8.1 JS/brute path below.

### M8.1 — JS-route extraction + wordlist brute-force — ✅ BUILT
**Goal:** map spec-less SPAs (like crAPI) with no operator input.
- [x] JS-route extractor — fetch the SPA shell, pull `<script>` bundles, regex the API routes out of
      the JS (leading-slash literals, relative `api/...` fragments, and `orders/`+id concatenation
      sites → item templates); `${…}` → `{id}`.
- [x] Service-prefix resolver — a bundle fragment like `api/shop/orders` is probed across the service
      prefixes (`/identity`, `/community`, `/workshop`, …) to recover the real path; the winning
      prefixes are then applied to the templated item routes.
- [x] Wordlist brute-force (`--brute`, opt-in) — probes a small path wordlist crossed with every
      discovered prefix; records anything that isn't a plain 404.
- [x] Offline tests (JS scrape primitives, JS-only object inference, wordlist probe); 61 tests green.
- [x] **Live crAPI (spec-less React SPA):** autonomously recovered **33 real endpoints** across all
      three services with correct prefixes — `/identity/api/v2/vehicle/vehicles`,
      `/community/api/v2/coupon/validate-coupon`, `/workshop/api/shop/orders/all`, … — from **zero**
      operator config. These feed the intent model directly.
- **Honest limit:** static scraping can't see item-by-id URLs the frontend builds at runtime. Closed
      by M8.2 below.

### M8.2 — Headless-browser XHR capture — ✅ BUILT
**Goal:** catch the runtime-built item URLs (`/vehicle/{id}/location`) no static scrape can see.
- [x] `core/browser.py` — drives real headless Chromium (Playwright), does a **generic form login**
      (finds the password field, the email field, the submit button — no per-app selectors), navigates
      the SPA routes, runs a **bounded interaction pass** (clicks cards/buttons/links to trigger lazy
      XHRs), and records every same-origin API request it fires.
- [x] `templatize()` collapses concrete ids back to `{id}` — numeric, uuid, long hex, VIN/base62
      tokens, and `null` placeholders — so captured item URLs feed straight into object inference.
- [x] `DiscoverySpec.browser` + `--browser`; graceful skip with an install hint when Playwright is
      absent; scope-gated navigation; failures never abort discovery. 65 tests green (pure logic:
      templatize, is_api, route extraction — no browser needed in CI).
- [x] **Live crAPI:** generic form login succeeded, then captured **12 runtime XHRs** incl. templated
      item endpoints (`/identity/api/v2/user/videos/{id}`,
      `/workshop/api/merchant/service_requests/{id}`) that static scraping never saw.
- **Note:** the headless browser is opt-in and slow (a real Chromium); `pip install "heretic[browser]"`
      + `python -m playwright install chromium`.

### M8.3 — Targeted list→detail probing — ✅ BUILT · 🎯 AUTONOMOUS BOLA ON crAPI
**Goal:** recover the item-by-id endpoints deterministically, with the right id field, and confirm a
real bug with zero operator config.
- [x] For each discovered list endpoint: fetch it, take REAL ids from the response, and probe the item
      + sub-resource URL patterns (`/base/{id}`, `/base/{id}/location`, …) with those ids.
- [x] **Id-field disambiguation** — an object often carries both `id` and `uuid`; the prober tries each
      and keeps the field that actually returns **200**, then threads it into the inferred `ObjectSpec`
      (so harvest uses the field the endpoint really keys on).
- [x] **Collection-aware pairing** — the list guesser prefers plural/collection-shaped siblings and
      verifies each returns an array, so an action endpoint (`/vehicle/add_vehicle`) can't pose as the list.
- [x] Offline test: a `/orders/{id}/status` sub-resource invisible to static scraping is recovered via a
      real id; 67 tests green.
- [x] **🎯 Live crAPI, ZERO config (`--discover`, empty `objects:`):** discovered
      `list=/identity/api/v2/vehicle/vehicles` + `item=/identity/api/v2/vehicle/{id}/location` (id field
      `uuid`, proven by 200), harvested both users' vehicles, and **CONFIRMED 2 BOLAs + the
      bulk-exfiltration chain — 3 confirmed / 0 dropped / 0 FP** — identical to the hand-tuned profile.
      **HERETIC now finds crAPI's flagship BOLA fully autonomously, no operator input.**
### M9 — Pairing hardened for diverse API shapes — ✅ BUILT
**Goal:** object inference that survives real targets beyond crAPI.
- [x] **OWASP Juice Shop** — unwrap the `{status, data:[...]}` envelope (`list_path` detection already
      handles it) and Capitalised, auto-generated models (`/api/Products/{id}`, `/api/Users/{id}`);
      object names normalise + lowercase (`Products` → `product`).
- [x] **VAmPI** — string-keyed items (`/users/v1/{username}`, `/books/v1/{book_title}`) with no numeric
      `id`: broadened the id-key list (`username`, `user_id`, `name`, `title`, `book_title`) and the
      `*name`/`*title`/`*key` fallback, and the detail-probe's 200-based disambiguation keeps `username`
      over `email`. Object naming skips version/gateway segments so `/users/v1` → `user`, not `v1`.
- [x] Offline mocks reproducing both response shapes; pairing yields the right list/item/id-field for
      each. **70 tests green**; crAPI's autonomous BOLA still confirms (no regression).
- **Next:** extend autonomous confirmation to the price/mass/workflow classes on a live target.

### M10 — Login-response id harvest — ✅ BUILT · 🎯 JUICE SHOP BOLA CONFIRMED LIVE
**Goal:** reach owned ids the app hands the user at login (not via a list endpoint).
- [x] `login_objects` in roe: `{name, item_url, id_from}` — `id_from` is a dotted path into the login
      JSON giving each role its owned id (e.g. Juice Shop's `authentication.bid`).
- [x] SessionManager keeps each role's login response and `harvest_login_ids()` extracts the per-role
      ids; the orchestrator merges them into the owned-id map and hands BOLA the `item_url` to attack —
      the existing differential oracle does the rest (no new false-positive surface).
- [x] Offline tests: confirms the basket IDOR when baskets are cross-readable, **zero FP** when they
      are properly owner-scoped. 72 tests green.
- [x] **🎯 Live OWASP Juice Shop, end to end:** harvested basket ids (userA=6, userB=7) from login,
      and **CONFIRMED both-direction basket IDOR + the bulk-exfil chain — 3 confirmed / 0 dropped / 0 FP.**
      HERETIC now catches ownership-BOLA on both crAPI (list→detail) *and* Juice Shop (login-derived id).
- **Note:** Juice Shop's leaky list endpoints (all rows to every user) are *excessive data exposure* —
      caught by M11 below.

### M11 — Excessive Data Exposure oracle — ✅ BUILT · LIVE ON JUICE SHOP
**Goal:** catch the "any user sees everyone's records" leak — a class distinct from ownership-BOLA.
- [x] `core/exposure.py` + Oracle `_verify_exposure` — mechanical, read-only. Fetch a list as userA /
      userB / guest; confirm ONLY when a single caller's list carries an owner field (`UserId`,
      `BasketId`, `email`, …) with **≥2 distinct owner values** AND the endpoint is **private** (guest
      denied). Deterministic, re-run confirmed, no LLM veto.
- [x] FP-guarded by design: a public catalog (no owner field) and a properly per-user list (single
      owner) are never flagged. Offline tests prove leak-confirm + both no-FP cases; 75 tests green.
- [x] New class `excessive_data_exposure` in the default set (read-only, always safe to run).
- [x] **Live Juice Shop:** flagged `/api/BasketItems` (mixed `BasketId`, guest-denied) as a leak while
      correctly dropping 9 other lists — alongside the basket BOLA + chain: **4 confirmed / 0 FP**.
- **Next:** owner-field learning per API, and extending live confirmation to price/mass/workflow.

### M12 — Zero-friction UX + model auto-detect + Ollama — ✅ BUILT
**Goal:** anyone can run it without memorising flags or model names.
- [x] `llm/select.py` — detects usable backends (NVIDIA / Gemini / Groq / OpenRouter keys + a running
      Ollama with its pulled models) and `best_available()` auto-picks; a saved `HERETIC_MODEL` wins.
- [x] `--model` now defaults to **auto-detect** across `scan` / `auto` / `doctor` / `livecheck` — no
      model flag needed; the resolved model is printed.
- [x] Menu **Model** screen: lists every backend with readiness (✓/○), the active one, key hints, and
      local Ollama models; **P pulls a bigger local model** (`ollama pull …`). Menu **Keys** saves API
      keys to gitignored `.env`. The banner shows the active model.
- [x] Ollama fully wired (`ollama:<model>`, OpenAI-compatible): fully private/offline runs, auto-selected
      when no hosted key is set. Falls back to `fake` (mechanical BOLA + data-exposure) with zero setup.
- **Adoption next (go-to-market, not code):** demo GIF in the README, publish to PyPI + a tagged release,
      submit to awesome-security / awesome-pentest lists, a short write-up of the crAPI + Juice Shop runs.

### M13 — Easy connect: login auto-detect + OTP/SSO — ✅ BUILT
**Goal:** a user points HERETIC at their app with two accounts and it does the rest.
- [x] `heretic connect` wizard (+ menu option 1): enter target URL + two users (email/username/phone +
      password) → it **auto-detects the login endpoint and the token field** (`core/login_detect.py`
      probes the common routes with the common credential shapes), writes `accounts.yaml` + a starter
      `roe.yaml`, and offers to scan.
- [x] **OTP / MFA / SSO** handled universally: if auto-login returns no token, the wizard has the user
      paste a bearer token per account (`Role.token`, no login step) — works for any auth scheme.
- [x] Offline tests: detects nested (`authentication.token`) + flat (`access_token`) tokens, tries
      username/email/phone variants, and token-only roles authenticate with no login.
- [x] **Live-validated on 3 targets:** auto-detected crAPI (`token`), Juice Shop (`authentication.token`),
      and VAmPI (`auth_token`) logins with no manual config.

### M14 — Owner-field-aware harvest + VAmPI — ✅ BUILT · 3rd LIVE TARGET
**Goal:** find ownership-BOLA even when the list endpoint leaks every user's records (the common case).
- [x] When a list carries an owner field (`user`, `UserId`, `owner`, `email`, …), HERETIC attributes each
      record to its true owner (matched to a role's identity) instead of "whoever fetched it" — turning a
      leaky list into a confirmable ownership-BOLA. Records with no owner field fall back to the fetcher.
- [x] Offline test (leaky book list + `user` field → 2 confirmed cross-reads); 80 tests green; no
      regression on the mock benchmark.
- [x] **🎯 Live OWASP VAmPI, zero config:** discovered its OpenAPI, owner-attributed the leaky `/books/v1`
      list, and **confirmed both-direction book BOLA + the chain — 3 confirmed / 0 FP.**
- **Track record now: crAPI · Juice Shop · VAmPI — three real targets, three different BOLA mechanisms,
      0 false positives each.**

### M15 — Broken Function-Level Authorization (BFLA) + public data-exposure — ✅ BUILT · LIVE
**Goal:** deterministic detection of two more OWASP-API classes, moat-aligned (0 FP).
- [x] **Public sensitive-data exposure** (extends the data-exposure oracle): a no-auth endpoint that
      exposes secrets (`password`, `token`, `ssn`) leaks on sight; PII (`email`, `phone`) leaks when it
      lists many people. **Live VAmPI:** flagged `/users/v1` (emails) and the debug endpoint (email +
      **passwords**) exposed without auth.
- [x] **BFLA oracle** (`core/bfla.py`, OWASP API #5) — mechanical, read-only. An admin-marked function
      reachable by *guest* (open to unauth, critical) or by a *regular user* while guest is denied
      (privilege escalation, high). Corroborated by an admin role or a strong path marker.
- [x] **FP guard that matters:** SPAs serve `index.html` (200) for unknown routes — the oracle requires
      a genuine API response (not the HTML shell), so `/admin`, `/actuator`, … catch-alls are dropped.
      **Live Juice Shop: 1 confirmed (`/rest/admin/application-configuration`) · 8 SPA fallbacks dropped;
      VAmPI: 1 confirmed (`/users/v1/_debug`) · 9 dropped — 0 FP each.**
- [x] 83 tests green; new class `bfla` in the default set (read-only, always safe).
- **Classes now: BOLA · BFLA · excessive/sensitive data exposure · price · mass · workflow · coupon ·
      race · (+ chains). Deterministic oracles carry BOLA/BFLA/data-exposure; the LLM path carries the
      rest. Next: land a price/mass/workflow confirmation on a live target.**

## Benchmark targets (free, with ground truth)

| Target | Type | Why |
|--------|------|-----|
| **crAPI** (OWASP) | vuln API | documented BOLA / mass-assignment / logic bugs |
| **OWASP Juice Shop** | web app | rich logic-challenge set, scored |
| **VAmPI** | API | broken-auth / BOLA reference |
| **Gin & Juice Shop** (PortSwigger) | web | realistic logic surface |
| **DVGA** | GraphQL | logic bugs in GraphQL context |

## Definition of "winning"

> On crAPI + Juice Shop, HERETIC runs fully autonomously and reports the documented business-logic bugs with a **false-positive rate under 10%** and a reproducible PoC per finding — a result no open tool reliably delivers in 2026.

Hit that and you have something real, publishable, and star-worthy on GitHub.

### M16 — Live logic-class confirmation: deterministic mass-assignment — ✅ BUILT · LIVE
**Goal:** land a logic class (beyond BOLA/BFLA/exposure) on a live target — the honest frontier.
- [x] Diagnosed the pure-LLM path live: nemotron generated plausible-but-WRONG tests (basket quantity/
      price on endpoints that don't reflect the field); the Oracle correctly **dropped all of them (0 FP)**
      — the moat working, but no confirmation. The real bug (registration role) was never proposed.
- [x] `core/massassign.py` — deterministic mass-assignment at registration (OWASP API #6): find the
      signup endpoint, learn a working body, re-register with a privileged field injected
      (`role: admin`, `isAdmin: true`, …), confirm ONLY if the response reflects it. State-changing →
      live-gated; creates throwaway accounts; 0 FP by construction.
- [x] **🎯 Live Juice Shop:** `POST /api/Users` accepts `role=admin` → **CONFIRM mass_assignment
      (CRITICAL)** — self-registration as admin. **Live VAmPI:** correctly **0 confirmed** (its register
      ignores the field) — no false positive. 87 tests green.
- **A logic class now confirms live, deterministically.** The LLM hypothesis path still runs alongside
      for exotic cases; the reliable confirmations come from deterministic oracles. Next: price_tamper
      (negative-quantity / total read-back) and workflow_bypass on a live target, same deterministic style.
