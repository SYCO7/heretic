# HERETIC — the talk

A speaker's guide to presenting HERETIC: what it is, why it matters, how it works, and the
proof it works. Each section is a "slide" with talking points you can expand. ~25–35 min.

---

## 1. The hook (2 min)

> `POST /transfer {"amount": -100, "to": "me"}` → your balance goes **up**.

No payload is malformed. The server returns `200 OK`. Every scanner says the app is clean.
A human sees it in one second — because a human understands money.

**That is a business-logic bug.** The code did exactly what it was told; what it was told
violated a rule the developers *assumed* but never enforced.

Say this: *"70% of critical web-app vulnerabilities are business-logic flaws, and in 2026 no
autonomous tool detects them reliably. HERETIC is my attempt to change that."*

---

## 2. Why it's the last unsolved problem (3 min)

Security tooling splits in two:

| | Finds logic bugs? | Why |
|---|---|---|
| **Signature scanners** (Nuclei, Burp scanner, Nikto) | ❌ | they match known-bad *patterns* — XSS, SQLi, CVE. A logic bug has no pattern. |
| **Human pentesters** | ✅ | they understand what the app is *supposed* to do. |

For 20 years, "understand intent" was human-only. **LLMs broke that moat** — reasoning about
intent is exactly what they're good at. HERETIC is built from the ground up to weaponize that
for the one bug class that plays to LLM strengths and that regex engines will never touch.

Say this: *"Every classic tool already has an AI wrapper — nmap, ghidra, burp. The wrap game is
over. The one big unsolved problem left is logic. That's the whole bet."*

---

## 3. The trap everyone falls into — and the moat (4 min)

Anyone can prompt an LLM: *"find logic bugs in this app."* You get **60–80% false positives** —
the AI slop that made HackerOne pause the Internet Bug Bounty in 2026. Triagers drown.

**The hard, defensible part isn't finding — it's PROVING.** A logic bug throws no error and
returns 200 OK, so you must *prove* an invariant actually broke.

That verification layer is **the Oracle** — the core of HERETIC. Three proof types:

1. **Cross-session differential (BOLA/IDOR)** — userB replays userA's request, gets identical
   200 data, guest is denied, re-run is stable → deterministic proof. No LLM opinion.
2. **Invariant assertion (price / mass-assignment)** — sent 1, server charged 1 not 100 → it's
   arithmetic, not judgment.
3. **State-delta judge (workflow) + a 3-skeptic refuter panel** — the only LLM-judged path, and
   even here a majority of independent skeptics must agree.

**Rule that makes it trustworthy:** an LLM may never veto a *deterministic* proof. A fuzzy model
doesn't get to overrule arithmetic or an access-control diff.

Say this: *"Whoever solves the Oracle wins this category. Everything else is plumbing. My false-
positive rate on three live targets is zero — not because the LLM is smart, but because unproven
findings are dropped before they're ever reported."*

---

## 4. Architecture — the phase pipeline (5 min)

HERETIC is a **deterministic state machine**; the LLM *proposes*, but plain code enforces scope,
rate, and mode gates the model can't override (prompt-injection defense).

```
        ┌───────────── you give it: a URL + two accounts ─────────────┐
        │                                                             │
  Phase 1   Multi-role login        guest / userA / userB / admin at once
  Phase 1b  Discovery               find the API surface itself (5 sources ↓)
  Phase 2   Intent model (LLM)      infer the app's invariants from observed traffic
  Phase 3   Hypotheses              one concrete test per invariant, per bug class
  Phase 4-5 Execute + ORACLE        run it, PROVE it broke, drop anything unproven
  Phase 6   Chain                   compose confirmed primitives into higher impact
  Phase 7   Report                  reproducible PoC · HTML/JSON/MD
```

Two pieces of infra do the heavy lifting:

- **Multi-role session manager** — logic bugs are *relational* (userA vs userB). A single session
  finds almost nothing. HERETIC authenticates every role at once and diffs. That's the raw signal.
- **The Oracle** — section 3.

---

## 5. Autonomous discovery — "just give it a URL" (5 min)

The biggest usability win: HERETIC finds the attack surface itself. **Five sources**, each blind to
what the others catch:

1. **OpenAPI / Swagger** — parse the published schema if there is one.
2. **JS-bundle extraction** — SPAs ship their API routes in the JS. Extract them, and **resolve the
   service prefix** by probing (`api/shop/orders` → `/workshop/api/shop/orders`).
3. **Headless browser (Playwright)** — generic form login, drive the SPA, capture the XHRs it fires,
   collapse ids to `{id}` — catches URLs built at runtime.
4. **Wordlist brute-force** — probe common paths crossed with discovered prefixes.
5. **List → detail probing** — fetch each list, take a *real id*, probe `/thing/{id}/…` to recover
   item endpoints **with the id field they key on**.

Then **object inference**: pair each list with its item endpoint → a BOLA target, no config.

Two real-world enablers worth calling out:
- **Owner-field-aware harvest** — most apps leak the whole list to everyone, so "who fetched it"
  tells you nothing; but records name their owner (`user`, `UserId`). HERETIC attributes ownership
  from that field — turning a leaky list into a confirmable BOLA.
- **Login-response id harvest** — some ids are handed to you at login (Juice Shop's basket `bid`),
  not via a list. HERETIC harvests those too.

---

## 6. The proof — three live targets, three mechanisms (4 min)

Not demos. Real containers, real findings, **zero false positives each.**

| Target | How the BOLA is reached | Result |
|---|---|---|
| **OWASP crAPI** | autonomous discovery → list→detail probing → `/vehicle/{id}/location` | vehicle BOLA + chain |
| **OWASP Juice Shop** | login-response id harvest → `/rest/basket/{id}` | basket IDOR + data-exposure + chain |
| **OWASP VAmPI** | owner-field-aware harvest → `/books/v1/{title}` | book BOLA + email/password exposure + chain |

The login endpoint + token field were **auto-detected** on all three (crAPI `token`, Juice Shop
`authentication.token`, VAmPI `auth_token`) — the user just typed a URL and two logins.

Say this: *"Same tool, same 0% FP, three totally different apps and three different ways the bug
hides. That's the thing no open tool does reliably today."*

---

## 7. Tech stack (3 min)

Deliberately lean — see [`docs/10-TECHSTACK.md`](10-TECHSTACK.md) for the full breakdown.

- **Language:** Python 3.11+. **CLI:** Typer + Rich (menu, live output).
- **HTTP:** httpx only — one client covers targets *and* every OpenAI-compatible LLM API.
- **Config/validation:** Pydantic v2 (the RoE authorization gate is a Pydantic model + plain code).
- **LLM backends (pluggable, all free-tier):** NVIDIA Nemotron (hosted), Gemini, Groq, OpenRouter,
  and **local Ollama** — auto-detected; runs fully offline/private on a local model.
- **Browser:** Playwright (optional) for XHR capture.
- **Packaging:** hatchling → `pip install`; Docker; Apache-2.0.
- **Quality:** ruff + 81 pytest tests + a benchmark FP-gate wired into CI.
- **No heavyweight deps by design** — no LangChain, no vector DB (RAG-lite is a keyword store), no
  provider SDKs. It's auditable and boring on purpose.

---

## 8. What makes it different from XBOW / generalist agents (2 min)

Be honest here — it earns credibility.

- **Narrow, not broad.** XBOW/Strix chase 40+ bug classes and exploitation. HERETIC does *one* class,
  deeply. A scalpel, not a swarm.
- **Proof-first, not exploit-first.** It refuses to report what it can't prove. That's the opposite
  of "spray exploits, LLM judges."
- **Deterministic where possible** + **multi-role differential** as core infra.
- **Open, local, free** vs closed SaaS.

Honest caveat to say out loud: *"As a general pentester, XBOW wins — it's funded and battle-tested
on thousands of targets. HERETIC's edge is depth in the one lane generalists are weakest at:
proving business-logic bugs at near-zero false positives. If it ever tries to be a broad pentest
agent, it becomes a worse XBOW clone. The strategy is to own logic."*

---

## 9. Live demo (3 min)

```bash
heretic connect            # URL + two users → auto-detects login → scans
# or, reproducibly:
bash scripts/demo.sh       # runs against a live Juice Shop; recording in docs/demo/
```

Point at the `CONFIRM` lines and the `N dropped (false positives)` — say *"those drops are the
product; anyone can find, the value is refusing to report noise."*

---

## 10. Where it goes next (1 min)

- More live targets → published precision/recall vs human-found bugs (the number that beats hype).
- Owner-field learning per API; extend live confirmation to price/mass/workflow classes.
- Distil a private local specialist model from confirmed traces (the export → QLoRA path).

Close with: *"The moat is the Oracle. The proof is three live targets at zero false positives. The
plan is to stay narrow and get the real-world numbers."*

---

### One-sentence version (for the elevator)

*"HERETIC is an open-source AI agent that finds business-logic vulnerabilities — the IDOR/price/
workflow bugs scanners can't see — and it only reports what it can prove, so it does that on live
apps at zero false positives."*
