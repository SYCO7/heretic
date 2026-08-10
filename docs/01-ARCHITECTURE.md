# 01 — Architecture

## Design principles

1. **CLI-first.** The engine is a library + CLI. Any future UI *calls* the CLI; logic is never duplicated in a web layer.
2. **LLM is a pluggable backend.** Swap Nemotron ↔ Gemini ↔ local Ollama with a flag. Never hardcode a provider.
3. **The Oracle gates everything.** No finding reaches a report without proof. False-positive control is a first-class component, not an afterthought.
4. **Stateful, resumable.** Every engagement writes to a SQLite file; runs can pause and resume.
5. **Safe by default.** Non-destructive / dry-run mode is the default. Test accounts only. Scope enforced before every action.

## Component map

```
                        ┌────────────────────────────┐
                        │           cli.py            │
                        │   heretic scan -u ... --roe │
                        └──────────────┬─────────────┘
                                       │ loads
                        ┌──────────────▼─────────────┐
                        │          config.py          │
                        │  roe.yaml + accounts.yaml   │
                        │  (scope, mode, credentials) │
                        └──────────────┬─────────────┘
                                       │
   ┌───────────────────────────────────▼───────────────────────────────┐
   │                        ORCHESTRATOR (LangGraph)                      │
   │   drives the phase state machine; owns the engagement state (SQLite)│
   └───┬─────────┬──────────┬──────────┬──────────┬──────────┬──────────┘
       │         │          │          │          │          │
 ┌─────▼───┐ ┌───▼─────┐ ┌──▼──────┐ ┌─▼───────┐ ┌▼────────┐ ┌▼────────┐
 │ session │ │ intent  │ │ hypo-   │ │  test   │ │ ORACLE  │ │ chain + │
 │  _mgr   │ │ _model  │ │ thesis  │ │  exec   │ │ (verify)│ │ report  │
 └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
      │           │           │           │           │           │
   multi-role  LLM builds  LLM+RAG     replay via  invariant   html/json/md
   auth+cookies app model  attack gen  MCP tools   + diff +     + PoC
   (KEY infra)  (1M ctx)   per invariant           state-judge
      │           │           │           │           │
      └───────────┴───────────┴─────┬─────┴───────────┘
                                     │
                          ┌──────────▼──────────┐
                          │   llm/ (pluggable)   │
                          │  Nemotron / Gemini / │
                          │  Groq / Ollama       │
                          └──────────┬──────────┘
                                     │
                          ┌──────────▼──────────┐
                          │  knowledge/ (RAG)    │
                          │  Chroma: WSTG, HackTricks,│
                          │  PortSwigger logic labs   │
                          └─────────────────────┘
```

## Data flow (one engagement)

```
target URL + roe.yaml + accounts.yaml
    │
    ▼  Phase 1
multi-role crawl  →  { endpoints, params, roles, sessions, object_ids }
    │
    ▼  Phase 2 (LLM, big context)
intent model      →  { entities, roles, workflows, INVARIANTS[] }
    │
    ▼  Phase 3 (LLM + RAG)
hypotheses        →  [ {invariant, attack_pattern, concrete_test} , ... ]
    │
    ▼  Phase 4 (multi-session exec)
raw results       →  [ {test, request_seq, responses[per role]} , ... ]
    │
    ▼  Phase 5 (ORACLE — adversarial)
verified findings →  [ {invariant_broken, proof, severity} ]   ← FP dropped here
    │
    ▼  Phase 6
chained findings  →  higher-impact attack narratives
    │
    ▼  Phase 7
report.html / report.json
```

## Key infrastructure (make-or-break)

### 1. Multi-session manager (`core/session_mgr.py`)
Logic bugs are **relational** — they exist *between* users (userA reads userB's order) or *across roles* (a `user` calls an `admin` route). A single authenticated session finds almost nothing. The session manager must:
- Hold N authenticated sessions concurrently (guest, userA, userB, admin).
- Re-auth / refresh tokens transparently.
- Replay the *same* request under different identities for **differential** testing (the Oracle depends on this).

### 2. Request-sequence engine
Logic bugs are about **order and state**, not single requests ("skip the payment step", "redeem the coupon twice in parallel"). The engine must replay ordered sequences, snapshot state between steps, and support parallel firing for race conditions.

### 3. Invariant store
The machine-checkable assumptions extracted in Phase 2. Each invariant is the *thing to break* in Phase 3 and the *thing to prove broken* in Phase 5.

### 4. Oracle (`core/oracle.py`) — the moat
Three stacked verifiers: invariant assertion, cross-session differential, LLM state-delta judge, plus an adversarial "refute-or-promote" gate. Full detail in [`03-ORACLE.md`](03-ORACLE.md).

## Tech stack (all free / open)

| Layer | Choice | Notes |
|-------|--------|-------|
| Language | Python 3.11+ | ecosystem, MCP support |
| CLI | **Typer** + **Rich** | pretty terminal, live progress |
| Agent orchestration | **LangGraph** | deterministic phase state machine |
| Browser / crawl | **Playwright** | authenticated multi-role crawling |
| HTTP replay | **httpx** | async, sequence replay |
| State | **SQLite** + NetworkX | resumable engagement + relationship graph |
| RAG | **Chroma** (local) | seed logic-bug tradecraft |
| Tools | **bugbounty-mcp** | idor_test, business_logic_test, race_condition_test, broken_access_control_test, session_management_test, parameter_discovery |
| LLM | Nemotron 3 / Gemini / Groq / Ollama | pluggable — see [`04-LLM-BACKENDS.md`](04-LLM-BACKENDS.md) |
| Packaging | `pyproject.toml`, `pipx`, Docker | `pipx install heretic` |

## Module responsibilities

| Module | Responsibility |
|--------|----------------|
| `cli.py` | parse args, load config, invoke orchestrator, render output |
| `config.py` | parse + validate `roe.yaml`, `accounts.yaml`; enforce scope schema |
| `core/session_mgr.py` | multi-role auth, cookie/token store, differential replay |
| `core/intent_model.py` | LLM → business-intent model + invariant extraction |
| `core/hypothesis.py` | invariants × attack-pattern library (RAG) → concrete tests |
| `core/oracle.py` | verify findings, drop false positives |
| `core/chain.py` | combine verified primitives into higher-impact chains |
| `llm/base.py` | provider-agnostic interface (`complete`, `judge`, `embed`) |
| `llm/backends.py` | Nemotron / Gemini / Groq / Ollama implementations |
| `report/render.py` | html / json / markdown output with PoC + remediation |
