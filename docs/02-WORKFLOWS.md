# 02 — Workflows & Flowcharts

## The core loop

HERETIC's engine is a phase state machine: **Recon → Model → Hypothesize → Test → Verify → Chain → Report.** It is not strictly linear — the orchestrator loops back (e.g. a verified finding spawns new hypotheses for chaining).

## Master flowchart

```mermaid
flowchart TD
    A[heretic scan -u TARGET] --> B{Load roe.yaml + accounts.yaml}
    B -->|scope invalid / no auth| Z[Abort: refuse to run]
    B -->|ok| C[Phase 1: Multi-role crawl]
    C --> D[Phase 2: Build business-intent model + invariants]
    D --> E[Phase 3: Generate hypotheses per invariant]
    E --> F[Phase 4: Execute tests via multi-session engine]
    F --> G{Phase 5: ORACLE — invariant broken?}
    G -->|no / unproven| H[Drop finding - false positive]
    G -->|proven| I[Confirmed finding]
    H --> J{More hypotheses?}
    I --> K[Phase 6: Attempt to chain into higher impact]
    K --> J
    J -->|yes| F
    J -->|no| L[Phase 7: Render report html/json/md]
    L --> M[Exit]
```

## Phase detail

### Phase 0 — Scope & authorization gate
```mermaid
flowchart LR
    A[roe.yaml] --> B{signed RoE present?}
    B -->|no| Z[refuse]
    B -->|yes| C{target in scope allowlist?}
    C -->|no| Z
    C -->|yes| D{mode = dry-run or authorized live?}
    D --> E[proceed]
```
- Enforced **before every action**, not just at start. See [`07-GUARDRAILS.md`](07-GUARDRAILS.md).

### Phase 1 — Multi-role recon
- Playwright crawls target once **per role** (guest, userA, userB, admin).
- Captures: endpoints, methods, params, request/response bodies, cookies/tokens, visible object IDs, workflow sequences.
- Output: normalized site map + per-role session objects.

### Phase 2 — Business-intent model (the "understanding" step)
- Feed the whole crawled map to a **large-context LLM** (Nemotron 3 / Gemini — both 1M ctx).
- Model outputs structured JSON:
```json
{
  "app_type": "e-commerce API",
  "entities": ["user", "order", "product", "coupon", "wallet"],
  "roles":    ["guest", "user", "admin"],
  "workflows": [
    {"name": "checkout", "steps": ["add_cart", "apply_coupon", "pay", "ship"]}
  ],
  "invariants": [
    {"id": "INV-1", "rule": "order is readable only by its owner",        "class": "bola"},
    {"id": "INV-2", "rule": "price is computed server-side from catalog",  "class": "price_tamper"},
    {"id": "INV-3", "rule": "a coupon is redeemable once per user",        "class": "coupon_abuse"},
    {"id": "INV-4", "rule": "shipping requires a completed payment",       "class": "workflow_bypass"},
    {"id": "INV-5", "rule": "a user cannot set their own role/balance",    "class": "mass_assignment"}
  ]
}
```
- **Invariants are the heart.** Everything downstream is "try to break invariant X, then prove it broke."

### Phase 3 — Hypothesis generation
```mermaid
flowchart TD
    A[invariants] --> B[for each invariant]
    B --> C[retrieve matching attack patterns from RAG]
    C --> D[LLM: turn invariant + pattern into concrete test]
    D --> E["test: userA GET /order/{userB_order_id} → expect 403, bug if 200 with data"]
    E --> F[queue test]
```
- RAG corpus: OWASP WSTG, PortSwigger logic labs, HackTricks, prior findings.
- Each hypothesis carries its **expected-safe outcome** — this is what the Oracle checks against.

### Phase 4 — Test execution
- Multi-session engine replays the test's request sequence.
- For differential tests, fires the *same* request as multiple identities.
- Calls `bugbounty-mcp` tools where they fit (`idor_test`, `race_condition_test`, etc.).
- Captures full request/response per identity + any state deltas.

### Phase 5 — Oracle (verification) — see [`03-ORACLE.md`](03-ORACLE.md)
```mermaid
flowchart TD
    A[raw test result] --> B[Oracle 1: invariant assertion]
    A --> C[Oracle 2: cross-session differential]
    A --> D[Oracle 3: LLM state-delta judge]
    B & C & D --> E{adversarial gate: refute-or-promote}
    E -->|majority refute| F[DROP false positive]
    E -->|survives| G[CONFIRM + attach proof]
```

### Phase 6 — Chaining
- Verified primitives are fed back to the LLM: "given IDOR on /order and mass-assignment on /profile, construct a higher-impact chain."
- Example: IDOR (read others' data) + mass-assignment (`is_admin:true`) → full account takeover.
- New chained hypotheses re-enter Phase 4.

### Phase 7 — Report
- Renders each confirmed finding: title, invariant broken, severity (CVSS-ish), reproducible PoC (exact requests), business impact, remediation.
- Formats: `--report out.html`, `-o json`, `-o md`.

## Sequence view (multi-session differential — the signature move)

```mermaid
sequenceDiagram
    participant H as HERETIC
    participant A as Session userA
    participant B as Session userB
    participant T as Target
    H->>B: create order, capture order_id=1042
    H->>A: GET /api/order/1042  (as userA)
    A->>T: GET /api/order/1042
    T-->>A: 200 OK {userB's order data}
    H->>H: Oracle: INV-1 broken (owner-only violated) → CONFIRM BOLA
```

## State machine (orchestrator)

```
   ┌─────┐   ┌───────┐   ┌───────────┐   ┌──────┐   ┌────────┐   ┌───────┐   ┌────────┐
   │SCOPE│──▶│ RECON │──▶│ INTENT    │──▶│ HYPO │──▶│ EXECUTE│──▶│ ORACLE│──▶│ REPORT │
   └─────┘   └───────┘   │ MODEL     │   └──────┘   └────────┘   └───┬───┘   └────────┘
                         └───────────┘       ▲                       │
                                             │      confirmed→chain  │
                                             └───────────────────────┘
```
