# 00 — Vision

## The problem

Web app security tools split into two camps:

1. **Signature scanners** (Nuclei, Nikto, Burp scanner) — match known-bad patterns. Great at XSS, SQLi, CVEs. Blind to logic.
2. **Human pentesters** — the only thing that reliably finds *business-logic* bugs, because those need understanding of what the app is *supposed* to do.

A business-logic bug has **no signature**. The request is well-formed. The server returns `200 OK`. Nothing is malformed. The code did exactly what it was written to do — but what it was written to do violates a business rule the developers assumed was safe.

Example: `POST /transfer {"amount": -100, "to": "me"}` → your balance goes *up*. No payload is "malicious." No scanner flags it. A human sees it in one second because a human understands money.

## The thesis

For 20 years, understanding intent was a human-only capability. **That moat just broke.** LLMs reason about intent. HERETIC is the first tool built from the ground up to weaponize that for the logic-bug class — not as a bolt-on to a scanner, but as the core loop.

- **2026 reality:** "70% of critical web app vulnerabilities are business-logic flaws, and no autonomous agent currently detects these reliably."
- Every famous tool already has an AI wrapper. The MCP-wrap land grab is over.
- Business logic is the **last big unsolved problem** in offensive security automation, and it happens to be the one that plays *directly* to LLM strengths.

## What HERETIC is

A **CLI tool** that:

1. Crawls a target as **multiple roles simultaneously** (guest / userA / userB / admin).
2. Builds a **business-intent model** — entities, roles, workflows, and the **invariants** the app assumes ("price is server-side", "one coupon per user", "only the owner reads an order", "payment precedes shipping").
3. **Systematically tries to violate every invariant**, mapping each to concrete attack patterns.
4. Runs those tests with a multi-session request engine.
5. **Verifies each finding with an adversarial Oracle** that proves the invariant actually broke — killing false positives before they reach a report.
6. **Chains** primitives into higher-impact attacks and writes a clean PoC + remediation report.

## What HERETIC is NOT

- Not a signature scanner (that's Nuclei — we integrate, we don't replace).
- Not a web app / SaaS. It is a terminal tool. Data stays on the operator's machine.
- Not a spray-and-pray exploit bot. It reasons, verifies, and refuses to report unproven findings.

## The moat: the Oracle

Anyone can prompt an LLM to "find logic bugs" — and get 60-80% false positives, exactly the AI slop that made HackerOne pause the Internet Bug Bounty in 2026. The hard, defensible part is the **Oracle**: a verification layer that *proves* a business invariant was violated (via invariant assertions + cross-session differential + state-delta judgment).

**Whoever solves the Oracle wins this category.** Everything else is plumbing. See [`03-ORACLE.md`](03-ORACLE.md).

## How it wins

| Competitor weakness | HERETIC answer |
|---|---|
| XBOW / Strix strong on technical bugs, weak on pure business logic | Purpose-built for logic; logic is the *only* focus |
| AI tools drown triagers in false positives | Oracle-gated: unproven findings are dropped, not reported |
| Generic "pentest agent" spreads thin over 40 bug classes | Narrow + deep: one bug class, done properly |
| Closed, expensive SaaS | Free, open, CLI, runs on the operator's box |

**Winning condition, concretely:** on a known target (crAPI, Juice Shop) HERETIC finds the documented logic bugs with a **false-positive rate below 10%**, fully autonomously. That is a result no open tool reliably delivers today.

## Non-goals

- Solving *all* vuln classes. Stay in the logic lane.
- Beating Nuclei at CVE matching. Call Nuclei for that; focus elsewhere.
- Autonomy at the cost of safety. Human-in-the-loop on any destructive action. See [`07-GUARDRAILS.md`](07-GUARDRAILS.md).
