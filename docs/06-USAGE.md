# 06 — Usage & How It Wins

## How the user uses it

HERETIC is a terminal tool. Install once, run per target.

```bash
# install
pipx install heretic          # or: docker run ghcr.io/you/heretic ...

# 1. describe the engagement (once)
heretic init                  # scaffolds roe.yaml + accounts.yaml

# 2. run a scan (lab, safe defaults)
heretic scan -u https://crapi.local \
  --roe roe.yaml \
  --accounts accounts.yaml \
  --model nemotron-super \
  --report findings.html

# 3. read results in terminal (live) + open the report
```

### Typical invocations

```bash
# focus on specific bug classes
heretic scan -u https://shop.test --classes bola,price,workflow,mass_assign

# fully local + private (real authorized target — nothing leaves the box)
heretic scan -u https://client.app --model ollama:nemotron-nano --mode dry-run

# pipe JSON into other tooling (classic-tool ergonomics)
heretic scan -u $TARGET -o json | jq '.findings[] | select(.severity=="critical")'

# resume a paused engagement
heretic resume --engagement ./engagements/crapi-2026-08-07.db
```

### What the operator sees (terminal, Rich live view)

```
HERETIC v0.1  ·  target https://crapi.local  ·  mode dry-run  ·  model nemotron-super

  Phase 1  recon (4 roles)        ✓  38 endpoints, 4 sessions
  Phase 2  intent model           ✓  12 invariants extracted
  Phase 3  hypotheses             ✓  57 tests queued
  Phase 4  execute        ██████░░  41/57
  Phase 5  oracle                 ▸  6 confirmed · 22 dropped (FP)

  CONFIRMED
  ┌ CRIT  BOLA  GET /api/order/{id}  · userA reads userB order 1042  · INV-1
  ├ HIGH  Mass-assignment  POST /api/profile  · set role=admin        · INV-5
  └ MED   Workflow bypass  ship without pay                           · INV-4
```

### The report (per finding)
- Title + severity + the **invariant broken**
- Expected-safe vs observed outcome
- **Reproducible PoC**: exact ordered requests, which identity sent each
- Business impact + remediation
- Which oracle(s) proved it

## Who uses it, and why they pick it

| User | Job to be done | Why HERETIC |
|------|----------------|-------------|
| **Bug bounty hunter** | find logic bugs faster than the crowd | automates the one class tools can't; low FP = reports get accepted |
| **Pentester / consultant** | cover logic testing in a time-boxed engagement | runs the tedious multi-session differential work autonomously |
| **AppSec engineer (internal)** | catch logic flaws pre-release in CI | CLI → drop into pipeline; local model = data never leaves |
| **Red team** | model + abuse business workflows at scale | intent model + chaining |

## How it wins (vs the crowded 2026 field)

The market is full of *broad* autonomous pentesters (XBOW, Strix, HexStrike, dozens more). They're strong on technical bugs and **weak on pure business logic** — the exact class HERETIC owns.

### Winning wedges

1. **Narrow + deep beats broad + shallow.** Everyone else spreads across 40 bug classes. HERETIC does one class properly. Depth is the differentiator.

2. **Low false-positive rate is the killer feature.** In 2026, 60-80% of AI bug submissions are invalid; HackerOne *paused* a program over AI slop. A tool that reports **only proven** logic bugs is worth more than one that reports 10× as many maybes. The Oracle is the product.

3. **Privacy via local Nemotron.** Consultants/enterprises can't send client apps to a cloud API. HERETIC runs fully local. Most competitors are cloud SaaS — they *can't* follow here.

4. **Free + open + CLI.** That's how HexStrike hit 10k★ and Strix hit 32k★. Distribution beats a paywall for adoption.

5. **Composable.** Pipes into existing workflows (`| jq`, CI, other tools). It's a *tool*, not a walled garden.

### The one-line pitch

> "The autonomous agent that finds the business-logic bugs your scanner can't and your competitors' AI reports wrong."

### The measurable claim that proves it

On crAPI + Juice Shop: finds the documented logic bugs, **< 10% false positives**, fully autonomous. Publish that benchmark → credibility → adoption.
