# 12 — OPD: Ownership Provenance Differential

**HERETIC's own algorithm** — a deterministic evidence metric for access-control
violations, original to this project. Source: [`src/heretic/core/provenance.py`](../src/heretic/core/provenance.py).

## The problem it solves

Field-based leak detection asks "does this record have an `owner` field pointing at
someone else?" That misses two big cases: APIs that don't *label* ownership, and
item responses that echo a foreign owner's data without any owner field at all.

OPD needs no label. It works from the **ownership tokens** an engagement already
knows — each identity's login identifiers plus the object ids that identity
provably owns — and asks a sharper question: *whose data is actually in this
response?*

## The algorithm

1. **Build the ownership map.** For every authenticated role, collect its tokens
   (login identifiers + owned object ids). Drop tokens shorter than 3 chars, common
   noise (`true`, `admin`, `id`…), and any token owned by more than one role (not
   owner-distinguishing). Result: `token → owning_role`.

2. **Signature a response.** Walk every scalar value out of a response and, by
   **whole-value equality** (not substring), count how many tokens of each role
   appear: `signature(response) = { role: count }`.

3. **Provenance purity.** For the identity that received the response (`viewer`):

   ```
   own      = signature[viewer]
   foreign  = Σ signature[r]  for r ≠ viewer
   purity   = own / (own + foreign)          # 1.0 if nothing matched
   ```

   `purity < 1` ⟺ the response carries another identity's data ⟹ a leak. The lower
   the purity and the more `foreign` tokens, the worse the exposure.

This single number unifies two bug classes:

| Case | Signature | Meaning |
|---|---|---|
| BOLA (item) | one foreign owner | `viewer` read another user's object |
| Data exposure (list) | many owners | one response co-mingles several users |
| Correct (private) | only `viewer` | purity = 1.0, no finding |
| Public catalog | no owned tokens at all | OPD stays silent (no evidence) |

## Why it fits HERETIC

- **Deterministic** — pure arithmetic over observed values; no LLM, reproducible.
- **Additive & safe** — OPD *enriches* an already-Oracle-confirmed finding with a
  `provenance` proof block; it never confirms on its own, so it **cannot raise the
  false-positive rate**. (Benchmark stays at precision/recall 100%, FP 0%.)
- **Label-agnostic** — catches leaks the `owner`-field heuristics can't see.

## What it looks like

A confirmed BOLA / data-exposure finding gains:

```json
"provenance": { "own_tokens": 0, "foreign_tokens": 2, "purity": 0.0, "leaked_owners": ["userA"] }
```

Verified live on **OWASP VAmPI**: the `/users/v1` exposure and the book BOLA carry
provenance blocks with `purity 0.0` — quantified proof of exactly whose data leaked.
