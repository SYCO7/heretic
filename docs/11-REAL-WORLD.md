# 11 — Get the real-world number (authorized targets)

The offline benchmark and the three vuln-labs prove HERETIC *works*. They do **not**
prove its false-positive / recall rate on a **hardened, real** application. That
number only comes from running it — legally — against a real target. This page is
how you do that, and how you report it credibly.

> ⚠️ **Authorized testing only.** A public bug-bounty scope or a system you own /
> have written permission to test. Never point HERETIC at a third party without it.

## 0. Before you touch the target

- Read the **program brief**. Note the **in-scope** hosts, the **out-of-scope**
  list, the **rate limit**, and any **required attribution header**.
- Register **two of your own** accounts on the app (plus-addressing works:
  `you+a@mail.com`, `you+b@mail.com`). Never use real users' data.
- Start from the template: `cp -r targets/bugbounty targets/<program>` and edit
  `roe.yaml` (scope, attribution header) — it ships **read-only + rate-limited**.

## 1. Run — safe first pass (read-only, no state change)

```bash
# fastest: auto-detect login from two accounts, then scan the read-only classes
heretic connect                         # writes the profile + runs it

# or drive the edited template explicitly:
heretic scan -u https://api.example.com \
  --roe targets/<program>/roe.yaml \
  --accounts targets/<program>/accounts.yaml \
  --discover --chain \
  --log engagements/<program>.jsonl \
  --report engagements/<program>.html
```

`classes: [bola, bfla, excessive_data_exposure]` change nothing on the target and
need no LLM key. That is your safe automated first pass on a live program.

**State-changing classes** (price / mass-assignment / workflow / coupon / race)
mutate state — run them **only** against an instance you own or a staging box you
are authorized to mutate: `--mode live` + RoE `destructive_allowed: ["*"]`.

## 2. Produce the number

Every confirmed finding is Oracle-proven with a reproducible PoC, so:

- **Precision** = (confirmed findings you triage as *real*) ÷ (all confirmed).
  Because the Oracle already dropped the unprovable candidates, this should be
  high — *measure it* by validating each confirmed PoC by hand and reporting the
  ratio. This is the headline real-world number.
- **Recall** is harder on a fresh target (you don't know the full bug set). Two
  honest ways to get a denominator:
  1. **Disclosed reports** — for a program with public disclosures, treat the
     known business-logic bugs as ground truth and see how many HERETIC re-finds.
  2. **Your own manual pass** — hunt the app by hand, then diff: what did HERETIC
     get, what did it miss? Misses are the coverage backlog.

To score automatically against a ground-truth file you maintain:

```bash
# add targets/<program>/ground_truth.yaml  ({bug_class, match} per known bug)
heretic livecheck --profile targets/<program> -u https://api.example.com \
  --max-fp 0.10 --min-recall 0.5
```

## 3. Report it credibly

- Publish **target build/version + the exact profile + the numbers together**, or
  the benchmark means nothing. That transparency is the credibility.
- Keep the trace: `--log` writes an auditable JSONL of every request/verdict; the
  `--report` HTML carries the PoC per finding — hand it straight to the program.
- Each confirmed finding already includes the invariant broken, the observed vs
  expected, and a replayable PoC — paste it into the report as-is.

## Honesty checklist

- Only in-scope hosts were tested (the scope gate blocks the rest — keep it tight).
- The required attribution header was set (`headers:` in the RoE, sent on every request).
- The rate limit was respected (`max_rate_rps` / `max_parallel`).
- State-changing tests ran **only** where you were authorized to mutate state.
- The reported precision/recall names the exact target build + profile used.
