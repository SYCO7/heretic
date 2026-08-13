# HERETIC in CI — shift-left business-logic testing

HERETIC emits **SARIF 2.1.0**, so its findings show up in the GitHub **Security → Code scanning**
tab (and GitLab / Azure DevOps ingest SARIF too). Fail the build on high-severity bugs before they
ship.

## One-line GitHub Action

Add this to `.github/workflows/heretic.yml` (point it at a **staging** instance you're authorized to
test — never production without written authorization):

```yaml
name: business-logic scan
on: [workflow_dispatch]          # or: schedule / deployment to staging
permissions:
  security-events: write         # required to upload SARIF
jobs:
  heretic:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: SYCO7/heretic@v1.0.0
        with:
          url: https://staging.example.com
          roe: security/roe.yaml
          accounts: security/accounts.yaml    # store real creds in secrets, template at build time
          classes: bola,bfla,excessive_data_exposure   # read-only set — safe in CI, no LLM key needed
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: heretic.sarif
```

Findings appear as code-scanning alerts; the job fails if anything is `high`+.

## Plain CLI (any pipeline)

```bash
pip install heretic-agent
heretic scan -u "$STAGING_URL" --roe roe.yaml --accounts accounts.yaml \
  --classes bola,bfla,excessive_data_exposure --discover \
  --sarif heretic.sarif --fail-on high
echo "exit: $?"   # non-zero if a high+ finding was confirmed
```

## Which classes in CI?

- **Read-only, no key, safe by default:** `bola`, `bfla`, `excessive_data_exposure`. These never change
  state and need no LLM — ideal for every pipeline run.
- **State-changing (create users/orders):** `mass_assignment`, `price_tamper`, `workflow_bypass`,
  `race_condition`. Only against a disposable staging DB — require `mode: live` +
  `destructive_allowed` in the RoE. Run these on a schedule, not every PR.

## Why it's safe to gate on

Every finding is **Oracle-proven** — HERETIC reports only what it can prove, at ~0 false positives on
its live targets. A failing build means a real, reproducible bug, not AI noise. That's the difference
between a gate developers trust and one they mute.
