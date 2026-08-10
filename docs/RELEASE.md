# Release checklist — ship HERETIC

Everything here is real and reproducible. Commands you run yourself are marked **(you run)**
because they need your accounts/tokens.

## 0. Pre-flight (already green)

```bash
make lint            # ruff — clean
make test            # 75 tests pass
heretic bench        # precision/recall/FP scoreboard, exit 0
python -m build && python -m twine check dist/*   # sdist + wheel, both PASSED
```

A fresh-venv install of the wheel runs (`heretic version`, `heretic bench`) — verified.

## 1. GitHub **(you run)**

⚠ Verify secrets never leave your box first:

```bash
git init && git add -A
git status --short | grep -E '\.env|accounts\.yaml$' && echo "STOP — secret staged" || echo "clean"
```

`.gitignore` already excludes `.env`, every `accounts.yaml`, `*.db`, engagement logs, and `dist/`.
The shippable target profiles (`targets/*/roe.yaml`, `ground_truth.yaml`, `accounts.yaml.example`) and
the real demo cast (`docs/demo/heretic-demo.cast`) DO get committed.

```bash
git commit -m "HERETIC v0.1.0 — autonomous business-logic vuln agent"
gh repo create heretic --public --source=. --push
git tag v0.1.0 && git push --tags
gh release create v0.1.0 --title "v0.1.0" --notes "First public release. Confirms crAPI + Juice Shop BOLA/IDOR live, 0 FP."
```

## 2. PyPI **(you run)** — so `pip install` works

Confirm the name is free on https://pypi.org/project/heretic-agent/ (change `name` in `pyproject.toml`
if taken; the CLI command stays `heretic` regardless).

```bash
python -m build                                   # dist/heretic_agent-0.1.0.{whl,tar.gz}
python -m twine upload dist/*                      # needs your PyPI API token
pip install heretic-agent && heretic version       # smoke test the published package
```

Tip: test on TestPyPI first — `twine upload --repository testpypi dist/*`.

## 3. The demo — real, not staged

`scripts/demo.sh` runs HERETIC against a live Juice Shop; `docs/demo/heretic-demo.cast` is the recording.

```bash
asciinema play docs/demo/heretic-demo.cast         # watch it locally
asciinema upload docs/demo/heretic-demo.cast       # (you run) → public URL to embed in the README
```

For a GIF (README auto-plays it): install `agg` (`cargo install --git https://github.com/asciinema/agg`)
then `agg docs/demo/heretic-demo.cast docs/demo/heretic-demo.gif`.

## 4. Get users (distribution)

- Submit to **awesome-pentest**, **awesome-security**, **awesome-hacking** (PRs — free durable traffic).
- One honest write-up: "open-source agent that finds business-logic bugs — beats crAPI + Juice Shop at
  0 false positives" → r/netsec, Hacker News, infosec Mastodon/Twitter. Link the cast.
- Pin a GitHub issue "targets validated" and keep adding real runs (VAmPI, DVGA, bug-bounty labs) with
  their precision/recall — the track record is what converts skeptics.
