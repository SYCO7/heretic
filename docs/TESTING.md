# Testing HERETIC on Windows (every feature, every backend)

A reproduce-and-screenshot checklist. PowerShell, installed on the **D: drive**,
exercised with all three backends: **offline (`fake`)**, **NVIDIA (hosted)**, and
**Ollama (local)**. Each numbered *shot* is one screenshot worth capturing.

## 0. Prerequisites

- **Python 3.11+** — `winget install Python.Python.3.12`
- **Docker Desktop** (for the live vulnerable labs) — start it before the live shots.
- *(optional)* **Ollama** — `winget install Ollama.Ollama` (local, private model).
- *(optional)* **NVIDIA free API key** — from build.nvidia.com (hosted model).

## 1. Install on D:

```powershell
D:
mkdir D:\heretic-lab ; cd D:\heretic-lab
git clone https://github.com/SYCO7/heretic.git
cd heretic

# pipx (recommended) — isolated global CLI
py -m pip install --user pipx ; py -m pipx ensurepath      # reopen PowerShell after
pipx install .

# …or a venv on D:
py -m venv .venv ; .\.venv\Scripts\Activate.ps1 ; pip install -e ".[dev]"
```

**📸 Shot 1 — install + version:** `heretic version` → `HERETIC v1.0.0`

## 2. Offline proof (no key, no target)

**📸 Shot 2 — command list:** `heretic --help`
**📸 Shot 3 — the headline test:** `heretic bench`
→ shows **precision 100% · recall 100% · false-positive rate 0% (PASS)**. This is the
screenshot that proves the ~0-FP claim with zero setup.

## 3. Configure the backends

```powershell
# NVIDIA (hosted) — this shell:
$env:NVIDIA_API_KEY = "nvapi-xxxxxxxx"

# Ollama (local, private):
ollama serve            # leave running in its own window
ollama pull qwen2.5:7b  # any model; bigger = better for logic reasoning
```

**📸 Shot 4 — NVIDIA works:** `heretic doctor --ping`
→ `✓ NVIDIA_API_KEY is set` · `✓ model nemotron-super responds — responded`
**📸 Shot 5 — Ollama works:** `heretic doctor --ping --model ollama:qwen2.5:7b`
→ `✓ no API key needed (local Ollama)` · `✓ model ... responds`
**📸 Shot 6 — offline backend:** `heretic doctor --ping --model fake`

## 4. Stand up the live labs (Docker Desktop)

```powershell
docker run -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
docker run -d -p 5001:5000 --name vampi     erev0s/vampi
Invoke-RestMethod http://localhost:5001/createdb        # seed VAmPI users + books

# register two Juice Shop users (BOLA needs owned baskets):
$b = '{"email":"userA@heretic.test","password":"Heretic1!","passwordRepeat":"Heretic1!","securityQuestion":{"id":1},"securityAnswer":"x"}'
Invoke-RestMethod -Method Post http://localhost:3000/api/Users -ContentType application/json -Body $b
# repeat for userB@heretic.test
```

## 5. Guided flow (auto-detect login)

**📸 Shot 7 — connect:** `heretic connect`
→ enter `http://localhost:3000` + the two users → `✓ login detected POST /rest/user/login`
then it discovers the surface and confirms findings live.

## 6. Feature-by-feature (screenshot each)

Copy `targets\juiceshop\accounts.yaml.example` → `accounts.yaml`, set the two users.

**📸 Shot 8 — read-only scan, NO key needed** (safe on anything):
```powershell
heretic scan -u http://localhost:3000 --roe targets\juiceshop\roe.yaml `
  --accounts targets\juiceshop\accounts.yaml `
  --classes bola,bfla,excessive_data_exposure --discover --chain
```
→ CONFIRM lines + the findings table + `N confirmed · M dropped (0 FP)`.

**📸 Shot 9 — one-command guided + HTML report:**
```powershell
heretic auto --profile targets\juiceshop -u http://localhost:3000
```
Then open `heretic-report.html` in a browser →
**📸 Shot 10 — the report**: target, per-class chips, severity, PoC, and the OPD
`provenance` block (whose data leaked). A clean deliverable.

**📸 Shot 11 — VAmPI (different app, same 0-FP Oracle):**
```powershell
heretic scan -u http://localhost:5001 --roe targets\vampi\roe.yaml `
  --accounts targets\vampi\accounts.yaml `
  --classes bola,excessive_data_exposure,bfla --discover --chain
```

**📸 Shot 12 — CI outputs (SARIF + fail-on):**
```powershell
heretic scan -u http://localhost:3000 --roe targets\juiceshop\roe.yaml `
  --accounts targets\juiceshop\accounts.yaml `
  --classes bola,bfla,excessive_data_exposure --sarif heretic.sarif --fail-on high
echo "exit code: $LASTEXITCODE"     # non-zero => a HIGH+ finding gated the build
```

**📸 Shot 13 — resumable engagement:**
```powershell
heretic scan -u http://localhost:3000 --roe targets\juiceshop\roe.yaml `
  --accounts targets\juiceshop\accounts.yaml --classes bola --save run.db
heretic resume --engagement run.db
```

**📸 Shot 14 — interactive menu:** run bare `heretic` → the logo + guided menu.

## 7. Backend matrix (repeat a scan per brain)

Same scan, three brains — screenshot each so the post shows it's backend-agnostic.
Only the LLM-driven classes exercise the model; add `price_tamper,workflow_bypass`.

```powershell
$common = "-u http://localhost:3000 --roe targets\juiceshop\roe.yaml --accounts targets\juiceshop\accounts.yaml --mode live --classes bola,bfla,excessive_data_exposure,price_tamper,workflow_bypass,mass_assignment --discover --chain"

heretic scan $common --model fake             # 📸 Shot 15 — offline (mechanical classes)
heretic scan $common --model nemotron-super   # 📸 Shot 16 — NVIDIA (hosted brain)
heretic scan $common --model ollama:qwen2.5:7b# 📸 Shot 17 — Ollama (fully local/private)
```

> `--mode live` fires the state-changing classes — the Juice Shop RoE already
> ships safe defaults; these labs are authorized-by-design, so it's fine here.
> On a real program keep `dry-run` + the read-only class set.

## What each screenshot proves

| Shot | Proves |
|---|---|
| 3 (bench) | ~0 FP with zero setup — the core claim |
| 4/5/6 | works on NVIDIA, Ollama, and offline |
| 8/9/11 | real findings on two live apps, 0 FP |
| 10 | deliverable-grade report + the OPD provenance evidence |
| 12 | CI-ready (SARIF + fail-on) |
| 15/16/17 | backend-agnostic (hosted / local / offline) |

## Teardown

```powershell
docker rm -f juiceshop vampi
```
