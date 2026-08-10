# 10 — Tech stack & design decisions

Everything HERETIC is built from, and *why*. The theme: **lean, auditable, no magic.** A security
tool people run against their own apps should be boring to read and easy to trust.

## Language & runtime

| Choice | Why |
|---|---|
| **Python 3.11+** | fast to write, ubiquitous in security tooling, great HTTP/async story. 3.11+ for `X \| None`, `StrEnum`, `tomllib`. |
| **No async framework** | the engine is I/O-bound but simple; threads (`ThreadPoolExecutor`) cover the one concurrent case (race-condition fire). Readability > cleverness. |

## Dependencies — deliberately five

Runtime deps, whole list:

| Package | Role |
|---|---|
| **typer** | the CLI (`scan`, `connect`, `auto`, `doctor`, `livecheck`, `bench`, …) |
| **rich** | live terminal output, the menu, tables, the banner |
| **httpx** | *one* HTTP client for BOTH the target and every OpenAI-compatible LLM API |
| **pyyaml** | `roe.yaml` / `accounts.yaml` |
| **pydantic v2** | config models + the authorization gate (a security boundary in plain code) |

Optional extras (only if you use them): **playwright** (browser XHR capture), **google-genai**
(Gemini backend), **chromadb** (swap the RAG-lite keyword store for embeddings).

**What we deliberately DON'T use, and why:**
- ❌ **LangChain / agent frameworks** — hidden control flow is the enemy of a tool that must enforce
  scope/mode gates deterministically. HERETIC's loop is a plain state machine you can read.
- ❌ **Provider SDKs** — every backend except Gemini speaks OpenAI-compatible `/chat/completions`, so
  one httpx client + a registry of `{base_url, model, key_env}` covers Nemotron, Groq, OpenRouter,
  Ollama. Swapping a model is a dict entry.
- ❌ **A vector DB** — the knowledge base is a bundled keyword store (RAG-lite). No external service,
  no embeddings server, fully offline.

## The LLM layer

- **Backends (all free-tier):** NVIDIA Nemotron (Super/Nano/Ultra), Gemini, Groq, OpenRouter (R1),
  and **local Ollama** (`ollama:<model>`).
- **Auto-detection** (`llm/select.py`): detects hosted keys + a running Ollama with its pulled models
  and picks the best automatically. A saved `HERETIC_MODEL` wins. Falls back to a `fake` scripted LLM
  (offline) so the mechanical checks always run with zero setup.
- **Per-phase routing** (`--model auto`): a strong model for intent/judge, a cheap one for hypotheses,
  a *diverse* one (DeepSeek-R1) for the refuter panel — different models catch different failure modes.
- **Private/offline:** point it at Ollama; nothing leaves the box.

## Core modules (`src/heretic/core/`)

| Module | Responsibility |
|---|---|
| `session_mgr.py` | multi-role auth engine; owner-field-aware + login-response id harvest |
| `login_detect.py` | auto-detect the login endpoint + token field from credentials |
| `discovery.py` | 5-source surface discovery (OpenAPI · JS+prefix-resolve · wordlist · list→detail) + object inference |
| `browser.py` | headless-Chromium XHR capture (Playwright) — runtime-built URLs |
| `intent_model.py` | LLM builds the app's invariant model from observed traffic |
| `hypothesis.py` + `bola.py` + `exposure.py` + `race.py` | per-class test generation |
| `oracle.py` | **the moat** — cross-session diff, invariant assertion, state-delta judge + refuter panel |
| `chain.py` | compose confirmed primitives into higher-impact chains |
| `mutate.py` | feedback loop — mutate a failed logic input and retry |
| `engagement.py` | SQLite checkpoint → resumable scans |
| `trace.py` + `dataset.py` + `memory.py` | audit log · fine-tune export · self-improvement memory |

## The security boundary

`config.py` is a hard boundary, not a suggestion. It refuses to run without a **signed RoE**
(`signed: true`, `authorized_by`, a non-empty scope allow-list). `assert_in_scope()` is called
before **every** request; state-changing tests are gated behind `mode: live` + explicit
`destructive_allowed`. The LLM can propose anything — plain code decides what actually fires. This is
the prompt-injection defense: a compromised model still can't leave scope or mutate state.

## Verification / CI

- **ruff** (lint) + **81 pytest tests** (fully offline via `httpx.MockTransport` + a scripted LLM).
- **`heretic bench`** — a built-in vulnerable mock app + ground truth; scores precision/recall/FP and
  **exits non-zero if the FP-rate regresses**. Wired into GitHub Actions alongside lint + tests.
- Every finding is Oracle-proven and re-run for reproducibility before it's reported.

## Packaging & distribution

- **hatchling** build backend → `pip install heretic-agent` (CLI stays `heretic`); sdist + wheel pass
  `twine check` and install/run clean in a fresh venv.
- **Docker** (`Dockerfile`), **Apache-2.0**, `pipx`-friendly, single entry point.

## Data flow (one line)

`URL + 2 accounts → multi-role login → discover surface → model invariants → generate tests →
Oracle proves/drops → chain → reproducible report`. Everything stays on the operator's machine.
