# 08 — AI Stack (models, routing, finetuning, ADK)

The engine is model-agnostic (`llm/base.py`), but here is the chosen, opinionated
default. TL;DR: **Nemotron 3** everywhere — Super (free NVIDIA NIM) as the brain,
**Nano (local Ollama)** as the private, finetunable workhorse.

## The layers are not competitors

| Name | What it is |
|------|-----------|
| **Nemotron 3** | the model (open weights): Nano / Super / Ultra |
| **NVIDIA NIM** | NVIDIA's hosted API to run Nemotron in the cloud (free credits) |
| **Ollama** | local runtime to run the open-weight Nemotron on your own box |
| **Gemini** | a separate Google model (cloud-only, not finetunable by us) |

"Nemotron vs NIM vs Ollama" = same model, different place to run it.

## Per-phase routing (`llm/router.py`)

Different agents want different brains. `--model auto` routes each phase:

| Phase / agent | Default model | Why |
|---------------|---------------|-----|
| intent model | `nemotron-super` (NIM) | needs the smartest reasoning + 1M ctx |
| hypothesis / chain | `nemotron-nano` (local) | cheap, many calls, private |
| oracle judge | `nemotron-super` (NIM) | verdict quality matters most (the moat) |
| refuter panel | `openrouter-r1` (DeepSeek-R1 free) | a DIVERSE voice — skeptics should fail differently from the judge |

Override per phase in the RoE:
```yaml
models:
  hypothesis: ollama:nemotron-nano
  refute:     groq
```

Modes:
- `--model nemotron-super` → one model for every phase (needs one key). **Default.**
- `--model auto` → the routing table above (needs NVIDIA + OpenRouter keys + local Ollama).
- `--model ollama:nemotron-nano` → fully local / private (nothing leaves the box).
- `--model fake` → offline ScriptedLLM (tests / demos).

Graceful fallback: if a phase's backend has no key, the router falls back to any
working backend; if none work, the engine runs the mechanical checks (BOLA, race)
only. **Control flow stays deterministic — the router only picks brains.**

## Access (all free)

```bash
export NVIDIA_API_KEY=...        # build.nvidia.com — free Nemotron Super/Nano
export GEMINI_API_KEY=...        # aistudio.google.com — free 1M-ctx Flash
export OPENROUTER_API_KEY=...    # openrouter.ai — free DeepSeek-R1 for refuters
# or fully local, no keys:
ollama pull nemotron-3-nano && ollama serve
```

## Finetuning — the private specialist (see `finetune/`)

Don't pretrain. The pipeline is already built:

```
1. run with the teacher   heretic scan --model nemotron-super --log run.jsonl ...
2. export confirmed traces heretic export --trace run.jsonl --out data.jsonl --format chat
3. QLoRA the student       python finetune/qlora_nemotron_nano.py data.jsonl
                             (Unsloth + free Colab T4 / Kaggle / Lightning GPU)
4. serve it                 ollama create heretic-nano -f Modelfile
                             heretic scan --model ollama:heretic-nano ...
```

This is **distillation**: the strong teacher (Super) generates confirmed reasoning
traces; the small student (Nano) learns them → a private, offline model that reasons
like the big one on your GPU. `heretic export` already produces the training file.
The `--memory` pattern loop improves prompting between runs *without* training; the
distil step bakes it into weights.

## ADK / multi-agent — the decision

HERETIC is already multi-agent (recon / intent / hypothesis / judge / refuter-panel /
chain), just hand-rolled. We deliberately **do not** hand control flow to an agent
framework (Google ADK, LangGraph autonomy, etc.):

> **LLM proposes, code disposes.** Scope / mode / rate gates are enforced in plain
> code the model cannot override (prompt-injection defense, see `07-GUARDRAILS.md`).
> An autonomous agent mesh driving control flow would break that guarantee.

What we adopted from the ADK philosophy instead: **per-phase model routing** (above) —
specialized agents with specialized models — while keeping the deterministic core.

Full ADK / A2A is worth revisiting only if we later need agents distributed across
machines or teams. Not required for v1.
