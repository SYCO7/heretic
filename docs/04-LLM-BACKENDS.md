# 04 — LLM Backends (incl. NVIDIA Nemotron analysis)

HERETIC treats the LLM as a **pluggable backend**. Pick per-phase; swap with a flag. Never hardcode.

```bash
heretic scan -u TARGET --model nemotron-super      # NVIDIA free API
heretic scan -u TARGET --model gemini-flash        # Google free API, 1M ctx
heretic scan -u TARGET --model ollama:nemotron-nano # fully local, private
```

---

## Should I use NVIDIA Nemotron? — YES, it's a strong fit. Here's why.

**Nemotron 3** (2026) is NVIDIA's open-weight family — **Nano / Super / Ultra** — built specifically for **agentic reasoning and tool-calling**, which is *exactly* HERETIC's workload. Hybrid Mamba-Transformer MoE, open weights + open training data/recipe, **1M-token context**.

Why it fits HERETIC better than a generic chat model:
- **RL-trained for multi-turn tool-calling / agentic behavior.** HERETIC is a tool-calling agent loop. This is the model's home turf, not an afterthought.
- **1M context** → feed the *entire* crawled app into Phase 2 intent-modeling in one shot. No chunking, no lost cross-endpoint invariants.
- **Open weights** → run it locally for private/real-target engagements. No data leaves the box. Huge for a pentest tool (sending a client's app to a cloud API is a legal problem).
- **MoE efficiency** → small *active* param count = fast + cheap to run locally.
- **Reasoning toggle** → turn deep chain-of-thought on for hard hypothesis/oracle steps, off for cheap mechanical calls → controls cost/latency.

### Nemotron 3 sizes (pick by hardware)

| Model | Total / active params | Local VRAM | Context | Best HERETIC role |
|-------|----------------------|-----------|---------|-------------------|
| **Nano 4B** | 4B | ~5 GB | 1M | laptop/CPU; cheap mechanical calls, hypothesis expansion |
| **Nano 30A3B** | 31.6B / 3.6B active (MoE) | ~24 GB (quantized) | 1M | **best local default** — runs on one consumer GPU, 4× faster than Nemotron 2 |
| **Super** | 120.6B / 12.7B active | multi-GPU / cloud | 1M | best quality via **free NVIDIA API**; Phase-2 modeling + Oracle judge |
| **Ultra** | 550B / 55B active | data-center | 1M | overkill for now; cloud only |

### How to access Nemotron for free
- **NVIDIA API (build.nvidia.com / NIM):** hosted Nemotron endpoints with free developer credits — OpenAI-compatible. Best zero-setup path for Super-tier quality.
- **Local via Ollama / llama.cpp / vLLM:** pull the open weights (Hugging Face `nvidia/…`), run Nano locally. Free forever, private, offline.

### The catch / watch-outs
- Nemotron is **reasoning/agentic-tuned**, not a safety-lobotomized chat model — good for us, but verify tool-call JSON formatting matches your schema (it's RL-trained for structured function calls, so usually clean).
- Super/Ultra local self-hosting needs serious VRAM — use the **free NVIDIA API** for those tiers, keep **Nano** for local.
- Free NVIDIA credits are finite — architect so the heavy Super calls are few (Phase 2 + Oracle judge), cheap calls go to local Nano.

---

## Full backend comparison

| Backend | Cost | Context | Strength | Use for | Privacy |
|---------|------|---------|----------|---------|---------|
| **Nemotron 3 Super** (NVIDIA API) | Free credits | 1M | agentic tool-calling, reasoning | Phase 2 model + Oracle judge | cloud |
| **Nemotron 3 Nano** (local Ollama) | Free | 1M | efficient, private, tool-calling | everything, offline / real targets | **local** |
| **Gemini 2.x Flash** (Google) | Free 1500 req/day | 1M | huge context, fast, multimodal | Phase 2 whole-app modeling | cloud |
| **Groq** (Llama 3.3 70B) | Free 30 rpm | 128K | very fast inference | tight hypothesis loops | cloud |
| **Cerebras** | Free 1M tok/day | — | highest throughput | batch test judging | cloud |
| **OpenRouter** (DeepSeek-R1 `:free`) | Free | large | strong reasoning | Oracle refuters | cloud |
| **Ollama** (Qwen3 14B) | Free | 128K+ | solid local generalist | fallback local brain | **local** |

## Recommended default config

```yaml
# heretic llm profile — zero dollar
phase_2_intent_model: nemotron-super      # or gemini-flash (both 1M ctx)
phase_3_hypothesis:   nemotron-nano-local # cheap, many calls
phase_5_oracle_judge: nemotron-super      # quality matters most here
phase_5_refuters:     openrouter:deepseek-r1:free  # diverse 2nd opinion
embeddings_rag:       local (bge-small / nomic-embed via Ollama)
private_real_targets: nemotron-nano-local ONLY   # nothing leaves the box
```

**Rule of thumb:**
- **Labs / research** → free cloud APIs (Nemotron Super, Gemini) for best quality.
- **Real authorized targets / client data** → **local Nemotron Nano only.** Privacy + legality.

## "Build my own AI for free, low resources"

Don't pretrain — impossible solo. Path, cheapest → best:
1. **RAG (do this first, near-free):** embed WSTG + HackTricks + PortSwigger logic labs + your own findings into Chroma. Small model now "knows" logic tradecraft without training.
2. **LoRA / QLoRA fine-tune (later):** free GPU on Google Colab T4 / Kaggle (30h/wk) / Lightning free tier. QLoRA a Nemotron Nano 4B on your *own logged successful attacks* → self-improving specialist.
3. **Distillation (the clever move):** use free Nemotron Super (API) to generate reasoning traces on solved bugs → fine-tune local Nano on those traces. Now a small, private, on-GPU model reasons like the big one. This is the realistic "my own AI" endgame.
