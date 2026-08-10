# Finetuning a private HERETIC specialist

Distil a small, offline, business-logic-specialist model from HERETIC's own
confirmed attack traces. Free GPU, no pretraining. See `docs/08-AI-STACK.md`.

## Pipeline

```bash
# 1. run with a strong teacher (free NVIDIA NIM), logging every verdict
export NVIDIA_API_KEY=...
heretic scan -u https://lab.local --roe roe.yaml --accounts accounts.yaml \
  --model nemotron-super --chain --log run.jsonl

# 2. turn the CONFIRMED traces into a chat-format finetune set
heretic export --trace run.jsonl --out data.jsonl --format chat

# 3. QLoRA Nemotron Nano on it  (Colab T4 / Kaggle 30h-wk / Lightning free tier)
pip install "unsloth[colab-new]" trl peft accelerate bitsandbytes datasets
python finetune/qlora_nemotron_nano.py data.jsonl --out heretic-nano-lora --gguf

# 4. serve the specialist locally via Ollama, then point HERETIC at it
#    (import the GGUF with a Modelfile, e.g. `ollama create heretic-nano -f Modelfile`)
heretic scan -u https://lab.local --roe roe.yaml --accounts accounts.yaml \
  --model ollama:heretic-nano
```

## Why this works

- **Distillation:** the teacher (Super) produces confirmed reasoning traces; the
  student (Nano) learns them → reasons like the big model, but runs on your GPU,
  offline, private.
- **Only confirmed traces** are exported — the Oracle already filtered out false
  positives, so you train on proven-good examples, not slop.
- **Accumulate across engagements:** keep appending to `run.jsonl` (or several logs)
  and re-export; more confirmed traces → a stronger specialist over time.

## Notes

- `qlora_nemotron_nano.py` needs a CUDA GPU + the unsloth stack; it is intentionally
  **not** part of the test suite.
- Swap `MODEL` in the script for the exact Nemotron Nano variant you want (4B for a
  5 GB card, 30A3B MoE for ~24 GB).
- Keep client data out of shared training sets — traces may contain sensitive values.
  `.gitignore` already excludes `*.jsonl` engagement/dataset/memory files.
