"""QLoRA finetune of Nemotron 3 Nano on HERETIC's confirmed attack traces.

This distils a private, offline business-logic specialist from the dataset that
`heretic export --format chat` produces. Runs on a free GPU (Colab T4 / Kaggle /
Lightning). NOT run by the test suite — it needs a GPU + the unsloth stack.

Usage:
    pip install "unsloth[colab-new]" trl peft accelerate bitsandbytes
    python finetune/qlora_nemotron_nano.py data.jsonl --out heretic-nano-lora

Input: JSONL, one {"messages":[{system},{user},{assistant}]} per line
       (exactly `heretic export --format chat`).
Output: a LoRA adapter (+ optional merged GGUF for Ollama).
"""
from __future__ import annotations

import argparse
import json

MODEL = "unsloth/nemotron-3-nano"          # open weights; swap for the 4B/30A3B variant you want
MAX_SEQ = 8192


def load_chat_jsonl(path: str) -> list[dict]:
    rows = []
    for line in open(path):
        line = line.strip()
        if line:
            rows.append(json.loads(line))          # {"messages": [...]}
    if not rows:
        raise SystemExit(f"no examples in {path} — run `heretic export --format chat` first")
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("data", help="chat-format JSONL from `heretic export`")
    ap.add_argument("--out", default="heretic-nano-lora")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--gguf", action="store_true", help="also export a merged GGUF for Ollama")
    args = ap.parse_args()

    # imports are local so the file is importable without a GPU stack installed
    from datasets import Dataset
    from trl import SFTTrainer, SFTConfig
    from unsloth import FastLanguageModel
    from unsloth.chat_templates import get_chat_template

    model, tokenizer = FastLanguageModel.from_pretrained(
        MODEL, max_seq_length=MAX_SEQ, load_in_4bit=True,   # QLoRA: 4-bit base
    )
    model = FastLanguageModel.get_peft_model(
        model, r=16, lora_alpha=16, lora_dropout=0.0,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing="unsloth",
    )
    tokenizer = get_chat_template(tokenizer, chat_template="chatml")

    rows = load_chat_jsonl(args.data)
    ds = Dataset.from_list(rows).map(
        lambda r: {"text": tokenizer.apply_chat_template(
            r["messages"], tokenize=False, add_generation_prompt=False)}
    )

    trainer = SFTTrainer(
        model=model, tokenizer=tokenizer, train_dataset=ds,
        args=SFTConfig(
            dataset_text_field="text", max_seq_length=MAX_SEQ,
            per_device_train_batch_size=2, gradient_accumulation_steps=4,
            warmup_steps=5, num_train_epochs=args.epochs, learning_rate=2e-4,
            logging_steps=1, optim="adamw_8bit", output_dir="outputs",
        ),
    )
    trainer.train()

    model.save_pretrained(args.out)
    tokenizer.save_pretrained(args.out)
    print(f"saved LoRA adapter -> {args.out}")

    if args.gguf:
        model.save_pretrained_gguf(args.out + "-gguf", tokenizer, quantization_method="q4_k_m")
        print(f"saved GGUF -> {args.out}-gguf  (import into Ollama, then: heretic scan --model ollama:heretic-nano)")


if __name__ == "__main__":
    main()
