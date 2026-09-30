#!/usr/bin/env python3
"""Train the SetFit labeler for blueteam_incident_label, backend=setfit.
Reads the JSONL corpus scripts/build_label_corpus.py writes and
scripts/calibrate_labeler.py evaluates, trains on ``split=train`` only, scores the
``val`` split, and saves the tree BLUETEAM_LAYA_MODEL_PATH points at. The printed
BLUETEAM_LAYA_MODEL_SHA256 is the tree hash the server verifies before it unpickles
the classification head; nothing is fetched at call time.
Training does download the base body from the Hugging Face Hub once, so run it on a
host with network access. ``--dry-run`` validates the corpus and prints class counts
without importing torch.
Run from the repo root:
python3 scripts/train_setfit_labeler.py --input calibration/corpus.jsonl \\
--out /opt/blue-team-mcp/setfit-tactics
"""
from __future__ import annotations
import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from calibrate_labeler import load_cases

DEFAULT_BODY = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"

def select_train_rows(cases: List[dict], per_class: int, seed: int) -> List[dict]:
    """Stratified few-shot selection, deterministic per (corpus, per_class, seed) so
    a re-run on the same corpus trains on the same rows. ``per_class=0`` keeps all."""
    if per_class <= 0:
        return list(cases)
    by_tactic: Dict[str, List[dict]] = {}
    for case in cases:
        by_tactic.setdefault(case["truth"], []).append(case)
    rng = random.Random(seed)
    picked: List[dict] = []
    for tactic in sorted(by_tactic):
        rows = list(by_tactic[tactic])
        rng.shuffle(rows)
        picked.extend(rows[:per_class])
    return picked


def _split_rows(cases: List[dict], split: str) -> List[dict]:
    return [case for case in cases if case["split"] == split]


def _train(args: argparse.Namespace, train: List[dict], val: List[dict]) -> int:
    from datasets import Dataset
    from setfit import SetFitModel, Trainer, TrainingArguments

    from mcp_server.label import criteria
    from mcp_server.label.backends import _tree_sha256

    train_ds = Dataset.from_list(
        [{"text": row["state_text"], "label": row["truth"]} for row in train])
    val_ds = Dataset.from_list(
        [{"text": row["state_text"], "label": row["truth"]} for row in val])

    # The labels passed here are what id2label is built from at load time, so they
    # are the criteria vocabulary in criteria order, never the corpus' first-seen.
    model = SetFitModel.from_pretrained(args.body, labels=list(criteria.TACTICS))
    # v1.1 moved max_seq_length off TrainingArguments; set it on the body when the
    # attribute exists and keep the trainer default otherwise.
    if hasattr(model, "max_seq_length"):
        model.max_seq_length = args.max_seq_length

    training_args = TrainingArguments(
        batch_size=args.batch_size,
        num_epochs=args.num_epochs,
        seed=args.seed,
        eval_strategy="epoch",
        save_strategy="no",
        report_to="none",
    )
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        metric="accuracy",
        column_mapping={"text": "text", "label": "label"},
    )
    trainer.train()
    metrics: Dict[str, Any] = trainer.evaluate()
    print(f"val metrics: {metrics}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(out))
    (out / "training_metrics.json").write_text(
        json.dumps({"body": args.body, "samples_per_class": args.samples_per_class,
                    "num_epochs": args.num_epochs,
                    "max_seq_length": args.max_seq_length, "seed": args.seed,
                    "metrics": metrics}, indent=2, sort_keys=True),
        encoding="utf-8")
    # Computed last, over everything the directory now holds: the server verifies the
    # whole tree before from_pretrained unpickles the head.
    print(f"BLUETEAM_LAYA_MODEL_SHA256={_tree_sha256(str(out))}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True,
                        help="JSONL corpus (build_label_corpus.py schema)")
    parser.add_argument("--out", required=True,
                        help="directory the server pins and loads")
    parser.add_argument("--body", default=DEFAULT_BODY,
                        help="sentence transformer to fine-tune")
    parser.add_argument("--samples-per-class", type=int, default=16,
                        help="few-shot cap per tactic on the train split; 0 keeps all")
    parser.add_argument("--num-epochs", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--max-seq-length", type=int, default=256)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--dry-run", action="store_true",
                        help="validate the corpus and print counts, no training")
    args = parser.parse_args()

    cases = load_cases(args.input)
    train = select_train_rows(_split_rows(cases, "train"), args.samples_per_class,
                              args.seed)
    val = _split_rows(cases, "val")
    if not train:
        splits = sorted({case["split"] for case in cases})
        print(f"error: no train rows in {args.input} (splits present: {splits})",
              file=sys.stderr)
        return 2
    counts = Counter(case["truth"] for case in train)
    print(f"{len(train)} train rows over {len(counts)} tactics; {len(val)} val rows")
    for tactic, count in sorted(counts.items()):
        print(f"  {tactic}: {count}")
    if args.dry_run:
        return 0
    if not val:
        print("error: no val rows; a run without evaluation cannot be gated",
              file=sys.stderr)
        return 2
    return _train(args, train, val)


if __name__ == "__main__":
    raise SystemExit(main())
