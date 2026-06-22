#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sweep score thresholds using detail.jsonl and truth labels.")
    parser.add_argument("--detail", required=True, help="detail.jsonl produced by run_detect.py.")
    parser.add_argument("--truth", required=True, help="Truth results.csv with md5,label columns.")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--stop", type=int, default=100)
    parser.add_argument("--step", type=int, default=5)
    return parser.parse_args()


def read_truth(path: Path) -> dict[str, int]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        labels: dict[str, int] = {}
        for row in reader:
            md5 = (row.get("md5") or "").strip()
            label = (row.get("label") or "").strip()
            if md5 and label in {"0", "1"}:
                labels[md5] = int(label)
        return labels


def read_scores(path: Path) -> dict[str, dict[str, Any]]:
    scores: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            md5 = str(row.get("md5", "")).strip()
            if md5:
                scores[md5] = row
        return scores


def compute_metrics(pred: dict[str, int], truth: dict[str, int]) -> dict[str, Any]:
    common = sorted(set(pred) & set(truth))
    tp = sum(1 for md5 in common if pred[md5] == 1 and truth[md5] == 1)
    tn = sum(1 for md5 in common if pred[md5] == 0 and truth[md5] == 0)
    fp = sum(1 for md5 in common if pred[md5] == 1 and truth[md5] == 0)
    fn = sum(1 for md5 in common if pred[md5] == 0 and truth[md5] == 1)
    total = len(common)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def main() -> int:
    args = parse_args()
    truth = read_truth(Path(args.truth))
    details = read_scores(Path(args.detail))
    rows = []
    for threshold in range(args.start, args.stop + 1, args.step):
        pred = {md5: 1 if float(row.get("score") or 0) >= threshold else 0 for md5, row in details.items()}
        rows.append({"threshold": threshold, **compute_metrics(pred, truth)})
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

