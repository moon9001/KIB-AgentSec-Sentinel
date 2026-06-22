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


def align_single_zip_truth_mismatch(
    details: dict[str, dict[str, Any]], truth: dict[str, int], truth_path: Path
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    missing = sorted(set(truth) - set(details))
    extra = sorted(set(details) - set(truth))
    zip_stems = sorted(path.stem for path in truth_path.parent.glob("*.zip"))
    zip_not_truth = sorted(set(zip_stems) - set(truth))
    diagnostics: dict[str, Any] = {
        "applied": False,
        "missing_before": missing,
        "extra_before": extra,
        "zip_count": len(zip_stems),
        "zip_not_truth": zip_not_truth,
    }
    if len(missing) == 1 and len(extra) == 1 and extra == zip_not_truth and extra[0] in details:
        aligned = dict(details)
        row = dict(aligned.pop(extra[0]))
        row["md5"] = missing[0]
        aligned[missing[0]] = row
        diagnostics.update({"applied": True, "mapped_detail_md5": extra[0], "to_truth_md5": missing[0]})
        return aligned, diagnostics
    return details, diagnostics


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
    truth_path = Path(args.truth)
    truth = read_truth(truth_path)
    details = read_scores(Path(args.detail))
    details, alignment = align_single_zip_truth_mismatch(details, truth, truth_path)
    rows = []
    for threshold in range(args.start, args.stop + 1, args.step):
        pred = {md5: 1 if float(row.get("score") or 0) >= threshold else 0 for md5, row in details.items()}
        rows.append({"threshold": threshold, **compute_metrics(pred, truth)})
    print(json.dumps({"md5_alignment": alignment, "sweep": rows}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
