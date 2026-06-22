#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate result.csv against a labeled results.csv if labels are available.")
    parser.add_argument("--pred", required=True, help="Predicted result.csv with md5,label columns.")
    parser.add_argument("--truth", required=True, help="Truth results.csv with md5,label columns.")
    return parser.parse_args()


def read_labels(path: Path, role: str) -> dict[str, int] | None:
    if not path.exists():
        print(json.dumps({"status": "skipped", "reason": f"{role} file not found: {path}"}, ensure_ascii=False, indent=2))
        return None
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "md5" not in reader.fieldnames or "label" not in reader.fieldnames:
            print(json.dumps({"status": "skipped", "reason": f"{role} file has no md5,label columns"}, ensure_ascii=False, indent=2))
            return None
        labels: dict[str, int] = {}
        for row in reader:
            md5 = (row.get("md5") or "").strip()
            label = (row.get("label") or "").strip()
            if not md5 or label not in {"0", "1"}:
                continue
            labels[md5] = int(label)
    return labels


def align_single_zip_truth_mismatch(pred: dict[str, int], truth: dict[str, int], truth_path: Path) -> tuple[dict[str, int], dict[str, Any]]:
    """Handle a single official example naming mismatch without changing result.csv."""
    missing = sorted(set(truth) - set(pred))
    extra = sorted(set(pred) - set(truth))
    zip_stems = sorted(path.stem for path in truth_path.parent.glob("*.zip"))
    zip_not_truth = sorted(set(zip_stems) - set(truth))
    diagnostics: dict[str, Any] = {
        "applied": False,
        "missing_before": missing,
        "extra_before": extra,
        "zip_count": len(zip_stems),
        "zip_not_truth": zip_not_truth,
    }
    if len(missing) == 1 and len(extra) == 1 and extra == zip_not_truth and extra[0] in pred:
        aligned = dict(pred)
        aligned[missing[0]] = aligned.pop(extra[0])
        diagnostics.update({"applied": True, "mapped_pred_md5": extra[0], "to_truth_md5": missing[0]})
        return aligned, diagnostics
    return pred, diagnostics


def main() -> int:
    args = parse_args()
    pred = read_labels(Path(args.pred), "pred")
    truth_path = Path(args.truth)
    truth = read_labels(truth_path, "truth")
    if pred is None or truth is None:
        return 0
    pred, alignment = align_single_zip_truth_mismatch(pred, truth, truth_path)
    common = sorted(set(pred) & set(truth))
    missing_predictions = sorted(set(truth) - set(pred))
    extra_predictions = sorted(set(pred) - set(truth))
    if not common:
        print(
            json.dumps(
                {
                    "status": "skipped",
                    "reason": "no overlapping md5 values",
                    "truth_count": len(truth),
                    "pred_count": len(pred),
                    "missing_predictions": missing_predictions[:50],
                    "extra_predictions": extra_predictions[:50],
                    "md5_alignment": alignment,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    tp = sum(1 for md5 in common if pred[md5] == 1 and truth[md5] == 1)
    tn = sum(1 for md5 in common if pred[md5] == 0 and truth[md5] == 0)
    fp = sum(1 for md5 in common if pred[md5] == 1 and truth[md5] == 0)
    fn = sum(1 for md5 in common if pred[md5] == 0 and truth[md5] == 1)
    total = len(common)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    metrics = {
        "status": "ok",
        "sample_count": total,
        "truth_count": len(truth),
        "pred_count": len(pred),
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "missing_predictions": missing_predictions,
        "extra_predictions": extra_predictions,
        "md5_alignment": alignment,
    }
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
