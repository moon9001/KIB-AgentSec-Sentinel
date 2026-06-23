#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentsec.pipeline import run_pipeline  # noqa: E402
from scripts.evaluate_example import align_single_zip_truth_mismatch  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build precision/balanced/recall candidate result files.")
    parser.add_argument("--input", required=True, help="Sample zip directory or zip file.")
    parser.add_argument("--output-dir", default=str(ROOT / "output" / "candidates"), help="Directory for candidate CSV/detail files.")
    parser.add_argument("--workdir", default=str(ROOT / "data" / "work" / "candidates"), help="Temporary extraction workspace.")
    parser.add_argument("--config", default=str(ROOT / "configs" / "default.yaml"), help="Base configuration path.")
    parser.add_argument("--truth", default=None, help="Optional truth results.csv for local evaluation.")
    parser.add_argument("--limit", type=int, default=None, help="Optional sample limit.")
    return parser.parse_args()


def read_labels(path: Path) -> dict[str, int] | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        labels: dict[str, int] = {}
        for row in csv.DictReader(handle):
            md5 = (row.get("md5") or "").strip()
            label = (row.get("label") or "").strip()
            if md5 and label in {"0", "1"}:
                labels[md5] = int(label)
        return labels


def metrics(pred: dict[str, int], truth: dict[str, int]) -> dict[str, Any]:
    common = sorted(set(pred) & set(truth))
    tp = sum(1 for md5 in common if pred[md5] == 1 and truth[md5] == 1)
    tn = sum(1 for md5 in common if pred[md5] == 0 and truth[md5] == 0)
    fp = sum(1 for md5 in common if pred[md5] == 1 and truth[md5] == 0)
    fn = sum(1 for md5 in common if pred[md5] == 0 and truth[md5] == 1)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    total = len(common)
    return {
        "sample_count": total,
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def summarize_candidate(result_csv: Path, truth_path: Path | None) -> dict[str, Any]:
    pred = read_labels(result_csv) or {}
    output: dict[str, Any] = {
        "pred_count": len(pred),
        "label_distribution": dict(Counter(str(value) for value in pred.values())),
    }
    if truth_path:
        truth = read_labels(truth_path)
        if truth is not None:
            aligned, alignment = align_single_zip_truth_mismatch(pred, truth, truth_path)
            output["evaluation"] = metrics(aligned, truth)
            output["md5_alignment"] = alignment
    return output


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    workdir = Path(args.workdir)
    output_dir.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)
    truth_path = Path(args.truth) if args.truth else None

    runs = [
        ("precision", "precision", False, "off"),
        ("balanced", "balanced", False, "off"),
        ("recall", "recall", False, "off"),
        ("balanced_llm_borderline", "balanced", True, "borderline"),
    ]
    summary: dict[str, Any] = {"candidates": {}}
    for name, profile, use_llm, llm_mode in runs:
        result_csv = output_dir / f"result_{name}.csv"
        detail_jsonl = output_dir / f"detail_{name}.jsonl"
        run_summary = run_pipeline(
            input_path=args.input,
            output_path=result_csv,
            detail_output_path=detail_jsonl,
            workdir=workdir / name,
            config_path=args.config,
            profile=profile,
            use_llm=use_llm,
            llm_mode=llm_mode,
            limit=args.limit,
        )
        candidate_summary = summarize_candidate(result_csv, truth_path)
        candidate_summary.update(
            {
                "profile": profile,
                "use_llm": use_llm,
                "llm_mode": run_summary.get("llm_mode"),
                "result": str(result_csv),
                "detail": str(detail_jsonl),
                "run_summary": run_summary,
            }
        )
        summary["candidates"][name] = candidate_summary

    summary_path = output_dir / "candidate_summary.json"
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2, default=str)
    print(json.dumps({"summary": str(summary_path), **summary}, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
