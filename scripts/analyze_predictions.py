#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Diagnose predictions against truth and detail.jsonl.")
    parser.add_argument("--pred", required=True, help="Predicted result.csv with md5,label columns.")
    parser.add_argument("--truth", required=True, help="Truth results.csv with md5,label columns.")
    parser.add_argument("--detail", required=True, help="detail.jsonl produced by run_detect.py.")
    return parser.parse_args()


def read_labels(path: Path) -> dict[str, int]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        labels: dict[str, int] = {}
        for row in reader:
            md5 = (row.get("md5") or "").strip()
            label = (row.get("label") or "").strip()
            if md5 and label in {"0", "1"}:
                labels[md5] = int(label)
        return labels


def read_details(path: Path) -> dict[str, dict[str, Any]]:
    details: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return details
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            md5 = str(row.get("md5", "")).strip()
            if md5:
                details[md5] = row
    return details


def rule_ids(row: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for item in row.get("matched_rules") or []:
        if isinstance(item, dict):
            ids.append(str(item.get("rule_id", "")))
        else:
            ids.append(str(item))
    return [item for item in ids if item]


def align_single_zip_truth_mismatch(
    pred: dict[str, int], details: dict[str, dict[str, Any]], truth: dict[str, int], truth_path: Path
) -> tuple[dict[str, int], dict[str, dict[str, Any]], dict[str, Any]]:
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
        aligned_pred = dict(pred)
        aligned_details = dict(details)
        aligned_pred[missing[0]] = aligned_pred.pop(extra[0])
        if extra[0] in aligned_details:
            row = dict(aligned_details.pop(extra[0]))
            row["md5"] = missing[0]
            row.setdefault("warnings", []).append(f"diagnostic md5 alias from zip stem {extra[0]}")
            aligned_details[missing[0]] = row
        diagnostics.update({"applied": True, "mapped_pred_md5": extra[0], "to_truth_md5": missing[0]})
        return aligned_pred, aligned_details, diagnostics
    return pred, details, diagnostics


def compact_row(md5: str, row: dict[str, Any], include_features: bool = False) -> dict[str, Any]:
    item: dict[str, Any] = {
        "md5": md5,
        "score": row.get("score"),
        "risk_level": row.get("risk_level"),
        "matched_rules": rule_ids(row),
        "behavior_chains": [
            {
                "chain_id": chain.get("chain_id"),
                "risk": chain.get("risk"),
                "steps": chain.get("steps"),
                "supporting_rules": chain.get("supporting_rules"),
            }
            for chain in (row.get("behavior_chains") or [])
            if isinstance(chain, dict)
        ],
        "summary": row.get("summary", ""),
    }
    if include_features:
        item["feature_summary"] = row.get("feature_summary", {})
    return item


def metrics(pred: dict[str, int], truth: dict[str, int]) -> dict[str, int]:
    common = sorted(set(pred) & set(truth))
    return {
        "tp": sum(1 for md5 in common if pred[md5] == 1 and truth[md5] == 1),
        "tn": sum(1 for md5 in common if pred[md5] == 0 and truth[md5] == 0),
        "fp": sum(1 for md5 in common if pred[md5] == 1 and truth[md5] == 0),
        "fn": sum(1 for md5 in common if pred[md5] == 0 and truth[md5] == 1),
    }


def main() -> int:
    args = parse_args()
    pred = read_labels(Path(args.pred))
    truth_path = Path(args.truth)
    truth = read_labels(truth_path)
    details = read_details(Path(args.detail))
    pred, details, alignment = align_single_zip_truth_mismatch(pred, details, truth, truth_path)

    missing = sorted(set(truth) - set(pred))
    extra = sorted(set(pred) - set(truth))
    fps = sorted(md5 for md5 in set(pred) & set(truth) if pred[md5] == 1 and truth[md5] == 0)
    fns = sorted(md5 for md5 in set(pred) & set(truth) if pred[md5] == 0 and truth[md5] == 1)

    fp_rule_counter: Counter[str] = Counter()
    all_rule_counter: Counter[str] = Counter()
    for md5, row in details.items():
        ids = rule_ids(row)
        all_rule_counter.update(ids)
        if md5 in fps:
            fp_rule_counter.update(ids)

    detail_count = len(details)
    overbroad = [
        {"rule_id": rule_id, "count": count}
        for rule_id, count in all_rule_counter.most_common()
        if detail_count and count == detail_count
    ]

    output = {
        "truth_count": len(truth),
        "pred_count": len(pred),
        "detail_count": detail_count,
        "missing": missing,
        "extra": extra,
        "md5_alignment": alignment,
        "confusion_matrix": metrics(pred, truth),
        "false_positives": [compact_row(md5, details.get(md5, {})) for md5 in fps],
        "false_negatives": [compact_row(md5, details.get(md5, {}), include_features=True) for md5 in fns],
        "fp_rule_ranking": fp_rule_counter.most_common(30),
        "rules_hitting_all_detail_rows": overbroad,
        "overall_rule_ranking": all_rule_counter.most_common(30),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
