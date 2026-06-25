#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsec.pipeline import run_pipeline  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run KIB-AgentSec Sentinel offline detection.")
    parser.add_argument("--input", required=True, help="Sample zip file, example directory, or directory containing zips.")
    parser.add_argument("--output", required=True, help="Path to result.csv with md5,label columns.")
    parser.add_argument("--detail-output", required=True, help="Path to detail.jsonl explanations.")
    parser.add_argument("--workdir", required=True, help="Temporary extraction workspace.")
    parser.add_argument("--config", default=str(ROOT / "configs" / "default.yaml"), help="YAML configuration path.")
    parser.add_argument("--profile", choices=["balanced", "recall", "precision"], default=None, help="Detection strategy profile. Overrides config file profile.")
    parser.add_argument("--use-llm", action="store_true", help="Enable optional OpenAI-compatible LLM attribution.")
    parser.add_argument("--llm-mode", choices=["off", "borderline", "all", "explain-only"], default=None, help="LLM selection/fusion mode.")
    parser.add_argument("--llm-review-final", action="store_true", help="Optionally let a local LLM review selected rule-positive borderline outputs for 1->0 correction.")
    parser.add_argument("--limit", type=int, default=None, help="Process only the first N sorted samples.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = run_pipeline(
        input_path=args.input,
        output_path=args.output,
        detail_output_path=args.detail_output,
        workdir=args.workdir,
        config_path=args.config,
        profile=args.profile,
        use_llm=args.use_llm,
        llm_mode=args.llm_mode,
        llm_review_final=args.llm_review_final,
        limit=args.limit,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
