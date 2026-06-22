from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pipeline_on_synthetic_samples(tmp_path: Path) -> None:
    sample_dir = tmp_path / "example-s7"
    output_dir = tmp_path / "output"
    workdir = tmp_path / "work"

    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "make_synthetic_sample.py"), "--output", str(sample_dir)],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_detect.py"),
            "--input",
            str(sample_dir),
            "--output",
            str(output_dir / "result.csv"),
            "--detail-output",
            str(output_dir / "detail.jsonl"),
            "--workdir",
            str(workdir),
            "--config",
            str(ROOT / "configs" / "default.yaml"),
            "--use-llm",
        ],
        cwd=ROOT,
        check=True,
    )

    with (output_dir / "result.csv").open("r", encoding="utf-8", newline="") as handle:
        rows = {row["md5"]: int(row["label"]) for row in csv.DictReader(handle)}
    assert rows == {"mal001": 1, "normal001": 0, "weak001": 0}

    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "evaluate_example.py"),
            "--pred",
            str(output_dir / "result.csv"),
            "--truth",
            str(sample_dir / "results.csv"),
        ],
        cwd=ROOT,
        check=True,
    )
