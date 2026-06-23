# KIB-AgentSec Sentinel

Offline baseline detector for AI agent malicious operation behavior. The tool reads sample zip files, extracts Linux `session.jsonl` / `audit.log` / `network.pcap` evidence plus optional Windows Sysmon-style logs, applies configurable rules and scoring, and writes:

- `result.csv`: final submission format with only `md5,label`
- `detail.jsonl`: local debugging explanations, rule hits, evidence excerpts, warnings, and optional LLM attribution

The project is read-only against input samples. It does not delete files, upload data, clean logs, or run attack actions.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
```

Optional PCAP parsing libraries:

```bash
python3 -m pip install -e ".[pcap]"
```

If `scapy` or `dpkt` is missing, PCAP parsing degrades gracefully and the pipeline still completes.

Optional EVTX parsing support:

```bash
python3 -m pip install -e ".[evtx]"
```

Sysmon JSON/JSONL/CSV/XML/TXT parsing does not require the EVTX extra.

## Create Synthetic Samples

The repository does not include official data. Use the synthetic sanitized generator for local smoke tests:

```bash
python3 scripts/make_synthetic_sample.py --output data/synthetic/example-s7 --force
```

## Run Detection

```bash
python3 scripts/run_detect.py \
  --input data/synthetic/example-s7 \
  --output output/result.csv \
  --detail-output output/detail.jsonl \
  --workdir data/work/run \
  --config configs/default.yaml \
  --profile balanced
```

Official-style command:

```bash
python3 scripts/run_detect.py \
  --input data/example/example-s7 \
  --output output/result.csv \
  --detail-output output/detail.jsonl \
  --workdir data/work/run \
  --config configs/default.yaml
```

`--input` may be a single zip, a directory containing multiple zips, or a nested dataset directory. The sample `md5` is the zip file stem.

Profiles:

- `balanced`: recommended default
- `recall`: recall-first rule thresholds
- `precision`: precision-first rule thresholds

`configs/default.yaml` points to the balanced profile. CLI `--profile` overrides the profile in the config file.

## Evaluate Labeled Example Data

If a truth file exists and has `md5,label` columns:

```bash
python3 scripts/evaluate_example.py \
  --pred output/result.csv \
  --truth data/example/example-s7/results.csv
```

If the truth file is absent or lacks labels, evaluation exits cleanly with a skipped status.

## Diagnostics

Use these helpers after a labeled local validation run:

```bash
python3 scripts/analyze_predictions.py --pred output/result_rule.csv --truth data/example/example-s7/results.csv --detail output/detail_rule.jsonl
python3 scripts/threshold_sweep.py --detail output/detail_rule.jsonl --truth data/example/example-s7/results.csv
python3 scripts/make_candidates.py --input data/example/example-s7 --output-dir output/candidates --workdir data/work/candidates --config configs/default.yaml --truth data/example/example-s7/results.csv
python3 scripts/offline_check.py
```

`analyze_predictions.py` reports prediction coverage, TP/TN/FP/FN counts, FP/FN detail summaries, FP rule ranking, and rules that hit every detail row. `threshold_sweep.py` reports accuracy, precision, recall, f1, TP, TN, FP, and FN across score thresholds.

`make_candidates.py` runs precision, balanced, recall, and balanced local-LLM borderline candidates. `offline_check.py` verifies imports, configs, local endpoint reachability, parser availability, and `.gitignore` coverage without contacting public network services.

The diagnostic scripts also print `md5_alignment`. If a labeled example set has exactly one truth md5 that does not match exactly one input zip stem, evaluation aliases that pair for metrics only. The submitted `result.csv` is still written with input zip stems.

## Optional LLM Attribution

The detector is rule-first. LLM attribution is optional, local-only by default, and selected with `--use-llm --llm-mode off|borderline|all|explain-only`.

Default local OpenAI-compatible endpoint:

- `base_url`: `http://127.0.0.1:8000/v1`
- `model`: `qwen36-27b`

Run with:

```bash
python3 scripts/run_detect.py \
  --input data/synthetic/example-s7 \
  --output output/result_llm.csv \
  --detail-output output/detail_llm.jsonl \
  --workdir data/work/run_llm \
  --config configs/default.yaml \
  --profile balanced \
  --use-llm \
  --llm-mode borderline
```

If the local endpoint is unavailable, the pipeline automatically falls back to mock attribution. External public LLM endpoints are disabled by default for compliance. For temporary local development overrides, use environment variables instead of committing secrets:

```bash
export AGENTSEC_LLM_BASE_URL="http://127.0.0.1:8000/v1"
export AGENTSEC_LLM_MODEL="qwen36-27b"
export AGENTSEC_LLM_API_KEY=""
```

## Offline Mode

For official offline runs, install dependencies ahead of time, keep `configs/default.yaml` pointing at the local endpoint, and run without network access. The main detector does not require an LLM service.

## Safety Notes

- Do not commit official samples, zips, PCAPs, logs, CSV results, keys, or environment files.
- Do not place accounts, passwords, AK/SK, SFTP, OBS, or API tokens in code or configuration.
- `detail.jsonl` is for local debugging only and may contain redacted evidence excerpts from input logs.
