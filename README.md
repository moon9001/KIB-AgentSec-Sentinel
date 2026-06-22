# KIB-AgentSec Sentinel

Offline baseline detector for AI agent malicious operation behavior. The tool reads sample zip files, extracts `session.jsonl`, `audit.log`, and `network.pcap`, applies configurable rules and scoring, and writes:

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
  --config configs/default.yaml
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

## Evaluate Labeled Example Data

If a truth file exists and has `md5,label` columns:

```bash
python3 scripts/evaluate_example.py \
  --pred output/result.csv \
  --truth data/example/example-s7/results.csv
```

If the truth file is absent or lacks labels, evaluation exits cleanly with a skipped status.

## Optional LLM Attribution

The detector is rule-first. LLM attribution is optional and only used for medium or higher rule scores.

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
  --use-llm
```

If the local endpoint is unavailable, the pipeline automatically falls back to mock attribution. External public LLM endpoints are disabled by default for compliance. For temporary local development overrides, use environment variables instead of committing secrets:

```bash
export AGENTSEC_LLM_BASE_URL="http://127.0.0.1:8000/v1"
export AGENTSEC_LLM_MODEL="qwen36-27b"
export AGENTSEC_LLM_API_KEY=""
```

Temporary DeepSeek smoke tests are supported, but should not be used for official offline runs:

```bash
export AGENTSEC_LLM_PROVIDER="deepseek"
export DEEPSEEK_API_KEY="<set locally only>"
export AGENTSEC_ALLOW_EXTERNAL_LLM="1"
```

## Offline Mode

For official offline runs, install dependencies ahead of time, keep `configs/default.yaml` pointing at the local endpoint, and run without network access. The main detector does not require an LLM service.

## Safety Notes

- Do not commit official samples, zips, PCAPs, logs, CSV results, keys, or environment files.
- Do not place accounts, passwords, AK/SK, SFTP, OBS, or API tokens in code or configuration.
- `detail.jsonl` is for local debugging only and may contain redacted evidence excerpts from input logs.
