from __future__ import annotations

import csv
import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from .chains import build_behavior_chains
from .config import load_config
from .llm import LLMAnalyzer
from .models import DetectionResult, Evidence, SampleFeatures
from .pcap import empty_pcap_features, extract_pcap_features
from .readers import discover_sample_zips, parse_extracted_sample, safe_extract_zip
from .rules import RuleEngine
from .scoring import score_hits


def run_pipeline(
    input_path: str | Path,
    output_path: str | Path,
    detail_output_path: str | Path,
    workdir: str | Path,
    config_path: str | Path | None = None,
    use_llm: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    config, rules_config = load_config(config_path)
    sample_zips = discover_sample_zips(input_path)
    if limit is not None:
        sample_zips = sample_zips[:limit]

    output = Path(output_path)
    detail_output = Path(detail_output_path)
    work = Path(workdir)
    output.parent.mkdir(parents=True, exist_ok=True)
    detail_output.parent.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)

    rule_engine = RuleEngine(rules_config, config.get("output", {}))
    llm_config = dict(config.get("llm", {}))
    llm_config["enabled"] = bool(use_llm or llm_config.get("enabled", False))
    llm_config.setdefault("score_threshold", config.get("scoring", {}).get("score_threshold", config.get("scoring", {}).get("label_threshold", 60)))
    llm_config.setdefault("llm_min_score", config.get("scoring", {}).get("llm_min_score", llm_config.get("min_score", 35)))
    llm = LLMAnalyzer(llm_config)

    results: list[DetectionResult] = []
    for zip_path in sample_zips:
        results.append(process_sample(zip_path, work, config, rule_engine, llm if llm_config["enabled"] else None))

    expected_md5s = [zip_path.stem for zip_path in sample_zips]
    results = ensure_complete_results(expected_md5s, results, config)

    write_result_csv(output, results)
    write_detail_jsonl(detail_output, results)
    return summarize_run(results, output, detail_output, expected_md5s)


def process_sample(
    zip_path: Path,
    workdir: Path,
    config: dict[str, Any],
    rule_engine: RuleEngine,
    llm: LLMAnalyzer | None = None,
) -> DetectionResult:
    md5 = zip_path.stem
    warnings: list[str] = []
    try:
        with tempfile.TemporaryDirectory(prefix=f"{md5}_", dir=workdir) as temp_name:
            sample_root = Path(temp_name)
            safe_extract_zip(zip_path, sample_root)
            parsed = parse_extracted_sample(md5, sample_root)
            warnings.extend(parsed.warnings)
            pcap_config = dict(config.get("pcap", {}))
            pcap_enabled = bool(config.get("pcap_enabled", pcap_config.get("enabled", True)))
            if "pcap_max_packets" in config and "max_packets" not in pcap_config:
                pcap_config["max_packets"] = config["pcap_max_packets"]
            pcap_path = Path(parsed.artifact_paths["pcap"]) if "pcap" in parsed.artifact_paths else None
            if pcap_enabled:
                pcap_features, pcap_warnings = extract_pcap_features(pcap_path, pcap_config)
            else:
                pcap_features, pcap_warnings = empty_pcap_features(pcap_path), ["pcap parsing disabled by config"]
            warnings.extend(pcap_warnings)
            event_counts = Counter(event.source for event in parsed.events)
            features = SampleFeatures(
                md5=md5,
                event_counts=dict(event_counts),
                audit_stats=parsed.audit_stats,
                pcap=pcap_features,
                warnings=warnings,
            )
            hits, signals = rule_engine.evaluate(parsed.events, pcap_features)
            features.signals = signals
            score, label, risk = score_hits(hits, config.get("scoring", {}), signals)
            evidence = [item for hit in hits for item in hit.evidence]
            chains = build_behavior_chains(md5, hits, features)
            result = DetectionResult(
                md5=md5,
                label=label,
                score=score,
                risk_level=risk,
                matched_rules=hits,
                evidence=evidence,
                behavior_chains=chains,
                feature_summary=features.to_dict(),
                warnings=warnings,
                summary=make_summary(md5, label, score, risk, hits),
            )
            if llm and llm.should_call(result):
                result.llm_analysis = llm.analyze(result)
                apply_llm_correction(result, config.get("scoring", {}))
            elif llm:
                result.llm_analysis = {
                    "mode": "skipped",
                    "reason": llm.skip_reason(result) or "not selected for LLM attribution",
                    "is_malicious": bool(label),
                    "risk_level": risk,
                }
            return result
    except Exception as exc:
        warning = f"sample processing failed: {type(exc).__name__}: {exc}"
        default_label = int(config.get("default_label_on_error", config.get("scoring", {}).get("default_label_on_error", 0)))
        return DetectionResult(
            md5=md5,
            label=default_label,
            score=0,
            risk_level="none",
            matched_rules=[],
            evidence=[Evidence(source="pipeline", rule_id="ERROR", message="sample failed", excerpt=warning)],
            behavior_chains=[],
            feature_summary=SampleFeatures(md5=md5, pcap=empty_pcap_features(), warnings=[warning]).to_dict(),
            warnings=[warning],
            summary=f"{md5}: processing failed; defaulted to label={default_label}",
        )


def ensure_complete_results(expected_md5s: list[str], results: list[DetectionResult], config: dict[str, Any]) -> list[DetectionResult]:
    by_md5: dict[str, DetectionResult] = {}
    duplicates: Counter[str] = Counter()
    for result in results:
        duplicates[result.md5] += 1
        by_md5[result.md5] = result

    default_label = int(config.get("default_label_on_error", config.get("scoring", {}).get("default_label_on_error", 0)))
    completed: list[DetectionResult] = []
    for md5 in expected_md5s:
        result = by_md5.get(md5)
        if result is None:
            warning = "missing pipeline result for input zip; emitted default label"
            result = DetectionResult(
                md5=md5,
                label=default_label,
                score=0,
                risk_level="none",
                matched_rules=[],
                evidence=[Evidence(source="pipeline", rule_id="MISSING_OUTPUT", message="missing output", excerpt=warning)],
                behavior_chains=[],
                feature_summary=SampleFeatures(md5=md5, pcap=empty_pcap_features(), warnings=[warning]).to_dict(),
                warnings=[warning],
                summary=f"{md5}: missing output; defaulted to label={default_label}",
            )
        elif duplicates[md5] > 1:
            result.warnings.append(f"duplicate result md5 encountered {duplicates[md5]} times; kept last result")
        completed.append(result)
    return completed


def apply_llm_correction(result: DetectionResult, scoring_config: dict[str, Any]) -> None:
    analysis = result.llm_analysis or {}
    if analysis.get("mode") != "llm":
        return
    signals = (result.feature_summary or {}).get("signals", {})
    if signals.get("terminal_rule") or (signals.get("strong_chain") and result.risk_level in {"high", "critical"}):
        analysis["label_correction"] = "skipped_strong_rule"
        return
    if result.risk_level != "medium":
        analysis["label_correction"] = "skipped_non_medium"
        return
    confidence = float(analysis.get("confidence") or 0)
    is_malicious = bool(analysis.get("is_malicious"))
    min_confidence = float(scoring_config.get("llm_correction_min_confidence", 0.7))
    if confidence < min_confidence:
        analysis["label_correction"] = "skipped_low_confidence"
        return
    old_label = result.label
    result.label = 1 if is_malicious else 0
    analysis["label_correction"] = f"{old_label}->{result.label}"
    result.summary = f"{result.summary}; llm_medium_correction={old_label}->{result.label}"


def write_result_csv(path: Path, results: list[DetectionResult]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["md5", "label"])
        for result in sorted(results, key=lambda item: item.md5.lower()):
            writer.writerow([result.md5, result.label])


def write_detail_jsonl(path: Path, results: list[DetectionResult]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for result in sorted(results, key=lambda item: item.md5.lower()):
            handle.write(json.dumps(result.to_dict(), ensure_ascii=False, default=str) + "\n")


def summarize_run(results: list[DetectionResult], output: Path, detail_output: Path, expected_md5s: list[str] | None = None) -> dict[str, Any]:
    label_counts = Counter(result.label for result in results)
    rule_counts: Counter[str] = Counter()
    for result in results:
        for hit in result.matched_rules:
            rule_counts[hit.rule_id] += 1
    expected = expected_md5s or [result.md5 for result in results]
    output_md5s = [result.md5 for result in results]
    missing_output = sorted(set(expected) - set(output_md5s))
    return {
        "sample_count": len(results),
        "input_zip_count": len(expected),
        "output_row_count": len(results),
        "missing_output_count": len(missing_output),
        "missing_output_md5": missing_output[:20],
        "label_distribution": {str(key): value for key, value in sorted(label_counts.items())},
        "output": str(output),
        "detail_output": str(detail_output),
        "top_rules": rule_counts.most_common(20),
    }


def make_summary(md5: str, label: int, score: float, risk: str, hits: list[Any]) -> str:
    if not hits:
        return f"{md5}: no suspicious rule hit; label={label}, score={score}, risk={risk}"
    rules = ", ".join(hit.rule_id for hit in hits[:8])
    return f"{md5}: label={label}, score={score}, risk={risk}, matched_rules={rules}"
