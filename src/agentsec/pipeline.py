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
    profile: str | None = None,
    use_llm: bool = False,
    llm_mode: str | None = None,
    llm_review_final: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    config, rules_config = load_config(config_path, profile=profile)
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
    selected_llm_mode = (llm_mode or llm_config.get("mode") or "borderline").strip().lower()
    if selected_llm_mode not in {"off", "borderline", "all", "explain-only"}:
        raise ValueError("--llm-mode must be one of: off, borderline, all, explain-only")
    llm_config["mode"] = selected_llm_mode
    llm_config["enabled"] = bool((use_llm or llm_config.get("enabled", False)) and selected_llm_mode != "off")
    llm_config.setdefault("score_threshold", config.get("scoring", {}).get("score_threshold", config.get("scoring", {}).get("label_threshold", 60)))
    llm_config.setdefault("llm_min_score", config.get("scoring", {}).get("llm_min_score", llm_config.get("min_score", 35)))
    llm = LLMAnalyzer(llm_config)
    runtime_llm_mode = selected_llm_mode if llm_config["enabled"] else "off"

    results: list[DetectionResult] = []
    for zip_path in sample_zips:
        results.append(process_sample(zip_path, work, config, rule_engine, llm if llm_config["enabled"] else None, runtime_llm_mode))

    expected_md5s = [zip_path.stem for zip_path in sample_zips]
    results = ensure_complete_results(expected_md5s, results, config)
    final_review_llm = LLMAnalyzer(llm_config) if llm_review_final else None
    final_review_summary = apply_final_llm_review(results, final_review_llm, config) if final_review_llm else {"enabled": False, "reviewed": 0, "changed": 0}

    write_result_csv(output, results)
    write_detail_jsonl(detail_output, results)
    return summarize_run(results, output, detail_output, expected_md5s, config, config_path, runtime_llm_mode, final_review_summary)


def process_sample(
    zip_path: Path,
    workdir: Path,
    config: dict[str, Any],
    rule_engine: RuleEngine,
    llm: LLMAnalyzer | None = None,
    llm_mode: str = "off",
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
                profile=str(config.get("profile", "balanced")),
                score_threshold=float(config.get("scoring", {}).get("score_threshold", config.get("scoring", {}).get("label_threshold", 60))),
                strong_chain_threshold=float(config.get("scoring", {}).get("strong_chain_threshold", 55)),
                llm_mode=llm_mode if llm else "off",
                label_before_llm=label,
                label_after_llm=label,
                llm_changed_label=False,
                matched_rules=hits,
                evidence=evidence,
                behavior_chains=chains,
                feature_summary=features.to_dict(),
                warnings=warnings,
                summary=make_summary(md5, label, score, risk, hits),
            )
            if llm and llm.should_call(result):
                result.llm_analysis = llm.analyze(result)
                apply_llm_correction(result, config.get("scoring", {}), llm.config)
                result.llm_decision = result.llm_analysis
            elif llm:
                result.llm_analysis = {
                    "mode": "skipped",
                    "reason": llm.skip_reason(result) or "not selected for LLM attribution",
                    "is_malicious": bool(label),
                    "risk_level": risk,
                }
                result.llm_decision = result.llm_analysis
            return result
    except Exception as exc:
        warning = f"sample processing failed: {type(exc).__name__}: {exc}"
        default_label = int(config.get("default_label_on_error", config.get("scoring", {}).get("default_label_on_error", 0)))
        return DetectionResult(
            md5=md5,
            label=default_label,
            score=0,
            risk_level="none",
            profile=str(config.get("profile", "balanced")),
            score_threshold=float(config.get("scoring", {}).get("score_threshold", config.get("scoring", {}).get("label_threshold", 60))),
            strong_chain_threshold=float(config.get("scoring", {}).get("strong_chain_threshold", 55)),
            llm_mode=llm_mode if llm else "off",
            label_before_llm=default_label,
            label_after_llm=default_label,
            llm_changed_label=False,
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
                profile=str(config.get("profile", "balanced")),
                score_threshold=float(config.get("scoring", {}).get("score_threshold", config.get("scoring", {}).get("label_threshold", 60))),
                strong_chain_threshold=float(config.get("scoring", {}).get("strong_chain_threshold", 55)),
                llm_mode=str(config.get("llm", {}).get("mode", "off")),
                label_before_llm=default_label,
                label_after_llm=default_label,
                llm_changed_label=False,
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


def apply_llm_correction(result: DetectionResult, scoring_config: dict[str, Any], llm_config: dict[str, Any] | None = None) -> None:
    llm_config = llm_config or {}
    analysis = result.llm_analysis or {}
    if analysis.get("mode") != "llm":
        result.label_after_llm = result.label
        result.llm_changed_label = False
        return
    result.label_before_llm = result.label
    if llm_config.get("mode") == "explain-only":
        analysis["label_correction"] = "skipped_explain_only"
        result.label_after_llm = result.label
        result.llm_changed_label = False
        return
    signals = (result.feature_summary or {}).get("signals", {})
    score_threshold = float(scoring_config.get("score_threshold", scoring_config.get("label_threshold", 60)))
    max_chain_weight = float(signals.get("max_chain_weight") or 0)
    if signals.get("terminal_rule") or max_chain_weight >= score_threshold:
        analysis["label_correction"] = "skipped_strong_rule"
        result.label_after_llm = result.label
        result.llm_changed_label = False
        return
    confidence = float(analysis.get("confidence") or 0)
    suggested = analysis.get("suggested_label")
    if str(suggested) in {"0", "1"}:
        suggested_label = int(str(suggested))
    else:
        suggested_label = 1 if bool(analysis.get("is_malicious")) else 0
    min_confidence = float(scoring_config.get("llm_correction_min_confidence", 0.8))
    if confidence < min_confidence:
        analysis["label_correction"] = "skipped_low_confidence"
        result.label_after_llm = result.label
        result.llm_changed_label = False
        return
    min_score = float(llm_config.get("min_score", scoring_config.get("llm_min_score", 4)))
    max_score = float(llm_config.get("max_score", score_threshold))
    weak_context = int(signals.get("hit_count") or 0) >= 2 or int(signals.get("strong_category_count") or 0) >= 2
    boundary_score = min_score <= float(result.score) <= max_score
    can_upgrade = result.label == 0 and suggested_label == 1 and weak_context and boundary_score
    can_downgrade = result.label == 1 and suggested_label == 0 and not signals.get("terminal_rule") and max_chain_weight < score_threshold
    if not (can_upgrade or can_downgrade):
        analysis["label_correction"] = "skipped_fusion_guard"
        result.label_after_llm = result.label
        result.llm_changed_label = False
        return
    old_label = result.label
    result.label = suggested_label
    result.label_after_llm = result.label
    result.llm_changed_label = old_label != result.label
    analysis["label_correction"] = f"{old_label}->{result.label}"
    result.summary = f"{result.summary}; llm_medium_correction={old_label}->{result.label}"


FINAL_REVIEW_AGGREGATE_RULES = {"R001", "R002", "R004", "R007", "R011", "R013", "R112", "R117"}
FINAL_REVIEW_CONFIRMED_EXFIL_RULES = {"R101", "R105", "R106", "R107", "R108", "R111", "R116", "R117"}
FINAL_REVIEW_ALLOWED_STRONG_RULES = {"R112", "R117"}


def final_llm_review_skip_reason(result: DetectionResult) -> str | None:
    if result.label != 1:
        return "rule label is not 1"
    signals = (result.feature_summary or {}).get("signals", {})
    if signals.get("terminal_rule") or signals.get("destructive") or signals.get("explicit_malicious_action"):
        return "explicit malicious or destructive rule"
    rule_ids = {hit.rule_id for hit in result.matched_rules}
    strong_chain_rules = {str(rule_id) for rule_id in signals.get("strong_chain_rules") or []}
    has_confirmed_exfil = bool(
        strong_chain_rules & FINAL_REVIEW_CONFIRMED_EXFIL_RULES
        and (signals.get("real_exfil") or signals.get("network_transfer") or signals.get("network_post"))
    )
    if has_confirmed_exfil:
        return "confirmed real exfil strong chain"
    if not (rule_ids & FINAL_REVIEW_AGGREGATE_RULES):
        return "not an aggregate-rule review candidate"
    if strong_chain_rules and not strong_chain_rules <= FINAL_REVIEW_ALLOWED_STRONG_RULES:
        return "strong chain outside final-review guard"
    if not (strong_chain_rules or (rule_ids & {"R112", "R013", "R117"})):
        return "no final-review aggregate chain"
    return None


def apply_final_llm_review(results: list[DetectionResult], llm: Any, config: dict[str, Any]) -> dict[str, Any]:
    scoring_config = config.get("scoring", {})
    min_confidence = float(scoring_config.get("llm_final_review_min_confidence", 0.85))
    reviewed = 0
    changed = 0
    skipped = 0
    timed_out = 0
    for result in results:
        skip_reason = final_llm_review_skip_reason(result)
        if skip_reason is not None:
            skipped += 1
            review = _normalize_final_review_detail(
                {"mode": "final_review_skipped", "reason": skip_reason},
                eligible=False,
                selected=False,
                skip_reason=skip_reason,
            )
            result.llm_analysis = _merge_llm_analysis(result.llm_analysis, review)
            result.llm_decision = result.llm_analysis
            continue
        reviewed += 1
        review = _normalize_final_review_detail(
            llm.review_final(result),
            eligible=True,
            selected=True,
        )
        if review.get("timeout"):
            timed_out += 1
        verdict = str(review.get("verdict", "")).strip().lower()
        try:
            confidence = float(review.get("confidence") or 0)
        except (TypeError, ValueError):
            confidence = 0.0
        if review.get("mode") == "llm_final_review" and verdict == "benign" and confidence >= min_confidence:
            old_label = result.label
            result.label = 0
            result.label_before_llm = old_label
            result.label_after_llm = result.label
            result.llm_changed_label = True
            review["change"] = True
            review["changed"] = True
            review["label_correction"] = f"{old_label}->0"
            result.summary = f"{result.summary}; llm_final_review={old_label}->0"
            changed += 1
        else:
            result.label_after_llm = result.label
            result.llm_changed_label = bool(result.llm_changed_label)
            review.setdefault("label_correction", "unchanged")
        result.llm_analysis = _merge_llm_analysis(result.llm_analysis, review)
        result.llm_decision = result.llm_analysis
    return {
        "enabled": True,
        "reviewed": reviewed,
        "changed": changed,
        "skipped": skipped,
        "timeouts": timed_out,
        "min_confidence": min_confidence,
    }


def _normalize_final_review_detail(
    review: dict[str, Any],
    eligible: bool,
    selected: bool,
    skip_reason: str = "",
) -> dict[str, Any]:
    normalized = dict(review or {})
    normalized.setdefault("mode", "final_review_skipped" if not selected else "final_review")
    normalized["eligible"] = eligible
    normalized["selected"] = selected
    normalized.setdefault("verdict", "unchanged")
    normalized.setdefault("confidence", 0)
    normalized.setdefault("reason", skip_reason or normalized.get("error", "") or "")
    if skip_reason:
        normalized["skip_reason"] = skip_reason
    elif selected and normalized.get("mode") != "llm_final_review":
        normalized["skip_reason"] = str(normalized.get("reason", "") or normalized.get("error", ""))
    else:
        normalized.setdefault("skip_reason", "")
    normalized.setdefault("change", False)
    normalized.setdefault("changed", False)
    normalized.setdefault("timeout", False)
    normalized.setdefault("retry_count", 0)
    normalized.setdefault("raw_response_short", "")
    return normalized


def _merge_llm_analysis(existing: dict[str, Any] | None, final_review: dict[str, Any]) -> dict[str, Any]:
    if not existing:
        return {"mode": "final_review", "final_review": final_review}
    merged = dict(existing)
    if "final_review" not in merged:
        merged = {"mode": str(existing.get("mode", "llm")), "attribution": existing}
    merged["final_review"] = final_review
    return merged


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


def summarize_run(
    results: list[DetectionResult],
    output: Path,
    detail_output: Path,
    expected_md5s: list[str] | None = None,
    config: dict[str, Any] | None = None,
    config_path: str | Path | None = None,
    llm_mode: str = "off",
    final_review_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
        "profile": str((config or {}).get("profile", "balanced")),
        "config_path": str(config_path) if config_path else "",
        "profile_config_source": str((config or {}).get("profile_config_source", "")),
        "score_threshold": (config or {}).get("scoring", {}).get("score_threshold"),
        "strong_chain_threshold": (config or {}).get("scoring", {}).get("strong_chain_threshold"),
        "profile_behavior": (config or {}).get("rules", {}).get("profile_behavior", {}),
        "llm_mode": llm_mode,
        "llm_review_final": final_review_summary or {"enabled": False, "reviewed": 0, "changed": 0},
        "output": str(output),
        "detail_output": str(detail_output),
        "top_rules": rule_counts.most_common(20),
    }


def make_summary(md5: str, label: int, score: float, risk: str, hits: list[Any]) -> str:
    if not hits:
        return f"{md5}: no suspicious rule hit; label={label}, score={score}, risk={risk}"
    rules = ", ".join(hit.rule_id for hit in hits[:8])
    return f"{md5}: label={label}, score={score}, risk={risk}, matched_rules={rules}"
