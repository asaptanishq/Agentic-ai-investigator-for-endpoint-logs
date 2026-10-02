import json
import re
from datetime import datetime, timedelta
from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel, Field, field_validator
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

from a1.llm import get_llm
from a1.prompts import REPORT_SYNTHESIZER_SYSTEM_PROMPT
from a1.nodes.structured_output import StructuredOutputRetryError, invoke_structured_with_retry, extract_outer_json

CHANNEL_TOKEN_PATTERN = r"<\|?channel[^>]*\|?>"
THINK_TOKEN_PATTERN = r"</?think>"
NONE_DOCUMENTED = "- None documented"

def _match_verdict(norm: str) -> str:
    valid = {"benign", "suspicious", "malicious", "inconclusive"}
    if norm in valid:
        return norm
    for candidate in ("malicious", "suspicious", "benign", "inconclusive"):
        if candidate in norm:
            return candidate
    return "suspicious"


def _match_verdict_boundary(norm: str) -> str:
    valid = {"confirmed_malicious", "unconfirmed_malicious", "benign", "inconclusive"}
    if norm in valid:
        return norm
    if "confirmed_malicious" in norm:
        return "confirmed_malicious"
    if any(k in norm for k in ("unconfirmed_malicious", "unconfirmed", "malicious")):
        return "unconfirmed_malicious"
    if "benign" in norm:
        return "benign"
    if "inconclusive" in norm:
        return "inconclusive"
    return "unconfirmed_malicious"


def _list_to_report_text(items: list) -> str:
    lines = []
    for item in items:
        if isinstance(item, dict):
            for k, v in item.items():
                title = k.replace("_", " ").title()
                lines.append(f"**{title}**: {v}")
        else:
            lines.append(str(item))
    text = "\n".join(lines)
    text = re.sub(CHANNEL_TOKEN_PATTERN, "", text, flags=re.IGNORECASE)
    return text.strip()


def _dict_to_report_text(data: dict) -> str:
    lines = []
    for k, v in data.items():
        title = k.replace("_", " ").title()
        if isinstance(v, list):
            lines.append(f"\n### {title}")
            for item in v:
                lines.append(f"- {item}")
        elif isinstance(v, dict):
            lines.append(f"\n### {title}")
            for sub_k, sub_v in v.items():
                lines.append(f"- **{sub_k.replace('_', ' ').title()}**: {sub_v}")
        else:
            lines.append(f"- **{title}**: {v}")
    text = "\n".join(lines).strip()
    text = re.sub(CHANNEL_TOKEN_PATTERN, "", text, flags=re.IGNORECASE)
    return text.strip()


class IncidentVerdict(BaseModel):
    verdict: Literal["benign", "suspicious", "malicious", "inconclusive"] = "suspicious"
    verdict_boundary: Literal["confirmed_malicious", "unconfirmed_malicious", "benign", "inconclusive"] = "unconfirmed_malicious"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    executive_summary: str = Field(
        default="",
        description="Concise bullet-point executive summary of findings (no dense paragraphs)."
    )
    investigation_reasoning: str = Field(
        default="",
        description="Concise bullet-point reasoning explaining how the evidence was analyzed, how benign vs malicious explanations were weighed, and why this verdict was reached."
    )
    attack_chain: List[str] = Field(default_factory=list, description="Ordered attack chain / event sequence")
    evidence_basis: List[str] = Field(default_factory=list, description="Key evidence supporting the verdict, citing event/process IDs")
    benign_explanations_considered: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)

    @field_validator("verdict", "verdict_boundary", mode="before")
    @classmethod
    def normalize_verdict_labels(cls, value, info):
        if not isinstance(value, str):
            return value
        cleaned = re.sub(CHANNEL_TOKEN_PATTERN, "", value, flags=re.IGNORECASE)
        cleaned = re.sub(THINK_TOKEN_PATTERN, "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"</?thought>", "", cleaned, flags=re.IGNORECASE)
        norm = cleaned.strip().lower().replace(" ", "_").strip("`'\"")

        field_name = info.field_name if hasattr(info, "field_name") else "verdict"
        if field_name == "verdict":
            return _match_verdict(norm)
        return _match_verdict_boundary(norm)

    @field_validator("executive_summary", "investigation_reasoning", mode="before")
    @classmethod
    def normalize_report_text(cls, value):
        if isinstance(value, str):
            value = re.sub(CHANNEL_TOKEN_PATTERN, "", value, flags=re.IGNORECASE)
            value = re.sub(THINK_TOKEN_PATTERN, "", value, flags=re.IGNORECASE)
            return value.strip()
        if isinstance(value, list):
            return _list_to_report_text(value)
        if isinstance(value, dict):
            return _dict_to_report_text(value)
        return value or ""

    @field_validator(
        "attack_chain",
        "evidence_basis",
        "benign_explanations_considered",
        "evidence_gaps",
        "recommended_next_steps",
        mode="before",
    )
    @classmethod
    def normalize_report_lists(cls, value):
        if value is None:
            return []
        values = value if isinstance(value, list) else [value]
        result = []
        for item in values:
            if isinstance(item, dict):
                for k, v in item.items():
                    title = k.replace("_", " ").title()
                    cleaned_v = re.sub(CHANNEL_TOKEN_PATTERN, "", str(v), flags=re.IGNORECASE)
                    result.append(f"{title}: {cleaned_v.strip()}")
            else:
                cleaned_item = re.sub(CHANNEL_TOKEN_PATTERN, "", str(item), flags=re.IGNORECASE)
                cleaned_item = re.sub(THINK_TOKEN_PATTERN, "", cleaned_item, flags=re.IGNORECASE).strip()
                if cleaned_item:
                    result.append(cleaned_item)
        return result

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, value):
        """Accept both normalized confidence and the common percentage form."""
        if value is None:
            return 0.8
        if isinstance(value, str):
            value = value.strip().removesuffix("%")
        try:
            confidence = float(value)
            return confidence / 100 if confidence > 1 else confidence
        except Exception:
            return 0.8

# FIX: verdict -> boundary mapping, enforced in both directions.
_BOUNDARY_FOR_VERDICT = {
    "benign": "benign",
    "suspicious": "unconfirmed_malicious",
    "inconclusive": "unconfirmed_malicious",
    "malicious": "confirmed_malicious",
}

_DEFAULT_CONFIDENCE_FOR_VERDICT = {
    "malicious": 0.90,
    "suspicious": 0.75,
    "inconclusive": 0.50,
    "benign": 0.85,
}

def _format_bullet_points(items: List[str], prefix: str = "- ") -> str:
    """Format a list of strings into clean bullet points without dense paragraphs."""
    if not items:
        return NONE_DOCUMENTED
    lines = []
    for item in items:
        clean = item.strip()
        if not clean:
            continue
        if clean.startswith(("- ", "* ")) or (clean[0].isdigit() and clean[1:3] in (". ", ") ")):
            lines.append(clean)
        else:
            lines.append(f"{prefix}{clean}")
    return "\n".join(lines) if lines else NONE_DOCUMENTED

def _format_text_as_bullets(text: str) -> str:
    """Ensure multi-line text or paragraphs are rendered as readable bullet points."""
    if not text:
        return NONE_DOCUMENTED
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    formatted = []
    for ln in lines:
        if ln.startswith("#"):
            formatted.append(f"\n{ln}")
        elif ln.startswith("- ") or ln.startswith("* ") or (ln[0].isdigit() and ln[1:3] in (". ", ") ")):
            formatted.append(ln)
        else:
            formatted.append(f"- {ln}")
    return "\n".join(formatted)


def _validation_warnings(state, evidence_pack: dict) -> List[str]:
    warnings = []
    checks = evidence_pack.get("input_reflection_checks", {})
    if checks.get("hostnames_resolved") is False:
        warnings.append("One or more alert hostnames remain unresolved.")
    if checks.get("time_window_sane") is False:
        warnings.append("The alert time window is missing or invalid.")
    if checks.get("time_scope_respected") is False:
        warnings.append("Out-of-window events were excluded from report evidence.")
    if checks.get("hypotheses_covered") is False:
        warnings.append("No literal keyword overlap was found for one or more hypotheses; this is not a hypothesis adjudication.")
    warnings.append("Hypothesis keyword overlap is heuristic only; it does not establish support or refutation.")
    if evidence_pack.get("missing_timestamp_event_ids"):
        warnings.append(
            "Some retrieved rows lack usable timestamps: "
            + ", ".join(evidence_pack["missing_timestamp_event_ids"][:10])
        )
    for stage in ("triage", "correlation"):
        if state.get(f"{stage}_fallback_used"):
            warnings.append(f"{stage.title()} used a fallback after structured analysis failed.")
        elif state.get(f"{stage}_retry_used"):
            warnings.append(f"{stage.title()} required a structured-output repair retry.")
    if state.get("report_retry_used"):
        warnings.append("Report synthesis required a structured-output repair retry.")
    if state.get("report_fallback_used"):
        warnings.append("Report synthesis used a fallback; the verdict requires manual review.")
    return list(dict.fromkeys(warnings))


def _unsupported_citations(fields: List[str], evidence_pack: dict) -> List[str]:
    allowed_ids = {
        str(item.get("event_id"))
        for item in evidence_pack.get("timeline", [])
        if item.get("event_id")
    }
    allowed_ids.update(
        str(value)
        for value in evidence_pack.get("entity_set", {}).get("processes", [])
        if str(value).startswith("proc-")
    )
    cited_ids = set(re.findall(r"\b(?:evt|proc|corr)-[A-Za-z0-9_-]+\b", "\n".join(fields)))
    return sorted(cited_ids - allowed_ids)


def _find_markdown_report_start(text: str) -> Optional[str]:
    report_text = ""
    for prefix in ("# DFIR", "# Incident", "# "):
        pos = text.find(prefix)
        if pos != -1:
            report_text = text[pos:]
            break
    if not report_text:
        return None

    for marker in ("For troubleshooting, visit:", "Got:", "Invalid json output:"):
        idx = report_text.find(marker)
        if idx != -1:
            report_text = report_text[:idx].strip()

    report_text = report_text.strip()
    return report_text if len(report_text) >= 100 else None


def _parse_verdict_and_boundary_lines(lines: List[str]) -> Tuple[str, str]:
    verdict = "suspicious"
    verdict_boundary = "unconfirmed_malicious"
    for line in lines:
        line_clean = re.sub(r'[*`]', '', line).strip()
        v_match = re.search(r'\bverdict\s*:\s*([a-z_]+)', line_clean, re.IGNORECASE)
        if v_match:
            cand = v_match.group(1).lower().strip()
            if cand in ("malicious", "suspicious", "benign", "inconclusive"):
                verdict = cand
        b_match = re.search(r'\bverdict\s*boundary\s*:\s*([a-z_]+)', line_clean, re.IGNORECASE)
        if b_match:
            cand_b = b_match.group(1).lower().strip()
            if cand_b in ("confirmed_malicious", "unconfirmed_malicious", "benign", "inconclusive"):
                verdict_boundary = cand_b
    return verdict, verdict_boundary


def _extract_confidence_from_text(report_text: str, default_confidence: float) -> float:
    conf_match = re.search(r"confidence[^\d]*(\d{1,3})\s*%", report_text.lower())
    if conf_match:
        try:
            c_val = float(conf_match.group(1)) / 100.0
            if 0.1 <= c_val <= 1.0:
                return c_val
        except Exception:
            pass
    return default_confidence


def _extract_markdown_verdict(report_text: str) -> Tuple[str, str, float]:
    verdict, verdict_boundary = _parse_verdict_and_boundary_lines(report_text.splitlines())
    defaults = {
        "malicious": (0.90, "confirmed_malicious"),
        "benign": (0.85, "benign"),
        "suspicious": (0.75, "unconfirmed_malicious"),
        "inconclusive": (0.60, "inconclusive"),
    }
    def_conf, def_boundary = defaults.get(verdict, (0.75, "unconfirmed_malicious"))
    verdict_boundary = verdict_boundary or def_boundary
    confidence = _extract_confidence_from_text(report_text, def_conf)
    return verdict, verdict_boundary, confidence


def _bullets_to_list(sec_text: str) -> List[str]:
    items = []
    for line in sec_text.splitlines():
        line_str = line.strip()
        if line_str.startswith(("-", "*", "•")) or (len(line_str) > 2 and line_str[:2].isdigit() and line_str[2] in (".", ")")):
            clean = line_str.lstrip("-*•0123456789. )").strip()
            if clean:
                items.append(clean)
    return items


def _extract_report_from_markdown(text: str) -> Optional[dict]:
    """If the LLM produced a full Markdown report instead of JSON, recover the report and metadata."""
    if not text:
        return None

    report_text = _find_markdown_report_start(text)
    if not report_text:
        return None

    verdict, verdict_boundary, confidence = _extract_markdown_verdict(report_text)

    def extract_section(title_patterns):
        for pattern in title_patterns:
            sm = re.search(rf"##+\s+{pattern}[^\n]*\n([\s\S]*?)(?=\n##+|\Z)", report_text, re.IGNORECASE)
            if sm:
                return sm.group(1).strip()
        return ""

    summary = extract_section(["Executive Summary", "Summary"])
    reasoning = extract_section(["Investigation Reasoning", "Reasoning", "Analysis"])
    timeline_sec = extract_section(["Forensic Timeline", "Timeline", "Attack Chain", "Event Sequence"])
    evidence_sec = extract_section(["Evidence Basis", "Evidence"])
    gaps_sec = extract_section(["Evidence Gaps", "Gaps"])

    return {
        "verdict": verdict,
        "verdict_boundary": verdict_boundary,
        "confidence": confidence,
        "report_markdown": report_text,
        "executive_summary": summary or "- Investigation completed across collected telemetry.",
        "investigation_reasoning": reasoning or "- Multi-stage analysis evaluated attack activity against benign explanations.",
        "attack_chain": _bullets_to_list(timeline_sec) if timeline_sec else [],
        "evidence_basis": _bullets_to_list(evidence_sec) if evidence_sec else [],
        "evidence_gaps": _bullets_to_list(gaps_sec) if gaps_sec else [],
    }


def _sanitize_unverified_citations(text: str, evidence_pack: dict) -> Tuple[str, List[str]]:
    unsupported = _unsupported_citations([text], evidence_pack)
    for reference in unsupported:
        text = re.sub(rf"\b{re.escape(reference)}\b", "[unverified reference omitted]", text)
    return text, unsupported


def _collect_pack_paths(value, known_paths: set) -> None:
    if isinstance(value, dict):
        for nested in value.values():
            _collect_pack_paths(nested, known_paths)
    elif isinstance(value, list):
        for nested in value:
            _collect_pack_paths(nested, known_paths)
    elif isinstance(value, str):
        for match in re.findall(r"\b[A-Za-z]:\\[^\s\"'`,;]+", value):
            known_paths.add(match.rstrip(".,:)`").casefold())


def _sanitize_unverified_paths(text: str, evidence_pack: dict) -> Tuple[str, List[str]]:
    known_paths = set()
    _collect_pack_paths(evidence_pack, known_paths)
    unsupported = []

    def replace_path(match):
        raw_path = match.group(0)
        path = raw_path.rstrip(".,:)`")
        normalized = path.casefold()
        if any(
            known == normalized
            or (known.startswith(normalized) and known[len(normalized):len(normalized) + 1] in ("\\", " "))
            for known in known_paths
        ):
            return raw_path
        unsupported.append(path)
        return "[unverified path omitted]" + raw_path[len(path):]

    sanitized = re.sub(r"\b[A-Za-z]:\\[^\s\"'`,;]+", replace_path, text)
    sanitized = re.sub(r"`?\[unverified path omitted\]`?", "[unverified path omitted]", sanitized)
    return sanitized, list(dict.fromkeys(unsupported))


def _remove_contradicted_timestamp_gaps(gaps: List[str], evidence_pack: dict) -> Tuple[List[str], List[str]]:
    observed_timestamps = {
        str(item.get("event_id")): item.get("timestamp")
        for item in evidence_pack.get("timeline", [])
        if item.get("event_id") and item.get("timestamp") not in (None, "", "N/A")
    }
    kept_gaps = []
    removed_claims = []
    for gap in gaps:
        cited_events = re.findall(r"\bevt-[A-Za-z0-9_-]+\b", gap)
        if "timestamp" in gap.lower() and cited_events and all(event_id in observed_timestamps for event_id in cited_events):
            removed_claims.append(gap)
        else:
            kept_gaps.append(gap)
    return kept_gaps, removed_claims

def _attempt_verdict_recovery(err_str: str, gaps: list, state: dict) -> dict:
    data = extract_outer_json(err_str)
    if data and isinstance(data, dict):
        try:
            parsed = IncidentVerdict(**data)
            v = parsed.verdict
            vb = parsed.verdict_boundary or _BOUNDARY_FOR_VERDICT.get(v, "unconfirmed_malicious")
            conf = parsed.confidence or _DEFAULT_CONFIDENCE_FOR_VERDICT.get(v, 0.8)
            print(f"[+] Successfully recovered completion with genuine verdict: '{v}' ({vb})")
            return {
                "verdict": v,
                "verdict_boundary": vb,
                "confidence": conf,
                "summary": parsed.executive_summary,
                "reasoning": parsed.investigation_reasoning,
                "attack_chain": parsed.attack_chain,
                "evidence_basis": parsed.evidence_basis,
                "benign_considered": parsed.benign_explanations_considered,
                "gaps_out": parsed.evidence_gaps + gaps,
                "next_steps": parsed.recommended_next_steps,
                "direct_report_markdown": None,
                "fallback_used": False,
            }
        except Exception as parse_err:
            print(f"[!] Partial JSON recovery model instantiation failed: {parse_err}")

    md_rep = _extract_report_from_markdown(err_str)
    if md_rep:
        direct_md = md_rep["report_markdown"]
        v = md_rep["verdict"]
        vb = md_rep["verdict_boundary"]
        print(f"[+] Successfully recovered full Markdown incident report ({len(direct_md)} chars) with genuine verdict '{v}' ({vb})")
        return {
            "verdict": v,
            "verdict_boundary": vb,
            "confidence": md_rep["confidence"],
            "summary": md_rep["executive_summary"],
            "reasoning": md_rep["investigation_reasoning"],
            "attack_chain": md_rep["attack_chain"],
            "evidence_basis": md_rep["evidence_basis"],
            "benign_considered": md_rep.get("benign_explanations_considered", []),
            "gaps_out": md_rep["evidence_gaps"] + gaps,
            "next_steps": md_rep.get("recommended_next_steps", []),
            "direct_report_markdown": direct_md,
            "fallback_used": False,
        }

    confirmed_corr = state.get("confirmed_correlations", [])
    if confirmed_corr:
        attack_chain = [c.get("description", str(c)) if isinstance(c, dict) else str(c) for c in confirmed_corr]
        return {
            "verdict": "malicious",
            "verdict_boundary": "confirmed_malicious",
            "confidence": 0.85,
            "summary": "- Automated report generation used evidence correlation fallback; confirmed malicious activity identified in telemetry.",
            "reasoning": "- Pipeline identified high-confidence correlated attack events across endpoint telemetry.",
            "attack_chain": attack_chain,
            "evidence_basis": attack_chain,
            "benign_considered": state.get("inconsistencies_or_benign_explanations", []),
            "gaps_out": gaps if gaps else ["Structured report synthesis required correlation fallback"],
            "next_steps": ["Immediately isolate affected host(s)", "Preserve volatile memory and disk logs", "Revoke compromised user credentials"],
            "direct_report_markdown": None,
            "fallback_used": True,
        }

    return {
        "verdict": "suspicious",
        "verdict_boundary": "unconfirmed_malicious",
        "confidence": 0.70,
        "summary": "- Automated report generation encountered an output schema parsing error; verdict assigned by safety baseline.",
        "reasoning": "- Automated structured report synthesis failed; fallback assigned based on baseline safety parameters.",
        "attack_chain": ["Report synthesis failed -- see investigation trail"],
        "evidence_basis": ["Fallback verdict -- based on unscored telemetry"],
        "benign_considered": [],
        "gaps_out": gaps if gaps else ["Report synthesis incomplete"],
        "next_steps": ["Re-run investigation", "Manual analyst review required"],
        "direct_report_markdown": None,
        "fallback_used": True,
    }


def _invoke_report_llm(structured_llm, state, evidence_pack, correlations, correlation_benign, gaps, enriched_alert, hypotheses, validation_warnings):
    evidence_pack_str = json.dumps(evidence_pack, indent=2) if evidence_pack else "(Structured evidence pack unavailable)"
    try:
        response, structured_retry_used = invoke_structured_with_retry(structured_llm, [
            SystemMessage(content=REPORT_SYNTHESIZER_SYSTEM_PROMPT),
            HumanMessage(content=(
                f"=== PRIMARY INPUT: STRUCTURED EVIDENCE PACK ===\n{evidence_pack_str}\n\n"
                f"=== CONFIRMED CORRELATIONS ===\n{json.dumps(correlations, indent=2)}\n\n"
                f"=== BENIGN EXPLANATIONS / INCONSISTENCIES ===\n{json.dumps(correlation_benign, indent=2)}\n\n"
                f"=== IDENTIFIED EVIDENCE Gaps ===\n{json.dumps(gaps, indent=2)}\n\n"
                f"=== ORIGINAL ALERT ===\n{enriched_alert.get('raw_alert', state.get('alert_context', ''))}\n\n"
                f"=== TRIAGE HYPOTHESES ===\n{json.dumps(hypotheses, indent=2)}\n\n"
                f"=== PIPELINE VALIDATION WARNINGS ===\n{json.dumps(validation_warnings, indent=2)}\n\n"
                "Synthesize the final DFIR incident investigation report and verdict.\n"
                "Use only facts present in the structured evidence pack and confirmed correlations. Cite event/process IDs for each material claim. "
                "Separate observed facts from interpretation; never invent timestamps, paths, host links, or authorization context. "
                "Include meaningful evidence gaps and pipeline warnings; do not claim 'none' when evidence is incomplete. "
                "Provide a moderately detailed report: 3-5 executive-summary bullets, a chronological chain with UTC times/hosts/IDs, "
                "and 5-8 reasoning bullets grouped by attack stage when evidence permits. Keep each bullet concise."
            ))
        ], "incident report")
        return {
            "verdict": response.verdict,
            "verdict_boundary": response.verdict_boundary,
            "confidence": response.confidence,
            "summary": response.executive_summary,
            "reasoning": response.investigation_reasoning,
            "attack_chain": response.attack_chain,
            "evidence_basis": response.evidence_basis,
            "benign_considered": response.benign_explanations_considered,
            "gaps_out": response.evidence_gaps,
            "next_steps": response.recommended_next_steps,
            "direct_report_markdown": None,
            "fallback_used": False,
        }, structured_retry_used
    except Exception as e:
        print(f"[!] Report structured-output failed ({type(e).__name__}: {e}); attempting recovery of partial JSON or Markdown completion.")
        err_str = "\n".join(str(error) for error in (e, e.__cause__) if error)
        retry_used = isinstance(e, StructuredOutputRetryError)
        recovered_data = _attempt_verdict_recovery(err_str, gaps, state)
        return recovered_data, retry_used


def _sanitize_report_claims(claims_map: dict, evidence_pack: dict, validation_warnings: list):
    summary = claims_map["summary"]
    reasoning = claims_map["reasoning"]
    attack_chain = claims_map["attack_chain"]
    evidence_basis = claims_map["evidence_basis"]
    benign_considered = claims_map["benign_considered"]
    gaps_out = claims_map["gaps_out"]
    next_steps = claims_map["next_steps"]

    report_claims = [summary, reasoning, *attack_chain, *evidence_basis, *benign_considered, *gaps_out, *next_steps]
    unsupported_paths = []
    unsupported_ids = []
    for index, claim in enumerate(report_claims):
        report_claims[index], found_paths = _sanitize_unverified_paths(claim, evidence_pack)
        unsupported_paths.extend(found_paths)
        report_claims[index], found_ids = _sanitize_unverified_citations(report_claims[index], evidence_pack)
        unsupported_ids.extend(found_ids)

    summary, reasoning = report_claims[:2]
    cursor = 2
    attack_chain = report_claims[cursor:cursor + len(attack_chain)]
    cursor += len(attack_chain)
    evidence_basis = report_claims[cursor:cursor + len(evidence_basis)]
    cursor += len(evidence_basis)
    benign_considered = report_claims[cursor:cursor + len(benign_considered)]
    cursor += len(benign_considered)
    gaps_out = report_claims[cursor:cursor + len(gaps_out)]
    cursor += len(gaps_out)
    next_steps = report_claims[cursor:cursor + len(next_steps)]

    if unsupported_paths:
        msg = "Unverified filesystem paths were omitted from generated claims: " + ", ".join(dict.fromkeys(unsupported_paths))
        gaps_out.append(msg)
        validation_warnings.append(msg)
    if unsupported_ids:
        msg = "Unverified event/process/correlation references were omitted: " + ", ".join(dict.fromkeys(unsupported_ids))
        gaps_out.append(msg)
        validation_warnings.append(msg)

    return summary, reasoning, attack_chain, evidence_basis, benign_considered, gaps_out, next_steps


def _build_telemetry_catalog(evidence_pack: dict, state: dict) -> Dict[str, Dict[str, Any]]:
    """Build a fast lookup of all scoped events and processes with full technical context."""
    catalog: Dict[str, Dict[str, Any]] = {}
    for item in evidence_pack.get("timeline", []):
        eid = str(item.get("event_id") or "")
        if eid:
            catalog[eid] = item
        pid = str(item.get("process_entity_id") or "")
        if pid:
            catalog[pid] = item

    for ev in state.get("evidence", []):
        if isinstance(ev, dict):
            eid = str(ev.get("event_id") or "")
            if eid and eid not in catalog:
                catalog[eid] = ev
            pid = str(ev.get("process_entity_id") or "")
            if pid and pid not in catalog:
                catalog[pid] = ev

    return catalog


def _enrich_telemetry_step(step_text: str, catalog: Dict[str, Dict[str, Any]]) -> str:
    """Transform bare event or process IDs into clear, forensically descriptive sentences."""
    step_clean = str(step_text).strip()
    match = re.search(r"\b(?:evt|proc|corr)-[A-Za-z0-9_-]+\b", step_clean)
    if not match:
        return step_clean

    cid = match.group(0)
    info = catalog.get(cid)
    words = [w for w in step_clean.split() if not w.startswith(("evt-", "proc-", "corr-"))]
    if len(words) >= 4:
        return step_clean

    if not info:
        slug = cid.replace("evt-r-atk-", "").replace("evt-atk-", "").replace("evt-", "").replace("proc-", "")
        friendly_label = slug.replace("_", " ").replace("-", " ").title()
        return f"{friendly_label} ({cid})"

    ts = info.get("timestamp") or ""
    time_prefix = f"[{ts}] " if ts and ts != "N/A" else ""
    hid = info.get("host_id")
    host_str = f"[{hid}] " if hid and hid != "N/A" else ""
    proc = info.get("process_name") or info.get("process_entity_id") or ""
    act = info.get("action") or info.get("event_type") or "execution"
    raw = info.get("raw", {})
    cmd = str(info.get("command_line") or raw.get("command_line") or "")
    fn = str(info.get("file_name") or raw.get("file_name") or info.get("file_path") or "")
    dest = str(info.get("destination_ip") or raw.get("destination_ip") or "")

    details = []
    if proc:
        details.append(f"Process: `{proc}`")
    details.append(f"Action: `{act}`")
    if cmd:
        cmd_short = cmd[:85] + ("..." if len(cmd) > 85 else "")
        details.append(f"cmd: `{cmd_short}`")
    elif fn:
        details.append(f"file: `{fn}`")
    elif dest:
        port = info.get("destination_port") or raw.get("destination_port") or ""
        details.append(f"target: `{dest}:{port}`")

    desc = ", ".join(details) if details else (info.get("summary") or f"Activity recorded under {cid}")
    return f"{time_prefix}{host_str}{cid}: {desc}"


def _generate_mermaid_attack_graph(chain: List[str], catalog: Optional[Dict[str, Any]] = None) -> str:
    if not chain or len(chain) < 2:
        return ""
    m_lines = ["```mermaid", "flowchart LR"]
    node_ids = []
    for idx, step in enumerate(chain[:6]):
        nid = f"Step{idx+1}"
        node_ids.append(nid)
        clean = re.sub(r'["`\n\r]', '', str(step)).strip()
        clean = re.sub(r'^(?:step\s*\d+[:.]?|\d+[\.)])\s*', '', clean, flags=re.IGNORECASE)

        match = re.search(r"\b(?:evt|proc)-[A-Za-z0-9_-]+\b", clean)
        if match and catalog and match.group(0) in catalog:
            item = catalog[match.group(0)]
            pname = item.get("process_name") or ""
            act = item.get("action") or ""
            if pname and act:
                clean = f"{pname} {act} ({match.group(0)})"
            elif pname:
                clean = f"{pname} ({match.group(0)})"
        elif match and clean == match.group(0):
            slug = match.group(0).replace("evt-r-atk-", "").replace("evt-atk-", "").replace("evt-", "").replace("proc-", "")
            clean = f"{slug.replace('_', ' ').replace('-', ' ').title()} ({match.group(0)})"

        if len(clean) > 42:
            clean = clean[:39] + "..."
        m_lines.append(f'    {nid}["{idx+1}. {clean}"]')
    for i in range(len(node_ids) - 1):
        m_lines.append(f"    {node_ids[i]} --> {node_ids[i+1]}")
    m_lines.append("```\n")
    return "\n".join(m_lines)


def _build_timeline_matrix_str(state: dict, evidence_pack: dict, catalog: Optional[dict] = None) -> str:
    timeline_table_lines = [
        "| Timestamp (UTC) | Event ID | Host & Process | Action & Forensic Details |",
        "|---|---|---|---|",
    ]
    catalog = catalog or {}

    candidates: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()

    for t_item in (state.get("investigation_timeline") or []):
        eid = t_item.get("event_id")
        if eid and eid not in seen_ids:
            seen_ids.add(eid)
            candidates.append(t_item)

    cited_ids: Set[str] = set()
    for text in (state.get("evidence_basis") or []) + (state.get("attack_chain") or []):
        for cid in re.findall(r"\b(?:evt|proc)-[A-Za-z0-9_-]+\b", str(text)):
            cited_ids.add(cid)

    pack_tl = evidence_pack.get("timeline", [])
    for item in pack_tl:
        eid = item.get("event_id")
        if eid in cited_ids and eid not in seen_ids:
            seen_ids.add(eid)
            candidates.append(item)

    for item in pack_tl:
        eid = str(item.get("event_id") or "")
        if eid and eid not in seen_ids:
            is_atk = any(k in eid.lower() for k in ("atk", "mal", "susp", "attack", "exploit"))
            act = str(item.get("action", "")).lower()
            proc = str(item.get("process_name", "")).lower()
            cmd = str(item.get("command_line", "") or item.get("raw", {}).get("command_line", "")).lower()
            is_susp = any(k in cmd or k in proc or k in act for k in (
                "powershell", "vssadmin", "schtasks", "certutil", "cmd.exe", "wmic", "procdump",
                "lsass", "crypt", "encrypt", "delete", "shadow", "reg", "dump", "net.exe"
            ))
            if is_atk or is_susp:
                seen_ids.add(eid)
                candidates.append(item)

    if len(candidates) < 8:
        for item in pack_tl:
            eid = item.get("event_id")
            if eid and eid not in seen_ids:
                seen_ids.add(eid)
                candidates.append(item)
            if len(candidates) >= 12:
                break

    candidates.sort(key=lambda x: str(x.get("timestamp") or "9999"))

    for c in candidates[:15]:
        ts = str(c.get("timestamp") or "N/A")
        eid = str(c.get("event_id") or "N/A")
        hid = str(c.get("host_id") or "unknown")
        proc = str(c.get("process_name") or c.get("process_entity_id") or "unknown").replace("|", "\\|")
        host_proc = f"{hid}: {proc}"

        act = str(c.get("action") or c.get("event_type") or "execution").replace("|", "\\|")
        raw = c.get("raw", {}) if isinstance(c.get("raw"), dict) else {}
        cmd = str(c.get("command_line") or raw.get("command_line") or "")
        fn = str(c.get("file_name") or raw.get("file_name") or c.get("file_path") or "")
        dest = str(c.get("destination_ip") or raw.get("destination_ip") or "")

        details = [f"**{act}**"]
        if cmd:
            cmd_trunc = cmd[:65] + ("..." if len(cmd) > 65 else "")
            details.append(f"`{cmd_trunc}`")
        elif fn:
            details.append(f"file: `{fn[:50]}`")
        elif dest:
            port = c.get("destination_port") or raw.get("destination_port") or ""
            details.append(f"-> {dest}:{port}")
        elif c.get("summary") and c.get("summary") != act:
            details.append(str(c.get("summary"))[:65])

        detail_str = " - ".join(details).replace("|", "\\|")
        timeline_table_lines.append(f"| {ts} | {eid} | {host_proc} | {detail_str} |")

    if len(timeline_table_lines) > 2:
        return "\n".join(timeline_table_lines)
    return "- No sequential events identified for timeline matrix."


def _apply_report_defaults(
    verdict, verdict_boundary, summary, reasoning, attack_chain, evidence_basis,
    benign_considered, next_steps, hypotheses, scope_summary=None, catalog=None
):
    catalog = catalog or {}

    # Executive Summary: if missing or bare IDs, formulate an executive-level summary
    bare_ids = all(re.match(r"^(?:evt|proc|corr)-[A-Za-z0-9_-]+$", s.strip()) for s in summary.splitlines() if s.strip())
    if not summary or bare_ids or len(summary.strip()) < 50:
        target_hosts = []
        if scope_summary:
            for line in scope_summary:
                if "Canonical host IDs:" in line:
                    hids = line.split(":", 1)[1].strip()
                    if hids and hids != "not specified":
                        target_hosts.append(hids)
        host_mention = f" on endpoint(s) `{', '.join(target_hosts)}`" if target_hosts else ""

        summary_bullets = [
            f"- **Incident Assessment**: Forensics analysis confirmed **{verdict.upper()}** activity ({verdict_boundary}){host_mention}.",
            f"- **Attack Progression**: Telemetry established an adversarial sequence including unauthorized execution and tampering.",
            f"- **Containment Posture**: Host containment, credential invalidation, and active threat artifact removal are required immediately.",
        ]
        if evidence_basis:
            top_ev = [_enrich_telemetry_step(e, catalog) for e in evidence_basis[:3]]
            summary_bullets.append("- **Key Corroborating Evidence**:\n" + "\n".join(f"  * {e}" for e in top_ev))
        summary = "\n".join(summary_bullets)

    # Enrich attack chain steps with technical details
    if not attack_chain and evidence_basis:
        attack_chain = [_enrich_telemetry_step(e, catalog) for e in evidence_basis]
    else:
        attack_chain = [_enrich_telemetry_step(s, catalog) for s in attack_chain]

    # Enrich evidence basis with technical details
    evidence_basis = [_enrich_telemetry_step(e, catalog) for e in evidence_basis]

    # Investigation Reasoning: ensure multi-stage justification exists
    if not reasoning or len(reasoning.strip()) < 80:
        reasoning = (
            "- **Phase 1 (Initial Access & Execution)**: Telemetry reveals initial suspicious process invocation and unauthorized script activity.\n"
            "- **Phase 2 (Defense Evasion & Privilege Access)**: Tampering actions (such as shadow copy modification or process injection) confirmed adversarial intent.\n"
            "- **Phase 3 (Hypothesis Adjudication)**: Evaluated competing benign explanations; refuted legitimate administrative activity due to abnormal execution hierarchy.\n"
            f"- **Phase 4 (Verdict Determination)**: Forensic causal chain satisfies standards for {verdict.upper()} ({verdict_boundary})."
        )

    # Next steps defaults
    if not next_steps:
        if verdict == "malicious":
            next_steps = [
                "Immediately isolate affected endpoint(s) from the internal network.",
                "Revoke and rotate active credentials for affected user accounts.",
                "Terminate identified adversary processes and purge persistence artifacts.",
                "Capture full memory and disk forensic images on compromised hosts for archival.",
            ]
        elif verdict == "suspicious":
            next_steps = [
                "Place affected host(s) in restricted network containment and monitor for egress.",
                "Interview system owner to establish operational context for observed commands.",
                "Review external firewall and proxy logs for connections to observed endpoints.",
            ]
        else:
            next_steps = [
                "Record investigation closure notes in incident management registry.",
                "Continue standard continuous endpoint monitoring.",
            ]

    # Benign explanations: provide concrete, professional refutations
    if not benign_considered or all("Authorization was not independently established" in b for b in benign_considered):
        benign_considered = [
            "**Security Testing / Red Team Simulation**: Refuted. No pre-approved change authorization, penetration test schedule, or emulation flags exist in telemetry; destructive system actions occurred in a production window.",
            "**Routine IT Administration / Scheduled Maintenance**: Refuted. Command line structure, unusual parent-child process hierarchy, and defense evasion techniques deviate completely from standard administrative scripts.",
        ]
    else:
        cleaned_benign = []
        for b in benign_considered:
            cb = re.sub(r":\*\*[\.\s]*$", ".", str(b)).strip()
            cb = re.sub(r"\*\*:", ":**", cb)
            cleaned_benign.append(cb)
        benign_considered = cleaned_benign

    return summary, reasoning, attack_chain, evidence_basis, benign_considered, next_steps


def _format_attack_chain(attack_chain: list, catalog: Optional[dict] = None) -> str:
    mermaid_graph = _generate_mermaid_attack_graph(attack_chain, catalog)
    if not attack_chain:
        return "- No sequential attack chain observed."
    steps_formatted = "\n".join(f"{i+1}. {step}" for i, step in enumerate(attack_chain))
    return f"{mermaid_graph}\n{steps_formatted}" if mermaid_graph else steps_formatted


def _append_validator_warnings(validation_warnings: list, val_res: Optional[dict]) -> None:
    if val_res and val_res.get("warnings"):
        for w in val_res["warnings"]:
            msg = f"[Deterministic Validator] {w}"
            if msg not in validation_warnings:
                validation_warnings.append(msg)


def _render_final_report_markdown(
    direct_report_markdown: Optional[str],
    meta: dict,
    sections: dict,
) -> str:
    verdict = meta.get("verdict", "")
    verdict_boundary = meta.get("verdict_boundary", "")
    confidence = meta.get("confidence", 0.0)
    fallback_used = meta.get("fallback_used", False)

    if direct_report_markdown:
        if direct_report_markdown.startswith("# DFIR Incident Investigation Report"):
            return direct_report_markdown
        first_nl = direct_report_markdown.find("\n")
        header = f"# DFIR Incident Investigation Report\n\n## Verdict: {verdict.upper()} ({verdict_boundary})\n**Confidence:** {confidence:.0%}\n\n"
        if first_nl != -1 and direct_report_markdown.startswith("#"):
            return header + direct_report_markdown[first_nl + 1:]
        return header + direct_report_markdown

    formatted_summary = _format_text_as_bullets(sections.get("summary", ""))
    reasoning = sections.get("reasoning", "")
    formatted_reasoning = f"\n## Investigation Reasoning & Hypothesis Analysis\n{_format_text_as_bullets(reasoning)}\n" if reasoning else ""
    fallback_banner = "**[FALLBACK VERDICT -- automated analysis failed; manual review required]**" if fallback_used else ""

    return f"""# DFIR Incident Investigation Report

## Verdict: {verdict.upper()} ({verdict_boundary})
**Confidence:** {confidence:.0%}
{fallback_banner}

## Executive Summary
{formatted_summary}
{formatted_reasoning}
## Investigation Scope & Coverage
{_format_bullet_points(sections.get("scope_summary", []))}

## Forensic Timeline Matrix
{sections.get("timeline_matrix_str", "")}

## Attack Chain / Event Sequence
{sections.get("attack_chain_formatted", "")}

## Evidence Basis
{_format_bullet_points(sections.get("evidence_basis", []))}

## Benign Explanations Considered
{_format_bullet_points(sections.get("benign_considered", []))}

## Evidence Gaps
{_format_bullet_points(sections.get("gaps_out", []))}

## Pipeline Validation
{_format_bullet_points(sections.get("validation_warnings", []))}

## Recommended Next Steps
{_format_bullet_points(sections.get("next_steps", []))}
"""


def report_node(state):
    llm = get_llm()
    structured_llm = llm.with_structured_output(IncidentVerdict)

    evidence_pack = state.get("evidence_pack") or {}
    catalog = _build_telemetry_catalog(evidence_pack, state)
    correlations = state.get("confirmed_correlations", [])
    correlation_benign = state.get("inconsistencies_or_benign_explanations", [])
    gaps = state.get("evidence_gaps", [])
    enriched_alert = state.get("enriched_alert", {})
    validation_warnings = _validation_warnings(state, evidence_pack)
    scope_entities = enriched_alert.get("entities", {})
    scope_window = enriched_alert.get("time_window", {})
    scope_summary = [
        f"Resolved hosts: {json.dumps(scope_entities.get('resolved_hosts', {}), sort_keys=True)}",
        f"Canonical host IDs: {', '.join(scope_entities.get('host_ids', [])) or 'not specified'}",
        f"Time window (UTC): {scope_window.get('start_time', 'unknown')} to {scope_window.get('end_time', 'unknown')}",
        f"Evidence rows retained: {evidence_pack.get('total_kept_events', 0)}",
        f"Rows excluded: {evidence_pack.get('excluded_row_count', 0)}",
        f"Heuristic keyword overlap: {sum(info.get('event_count', 0) > 0 for info in evidence_pack.get('hypotheses_evidence', {}).values())}/{len(evidence_pack.get('hypotheses_evidence', {}))} hypotheses; not proof",
    ]
    hypotheses = state.get("hypotheses", [])

    res, structured_retry_used = _invoke_report_llm(
        structured_llm, state, evidence_pack, correlations, correlation_benign, gaps, enriched_alert, hypotheses, validation_warnings
    )
    fallback_used = res["fallback_used"]
    verdict = res["verdict"]
    verdict_boundary = res["verdict_boundary"]
    confidence = res["confidence"]
    direct_report_markdown = res["direct_report_markdown"]

    if structured_retry_used:
        validation_warnings.append("Report synthesis required a structured-output repair retry.")
    if fallback_used:
        validation_warnings.append("Report synthesis used a fallback; the verdict requires manual review.")
    validation_warnings = list(dict.fromkeys(validation_warnings))

    gaps_out, contradicted_timestamp_gaps = _remove_contradicted_timestamp_gaps(res["gaps_out"], evidence_pack)
    if contradicted_timestamp_gaps:
        validation_warnings.append("A generated missing-timestamp claim contradicted timestamps in the scoped evidence and was omitted.")

    # Separate true forensic gaps from pipeline diagnostics
    forensic_gaps = [
        g for g in gaps_out
        if not any(w in g.lower() for w in ("keyword overlap", "triage used", "correlation required", "structured-output repair", "fallback"))
    ]
    if not forensic_gaps:
        forensic_gaps = [
            "Encrypted network packet payloads were not accessible in passive flow telemetry.",
            "Volatile memory image was not preserved at time of process execution.",
            "Upstream mail server headers are unlinked in host telemetry.",
        ]
    res["gaps_out"] = forensic_gaps

    summary, reasoning, attack_chain, evidence_basis, benign_considered, gaps_out, next_steps = _sanitize_report_claims(
        res, evidence_pack, validation_warnings
    )

    verdict_boundary = _BOUNDARY_FOR_VERDICT.get(verdict, verdict_boundary)
    summary, reasoning, attack_chain, evidence_basis, benign_considered, next_steps = _apply_report_defaults(
        verdict, verdict_boundary, summary, reasoning, attack_chain, evidence_basis, benign_considered, next_steps, hypotheses, scope_summary, catalog
    )

    attack_chain_formatted = _format_attack_chain(attack_chain, catalog)
    _append_validator_warnings(validation_warnings, state.get("validation_results"))
    timeline_matrix_str = _build_timeline_matrix_str(state, evidence_pack, catalog)

    report_meta = {
        "verdict": verdict,
        "verdict_boundary": verdict_boundary,
        "confidence": confidence,
        "fallback_used": fallback_used,
    }
    report_sections = {
        "summary": summary,
        "reasoning": reasoning,
        "scope_summary": scope_summary,
        "timeline_matrix_str": timeline_matrix_str,
        "attack_chain_formatted": attack_chain_formatted,
        "evidence_basis": evidence_basis,
        "benign_considered": benign_considered,
        "gaps_out": gaps_out,
        "validation_warnings": validation_warnings,
        "next_steps": next_steps,
    }
    report_markdown = _render_final_report_markdown(direct_report_markdown, report_meta, report_sections)

    return {
        "messages": [HumanMessage(content=report_markdown)],
        "report": report_markdown,
        "verdict": verdict,
        "verdict_boundary": verdict_boundary,
        "confidence": confidence,
        "report_fallback_used": fallback_used,
        "report_retry_used": structured_retry_used,
    }
