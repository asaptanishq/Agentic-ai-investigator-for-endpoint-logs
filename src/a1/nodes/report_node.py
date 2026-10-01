import json
import re
from datetime import datetime, timedelta
from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel, Field, field_validator
from typing import List, Literal, Optional, Tuple

from a1.llm import get_llm
from a1.prompts import REPORT_SYNTHESIZER_SYSTEM_PROMPT
from a1.nodes.structured_output import StructuredOutputRetryError, invoke_structured_with_retry, extract_outer_json

CHANNEL_TOKEN_PATTERN = r"<\|?channel[^>]*\|?>"
THINK_TOKEN_PATTERN = r"</?think>"
NONE_DOCUMENTED = "- None documented"

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
            valid = {"benign", "suspicious", "malicious", "inconclusive"}
            if norm in valid:
                return norm
            if "malicious" in norm:
                return "malicious"
            if "suspicious" in norm:
                return "suspicious"
            if "benign" in norm:
                return "benign"
            if "inconclusive" in norm:
                return "inconclusive"
            return "suspicious"
        else:
            valid = {"confirmed_malicious", "unconfirmed_malicious", "benign", "inconclusive"}
            if norm in valid:
                return norm
            if "confirmed_malicious" in norm:
                return "confirmed_malicious"
            if "unconfirmed_malicious" in norm or "unconfirmed" in norm or "malicious" in norm:
                return "unconfirmed_malicious"
            if "benign" in norm:
                return "benign"
            if "inconclusive" in norm:
                return "inconclusive"
            return "unconfirmed_malicious"

    @field_validator("executive_summary", "investigation_reasoning", mode="before")
    @classmethod
    def normalize_report_text(cls, value):
        if isinstance(value, str):
            value = re.sub(CHANNEL_TOKEN_PATTERN, "", value, flags=re.IGNORECASE)
            value = re.sub(THINK_TOKEN_PATTERN, "", value, flags=re.IGNORECASE)
            return value.strip()
        if isinstance(value, list):
            lines = []
            for item in value:
                if isinstance(item, dict):
                    for k, v in item.items():
                        title = k.replace("_", " ").title()
                        lines.append(f"**{title}**: {v}")
                else:
                    lines.append(str(item))
            text = "\n".join(lines)
            text = re.sub(CHANNEL_TOKEN_PATTERN, "", text, flags=re.IGNORECASE)
            return text.strip()
        if isinstance(value, dict):
            lines = []
            for k, v in value.items():
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


def _extract_report_from_markdown(text: str) -> Optional[dict]:
    """If the LLM produced a full Markdown report instead of JSON, recover the report and metadata."""
    if not text:
        return None

    m = re.search(r"(?:Invalid json output:\s*|Got:\s*|\n|^)(#\s*(?:DFIR|Incident)?[^\n]*Report[^\n]*\n[\s\S]+)", text, re.IGNORECASE)
    if not m:
        m2 = re.search(r"(#{1,3}\s+[^\n]+[\s\S]+)", text)
        if not m2 or ("## Executive Summary" not in text and "## Verdict" not in text and "## Investigation Reasoning" not in text):
            return None
        report_text = m2.group(1)
    else:
        report_text = m.group(1)

    for marker in ("For troubleshooting, visit:", "Got:", "Invalid json output:"):
        idx = report_text.find(marker)
        if idx != -1:
            report_text = report_text[:idx].strip()

    report_text = report_text.strip()
    if len(report_text) < 100:
        return None

    verdict = "suspicious"
    verdict_boundary = "unconfirmed_malicious"
    confidence = 0.85

    for line in report_text.splitlines():
        line_clean = re.sub(r'[*`]', '', line).strip()
        v_match = re.search(r'\bverdict\s*:\s*([a-zA-Z_]+)', line_clean, re.IGNORECASE)
        if v_match:
            cand = v_match.group(1).lower().strip()
            if cand in ("malicious", "suspicious", "benign", "inconclusive"):
                verdict = cand
        b_match = re.search(r'\bverdict\s*boundary\s*:\s*([a-zA-Z_]+)', line_clean, re.IGNORECASE)
        if b_match:
            cand_b = b_match.group(1).lower().strip()
            if cand_b in ("confirmed_malicious", "unconfirmed_malicious", "benign", "inconclusive"):
                verdict_boundary = cand_b

    if verdict == "malicious":
        confidence = 0.90
        verdict_boundary = "confirmed_malicious"
    elif verdict == "benign":
        confidence = 0.85
        verdict_boundary = "benign"
    elif verdict == "suspicious":
        confidence = 0.75
        verdict_boundary = "unconfirmed_malicious"
    elif verdict == "inconclusive":
        confidence = 0.60
        verdict_boundary = "inconclusive"

    conf_match = re.search(r"confidence[^\d]*(\d{1,3})\s*%", report_text.lower())
    if conf_match:
        try:
            c_val = float(conf_match.group(1)) / 100.0
            if 0.1 <= c_val <= 1.0:
                confidence = c_val
        except Exception:
            pass

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

    def bullets_to_list(sec_text):
        items = []
        for line in sec_text.splitlines():
            line_str = line.strip()
            if line_str.startswith(("-", "*", "•")) or (len(line_str) > 2 and line_str[:2].isdigit() and line_str[2] in (".", ")")):
                clean = line_str.lstrip("-*•0123456789. )").strip()
                if clean:
                    items.append(clean)
        return items

    return {
        "verdict": verdict,
        "verdict_boundary": verdict_boundary,
        "confidence": confidence,
        "report_markdown": report_text,
        "executive_summary": summary or "- Investigation completed across collected telemetry.",
        "investigation_reasoning": reasoning or "- Multi-stage analysis evaluated attack activity against benign explanations.",
        "attack_chain": bullets_to_list(timeline_sec) if timeline_sec else [],
        "evidence_basis": bullets_to_list(evidence_sec) if evidence_sec else [],
        "evidence_gaps": bullets_to_list(gaps_sec) if gaps_sec else [],
    }


def _sanitize_unverified_citations(text: str, evidence_pack: dict) -> Tuple[str, List[str]]:
    unsupported = _unsupported_citations([text], evidence_pack)
    for reference in unsupported:
        text = re.sub(rf"\b{re.escape(reference)}\b", "[unverified reference omitted]", text)
    return text, unsupported

def _sanitize_unverified_paths(text: str, evidence_pack: dict) -> Tuple[str, List[str]]:
    known_paths = set()

    def collect_paths(value):
        if isinstance(value, dict):
            for nested in value.values():
                collect_paths(nested)
        elif isinstance(value, list):
            for nested in value:
                collect_paths(nested)
        elif isinstance(value, str):
            for match in re.findall(r"\b[A-Za-z]:\\[^\s\"'`,;]+", value):
                known_paths.add(match.rstrip(".,:)`").casefold())

    collect_paths(evidence_pack)
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

def report_node(state):
    llm = get_llm()
    structured_llm = llm.with_structured_output(IncidentVerdict)

    # Primary Input: Structured Evidence Pack from Evidence Packing node
    evidence_pack = state.get("evidence_pack") or {}
    evidence_pack_str = json.dumps(evidence_pack, indent=2) if evidence_pack else "(Structured evidence pack unavailable)"

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

    fallback_used = False
    structured_retry_used = False
    direct_report_markdown = None

    # Safe defaults to prevent UnboundLocalError in any branch
    verdict = "suspicious"
    verdict_boundary = "unconfirmed_malicious"
    confidence = 0.8
    summary = ""
    reasoning = ""
    attack_chain = []
    evidence_basis = []
    benign_considered = []
    gaps_out = []
    next_steps = []

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
        verdict = response.verdict
        verdict_boundary = response.verdict_boundary
        confidence = response.confidence
        summary = response.executive_summary
        reasoning = response.investigation_reasoning
        attack_chain = response.attack_chain
        evidence_basis = response.evidence_basis
        benign_considered = response.benign_explanations_considered
        gaps_out = response.evidence_gaps
        next_steps = response.recommended_next_steps
    except Exception as e:
        print(f"[!] Report structured-output failed ({type(e).__name__}: {e}); attempting recovery of partial JSON or Markdown completion.")
        recovered = False
        err_str = "\n".join(str(error) for error in (e, e.__cause__) if error)
        structured_retry_used = isinstance(e, StructuredOutputRetryError)

        # Attempt 1: Recover JSON from completion in exception using balanced bracket parser
        data = extract_outer_json(err_str)

        if data and isinstance(data, dict):
            try:
                parsed = IncidentVerdict(**data)
                verdict = parsed.verdict
                verdict_boundary = parsed.verdict_boundary or _BOUNDARY_FOR_VERDICT.get(verdict, "unconfirmed_malicious")
                confidence = parsed.confidence or _DEFAULT_CONFIDENCE_FOR_VERDICT.get(verdict, 0.8)
                summary = parsed.executive_summary
                reasoning = parsed.investigation_reasoning
                attack_chain = parsed.attack_chain
                evidence_basis = parsed.evidence_basis
                benign_considered = parsed.benign_explanations_considered
                gaps_out = parsed.evidence_gaps + gaps
                next_steps = parsed.recommended_next_steps
                recovered = True
                print(f"[+] Successfully recovered completion with genuine verdict: '{verdict}' ({verdict_boundary})")
            except Exception as parse_err:
                print(f"[!] Partial JSON recovery model instantiation failed: {parse_err}")

        # Attempt 2: Recover full Markdown incident report from completion
        if not recovered:
            md_rep = _extract_report_from_markdown(err_str)
            if md_rep:
                direct_report_markdown = md_rep["report_markdown"]
                verdict = md_rep["verdict"]
                verdict_boundary = md_rep["verdict_boundary"]
                confidence = md_rep["confidence"]
                summary = md_rep["executive_summary"]
                reasoning = md_rep["investigation_reasoning"]
                attack_chain = md_rep["attack_chain"]
                evidence_basis = md_rep["evidence_basis"]
                benign_considered = md_rep.get("benign_explanations_considered", [])
                gaps_out = md_rep["evidence_gaps"] + gaps
                next_steps = md_rep.get("recommended_next_steps", [])
                recovered = True
                fallback_used = False
                print(f"[+] Successfully recovered full Markdown incident report ({len(direct_report_markdown)} chars) with genuine verdict '{verdict}' ({verdict_boundary})")

        if not recovered:
            fallback_used = True
            confirmed_corr = state.get("confirmed_correlations", [])
            if confirmed_corr:
                verdict = "malicious"
                verdict_boundary = "confirmed_malicious"
                confidence = 0.85
                summary = "- Automated report generation used evidence correlation fallback; confirmed malicious activity identified in telemetry."
                reasoning = "- Pipeline identified high-confidence correlated attack events across endpoint telemetry."
                attack_chain = [c.get("description", str(c)) if isinstance(c, dict) else str(c) for c in confirmed_corr]
                evidence_basis = attack_chain
                benign_considered = state.get("inconsistencies_or_benign_explanations", [])
                gaps_out = gaps if gaps else ["Structured report synthesis required correlation fallback"]
                next_steps = ["Immediately isolate affected host(s)", "Preserve volatile memory and disk logs", "Revoke compromised user credentials"]
            else:
                verdict = "suspicious"
                verdict_boundary = "unconfirmed_malicious"
                confidence = 0.70
                summary = "- Automated report generation encountered an output schema parsing error; verdict assigned by safety baseline."
                reasoning = "- Automated structured report synthesis failed; fallback assigned based on baseline safety parameters."
                attack_chain = ["Report synthesis failed -- see investigation trail"]
                evidence_basis = ["Fallback verdict -- based on unscored telemetry"]
                benign_considered = []
                gaps_out = gaps if gaps else ["Report synthesis incomplete"]
                next_steps = ["Re-run investigation", "Manual analyst review required"]

    if structured_retry_used:
        validation_warnings.append("Report synthesis required a structured-output repair retry.")
    if fallback_used:
        validation_warnings.append("Report synthesis used a fallback; the verdict requires manual review.")
    validation_warnings = list(dict.fromkeys(validation_warnings))
    gaps_out, contradicted_timestamp_gaps = _remove_contradicted_timestamp_gaps(gaps_out, evidence_pack)
    if contradicted_timestamp_gaps:
        validation_warnings.append("A generated missing-timestamp claim contradicted timestamps in the scoped evidence and was omitted.")
    gaps_out = list(dict.fromkeys(gaps_out + validation_warnings))
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
        message = "Unverified filesystem paths were omitted from generated claims: " + ", ".join(dict.fromkeys(unsupported_paths))
        gaps_out.append(message)
        validation_warnings.append(message)
    if unsupported_ids:
        message = "Unverified event/process/correlation references were omitted: " + ", ".join(dict.fromkeys(unsupported_ids))
        gaps_out.append(message)
        validation_warnings.append(message)

    verdict_boundary = _BOUNDARY_FOR_VERDICT.get(verdict, verdict_boundary)

    # Populate smart defaults for summary and attack chain if model returned empty
    if not summary:
        if evidence_basis:
            summary = "- Activity identified and confirmed across target endpoints.\n" + _format_bullet_points(evidence_basis[:3])
        elif reasoning:
            summary = _format_text_as_bullets(reasoning[:300])
        else:
            summary = f"- Telemetry evaluated under verdict: {verdict.upper()} ({verdict_boundary})."

    if not attack_chain and evidence_basis:
        attack_chain = evidence_basis

    if not next_steps:
        if verdict == "malicious":
            next_steps = [
                "Immediately isolate affected endpoint(s) from the network.",
                "Revoke and rotate credentials for affected user accounts.",
                "Terminate malicious processes and remove created services/persistence artifacts.",
                "Conduct full disk and memory forensics on compromised hosts."
            ]
        elif verdict == "suspicious":
            next_steps = [
                "Monitor affected host(s) for further lateral movement or beaconing activity.",
                "Interview system owner to verify authorization of observed commands.",
                "Collect full host event logs for deeper manual analysis."
            ]
        else:
            next_steps = [
                "Document findings in incident case tracker.",
                "Continue routine security monitoring."
            ]

    if not benign_considered:
        benign_hypotheses = [
            hypothesis for hypothesis in hypotheses
            if any(term in hypothesis.lower() for term in ("benign", "routine", "legitimate", "false positive", "maintenance"))
        ]
        benign_considered = [
            f"Considered: {hypothesis}. Authorization was not independently established by the telemetry."
            for hypothesis in benign_hypotheses
        ]

    def _generate_mermaid_attack_graph(chain: List[str]) -> str:
        if not chain or len(chain) < 2:
            return ""
        m_lines = ["```mermaid", "flowchart LR"]
        node_ids = []
        for idx, step in enumerate(chain[:6]):
            nid = f"Step{idx+1}"
            node_ids.append(nid)
            clean = re.sub(r'["`\n\r]', '', str(step)).strip()
            clean = re.sub(r'^(?:step\s*\d+[:.]?|\d+[\.)])\s*', '', clean, flags=re.IGNORECASE)
            if len(clean) > 42:
                clean = clean[:39] + "..."
            m_lines.append(f'    {nid}["{idx+1}. {clean}"]')
        for i in range(len(node_ids) - 1):
            m_lines.append(f"    {node_ids[i]} --> {node_ids[i+1]}")
        m_lines.append("```\n")
        return "\n".join(m_lines)

    mermaid_graph = _generate_mermaid_attack_graph(attack_chain)
    attack_chain_formatted = (f"{mermaid_graph}\n" if mermaid_graph else "") + (
        chr(10).join(f'{i+1}. {step}' for i, step in enumerate(attack_chain))
        if attack_chain
        else "- No sequential attack chain observed."
    )

    formatted_summary = _format_text_as_bullets(summary)
    formatted_reasoning = f"\n## Investigation Reasoning & Hypothesis Analysis\n{_format_text_as_bullets(reasoning)}\n" if reasoning else ""

    if direct_report_markdown:
        report_markdown = direct_report_markdown
        if not report_markdown.startswith("# DFIR Incident Investigation Report"):
            first_nl = report_markdown.find("\n")
            if first_nl != -1 and report_markdown.startswith("#"):
                report_markdown = f"# DFIR Incident Investigation Report\n\n## Verdict: {verdict.upper()} ({verdict_boundary})\n**Confidence:** {confidence:.0%}\n\n" + report_markdown[first_nl+1:]
            else:
                report_markdown = f"# DFIR Incident Investigation Report\n\n## Verdict: {verdict.upper()} ({verdict_boundary})\n**Confidence:** {confidence:.0%}\n\n" + report_markdown
    else:
        report_markdown = f"""# DFIR Incident Investigation Report

## Verdict: {verdict.upper()} ({verdict_boundary})
**Confidence:** {confidence:.0%}
{'**[FALLBACK VERDICT -- automated analysis failed; manual review required]**' if fallback_used else ''}

## Executive Summary
{formatted_summary}
{formatted_reasoning}
## Investigation Scope & Coverage
{_format_bullet_points(scope_summary)}

## Attack Chain / Event Sequence
{attack_chain_formatted}

## Evidence Basis
{_format_bullet_points(evidence_basis)}

## Benign Explanations Considered
{_format_bullet_points(benign_considered)}

## Evidence Gaps
{_format_bullet_points(gaps_out)}

## Pipeline Validation
{_format_bullet_points(validation_warnings)}

## Recommended Next Steps
{_format_bullet_points(next_steps)}
"""

    return {
        "messages": [HumanMessage(content=report_markdown)],
        "report": report_markdown,
        "verdict": verdict,
        "verdict_boundary": verdict_boundary,
        "confidence": confidence,
        "report_fallback_used": fallback_used,
        "report_retry_used": structured_retry_used,
    }
