import json
import re
from pathlib import Path
import sys
from typing import Dict, Any, Optional, Tuple

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from a1.graph import create_investigation_graph
import a1.config as cfg

DATASET_DIR = cfg.DATASET_DIR

# One entry per scenario. ``database`` names the telemetry file the scenario lives
# in, so the benchmark switches databases between cases.
#
# Covers 10 benchmark scenarios across 4 operational classes: malicious intrusions,
# benign administrative activity (BEN-A), ambiguous developer tool execution (AMB-A),
# and incomplete telemetry gaps (INC-A).
BENCHMARK_CASES = {
    "ATK-A": {
        "prompt": (
            "Investigate suspicious activity on WS-OPS-01: a process accessed "
            "lsass.exe memory and a dump file appeared in a user Temp directory, "
            "the same session then opened SMB connections to SRV-FILE-01, and "
            "repeated failed network logons for one account were followed by a "
            "successful one and a new Windows service installation. Determine "
            "whether this is credential dumping and lateral movement or benign "
            "administrative activity."
        ),
        "database": "attack_lateral_movement.db",
    },
    "ATK-B": {
        "prompt": (
            "Investigate suspicious activity on WS-DEV-02: PowerShell spawned an "
            "archiver that staged the user's spreadsheets into a password-protected "
            "archive in Temp, then dropped a script and created a logon scheduled "
            "task, made repeated outbound HTTPS connections to an external address, "
            "and the archive was later deleted. Determine whether this is data "
            "exfiltration or benign software activity."
        ),
        "database": "attack_data_exfiltration.db",
    },
    "ATK-C": {
        "prompt": (
            "Investigate suspicious ransomware activity on WS-ACCT-01: Microsoft Word opened "
            "invoice_2026-Q3.docx, hidden PowerShell invoked vssadmin.exe to delete shadow "
            "copies, and LockBit executed encrypting user documents with .locked extensions. "
            "Determine whether this is ransomware or benign activity."
        ),
        "database": "ransomware_attack_complete_ecs.db",
    },
    "ATK-D": {
        "prompt": (
            "Investigate suspicious Living-off-the-Land and fileless execution on WS-EXEC-02: "
            "mshta.exe spawned hidden encoded PowerShell establishing outbound C2, discovery "
            "LOLBins executed, certutil staged payloads, and remote WMI execution occurred against "
            "DC-AUTH-01. Determine whether this is a fileless intrusion or benign administrative activity."
        ),
        "database": "attack_lotl_fileless.db",
    },
    "ATK-E": {
        "prompt": (
            "Investigate suspicious Living-off-the-Land PowerShell execution and SAM registry access "
            "on WS-DEV-01: hidden PowerShell executed, SAM registry hive was accessed, C2 connections "
            "were made to attacker.com, and lateral movement was attempted to WS-ADMIN-01. "
            "Determine whether this is an attack or benign administrative activity."
        ),
        "database": "wazuh_lotl_attack_dataset.db",
    },
    "ATK-F": {
        "prompt": (
            "Investigate suspicious Suricata NIDS alerts on WS-FINANCE-01 (192.168.1.105): "
            "ET MALWARE Win32/CobaltStrike Malleable C2 Beacon activity was triggered on port 8443 to 203.0.113.88, "
            "followed by internal SMB reconnaissance against DC-AUTH-01 (192.168.1.10) "
            "and outbound data transfer to 203.0.113.88. Determine whether this is a malicious "
            "intrusion or benign administrative/network activity."
        ),
        "database": "suricata_c2_intrusion.db",
    },
    "ATK-G": {
        "prompt": (
            "Investigate a potential supply chain compromise on WS-DEV-07: "
            "the CorpTools application auto-updated and shortly after, discovery "
            "commands were executed, a new local administrator account appeared, "
            "Kerberos ticket requests targeted SQL service accounts, and WinRM "
            "sessions were established to WS-DBA-03 and DC-CORP-01. Determine "
            "whether this is a supply chain attack or legitimate software activity."
        ),
        "database": "attack_supply_chain.db",
    },
    "BEN-A": {
        "prompt": (
            "Investigate scheduled activity on WS-ADMIN-05: svchost.exe spawned "
            "PowerShell running backup_verification.ps1 under CORP\\sysadmin, which "
            "opened SMB connections to SRV-FILE-02, wrote to backup_audit_20260915.log, "
            "and checked W32Time registry settings. Determine whether this is an attack "
            "or benign administrative activity."
        ),
        "database": "benign_admin_activity.db",
    },
    "AMB-A": {
        "prompt": (
            "Investigate command-line and utility activity on WS-EXEC-02: certutil.exe "
            "and PowerShell with flags were invoked during business hours. "
            "Evaluate whether this represents malicious C2 staging, dual-use developer "
            "activity, or benign administration, noting any ambiguity in intent."
        ),
        "database": "attack_lotl_fileless.db",
    },
    "INC-A": {
        "prompt": (
            "Investigate an alert claiming unauthorized execution on SRV-FILE-01. "
            "Examine telemetry for the parent process, network flows, and authentication. "
            "If essential telemetry is absent to prove or disprove malicious activity, "
            "render an inconclusive outcome citing the specific missing telemetry."
        ),
        "database": "attack_lateral_movement.db",
    },
}

# Case id -> prompt, kept as a flat mapping for existing tooling/tests.
BENCHMARK_PROMPTS = {case_id: case["prompt"] for case_id, case in BENCHMARK_CASES.items()}

def load_case_labels() -> list:
    """Load per-case evaluation labels.

    Prefers the evaluator-only ``case_labels.json`` when it exists (original
    five-scenario bundle layout). Otherwise derives equivalent labels from the
    shipped ``groundtruth_attack_*.json`` files, so the benchmark runs against
    the attack databases that ship with this repository.
    """
    labels_path = Path(DATASET_DIR) / "case_labels.json"
    if labels_path.exists():
        with open(labels_path, encoding="utf-8") as f:
            return json.load(f)
    derived = _labels_from_groundtruth_files()
    if derived:
        return derived
    raise FileNotFoundError(
        f"Benchmark labels not found at {labels_path}, and no "
        "groundtruth_attack_*.json files could be used as a fallback. "
        "Restore the evaluator metadata before scoring a benchmark run."
    )


def _extract_case_id_from_gt(gt_path: Path, gt: dict) -> str:
    stem_lower = gt_path.stem.lower()
    if "benign" in stem_lower:
        return "BEN-A"
    if "ambiguous" in stem_lower:
        return "AMB-A"
    if "incomplete" in stem_lower:
        return "INC-A"

    case_match = re.search(r"attack_([a-z0-9]+)", gt_path.name, re.IGNORECASE)
    if case_match:
        return f"ATK-{case_match.group(1).upper()}"
    if gt.get("case_id"):
        return str(gt["case_id"])

    dataset = gt.get("dataset", "")
    dataset_prefix_map = {
        "lateral": "ATK-A",
        "exfiltration": "ATK-B",
        "ransomware": "ATK-C",
        "lotl": "ATK-D",
        "wazuh": "ATK-E",
        "suricata": "ATK-F",
        "supply_chain": "ATK-G",
    }
    for key, cid in dataset_prefix_map.items():
        if key in dataset:
            return cid
    return gt_path.stem


def _load_single_gt_file(gt_path: Path) -> Optional[dict]:
    try:
        with open(gt_path, encoding="utf-8") as f:
            gt = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    case_id = _extract_case_id_from_gt(gt_path, gt)
    return {
        "case_id": case_id,
        "prompt": BENCHMARK_PROMPTS.get(case_id, gt.get("summary", "")),
        "case_label": gt.get("expected_verdict", "malicious"),
        "verdict_boundary": gt.get("verdict_boundary", "confirmed_malicious"),
        "confidence": "high",
        "evidence_basis": gt.get("evidence_basis", []),
    }


def _labels_from_groundtruth_files() -> list:
    """Build ``case_labels.json``-shaped labels from shipped groundtruth files."""
    gt_dir = Path(DATASET_DIR) / "groundtruth"
    gt_files = sorted(gt_dir.glob("groundtruth_*.json")) if gt_dir.is_dir() else []
    if not gt_files:
        gt_files = sorted(Path(DATASET_DIR).glob("groundtruth_*.json"))

    labels = []
    for gt_path in gt_files:
        entry = _load_single_gt_file(gt_path)
        if entry:
            labels.append(entry)

    labels.sort(key=lambda item: item.get("case_id", "ZZ"))
    return labels

def activate_case_database(database_name) -> None:
    """Switch to the telemetry database a scenario lives in, when available."""
    if not database_name:
        return
    candidate = Path(DATASET_DIR) / database_name
    if not candidate.exists():
        print(f"  [!] Scenario database '{database_name}' not found -- using {Path(cfg.DB_PATH).name}")
        return
    cfg.set_active_database(candidate)
    print(f"  [*] Telemetry database: {candidate.name}")

def _normalize_boundary(boundary: str) -> str:
    b = str(boundary).lower().strip()
    if b in ("confirmed_benign", "benign"):
        return "benign"
    if b == "telemetry_gap_inconclusive":
        return "inconclusive"
    return b


def _score_verdict(agent_verdict: str, expected_label: str, agent_boundary: str, expected_boundary: str, fallback_used: bool) -> float:
    if fallback_used:
        return 0.0
    pts = 0.0
    if agent_verdict == expected_label:
        pts += 15.0
    if _normalize_boundary(agent_boundary) == _normalize_boundary(expected_boundary):
        pts += 5.0
    return pts


def _extract_report_text_from_state(final_state: dict) -> str:
    messages = final_state.get("messages") or []
    for m in reversed(messages):
        content = getattr(m, "content", "")
        if "## Verdict" in content or "# DFIR" in content or "Executive Summary" in content:
            return content
    if messages:
        return str(getattr(messages[-1], "content", ""))
    return ""


_EVIDENCE_STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "via", "was", "were",
    "into", "then", "than", "after", "before", "same", "host", "event", "process",
    "activity", "execution", "sequence", "observed", "using", "used", "user",
}


def _stem(term: str) -> str:
    term = term.strip(". _-").lower()
    for suffix in ("ing", "ed", "es", "s"):
        if len(term) > 4 and term.endswith(suffix):
            return term[: -len(suffix)]
    return term


def _evidence_terms(item: Any) -> set:
    """Extract distinctive indicators from a ground-truth evidence item."""
    text = str(item or "")
    terms = set()
    for path in re.findall(r"[A-Za-z]:\\[^\s,;)\"']+|(?:[\w.-]+/)+[\w.-]+", text):
        clean = path.rstrip(".,;:)").lower()
        if len(clean) >= 5:
            terms.add(clean)
            base = clean.replace("\\", "/").rsplit("/", 1)[-1]
            if len(base) >= 4:
                terms.add(base)
    for token in re.findall(r"\b[a-z0-9][a-z0-9_.-]{2,}\b", text.lower()):
        if token in _EVIDENCE_STOPWORDS or token.isdigit():
            continue
        terms.add(_stem(token))
    return terms


def _score_evidence_recall(evidence_basis: list, combined_evidence_text: str) -> Tuple[float, float]:
    """Graded indicator coverage: partial matches count, not just one token."""
    if not evidence_basis:
        return 0.0, 0.0
    coverage = 0.0
    for item in evidence_basis:
        terms = _evidence_terms(item)
        if not terms:
            continue
        matched = sum(1 for term in terms if term in combined_evidence_text)
        coverage += matched / len(terms)
    recall_pct = coverage / len(evidence_basis)
    return round(25.0 * recall_pct, 1), recall_pct


_CITATION_RE = re.compile(r"\b(?:evt|proc|suri)-(?=[A-Za-z0-9_.:-]*\d)[A-Za-z0-9_.:-]*[A-Za-z0-9_]\b")


def _score_evidence_grounding(report_text: str) -> Tuple[float, int, int, int]:
    from a1.db import EndpointDatabase
    citations = list(dict.fromkeys(_CITATION_RE.findall(report_text)))
    cited_eids = [c for c in citations if not c.startswith("proc-")]
    cited_pids = [c for c in citations if c.startswith("proc-")]
    total_cited = len(cited_eids) + len(cited_pids)
    if total_cited == 0:
        return 0.0, 0, 0, 0

    def _exists(db, table: str, column: str, identifier: str) -> bool:
        candidates = [identifier]
        if identifier.startswith("evt-"):
            candidates.append(identifier[4:])
        for candidate in candidates:
            rows = db.execute_query(
                f"SELECT count(*) as c FROM {table} WHERE {column} = ?", (candidate,)
            )
            if rows and rows[0].get("c", 0) > 0:
                return True
        return False

    hallucinated = 0
    unverified = 0
    db = EndpointDatabase()
    for eid in cited_eids:
        try:
            if not _exists(db, "events", "event_id", eid):
                hallucinated += 1
        except Exception:
            unverified += 1
    for pid in cited_pids:
        try:
            # Process rows are materialized only for process-bearing events; a cited
            # process_entity_id that appears solely on events.* is still real telemetry.
            if not _exists(db, "processes", "process_entity_id", pid) and not _exists(
                db, "events", "process_entity_id", pid
            ):
                hallucinated += 1
        except Exception:
            unverified += 1
    valid = max(0, total_cited - hallucinated - unverified)
    return round(20.0 * valid / total_cited, 1), hallucinated, total_cited, unverified


def _score_confidence_calibration(final_state: dict, verdict_match: bool, boundary_match: bool, fallback_used: bool) -> Tuple[float, float, float]:
    confidence = final_state.get("confidence")
    try:
        confidence = float(confidence)
        if confidence > 1.0:
            confidence /= 100.0
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))
    outcome = 1.0 if verdict_match and not fallback_used else 0.0
    brier = (confidence - outcome) ** 2
    return round(10.0 * (1.0 - brier), 1), round(brier, 3), confidence


def _score_investigation_efficiency(final_state: dict, fallback_used: bool) -> float:
    repeat_nudges = final_state.get("repeat_nudges", 0)
    rep_pts = max(0.0, 3.0 - (repeat_nudges * 1.2))
    iter_count = final_state.get("iteration_count", 0)
    if iter_count <= 4:
        step_pts = 3.0
    elif iter_count <= 6:
        step_pts = 2.0
    else:
        step_pts = 1.0
    retry_pts = 2.0 if not fallback_used and not final_state.get("report_retry_used") else 0.5
    metrics = final_state.get("quality_metrics") or {}
    duplicates = int(metrics.get("duplicate_calls", 0) or 0)
    query_pts = 2.0 if duplicates == 0 else 1.0 if duplicates <= 2 else 0.0
    return round(rep_pts + step_pts + retry_pts + query_pts, 1)


def _score_report_quality(report_text: str) -> float:
    """Score report usefulness: timeline, grounded citations, caveats, actions."""
    has_timeline = "| Timestamp" in report_text or "Forensic Timeline Matrix" in report_text
    timeline_rows = len(re.findall(r"(?m)^\|\s*\d{4}-\d{2}-\d{2}", report_text))
    timeline_pts = 4.0 if has_timeline and timeline_rows >= 2 else 1.0 if has_timeline else 0.0
    citations = len(set(_CITATION_RE.findall(report_text)))
    citation_pts = 3.0 if citations >= 2 else 1.0 if citations == 1 else 0.0
    caveat_pts = 2.0 if ("Benign Explanation" in report_text or "Evidence Gap" in report_text) else 0.0
    action_pts = 3.0 if ("Next Steps" in report_text or "Remediation" in report_text or "Playbook" in report_text) else 0.0
    headings = len(re.findall(r"(?m)^#{2,3}\s+", report_text))
    structure_pts = 3.0 if len(report_text) >= 1000 and headings >= 3 else 1.0 if headings >= 2 else 0.0
    return round(timeline_pts + citation_pts + caveat_pts + action_pts + structure_pts, 1)


def _score_to_grade(score: float) -> str:
    if score >= 90:
        return "A+ (Exemplary)"
    if score >= 80:
        return "A (Superior)"
    if score >= 70:
        return "B (Acceptable)"
    if score >= 60:
        return "C (Deficient)"
    return "F (Unacceptable)"


def evaluate_case_rubric(case: dict, final_state: dict) -> dict:
    """Calculate the 100-point DFIR evaluation rubric score for an investigation case."""
    expected_label = case.get("case_label", "malicious").lower()
    expected_boundary = case.get("verdict_boundary", "confirmed_malicious").lower()
    evidence_basis = case.get("evidence_basis", [])

    agent_verdict = (final_state.get("verdict") or "unknown").lower()
    agent_boundary = (final_state.get("verdict_boundary") or "unknown").lower()
    fallback_used = bool(final_state.get("report_fallback_used"))

    verdict_pts = _score_verdict(agent_verdict, expected_label, agent_boundary, expected_boundary, fallback_used)
    report_text = _extract_report_text_from_state(final_state)
    memory = final_state.get("investigation_memory") or {}
    combined_evidence_text = (report_text + " " + json.dumps(memory, default=str)).lower()

    verdict_match = (agent_verdict == expected_label) and not fallback_used
    boundary_match = (_normalize_boundary(agent_boundary) == _normalize_boundary(expected_boundary)) and not fallback_used
    recall_pts, recall_pct = _score_evidence_recall(evidence_basis, combined_evidence_text)
    grounding_pts, hallucinated, total_cited, unverified = _score_evidence_grounding(report_text)
    calibration_pts, brier_score, confidence = _score_confidence_calibration(
        final_state, verdict_match, boundary_match, fallback_used
    )
    efficiency_pts = _score_investigation_efficiency(final_state, fallback_used)
    report_quality_pts = _score_report_quality(report_text)

    composite_score = round(verdict_pts + recall_pts + grounding_pts + calibration_pts + efficiency_pts + report_quality_pts, 1)
    grade = _score_to_grade(composite_score)

    is_fp = (expected_label in ("benign", "inconclusive")) and (agent_verdict in ("malicious", "suspicious"))
    is_fn = (expected_label == "malicious") and (agent_verdict in ("benign", "inconclusive"))
    supported = max(0, total_cited - hallucinated - unverified)
    ev_precision = round(supported / total_cited, 3) if total_cited > 0 else 0.0
    ev_recall = round(recall_pct, 3) if evidence_basis else 0.0
    ev_f1 = round((2 * ev_precision * ev_recall) / (ev_precision + ev_recall), 3) if (ev_precision + ev_recall) else 0.0
    iter_count = final_state.get("iteration_count", 0)
    repeat_nudges = final_state.get("repeat_nudges", 0)
    dup_query_rate = round(repeat_nudges / max(1, iter_count), 3)

    # Validation correctness & unverified evidence metrics (Issue #2, #3, #5)
    val_results = final_state.get("validation_results") or {}
    val_status = val_results.get("validation_status", "unknown")
    unverified_count = (
        len(val_results.get("event_ids_unverified", []))
        + len(val_results.get("process_ids_unverified", []))
        + len(val_results.get("hostnames_unverified", []))
    )

    # Relationship validation metrics (Issue #3, #5)
    rel_validations = val_results.get("relationship_validations", [])
    observed_rels = sum(1 for r in rel_validations if r.get("status") == "observed")
    total_rels = len(rel_validations)
    rel_correctness = round(observed_rels / total_rels, 3) if total_rels else 1.0

    # Dynamic hypothesis metrics (Issue #1, #5)
    tracker_data = final_state.get("hypothesis_tracker") or {}
    all_hypos = tracker_data.get("hypotheses", {})
    dynamic_hypos = [h for h in all_hypos.values() if h.get("source") == "dynamic"]
    dynamic_count = len(dynamic_hypos)

    # Investigation completeness (Issue #5)
    unresolved_hypos = [h for h in all_hypos.values() if h.get("status") in ("active", "unresolved")]
    completeness = round(1.0 - (len(unresolved_hypos) / max(1, len(all_hypos))), 3)

    return {
        "verdict_score": verdict_pts,
        "recall_score": recall_pts,
        "grounding_score": grounding_pts,
        "calibration_score": calibration_pts,
        "brier_score": brier_score,
        "confidence": confidence,
        "efficiency_score": efficiency_pts,
        "report_score": report_quality_pts,
        "composite_score": composite_score,
        "grade": grade,
        "hallucinated_citations": hallucinated,
        "total_citations": total_cited,
        "is_false_positive": is_fp,
        "is_false_negative": is_fn,
        "evidence_precision": ev_precision,
        "evidence_recall": ev_recall,
        "evidence_f1": ev_f1,
        "unverified_citations": unverified,
        "duplicate_query_rate": dup_query_rate,
        "unsupported_claims_count": hallucinated,
        "validation_status": val_status,
        "unverified_evidence_count": unverified_count,
        "relationship_correctness": rel_correctness,
        "dynamic_hypotheses_created": dynamic_count,
        "investigation_completeness": completeness,
        "unresolved_hypothesis_count": len(unresolved_hypos),
    }


DEV_SPLIT_CASES = ["ATK-A", "ATK-B", "ATK-C", "ATK-D", "ATK-E"]
EVAL_SPLIT_CASES = ["ATK-F", "ATK-G", "BEN-A", "AMB-A", "INC-A"]


def _filter_benchmark_scenarios(case_labels: list, split: Optional[str], limit: int) -> Tuple[list, dict]:
    labels_by_id = {c["case_id"]: c for c in case_labels}
    if split == "dev":
        allowed_cases = set(DEV_SPLIT_CASES)
    elif split == "eval":
        allowed_cases = set(EVAL_SPLIT_CASES)
    else:
        allowed_cases = set(BENCHMARK_CASES.keys())

    scenario_ids = [cid for cid in BENCHMARK_CASES if cid in labels_by_id and cid in allowed_cases][:limit]
    missing = [cid for cid in BENCHMARK_CASES if cid not in labels_by_id]
    if missing:
        print(f"[!] No case labels found for: {', '.join(missing)} -- skipping.")
    return scenario_ids, labels_by_id


def _execute_benchmark_case(app, case_id: str, case: dict, db_path: Optional[str] = None) -> dict:
    expected_label = case["case_label"]
    expected_boundary = case["verdict_boundary"]

    print(f"\n{'='*60}\nBenchmark: {case_id}\n{'='*60}")
    print(f"Expected: {expected_label} / {expected_boundary}")

    if not db_path:
        activate_case_database(BENCHMARK_CASES[case_id].get("database"))

    initial_state = {
        "messages": [],
        "hypotheses": [],
        "iteration_count": 0,
        "alert_context": BENCHMARK_PROMPTS[case_id],
    }
    final_state = app.invoke(initial_state)

    agent_verdict = (final_state.get("verdict") or "unknown").lower()
    agent_boundary = (final_state.get("verdict_boundary") or "unknown").lower()

    fallback_used = bool(final_state.get("report_fallback_used"))
    verdict_match = (agent_verdict == expected_label.lower()) and not fallback_used
    boundary_match = (_normalize_boundary(agent_boundary) == _normalize_boundary(expected_boundary)) and not fallback_used

    if fallback_used:
        print("  [!] Report generated via structured-output fallback -- counted as FAIL")

    rubric = evaluate_case_rubric(case, final_state)
    report_text = _extract_report_text_from_state(final_state)
    status = "PASS" if (verdict_match and boundary_match) else "FAIL"
    print(f"  Agent: {agent_verdict} / {agent_boundary} -> {status}")
    print(f"  Scorecard: {rubric['composite_score']}/100 [{rubric['grade']}]")
    print(f"    * Verdict & Boundary: {rubric['verdict_score']}/20")
    print(f"    * Evidence Recall:    {rubric['recall_score']}/25 (F1: {rubric['evidence_f1']:.1%})")
    print(f"    * Grounding/Anti-Hal: {rubric['grounding_score']}/20 (Hallucinations: {rubric['hallucinated_citations']}/{rubric['total_citations']}, Unverified: {rubric['unverified_citations']})")
    print(f"    * Confidence Calib:   {rubric['calibration_score']}/10 (Brier: {rubric['brier_score']:.3f})")
    print(f"    * Investigation Eff:  {rubric['efficiency_score']}/10")
    print(f"    * Report Quality:     {rubric['report_score']}/15")
    print(f"    * Validation Status:  {rubric['validation_status']} (Unverified: {rubric['unverified_evidence_count']})")
    print(f"    * Relationship Corr:  {rubric['relationship_correctness']:.1%} | Completeness: {rubric['investigation_completeness']:.1%} (Dynamic: {rubric['dynamic_hypotheses_created']})")

    return {
        "case_id": case_id,
        "expected_label": expected_label,
        "agent_verdict": agent_verdict,
        "verdict_match": verdict_match,
        "expected_boundary": expected_boundary,
        "agent_boundary": agent_boundary,
        "boundary_match": boundary_match,
        "fallback_used": fallback_used,
        "confidence": final_state.get("confidence"),
        "report_text": report_text,
        "rubric": rubric,
    }


def _compute_and_print_benchmark_summary(results: list) -> dict:
    total = len(results)
    verdict_acc = sum(r["verdict_match"] for r in results) / total if total else 0
    boundary_acc = sum(r["boundary_match"] for r in results) / total if total else 0
    fallback_count = sum(r["fallback_used"] for r in results)
    avg_score = sum(r["rubric"]["composite_score"] for r in results) / total if total else 0

    fps = sum(1 for r in results if r["rubric"].get("is_false_positive"))
    fns = sum(1 for r in results if r["rubric"].get("is_false_negative"))
    total_benign_inconclusive = sum(1 for r in results if r["expected_label"].lower() in ("benign", "inconclusive"))
    total_malicious = sum(1 for r in results if r["expected_label"].lower() == "malicious")
    fpr = (fps / total_benign_inconclusive) if total_benign_inconclusive else 0.0
    fnr = (fns / total_malicious) if total_malicious else 0.0
    avg_ev_precision = sum(r["rubric"].get("evidence_precision", 0.0) for r in results) / total if total else 0.0
    avg_ev_recall = sum(r["rubric"].get("evidence_recall", 1.0) for r in results) / total if total else 1.0
    avg_ev_f1 = sum(r["rubric"].get("evidence_f1", 0.0) for r in results) / total if total else 0.0
    avg_brier = sum(r["rubric"].get("brier_score", 0.25) for r in results) / total if total else 0.25
    avg_rel_correctness = sum(r["rubric"].get("relationship_correctness", 1.0) for r in results) / total if total else 1.0
    avg_completeness = sum(r["rubric"].get("investigation_completeness", 1.0) for r in results) / total if total else 1.0
    total_dynamic_hypos = sum(r["rubric"].get("dynamic_hypotheses_created", 0) for r in results)

    print(f"\n{'='*60}\nBenchmark Summary\n{'='*60}")
    print(f"Verdict accuracy:          {verdict_acc:.0%} ({sum(r['verdict_match'] for r in results)}/{total})")
    print(f"Verdict-boundary accuracy: {boundary_acc:.0%} ({sum(r['boundary_match'] for r in results)}/{total})")
    print(f"Average Rubric Score:      {avg_score:.1f}/100")
    print(f"False-Positive Rate:       {fpr:.1%}")
    print(f"False-Negative Rate:       {fnr:.1%}")
    print(f"Avg Evidence Precision:    {avg_ev_precision:.1%}")
    print(f"Avg Evidence Recall:       {avg_ev_recall:.1%}")
    print(f"Avg Evidence F1:           {avg_ev_f1:.1%}")
    print(f"Avg Confidence Brier:      {avg_brier:.3f}")
    print(f"Avg Relationship Corr:     {avg_rel_correctness:.1%}")
    print(f"Avg Inv. Completeness:     {avg_completeness:.1%}")
    print(f"Total Dynamic Hypotheses:  {total_dynamic_hypos}")
    print(f"Fallback runs (auto-FAIL):  {fallback_count}/{total}")

    return {
        "results": results,
        "verdict_accuracy": verdict_acc,
        "boundary_accuracy": boundary_acc,
        "average_rubric_score": avg_score,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "avg_evidence_precision": avg_ev_precision,
        "avg_evidence_recall": avg_ev_recall,
        "avg_evidence_f1": avg_ev_f1,
        "avg_confidence_brier": avg_brier,
        "avg_relationship_correctness": avg_rel_correctness,
        "avg_investigation_completeness": avg_completeness,
        "total_dynamic_hypotheses": total_dynamic_hypos,
        "fallback_count": fallback_count,
    }


def run_benchmark(
    limit: int = 5,
    provider: str = None,
    model: str = None,
    db_path: str = None,
    split: str = None,
    out_path: str = None,
) -> Dict[str, Any]:
    """Evaluate the LangGraph investigator agent against the shipped attack scenarios.

    Each case runs against the telemetry database its scenario lives in, unless
    ``db_path`` is given, in which case that single database is used for every case.
    ``split`` may be 'dev', 'eval', or 'all' to support train/eval separation (Issue #1).
    """
    from a1.llm import set_active_llm, get_active_llm_info
    if provider or model:
        set_active_llm(provider=provider, model=model)
    info = get_active_llm_info()
    print(f"[*] Benchmark running with LLM: Provider={info['provider']}, Model={info['model']}")

    empty_return = {"results": [], "verdict_accuracy": 0.0, "boundary_accuracy": 0.0, "fallback_count": 0}
    if db_path:
        try:
            active = cfg.set_active_database(db_path)
            print(f"[*] Benchmark pinned to database: {active.name}")
        except FileNotFoundError as e:
            print(f"[!] {e}")
            return empty_return

    try:
        case_labels = load_case_labels()
    except FileNotFoundError as e:
        print(f"[!] {e}")
        print("[!] Benchmark skipped: there are no labels to score against.")
        return empty_return

    scenario_ids, labels_by_id = _filter_benchmark_scenarios(case_labels, split, limit)
    if not scenario_ids:
        print("[!] No benchmark cases matched the supplied labels -- nothing to run.")
        return empty_return

    app = create_investigation_graph()
    results = [_execute_benchmark_case(app, cid, labels_by_id[cid], db_path) for cid in scenario_ids]
    summary = _compute_and_print_benchmark_summary(results)
    if out_path:
        Path(out_path).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Results written to: {out_path}")
    return summary

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run DFIR evaluation benchmark")
    parser.add_argument("--limit", "-l", type=int, default=5, help="Number of scenarios to test")
    parser.add_argument("--split", "-s", type=str, choices=["dev", "eval", "all"], default="all",
                        help="Scenario split: dev, eval, or all")
    parser.add_argument("--provider", "-p", type=str, choices=["ollama", "openai"], default=None, help="LLM provider")
    parser.add_argument("--model", "-m", type=str, default=None, help="LLM model name")
    parser.add_argument("--db", type=str, default=None,
                        help="Pin every case to one SQLite telemetry database instead of switching per scenario")
    parser.add_argument("--out", type=str, default=None, help="Write full results (including reports) as JSON")
    args = parser.parse_args()
    run_benchmark(limit=args.limit, provider=args.provider, model=args.model, db_path=args.db, split=args.split, out_path=args.out)
