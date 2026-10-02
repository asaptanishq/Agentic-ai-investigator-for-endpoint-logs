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
# NOTE on scoring honesty: both shipped scenarios expect "malicious", so a model
# that answers "malicious" every time scores 100% on verdicts. The dataset ships
# no benign-scenario database, so this benchmark measures whether an
# investigation can *find* a real attack chain (and whether it fell back), not
# whether it can rule one out. Report it that way.
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

def _score_verdict(agent_verdict: str, expected_label: str, agent_boundary: str, expected_boundary: str, fallback_used: bool) -> float:
    if fallback_used:
        return 0.0
    pts = 0.0
    if agent_verdict == expected_label:
        pts += 15.0
    if agent_boundary == expected_boundary:
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


def _score_evidence_recall(evidence_basis: list, combined_evidence_text: str) -> Tuple[float, float]:
    if not evidence_basis:
        return 30.0, 1.0
    matched_indicators = 0
    stopwords = {"the", "and", "for", "with", "from", "that", "this", "via", "was"}
    for item in evidence_basis:
        terms = [t.lower() for t in re.findall(r"\b[a-zA-Z0-9_.-]{3,}\b", str(item)) if t.lower() not in stopwords]
        if terms and any(term in combined_evidence_text for term in terms):
            matched_indicators += 1
    recall_pct = matched_indicators / len(evidence_basis)
    return round(30.0 * recall_pct, 1), recall_pct


def _score_evidence_grounding(report_text: str) -> Tuple[float, int, int]:
    from a1.db import EndpointDatabase
    cited_eids = list(dict.fromkeys(re.findall(r"\bevt-[a-zA-Z0-9_-]+\b", report_text)))
    cited_pids = list(dict.fromkeys(re.findall(r"\bproc-[a-zA-Z0-9_-]+\b", report_text)))
    total_cited = len(cited_eids) + len(cited_pids)
    if total_cited == 0:
        return 15.0, 0, 0

    hallucinated = 0
    db = EndpointDatabase()
    for eid in cited_eids:
        try:
            cnt = db.execute_query("SELECT count(*) as c FROM events WHERE event_id = ?", (eid,))
            if not cnt or cnt[0].get("c", 0) == 0:
                hallucinated += 1
        except Exception:
            pass
    for pid in cited_pids:
        try:
            cnt = db.execute_query("SELECT count(*) as c FROM processes WHERE process_entity_id = ?", (pid,))
            if not cnt or cnt[0].get("c", 0) == 0:
                hallucinated += 1
        except Exception:
            pass
    grounding_ratio = max(0.0, 1.0 - (hallucinated / total_cited))
    return round(25.0 * grounding_ratio, 1), hallucinated, total_cited


def _score_investigation_efficiency(final_state: dict, fallback_used: bool) -> float:
    repeat_nudges = final_state.get("repeat_nudges", 0)
    rep_pts = max(0.0, 5.0 - (repeat_nudges * 2.5))
    iter_count = final_state.get("iteration_count", 0)
    if iter_count <= 4:
        step_pts = 5.0
    elif iter_count == 5:
        step_pts = 3.0
    else:
        step_pts = 1.0
    retry_pts = 5.0 if not fallback_used and not final_state.get("report_retry_used") else 2.0
    return round(rep_pts + step_pts + retry_pts, 1)


def _score_report_quality(report_text: str) -> float:
    timeline_pts = 4.0 if ("Forensic Timeline Matrix" in report_text or "| Timestamp" in report_text) else 1.0
    ioc_pts = 3.0 if ("Indicator" in report_text or "IOC" in report_text) else 1.0
    action_pts = 3.0 if ("Next Steps" in report_text or "Remediation" in report_text or "Playbook" in report_text) else 1.0
    return round(timeline_pts + ioc_pts + action_pts, 1)


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

    recall_pts, recall_pct = _score_evidence_recall(evidence_basis, combined_evidence_text)
    grounding_pts, hallucinated, total_cited = _score_evidence_grounding(report_text)
    efficiency_pts = _score_investigation_efficiency(final_state, fallback_used)
    report_quality_pts = _score_report_quality(report_text)

    composite_score = round(verdict_pts + recall_pts + grounding_pts + efficiency_pts + report_quality_pts, 1)
    grade = _score_to_grade(composite_score)

    is_fp = (expected_label in ("benign", "inconclusive")) and (agent_verdict in ("malicious", "suspicious"))
    is_fn = (expected_label == "malicious") and (agent_verdict in ("benign", "inconclusive"))
    ev_precision = round((total_cited - hallucinated) / total_cited, 3) if total_cited > 0 else 1.0
    ev_recall = round(recall_pct, 3) if evidence_basis else 1.0
    iter_count = final_state.get("iteration_count", 0)
    repeat_nudges = final_state.get("repeat_nudges", 0)
    dup_query_rate = round(repeat_nudges / max(1, iter_count), 3)

    return {
        "verdict_score": verdict_pts,
        "recall_score": recall_pts,
        "grounding_score": grounding_pts,
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
        "duplicate_query_rate": dup_query_rate,
        "unsupported_claims_count": hallucinated,
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
    boundary_match = (agent_boundary == expected_boundary.lower()) and not fallback_used

    if fallback_used:
        print("  [!] Report generated via structured-output fallback -- counted as FAIL")

    rubric = evaluate_case_rubric(case, final_state)
    status = "PASS" if (verdict_match and boundary_match) else "FAIL"
    print(f"  Agent: {agent_verdict} / {agent_boundary} -> {status}")
    print(f"  Scorecard: {rubric['composite_score']}/100 [{rubric['grade']}]")
    print(f"    * Verdict & Boundary: {rubric['verdict_score']}/20")
    print(f"    * Evidence Recall:    {rubric['recall_score']}/30")
    print(f"    * Grounding/Anti-Hal: {rubric['grounding_score']}/25 (Hallucinations: {rubric['hallucinated_citations']}/{rubric['total_citations']})")
    print(f"    * Investigation Eff:  {rubric['efficiency_score']}/15")
    print(f"    * Report Quality:     {rubric['report_score']}/10")

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
    avg_ev_precision = sum(r["rubric"].get("evidence_precision", 1.0) for r in results) / total if total else 1.0
    avg_ev_recall = sum(r["rubric"].get("evidence_recall", 1.0) for r in results) / total if total else 1.0

    print(f"\n{'='*60}\nBenchmark Summary\n{'='*60}")
    print(f"Verdict accuracy:          {verdict_acc:.0%} ({sum(r['verdict_match'] for r in results)}/{total})")
    print(f"Verdict-boundary accuracy: {boundary_acc:.0%} ({sum(r['boundary_match'] for r in results)}/{total})")
    print(f"Average Rubric Score:      {avg_score:.1f}/100")
    print(f"False-Positive Rate:       {fpr:.1%}")
    print(f"False-Negative Rate:       {fnr:.1%}")
    print(f"Avg Evidence Precision:    {avg_ev_precision:.1%}")
    print(f"Avg Evidence Recall:       {avg_ev_recall:.1%}")
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
        "fallback_count": fallback_count,
    }


def run_benchmark(
    limit: int = 5,
    provider: str = None,
    model: str = None,
    db_path: str = None,
    split: str = None,
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
    return _compute_and_print_benchmark_summary(results)

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
    args = parser.parse_args()
    run_benchmark(limit=args.limit, provider=args.provider, model=args.model, db_path=args.db, split=args.split)
