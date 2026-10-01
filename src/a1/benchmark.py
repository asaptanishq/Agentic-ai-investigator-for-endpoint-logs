import json
import re
from pathlib import Path
import sys
from typing import Dict, Any

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


def _labels_from_groundtruth_files() -> list:
    """Build ``case_labels.json``-shaped labels from shipped groundtruth files."""
    labels: list = []
    # Search groundtruth subfolder first, then dataset root
    gt_dir = Path(DATASET_DIR) / "groundtruth"
    gt_files = sorted(gt_dir.glob("groundtruth_*.json")) if gt_dir.is_dir() else []
    if not gt_files:
        gt_files = sorted(Path(DATASET_DIR).glob("groundtruth_*.json"))
    for gt_path in gt_files:
        try:
            with open(gt_path, encoding="utf-8") as f:
                gt = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        # Dynamically extract canonical case_id from filename (attack_A -> ATK-A) or JSON
        case_match = re.search(r"attack_([A-Za-z0-9]+)", gt_path.name, re.IGNORECASE)
        if case_match:
            case_id = f"ATK-{case_match.group(1).upper()}"
        elif gt.get("case_id"):
            case_id = str(gt["case_id"])
        else:
            dataset = gt.get("dataset", "")
            if "lateral" in dataset:
                case_id = "ATK-A"
            elif "exfiltration" in dataset:
                case_id = "ATK-B"
            elif "ransomware" in dataset:
                case_id = "ATK-C"
            elif "lotl" in dataset:
                case_id = "ATK-D"
            elif "wazuh" in dataset:
                case_id = "ATK-E"
            elif "suricata" in dataset:
                case_id = "ATK-F"
            elif "supply_chain" in dataset:
                case_id = "ATK-G"
            else:
                case_id = gt_path.stem

        labels.append({
            "case_id": case_id,
            "prompt": BENCHMARK_PROMPTS.get(case_id, gt.get("summary", "")),
            "case_label": gt.get("expected_verdict", "malicious"),
            "verdict_boundary": gt.get("verdict_boundary", "confirmed_malicious"),
            "confidence": "high",
            "evidence_basis": gt.get("evidence_basis", []),
        })

    # Sort naturally by case_id (ATK-A, ATK-B, ..., ATK-G)
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

def evaluate_case_rubric(case: dict, final_state: dict) -> dict:
    """Calculate the 100-point DFIR evaluation rubric score for an investigation case."""
    expected_label = case.get("case_label", "malicious").lower()
    expected_boundary = case.get("verdict_boundary", "confirmed_malicious").lower()
    evidence_basis = case.get("evidence_basis", [])
    
    agent_verdict = (final_state.get("verdict") or "unknown").lower()
    agent_boundary = (final_state.get("verdict_boundary") or "unknown").lower()
    fallback_used = bool(final_state.get("report_fallback_used"))
    
    # 1. Verdict & Boundary Precision (20 pts)
    verdict_pts = 0.0
    if not fallback_used:
        if agent_verdict == expected_label:
            verdict_pts += 15.0
        if agent_boundary == expected_boundary:
            verdict_pts += 5.0

    # Extract report text
    report_text = ""
    messages = final_state.get("messages") or []
    for m in reversed(messages):
        content = getattr(m, "content", "")
        if "## Verdict" in content or "# DFIR" in content or "Executive Summary" in content:
            report_text = content
            break
    if not report_text and messages:
        report_text = str(getattr(messages[-1], "content", ""))

    memory = final_state.get("investigation_memory") or {}
    combined_evidence_text = (report_text + " " + json.dumps(memory, default=str)).lower()

    # 2. Evidence Retrieval / Recall (30 pts)
    if evidence_basis:
        matched_indicators = 0
        for item in evidence_basis:
            terms = [t.lower() for t in re.findall(r"\b[a-zA-Z0-9_.-]{3,}\b", str(item))
                     if t.lower() not in ("the", "and", "for", "with", "from", "that", "this", "via", "was")]
            if terms and any(term in combined_evidence_text for term in terms):
                matched_indicators += 1
        recall_pct = matched_indicators / len(evidence_basis) if evidence_basis else 1.0
        recall_pts = round(30.0 * recall_pct, 1)
    else:
        recall_pts = 30.0

    # 3. Evidence Grounding & Zero-Hallucination Rate (25 pts)
    from a1.db import EndpointDatabase
    cited_eids = list(dict.fromkeys(re.findall(r"\bevt-[a-zA-Z0-9_-]+\b", report_text)))
    cited_pids = list(dict.fromkeys(re.findall(r"\bproc-[a-zA-Z0-9_-]+\b", report_text)))
    
    hallucinated = 0
    total_cited = len(cited_eids) + len(cited_pids)
    if total_cited > 0:
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
        grounding_pts = round(25.0 * grounding_ratio, 1)
    else:
        grounding_pts = 15.0

    # 4. Investigation Efficiency & Reasoning Quality (15 pts)
    repeat_nudges = final_state.get("repeat_nudges", 0)
    rep_pts = max(0.0, 5.0 - (repeat_nudges * 2.5))
    iter_count = final_state.get("iteration_count", 0)
    step_pts = 5.0 if iter_count <= 4 else (3.0 if iter_count == 5 else 1.0)
    retry_pts = 5.0 if not fallback_used and not final_state.get("report_retry_used") else 2.0
    efficiency_pts = round(rep_pts + step_pts + retry_pts, 1)

    # 5. Executive Report Actionability (10 pts)
    timeline_pts = 4.0 if ("Forensic Timeline Matrix" in report_text or "| Timestamp" in report_text) else 1.0
    ioc_pts = 3.0 if ("Indicator" in report_text or "IOC" in report_text) else 1.0
    action_pts = 3.0 if ("Next Steps" in report_text or "Remediation" in report_text or "Playbook" in report_text) else 1.0
    report_quality_pts = round(timeline_pts + ioc_pts + action_pts, 1)

    composite_score = round(verdict_pts + recall_pts + grounding_pts + efficiency_pts + report_quality_pts, 1)
    
    if composite_score >= 90:
        grade = "A+ (Exemplary)"
    elif composite_score >= 80:
        grade = "A (Superior)"
    elif composite_score >= 70:
        grade = "B (Acceptable)"
    elif composite_score >= 60:
        grade = "C (Deficient)"
    else:
        grade = "F (Unacceptable)"

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
    }


def run_benchmark(limit: int = 5, provider: str = None, model: str = None, db_path: str = None) -> Dict[str, Any]:
    """Evaluate the LangGraph investigator agent against the shipped attack scenarios.

    Each case runs against the telemetry database its scenario lives in, unless
    ``db_path`` is given, in which case that single database is used for every case.
    """
    from a1.llm import set_active_llm, get_active_llm_info
    if provider or model:
        set_active_llm(provider=provider, model=model)
    info = get_active_llm_info()
    print(f"[*] Benchmark running with LLM: Provider={info['provider']}, Model={info['model']}")

    if db_path:
        try:
            active = cfg.set_active_database(db_path)
            print(f"[*] Benchmark pinned to database: {active.name}")
        except FileNotFoundError as e:
            print(f"[!] {e}")
            return {"results": [], "verdict_accuracy": 0.0, "boundary_accuracy": 0.0, "fallback_count": 0}

    try:
        case_labels = load_case_labels()
    except FileNotFoundError as e:
        print(f"[!] {e}")
        print("[!] Benchmark skipped: there are no labels to score against.")
        return {"results": [], "verdict_accuracy": 0.0, "boundary_accuracy": 0.0, "fallback_count": 0}

    # Match scenarios to labels by case_id.
    labels_by_id = {c["case_id"]: c for c in case_labels}
    scenario_ids = [cid for cid in BENCHMARK_CASES if cid in labels_by_id][:limit]
    missing = [cid for cid in BENCHMARK_CASES if cid not in labels_by_id]
    if missing:
        print(f"[!] No case labels found for: {', '.join(missing)} -- skipping.")

    if not scenario_ids:
        print("[!] No benchmark cases matched the supplied labels -- nothing to run.")
        return {"results": [], "verdict_accuracy": 0.0, "boundary_accuracy": 0.0, "fallback_count": 0}

    app = create_investigation_graph()
    results = []

    for case_id in scenario_ids:
        case = labels_by_id[case_id]
        expected_label = case["case_label"]
        expected_boundary = case["verdict_boundary"]

        print(f"\n{'='*60}\nBenchmark: {case_id}\n{'='*60}")
        print(f"Expected: {expected_label} / {expected_boundary}")

        # Each scenario lives in its own telemetry database unless pinned.
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

        # Evaluate 100-point rubric
        rubric = evaluate_case_rubric(case, final_state)

        results.append({
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
        })

        status = "PASS" if (verdict_match and boundary_match) else "FAIL"
        print(f"  Agent: {agent_verdict} / {agent_boundary} -> {status}")
        print(f"  Scorecard: {rubric['composite_score']}/100 [{rubric['grade']}]")
        print(f"    * Verdict & Boundary: {rubric['verdict_score']}/20")
        print(f"    * Evidence Recall:    {rubric['recall_score']}/30")
        print(f"    * Grounding/Anti-Hal: {rubric['grounding_score']}/25 (Hallucinations: {rubric['hallucinated_citations']}/{rubric['total_citations']})")
        print(f"    * Investigation Eff:  {rubric['efficiency_score']}/15")
        print(f"    * Report Quality:     {rubric['report_score']}/10")

    total = len(results)
    verdict_acc = sum(r["verdict_match"] for r in results) / total if total else 0
    boundary_acc = sum(r["boundary_match"] for r in results) / total if total else 0
    fallback_count = sum(r["fallback_used"] for r in results)
    avg_score = sum(r["rubric"]["composite_score"] for r in results) / total if total else 0

    print(f"\n{'='*60}\nBenchmark Summary\n{'='*60}")
    print(f"Verdict accuracy:          {verdict_acc:.0%} ({sum(r['verdict_match'] for r in results)}/{total})")
    print(f"Verdict-boundary accuracy: {boundary_acc:.0%} ({sum(r['boundary_match'] for r in results)}/{total})")
    print(f"Average Rubric Score:      {avg_score:.1f}/100")
    print(f"Fallback runs (auto-FAIL):  {fallback_count}/{total}")

    return {
        "results": results,
        "verdict_accuracy": verdict_acc,
        "boundary_accuracy": boundary_acc,
        "average_rubric_score": avg_score,
        "fallback_count": fallback_count,
    }

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run DFIR evaluation benchmark")
    parser.add_argument("--limit", "-l", type=int, default=5, help="Number of scenarios to test")
    parser.add_argument("--provider", "-p", type=str, choices=["ollama", "openai"], default=None, help="LLM provider")
    parser.add_argument("--model", "-m", type=str, default=None, help="LLM model name")
    parser.add_argument("--db", type=str, default=None,
                        help="Pin every case to one SQLite telemetry database instead of switching per scenario")
    args = parser.parse_args()
    run_benchmark(limit=args.limit, provider=args.provider, model=args.model, db_path=args.db)
