import json
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
}

# Case id -> prompt, kept as a flat mapping for existing tooling/tests.
BENCHMARK_PROMPTS = {case_id: case["prompt"] for case_id, case in BENCHMARK_CASES.items()}

def load_case_labels() -> list:
    """Load per-case evaluation labels.

    Prefers the evaluator-only ``case_labels.json`` when it exists (original
    five-scenario bundle layout). Otherwise derives equivalent labels from the
    shipped ``groundtruth_attack_*.json`` files, so the benchmark runs against
    the two attack databases that actually ship with this repository.
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
    for gt_path in sorted(Path(DATASET_DIR).glob("groundtruth_*.json")):
        try:
            with open(gt_path, encoding="utf-8") as f:
                gt = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        dataset = gt.get("dataset", "")
        if "lateral" in dataset:
            case_id = "ATK-A"
        elif "exfiltration" in dataset:
            case_id = "ATK-B"
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
    # Keep canonical ATK-A / ATK-B ordering.
    order = {"ATK-A": 0, "ATK-B": 1}
    labels.sort(key=lambda item: order.get(item.get("case_id"), 99))
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
        # The shipped case_labels.json uses "case_label" / "verdict_boundary".
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

        # FIX: a run that fell back to the hardcoded report verdict is counted
        # as a failure. Previously the fallback's "suspicious" verdict could
        # accidentally pass suspicious-labeled cases, inflating accuracy.
        fallback_used = bool(final_state.get("report_fallback_used"))
        verdict_match = (agent_verdict == expected_label.lower()) and not fallback_used
        boundary_match = (agent_boundary == expected_boundary.lower()) and not fallback_used

        if fallback_used:
            print("  [!] Report generated via structured-output fallback -- counted as FAIL")

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
        })

        status = "PASS" if (verdict_match and boundary_match) else "FAIL"
        print(f"  Agent: {agent_verdict} / {agent_boundary} -> {status}")

    total = len(results)
    verdict_acc = sum(r["verdict_match"] for r in results) / total if total else 0
    boundary_acc = sum(r["boundary_match"] for r in results) / total if total else 0
    fallback_count = sum(r["fallback_used"] for r in results)

    print(f"\n{'='*60}\nBenchmark Summary\n{'='*60}")
    print(f"Verdict accuracy:          {verdict_acc:.0%} ({sum(r['verdict_match'] for r in results)}/{total})")
    print(f"Verdict-boundary accuracy: {boundary_acc:.0%} ({sum(r['boundary_match'] for r in results)}/{total})")
    print(f"Fallback runs (auto-FAIL):  {fallback_count}/{total}")

    distinct_expected = {r["expected_label"] for r in results}
    if len(distinct_expected) == 1:
        print(f"[!] All {total} expected labels are '{next(iter(distinct_expected))}': this measures whether a "
              "real attack chain gets found, not benign-vs-malicious discrimination.")

    return {
        "results": results,
        "verdict_accuracy": verdict_acc,
        "boundary_accuracy": boundary_acc,
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
