"""CLI for running single DFIR investigations."""
import argparse
import json
import sys

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
from a1.config import MAX_INVESTIGATION_STEPS
from a1.tools import summarize_tool_output

def run_investigation(alert: str, verbose: bool = False):
    app = create_investigation_graph()

    initial_state = {
        "messages": [],
        "hypotheses": [],
        "iteration_count": 0,
        "alert_context": alert,
    }

    print(f"\n{'='*70}", flush=True)
    print(f"INVESTIGATING: {alert[:100]}", flush=True)
    print(f"{'='*70}\n", flush=True)

    step_num = 0
    final_state = None
    alert_prep_printed = False
    triage_printed = False
    evidence_pack_printed = False
    last_iteration = 0
    processed_msg_count = 0

    from a1.llm import get_active_llm_info
    llm_info = get_active_llm_info()
    print(f"[*] Active LLM: Provider={llm_info['provider']}, Model={llm_info['model']}\n", flush=True)

    for event in app.stream(initial_state, stream_mode="values"):
        final_state = event

        # Display Alert Prep results
        enriched = event.get("enriched_alert")
        if enriched and not alert_prep_printed:
            print("[ALERT PREP] Deterministic Input Reflection Complete:", flush=True)
            ents = enriched.get("entities", {})
            print(f"  Canonical Host IDs: {', '.join(ents.get('host_ids', [])) or 'None'}", flush=True)
            if ents.get("resolved_hosts"):
                print(f"  Resolved Hostnames: {json.dumps(ents['resolved_hosts'])}", flush=True)
            tw = enriched.get("time_window", {})
            print(f"  Time Window: {tw.get('start_time')} -> {tw.get('end_time')} (defaulted: {tw.get('is_default')})", flush=True)
            if enriched.get("missing"):
                print(f"  Recorded Missing Indicators: {', '.join(enriched['missing'])}", flush=True)
            print(flush=True)
            alert_prep_printed = True

        # Display Triage Plan and Hypotheses once gathered
        hypos = event.get("hypotheses", [])
        if hypos and not triage_printed:
            print("[TRIAGE] Initial Hypotheses Gathered:", flush=True)
            for i, h in enumerate(hypos, 1):
                print(f"  H{i}: {h}", flush=True)
            # If the initial triage message has plan details, print it
            for m in event.get("messages", []):
                if getattr(m, "type", "") == "human" and "Plan:" in getattr(m, "content", ""):
                    lines = [ln for ln in m.content.splitlines() if ln.startswith(("Plan:", "Initial entities:"))]
                    for ln in lines:
                        print(f"  {ln}", flush=True)
                    break
            print(flush=True)
            triage_printed = True

        iteration = event.get("iteration_count", 0)
        active_hypo = event.get("active_hypothesis")

        # Display Loop transition and active hypothesis being investigated
        if iteration > last_iteration:
            print(f"\n>>> [Investigation Loop {iteration}/{MAX_INVESTIGATION_STEPS}]", flush=True)
            if active_hypo:
                print(f"    Target Hypothesis: {active_hypo}", flush=True)
            if hypos:
                print(f"    Passing Hypotheses to Loop {iteration}: {len(hypos)} under evaluation", flush=True)
            last_iteration = iteration

        # Display Evidence Pack status
        pack = event.get("evidence_pack")
        if pack and not evidence_pack_printed:
            print("[EVIDENCE PACK] Input Reflection Pack Ready for Correlation & Report:", flush=True)
            print(f"  Total Kept Telemetry Events: {pack.get('total_kept_events')}", flush=True)
            print(f"  Chronological Timeline Items: {len(pack.get('timeline', []))}", flush=True)
            print(f"  Excluded/Filtered Rows: {pack.get('excluded_row_count')}", flush=True)
            hypo_cov = pack.get("hypotheses_evidence", {})
            for h, info in hypo_cov.items():
                print(f"    - {h[:60]}... => {info.get('status')} ({info.get('event_count', 0)} events)", flush=True)
            print(flush=True)
            evidence_pack_printed = True

        messages = event.get("messages", [])
        if len(messages) > processed_msg_count:
            new_msgs = messages[processed_msg_count:]
            processed_msg_count = len(messages)

            for msg in new_msgs:
                msg_type = getattr(msg, "type", "unknown")
                if msg_type == "ai":
                    # Check for dedicated reasoning_content (e.g. from DeepSeek-R1 / QwQ)
                    add_kwargs = getattr(msg, "additional_kwargs", {}) or {}
                    reasoning_content = (
                        add_kwargs.get("reasoning_content")
                        or getattr(msg, "reasoning_content", None)
                        or ""
                    )
                    text_content = str(getattr(msg, "content", "") or "").strip()

                    if reasoning_content:
                        print(f"[Agent Thinking]\n{reasoning_content}\n", flush=True)

                    if text_content and text_content != reasoning_content:
                        # Print the agent's textual thought process and hypothesis reasoning
                        print(f"[Reasoning] {text_content}", flush=True)

                    tool_calls = getattr(msg, "tool_calls", None) or []
                    if tool_calls:
                        for tc in tool_calls:
                            step_num += 1
                            args_str = json.dumps(tc.get("args") or {})
                            if not verbose and len(args_str) > 160:
                                args_str = args_str[:157] + "..."
                            print(f"[Step {step_num}] Tool: {tc.get('name')}({args_str})", flush=True)

                elif msg_type == "tool":
                    tool_name = getattr(msg, "name", "tool")
                    summary = summarize_tool_output(str(getattr(msg, "content", "")))
                    print(f"  -> {tool_name}: {summary}", flush=True)

    print(f"\n{'='*70}", flush=True)
    print("INVESTIGATION COMPLETE", flush=True)
    print(f"{'='*70}", flush=True)
    if final_state:
        print(f"Verdict: {final_state.get('verdict')} ({final_state.get('verdict_boundary')})", flush=True)
        print(f"Confidence: {final_state.get('confidence')}", flush=True)
        if final_state.get("report_fallback_used"):
            print("[!] Report was generated via fallback -- manual review required.", flush=True)
        if final_state.get("hypotheses"):
            print("\n[Triage Hypotheses Evaluated]:", flush=True)
            for i, h in enumerate(final_state.get("hypotheses", []), 1):
                print(f"  - H{i}: {h}", flush=True)
        report_msgs = [m for m in final_state.get("messages", []) if getattr(m, "type", "") == "human"]
        if report_msgs:
            print(f"\n{report_msgs[-1].content}", flush=True)

def main():
    parser = argparse.ArgumentParser(description="Agentic AI DFIR Investigator")
    parser.add_argument("alert", nargs="*", help="Alert or investigation prompt (e.g. 'Investigate host-001...')")
    parser.add_argument("--query", "-q", type=str, default=None, help="Alternative flag to supply the investigation prompt")
    parser.add_argument("--provider", "-p", type=str, choices=["ollama", "openai"], default=None, help="Select LLM provider ('ollama' or 'openai')")
    parser.add_argument("--model", "-m", type=str, default=None, help="Select LLM model name (e.g. 'llama3.1', 'gemma4:31b', 'gpt-4o')")
    parser.add_argument("--select-llm", action="store_true", help="Interactively select LLM provider and model")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show agent reasoning")
    parser.add_argument("--benchmark", action="store_true", help="Run evaluation benchmark")
    parser.add_argument("--limit", type=int, default=5, help="Benchmark case limit")
    parser.add_argument("--db", type=str, default=None, help="Path to custom SQLite telemetry database")
    parser.add_argument("--web", action="store_true", help="Launch the ChatGPT-style Web Interface")
    parser.add_argument("--port", type=int, default=8000, help="Port for the web server (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the browser on web launch")
    args = parser.parse_args()

    # Launch web interface if requested or if 'web' subcommand was passed
    raw_tokens = list(args.alert or [])
    if args.web or (raw_tokens and raw_tokens[0].lower() == "web"):
        from a1.web.server import start
        start(port=args.port, open_browser=not args.no_browser)
        return

    # Handle interactive LLM selection
    from a1.llm import set_active_llm, get_active_llm_info
    if args.select_llm:
        print("\n--- LLM Configuration ---")
        curr_info = get_active_llm_info()
        print(f"Current default: Provider={curr_info['provider']}, Model={curr_info['model']}")
        chosen_p = input(f"Enter provider [ollama/openai] (default: {curr_info['provider']}): ").strip().lower() or curr_info["provider"]
        chosen_m = input(f"Enter model name (default: {curr_info['model']}): ").strip() or curr_info["model"]
        set_active_llm(provider=chosen_p, model=chosen_m)
        print(f"[+] Active LLM set to: Provider={chosen_p}, Model={chosen_m}\n")
    elif args.provider or args.model:
        set_active_llm(provider=args.provider, model=args.model)
        active = get_active_llm_info()
        print(f"[*] Configured LLM: Provider={active['provider']}, Model={active['model']}")

    # Handle database selection (--db): delegate to the shared
    # config helper so CLI, web and benchmark switch databases identically.
    if args.db:
        from pathlib import Path
        import a1.config as cfg
        db_path = Path(args.db).resolve()

        try:
            active = cfg.set_active_database(db_path)
        except FileNotFoundError:
            print(f"[!] Specified database not found: {db_path}", flush=True)
            return

        print(f"[*] Using database: {active.name}", flush=True)

    # Handle optional 'investigate' subcommand or positional tokens
    raw_tokens = list(args.alert or [])
    if raw_tokens and raw_tokens[0].lower() == "investigate":
        raw_tokens.pop(0)

    alert_text = args.query or (" ".join(raw_tokens).strip() if raw_tokens else None)

    if args.benchmark:
        from a1.benchmark import run_benchmark
        run_benchmark(limit=args.limit)
    elif alert_text:
        run_investigation(alert_text, verbose=args.verbose)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
