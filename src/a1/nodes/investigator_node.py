import json
import re
from langchain_core.messages import SystemMessage, AIMessage, HumanMessage
from a1.llm import get_llm
from a1.tools import ALL_INVESTIGATION_TOOLS
from a1.prompts import INVESTIGATOR_SYSTEM_PROMPT
from a1.config import MAX_INVESTIGATION_STEPS
# FIX: minimum reasoning passes before a tool-free conclusion is allowed.
# Previously the agent could return plain text on step 1 (zero tool calls) and
# jump straight to correlation/report with no evidence collected.
MIN_INVESTIGATION_STEPS = 2
# FIX: circuit breaker for repeat loops. After this many "you already tried
# that" nudges, stop looping and force the investigation to correlation.
MAX_REPEAT_NUDGES = 2
# FIX: prefix marking nudge messages this node injects (distinguishes them from
# the user's own messages in should_continue).
_NUDGE_PREFIX = "[SYSTEM-NOTE: repeated tool call]"

_SCHEMA_HINT_CACHE = {}


def _get_schema_hint() -> str:
    """Compact one-line-per-table schema, fetched once and cached per database.

    FIX: the old prompt told the model to call get_database_schema first, but
    models routinely skipped it and then queried nonexistent columns
    (e.g. `events.process_name` -- process_name lives on `processes`), burning
    steps on SQL errors. Injecting the real schema into the system prompt
    removes that wasted round trip.
    """
    from a1.config import get_db_path
    try:
        db_key = str(get_db_path().resolve())
    except Exception:
        db_key = "default"

    if db_key not in _SCHEMA_HINT_CACHE:
        try:
            from a1.db import EndpointDatabase
            schema = EndpointDatabase().get_schema()
            lines = [f"  {t}({', '.join(cols)})" for t, cols in sorted(schema.items())]
            _SCHEMA_HINT_CACHE[db_key] = (
                "DATABASE SCHEMA -- use exactly these table and column names, "
                "never guess column names:\n" + "\n".join(lines)
            )
        except Exception as e:
            _SCHEMA_HINT_CACHE[db_key] = f"(schema unavailable: {e})"
    return _SCHEMA_HINT_CACHE[db_key]



def _call_key(tool_call) -> tuple:
    # FIX: canonical key for repeat detection -- arg order and JSON spacing
    # must not matter.
    return (
        tool_call.get("name"),
        json.dumps(tool_call.get("args") or {}, sort_keys=True, default=str),
    )


def _missing_smb_auth_correlation(messages):
    rows = []
    for message in messages:
        if getattr(message, "type", "") != "tool":
            continue
        try:
            payload = json.loads(getattr(message, "content", ""))
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(payload, list):
            rows.extend(row for row in payload if isinstance(row, dict))
        elif isinstance(payload, dict):
            for key in ("matches", "events", "network_connections", "files", "registry_events"):
                value = payload.get(key)
                if isinstance(value, list):
                    rows.extend(row for row in value if isinstance(row, dict))

    aliases = {
        "source.ip": "source_ip",
        "destination.ip": "destination_ip",
        "destination.port": "destination_port",
        "authentication.package": "authentication_package",
        "logon.type": "logon_type",
        "user.name": "user_name",
        "user.domain": "user_domain",
    }
    normalized = []
    for row in rows:
        details = row.get("details", {})
        projected = row.get("raw_json_projected", {})
        if not isinstance(details, dict):
            details = {}
        if not isinstance(projected, dict):
            projected = {}
        fields = {aliases.get(key, key): value for key, value in projected.items()}
        fields.update(row)
        fields.update(details)
        normalized.append({
            "fields": fields,
            "action": str(row.get("action", "")).lower(),
            "host_id": str(row.get("host_id") or ""),
            "timestamp": str(row.get("timestamp") or ""),
        })

    def field(record, key):
        value = record["fields"].get(key)
        return str(value) if value not in (None, "") else ""

    failures = [record for record in normalized if (
        record["action"] == "logon_failed"
        and field(record, "authentication_package").casefold() == "ntlm"
        and field(record, "logon_type") == "3"
        and field(record, "source_ip")
        and field(record, "destination_ip")
        and field(record, "user_name")
    )]
    successes = [record for record in normalized if (
        record["action"] == "logon_success"
        and field(record, "authentication_package").casefold() == "ntlm"
        and field(record, "logon_type") == "3"
    )]

    for success in successes:
        related_failures = [failure for failure in failures if (
            failure["host_id"] == success["host_id"]
            and field(failure, "source_ip") == field(success, "source_ip")
            and field(failure, "destination_ip") == field(success, "destination_ip")
            and field(failure, "user_name").casefold() == field(success, "user_name").casefold()
            and field(failure, "user_domain").casefold() == field(success, "user_domain").casefold()
            and failure["timestamp"] < success["timestamp"]
        )]
        if len(related_failures) < 2:
            continue
        source_ip = field(success, "source_ip")
        destination_ip = field(success, "destination_ip")
        matching_smb = any(
            record["action"] == "network_connection"
            and record["host_id"] != success["host_id"]
            and field(record, "source_ip") == source_ip
            and field(record, "destination_ip") == destination_ip
            and field(record, "destination_port") == "445"
            for record in normalized
        )
        if not matching_smb:
            return source_ip, destination_ip, success["host_id"]
    return None


def _missing_requested_auth_hosts(state):
    alert_text = str(state.get("alert_context", "")).casefold()
    if "afternoon" not in alert_text or not any(
        term in alert_text for term in ("logon", "login", "authentication")
    ):
        return []

    enriched_alert = state.get("enriched_alert") or {}
    entities = enriched_alert.get("entities", {})
    host_ids = entities.get("host_ids", [])
    time_window = enriched_alert.get("time_window", {})
    scope_start = str(time_window.get("start_time") or "")
    scope_end = str(time_window.get("end_time") or "")
    covered_hosts = set()

    for message in state.get("messages", []):
        for tool_call in getattr(message, "tool_calls", None) or []:
            if tool_call.get("name") != "search_timeline":
                continue
            args = tool_call.get("args") or {}
            category = args.get("category", "")
            categories = (
                [str(value).casefold() for value in category]
                if isinstance(category, list)
                else [value.strip().casefold() for value in str(category).split(",")]
            )
            if not any(value in ("authentication", "auth", "logon", "login") for value in categories):
                continue

            query_hosts = args.get("host_id", "")
            if isinstance(query_hosts, list):
                query_hosts = [str(value) for value in query_hosts]
            else:
                query_hosts = [value.strip() for value in str(query_hosts).split(",") if value.strip()]

            query_start = str(args.get("start_time") or "")
            query_end = str(args.get("end_time") or "")
            if scope_start and query_start and query_start > scope_start:
                continue
            if scope_end and query_end and query_end < scope_end:
                continue
            covered_hosts.update(query_hosts)

    return [host_id for host_id in host_ids if host_id not in covered_hosts]


def _missing_requested_archive_files(state):
    alert_text = str(state.get("alert_context", "")).casefold()
    archive_names = {
        name.casefold()
        for name in re.findall(r"\b\w+(?:[.-]\w+)*\.(?:7z|zip|rar|tar|gz|cab)\b", alert_text)
    }
    if not archive_names:
        return []

    host_ids = (state.get("enriched_alert") or {}).get("entities", {}).get("host_ids", [])
    created_names = set()
    for message in state.get("messages", []):
        if getattr(message, "type", "") != "tool":
            continue
        try:
            payload = json.loads(getattr(message, "content", ""))
        except (TypeError, json.JSONDecodeError):
            continue
        rows = []
        if isinstance(payload, list):
            rows.extend((row, "") for row in payload if isinstance(row, dict))
        elif isinstance(payload, dict):
            for key in ("matches", "events", "files", "network_connections", "registry_events"):
                value = payload.get(key)
                if isinstance(value, list):
                    rows.extend((row, key) for row in value if isinstance(row, dict))

        aliases = {"file.name": "file_name", "file.path": "file_path"}
        for row, source in rows:
            row_host = str(row.get("host_id") or payload.get("host_id") if isinstance(payload, dict) else row.get("host_id") or "")
            if row_host and host_ids and row_host not in host_ids:
                continue
            details = row.get("details", {})
            projected = row.get("raw_json_projected", {})
            if not isinstance(details, dict):
                details = {}
            if not isinstance(projected, dict):
                projected = {}
            fields = {aliases.get(key, key): value for key, value in projected.items()}
            fields.update(row)
            fields.update(details)
            action = str(row.get("action") or "").casefold()
            is_file_creation = action == "file_created" or source == "files" or row.get("file_id") is not None
            if not is_file_creation:
                continue
            file_name = str(fields.get("file_name") or "").casefold()
            file_path = str(fields.get("file_path") or "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()
            if file_name in archive_names:
                created_names.add(file_name)
            if file_path in archive_names:
                created_names.add(file_path)

    return sorted(archive_names - created_names)


def _update_investigation_memory(current_memory: dict, messages: list) -> dict:
    """Accumulate and de-duplicate forensic entities discovered across tool executions."""
    mem = dict(current_memory) if isinstance(current_memory, dict) else {}
    processes = dict(mem.get("discovered_processes") or {})
    hosts = set(mem.get("discovered_hosts") or [])
    users = set(mem.get("discovered_users") or [])
    network = list(mem.get("discovered_network") or [])
    files = list(mem.get("discovered_files") or [])
    registry = list(mem.get("discovered_registry") or [])
    key_events = list(mem.get("key_events") or [])

    seen_net = {(n.get("source_ip"), n.get("destination_ip"), str(n.get("destination_port"))) for n in network}
    seen_files = {(f.get("file_name"), f.get("action")) for f in files}
    seen_reg = {r.get("registry_path") for r in registry}
    seen_evt = {e.get("event_id") for e in key_events}

    for m in messages:
        if getattr(m, "type", "") != "tool":
            continue
        content = getattr(m, "content", "")
        if not content:
            continue
        try:
            payload = json.loads(content)
        except Exception:
            continue

        rows = []
        if isinstance(payload, list):
            rows.extend(row for row in payload if isinstance(row, dict))
        elif isinstance(payload, dict):
            if "target_process" in payload and isinstance(payload["target_process"], dict):
                tp = payload["target_process"]
                pid_key = tp.get("process_entity_id")
                if pid_key:
                    processes[pid_key] = {
                        "process_name": tp.get("process_name"),
                        "pid": tp.get("pid"),
                        "command_line": tp.get("command_line"),
                        "parent_entity_id": tp.get("parent_entity_id"),
                        "host_id": tp.get("host_id"),
                    }
            for list_key in ("matches", "events", "processes", "network_connections", "files", "registry_events", "ancestors", "descendants", "spawned_processes", "parent_process", "process_details"):
                val = payload.get(list_key)
                if isinstance(val, list):
                    rows.extend(r for r in val if isinstance(r, dict))

        for row in rows:
            hid = str(row.get("host_id") or "")
            if hid and hid not in ("unknown", "N/A", "None", ""):
                hosts.add(hid)
            uid = str(row.get("user_id") or row.get("user_name") or row.get("username") or "")
            if uid and uid not in ("unknown", "N/A", "None", ""):
                users.add(uid)

            peid = row.get("process_entity_id") or row.get("child_process_entity_id")
            if peid:
                p_entry = dict(processes.get(peid, {}))
                for k in ("process_name", "executable", "pid", "parent_entity_id", "parent_pid", "parent_process_name", "command_line", "host_id"):
                    val = row.get(k) or row.get(f"child_{k}")
                    if val is not None and not p_entry.get(k):
                        p_entry[k] = val
                processes[peid] = p_entry

            dip = row.get("destination_ip")
            if dip:
                sip = row.get("source_ip")
                dport = str(row.get("destination_port") or "")
                net_key = (sip, dip, dport)
                if net_key not in seen_net:
                    seen_net.add(net_key)
                    network.append({
                        "source_ip": sip,
                        "destination_ip": dip,
                        "destination_port": dport,
                        "process_entity_id": peid,
                        "event_id": row.get("event_id"),
                    })

            fname = row.get("file_name") or row.get("file_path")
            if fname and (row.get("file_id") or "file" in str(row.get("action", "")).lower()):
                act = str(row.get("action") or "file_activity")
                f_key = (str(fname), act)
                if f_key not in seen_files:
                    seen_files.add(f_key)
                    files.append({
                        "file_name": str(fname),
                        "file_path": row.get("file_path"),
                        "action": act,
                        "sha256": row.get("sha256"),
                        "process_entity_id": peid,
                        "event_id": row.get("event_id"),
                    })

            rpath = row.get("registry_path") or row.get("registry_key")
            rkey = row.get("registry_key")
            if rpath:
                full_reg = f"{rpath}\\{rkey}" if rkey and rkey not in str(rpath) else str(rpath)
                if full_reg not in seen_reg:
                    seen_reg.add(full_reg)
                    registry.append({
                        "registry_path": full_reg,
                        "registry_key": rkey,
                        "registry_value": row.get("registry_value"),
                        "process_entity_id": peid,
                        "event_id": row.get("event_id"),
                    })

            eid = row.get("event_id")
            if eid and eid not in seen_evt:
                seen_evt.add(eid)
                key_events.append({
                    "event_id": eid,
                    "timestamp": row.get("timestamp"),
                    "host_id": row.get("host_id"),
                    "action": row.get("action"),
                    "category": row.get("category"),
                })

    return {
        "discovered_processes": processes,
        "discovered_hosts": sorted(hosts),
        "discovered_users": sorted(users),
        "discovered_network": network[:15],
        "discovered_files": files[:20],
        "discovered_registry": registry[:15],
        "key_events": key_events[:30],
    }


def _format_investigation_memory(memory: dict) -> str:
    """Format persistent working memory into an authoritative prompt section."""
    lines = ["## CURRENT INVESTIGATION WORKING MEMORY (PERSISTENT FINDINGS ACROSS ALL ITERATIONS):"]
    if memory.get("discovered_hosts"):
        lines.append(f"- Active Hosts: {', '.join(memory['discovered_hosts'])}")
    if memory.get("discovered_users"):
        lines.append(f"- Observed Accounts: {', '.join(memory['discovered_users'])}")

    procs = memory.get("discovered_processes", {})
    if procs:
        lines.append("- Discovered Processes & Lineage:")
        for peid, p in list(procs.items())[:10]:
            pname = p.get("process_name") or p.get("executable") or "unknown"
            pid = p.get("pid") or "?"
            cmd = p.get("command_line")
            cmd_str = f" | cmd: {str(cmd)[:60]}..." if cmd else ""
            parent = f" (parent: {p.get('parent_process_name') or p.get('parent_entity_id')})" if p.get('parent_process_name') or p.get('parent_entity_id') else ""
            lines.append(f"  * {peid} ({pname}, PID {pid}){parent}{cmd_str}")

    net = memory.get("discovered_network", [])
    if net:
        lines.append("- Discovered Network Connections:")
        for n in net[:5]:
            lines.append(f"  * {n.get('source_ip') or '?'} -> {n.get('destination_ip')}:{n.get('destination_port')} (proc: {n.get('process_entity_id') or '?'})")

    fls = memory.get("discovered_files", [])
    if fls:
        lines.append("- Discovered File Modifications:")
        for f in fls[:6]:
            lines.append(f"  * {f.get('action')}: {f.get('file_name')} (path: {f.get('file_path') or '?'})")

    regs = memory.get("discovered_registry", [])
    if regs:
        lines.append("- Discovered Registry Activity:")
        for r in regs[:4]:
            lines.append(f"  * {r.get('registry_path')} (val: {r.get('registry_value') or '?'})")

    lines.append("Use these confirmed entities to guide subsequent queries and correlate the full attack chain.")
    return "\n".join(lines)


def investigator_node(state):
    llm = get_llm().bind_tools(ALL_INVESTIGATION_TOOLS)

    iteration = state.get("iteration_count", 0) + 1

    # Accumulate working memory from all tool messages so far
    working_memory = _update_investigation_memory(state.get("investigation_memory"), state.get("messages", []))

    # Inject active hypotheses into the investigator prompt
    hypos = state.get("hypotheses", [])
    active_hypo = None
    hypo_block = ""
    if hypos:
        active_hypo = hypos[(iteration - 1) % len(hypos)]
        hypo_lines = "\n".join(f"  [{i+1}] {h}" for i, h in enumerate(hypos))
        hypo_block = (
            f"\n\nCURRENT INVESTIGATION HYPOTHESES TO TEST:\n{hypo_lines}\n"
            f"Active Focus for this step: {active_hypo}\n"
            "Issue tool calls to gather telemetry confirming or refuting these hypotheses."
        )

    # FIX: schema hint appended to the system prompt (see _get_schema_hint).
    system = INVESTIGATOR_SYSTEM_PROMPT + "\n\n" + _get_schema_hint() + hypo_block

    # Inject authoritative working memory into prompt
    if working_memory and any(working_memory.values()):
        system += "\n\n" + _format_investigation_memory(working_memory)

    enriched_alert = state.get("enriched_alert") or {}
    if enriched_alert:
        scope = {
            "host_ids": enriched_alert.get("entities", {}).get("host_ids", []),
            "time_window": enriched_alert.get("time_window", {}),
            "unresolved_hostnames": enriched_alert.get("entities", {}).get("unresolved_hostnames", []),
        }
        system += (
            "\n\nALERT SCOPE (authoritative):\n"
            + json.dumps(scope, indent=2)
            + "\nApply these time bounds to every timeline or SQL query. Start with the resolved host IDs. "
            "Expand to another host only when an observed event links it to the scoped host; do not guess host IDs. "
            "If a hostname is unresolved or the scoped queries return no events, report that limitation instead of silently searching unrelated telemetry."
        )

    # Optimize message history to prevent context explosion on local LLMs
    pruned_history = []
    total_msgs = len(state["messages"])
    for idx, m in enumerate(state["messages"]):
        if idx < total_msgs - 3 and getattr(m, "type", "") == "tool" and len(str(getattr(m, "content", ""))) > 1000:
            from langchain_core.messages import ToolMessage
            trimmed = str(m.content)[:1000] + "\n... [older telemetry output truncated to optimize context]"
            pruned_history.append(ToolMessage(content=trimmed, tool_call_id=getattr(m, "tool_call_id", ""), name=getattr(m, "name", "tool")))
        else:
            pruned_history.append(m)

    messages = [SystemMessage(content=system)] + pruned_history

    import time
    max_retries = 3
    response = None
    for attempt in range(max_retries):
        try:
            response = llm.invoke(messages)
            break
        except Exception as e:
            err_str = f"{type(e).__name__} {str(e)}".lower()
            if attempt < max_retries - 1 and any(
                k in err_str for k in ("disconnect", "protocol", "timeout", "connection", "remote", "reset")
            ):
                import logging
                logging.getLogger("a1.investigator").warning(
                    f"Transient LLM network glitch ({type(e).__name__}: {e}). Retrying attempt {attempt + 2}/{max_retries} in {1.5 * (attempt + 1)}s..."
                )
                time.sleep(1.5 * (attempt + 1))
                continue
            raise

    # Prevent speculative over-generation: cap at 2 tool calls per step so the agent
    # investigates iteratively with real data instead of hallucinating forward
    if getattr(response, "tool_calls", None) and len(response.tool_calls) > 2:
        response.tool_calls = response.tool_calls[:2]

    # FIX: repetition guard. Observed in a real run: the model called
    # trace_process_tree with identical arguments 17 times in a row, each
    # returning "0 ancestors, 0 descendants" -- which was the CORRECT answer
    # (251/275 processes in this dataset have no recorded parent). Re-executing
    # teaches nothing, so instead of running the duplicate calls we inject a
    # nudge telling the model to try a different tool/arguments or conclude.
    seen = set()
    for m in state["messages"]:
        for tc in getattr(m, "tool_calls", None) or []:
            seen.add(_call_key(tc))
    new_calls = list(getattr(response, "tool_calls", None) or [])
    if new_calls and all(_call_key(tc) in seen for tc in new_calls):
        nudge = HumanMessage(
            content=(
                _NUDGE_PREFIX + " You already called these exact tool(s) with these "
                "exact arguments and received their results. Calling them again will "
                "return the same data -- do NOT repeat them. Instead: call a DIFFERENT "
                "tool, use DIFFERENT arguments (a different process, host, time window, "
                "or indicator), or write your investigation conclusion as plain text so "
                "the investigation can move to correlation."
            )
        )
        return {
            "messages": [response, nudge],
            "iteration_count": iteration,
            "repeat_nudges": state.get("repeat_nudges", 0) + 1,
            "active_hypothesis": active_hypo,
            "investigation_memory": working_memory,
        }

    missing_smb = _missing_smb_auth_correlation(state.get("messages", []))
    if (
        not new_calls
        and missing_smb
        and not state.get("lateral_network_nudge_sent")
        and iteration < MAX_INVESTIGATION_STEPS
    ):
        source_ip, destination_ip, target_host = missing_smb
        host_ids = enriched_alert.get("entities", {}).get("host_ids", [])
        source_hosts = [host_id for host_id in host_ids if host_id != target_host]
        source_scope = source_hosts[0] if len(source_hosts) == 1 else "the other resolved in-scope host"
        nudge = HumanMessage(
            content=(
                _NUDGE_PREFIX + f" The collected telemetry has repeated NTLM type-3 failures followed by success "
                f"on {target_host} from {source_ip} to {destination_ip}, but no matching source-host SMB event. "
                f"Query search_timeline(host_id='{source_scope}', category='network') and verify an outbound "
                "TCP/445 event with this source/destination and its process_entity_id before concluding."
            )
        )
        return {
            "messages": [response, nudge],
            "iteration_count": iteration,
            "repeat_nudges": state.get("repeat_nudges", 0),
            "active_hypothesis": active_hypo,
            "lateral_network_nudge_sent": True,
            "investigation_memory": working_memory,
        }

    missing_auth_hosts = _missing_requested_auth_hosts(state)
    if (
        not new_calls
        and missing_auth_hosts
        and not state.get("requested_auth_nudge_sent")
        and iteration < MAX_INVESTIGATION_STEPS
    ):
        time_window = enriched_alert.get("time_window", {})
        query_lines = [
            f"search_timeline(host_id='{host_id}', category='authentication'"
            + (f", start_time='{time_window['start_time']}'" if time_window.get("start_time") else "")
            + (f", end_time='{time_window['end_time']}'" if time_window.get("end_time") else "")
            + ")"
            for host_id in missing_auth_hosts
        ]
        nudge = HumanMessage(
            content=(
                _NUDGE_PREFIX + " The alert explicitly asks for afternoon logon/authentication review, but no "
                "full-scope authentication query has been run for: " + ", ".join(missing_auth_hosts) + ". "
                "Run " + "; ".join(query_lines) + ". Evaluate any interactive failure-success pair separately from "
                "the primary attack chain; do not attribute it without causal links."
            )
        )
        return {
            "messages": [response, nudge],
            "iteration_count": iteration,
            "repeat_nudges": state.get("repeat_nudges", 0),
            "active_hypothesis": active_hypo,
            "requested_auth_nudge_sent": True,
            "investigation_memory": working_memory,
        }

    missing_archives = _missing_requested_archive_files(state)
    if (
        not new_calls
        and missing_archives
        and not state.get("requested_archive_nudge_sent")
        and iteration < MAX_INVESTIGATION_STEPS
    ):
        time_window = enriched_alert.get("time_window", {})
        host_ids = enriched_alert.get("entities", {}).get("host_ids", [])
        query_lines = [
            f"search_timeline(host_id='{host_id}', category='file', keyword='{archive_name}'"
            + (f", start_time='{time_window['start_time']}'" if time_window.get("start_time") else "")
            + (f", end_time='{time_window['end_time']}'" if time_window.get("end_time") else "")
            + ")"
            for host_id in host_ids
            for archive_name in missing_archives
        ]
        nudge = HumanMessage(
            content=(
                _NUDGE_PREFIX + " The alert names archive artifact(s) " + ", ".join(missing_archives)
                + ", but the retrieved telemetry does not include their file-creation event(s). Run "
                + "; ".join(query_lines)
                + " and distinguish the archive command from a separate file-created event before concluding."
            )
        )
        return {
            "messages": [response, nudge],
            "iteration_count": iteration,
            "repeat_nudges": state.get("repeat_nudges", 0),
            "active_hypothesis": active_hypo,
            "requested_archive_nudge_sent": True,
            "investigation_memory": working_memory,
        }

    # FIX: Prevent premature termination before gathering data. If the model outputs text
    # without any tool calls before at least 2 tool results have been collected, nudge it to query.
    tool_results_count = sum(1 for m in state.get("messages", []) if getattr(m, "type", "") == "tool")
    if not new_calls and tool_results_count < 2 and iteration < (MAX_INVESTIGATION_STEPS - 2):
        nudge = HumanMessage(
            content=(
                _NUDGE_PREFIX + " You provided reasoning text without executing a tool call, and insufficient telemetry "
                "has been gathered so far. You must execute a tool call (such as find_process_relationships, "
                "find_process_associations, or search_timeline) to query the database. Please invoke the tool now."
            )
        )
        return {
            "messages": [response, nudge],
            "iteration_count": iteration,
            "repeat_nudges": state.get("repeat_nudges", 0),
            "active_hypothesis": active_hypo,
            "investigation_memory": working_memory,
        }

    return {
        "messages": [response],
        "iteration_count": iteration,
        "active_hypothesis": active_hypo,
        "investigation_memory": working_memory,
    }

def should_continue(state):
    messages = state.get("messages", [])
    last_message = messages[-1] if messages else None
    iteration = state.get("iteration_count", 0)

    if iteration >= MAX_INVESTIGATION_STEPS:
        return "correlate"

    # FIX: circuit breaker -- if the model keeps repeating itself even after
    # nudges, stop burning LLM calls and force correlation on what was found.
    if state.get("repeat_nudges", 0) >= MAX_REPEAT_NUDGES:
        return "correlate"

    if isinstance(last_message, AIMessage) and getattr(last_message, "tool_calls", None):
        return "tools"

    # FIX: after a repetition nudge (a HumanMessage injected by this node, not
    # the user), give the model another pass with the nudge in context instead
    # of advancing to correlation.
    if isinstance(last_message, HumanMessage) and last_message.content.startswith(_NUDGE_PREFIX):
        return "investigator"

    # FIX: force at least MIN_INVESTIGATION_STEPS passes before a tool-free
    # conclusion can advance. iteration_count increments on every investigator
    # visit, so this always terminates. Requires the
    # "investigator": "investigator" edge in graph.py.
    if iteration < MIN_INVESTIGATION_STEPS:
        return "investigator"

    return "correlate"
