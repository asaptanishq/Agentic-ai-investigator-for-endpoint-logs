"""Tool output summarization for CLI and Web interfaces."""
import json


def _summarize_dict_output(data: dict) -> str:
    if "matches" in data:
        matches = data.get("matches", [])
        count = len(matches)
        details = ", ".join(
            str(m.get("child_process_name", m.get("process_entity_id", "?")))
            for m in matches[:3]
        )
        return f"{count} process match(es): {details}" if details else f"{count} match(es)"
    if "ancestors" in data or "descendants" in data:
        a = len(data.get("ancestors", []))
        d = len(data.get("descendants", []))
        return f"Process tree: {a} ancestor(s), {d} descendant(s)"
    if "network_connections" in data:
        return (
            f"{len(data.get('network_connections', []))} net conns, "
            f"{len(data.get('files', []))} file ops, "
            f"{len(data.get('registry_events', []))} reg events"
        )
    parts = []
    for k, v in data.items():
        if isinstance(v, list):
            parts.append(f"{k}: {len(v)} item(s)")
        elif isinstance(v, dict):
            parts.append(f"{k}: object")
        else:
            parts.append(f"{k}={v}")
        if len(parts) >= 8:
            break
    return "; ".join(parts) if parts else "(empty result)"


def summarize_tool_output(content: str) -> str:
    """Produce a clean human-readable summary of tool output for display."""
    if not content:
        return "(empty)"
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return _summarize_dict_output(data)
        if isinstance(data, list):
            return f"{len(data)} row(s) returned"
        return str(data)[:200]
    except Exception:
        return str(content)[:200]
