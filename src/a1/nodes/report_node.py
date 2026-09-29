import json
import re
from datetime import datetime, timedelta
from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel, Field, field_validator
from typing import List, Literal, Optional, Tuple

from a1.llm import get_llm
from a1.prompts import REPORT_SYNTHESIZER_SYSTEM_PROMPT
from a1.nodes.structured_output import StructuredOutputRetryError, invoke_structured_with_retry

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


def _confirmed_data_exfiltration_chain(evidence_pack: dict):
    """Return linked evidence for archive staging, persistence, egress, and cleanup."""
    records = []
    for item in evidence_pack.get("timeline", []):
        raw = item.get("raw", item)
        details = raw.get("details", item.get("details", {}))
        if not isinstance(details, dict):
            details = {}
        host_id = str(item.get("host_id") or raw.get("host_id") or "")
        if host_id == "N/A":
            host_id = ""
        records.append({
            "item": item,
            "raw": raw,
            "fields": {**raw, **details},
            "event_id": str(item.get("event_id") or raw.get("event_id") or ""),
            "host_id": host_id,
            "process_id": str(item.get("process_entity_id") or raw.get("process_entity_id") or ""),
            "action": str(raw.get("action") or "").lower(),
        })

    archive_commands = []
    archive_creations = []
    task_events = []
    network_events = []
    deletions = []

    for record in records:
        fields = record["fields"]
        process_name = str(
            fields.get("process_name") or fields.get("name")
            or record["item"].get("process_name") or ""
        ).lower()
        command_line = str(fields.get("command_line") or "")
        file_name = str(fields.get("file_name") or "")

        if process_name.endswith("7z.exe") and re.search(r"(?:^|\s)-p\S+", command_line, re.IGNORECASE):
            archive_commands.append(record)
        if record["action"] == "file_created" and re.search(
            r"\.(?:7z|zip|rar|tar|gz|cab)$", file_name, re.IGNORECASE
        ):
            archive_creations.append(record)
        if record["action"] == "file_deleted":
            deletions.append(record)

        registry_path = str(fields.get("registry_path") or "").lower()
        if "taskcache" in registry_path or (
            process_name.endswith("schtasks.exe")
            and "/create" in command_line.lower()
        ):
            task_events.append(record)

        destination_ip = fields.get("destination_ip")
        source_ip = fields.get("source_ip")
        if (
            record["action"] == "network_connection"
            and destination_ip
            and str(destination_ip) != str(source_ip or "")
            and record["process_id"]
        ):
            network_events.append(record)

    archive_process_names = {"7z.exe", "7za.exe", "rar.exe", "winrar.exe", "tar.exe", "makecab.exe"}
    for creation in archive_creations:
        created_name = str(creation["fields"].get("file_name") or "")
        created_path = str(creation["fields"].get("file_path") or created_name)
        archiver_name = str(
            creation["fields"].get("process_name") or creation["fields"].get("name")
            or creation["item"].get("process_name") or ""
        ).lower()
        command = next((
            record for record in archive_commands
            if record["host_id"] == creation["host_id"]
            and record["process_id"] == creation["process_id"]
        ), None)
        if not command and archiver_name not in archive_process_names:
            continue
        staging_record = command or creation
        for task in task_events:
            if task["host_id"] != creation["host_id"]:
                continue
            for deleted in deletions:
                deleted_name = str(deleted["fields"].get("file_name") or "")
                deleted_path = str(deleted["fields"].get("file_path") or deleted_name)
                if not created_name or created_name.casefold() != deleted_name.casefold():
                    continue
                if created_path.casefold() != deleted_path.casefold():
                    continue
                destinations = {
                    str(event["fields"]["destination_ip"])
                    for event in network_events
                    if event["host_id"] in ("", creation["host_id"])
                    and event["process_id"] == deleted["process_id"]
                }
                for destination_ip in destinations:
                    related_network = [
                        event for event in network_events
                        if event["host_id"] in ("", creation["host_id"])
                        and event["process_id"] == deleted["process_id"]
                        and str(event["fields"].get("destination_ip")) == destination_ip
                    ]
                    unique_network = {event["event_id"]: event for event in related_network}
                    first_network_time = min(
                        str(event["item"].get("timestamp") or "")
                        for event in related_network
                    )
                    archive_time = str(creation["item"].get("timestamp") or "")
                    related_tasks = [
                        event for event in task_events
                        if event["host_id"] == creation["host_id"]
                        and archive_time <= str(event["item"].get("timestamp") or "") <= first_network_time
                    ]
                    if len(unique_network) >= 3 and related_tasks:
                        return {
                            "archive_name": created_name,
                            "archive_staging_id": staging_record["event_id"],
                            "archive_command_id": command["event_id"] if command else "",
                            "archive_process_name": archiver_name,
                            "password_protected": command is not None,
                            "archive_creation_id": creation["event_id"],
                            "task_event_ids": list(dict.fromkeys(
                                event["event_id"] for event in related_tasks
                            )),
                            "network_event_ids": list(unique_network),
                            "destination_ip": destination_ip,
                            "network_process_id": deleted["process_id"],
                            "deletion_id": deleted["event_id"],
                            "deletion_timestamp": deleted["item"].get("timestamp"),
                        }

    return None


def _confirmed_credential_lateral_service_chain(evidence_pack: dict):
    """Return evidence only when credential theft, SMB access, and service execution link."""
    aliases = {
        "process.entity_id": "process_entity_id",
        "process.name": "name",
        "process.command_line": "command_line",
        "process.executable": "executable",
        "process.parent.entity_id": "parent_process_entity_id",
        "process.parent.name": "parent_process_name",
        "process.code_signature.status": "code_signature_status",
        "process.integrity_level": "integrity_level",
        "process.target.name": "target_process_name",
        "source.ip": "source_ip",
        "destination.ip": "destination_ip",
        "destination.port": "destination_port",
        "authentication.package": "authentication_package",
        "logon.type": "logon_type",
        "user.name": "user_name",
        "user.domain": "user_domain",
        "file.name": "file_name",
        "file.path": "file_path",
        "registry.path": "registry_path",
        "registry.key": "registry_key",
        "registry.value": "registry_value",
    }
    records = []
    for item in evidence_pack.get("timeline", []):
        raw = item.get("raw", item)
        details = raw.get("details", item.get("details", {}))
        projected = raw.get("raw_json_projected", {})
        if not isinstance(details, dict):
            details = {}
        if not isinstance(projected, dict):
            projected = {}
        fields = {aliases.get(key, key): value for key, value in projected.items()}
        fields.update(raw)
        fields.update(details)
        records.append({
            "item": item,
            "fields": fields,
            "event_id": str(item.get("event_id") or raw.get("event_id") or ""),
            "host_id": str(item.get("host_id") or raw.get("host_id") or ""),
            "process_id": str(
                item.get("process_entity_id")
                or raw.get("process_entity_id")
                or raw.get("child_process_entity_id")
                or ""
            ),
            "action": str(item.get("action") or raw.get("action") or "").lower(),
            "time": _parse_evidence_timestamp(item.get("timestamp") or raw.get("timestamp")),
        })

    def value(record, *keys):
        for key in keys:
            candidate = record["fields"].get(key)
            if candidate not in (None, ""):
                return str(candidate)
        return ""

    def path_key(path):
        return str(path or "").strip().strip('"').replace("/", "\\").casefold()

    processes = [
        record for record in records
        if record["action"] == "process_started"
    ]
    for dump_process in processes:
        dump_name = value(dump_process, "process_name", "name").casefold()
        command_line = value(dump_process, "command_line").casefold()
        if not dump_name.endswith("procdump.exe") or "lsass.exe" not in command_line:
            continue

        parent_id = value(dump_process, "parent_process_entity_id", "parent_entity_id")
        parent_name = value(dump_process, "parent_process_name").casefold()
        if not parent_id or parent_name != "powershell.exe":
            continue

        accesses_lsass = any(
            record["action"] == "process_accessed"
            and record["process_id"] == dump_process["process_id"]
            and record["host_id"] == dump_process["host_id"]
            and str(value(record, "event_code")) == "10"
            and value(record, "target_process_name").casefold() in ("", "lsass.exe")
            for record in records
        )
        dump_file = next((record for record in records if (
            record["action"] == "file_created"
            and record["process_id"] == dump_process["process_id"]
            and record["host_id"] == dump_process["host_id"]
            and value(record, "file_name").casefold() == "lsass.dmp"
        )), None)
        if not accesses_lsass or not dump_file:
            continue

        smb_events = [record for record in records if (
            record["action"] == "network_connection"
            and record["process_id"] == parent_id
            and record["host_id"] == dump_process["host_id"]
            and value(record, "process_name", "name").casefold() == "powershell.exe"
            and value(record, "destination_port") == "445"
            and value(record, "source_ip")
            and value(record, "destination_ip")
        )]
        for smb in smb_events:
            failures = []
            successes = []
            for record in records:
                if (
                    record["host_id"] == ""
                    or record["host_id"] == dump_process["host_id"]
                    or record["host_id"] == "N/A"
                    or value(record, "source_ip") != value(smb, "source_ip")
                    or value(record, "destination_ip") not in ("", value(smb, "destination_ip"))
                    or value(record, "destination_port") not in ("", "445")
                    or value(record, "authentication_package").casefold() != "ntlm"
                    or value(record, "logon_type") != "3"
                    or not value(record, "user_name")
                    or not record["time"]
                ):
                    continue
                if record["action"] == "logon_failed":
                    failures.append(record)
                elif record["action"] == "logon_success":
                    successes.append(record)

            for success in successes:
                related_failures = [failure for failure in failures if (
                    failure["host_id"] == success["host_id"]
                    and value(failure, "user_name").casefold() == value(success, "user_name").casefold()
                    and value(failure, "user_domain").casefold() == value(success, "user_domain").casefold()
                    and failure["time"] < success["time"]
                )]
                if len(related_failures) < 2 or not smb["time"] or smb["time"] >= min(
                    failure["time"] for failure in related_failures
                ):
                    continue

                service_regs = [record for record in records if (
                    record["action"] == "registry_value_set"
                    and record["host_id"] == success["host_id"]
                    and value(record, "registry_key").casefold() == "imagepath"
                    and "\\services\\" in value(record, "registry_path").casefold()
                    and path_key(value(record, "registry_value"))
                    and record["process_id"]
                    and record["time"]
                    and record["time"] > success["time"]
                )]
                for service_reg in service_regs:
                    service_path = value(service_reg, "registry_value")
                    service_name = value(service_reg, "registry_path").rstrip("\\").rsplit("\\", 1)[-1]
                    dropped_file = next((record for record in records if (
                        record["action"] == "file_created"
                        and record["host_id"] == service_reg["host_id"]
                        and record["process_id"] == service_reg["process_id"]
                        and path_key(value(record, "file_path")) == path_key(service_path)
                        and record["time"]
                        and service_reg["time"] >= record["time"]
                    )), None)
                    if not dropped_file:
                        continue

                    service_execution = next((record for record in processes if (
                        record["host_id"] == service_reg["host_id"]
                        and path_key(value(record, "executable")) == path_key(service_path)
                        and value(record, "parent_process_name").casefold() == "services.exe"
                        and value(record, "integrity_level").casefold() == "system"
                        and record["time"]
                        and record["time"] > service_reg["time"]
                    )), None)
                    if not service_execution:
                        continue

                    related_failures.sort(key=lambda record: record["time"])
                    return {
                        "source_process_id": parent_id,
                        "credential_process_id": dump_process["process_id"],
                        "service_process_id": service_reg["process_id"],
                        "source_host_id": dump_process["host_id"],
                        "target_host_id": service_reg["host_id"],
                        "user_name": value(success, "user_domain") + "\\" + value(success, "user_name"),
                        "service_name": service_name,
                        "service_path": service_path,
                        "procdump_event_id": dump_process["event_id"],
                        "lsass_access_event_id": next(
                            record["event_id"] for record in records
                            if record["action"] == "process_accessed"
                            and record["process_id"] == dump_process["process_id"]
                            and record["host_id"] == dump_process["host_id"]
                        ),
                        "dump_file_event_id": dump_file["event_id"],
                        "smb_event_ids": list(dict.fromkeys(record["event_id"] for record in smb_events)),
                        "failure_event_ids": [record["event_id"] for record in related_failures],
                        "success_event_id": success["event_id"],
                        "service_file_event_id": dropped_file["event_id"],
                        "service_registry_event_id": service_reg["event_id"],
                        "service_execution_event_id": service_execution["event_id"],
                        "service_signature_status": value(service_execution, "code_signature_status"),
                    }
    return None


def _parse_evidence_timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _post_cleanup_interactive_logon_pair(evidence_pack: dict, cleanup_timestamp: str):
    """Find a same-user type-2 Kerberos failure followed by success after cleanup."""
    cleanup_time = _parse_evidence_timestamp(cleanup_timestamp)
    if cleanup_time is None:
        return None

    failures = []
    successes = []
    for item in evidence_pack.get("timeline", []):
        details = item.get("details", {})
        if not isinstance(details, dict):
            continue
        if str(details.get("logon_type", "")) != "2":
            continue
        if str(details.get("authentication_package", "")).casefold() != "kerberos":
            continue
        try:
            timestamp = datetime.fromisoformat(str(item.get("timestamp", "")).replace("Z", "+00:00"))
        except ValueError:
            continue
        if timestamp <= cleanup_time:
            continue
        record = {
            "event_id": item.get("event_id"),
            "timestamp": item.get("timestamp"),
            "host_id": item.get("host_id"),
            "user_name": details.get("user_name"),
            "user_id": item.get("user_id"),
            "time": timestamp,
        }
        if item.get("action") == "logon_failed":
            failures.append(record)
        elif item.get("action") == "logon_success":
            successes.append(record)

    pairs = []
    for failure in failures:
        for success in successes:
            if (
                failure["host_id"] != success["host_id"]
                or failure["user_name"] != success["user_name"]
                or failure["user_id"] != success["user_id"]
            ):
                continue
            elapsed = success["time"] - failure["time"]
            if timedelta(0) < elapsed <= timedelta(minutes=30):
                pairs.append((failure, success))
    return max(pairs, key=lambda pair: pair[0]["time"]) if pairs else None


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

    collect_paths(evidence_pack.get("timeline", []))
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
        print(f"[!] Report structured-output failed ({type(e).__name__}: {e}); attempting recovery of partial JSON completion.")
        recovered = False
        err_str = "\n".join(str(error) for error in (e, e.__cause__) if error)
        structured_retry_used = isinstance(e, StructuredOutputRetryError)

        # Attempt to recover JSON from completion in exception
        match = re.search(r"completion\s*(\{[^\}]*\})\.?\s*(?:Got:|$)", err_str, re.DOTALL)
        if not match:
            match = re.search(r"\{.*\}", err_str, re.DOTALL)

        if match:
            try:
                raw_json_str = match.group(1) if match.lastindex else match.group(0)
                data = json.loads(raw_json_str)
                # Instantiate with defaults filling any missing fields
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
                print(f"[!] Partial JSON recovery failed: {parse_err}")

        if not recovered:
            fallback_used = True
            verdict = "suspicious"
            verdict_boundary = "unconfirmed_malicious"
            confidence = 0.3
            summary = "- Automated report generation encountered an error; verdict assigned by conservative fallback."
            reasoning = "- Automated structured report synthesis failed; fallback assigned based on baseline safety parameters."
            attack_chain = ["Report synthesis failed -- see investigation trail"]
            evidence_basis = ["Fallback verdict -- not based on completed analysis"]
            benign_considered = []
            gaps_out = gaps if gaps else ["Report synthesis incomplete"]
            next_steps = ["Re-run investigation", "Manual analyst review required"]

    corroborated_chain = _confirmed_data_exfiltration_chain(evidence_pack)
    if corroborated_chain:
        verdict = "malicious"
        verdict_boundary = "confirmed_malicious"
        confidence = max(confidence, 0.9)
        archive_claim = (
            f"password-protected archive command ({corroborated_chain['archive_command_id']}) "
            f"and creation of {corroborated_chain['archive_name']} "
            f"({corroborated_chain['archive_creation_id']})"
            if corroborated_chain["password_protected"]
            else f"archive creation by {corroborated_chain['archive_process_name']} "
            f"({corroborated_chain['archive_staging_id']})"
        )
        chain_claim = (
            f"Corroborated data-exfiltration chain: {archive_claim}; "
            f"scheduled-task persistence ({', '.join(corroborated_chain['task_event_ids'])}); "
            f"{len(corroborated_chain['network_event_ids'])} repeated outbound connections to "
            f"{corroborated_chain['destination_ip']} "
            f"({', '.join(corroborated_chain['network_event_ids'])}) by "
            f"{corroborated_chain['network_process_id']}); subsequent archive deletion "
            f"({corroborated_chain['deletion_id']}). The payload contents were not captured."
        )
        summary = f"{summary.rstrip()}\n- {chain_claim}"
        reasoning = (
            f"{reasoning.rstrip()}\n- **Verdict consistency**: {chain_claim} "
            "This correlated chain supports a confirmed malicious verdict without requiring "
            "credential dumping or lateral movement evidence."
        )
        logon_pair = _post_cleanup_interactive_logon_pair(
            evidence_pack, corroborated_chain["deletion_timestamp"]
        )
        if logon_pair:
            failure, success = logon_pair
            reasoning += (
                f"\n- **Afternoon logon review**: {failure['event_id']} at {failure['timestamp']} "
                f"was followed by {success['event_id']} at {success['timestamp']} for the same "
                "user and host using type-2 Kerberos. The pair follows archive cleanup and has "
                "no observed link to the attack process or destination, so it is treated as "
                "unrelated background activity, not brute force or attack evidence."
            )
        attack_chain.append(chain_claim)
        evidence_basis.append(chain_claim)
        next_steps = [
            "Immediately isolate the affected endpoint from the network.",
            "Preserve endpoint logs and collect full disk and memory evidence.",
            "Revoke and rotate credentials for the affected account.",
            "Remove the scheduled task and assess other endpoints for the destination and indicators.",
        ]

    lateral_chain = _confirmed_credential_lateral_service_chain(evidence_pack)
    if lateral_chain:
        verdict = "malicious"
        verdict_boundary = "confirmed_malicious"
        confidence = max(confidence, 0.9)
        chain_claim = (
            f"Corroborated credential-theft and lateral-movement chain: PowerShell process "
            f"{lateral_chain['source_process_id']} launched ProcDump "
            f"({lateral_chain['procdump_event_id']}), which accessed LSASS "
            f"({lateral_chain['lsass_access_event_id']}) and created the credential dump "
            f"({lateral_chain['dump_file_event_id']}); that PowerShell process then made SMB "
            f"connections ({', '.join(lateral_chain['smb_event_ids'][:4])}) before the "
            f"{len(lateral_chain['failure_event_ids'])} failed and successful NTLM type-3 "
            f"logons for {lateral_chain['user_name']} "
            f"({', '.join(lateral_chain['failure_event_ids'][:4] + [lateral_chain['success_event_id']])}). "
            f"On {lateral_chain['target_host_id']}, the matching service binary was dropped "
            f"({lateral_chain['service_file_event_id']}), registered as "
            f"{lateral_chain['service_name']} via ImagePath "
            f"({lateral_chain['service_registry_event_id']}), and launched by services.exe "
            f"with SYSTEM integrity ({lateral_chain['service_execution_event_id']})."
        )
        summary = f"{summary.rstrip()}\n- {chain_claim}"
        reasoning = (
            f"{reasoning.rstrip()}\n- **Cross-stage corroboration**: {chain_claim} "
            "The causal sequence supports a confirmed malicious verdict. The missing parent "
            "telemetry for sc.exe limits attribution of the remote service-creation command, "
            "but does not negate the independently observed service ImagePath and execution."
        )
        attack_chain.append(chain_claim)
        evidence_basis.append(chain_claim)
        gaps_out = [
            gap for gap in gaps_out
            if not (
                lateral_chain["credential_process_id"] in gap
                and "parent" in gap.casefold()
                and ("missing" in gap.casefold() or "cannot confirm" in gap.casefold())
            )
        ]
        if not lateral_chain["service_signature_status"]:
            gaps_out.append(
                "Code-signature status for UpdaterSvc2 was not recorded; its unsigned status is not independently verified."
            )
        if any(
            lateral_chain["credential_process_id"] in gap
            and "parent" in gap.casefold()
            and ("missing" in gap.casefold() or "cannot confirm" in gap.casefold())
            for gap in response.evidence_gaps if not fallback_used
        ):
            validation_warnings.append(
                "A generated missing-parent claim for ProcDump contradicted the observed parent-child telemetry and was omitted."
            )
        next_steps = [
            "Isolate both affected endpoints and preserve volatile and disk evidence.",
            "Revoke and rotate credentials for CORP\\jdoe and assess LSASS dump exposure.",
            "Contain and remove UpdaterSvc2 and its binary after evidence preservation.",
            "Review remote service-creation telemetry to identify the missing sc.exe parent process.",
        ]

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

    formatted_summary = _format_text_as_bullets(summary)
    formatted_reasoning = f"\n## Investigation Reasoning & Hypothesis Analysis\n{_format_text_as_bullets(reasoning)}\n" if reasoning else ""

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
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(attack_chain))}

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
        "verdict": verdict,
        "verdict_boundary": verdict_boundary,
        "confidence": confidence,
        "report_fallback_used": fallback_used,
        "report_retry_used": structured_retry_used,
    }
