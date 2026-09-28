# Schema Specification

> **Repository-state note (2026-09):** this spec was written for the original
> five-scenario bundle. The table/view semantics below still describe the two
> shipped databases (`attack_lateral_movement.db`,
> `attack_data_exfiltration.db`), which contain the same `hosts`, `users`,
> `events`, `processes`, `network_connections`, `files`, `registry_events`
> tables plus the `agent_events` view. The evaluator-only objects named below
> (`ground_truth_events`, `scenario_metadata`, `endpoint_security.db`,
> `agent_bundle/`, `events.jsonl`, `ground_truth.jsonl`, `case_labels.json`,
> `dataset_summary.json`) are **not** in this repository; per-scenario ground
> truth lives in `groundtruth_attack_A_lateral_movement.json` and
> `groundtruth_attack_B_data_exfiltration.json` instead. Keep this note
> until/unless the full bundle is restored.

- **Schema name:** Agentic AI Investigator Endpoint Security Dataset
- **Schema version:** `1.0.0`
- **Conformance:** ECS-inspired; not claimed to be fully ECS-compliant.
- **Encoding:** UTF-8 JSONL without a byte order mark (BOM); every line must parse
  under strict UTF-8 decoding.
- **Timestamp:** ISO 8601 UTC timestamps with `Z`.
- **Synthetic data:** All event IDs, host IDs, user IDs, process entity IDs, hashes, IPs/domains, and relationship identifiers are synthetic. Hashes are deterministic SHA-256 values used only for reproducibility.

## Separation of concerns

`events.jsonl` contains agent-accessible observed telemetry only. It excludes scenario IDs, event roles, relevance, explanations, expected correlations, and investigative conclusions. Evaluation information is stored in `ground_truth.jsonl` and the protected database table `ground_truth_events`.

## Core event fields

| Field | Type | Required | Description |
|---|---|---:|---|
| `event.id` | string | yes | Unique synthetic event identifier |
| `@timestamp` | string | yes | ISO 8601 UTC timestamp |
| `dataset.schema_version` | string | yes | ECS-inspired version marker |
| `event.kind` | string | yes | Observed event kind |
| `event.category` | array[string] | yes | Normalized event category |
| `event.type` | array[string] | yes | Normalized event type |
| `event.action` | string | yes | Observed action |
| `event.code` | string | yes | Source event identifier |
| `event.provider` | string | yes | `Sysmon` or `Security` |
| `event.outcome` | string/null | yes | Observed outcome when available |
| `event.severity` | integer/null | yes | Dataset severity representation |
| `dataset.source_type` | string | yes | Source telemetry family |
| `dataset.generation_id` | string | yes | Generation identifier |

## Entity fields

Host fields use `host.*`; user fields use `user.*`; process fields use `process.*`; network fields use `source.*`, `destination.*`, and `network.*`; file fields use `file.*`; registry fields use `registry.*`.

Fields are optional unless explicitly marked required. Irrelevant fields are omitted or represented as `null`; missing evidence is not inferred.

## Process relationships

Observed process telemetry uses:
- `process.entity_id`
- `process.parent.entity_id`
- `process.parent.pid`
- `process.parent.name`
- `process.parent.executable`
- `process.parent.command_line`

Evaluation data records observed relationships in `expected_correlations`. Two
`relation_type` values are defined, and each has its own field shape.

### `process_parent_child`

A parent-child relationship between two observed processes:

- `relation_type: process_parent_child`
- `source_process_entity_id`: parent process entity ID
- `target_process_entity_id`: child process entity ID

### `event_process_association`

An association between a telemetry event and the process it belongs to (for
example a network connection event attributed to the process that opened it):

- `relation_type: event_process_association`
- `source_event_id`: the event that anchors the association, typically the
  process-start event that introduced the process
- `process_entity_id`: the process entity ID the event is associated with

An `event_process_association` is not a parent-child relationship and must not
be interpreted as process ancestry. It records only that the two records refer
to the same observed process.

Neither relationship type is treated as proof of maliciousness.

## Investigation interpretation

Telemetry records describe observations. Ground truth contains evaluation annotations and expected correlations. A document-associated process, registry change, file creation, network connection, or authentication pattern is an investigation trigger—not an automatic malicious classification.

Case-level evaluation labels are stored separately in `case_labels.json`, keyed
by `case_id` (`SCN-001` through `SCN-005`). The allowed `case_label` values are
`benign`, `suspicious`, `malicious`, and `inconclusive`. Labels are evaluator-only
metadata and must not be exposed through `agent_events`.

Each case label includes `confidence`, `expected_conclusion`, `evidence_basis`,
and `verdict_boundary`. The verdict boundary records whether the evidence supports
an unconfirmed or confirmed maliciousness conclusion; a `suspicious` label alone
does not establish that a case is malicious.

## Incomplete evidence

The dataset intentionally permits missing parent events, absent process associations, incomplete authentication sequences, unavailable hashes, and partial timelines. Missing data must remain missing and should be reported as an evidence gap.

## Database relationships

- `events.event_id` is the primary key.
- `hosts.host_id` and `users.user_id` are referenced by normalized records.
- `processes.process_entity_id` links process records and process-associated events.
- `network_connections`, `files`, and `registry_events` reference `event_id`.
- `ground_truth_events` references `events.event_id` but is logically isolated from agent-facing views.
- Indexes cover timestamps, hosts, process entities, and scenario IDs.
- `raw_json` is the authoritative observed payload. For every row, `raw_json` is
  identical to the corresponding record in `events.jsonl`: `events.raw_json` holds
  the event itself, and the normalized tables hold the parent event record
  unchanged. Any consumer may therefore rely on `raw_json` alone for detection.

## Agent-facing database

`endpoint_security.db` is the complete evaluation database and contains the
protected tables `ground_truth_events` and `scenario_metadata`. A SQLite view is
not an access-control boundary: any process that can open the file can also read
those tables directly.

`agent_bundle/agent_endpoint_security.db` is the agent-facing subset. It contains
only agent-accessible objects (`hosts`, `users`, `events`, `files`,
`network_connections`, `registry_events`, `processes`) and the `agent_events`
view. The protected tables are not present in that file, so the bundle can be
handed to an investigating agent safely.


## Schema Version and ECS Compatibility

- `dataset.schema_version`: custom dataset schema version (`1.0.0`). It is present
  on every telemetry record in `events.jsonl`, in `events.raw_json`, and in the
  `raw_json` of every normalized table (`files`, `network_connections`,
  `registry_events`, `processes`).
- `ecs.version`: omitted from all generated records because the dataset is
  ECS-inspired rather than a claim of complete ECS 8.11.0 compliance. No table
  embeds an `ecs.version` key.
- ECS-compatible field names are used where practical, but compatibility limitations
  are documented and should be considered during downstream evaluation.

## Process Relationship Semantics

For explicit parent-child process relationships:

```text
source_process_entity_id = parent process
target_process_entity_id = child process
relation_type = process_parent_child
```

For event-to-process associations:

```text
source_event_id = anchoring event (usually the process-start event)
process_entity_id = associated process
relation_type = event_process_association
```

A missing parent process record indicates incomplete available telemetry only; it
does not, by itself, establish that the process is malicious.

## Event Completeness

The dataset summary reports field-level completeness checks. An event is counted
as incomplete only when one or more expected evidence fields for its event category
are missing or empty. Fields that are legitimately irrelevant to an event category
are excluded from this calculation.
