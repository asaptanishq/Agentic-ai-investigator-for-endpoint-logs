# Expanded Endpoint Security Dataset

> **Repository-state note (2026-09):** this guide was written for the original
> five-scenario generated bundle (`gen-20260920-expanded`, 1,050 events). That
> full bundle is **not** in this repository. What actually ships here is a
> reduced two-attack layout:
>
> | File | Contents |
> |---|---|
> | `attack_lateral_movement.db` | ATK-A telemetry: credential dumping + lateral movement + service persistence (127 events; hosts `WS-OPS-01`, `SRV-FILE-01`) |
> | `attack_data_exfiltration.db` | ATK-B telemetry: data staging + scheduled-task persistence + HTTPS exfiltration + cleanup |
> | `groundtruth_attack_A_lateral_movement.json` | ATK-A ground truth: kill chain, key IOCs, `expected_verdict: malicious`, `verdict_boundary: confirmed_malicious` |
> | `groundtruth_attack_B_data_exfiltration.json` | ATK-B ground truth (includes a benign logon distractor), same verdict fields |
> | `schema.md` | Field/table semantics — still accurate for the shipped `.db` files |
>
> The artifacts named below (`events.jsonl`, `agent_bundle/`,
> `endpoint_security.db`, `case_labels.json`, `dataset_summary.json`,
> `ground_truth.jsonl`, `hosts.json`, `users.json`) belong to the original
> bundle layout and are **absent** here. The agent queries the two
> `attack_*.db` files directly through the `agent_events` view (same columns as
> documented), and the benchmark derives its expected labels from the two
> `groundtruth_attack_*.json` files. Keep this note until/unless the full
> bundle is restored.

Generation ID: `gen-20260920-expanded`
Seed: `20260920`
Schema version: `1.0.0`
Events: `1050` (original bundle; the two shipped attack databases hold a subset)

This expanded synthetic dataset supports agentic investigation across five scenarios. Agent-accessible telemetry is stored in `events.jsonl` and the `agent_events` SQLite view. Ground truth is isolated in `ground_truth.jsonl` and `ground_truth_events`. Case-level evaluation labels are isolated in `case_labels.json` and must remain unavailable to the investigating agent.

All hosts, users, event IDs, process IDs, hashes, IPs, and domains are synthetic. Suspicious patterns are investigation triggers, not automatic malicious classifications. Missing evidence is preserved where applicable.

## Agent surface vs evaluator surface

Hand the investigating agent **only** the allow-listed artifacts below.

| Artifact | Surface | Notes |
|---|---|---|
| `events.jsonl` | agent | 1,050 telemetry records, UTF-8 JSONL without a BOM |
| `agent_bundle/agent_endpoint_security.db` | agent | Reduced database: `hosts`, `users`, `events`, `files`, `network_connections`, `registry_events`, `processes` + the `agent_events` view |
| `hosts.json`, `users.json` | agent | Entity reference data |
| `ground_truth.jsonl` | evaluator only | Scenario IDs, event roles, expected correlations |
| `case_labels.json` | evaluator only | Per-case conclusion labels and evidence basis |
| `dataset_summary.json` | evaluator only | Contains `case_label_distribution` and `event_count_per_scenario` |
| `endpoint_security.db` | evaluator only | Full database; also contains the `ground_truth_events` and `scenario_metadata` tables |

`dataset_summary.json` is **not** agent-accessible: although it holds no per-event
labels, its `case_label_distribution` and `event_count_per_scenario` fields would
reveal label prevalence and scenario sizes to the agent. Keep it on the evaluator
side.

The full `endpoint_security.db` is also evaluator-only. A SQLite view is not an
access-control boundary, so an agent holding that file could read
`ground_truth_events` and `scenario_metadata` directly. Use
`agent_bundle/agent_endpoint_security.db`, which omits those tables entirely.


## Query example
```sql
SELECT * FROM agent_events
WHERE host_id = 'host-001'
ORDER BY timestamp;
```


## Distribution and Validation Clarifications

The dataset contains 1,050 total telemetry events. Scenario-related coverage is
reported separately from background/noise telemetry using unique event IDs present
in `ground_truth.jsonl`. Background/noise events are checked to ensure they do not
contain hidden scenario IDs, event roles, explanations, or expected correlations.

The `agent_events` view exposes observed telemetry only. It does not join to or
expose `ground_truth_events`, scenario IDs, event roles, explanations, or expected
correlations.

`case_labels.json` is evaluator-only metadata. It provides one conclusion label
per scenario: `benign`, `suspicious`, `malicious`, or `inconclusive`. Each case
also records confidence, evidence basis, expected conclusion, and a
`verdict_boundary` so that `suspicious` is not treated as confirmed maliciousness.

## Evaluation hygiene

Telemetry records in `events.jsonl` are deterministically shuffled with the
dataset seed. Event order must not be used as a signal for scenario membership;
evaluation code should join only on documented event fields and keep
`ground_truth.jsonl` inaccessible to the investigating agent.

For a stronger benchmark, split by scenario, host, or time window rather than
randomly splitting individual events. This prevents events from the same
investigation chain appearing in both training and test data.

Background telemetry includes deterministic variation in process command lines,
file paths, and destination domains. These values are synthetic and should be
treated as contextual diversity, not reputation or threat-intelligence data.

The custom schema version is represented by `dataset.schema_version: 1.0.0`.
`ecs.version` is omitted because the dataset uses ECS-inspired naming without
asserting complete ECS 8.11.0 compliance.

## Consistency guarantees

- `events.jsonl` is UTF-8 JSONL with no byte order mark, so it parses under strict
  UTF-8 decoding.
- Every `raw_json` payload in `endpoint_security.db` is identical to the
  corresponding `events.jsonl` record: `events.raw_json` carries the event, and the
  normalized tables (`files`, `network_connections`, `registry_events`,
  `processes`) carry the unchanged parent event record.
- `dataset.schema_version` is the only schema-version key present anywhere; no
  record embeds `ecs.version`.
- `ground_truth.jsonl` and the `ground_truth_events` table are row-for-row
  identical, as are `case_labels.json`, `dataset_summary.json`, `hosts.json` and
  `users.json` against their SQLite counterparts.


