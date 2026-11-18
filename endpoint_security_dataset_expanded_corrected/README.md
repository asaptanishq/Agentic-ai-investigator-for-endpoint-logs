# Expanded Endpoint Security Dataset

> **Repository-state note (2026-10):** This dataset ships eight forensic telemetry databases with evaluator ground truth isolated in the `groundtruth/` subfolder:
>
> | File | Contents |
> |---|---|
> | `attack_lateral_movement.db` | **ATK-A** telemetry (credential dumping + lateral movement + service persistence; 127 events; hosts `WS-OPS-01`, `SRV-FILE-01`) and **INC-A** telemetry (incomplete telemetry evaluation; missing parent process & flows) |
> | `attack_data_exfiltration.db` | **ATK-B** telemetry: data staging + scheduled-task persistence + HTTPS exfiltration + cleanup |
> | `ransomware_attack_complete_ecs.db` | **ATK-C** telemetry: phishing document delivery, vssadmin shadow copy deletion, LockBit file encryption |
> | `attack_lotl_fileless.db` | **ATK-D** telemetry (Living-off-the-Land LOLBins, mshta, PowerShell, certutil, wmic) and **AMB-A** telemetry (ambiguous developer vs. C2 staging evaluation) |
> | `wazuh_lotl_attack_dataset.db` | **ATK-E** telemetry: Wazuh SIEM/EDR, LotL command execution and SAM registry access |
> | `suricata_c2_intrusion.db` | **ATK-F** telemetry: Suricata NIDS alerts, CobaltStrike C2 beaconing, internal SMB sweeps, and exfiltration |
> | `attack_supply_chain.db` | **ATK-G** telemetry: Enterprise supply chain software compromise across 32 endpoints (1,890 events) |
> | `benign_admin_activity.db` | **BEN-A** telemetry: Benign administrative backup verification script, SMB connections, audit logs, and W32Time registry queries |
> | `groundtruth/` | Ground truth JSON files for ATK-A through ATK-G, BEN-A, AMB-A, and INC-A (`expected_verdict`, `verdict_boundary`, key IOCs, kill chain / evidence basis) |
> | `schema.md` | Field and table semantics for the shipped `.db` telemetry files |
>
> The agent queries the telemetry `.db` files directly through safe read-only connections and convenience views, and the benchmark derives evaluation labels from `groundtruth/groundtruth_*.json`.

Generation ID: `gen-20260920-expanded`
Seed: `20260920`
Schema version: `1.0.0`
Events: `1050` (original bundle; the two shipped attack databases hold a subset)

This expanded synthetic dataset supports agentic investigation across diverse scenarios (malicious intrusions, benign administrative tasks, ambiguous developer utility executions, and incomplete telemetry gaps). Agent-accessible telemetry is stored in the shipped `.db` files and queried via safe read-only connections. Ground truth is isolated in the `groundtruth/` subfolder and must remain unavailable to the investigating agent.

All hosts, users, event IDs, process IDs, hashes, IPs, and domains are synthetic. Suspicious patterns are investigation triggers, not automatic malicious classifications. Missing evidence is preserved where applicable.

## Agent surface vs evaluator surface

Hand the investigating agent **only** the allow-listed telemetry database files.

| Artifact | Surface | Notes |
|---|---|---|
| `*.db` (8 shipped databases) | agent | Shipped databases: `attack_lateral_movement.db`, `attack_data_exfiltration.db`, `ransomware_attack_complete_ecs.db`, `attack_lotl_fileless.db`, `wazuh_lotl_attack_dataset.db`, `suricata_c2_intrusion.db`, `attack_supply_chain.db`, `benign_admin_activity.db`. Queried read-only via virtual views. |
| `groundtruth/groundtruth_*.json` | evaluator only | Ground truth evaluation files with expected verdicts, boundaries, IOCs, and evidence criteria. Must remain isolated from the agent. |

## Query example
```sql
SELECT * FROM events
WHERE host_id = 'WS-OPS-01'
ORDER BY timestamp;
```

## Distribution and Validation

The dataset contains diverse forensic scenarios across 8 standalone SQLite databases. Background and noise telemetry are integrated into each scenario to ensure realistic signal-to-noise ratios.

The `groundtruth/` directory provides one conclusion label per scenario: `benign`, `suspicious`, `malicious`, or `inconclusive`. Each case also records confidence, evidence basis, expected conclusion, and a `verdict_boundary` so that `suspicious` is not treated as confirmed maliciousness.

## Consistency guarantees

- All SQLite telemetry databases are opened in URI read-only mode (`?mode=ro`) to prevent writes.
- Views (`processes`, `files`, `network_connections`, `registry_events`, `hosts`, `users`, `agent_events`) are synthesized dynamically in session RAM via `json_extract()` when not physically present.
- Ground truth is strictly isolated in `groundtruth/` and never queried during live investigations.


