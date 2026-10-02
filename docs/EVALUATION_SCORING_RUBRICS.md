# DFIR Agentic Investigator: 100-Point Multi-Dimensional Evaluation Rubrics

## 1. Executive Summary & Objective

In modern Security Operations Centers (SOC) and Digital Forensics & Incident Response (DFIR), evaluating an autonomous investigation agent purely on binary accuracy ("did it output malicious?") is fundamentally flawed. When all evaluated attack datasets represent genuine intrusion incidents, an uncalibrated model that blindly declares "malicious" achieves 100% accuracy, despite hallucinating nonexistent indicators, overlooking root causes, or catastrophically false-positive alarming on benign operations.

To establish true forensic rigor, this specification defines an objective, transparent, 100-point multi-dimensional evaluation rubric that measures five critical capabilities across a balanced dataset of **Malicious Intrusions** (`ATK-A` through `ATK-G`), **Benign Administrative Operations** (`BEN-A`), **Ambiguous Dual-Use Activities** (`AMB-A`), and **Incomplete Telemetry Gaps** (`INC-A`).

### Core Evaluation Capabilities:
1. **Verdict & Boundary Accuracy** (20 Points)
2. **Ground Truth Evidence Retrieval & IOC Recall** (30 Points)
3. **Evidence Grounding & Zero-Hallucination Rate** (25 Points)
4. **Investigation Efficiency & Reasoning Quality** (15 Points)
5. **Executive Incident Report Quality & Actionability** (10 Points)

---

## 2. Multi-Dimensional Scoring Breakdown

```
+-----------------------------------------------------------------------------------+
|                        DFIR 100-POINT EVALUATION RUBRIC                           |
+-----------------------------------------------------------------------------------+
| Dimension                                              | Weight | Min-Max Points  |
+--------------------------------------------------------+--------+-----------------+
| 1. Incident Verdict & Boundary Precision               | 20%    | 0 to 20 pts     |
| 2. Ground Truth Evidence Retrieval (IOC Recall)        | 30%    | 0 to 30 pts     |
| 3. Evidence Grounding & Zero-Hallucination Integrity   | 25%    | 0 to 25 pts     |
| 4. Investigation Efficiency & Query Quality            | 15%    | 0 to 15 pts     |
| 5. Executive Report Completeness & Actionability       | 10%    | 0 to 10 pts     |
+--------------------------------------------------------+--------+-----------------+
| TOTAL COMPOSITE BENCHMARK SCORE                        | 100%   | 0 to 100 pts    |
+-----------------------------------------------------------------------------------+
```

---

### Dimension 1: Incident Verdict & Boundary Precision (20 Points)

Measures the agent's ability to accurately discriminate between genuine threats, legitimate IT administration, ambiguous developer tasks, and telemetry blind spots without relying on hardcoded fallback routines.

- **Verdict Match (15 Points)**:
  - **15 pts**: Agent verdict matches scenario ground truth (`malicious`, `benign`, `suspicious`, `inconclusive`).
    - For `BEN-A`: Agent must recognize benign administrative activity (`benign`) and avoid raising a false positive alarm.
    - For `INC-A`: Agent must detect missing telemetry chains (parent process, network flows) and correctly report `inconclusive` / `insufficient_telemetry` rather than making unsupported accusations.
    - For `AMB-A`: Agent evaluates dual-use utility intent and reaches the documented operational determination.
  - **0 pts**: Agent verdict diverges from ground truth.
- **Verdict Boundary Match (5 Points)**:
  - **5 pts**: Correct operational confidence boundary (`confirmed_malicious`, `inconclusive_suspicious`, `benign`).
  - **0 pts**: Mismatched confidence boundary.
- **Structured Output Fallback Penalty**:
  - Automatic deduction of all 20 points if the report was produced via structured output recovery fallback (`report_fallback_used = True`).

#### False Positive (FP) and False Negative (FN) Tracking:
- **False Positive (FP)**: Marking a benign or incomplete scenario as `malicious`.
- **False Negative (FN)**: Marking a confirmed intrusion scenario as `benign` or failing to detect critical attack indicators.

---

### Dimension 2: Ground Truth Evidence Retrieval / IOC Recall (30 Points)

Measures whether the agent uncovered the actual technical building blocks of the attack chain or benign baseline as documented in `endpoint_security_dataset_expanded_corrected/groundtruth/groundtruth_*.json` (`evidence_basis`):

$$\text{Recall Score} = 30 \times \frac{\sum_{i=1}^{N} \mathbb{I}(\text{Key Indicator } i \text{ captured in report or memory})}{N}$$

Key indicators evaluated:
1. **Process Execution & Ancestry**: Identified malicious/benign process entity IDs, PIDs, executables, and command lines (e.g. `procdump.exe`, `7z.exe`, `LockBit`, `mshta.exe`, `backup_verification.ps1`) (8 pts).
2. **Causal Ancestry / Spawning Chain**: Reconstructed parent-child execution lineage (e.g. `winword.exe` -> `powershell.exe` -> `vssadmin.exe`) (6 pts).
3. **Network Flows & C2 Egress**: Discovered critical external IPs, beaconing ports, or internal SMB pivoting flows (6 pts).
4. **File Staging or Modification**: Discovered dropped payloads, staged archives, encrypted files, or audit log paths (5 pts).
5. **Persistence & System Mutations**: Discovered scheduled tasks, service installations, or registry hive manipulations (5 pts).

---

### Dimension 3: Evidence Grounding & Zero-Hallucination Integrity (25 Points)

In forensic investigations, citing an event ID, hash, or IP address that does not exist in the raw telemetry is a severe breach of evidentiary integrity. This dimension is deterministically verified against the active SQLite database by the **Evidence Validator** node (`validator_node.py`):

$$\text{Grounding Score} = 25 \times \left(1.0 - \min\left(1.0, \frac{\text{Hallucinated References}}{\text{Total Cited References}}\right)\right)$$

Audit checks performed:
- **Event ID Grounding (15 Points)**: Every `event_id` cited in the executive summary, reasoning, attack chain, and timeline matrix is queried against the active SQLite database (`SELECT count(*) FROM events WHERE event_id = ?`).
  - **15 pts**: 100% of cited event IDs exist in the database.
  - Linear deduction for each unobserved / hallucinated event ID (-5 pts per hallucinated ID).
- **Entity ID & Indicator Grounding (10 Points)**: Every `process_entity_id`, file path, and IP address cited must exist in the database telemetry.
  - **10 pts**: 100% of cited entity identifiers verified in telemetry.
  - -3 pts per hallucinated process ID or IP address.

---

### Dimension 4: Investigation Efficiency & Query Quality (15 Points)

Measures the economy, focus, and precision of the agent's autonomous workflow, enhanced by the **Adaptive Investigation Planner** (`planner_node.py`):
- **Repetition Loop Freedom (5 Points)**:
  - **5 pts**: Zero repetition nudges triggered (`repeat_nudges == 0`).
  - **2 pts**: 1 repetition nudge triggered.
  - **0 pts**: $\ge 2$ repetition nudges triggered.
- **SQL & Query Conformance (5 Points)**:
  - **5 pts**: All SQL queries and tool invocations executed with valid syntax and schema conformance.
  - -2 pts for every unhandled syntax or column error.
- **Step Economy (5 Points)**:
  - **5 pts**: Concluded within optimal budget (2 to 4 reasoning steps).
  - **3 pts**: Concluded at step 5.
  - **1 pt**: Hit maximum iteration limit (`MAX_INVESTIGATION_STEPS = 12`) without resolving all hypotheses.

---

### Dimension 5: Executive Report Completeness & Actionability (10 Points)

Measures whether the generated report provides SOC leadership and incident response teams with immediately actionable deliverables:
- **Forensic Timeline Matrix (4 Points)**: A chronological Markdown table mapping timestamps, hosts, process names, action descriptions, and citing event IDs.
- **Indicator of Compromise (IOC) Matrix (3 Points)**: Structured artifact table detailing artifact type, value, context, and detection status.
- **Containment & Remediation Playbook (3 Points)**: Clear, bulleted, prioritized incident response actions (host isolation, credential rotation, artifact eradication, hunting queries).

---

## 3. Scorecard Grade Scale

| Composite Score | Grade | Operational Assessment |
|:---|:---:|:---|
| **90 - 100** | **A+ (Exemplary)** | Forensic-grade investigation: accurate verdict, high recall, zero hallucination, comprehensive timeline & IOC tables. |
| **80 - 89** | **A (Superior)** | Strong investigation: accurate verdict and solid evidence grounding with minor omissions in background timeline. |
| **70 - 79** | **B (Acceptable)** | Actionable verdict with partial IOC recall or minor query inefficiencies. |
| **60 - 69** | **C (Deficient)** | Premature conclusion, significant telemetry gaps, or minor citation inconsistencies. |
| **< 60** | **F (Unacceptable)** | Mismatched verdict, false positive alarm, hallucinated citations, or infinite tool repetition loop. |

---

## 4. Benchmark Scenarios Catalog

| Scenario ID | Class | Database | Telemetry Focus | Ground Truth Reference |
|:---|:---|:---|:---|:---|
| **ATK-A** | Malicious | `attack_lateral_movement.db` | LSASS memory dump, SMB connection, NTLM logon, service install | `groundtruth/groundtruth_attack_A_lateral_movement.json` |
| **ATK-B** | Malicious | `attack_data_exfiltration.db` | Staged spreadsheet archive, scheduled task, outbound HTTPS, cleanup | `groundtruth/groundtruth_attack_B_data_exfiltration.json` |
| **ATK-C** | Malicious | `ransomware_attack_complete_ecs.db` | Phishing attachment, vssadmin shadow delete, LockBit encryption | `groundtruth/groundtruth_attack_C_ransomware.json` |
| **ATK-D** | Malicious | `attack_lotl_fileless.db` | LOLBins (mshta, certutil, wmic), encoded PowerShell, in-memory C2 | `groundtruth/groundtruth_attack_D_lotl_fileless.json` |
| **ATK-E** | Malicious | `wazuh_lotl_attack_dataset.db` | Wazuh SIEM/EDR, LotL commands, SAM registry access, lateral movement | `groundtruth/groundtruth_attack_E_wazuh_lotl.json` |
| **ATK-F** | Malicious | `suricata_c2_intrusion.db` | Suricata NIDS alerts, CobaltStrike C2 beaconing, SMB reconnaissance | `groundtruth/groundtruth_attack_F_suricata.json` |
| **ATK-G** | Malicious | `attack_supply_chain.db` | Enterprise supply chain compromise across 32 endpoints (1,890 events) | `groundtruth/groundtruth_attack_G_supply_chain.json` |
| **BEN-A** | Benign | `benign_admin_activity.db` | Legitimate backup script (`backup_verification.ps1`), SMB flows, registry checks | `groundtruth/groundtruth_benign_A_admin_activity.json` |
| **AMB-A** | Ambiguous | `attack_lotl_fileless.db` | Dual-use developer utility invocations (certutil, powershell flags) | `groundtruth/groundtruth_ambiguous_A_dev_activity.json` |
| **INC-A** | Inconclusive | `attack_lateral_movement.db` | Alert on SRV-FILE-01 missing parent process and network connection telemetry | `groundtruth/groundtruth_incomplete_A_missing_telemetry.json` |

---

## 5. Ablation Studies & Experimental Comparison Framework

To empirically evaluate system contributions, the repository includes an experiment runner (`src/a1/experiment.py`) for conducting ablation studies across four core architectural augmentations:

1. **Evidence Graph** (`enable_evidence_graph`): Structured entity-relationship DAG linking processes, files, network flows, and hosts.
2. **Adaptive Planner** (`enable_adaptive_planner`): Information-gain action candidate scoring minimizing wasted steps.
3. **Evidence Validator** (`enable_validator`): Deterministic database grounding checking every cited artifact ID against SQLite.
4. **Baseline Context** (`enable_baseline_context`): Enterprise baseline context injection separating normal operations from deviations.

### Running Evaluations

```powershell
# Run the complete 10-scenario benchmark:
.venv\Scripts\python.exe -m a1.benchmark

# Run the benchmark with a limit of 5 cases:
.venv\Scripts\python.exe -m a1.cli --benchmark --limit 5

# Run baseline comparison and ablation experiments:
.venv\Scripts\python.exe -m a1.experiment
```
