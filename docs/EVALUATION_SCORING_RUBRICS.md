# DFIR Agentic Investigator: 100-Point Multi-Dimensional Evaluation Rubrics

## 1. Executive Summary & Objective

In modern Security Operations Centers (SOC) and Digital Forensics & Incident Response (DFIR), evaluating an autonomous investigation agent purely on binary accuracy ("did it output malicious?") is fundamentally flawed. When all evaluated attack datasets represent genuine intrusion incidents, an uncalibrated model that blindly declares "malicious" achieves 100% accuracy, despite hallucinating nonexistent indicators, overlooking root causes, or catastrophically false-positive alarming on benign operations.

To establish true forensic rigor, this specification defines an objective, transparent, 100-point multi-dimensional evaluation rubric that measures six critical capabilities across a balanced dataset of **Malicious Intrusions** (`ATK-A` through `ATK-G`), **Benign Administrative Operations** (`BEN-A`), **Ambiguous Dual-Use Activities** (`AMB-A`), and **Incomplete Telemetry Gaps** (`INC-A`).

### Core Evaluation Capabilities:
1. **Verdict & Boundary Accuracy** (20 Points)
2. **Ground Truth Evidence Retrieval** (25 Points)
3. **Evidence Grounding & Zero-Hallucination Rate** (20 Points)
4. **Confidence Calibration** (10 Points)
5. **Investigation Efficiency & Query Quality** (10 Points)
6. **Executive Incident Report Quality & Actionability** (15 Points)

---

## 2. Multi-Dimensional Scoring Breakdown

```
+-----------------------------------------------------------------------------------+
|                        DFIR 100-POINT EVALUATION RUBRIC                           |
+-----------------------------------------------------------------------------------+
| Dimension                                              | Weight | Min-Max Points  |
+--------------------------------------------------------+--------+-----------------+
| 1. Incident Verdict & Boundary Precision               | 20%    | 0 to 20 pts     |
| 2. Ground Truth Evidence Retrieval (Graded Recall)     | 25%    | 0 to 25 pts     |
| 3. Evidence Grounding & Zero-Hallucination Integrity   | 20%    | 0 to 20 pts     |
| 4. Confidence Calibration (Brier Score)                | 10%    | 0 to 10 pts     |
| 5. Investigation Efficiency & Query Quality            | 10%    | 0 to 10 pts     |
| 6. Executive Report Completeness & Actionability       | 15%    | 0 to 15 pts     |
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
  - **5 pts**: Correct operational confidence boundary (`confirmed_malicious`, `unconfirmed_malicious`, `benign`). Boundaries are normalized across evaluation datasets (`confirmed_benign` is treated as equivalent to `benign`).
  - **0 pts**: Mismatched confidence boundary.
- **Structured Output Fallback Penalty**:
  - Automatic deduction of all 20 points if the report was produced via structured output recovery fallback (`report_fallback_used = True`).

#### False Positive (FP) and False Negative (FN) Tracking:
- **False Positive (FP)**: Marking a benign or incomplete scenario as `malicious` or `suspicious`.
- **False Negative (FN)**: Marking a confirmed intrusion scenario as `benign` or `inconclusive`.

---

### Dimension 2: Ground Truth Evidence Retrieval (25 Points)

Measures whether the agent uncovered the technical building blocks documented in `endpoint_security_dataset_expanded_corrected/groundtruth/groundtruth_*.json` (`evidence_basis`). Each evidence item becomes a set of distinctive indicators (paths, executables, IPs, event/process IDs, and content words after light stemming). An item earns graded coverage:

$$\text{Coverage}_i = \frac{\text{matched indicators}_i}{\text{total indicators}_i}, \qquad \text{Recall} = \frac{1}{N}\sum_{i=1}^{N}\text{Coverage}_i$$

$$\text{Evidence Recall Score} = 25 \times \text{Recall}$$

`benchmark.py` also reports **evidence precision** (supported citations / total citations) and **evidence F1**, so mentioning many incidental tokens does not automatically earn full recall. A label with an empty `evidence_basis` scores 0 (there is nothing to verify), not full credit.

### Dimension 3: Evidence Grounding & Zero-Hallucination Integrity (20 Points)

Citing an event ID or process ID that does not exist in the active telemetry is a severe evidentiary breach. Every cited `evt-*`, `proc-*`, and `suri-*` identifier is queried against SQLite (process IDs may resolve through `processes` or through `events.process_entity_id`, since not every event-spawned process gets its own process row):

$$\text{Grounding Score} = 20 \times \frac{\text{verified citations}}{\text{total citations}}$$

- No citations at all ⇒ **0 points** (an unsupported report is not grounded).
- A citation whose query fails because the table/view is unavailable is **UNVERIFIED** and does not count as verified.
- `hallucinated_citations`, `total_citations`, and `unverified_citations` are reported per case.

The validator separately checks claimed relationships (parentage, network flows, hostnames) and reports `validation_status` plus `relationship_correctness`; these are diagnostics, not double-counted points.

### Dimension 4: Confidence Calibration (10 Points)

An accurate verdict with unjustified certainty is operationally unsafe. Calibration uses the Brier score against binary correctness of the **verdict** (boundary precision is scored separately, so a near-miss boundary is not double-penalized):

$$\text{Brier} = (c - o)^2, \qquad o \in \{0,1\}$$

$$\text{Calibration Score} = 10 \times (1 - \text{Brier})$$

Missing confidence defaults to 0.5. A correct verdict at 90% confidence scores 9.9; a correct verdict at 50% scores 7.5; an incorrect verdict at 90% scores 1.0.

### Dimension 5: Investigation Efficiency & Query Quality (10 Points)

- **Repetition loop freedom (3 pts)**: 3 minus 1.2 per repetition nudge, floored at 0.
- **Step economy (3 pts)**: 3 for ≤4 iterations, 2 for 5–6, 1 for longer.
- **Retry/fallback (2 pts)**: 2 when no report fallback/retry, 0.5 otherwise.
- **Query quality (2 pts)**: 2 for zero duplicate tool calls, 1 for 1–2 duplicates, 0 for more (from `quality_metrics`).

### Dimension 6: Executive Report Completeness & Actionability (15 Points)

- **Forensic timeline (4 pts)**: Markdown table with at least two dated rows (1 pt if only a header/heading).
- **Grounded citations (3 pts)**: 3 for ≥2 distinct `evt-*`/`proc-*`/`suri-*` IDs, 1 for one, 0 for none.
- **Benign explanations / evidence gaps (2 pts)**: present and substantive.
- **Containment & remediation (3 pts)**: Next Steps, Remediation, or Playbook section.
- **Structure (3 pts)**: ≥1,000 characters and ≥3 level-2/3 headings (1 pt for ≥2 headings).

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

## 5. Latest Measured Results (Dev Split)

Command: `python -m a1.benchmark --split dev --limit 2 --out bench_after.json`
Provider/model: opencode `glm-5.3-flash`. One run per case; LLM output is non-deterministic, so treat these as a snapshot rather than a stable leaderboard.

| Case | Database | Verdict / Boundary | Verdict | Recall | Grounding | Calibration | Efficiency | Report | Composite |
|---|---|---|---|---|---|---|---|---|---|
| ATK-A | `attack_lateral_movement.db` | malicious / confirmed_malicious (match) | 20/20 | 23.6/25 | 19.5/20 (1/43) | 9.9/10 | 10/10 | 15/15 | **98.0 (A+)** |
| ATK-B | `attack_data_exfiltration.db` | malicious / confirmed_malicious (match) | 20/20 | 17.3/25 | 20/20 (0/47) | 9.9/10 | 9/10 | 15/15 | **91.2 (A+)** |
| **Mean** | | 100% verdict/boundary | 20/20 | 20.5/25 | 19.75/20 | 9.9/10 | 9.5/10 | 15/15 | **94.6** |

Aggregate: evidence precision 98.8%, evidence recall 81.8%, evidence F1 88.9%, average Brier 0.008, FPR 0%, FNR 0%, structured-output fallbacks 0/2. The held-out eval split (ATK-F, ATK-G, BEN-A, AMB-A, INC-A) was not run in this pass.

Scoring fixes applied before this run:

- `proc-*` citations now resolve through `processes` **or** `events.process_entity_id`; noise processes that only appear on events are real telemetry. Re-scoring the same ATK-A report moved grounding from 17.2 to 19.5 (6 → 1 citations flagged).
- Citation regex ignores truncated fragments such as `proc-atk`, and report-quality citation credit includes `suri-*`.
- Brier calibration now measures correctness of the verdict only, so a near-miss boundary is not double-penalized.
- A label with an empty `evidence_basis` now scores 0 recall instead of free full credit.

`investigation_completeness` remains a diagnostic and reads 0% on these runs because hypotheses stay `active`/`unresolved`; it is not part of the composite score.
