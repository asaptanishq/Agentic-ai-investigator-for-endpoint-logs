# DFIR Agentic Investigator: 100-Point Multi-Dimensional Evaluation Rubrics

## 1. Executive Summary & Objective

In security operations centers (SOC) and digital forensics and incident response (DFIR), evaluating an autonomous investigator on binary accuracy alone ("did it say malicious?") is fundamentally flawed. When all evaluated attack datasets represent genuine intrusion incidents, an uncalibrated model that blindly outputs "malicious" scores 100%, while hallucinating nonexistent indicators or missing the root cause.

This specification establishes an objective, transparent, 100-point multi-dimensional evaluation rubric that measures five critical capabilities:
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

Measures the agent's ability to accurately determine whether malicious activity occurred and assign the legally and operationally appropriate confidence boundary without relying on hardcoded fallbacks.

- **Verdict Match (15 Points)**:
  - 15 pts: Agent verdict matches ground truth (`malicious`, `suspicious`, `benign`).
  - 0 pts: Agent verdict diverges from ground truth.
- **Verdict Boundary Match (5 Points)**:
  - 5 pts: Correct operational boundary (`confirmed_malicious`, `inconclusive_suspicious`, `benign`).
  - 0 pts: Mismatched boundary.
- **Fallback Penalty**:
  - Automatic deduction of all 20 points if the report was produced via structured output recovery fallback (`report_fallback_used = True`).

---

### Dimension 2: Ground Truth Evidence Retrieval / IOC Recall (30 Points)

Measures whether the agent uncovered the actual technical building blocks of the attack chain as documented in `endpoint_security_dataset_expanded_corrected/groundtruth/groundtruth_attack_*.json` (`evidence_basis`):

$$\text{Recall Score} = 30 \times \frac{\sum_{i=1}^{N} \mathbb{I}(\text{Key Indicator } i \text{ captured in report or memory})}{N}$$

Key indicators evaluated:
1. **Malicious Process Execution**: Did the agent identify the core malicious process name, PID, or entity ID (e.g. `procdump.exe`, `7z.exe`, `LockBit`, `mshta.exe`)? (8 pts)
2. **Causal Ancestry / Spawning**: Did the agent reconstruct the parent-child relationship (e.g. `winword.exe` -> `powershell.exe`)? (6 pts)
3. **Network C2 / Egress**: Did the agent discover the malicious destination IP or port (e.g. external C2 IP, SMB 445 cross-host)? (6 pts)
4. **File Staging or Modification**: Did the agent locate the dropped binary, staged archive, or encrypted extensions? (5 pts)
5. **Persistence / Registry / Task**: Did the agent identify the scheduled task, service ImagePath, or registry key? (5 pts)

---

### Dimension 3: Evidence Grounding & Zero-Hallucination Integrity (25 Points)

In forensic investigations, citing an event ID, hash, or IP that does not exist in the raw telemetry is unacceptable.

$$\text{Grounding Score} = 25 \times \left(1.0 - \min\left(1.0, \frac{\text{Hallucinated References}}{\text{Total Cited References}}\right)\right)$$

Audit checks performed:
- **Event ID Grounding (15 Points)**: Every `event_id` cited in the executive summary, reasoning, attack chain, and timeline matrix is queried against the active SQLite database (`SELECT count(*) FROM events WHERE event_id = ?`).
  - 15 pts: 100% of cited event IDs exist in the database.
  - Linear deduction for each unobserved / hallucinated event ID (-5 pts per hallucinated ID).
- **Entity ID & Indicator Grounding (10 Points)**: Every `process_entity_id`, file path, and IP address cited must exist in the database telemetry.
  - 10 pts: 100% of cited entity identifiers verified.
  - -3 pts per hallucinated process ID or IP address.

---

### Dimension 4: Investigation Efficiency & Query Quality (15 Points)

Measures the economy and precision of the agent's autonomous workflow:
- **Repetition Loop Freedom (5 Points)**:
  - 5 pts: Zero repetition nudges triggered (`repeat_nudges == 0`).
  - 2 pts: 1 repetition nudge triggered.
  - 0 pts: $\ge 2$ repetition nudges triggered.
- **SQL & Query Health (5 Points)**:
  - 5 pts: All SQL queries and tool invocations executed with valid syntax and schema conformance.
  - -2 pts for every unhandled syntax error.
- **Step Economy (5 Points)**:
  - 5 pts: Concluded within optimal budget (2 to 4 reasoning steps).
  - 3 pts: Concluded at step 5.
  - 1 pt: Hit maximum iteration limit without resolving all hypotheses.

---

### Dimension 5: Executive Report Completeness & Actionability (10 Points)

Measures whether the generated report provides SOC leadership and incident response teams with immediately actionable deliverables:
- **Forensic Timeline Matrix (4 Points)**: A chronological Markdown table mapping timestamps, hosts, process names, action descriptions, and citing event IDs.
- **Indicator of Compromise (IOC) Matrix (3 Points)**: Structured artifact table detailing artifact type, value, context, and detection status.
- **Containment & Remediation Playbook (3 Points)**: Clear, bulleted, prioritized incident response actions (isolation, credential rotation, artifact eradication, hunting queries).

---

## 3. Scorecard Grade Scale

| Composite Score | Grade | Operational Assessment |
|:---|:---:|:---|
| **90 - 100** | **A+ (Exemplary)** | Forensic-grade investigation: accurate verdict, high recall, zero hallucination, comprehensive timeline & IOC tables. |
| **80 - 89** | **A (Superior)** | Strong investigation: accurate verdict and solid evidence grounding with minor omissions in background timeline. |
| **70 - 79** | **B (Acceptable)** | Actionable verdict with partial IOC recall or minor query inefficiencies. |
| **60 - 69** | **C (Deficient)** | Premature conclusion, significant telemetry gaps, or minor citation inconsistencies. |
| **< 60** | **F (Unacceptable)** | Mismatched verdict, hallucinated citations, or infinite tool repetition loop. |

---

## 4. Benchmark Execution Command

To run the full evaluation suite against all shipped attack scenarios and compute composite scorecards:

```powershell
.venv\Scripts\python.exe -m a1.benchmark --limit 5
```
