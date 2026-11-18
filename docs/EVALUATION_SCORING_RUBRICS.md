# DFIR Agentic Investigator: 100-Point Multi-Dimensional Evaluation Rubrics

## 1. Executive Summary & Objective

Binary accuracy ("did the agent say malicious?") is not a useful measure of a DFIR investigator. An agent can be right about the verdict while inventing citations, missing the attack chain, or flagging legitimate administration. The benchmark therefore scores six dimensions:

1. **Verdict & Boundary Accuracy** (20 points)
2. **Ground-Truth Evidence Retrieval** (25 points)
3. **Evidence Grounding & Claim Support** (20 points)
4. **Confidence Calibration** (10 points)
5. **Investigation Efficiency** (10 points)
6. **Report Quality & Actionability** (15 points)

The suite covers 10 built-in scenarios (7 malicious, 1 benign, 1 ambiguous, 1 incomplete-telemetry) plus optional AIT-ADS cases built from AMiner alert exports. The built-in dataset is supplied locally and is not stored in the repository. Every case is scored against a SQLite database, not against the agent's own narrative.

---

## 2. Multi-Dimensional Scoring Breakdown

| Dimension | Weight | What it measures |
|---|---:|---|
| 1. Verdict & boundary | 20 | Correct label and operational boundary |
| 2. Evidence retrieval | 25 | Weighted checklist coverage (20) + key-IOC coverage (5) |
| 3. Grounding & claim support | 20 | Cited IDs exist **and** support the surrounding claim |
| 4. Confidence calibration | 10 | Brier score, rescaled so a 0.5 guess earns zero |
| 5. Investigation efficiency | 10 | Work done, loops, retries, duplicate queries |
| 6. Report quality | 15 | Case-specific timeline, attribution, rationale, actions, caveats |
| **Total** | **100** | |

### Dimension 1 — Incident Verdict & Boundary (20 Points)

- **Verdict (15)**: exact match with `malicious`, `benign`, `suspicious`, or `inconclusive`.
- **Boundary (5)**: match with `confirmed_malicious`, `unconfirmed_malicious`, `benign`, `inconclusive`, or `telemetry_gap_inconclusive` (with documented normalization).
- **Fallback penalty**: a report recovered through the structured-output fallback receives 0 for this dimension.

**FP/FN**:
- **FP**: expected benign/inconclusive, agent says malicious/suspicious.
- **FN**: expected malicious, agent says anything other than malicious (this now includes `suspicious`).
- Ambiguous-case errors are counted separately via `is_ambiguous_error`.

The summary also emits the full verdict confusion matrix, per-label precision/recall/F1, macro F1, and bootstrap 95% confidence intervals for verdict accuracy and mean rubric score.

### Dimension 2 — Ground-Truth Evidence Retrieval (25 Points)

**Checklist coverage (20 points).** Each case has weighted `checks` in the local `groundtruth/eval_checks.json` (supplied with the dataset). A check is either matched by any of its phrases/indicators or not; critical checks receive weight 2, ordinary checks weight 1. Coverage is `sum(matched weights) / sum(all weights)`, and the score is `20 × coverage`. If a case has no checks, they are derived from `evidence_basis`. Evidence is searched in the report only, never in raw tool output or `investigation_memory`.

**Key IOC coverage (5 points).** Each case's `key_iocs` (paths, hashes, IPs, service names, command lines) is tested independently: `5 × covered / total`. A case with no `key_iocs` folds its full 25 points into checklist coverage. `distractors` are reported diagnostically but are not scored yet.

### Dimension 3 — Evidence Grounding & Claim Support (20 Points)

Every cited `evt-*`, `proc-*`, and `suri-*` identifier is resolved against SQLite. Process IDs may resolve through `processes` or through `events.process_entity_id`; `suri-*` IDs resolve through the canonical `events` view.

Existence is not enough: the cited row must share a distinctive token (host, process, path, IP, URL, etc.) with the sentence/line that cites it. A real ID attached to an unrelated claim is therefore **unsupported**, not verified.

```
base       = 20 × supported / total_cited
penalty    = min(10, 2 × hallucinated)
Grounding  = max(0, base − penalty)
```

- A fabricated ID costs a flat 2 points on top of losing its share of the ratio.
- An ID that exists but does not support its surrounding claim loses its share but is not called a hallucination.
- An unavailable table/view makes the citation **unverified**; it does not count as supported.
- No citations ⇒ 0.

Reported diagnostics: `hallucinated_citations`, `unsupported_citations`, `unverified_citations`, `total_citations`, `supported_citations`, and `citation_support_rate`.

### Dimension 4 — Confidence Calibration (10 Points)

Calibration uses the Brier score of the **verdict** outcome only (boundary is scored in Dimension 1, so a near-miss boundary is not double-penalized):

```
Brier = (confidence − outcome)²
Calibration = 10 × max(0, 1 − Brier / 0.25)
```

A correct verdict at 90% confidence scores 9.6; at 50% it scores 0; a wrong verdict at 90% also scores 0. Constant 0.5 confidence no longer earns 7.5 points. Missing confidence defaults to 0.5.

### Dimension 5 — Investigation Efficiency (10 Points)

- **Repetition freedom (3)**: 3 minus 1.2 per repetition nudge, floored at 0.
- **Step economy (3)**: 3 for 1–6 iterations, 2 for 7–9, 1 for more.
- **Retry/fallback (2)**: 2 with no report fallback/retry, 0.5 if a retry was used, 0 on fallback.
- **Query quality (2)**: requires at least one tool call; 2 for zero duplicate calls, 1 for 1–2, 0 for more.

A run with `iteration_count = 0` scores **0**, so "investigate nothing" is no longer maximally efficient.

### Dimension 6 — Report Quality & Actionability (15 Points)

- **Timeline (4)**: at least two dated table rows; full credit requires a citation in the timeline.
- **Case attribution (4)**: 2 for an expected host, 2 for a key IOC. Without case metadata, 2 for naming a concrete target.
- **Grounded rationale (3)**: a Reasoning/Analysis section with a citation; 1.5 for substantive prose without one.
- **Concrete actions (2)**: a response section with an action verb and a named target.
- **Caveats (2)**: a non-empty Evidence Gaps/Limitations section.

Headings and a table alone cannot reach 15/15.

### Scorecard Grade Scale

| Composite | Grade | Meaning |
|---:|:---:|---|
| 90–100 | **A+** | Forensic-grade: correct verdict, strong checklist/IOC coverage, supported citations |
| 80–89 | **A** | Strong, with minor evidence or reporting gaps |
| 70–79 | **B** | Actionable but incomplete |
| 60–69 | **C** | Premature conclusion or significant gaps |
| <60 | **F** | Wrong verdict, fabricated evidence, or no usable report |

---

## 3. Reliability Notes

- **Scoring is deterministic; the agent is not.** A single run per case is a snapshot. For a leaderboard, run each case at least 3–5 times and compare confidence intervals, not one composite.
- The summary prints 95% bootstrap CIs for verdict accuracy and mean score. With four cases those intervals are necessarily wide; treat them as uncertainty bounds, not precision estimates.
- Grounding claim support is a lexical heuristic, not semantic entailment. It blocks obvious "real ID, unrelated claim" citations but cannot prove that an inference is correct.
- Checklist phrases are curated per case; inspect `eval_checks.json` before comparing across datasets. AIT-ADS cases use attack-step anchors and are coarser than the hand-written built-in checks.
- The 100-point weights are design choices, not empirically validated against human experts. Report per-dimension scores alongside the composite.
- AIT-ADS cases only include AMiner anomaly records, not full packet/process telemetry. They test triage under telemetry limits, not endpoint forensics.

---

## 4. Benchmark Scenarios

| ID | Class | Database | Focus |
|:---|:---|:---|:---|
| **ATK-A** | Malicious | `attack_lateral_movement.db` | LSASS dump, SMB, NTLM logon, service persistence |
| **ATK-B** | Malicious | `attack_data_exfiltration.db` | Staged archive, scheduled task, outbound HTTPS, cleanup |
| **ATK-C** | Malicious | `ransomware_attack_complete_ecs.db` | Phishing, shadow-copy deletion, LockBit encryption |
| **ATK-D** | Malicious | `attack_lotl_fileless.db` | LOLBins, encoded PowerShell, in-memory activity |
| **ATK-E** | Malicious | `wazuh_lotl_attack_dataset.db` | Wazuh SIEM/EDR, LotL commands, SAM access |
| **ATK-F** | Malicious | `suricata_c2_intrusion.db` | Suricata alerts, CobaltStrike beaconing, SMB recon |
| **ATK-G** | Malicious | `attack_supply_chain.db` | 32-endpoint supply-chain compromise |
| **BEN-A** | Benign | `benign_admin_activity.db` | Backup script, SMB flows, registry checks |
| **AMB-A** | Ambiguous | `attack_lotl_fileless.db` | Dual-use developer tooling |
| **INC-A** | Inconclusive | `attack_lateral_movement.db` | Missing parent/network telemetry |
| **AIT-FOX** | Malicious (external) | `benchmark_ait/ait_fox.db` | AMiner anomaly alerts around a multi-step attack |
| **AIT-HARRISON** | Malicious (external) | `benchmark_ait/ait_harrison.db` | Same adapter, different environment |

AIT-ADS source files are not redistributed. Point the runner at a local extract of `ait_ads`:

```powershell
.venv\Scripts\python.exe -m a1.benchmark --split ait --limit 2 `
  --ait-ads-dir C:\Users\you\Downloads\ait_ads `
  --out bench_ait.json
```

Use `--ait-scenarios fox,harrison` to select scenarios and `--ait-rebuild` after changing the adapter. Generated databases go to `benchmark_ait/` (git-ignored).

---

## 5. Running Evaluations

```powershell
# All 10 built-in scenarios (requires local dataset; limit defaults to 0 = all)
.venv\Scripts\python.exe -m a1.benchmark --split all --out bench_all.json

# Two built-in scenarios
.venv\Scripts\python.exe -m a1.benchmark --split dev --limit 2 --out bench_dev.json

# AIT-ADS cases
.venv\Scripts\python.exe -m a1.benchmark --split ait --limit 2 `
  --ait-ads-dir C:\path\to\ait_ads --out bench_ait.json

# Benchmark through the CLI
.venv\Scripts\python.exe -m a1.cli --benchmark --limit 5

# Ablation experiments
.venv\Scripts\python.exe -m a1.experiment
```

`--out` writes per-case rubrics, reports, and aggregate metrics as JSON. The console summary prints verdict/boundary accuracy, macro F1, FPR/FNR, checklist/IOC coverage, citation support, Brier score, and 95% CIs.

---

## 6. Latest Measured Results (4 Cases)

Command:

```powershell
.venv\Scripts\python.exe -m a1.benchmark --split dev --limit 2 --out bench_final_existing.json
.venv\Scripts\python.exe -m a1.benchmark --split ait --limit 2 `
  --ait-ads-dir C:\Users\vanam\Downloads\ait_ads --out bench_final_ait.json
```

Provider/model: opencode `glm-5.3-flash`; one run per case, temperature-controlled but not deterministic. Snapshot date: 2026-11-18.

| Case | Verdict / Boundary | Verdict | Recall | Grounding | Calib. | Effic. | Report | Composite |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| ATK-A | malicious / confirmed (match) | 20 | 25.0 | 17.6 (1/48) | 9.4 | 8.0 | 15.0 | **95.0 (A+)** |
| ATK-B | malicious / confirmed (match) | 20 | 25.0 | 20.0 (0/51) | 9.7 | 10.0 | 15.0 | **99.7 (A+)** |
| AIT-FOX | malicious / confirmed (match) | 20 | 21.5 | 20.0 (0/34) | 9.7 | 10.0 | 15.0 | **96.2 (A+)** |
| AIT-HARRISON | inconclusive / inconclusive (miss) | 0 | 13.3 | 19.4 (0/34) | 0.0 | 6.8 | 13.5 | **53.0 (F)** |
| **Mean** | 3/4 verdict & boundary | 15.0 | 21.2 | 19.3 | 7.2 | 8.7 | 14.6 | **86.0** |

Descriptive aggregates across the four cases: evidence precision **98.8%**, evidence recall **84.8%**, evidence F1 **90.0%**, checklist coverage **85.2%**, key-IOC coverage **83.4%**, citation support **98.8%**, mean Brier **0.136**, structured-output fallbacks **0/4**.

Per-split summary:

- Existing two: mean **97.3/100** (95% CI 95.0–99.7), 2/2 verdict/boundary, precision 99.0%, recall 100%, F1 99.4%, Brier 0.010.
- AIT two: mean **74.6/100** (95% CI 53.0–96.2), 1/2 verdict/boundary, precision 98.6%, recall 70.5%, F1 80.6%, Brier 0.262, FNR 50%.

**Interpretation.** ATK-A and ATK-B are strong attacks with complete endpoint telemetry; the only grounding deduction was one unsupported citation each in ATK-A and an earlier ATK-B run. AIT-FOX is also detected, but AIT-HARRISON is reported `inconclusive`: its AMiner extract contains first-seen log-format anomalies without process, DNS, or authentication telemetry, so the agent correctly describes a telemetry gap rather than inventing a chain. That is the honest result of the adapter, not a fabricated pass. FPR is not estimable from this slice because no benign case was included; run BEN-A with `--split eval` for that.

**Known limitations.** One run per case; four cases do not support a leaderboard claim. Claim support is lexical. AIT checks are coarse. The rubric weights are asserted, not validated by human raters.

---

## 7. Changes From Rubric v2

- Replaced free-text token recall with case-specific weighted checks plus separate IOC coverage.
- Grounding now checks the claim around a citation, not just ID existence; fabricated IDs cost 2 points each.
- Calibration is rescaled so a 0.5 guess earns 0 and a 0.9 correct verdict earns 9.6.
- Efficiency gives zero credit for zero investigation and requires tool calls for query-quality points.
- Report quality scores timeline citations, case attribution, rationale, concrete actions, and caveats instead of heading/table presence.
- FN now includes `suspicious` for malicious cases; the summary adds a full confusion matrix, per-label metrics, macro F1, ambiguous-error tracking, and bootstrap CIs.
- Added AIT-ADS ingestion across AMiner JSONL with cached SQLite databases and attack-window labels.
