# Comprehensive Project Audit, Issues Ledger & Architecture Report
**Project:** `A1: Autonomous DFIR Investigation Agent`  
**Date of Audit:** November 2026  
**Scope:** Full repository source code (`src/a1/`), test suites (`tests/`), telemetry databases & ground truth (`endpoint_security_dataset_expanded_corrected/`), operational scripts (`scripts/`), documentation (`docs/`, `ui.md`, `README.md`, `ARCHITECTURE.md`), and web surface (`src/a1/web/`).

---

## Table of Contents
1. [Executive Summary & System Status](#1-executive-summary--system-status)
2. [Catalog of Misinformed, Contradictory & Stale Documentation](#2-catalog-of-misinformed-contradictory--stale-documentation)
   - [2.1 Configuration & Environment Variable Mismatches](#21-configuration--environment-variable-mismatches)
   - [2.2 Stale Architecture & Test Suite Counts](#22-stale-architecture--test-suite-counts)
   - [2.3 Phantom Dataset Architecture & Spec Inconsistencies](#23-phantom-dataset-architecture--spec-inconsistencies)
   - [2.4 UI Design Record vs. Shipped DOM Implementation](#24-ui-design-record-vs-shipped-dom-implementation)
   - [2.5 Missing Web API Endpoints in Documentation](#25-missing-web-api-endpoints-in-documentation)
3. [Prompt Biases, Prompt Misinformation & Benchmark Overfitting](#3-prompt-biases-prompt-misinformation--benchmark-overfitting)
   - [3.1 Inconclusive Verdict Boundary Three-Way Collision](#31-inconclusive-verdict-boundary-three-way-collision)
   - [3.2 Triage Prompt Overfitting to Lateral Movement (ATK-A)](#32-triage-prompt-overfitting-to-lateral-movement-atk-a)
   - [3.3 Handcrafted Benchmark Nudge Guards in Investigator Node](#33-handcrafted-benchmark-nudge-guards-in-investigator-node)
4. [In-Depth Technical Shortcomings, Pipeline Gaps & Newly Discovered Critical Flaws](#4-in-depth-technical-shortcomings-pipeline-gaps--newly-discovered-critical-flaws)
   - [4.1 Critical Type Mismatch in Validator Node Skipping All Correlation Citations](#41-critical-type-mismatch-in-validator-node-skipping-all-correlation-citations)
   - [4.2 Conversational Amnesia in Web Chat Copilot (`/api/chat`)](#42-conversational-amnesia-in-web-chat-copilot-apichat)
   - [4.3 Mock-Driven vs. Live Ablation Incoherence in `experiment.py` and `graph.py`](#43-mock-driven-vs-live-ablation-incoherence-in-experimentpy-and-graphpy)
   - [4.4 Database Instance Sprawl & Decoupled Path State](#44-database-instance-sprawl--decoupled-path-state)
   - [4.5 Lossy Tool Message Slicing Cutting Off Evidentiary Anchors](#45-lossy-tool-message-slicing-cutting-off-evidentiary-anchors)
   - [4.6 Hardcoded Frontend Suggestions Lacking Dynamic Dataset Discovery](#46-hardcoded-frontend-suggestions-lacking-dynamic-dataset-discovery)
   - [4.7 Orphaned `planner_node` Function in `planner_node.py`](#47-orphaned-planner_node-function-in-planner_nodepy)
   - [4.8 Inconsistent `InvestigationState` TypedDict Initialization](#48-inconsistent-investigationstate-typeddict-initialization)
   - [4.9 Exception String Scraping Instead of Typed Network Exception Handling](#49-exception-string-scraping-instead-of-typed-network-exception-handling)
   - [4.10 HTTP 429 / Rate Limit & Quota Omission in Retry Logic](#410-http-429--rate-limit--quota-omission-in-retry-logic)
   - [4.11 Concurrency Race Conditions & Threading Misuse in Web Server](#411-concurrency-race-conditions--threading-misuse-in-web-server)
   - [4.12 Quadratic ($O(K^2)$) Tool Reprocessing & Redundant JSON Deserialization](#412-quadratic-ok2-tool-reprocessing--redundant-json-deserialization)
   - [4.13 Baseline Context Pipeline Analysis & Test Suite Gap](#413-baseline-context-pipeline-analysis--test-suite-gap)
   - [4.14 Database Schema Contradictions & Raw Direct Query Failure](#414-database-schema-contradictions--raw-direct-query-failure)
   - [4.15 Orphaned `InvestigationTrace` Module in `investigation_trace.py`](#415-orphaned-investigationtrace-module-in-investigation_tracepy)
5. [Redundant Code, Dead Code & Asset Bloat](#5-redundant-code-dead-code--asset-bloat)
6. [Prioritized Remediation & Action Plan](#6-prioritized-remediation--action-plan)
7. [Remaining Questions & Gaps](#7-remaining-questions--gaps)

---

## 1. Executive Summary & System Status

`A1` is an autonomous Digital Forensics and Incident Response (DFIR) investigation engine built with **LangGraph**, **LangChain**, and **SQLite**. The system ingests raw security alerts, normalizes time windows and host identities, formulates competing investigation hypotheses, executes queries over endpoint telemetry databases using 8 specialized forensic tools, constructs an explicit **Evidence Graph**, validates citations against raw SQLite tables, and generates structured, audit-ready DFIR reports with verifiable verdicts and confidence scores.

### Verification Status
- **Test Suite:** `pytest` collects and executes **100 tests** across 14 test modules; **all 100 tests pass** (verified via `.\.venv\Scripts\python.exe -m pytest` in 3.56s).
- **Smoke Tests:** Standalone `scripts/smoke_test.py` executes **17 end-to-end checks** covering tool registration, database querying, process tree traversal, anti-loop circuit breakers, and read-only integrity; **all 17 checks pass**.
- **Shipped Telemetry Databases:** 8 standalone SQLite databases ship in `endpoint_security_dataset_expanded_corrected/` with 10 evaluator ground truth JSON specs in `groundtruth/`. 
- **Exact Shipped Event Count:** The 8 shipped databases contain a cumulative total of **4,490 telemetry events** (correcting earlier drafts that cited 4,244 events, and correcting stale dataset documentation citing 1,050 events).

#### Verified Database Breakdown (4,490 Total Events)
| Database File | Primary Event Table | Telemetry Events | Additional Entities / Notes |
|:---|:---|:---:|:---|
| `attack_data_exfiltration.db` | `events` | 83 | 24 processes, 14 files, 24 network conns, 4 registry events, 1 host, 1 user |
| `attack_lateral_movement.db` | `events` | 127 | 37 processes, 19 files, 26 network conns, 14 registry events, 2 hosts, 3 users |
| `attack_lotl_fileless.db` | `events` | 708 | Monolithic raw table; lacks separate relational entity tables |
| `attack_supply_chain.db` | `events` | 1,890 | 571 processes, 382 files, 559 network conns, 170 registry events, 32 hosts, 32 users |
| `benign_admin_activity.db` | `events` | 7 | 1 process, 2 files, 1 network conn, 1 registry event, 2 hosts, 2 users |
| `ransomware_attack_complete_ecs.db` | `events` | 1,004 | 604 processes, 401 files, 4 hosts, 5 users (0 network conns, 0 registry events) |
| `suricata_c2_intrusion.db` | `suricata_events` | 59 | 3 network assets (no physical `events` table on disk; synthesized via view) |
| `wazuh_lotl_attack_dataset.db` | `wazuh_events` | 612 | 5 hosts, 5 users (no physical `events` table on disk; synthesized via view) |
| **Total Across 8 Databases** | | **4,490** | **Complete Telemetry Corpus** |

*(Note on discrepancy resolution: 3,819 rows exist in physical `events` tables + 59 in `suricata_events` + 612 in `wazuh_events` = 4,490 events. Older drafts reported 4,244 by omitting non-standard event tables or miscounting partial views).*

### Architecture Workflow
```
[Raw Alert Input]
       │
       ▼
[1. Alert Prep Node] (alert_prep_node.py)
       │  - Deterministic regex entity extraction (hostnames, IPs, accounts, artifacts)
       │  - Hostname resolution against SQLite `hosts` table
       │  - UTC time-window parsing & clamping
       ▼
[2. Triage Node] (triage_node.py)
       │  - Emits structured TriagePlan (2–4 competing hypotheses)
       │  - Seeds initial target entities
       ▼
[3. Investigator Node Loop] (investigator_node.py) ◄────────┐
       │  - ReAct tool invocation loop (binds 8 DFIR tools)  │
       │  - Evaluates heuristic repetition guards            │ (Tool Results)
       │  - Dynamic hypothesis expansion (persistence, etc.) │
       │  - Calls Adaptive Planner for action scoring        │
       ▼                                                     │
[Conditional Route: should_continue] ────────────────────────┘
       │  (Routes to ToolNode when tool calls pending; loops until >= 2 steps;
       │   advances to packing upon max steps, circuit break, or completion)
       ▼
[4. Evidence Packing Node] (evidence_packing_node.py)
       │  - Normalizes tool outputs from message history
       │  - Deduplicates events by event_id
       │  - Filters events to scoped time window
       │  - Builds chronological timeline & entity sets
       │  - Emits state["evidence"] and pack["scoped_evidence"]
       ▼
[5. Correlation Node] (correlation_node.py)
       │  - Structured CorrelationAndGapAnalysis
       │  - Evaluates deterministic baseline anomalies via assess_activity_context()
       │  - Confirms/refutes triage hypotheses
       │  - Identifies telemetry gaps & benign explanations
       ▼
[6. Validator Node] (validator_node.py)
       │  - Deterministic SQL queries to check event IDs & process IDs
       │  - Audits causal relationship links (parent-child, network)
       │  - Flags invalid, unverified, or adversarial telemetry
       ▼
[7. Report Node] (report_node.py)
       │  - Synthesizes IncidentVerdict (verdict, boundary, confidence)
       │  - Generates Executive Summary, Timeline Matrix, IOC Table, Playbook
       ▼
[Structured Incident Report & Verdict Output]
```

---

## 2. Catalog of Misinformed, Contradictory & Stale Documentation

### 2.1 Configuration & Environment Variable Mismatches
* **Files:** [README.md:258-265](file:///c:/Users/vanam/Downloads/ai-musefix/README.md#L258-L265), [src/a1/config.py:36-50](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/config.py#L36-L50), [.env.example:3-19](file:///c:/Users/vanam/Downloads/ai-musefix/.env.example#L3-L19).
* **Misinformed & Contradictory Info:**
  1. The Configuration Reference table in `README.md` (lines 258-265) states:
     ```markdown
     | Variable | Default | Purpose |
     | `LLM_PROVIDER` | `ollama` | `ollama` or `openai` |
     | `OLLAMA_MODEL_NAME` | `gemma4:31b` | Ollama model tag |
     | `OLLAMA_BASE_URL` | `https://ollama.com/api` | Base URL |
     ```
     This contradicts both `config.py` and `.env.example`:
     - In [src/a1/config.py:36](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/config.py#L36), `LLM_PROVIDER = os.getenv("LLM_PROVIDER", "opencode").lower()`. OpenCode is the actual system default, not Ollama.
     - In [src/a1/config.py:39-41](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/config.py#L39-L41), default model is `deepseek-v4.1-flash` at `https://opencode.ai/inference/go/openai/v1`.
     - In [src/a1/config.py:44](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/config.py#L44), `OLLAMA_MODEL_NAME = os.getenv("OLLAMA_MODEL_NAME", "llama3.1")`. The default is `llama3.1`, not `gemma4:31b`.
     - In [src/a1/config.py:45](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/config.py#L45), `os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")`. The default is localhost, not Ollama Cloud.
     - The table in `README.md` completely omits OpenCode settings (`OPENCODE_MODEL_NAME`, `OPENCODE_BASE_URL`, `OPENCODE_API_KEY`), despite [README.md:11](file:///c:/Users/vanam/Downloads/ai-musefix/README.md#L11) stating that OpenCode is the default provider.

### 2.2 Stale Architecture & Test Suite Counts
* **Files:** [ARCHITECTURE.md:166](file:///c:/Users/vanam/Downloads/ai-musefix/ARCHITECTURE.md#L166), [ARCHITECTURE.md:145-151](file:///c:/Users/vanam/Downloads/ai-musefix/ARCHITECTURE.md#L145-L151), [README.md:83](file:///c:/Users/vanam/Downloads/ai-musefix/README.md#L83).
* **Misinformed & Stale Info:**
  1. `ARCHITECTURE.md` line 166 states:
     `|-- tests/ [Test Suite (92 Tests)]`
     This is stale. The test suite contains 100 passing tests across 14 modules (as documented in `README.md` line 83 and verified via `pytest`).
  2. In `ARCHITECTURE.md` Section 2 (lines 145-151) and Section 3, the file catalog for `src/a1/web/static/` lists only `index.html`, `app.js`, `forensic-graph.js`, and `style.css`.
     It omits newly introduced production frontend components:
     - `src/a1/web/static/evidence-tree.js` (653 lines, renders the primary per-host entity hierarchy)
     - `src/a1/web/static/process-links.js` (444 lines, renders the process link board)
     - `src/a1/web/static/vendor/marked.min.js` and `purify.min.js` (client-side markdown parsing and sanitization)
  3. Neither `README.md` nor `ARCHITECTURE.md` includes the newly added UI documentation file `ui.md` in their directory tree structure.

### 2.3 Phantom Dataset Architecture & Spec Inconsistencies
* **Files:** [endpoint_security_dataset_expanded_corrected/schema.md:8-9, 82, 101-117](file:///c:/Users/vanam/Downloads/ai-musefix/endpoint_security_dataset_expanded_corrected/schema.md#L8-L117), [endpoint_security_dataset_expanded_corrected/README.md:23](file:///c:/Users/vanam/Downloads/ai-musefix/endpoint_security_dataset_expanded_corrected/README.md#L23).
* **Misinformed & Phantom Info:**
  1. `schema.md` lines 8-9: Claims the dataset format is `"Encoding: UTF-8 JSONL without a byte order mark (BOM); every line must parse under strict UTF-8 decoding"`.
     No JSONL dataset files exist in the repository; the telemetry is distributed entirely as 8 standalone SQLite `.db` files.
  2. `schema.md` line 82: States `"Case-level evaluation labels are stored in case_labels.json and in scenario ground truth files"`.
     `case_labels.json` does not exist on disk. Evaluator labels are derived dynamically from `groundtruth/groundtruth_*.json`.
  3. `schema.md` lines 101-104: Asserts that `"For every row, raw_json is identical to the corresponding record in events.jsonl"`.
     `events.jsonl` does not exist.
  4. `schema.md` lines 108-117: Describes an obsolete multi-database bundle layout:
     `endpoint_security.db is the complete evaluation database and contains the protected tables ground_truth_events and scenario_metadata... agent_bundle/agent_endpoint_security.db is the agent-facing subset.`
     Neither `endpoint_security.db` nor `agent_bundle/` exists anywhere in the repository. Shipped databases are completely separate per scenario (e.g. `attack_lateral_movement.db`, `benign_admin_activity.db`, etc.), and ground truth is stored outside SQLite in JSON files.
  5. `endpoint_security_dataset_expanded_corrected/README.md` line 23 states:
     `Events: 1050 (original bundle; the two shipped attack databases hold a subset)`
     This is obsolete from an earlier draft when only two databases were shipped. The 8 shipped databases contain a total of **4,490 events**.

### 2.4 UI Design Record vs. Shipped DOM Implementation
* **Files:** [ui.md:27, 73, 110-115](file:///c:/Users/vanam/Downloads/ai-musefix/ui.md#L27), [src/a1/web/static/index.html:13-89, 91-126](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/web/static/index.html#L13-L126).
* **Misinformed & Contradictory Info:**
  1. `ui.md` lines 27 and 73 specify a 3-pane side-by-side desktop layout:
     ```
     ┌ rail 264 ┬──────── bench ────────┬── case map (52vw, max 760) ──┐
     │ dataset  │ topbar: case · stamp  │ Map | Events | Report   status│
     │ surface  │                       │ toolbar: search zoom fit reset│
     │ case log │ record of the run     │ canvas            │ inspector│
     └──────────┴───────────────────────┴──────────────────────────────┘
     ```
     In the shipped code ([src/a1/web/static/index.html:13-89](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/web/static/index.html#L13-L89)), there is **no persistent rail pane**. The dataset selector, entity counts, and case log were collapsed into a header popup menu (`#caseMenu` under `#caseBtn`).
  2. `ui.md` lines 110-115 lists only 4 files (`index.html`, `style.css`, `app.js`, `forensic-graph.js`), omitting `evidence-tree.js` and `process-links.js`, which are loaded by `index.html` (lines 216-217) and provide the two toggleable layout modes (`#mapViewTree` and `#mapViewLinks`).

### 2.5 Missing Web API Endpoints in Documentation
* **Files:** [ARCHITECTURE.md:335-341](file:///c:/Users/vanam/Downloads/ai-musefix/ARCHITECTURE.md#L335-L341), [src/a1/web/server.py:700, 772](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/web/server.py#L700).
* **Misinformed Info:**
  - `ARCHITECTURE.md` documents only 7 API endpoints: `/api/status`, `/api/models`, `/api/models/set`, `/api/databases`, `/api/databases/set`, `/api/investigate`, and `/api/cancel`.
  - It completely omits `/api/events` (which serves raw database events to the client-side graph builder and events table) and `/api/chat` (the conversational copilot endpoint).

---

## 3. Prompt Biases, Prompt Misinformation & Benchmark Overfitting

### 3.1 Inconclusive Verdict Boundary Three-Way Collision
* **Files:** [src/a1/prompts/investigator.py:86](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/prompts/investigator.py#L86), [src/a1/prompts/report.py:27](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/prompts/report.py#L27), [src/a1/nodes/report_node.py:76](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/report_node.py#L76), [src/a1/benchmark.py:232-247](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/benchmark.py#L232-L247), [endpoint_security_dataset_expanded_corrected/groundtruth/groundtruth_incomplete_A_missing_telemetry.json:13](file:///c:/Users/vanam/Downloads/ai-musefix/endpoint_security_dataset_expanded_corrected/groundtruth/groundtruth_incomplete_A_missing_telemetry.json#L13).
* **The Flaw:**
  A three-way architectural collision exists regarding inconclusive boundary values:
  1. In `investigator.py` line 86, the prompt instructs the investigator model:
     `* INCONCLUSIVE (boundary: unconfirmed_malicious): Uncorrelated events without causal link`
  2. In `report.py` line 27, the prompt instructs the report synthesizer model:
     `- If verdict is inconclusive, verdict_boundary MUST BE inconclusive or telemetry_gap_inconclusive.`
  3. In `report_node.py` line 76, `IncidentVerdict` restricts the field type to:
     `verdict_boundary: Literal["confirmed_malicious", "unconfirmed_malicious", "benign", "inconclusive"]`
     Notice that `telemetry_gap_inconclusive` is **not an allowed Literal value**. Line 105 / `_match_verdict_boundary` coerces `"telemetry_gap_inconclusive"` into `"inconclusive"`.
  4. In `groundtruth_incomplete_A_missing_telemetry.json` line 13:
     `"expected_verdict": "inconclusive", "verdict_boundary": "telemetry_gap_inconclusive"`
  5. In `benchmark.py` lines 232-246, `_normalize_boundary` only maps `"confirmed_benign"` to `"benign"`. It does NOT normalize `"telemetry_gap_inconclusive"` to `"inconclusive"`.
* **Impact:** When `benchmark.py` checks `_normalize_boundary(agent_boundary) == _normalize_boundary(expected_boundary)` (line 245), `"inconclusive" == "telemetry_gap_inconclusive"` evaluates to **`False`**. An agent investigating scenario `INC-A` is structurally guaranteed to lose 5 points on the verdict boundary, whether it follows `investigator.py` (which emits `unconfirmed_malicious`) or `report_node.py` (which emits `inconclusive`).

### 3.2 Triage Prompt Overfitting to Lateral Movement (ATK-A)
* **Files:** [src/a1/prompts/triage.py:18-30](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/prompts/triage.py#L18-L30).
* **The Flaw:**
  - Although the header comment in `triage.py` (lines 1-5) claims scenario-specific examples were removed, lines 18-30 hardcode instructions that force lateral movement reasoning:
    ```text
    1. EXTRACT ALL ENTITIES & CONTEXT:
       - Identify every mentioned host: If the alert involves remote connections or lateral movement, extract BOTH the TARGET host... AND the SOURCE host...
    2. FORMULATE MULTI-STAGE HYPOTHESES:
       - Suspicious Hypothesis (Lateral Movement & Target Host Compromise)...
       - Suspicious Hypothesis (Source Host Staging & Credential Access)...
    3. INITIAL INVESTIGATION TARGETS:
       - First target: Query authentication on the TARGET host...
       - Second target: Check the SOURCE host for what process initiated the connection...
    ```
  - **Impact:** When investigating alerts with no lateral movement—such as ransomware document execution on a single endpoint (`ATK-C`), data exfiltration via HTTPS (`ATK-B`), benign scheduled backup scripts (`BEN-A`), or developer utility executions (`AMB-A`)—the triage specialist prompt biases the LLM into generating multi-host lateral movement hypotheses and attempting to query non-existent source/target pairs.

### 3.3 Handcrafted Benchmark Nudge Guards in Investigator Node
* **Files:** [src/a1/nodes/investigator_node.py:65-150, 153-197, 199-252, 713-805](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/investigator_node.py#L65-L252).
* **The Flaw:**
  - `investigator_node.py` contains 3 specialized heuristic checker functions:
    1. `_missing_smb_auth_correlation` (lines 65-150): Detects NTLM logon type 3 failure/success sequences and checks for matching outbound TCP 445 SMB connections. If missing, it injects a specific prompt directing the model to query `search_timeline(host_id=..., category='network')` for TCP/445 events. This is custom-tailored to solve benchmark scenario `ATK-A`.
    2. `_missing_requested_auth_hosts` (lines 153-197): Injects a nudge to force `search_timeline(category='authentication')` on specific hosts.
    3. `_missing_requested_archive_files` (lines 199-252): Searches alert text for `.7z`, `.zip`, `.rar`, and checks if a file creation event was observed; if not, injects a nudge to search `category='file', keyword='{archive_name}'`. This is custom-tailored to solve benchmark scenario `ATK-B`.
  - **Impact:** Rather than exhibiting true autonomous, generalized forensic reasoning, the agent relies on hand-crafted heuristic shortcuts designed to maximize scores on specific benchmark cases.

---

## 4. In-Depth Technical Shortcomings, Pipeline Gaps & Newly Discovered Critical Flaws

### 4.1 Critical Type Mismatch in Validator Node Skipping All Correlation Citations
* **Files:** [src/a1/nodes/validator_node.py:197-203](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/validator_node.py#L197-L203), [src/a1/nodes/correlation_node.py:11-26](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/correlation_node.py#L11-L26), [src/a1/state.py:12](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/state.py#L12), [tests/test_conservative_failures.py:19](file:///c:/Users/vanam/Downloads/ai-musefix/tests/test_conservative_failures.py#L19).
* **Code Evidence:**
  In `validator_node.py`:
  ```python
  # From confirmed correlations
  for corr in state.get("confirmed_correlations") or []:
      if isinstance(corr, dict):
          corr_text = str(corr)
          extracted = extract_cited_ids_from_text(corr_text)
          cited_event_ids.update(extracted["event_ids"])
          cited_process_ids.update(extracted["process_ids"])
  ```
  In `correlation_node.py`:
  ```python
  class CorrelationAndGapAnalysis(BaseModel):
      confirmed_correlations: List[str] = Field(default_factory=list, ...)
  ```
* **The Root Cause & Defect:**
  In `state.py` line 12, `InvestigationState` documents:
  `confirmed_correlations: Optional[List[dict]]`
  Because `state.py` and `test_conservative_failures.py` typed `confirmed_correlations` as a list of dictionaries, the developer of `validator_node.py` guarded citation extraction with `if isinstance(corr, dict):`.
  However, in `correlation_node.py` line 12, `CorrelationAndGapAnalysis` produces `confirmed_correlations` as a `List[str]` (and line 26 coerces any dictionary inputs to JSON strings).
  Because every element `corr` is a string, `isinstance(corr, dict)` **always evaluates to `False`**.
* **Impact:** **100% of event IDs and process IDs cited in `confirmed_correlations` are silently skipped by the deterministic validator.** Hallucinated citations or unverified entities introduced during correlation analysis completely escape SQLite validation.

### 4.2 Conversational Amnesia in Web Chat Copilot (`/api/chat`)
* **Files:** [src/a1/web/server.py:606-625](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/web/server.py#L606-L625).
* **Code Evidence:**
  ```python
  llm = get_llm(temperature=0.1, provider=provider, model=model)
  prompt_msgs = [
      SystemMessage(content=system_prompt),
      HumanMessage(content=message),
  ]

  _safe_queue_put(loop, queue, {"type": "start", "session_id": session_id, "query": message})
  response = invoke_with_network_retry(llm, prompt_msgs)
  ...
  if session_data:
      session_data.setdefault("messages", []).append({"role": "user", "content": message})
      session_data["messages"].append({"role": "assistant", "content": cleaned or raw_text})
  ```
* **The Defect:**
  While lines 621-623 append each user inquiry and assistant reply to `session_data["messages"]`, lines 607-610 construct `prompt_msgs` using **only** the `system_prompt` and the current turn's `HumanMessage(content=message)`. The accumulated message turns in `session_data["messages"]` are **never loaded** into `prompt_msgs`.
* **Impact:** Multi-turn conversation suffers from total amnesia. If an analyst asks "Why is that process suspicious?" followed by "What network connections did it make?", the copilot cannot resolve "it" because it only receives the latest question in complete isolation from the previous turn.

### 4.3 Mock-Driven vs. Live Ablation Incoherence in `experiment.py` and `graph.py`
* **Files:** [src/a1/experiment.py:14-21, 31-57, 60-91](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/experiment.py#L14-L91), [src/a1/graph.py:20-23, 33-35](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/graph.py#L20-L35).
* **Code Evidence:**
  In `experiment.py`:
  ```python
  @dataclass
  class ExperimentConfig:
      name: str
      enable_evidence_graph: bool = True
      enable_adaptive_planner: bool = True
      enable_validator: bool = True
      enable_baseline_context: bool = True
      max_steps: int = 12
  ```
  In `graph.py`:
  ```python
  def create_investigation_graph(config: Optional[Any] = None):
      ...
      enable_validator = True
      if config is not None:
          enable_validator = getattr(config, "enable_validator", True)
      ...
      if enable_validator:
          workflow.add_node("validate", validator_node)
  ```
* **The Defect:**
  `create_investigation_graph` only checks `enable_validator`. The configuration flags `enable_evidence_graph`, `enable_adaptive_planner`, and `enable_baseline_context` are **completely ignored** during graph compilation and node execution.
* **Impact:**
  - In **Live Mode** (`--live`), Stage A (Baseline), Stage B (+EvidenceGraph), and Stage C (+AdaptivePlanner) execute the exact same codebase with all augmentations running identically. The ablation study does not actually measure the contribution of individual subsystems in live execution.
  - In **Mock Mode** (`_simulate_mock_case_state`), the scores are artificially constructed through hardcoded formulas:
    ```python
    hallucinated = 0 if config.enable_validator else 2
    recall_factor = 1.0 if config.enable_evidence_graph else 0.7
    iteration_count = 4 if config.enable_adaptive_planner else 7
    ```
    This produces fabricated ablation results (e.g. `docs/experiments/ablation_study_results.json`) that do not reflect real experimental empirical data.

### 4.4 Database Instance Sprawl & Decoupled Path State
* **Files:** [src/a1/nodes/alert_prep_node.py:219](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/alert_prep_node.py#L219), [src/a1/nodes/investigator_node.py:43](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/investigator_node.py#L43), [src/a1/config.py:58-84](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/config.py#L58-L84), [src/a1/web/server.py:661, 702](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/web/server.py#L661).
* **The Defect:**
  1. `db.py` implements a thread-safe singleton cache with locking (`get_active_db()`). However, `alert_prep_node.py` (line 219) instantiates `EndpointDatabase(get_db_path())` directly, and `investigator_node.py` (line 43) calls `EndpointDatabase().get_schema()`. These bypass the active database cache and thread locks.
  2. `cfg.DB_PATH` is initialized at module load time ([src/a1/config.py:61](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/config.py#L61)). When `server.py` handles `/api/status`, it reads `cfg.DB_PATH`, but `/api/events` calls `cfg.get_db_path()`. If `ENDPOINT_DB_PATH` is modified in the environment without calling `set_active_database()`, the status endpoint reports stale database metadata.

### 4.5 Lossy Tool Message Slicing Cutting Off Evidentiary Anchors
* **Files:** [src/a1/nodes/investigator_node.py:667-678](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/investigator_node.py#L667-L678).
* **Code Evidence:**
  ```python
  for idx, m in enumerate(state["messages"]):
      if idx < total_msgs - 3 and getattr(m, "type", "") == "tool" and len(str(getattr(m, "content", ""))) > 1000:
          raw_str = str(m.content)
          summary_info = summarize_tool_output(raw_str)
          trimmed = f"[Summary: {summary_info}]\n[Telemetry sample]:\n" + raw_str[:700] + "\n... [older telemetry output condensed to preserve context]"
          pruned_history.append(ToolMessage(content=trimmed, tool_call_id=getattr(m, "tool_call_id", ""), name=getattr(m, "name", "tool")))
  ```
* **The Defect:**
  Arbitrarily slicing `raw_str[:700]` cuts through the middle of serialized JSON records.
* **Impact:**
  - Produces malformed JSON fragments in the LLM conversation context.
  - Slices off subsequent records containing critical `event_id`, `process_entity_id`, or `hash` values, preventing the LLM from seeing valid evidence returned in earlier steps.

### 4.6 Hardcoded Frontend Suggestions Lacking Dynamic Dataset Discovery
* **Files:** [src/a1/web/static/app.js:28-86](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/web/static/app.js#L28-L86).
* **The Defect:**
  `DEFAULT_SUGGESTIONS` defines hardcoded prompt strings mapped to exact filenames (`attack_lateral_movement.db`, `attack_data_exfiltration.db`, etc.).
* **Impact:**
  When an analyst connects a custom or renamed SQLite telemetry database, the welcome screen provides zero guidance, displaying: `"No saved patterns for this dataset. Ask a question below."` The UI does not query `/api/events` or `/api/status` to dynamically generate starter prompts from discovered hostnames or suspicious actions.

### 4.7 Orphaned `planner_node` Function in `planner_node.py`
* **Files:** [src/a1/nodes/planner_node.py:108-153](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/planner_node.py#L108-L153), [src/a1/graph.py:25-36](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/graph.py#L25-L36).
* **The Defect:**
  `src/a1/nodes/planner_node.py` defines a full LangGraph node function `def planner_node(state: InvestigationState) -> Dict[str, Any]:`. However, in `graph.py`, `planner_node` is never added to the `StateGraph`. Instead, `investigator_node.py` directly imports helper functions `generate_candidate_actions` and `score_actions`.
* **Impact:** Dead/orphaned node function that creates confusion regarding whether planning is an independent graph stage or an internal step of the investigator.

### 4.8 Inconsistent `InvestigationState` TypedDict Initialization
* **Files:** [src/a1/state.py:32](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/state.py#L32), [src/a1/cli.py:114-119](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/cli.py#L114-L119), [src/a1/benchmark.py:446-450](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/benchmark.py#L446-L450).
* **The Defect:**
  In `state.py`, `repeat_nudges: int` is defined as a non-optional required field. However, `cli.py` and `benchmark.py` initialize `initial_state` without `repeat_nudges` (`{"messages": [], "hypotheses": [], "iteration_count": 0, "alert_context": ...}`).
* **Impact:** Static type checkers (mypy, pyright) reject initial state dictionaries as non-conformant to `InvestigationState`.

### 4.9 Exception String Scraping Instead of Typed Network Exception Handling
* **Files:** [src/a1/llm.py:205-224](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/llm.py#L205-L224), [src/a1/nodes/structured_output.py:26-28](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/structured_output.py#L26-L28).
* **Code Evidence:**
  ```python
  def invoke_with_network_retry(runnable: Any, messages: Any, max_attempts: int = 3) -> Any:
      ...
      for attempt in range(max_attempts):
          try:
              return runnable.invoke(messages)
          except Exception as e:
              err_str = f"{type(e).__name__} {str(e)}".lower()
              is_net = any(k in err_str for k in ("disconnect", "protocol", "timeout", "connection", "remote", "reset"))
              if is_net and attempt < max_attempts - 1:
                  delay = 1.5 * (attempt + 1)
                  time.sleep(delay)
                  continue
              raise
  ```
* **The Flaw:**
  Instead of inspecting typed exception classes defined by SDKs and HTTP clients (e.g. `openai.APIConnectionError`, `openai.APITimeoutError`, `httpx.ConnectError`, `httpx.TimeoutException`, `urllib.error.URLError`), both `llm.py` and `structured_output.py` convert the exception to lowercase text and scrape for arbitrary substrings (`"disconnect"`, `"protocol"`, `"timeout"`, `"connection"`, `"remote"`, `"reset"`).
* **Impact:**
  - Highly fragile: any change in third-party exception formatting, nested cause chains, localized system messages, or new error wrappers will fail the substring match and abort immediately.
  - Silent false positives: unrelated errors (e.g. invalid JSON payload parsing that contains the word "protocol" or "remote") can be misidentified as network failures and retried unnecessarily.

### 4.10 HTTP 429 / Rate Limit & Quota Omission in Retry Logic
* **Files:** [src/a1/llm.py:215-224](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/llm.py#L215-L224), [src/a1/nodes/structured_output.py:26-28](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/structured_output.py#L26-L28).
* **The Flaw:**
  The keyword list in `invoke_with_network_retry` completely omits rate-limiting and quota-exhaustion indicators:
  - Checked terms: `("disconnect", "protocol", "timeout", "connection", "remote", "reset")`.
  - Omitted terms: `429`, `rate_limit`, `rate limit`, `too many requests`, `quota`, `resource_exhausted`, `overloaded`.
  - Omitted typed exceptions: `openai.RateLimitError`.
* **Impact:**
  When executing investigations against live providers (such as OpenCode or OpenAI), rapid multi-step tool loops (often 10–15 calls per investigation) frequently encounter transient HTTP 429 rate limits. Because `is_net` evaluates to `False`, the agent immediately crashes with an unhandled exception rather than applying exponential backoff or honoring `Retry-After` headers.

### 4.11 Concurrency Race Conditions & Threading Misuse in Web Server
* **Files:** [src/a1/web/server.py:36-38, 509, 534, 621-624, 754-766, 791-802, 808-811](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/web/server.py#L754-L811).
* **The Flaw:**
  1. **Thread-Unsafe Cancellation Signaling:** In lines 755 and 791, `cancel_event = asyncio.Event()` is created on the main async event loop and passed across thread boundaries into background OS threads (`worker = threading.Thread(target=_run_sync_investigation, ...)`). In Python, `asyncio.Event` is strictly thread-unsafe. Invoking `cancel_event.set()` from the async endpoint thread or `/api/cancel` while the background worker thread calls `cancel_event.is_set()` produces undefined behavior and race conditions. For cross-thread synchronization, `threading.Event` is mandatory.
  2. **Global State Mutation on Shared Endpoints:** Both `/api/investigate` (lines 746-752) and `/api/chat` (lines 782-788) invoke `set_active_llm(req.provider, req.model)` and `set_active_database(req.db_path)`. These mutate global process variables (`_ACTIVE_PROVIDER`, `_ACTIVE_MODEL`, `_active_db`, `cfg.DB_PATH`). If two analysts initiate concurrent investigations on different databases or with different models, Request B clobbers Request A's active database and LLM model midway through Request A's background execution.
  3. **Unsynchronized Shared Session Access:** `_investigation_sessions` (line 38) is a plain Python dictionary. Background worker threads write to `_investigation_sessions[session_id]` (line 534) and mutate `session_data["messages"]` (lines 622-623) without acquiring any lock or mutex, creating data races with concurrent read endpoints.

### 4.12 Quadratic ($O(K^2)$) Tool Reprocessing & Redundant JSON Deserialization
* **Files:** [src/a1/nodes/investigator_node.py:254-285, 601-602, 65-150, 153-197, 199-252, 668-678, 808](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/investigator_node.py#L254-L285).
* **The Flaw:**
  In each cycle of the LangGraph investigation loop:
  - At line 601: `working_memory = _update_investigation_memory(state.get("investigation_memory"), state.get("messages", []))`.
  - Lines 270-280 iterate through **all** messages in history from index 0 to $N$, parsing `json.loads(content)` on every single tool message ever produced.
  - Furthermore, 8 distinct helper routines (`_missing_smb_auth_correlation`, `_missing_requested_auth_hosts`, `_missing_requested_archive_files`, lines 513, 536, 669, 690, 808) also re-scan and re-parse the full accumulated message list from scratch.
* **Impact:**
  Across a 12-step investigation where each tool returns multi-kilobyte JSON records (e.g. 50–100 process or timeline records), the system performs $O(K^2)$ JSON deserializations and string scans. By iteration 10, the first 9 tool outputs have been parsed 10 redundant times, generating excessive CPU overhead, garbage collection churn, and unnecessary memory allocations.

### 4.13 Baseline Context Pipeline Analysis & Test Suite Gap
* **Files:** [src/a1/baseline_context.py:1-153](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/baseline_context.py#L1-L153), [src/a1/nodes/correlation_node.py:89-97, 130](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/nodes/correlation_node.py#L89-L97), [src/a1/experiment.py:19](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/experiment.py#L19), [src/a1/graph.py:20-35](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/graph.py#L20-L35).
* **The Verified Facts & Flaws:**
  1. `src/a1/baseline_context.py` defines 153 lines of detailed domain rules for identifying administrative accounts (`KNOWN_ADMIN_ACCOUNTS`), management hosts (`KNOWN_MANAGEMENT_HOSTS`), benign parent-child relationships (`NORMAL_PARENT_CHILD`), suspicious process spawning (`SUSPICIOUS_PARENT_CHILD`), and legitimate updaters (`NORMAL_UPDATER_PROCESSES`).
  2. Contrary to previous assertions that `baseline_context.py` is never called, `src/a1/nodes/correlation_node.py` (lines 89-97) **does import and call** `assess_activity_context(ev)` on every evidence record in `state.get("evidence")`, injecting anomalies into the LLM prompt under `"=== BASELINE CONTEXT & ANOMALY FINDINGS ==="` (line 130).
  3. **Silent Exception Swallowing:** In `correlation_node.py` lines 89-97, the execution is wrapped in a blanket `try: ... except Exception: pass` block. Any runtime bug, schema anomaly, or failure in `assess_activity_context` is completely swallowed without logging.
  4. **Zero Unit Test Coverage:** Across all 14 test modules in `tests/`, there are **zero unit tests** covering `baseline_context.py`.
  5. **Dead Configuration Knob:** In `experiment.py`, `enable_baseline_context: bool = True` exists in `ExperimentConfig`, but `graph.py` and `correlation_node.py` never check this flag; baseline context logic cannot be disabled for ablation testing.

### 4.14 Database Schema Contradictions & Raw Direct Query Failure
* **Files:** [src/a1/db.py:158-247](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/db.py#L158-L247), [endpoint_security_dataset_expanded_corrected/schema.md:1-120](file:///c:/Users/vanam/Downloads/ai-musefix/endpoint_security_dataset_expanded_corrected/schema.md#L1-L120), [src/a1/web/server.py:706-715](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/web/server.py#L706-L715).
* **The Flaw:**
  1. The dataset schema document (`schema.md`) prescribes uniform relational tables (`events`, `processes`, `network_connections`, `files`, `registry_events`, `hosts`, `users`).
  2. In reality, the disk schemas contradict this specification across 4 out of 8 databases:
     - `suricata_c2_intrusion.db` has only `network_assets` (3 rows) and `suricata_events` (59 rows).
     - `wazuh_lotl_attack_dataset.db` has only `hosts` (5 rows), `users` (5 rows), and `wazuh_events` (612 rows).
     - `attack_lotl_fileless.db` has only `events` (708 rows) without separate normalized tables.
     - `ransomware_attack_complete_ecs.db` has empty (0 rows) `network_connections` and `registry_events`.
  3. `EndpointDatabase` reconciles this internally by executing `CREATE TEMP VIEW` statements on its connection. However, SQLite `TEMP VIEW` objects exist **only within that specific database connection handle**.
  4. Any direct connection using standard SQLite tooling (e.g. `sqlite3.connect(db_path)` in external scripts, data ingestion tools, or unmanaged test fixtures) fails with `OperationalError: no such table: events`.

### 4.15 Orphaned `InvestigationTrace` Module in `investigation_trace.py`
* **Files:** [src/a1/investigation_trace.py:1-110](file:///c:/Users/vanam/Downloads/ai-musefix/src/a1/investigation_trace.py#L1-L110), [tests/test_experiment.py:5-45](file:///c:/Users/vanam/Downloads/ai-musefix/tests/test_experiment.py#L5-L45).
* **The Defect:**
  `src/a1/investigation_trace.py` contains 110 lines of code defining `InvestigationTrace` and `TraceStep` with methods for serialization (`to_dict`, `save`, `from_dict`, `load`) and deterministic replay (`replay()`).
  However, across the entire operational pipeline (`cli.py`, `server.py`, `benchmark.py`, `graph.py`, and all node modules), `InvestigationTrace` is **never instantiated, saved, loaded, or replayed**. It is only imported by `tests/test_experiment.py` to assert that dummy data can be serialized to a temporary JSON file.
* **Impact:** A phantom architectural module that gives the false impression of deterministic trace replay capability, while remaining completely disconnected from production investigations.

---

## 5. Redundant Code, Dead Code & Asset Bloat

1. **Temporary Chrome Profiles & Log Bloat in `scratch/`:**
   - The `scratch/` directory contains over 100 unversioned debugging files, including `scratch/chrome-cdp` and `scratch/wsb-chrome` directories containing persistent Chrome session storage, LevelDB logs, and Dawn Graphite caches (exceeding 50 MB).
   - `.gitignore` line 18 ignores `scratch/`, but the accumulation of browser binaries and logs wastes disk space and complicates repository analysis.
2. **Duplicate Query Parsing Logic in `tools/process.py` and `tools/association.py`:**
   - Both tools implement separate, slightly divergent SQL queries to resolve process entities, command lines, and parentage. `find_process_associations` expands children manually via comma-joined SQL parameters, whereas `trace_process_tree` uses sequential loop queries. These should be unified under a single process resolution helper in `db.py`.
3. **Redundant Fallback Hypotheses Logic in `triage_node.py`:**
   - `_extract_fallback_hypotheses` (lines 89-105) contains regex matching for `"H1:", "H2:"` that mirrors recovery logic in `_recover_or_fallback_triage`.
4. **Orphaned `planner_node` in `planner_node.py`:**
   - A complete 46-line LangGraph node function that is never wired into `graph.py`.
5. **Orphaned `InvestigationTrace` in `investigation_trace.py`:**
   - A complete 110-line trace serialization and replay engine that is never wired into the investigation execution pipeline.

---

## 6. Prioritized Remediation & Action Plan

| Priority | Issue ID | Area | Impacted Component | Actionable Remediation |
|:---:|:---:|:---|:---|:---|
| **P0** | **ISSUE-01** | Bug / Grounding | `src/a1/nodes/validator_node.py` (line 198), `src/a1/state.py` (line 12) | Update `state.py` to type `confirmed_correlations: Optional[List[str]]`; in `validator_node.py`, change `if isinstance(corr, dict):` to extract event IDs and process IDs from strings using `extract_cited_ids_from_text(str(corr))`. Ensures correlation findings are validated against SQLite. |
| **P0** | **ISSUE-02** | Bug / Conversational | `src/a1/web/server.py` (lines 606-610) | Load existing session turns from `session_data["messages"]` into `prompt_msgs` so the copilot retains conversational context across multi-turn inquiries. |
| **P0** | **ISSUE-03** | Resilience / Quotas | `src/a1/llm.py` (lines 205-224), `src/a1/nodes/structured_output.py` (lines 26-28) | Add HTTP 429 / Rate Limit detection (`openai.RateLimitError`, status code 429, `"too many requests"`, `"rate limit"`, `"quota"`) to `invoke_with_network_retry` with exponential backoff and jitter. |
| **P0** | **ISSUE-04** | Concurrency / Stability | `src/a1/web/server.py` (lines 755, 791, 809) | Replace `asyncio.Event()` with `threading.Event()` for cross-thread cancellation signaling; protect `_investigation_sessions` with a `threading.Lock()`; isolate LLM and DB settings per request/session rather than mutating global variables. |
| **P1** | **ISSUE-05** | Resilience / Typing | `src/a1/llm.py` (lines 215-217), `src/a1/nodes/structured_output.py` (lines 26-28) | Replace fragile exception string scraping (`is_net = any(...)`) with explicit typed exception catches (`openai.APIConnectionError`, `openai.APITimeoutError`, `httpx.RequestError`, `urllib.error.URLError`). |
| **P1** | **ISSUE-06** | Performance / Scaling | `src/a1/nodes/investigator_node.py` (lines 254-285, 601) | Make `_update_investigation_memory` incremental by passing only new messages (`messages[processed_msg_count:]`) rather than re-deserializing the entire JSON message history $O(K^2)$ times. |
| **P1** | **ISSUE-07** | Pipeline Gap / Testing | `src/a1/baseline_context.py`, `src/a1/nodes/correlation_node.py` | Remove silent `except Exception: pass` in `correlation_node.py` (log errors properly); wire `enable_baseline_context` from `ExperimentConfig` to allow toggling; add dedicated unit tests in `tests/test_baseline_context.py`. |
| **P1** | **ISSUE-08** | Prompt / Schema Collision | `src/a1/prompts/investigator.py` (line 86), `src/a1/nodes/report_node.py` (line 76), `src/a1/benchmark.py` (line 234) | Resolve three-way collision: allow `telemetry_gap_inconclusive` in `IncidentVerdict` Literal, update `_normalize_boundary` in `benchmark.py` to normalize `telemetry_gap_inconclusive` to `inconclusive`, and fix `investigator.py` prompt boundary. |
| **P1** | **ISSUE-09** | Prompt Generalization | `src/a1/prompts/triage.py` (lines 18-30) | Remove hardcoded instructions requiring source/target host extraction and lateral movement hypotheses; use generic multi-stage hypothesis templates suitable for ransomware, data exfiltration, and benign admin tasks. |
| **P1** | **ISSUE-10** | Benchmark Rigor | `src/a1/nodes/investigator_node.py` (lines 65-252) | Decouple scenario-specific nudge functions (`_missing_smb_auth_correlation`, `_missing_requested_archive_files`) from the core investigation loop; rely on dynamic information gain via `planner_node.py`. |
| **P1** | **ISSUE-11** | Experiment Rigor | `src/a1/graph.py`, `src/a1/experiment.py` | Wire `enable_evidence_graph`, `enable_adaptive_planner`, and `enable_baseline_context` from `ExperimentConfig` into the LangGraph state machine so live ablation studies empirically measure component contributions. |
| **P2** | **ISSUE-12** | Database Integrity | `src/a1/db.py`, `server.py` | Reconcile disk schemas with documentation; document `CREATE TEMP VIEW` requirements for external tooling; ensure `/api/events` falls back gracefully on non-standard schemas. |
| **P2** | **ISSUE-13** | Documentation Drift | `README.md`, `ARCHITECTURE.md`, `config.py` | Update configuration table in `README.md` to document OpenCode settings and match `config.py` defaults; update test count in `ARCHITECTURE.md` to 100 tests. |
| **P2** | **ISSUE-14** | Stale Dataset Specs | `schema.md`, dataset `README.md` | Remove phantom references to `events.jsonl`, `case_labels.json`, `endpoint_security.db`, and `agent_bundle/`. Accurately document the 8 shipped `.db` files and total event count (4,490). |
| **P2** | **ISSUE-15** | Architecture / UI Drift| `ui.md`, `ARCHITECTURE.md` | Reconcile UI documentation with shipped DOM: document the case menu popup instead of a persistent rail pane, and catalog `evidence-tree.js` and `process-links.js`. |
| **P2** | **ISSUE-16** | Database Concurrency | `alert_prep_node.py`, `investigator_node.py` | Replace raw `EndpointDatabase()` instantiations with centralized `get_active_db()`; synchronize `cfg.DB_PATH` with `cfg.get_db_path()`. |
| **P3** | **ISSUE-17** | Robustness / Context | `src/a1/nodes/investigator_node.py` (line 675) | Replace 700-character raw string truncation with structured entity and summary extraction to prevent cutting off JSON strings and event ID anchors. |
| **P3** | **ISSUE-18** | Code Cleanliness | `src/a1/nodes/planner_node.py` | Refactor orphaned `planner_node` function into helper module or officially register it as a conditional pre-investigation graph node. |
| **P3** | **ISSUE-19** | Static Typing | `src/a1/state.py`, `cli.py`, `benchmark.py` | Initialize `repeat_nudges: 0` in all initial state definitions or mark `repeat_nudges: Optional[int]` in `InvestigationState`. |
| **P3** | **ISSUE-20** | Workspace Cleanup | `scratch/` | Purge unneeded Chrome cache directories (`scratch/chrome-cdp/`, `scratch/wsb-chrome/`) to reclaim disk space and prevent git bloat. |
| **P3** | **ISSUE-21** | Dead Architecture | `src/a1/investigation_trace.py` | Wire `InvestigationTrace` recording and replay into `cli.py` and `server.py`, or decommission the unused 110-line module. |

---

## 7. Remaining Questions & Gaps

1. **OpenCode Live Rate-Limit & Token Bucket Capacity:**
   - Deep tool investigations generate 10–15 calls in rapid succession. Live stress-testing across all 10 evaluation cases against `https://opencode.ai/inference/go/openai/v1` is needed to profile token bucket exhaustion and determine optimal backoff jitter.
2. **Multi-Tenant State Isolation Architecture:**
   - Resolving global variable mutations in `server.py` requires restructuring `get_active_db()` and `get_active_llm_info()` into request-scoped dependency injection or context variables.
3. **Evidence Tree DOM Virtualization at Scale:**
   - Datasets exceeding 1,500 events (e.g. `attack_supply_chain.db` with 1,890 events) produce large SVG/DOM graphs in `evidence-tree.js`. Virtualized node rendering should be evaluated for enterprise-scale deployments (>5,000 events).
4. **Follow-Up Priorities for Next Engineering Iteration:**
   - Apply P0 fixes in `validator_node.py`, `server.py`, and `llm.py` first.
   - Reconcile `IncidentVerdict` literal and `benchmark.py` boundary normalization for `telemetry_gap_inconclusive`.
   - Add a unit test suite for `baseline_context.py` and remove silent error swallowing in `correlation_node.py`.
