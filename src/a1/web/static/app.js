/**
 * A1 DFIR Investigator - ChatGPT Style Frontend Logic
 */

(function () {
  "use strict";

  // Application State
  const state = {
    activeProvider: "ollama",
    activeModel: "gemma4:31b",
    currentDb: "",
    databases: [],
    models: {
      ollama: [],
      openai: [],
    },
    isGenerating: false,
    activeAbortController: null,
    history: [],
    currentSessionId: null,
  };

  // DOM Elements
  const elements = {
    themeToggleBtn: document.getElementById("themeToggleBtn"),
    sidebar: document.getElementById("sidebar"),
    sidebarCollapseBtn: document.getElementById("sidebarCollapseBtn"),
    sidebarOpenBtn: document.getElementById("sidebarOpenBtn"),
    newChatBtn: document.getElementById("newChatBtn"),
    clearChatBtn: document.getElementById("clearChatBtn"),
    clearHistoryBtn: document.getElementById("clearHistoryBtn"),
    historyList: document.getElementById("historyList"),
    dbSelect: document.getElementById("dbSelect"),
    headerDbName: document.getElementById("headerDbName"),
    headerDbPill: document.getElementById("headerDbPill"),
    // Model Selector Dropdown Elements
    modelDropdownContainer: document.getElementById("modelDropdownContainer"),
    modelSelectorPill: document.getElementById("modelSelectorPill"),
    modelMenu: document.getElementById("modelMenu"),
    activeModelName: document.getElementById("activeModelName"),
    activeProviderBadge: document.getElementById("activeProviderBadge"),
    tabOllama: document.getElementById("tabOllama"),
    tabOpenai: document.getElementById("tabOpenai"),
    modelSearchInput: document.getElementById("modelSearchInput"),
    modelList: document.getElementById("modelList"),
    customModelInput: document.getElementById("customModelInput"),
    applyCustomModelBtn: document.getElementById("applyCustomModelBtn"),
    // Chat Stage & Input
    chatStage: document.getElementById("chatStage"),
    welcomeScreen: document.getElementById("welcomeScreen"),
    messagesContainer: document.getElementById("messagesContainer"),
    promptInput: document.getElementById("promptInput"),
    sendBtn: document.getElementById("sendBtn"),
    inputMetaModel: document.getElementById("inputMetaModel"),
    inputMetaDb: document.getElementById("inputMetaDb"),
    systemStatusDot: document.getElementById("systemStatusDot"),
    systemStatusText: document.getElementById("systemStatusText"),
  };

  // -------------------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------------------
  async function init() {
    loadTheme();
    loadSavedHistory();
    setupEventListeners();
    await fetchInitialStatus();
    await fetchModels();
  }

  // -------------------------------------------------------------------------
  // Theme Handling
  // -------------------------------------------------------------------------
  function loadTheme() {
    const savedTheme = localStorage.getItem("a1_theme") || "dark";
    if (savedTheme === "dark") {
      document.body.classList.add("theme-dark");
    } else {
      document.body.classList.remove("theme-dark");
    }
  }

  function toggleTheme() {
    const isDark = document.body.classList.toggle("theme-dark");
    localStorage.setItem("a1_theme", isDark ? "dark" : "light");
  }

  // -------------------------------------------------------------------------
  // API Calls & State Sync
  // -------------------------------------------------------------------------
  async function fetchInitialStatus() {
    try {
      const res = await fetch("/api/status");
      if (!res.ok) throw new Error("Failed to load status");
      const data = await res.json();

      if (data.active_llm) {
        state.activeProvider = data.active_llm.provider;
        state.activeModel = data.active_llm.model;
        updateModelUI();
      }

      if (data.databases) {
        state.databases = data.databases;
        renderDatabases();
      }

      elements.systemStatusText.textContent = "Ready";
      elements.systemStatusDot.style.backgroundColor = "var(--accent-primary)";
    } catch (err) {
      console.error("fetchInitialStatus error:", err);
      elements.systemStatusText.textContent = "Offline";
      elements.systemStatusDot.style.backgroundColor = "#ef4444";
    }
  }

  async function fetchModels() {
    try {
      const res = await fetch("/api/models");
      if (!res.ok) return;
      const data = await res.json();
      state.models.ollama = data.ollama || [];
      state.models.openai = data.openai || [];
      renderModelList();
    } catch (err) {
      console.warn("fetchModels error:", err);
    }
  }

  function renderDatabases() {
    elements.dbSelect.innerHTML = "";
    state.databases.forEach((db) => {
      const opt = document.createElement("option");
      opt.value = db.path;
      opt.textContent = `${db.display || db.name} (${formatBytes(db.size_bytes)})`;
      if (db.is_active) {
        opt.selected = true;
        state.currentDb = db.name;
        elements.headerDbName.textContent = db.name;
        elements.inputMetaDb.textContent = db.name;
      }
      elements.dbSelect.appendChild(opt);
    });
  }

  async function onDatabaseChange(e) {
    const path = e.target.value;
    try {
      const res = await fetch("/api/databases/set", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ db_path: path }),
      });
      if (!res.ok) throw new Error("Failed to switch database");
      const data = await res.json();
      const dbObj = state.databases.find((d) => d.path === path);
      if (dbObj) {
        state.currentDb = dbObj.name;
        elements.headerDbName.textContent = dbObj.name;
        elements.inputMetaDb.textContent = dbObj.name;
      }
    } catch (err) {
      alert("Error switching database: " + err.message);
    }
  }

  // -------------------------------------------------------------------------
  // Model Selector Dropdown
  // -------------------------------------------------------------------------
  function toggleModelMenu(forceState) {
    const shouldOpen =
      forceState !== undefined
        ? forceState
        : !elements.modelDropdownContainer.classList.contains("open");
    if (shouldOpen) {
      elements.modelDropdownContainer.classList.add("open");
      elements.modelSelectorPill.setAttribute("aria-expanded", "true");
      renderModelList();
      elements.modelSearchInput.focus();
    } else {
      elements.modelDropdownContainer.classList.remove("open");
      elements.modelSelectorPill.setAttribute("aria-expanded", "false");
    }
  }

  function updateModelUI() {
    elements.activeModelName.textContent = state.activeModel;
    elements.activeProviderBadge.textContent = state.activeProvider;
    elements.inputMetaModel.textContent = state.activeModel;
    if (state.activeProvider === "openai") {
      elements.tabOpenai.classList.add("active");
      elements.tabOllama.classList.remove("active");
    } else {
      elements.tabOllama.classList.add("active");
      elements.tabOpenai.classList.remove("active");
    }
  }

  function renderModelList() {
    const provider = state.activeProvider;
    const filter = (elements.modelSearchInput.value || "").toLowerCase().trim();
    const list = state.models[provider] || [];

    elements.modelList.innerHTML = "";
    const filtered = list.filter((m) => m.toLowerCase().includes(filter));

    if (filtered.length === 0) {
      const empty = document.createElement("div");
      empty.className = "history-empty";
      empty.textContent = `No ${provider} models matching "${filter}"`;
      elements.modelList.appendChild(empty);
      return;
    }

    filtered.forEach((modelName) => {
      const item = document.createElement("div");
      item.className = "model-item" + (modelName === state.activeModel ? " selected" : "");
      item.onclick = () => selectModel(provider, modelName);

      const info = document.createElement("div");
      info.className = "model-item-info";

      const name = document.createElement("span");
      name.className = "model-item-name";
      name.textContent = modelName;

      const desc = document.createElement("span");
      desc.className = "model-item-desc";
      desc.textContent =
        provider === "ollama" ? "Local / Remote Ollama" : "OpenAI Chat Model";

      info.appendChild(name);
      info.appendChild(desc);

      const check = document.createElement("span");
      check.className = "model-item-check";
      check.textContent = "✓";

      item.appendChild(info);
      item.appendChild(check);
      elements.modelList.appendChild(item);
    });
  }

  async function selectModel(provider, modelName) {
    try {
      const res = await fetch("/api/models/set", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider, model: modelName }),
      });
      if (!res.ok) throw new Error("Failed to set model");
      state.activeProvider = provider;
      state.activeModel = modelName;
      updateModelUI();
      toggleModelMenu(false);
    } catch (err) {
      alert("Error changing model: " + err.message);
    }
  }

  function handleCustomModelApply() {
    const custom = elements.customModelInput.value.trim();
    if (!custom) return;
    selectModel(state.activeProvider, custom);
    elements.customModelInput.value = "";
  }

  // -------------------------------------------------------------------------
  // Chat & Stream Handling
  // -------------------------------------------------------------------------
  function setupEventListeners() {
    elements.themeToggleBtn.addEventListener("click", toggleTheme);

    elements.sidebarCollapseBtn.addEventListener("click", () => {
      elements.sidebar.classList.add("collapsed");
    });
    elements.sidebarOpenBtn.addEventListener("click", () => {
      elements.sidebar.classList.remove("collapsed");
    });

    elements.newChatBtn.addEventListener("click", startNewChat);
    elements.clearChatBtn.addEventListener("click", startNewChat);
    elements.clearHistoryBtn.addEventListener("click", clearAllHistory);

    elements.dbSelect.addEventListener("change", onDatabaseChange);

    // Model Dropdown
    elements.modelSelectorPill.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleModelMenu();
    });

    document.addEventListener("click", (e) => {
      if (!elements.modelDropdownContainer.contains(e.target)) {
        toggleModelMenu(false);
      }
    });

    elements.tabOllama.addEventListener("click", () => {
      state.activeProvider = "ollama";
      updateModelUI();
      renderModelList();
    });

    elements.tabOpenai.addEventListener("click", () => {
      state.activeProvider = "openai";
      updateModelUI();
      renderModelList();
    });

    elements.modelSearchInput.addEventListener("input", renderModelList);

    elements.applyCustomModelBtn.addEventListener("click", handleCustomModelApply);
    elements.customModelInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") handleCustomModelApply();
    });

    // Prompt Textarea Auto-resize & Enter to send
    elements.promptInput.addEventListener("input", function () {
      this.style.height = "auto";
      this.style.height = Math.min(this.scrollHeight, 200) + "px";
    });

    elements.promptInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        handleSubmitPrompt();
      }
    });

    elements.sendBtn.addEventListener("click", () => {
      if (state.isGenerating) {
        stopInvestigation();
      } else {
        handleSubmitPrompt();
      }
    });

    // Suggestions click
    document.querySelectorAll(".suggestion-card").forEach((card) => {
      card.addEventListener("click", () => {
        const query = card.getAttribute("data-query");
        if (query) {
          elements.promptInput.value = query;
          handleSubmitPrompt();
        }
      });
    });
  }

  function startNewChat() {
    if (state.isGenerating) stopInvestigation();
    elements.messagesContainer.innerHTML = "";
    elements.welcomeScreen.style.display = "flex";
    elements.promptInput.value = "";
    elements.promptInput.style.height = "auto";
    state.currentSessionId = null;
    document.querySelectorAll(".history-item").forEach((i) => i.classList.remove("active"));
  }

  async function handleSubmitPrompt() {
    const query = elements.promptInput.value.trim();
    if (!query || state.isGenerating) return;

    elements.welcomeScreen.style.display = "none";
    elements.promptInput.value = "";
    elements.promptInput.style.height = "auto";

    // 1. Render User Message
    renderUserMessage(query);

    // 2. Prepare Assistant Message Box with Live Stepper
    const assistantMsg = createAssistantMessageElement();
    elements.messagesContainer.appendChild(assistantMsg.container);
    scrollToBottom();

    // 3. Start Investigation SSE Stream
    state.isGenerating = true;
    updateSendBtnState(true);

    const sessionId = "sess-" + Date.now();
    state.currentSessionId = sessionId;

    try {
      const response = await fetch("/api/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: query,
          provider: state.activeProvider,
          model: state.activeModel,
          db_path: elements.dbSelect.value || undefined,
        }),
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop(); // Keep last partial chunk

        for (const block of lines) {
          const trimmed = block.trim();
          if (trimmed.startsWith("data: ")) {
            const jsonStr = trimmed.slice(6);
            try {
              const event = JSON.parse(jsonStr);
              handleStreamEvent(event, assistantMsg);
            } catch (err) {
              console.warn("SSE JSON Parse error:", err, jsonStr);
            }
          }
        }
      }

      // Finalize and save to history
      saveInvestigationSession(sessionId, query, assistantMsg.state);
    } catch (err) {
      console.error("Stream error:", err);
      assistantMsg.setErrorMessage(err.message);
    } finally {
      state.isGenerating = false;
      updateSendBtnState(false);
      scrollToBottom();
    }
  }

  async function stopInvestigation() {
    try {
      await fetch("/api/cancel", { method: "POST" });
    } catch (e) {
      console.warn("Cancel request failed", e);
    }
    state.isGenerating = false;
    updateSendBtnState(false);
  }

  function updateSendBtnState(isGenerating) {
    if (isGenerating) {
      elements.sendBtn.classList.add("generating");
      elements.sendBtn.title = "Stop investigation";
    } else {
      elements.sendBtn.classList.remove("generating");
      elements.sendBtn.title = "Send message";
    }
  }

  // -------------------------------------------------------------------------
  // Message Components & UI Rendering
  // -------------------------------------------------------------------------
  function renderUserMessage(text) {
    const row = document.createElement("div");
    row.className = "message-row user";

    const bubble = document.createElement("div");
    bubble.className = "user-bubble";
    bubble.textContent = text;

    row.appendChild(bubble);
    elements.messagesContainer.appendChild(row);
  }

  function createAssistantMessageElement() {
    const row = document.createElement("div");
    row.className = "message-row assistant";

    const avatar = document.createElement("div");
    avatar.className = "message-avatar";
    avatar.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`;

    const content = document.createElement("div");
    content.className = "assistant-content";

    // Stepper
    const stepper = document.createElement("div");
    stepper.className = "investigation-stepper";
    stepper.innerHTML = `
      <div class="step-item active" id="st-prep"><div class="step-dot"></div><span>Alert Prep</span></div>
      <span class="step-separator">›</span>
      <div class="step-item" id="st-triage"><div class="step-dot"></div><span>Triage Plan</span></div>
      <span class="step-separator">›</span>
      <div class="step-item" id="st-loop"><div class="step-dot"></div><span>Telemetry</span></div>
      <span class="step-separator">›</span>
      <div class="step-item" id="st-pack"><div class="step-dot"></div><span>Evidence Pack</span></div>
      <span class="step-separator">›</span>
      <div class="step-item" id="st-report"><div class="step-dot"></div><span>Verdict</span></div>
    `;

    // Hypotheses Container
    const hypothesesBox = document.createElement("div");
    hypothesesBox.className = "hypotheses-box";
    hypothesesBox.style.display = "none";
    hypothesesBox.innerHTML = `
      <div class="hypotheses-title">Triage Hypotheses</div>
      <div class="hypotheses-list"></div>
    `;

    // Retrieved Evidence Timeline
    const evidenceBox = document.createElement("section");
    evidenceBox.className = "evidence-pack-box";
    evidenceBox.style.display = "none";
    evidenceBox.innerHTML = `
      <div class="evidence-pack-heading">
        <div>
          <div class="hypotheses-title">Retrieved Evidence</div>
          <div class="evidence-pack-meta"></div>
        </div>
        <button class="action-pill-btn evidence-table-open" type="button" aria-haspopup="dialog">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"></rect><path d="M3 9h18M3 15h18M9 3v18m6-18v18"></path></svg>
          <span>View table</span>
        </button>
      </div>
      <dialog class="evidence-table-dialog" aria-label="Retrieved telemetry events">
        <div class="evidence-table-dialog-heading">
          <div>
            <h2>Retrieved telemetry events</h2>
            <div class="evidence-dialog-meta"></div>
          </div>
          <button class="icon-btn evidence-table-close" type="button" aria-label="Close evidence table" title="Close">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"></path></svg>
          </button>
        </div>
        <div class="evidence-table-wrap"></div>
      </dialog>
      <div class="evidence-hypotheses"></div>
    `;
    const evidenceDialog = evidenceBox.querySelector(".evidence-table-dialog");
    evidenceBox.querySelector(".evidence-table-open").addEventListener("click", () => {
      evidenceDialog.showModal();
    });
    evidenceBox.querySelector(".evidence-table-close").addEventListener("click", () => {
      evidenceDialog.close();
    });

    // Telemetry & Steps Accordion
    const traceBox = document.createElement("div");
    traceBox.className = "telemetry-trace";
    traceBox.innerHTML = `
      <button class="telemetry-toggle">
        <span>Investigation Telemetry Trace <span class="trace-count-pill">0 steps</span></span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
      </button>
      <div class="telemetry-body" style="display: none;"></div>
    `;

    const toggleBtn = traceBox.querySelector(".telemetry-toggle");
    const traceBody = traceBox.querySelector(".telemetry-body");
    const countPill = traceBox.querySelector(".trace-count-pill");

    toggleBtn.addEventListener("click", () => {
      const isHidden = traceBody.style.display === "none";
      traceBody.style.display = isHidden ? "flex" : "none";
      toggleBtn.querySelector("svg").style.transform = isHidden
        ? "rotate(180deg)"
        : "rotate(0deg)";
    });

    // Verdict Banner
    const verdictBanner = document.createElement("div");
    verdictBanner.className = "verdict-banner";
    verdictBanner.style.display = "none";

    // Markdown Report Container
    const reportBox = document.createElement("div");
    reportBox.className = "report-markdown";

    // Report Actions
    const reportActions = document.createElement("div");
    reportActions.className = "report-actions";
    reportActions.style.display = "none";
    reportActions.innerHTML = `
      <button class="action-pill-btn copy-report-btn">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
        <span>Copy Report</span>
      </button>
    `;

    content.appendChild(stepper);
    content.appendChild(hypothesesBox);
    content.appendChild(evidenceBox);
    content.appendChild(traceBox);
    content.appendChild(verdictBanner);
    content.appendChild(reportBox);
    content.appendChild(reportActions);

    row.appendChild(avatar);
    row.appendChild(content);

    const internalState = {
      stepCount: 0,
      reportMarkdown: "",
      verdict: "",
      hypotheses: [],
    };

    const copyBtn = reportActions.querySelector(".copy-report-btn");
    copyBtn.addEventListener("click", () => {
      if (internalState.reportMarkdown) {
        navigator.clipboard.writeText(internalState.reportMarkdown);
        copyBtn.querySelector("span").textContent = "Copied!";
        setTimeout(() => {
          copyBtn.querySelector("span").textContent = "Copy Report";
        }, 2000);
      }
    });

    return {
      container: row,
      state: internalState,
      setStepActive: (stepId) => {
        const ids = ["st-prep", "st-triage", "st-loop", "st-pack", "st-report"];
        let passed = true;
        ids.forEach((id) => {
          const el = stepper.querySelector("#" + id);
          if (!el) return;
          if (id === stepId) {
            el.className = "step-item active";
            passed = false;
          } else if (passed) {
            el.className = "step-item done";
          } else {
            el.className = "step-item";
          }
        });
      },
      addHypotheses: (hypos) => {
        internalState.hypotheses = hypos;
        hypothesesBox.style.display = "block";
        const list = hypothesesBox.querySelector(".hypotheses-list");
        list.innerHTML = "";
        hypos.forEach((h, idx) => {
          const item = document.createElement("div");
          item.className = "hypo-item";
          item.innerHTML = `<span class="hypo-badge">H${idx + 1}:</span><span>${escapeHtml(h)}</span>`;
          list.appendChild(item);
        });
      },
      setEvidencePack: (pack) => {
        const timeline = Array.isArray(pack.timeline) ? pack.timeline : [];
        evidenceBox.style.display = "block";
        evidenceBox.querySelector(".evidence-pack-meta").textContent =
          `${pack.total_kept_events ?? timeline.length} events retained; ${pack.excluded_count ?? 0} rows filtered`;
        evidenceBox.querySelector(".evidence-dialog-meta").textContent =
          `${pack.total_kept_events ?? timeline.length} events retained`;

        const tableWrap = evidenceBox.querySelector(".evidence-table-wrap");
        tableWrap.replaceChildren();
        const table = document.createElement("table");
        table.className = "evidence-table";
        table.setAttribute("aria-label", "Retrieved telemetry events");
        const caption = table.createCaption();
        caption.className = "sr-only";
        caption.textContent = "Retrieved telemetry events";
        const columns = ["Time", "Event ID", "Host", "Action", "Process", "Summary"];
        const headerRow = table.createTHead().insertRow();
        columns.forEach((column) => {
          const header = document.createElement("th");
          header.scope = "col";
          header.textContent = column;
          headerRow.appendChild(header);
        });
        const tableBody = table.createTBody();
        timeline.forEach((event) => {
          const details = event.details && typeof event.details === "object" ? event.details : {};
          const processName = event.process_name || details.name || "";
          const processId = event.process_entity_id || "";
          const process = processName && processId
            ? `${processName} (${processId})`
            : processName || processId || "Unknown";
          const values = [
            event.timestamp || "Time unavailable",
            event.event_id || "Unknown event",
            event.host_id || "Unknown host",
            event.action || "Unknown",
            process,
            event.summary || "No summary available",
          ];
          const row = tableBody.insertRow();
          values.forEach((value) => {
            const cell = row.insertCell();
            cell.textContent = value;
          });
        });
        tableWrap.appendChild(table);

        const hypothesisList = evidenceBox.querySelector(".evidence-hypotheses");
        hypothesisList.replaceChildren();
        Object.entries(pack.hypotheses_evidence || {}).forEach(([hypothesis, evidence]) => {
          const row = document.createElement("div");
          row.className = "evidence-hypothesis";
          row.textContent = `${evidence.event_count || 0} candidate event(s): ${hypothesis}`;
          hypothesisList.appendChild(row);
        });
      },
      addTraceStep: (toolName, summary) => {
        internalState.stepCount++;
        countPill.textContent = `${internalState.stepCount} step(s)`;
        const rowEl = document.createElement("div");
        rowEl.className = "trace-row";
        rowEl.innerHTML = `
          <div class="trace-row-header">
            <span class="trace-tool-name">${escapeHtml(toolName)}</span>
            <span style="font-size:10px; color:var(--text-faint);">#${internalState.stepCount}</span>
          </div>
          <div class="trace-summary">${escapeHtml(summary)}</div>
        `;
        traceBody.appendChild(rowEl);
        traceBody.scrollTop = traceBody.scrollHeight;
      },
      addReasoning: (text) => {
        const rowEl = document.createElement("div");
        rowEl.className = "trace-reasoning";
        rowEl.textContent = text;
        traceBody.appendChild(rowEl);
        traceBody.scrollTop = traceBody.scrollHeight;
      },
      setVerdict: (verdict, boundary, confidence) => {
        internalState.verdict = verdict;
        verdictBanner.className = `verdict-banner ${verdict}`;
        verdictBanner.style.display = "flex";
        verdictBanner.innerHTML = `
          <div class="verdict-left">
            <div class="verdict-title">${escapeHtml(verdict)}</div>
            ${boundary ? `<div class="verdict-boundary">${escapeHtml(boundary)}</div>` : ""}
          </div>
          <div class="verdict-confidence">Confidence: ${(confidence * 100).toFixed(0)}%</div>
        `;
      },
      setReport: (markdown) => {
        internalState.reportMarkdown = markdown;
        reportBox.innerHTML = renderMarkdown(markdown);
        reportActions.style.display = "flex";
      },
      setErrorMessage: (msg) => {
        reportBox.innerHTML = `<div style="color:var(--verdict-malicious-text); padding:10px; background:var(--verdict-malicious-bg); border-radius:8px;">⚠️ ${escapeHtml(msg)}</div>`;
      },
    };
  }

  function handleStreamEvent(event, assistantMsg) {
    switch (event.type) {
      case "start":
        assistantMsg.setStepActive("st-prep");
        break;

      case "alert_prep":
        assistantMsg.setStepActive("st-triage");
        break;

      case "triage":
        assistantMsg.setStepActive("st-loop");
        if (event.data && event.data.hypotheses) {
          assistantMsg.addHypotheses(event.data.hypotheses);
        }
        break;

      case "loop":
        assistantMsg.setStepActive("st-loop");
        break;

      case "evidence_pack":
        assistantMsg.setStepActive("st-pack");
        assistantMsg.setEvidencePack(event.data || {});
        break;

      case "tool_call":
        const tc = event.data;
        const argStr = JSON.stringify(tc.args || {});
        assistantMsg.addTraceStep(
          `Invoking ${tc.tool}`,
          argStr.length > 120 ? argStr.slice(0, 117) + "..." : argStr
        );
        break;

      case "tool_result":
        assistantMsg.addTraceStep(event.data.tool, event.data.summary);
        break;

      case "thought":
      case "reasoning":
        assistantMsg.addReasoning(event.text);
        break;

      case "complete":
        assistantMsg.setStepActive("st-report");
        const res = event.data;
        if (res.verdict) {
          assistantMsg.setVerdict(
            res.verdict,
            res.verdict_boundary,
            res.confidence || 0.0
          );
        }
        if (res.report) {
          assistantMsg.setReport(res.report);
        }
        scrollToBottom();
        break;

      case "error":
        assistantMsg.setErrorMessage(event.message || "An unexpected error occurred.");
        break;
    }
    scrollToBottom();
  }

  // -------------------------------------------------------------------------
  // Local History Management
  // -------------------------------------------------------------------------
  function loadSavedHistory() {
    try {
      const raw = localStorage.getItem("a1_dfir_history");
      if (raw) {
        state.history = JSON.parse(raw);
        renderHistoryList();
      }
    } catch (e) {
      console.warn("Could not load history", e);
    }
  }

  function saveInvestigationSession(id, query, sessionState) {
    const item = {
      id: id,
      query: query,
      timestamp: Date.now(),
      verdict: sessionState.verdict,
      report: sessionState.reportMarkdown,
      model: state.activeModel,
      db: state.currentDb,
    };
    state.history.unshift(item);
    if (state.history.length > 25) state.history.pop();
    try {
      localStorage.setItem("a1_dfir_history", JSON.stringify(state.history));
      renderHistoryList();
    } catch (e) {
      console.warn("Could not save history to localStorage", e);
    }
  }

  function renderHistoryList() {
    elements.historyList.innerHTML = "";
    if (state.history.length === 0) {
      elements.historyList.innerHTML = `<div class="history-empty">No previous investigations</div>`;
      return;
    }

    state.history.forEach((item) => {
      const el = document.createElement("div");
      el.className = "history-item" + (item.id === state.currentSessionId ? " active" : "");

      const span = document.createElement("span");
      span.textContent = item.query;
      span.title = item.query;

      const delBtn = document.createElement("button");
      delBtn.className = "history-del-btn";
      delBtn.innerHTML = "×";
      delBtn.title = "Delete this investigation";
      delBtn.onclick = (e) => {
        e.stopPropagation();
        deleteHistoryItem(item.id);
      };

      el.appendChild(span);
      el.appendChild(delBtn);

      el.onclick = () => loadHistoryItem(item);
      elements.historyList.appendChild(el);
    });
  }

  function deleteHistoryItem(id) {
    state.history = state.history.filter((h) => h.id !== id);
    localStorage.setItem("a1_dfir_history", JSON.stringify(state.history));
    renderHistoryList();
    if (state.currentSessionId === id) startNewChat();
  }

  function clearAllHistory() {
    if (!confirm("Clear all recent investigation history?")) return;
    state.history = [];
    localStorage.removeItem("a1_dfir_history");
    renderHistoryList();
  }

  function loadHistoryItem(item) {
    startNewChat();
    state.currentSessionId = item.id;
    renderHistoryList();

    elements.welcomeScreen.style.display = "none";
    renderUserMessage(item.query);

    const assistantMsg = createAssistantMessageElement();
    elements.messagesContainer.appendChild(assistantMsg.container);

    if (item.verdict) {
      assistantMsg.setVerdict(item.verdict, "", 0.95);
    }
    if (item.report) {
      assistantMsg.setReport(item.report);
    }
    assistantMsg.setStepActive("st-report");
    scrollToBottom();
  }

  // -------------------------------------------------------------------------
  // Helpers: Markdown Renderer & Utilities
  // -------------------------------------------------------------------------
  function renderMarkdown(mdText) {
    if (!mdText) return "";
    // If marked & DOMPurify are available from CDN, use them
    if (window.marked && window.DOMPurify) {
      try {
        return window.DOMPurify.sanitize(window.marked.parse(mdText));
      } catch (e) {
        console.warn("marked.parse failed, falling back to local renderer:", e);
      }
    }

    // Built-in Lightweight Markdown Fallback (100% offline reliable)
    let html = escapeHtml(mdText);

    // Code blocks ```...```
    html = html.replace(/```([\s\S]*?)```/g, function (match, p1) {
      return `<pre><code>${p1}</code></pre>`;
    });

    // Inline code `...`
    html = html.replace(/`([^`]+)`/g, "<code>$1</code>");

    // Headers
    html = html.replace(/^### (.*$)/gim, "<h3>$1</h3>");
    html = html.replace(/^## (.*$)/gim, "<h2>$1</h2>");
    html = html.replace(/^# (.*$)/gim, "<h1>$1</h1>");

    // Bold & Italic
    html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");

    // Blockquotes
    html = html.replace(/^\> (.*$)/gim, "<blockquote>$1</blockquote>");

    // Unordered lists
    html = html.replace(/^\- (.*$)/gim, "<li>$1</li>");
    html = html.replace(/(<li>.*<\/li>)/gim, "<ul>$1</ul>");

    // Paragraphs
    html = html.replace(/\n\n+/g, "<br><br>");

    return html;
  }

  function escapeHtml(text) {
    if (text === null || text === undefined) return "";
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function scrollToBottom() {
    elements.chatStage.scrollTop = elements.chatStage.scrollHeight;
  }

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  // Run initialization
  document.addEventListener("DOMContentLoaded", init);
})();
