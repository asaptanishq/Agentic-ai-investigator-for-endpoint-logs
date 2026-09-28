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
      ollama: [
        "gemma4:31b",
        "llama3.1",
        "llama3.3",
        "mistral-large-3:675b",
        "deepseek-v4-pro:0813",
        "deepseek-r1",
        "nemotron-3-nano:30b",
        "glm-5.3-flash",
      ],
      openai: [
        "gpt-4o",
        "gpt-4o-mini",
        "o1-mini",
        "o3-mini",
        "gpt-4-turbo",
      ],
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
    sidebarToggleBtn: document.getElementById("sidebarToggleBtn"),
    sidebarViewTableBtn: document.getElementById("sidebarViewTableBtn"),
    newChatBtn: document.getElementById("newChatBtn"),
    clearChatBtn: document.getElementById("clearChatBtn"),
    clearHistoryBtn: document.getElementById("clearHistoryBtn"),
    historyList: document.getElementById("historyList"),
    dbSelect: document.getElementById("dbSelect"),
    headerDbName: document.getElementById("headerDbName"),
    headerDbPill: document.getElementById("headerDbPill"),
    headerTableBtn: document.getElementById("headerTableBtn"),
    headerTableBadge: document.getElementById("headerTableBadge"),
    // Global Table Dialog
    globalTableDialog: document.getElementById("globalTableDialog"),
    globalDialogCloseBtn: document.getElementById("globalDialogCloseBtn"),
    globalDialogCopyBtn: document.getElementById("globalDialogCopyBtn"),
    globalDialogSearchInput: document.getElementById("globalDialogSearchInput"),
    globalDialogCountBadge: document.getElementById("globalDialogCountBadge"),
    globalDialogTableWrap: document.getElementById("globalDialogTableWrap"),
    globalDialogTitle: document.getElementById("globalDialogTitle"),
    globalDialogMeta: document.getElementById("globalDialogMeta"),
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

  let activeEvidenceHandler = null;
  let latestEvidenceTimeline = null;

  // -------------------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------------------
  async function init() {
    loadTheme();
    loadSavedHistory();
    loadSidebarState();
    setupEventListeners();
    await fetchInitialStatus();
    await fetchModels();
    preloadEventCount();
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
  // Sidebar State & Keyboard Shortcuts
  // -------------------------------------------------------------------------
  function loadSidebarState() {
    const saved = localStorage.getItem("a1_sidebar_collapsed") === "true";
    if (saved && elements.sidebar) {
      elements.sidebar.classList.add("collapsed");
      if (elements.sidebarToggleBtn) {
        elements.sidebarToggleBtn.title = "Open Sidebar (Ctrl+B)";
        elements.sidebarToggleBtn.setAttribute("aria-label", "Open Sidebar");
      }
    }
  }

  function toggleSidebar(forceState) {
    if (!elements.sidebar) return;
    const isCollapsed = forceState !== undefined ? !forceState : !elements.sidebar.classList.contains("collapsed");
    if (isCollapsed) {
      elements.sidebar.classList.add("collapsed");
      if (elements.sidebarToggleBtn) {
        elements.sidebarToggleBtn.title = "Open Sidebar (Ctrl+B)";
        elements.sidebarToggleBtn.setAttribute("aria-label", "Open Sidebar");
      }
    } else {
      elements.sidebar.classList.remove("collapsed");
      if (elements.sidebarToggleBtn) {
        elements.sidebarToggleBtn.title = "Collapse Sidebar (Ctrl+B)";
        elements.sidebarToggleBtn.setAttribute("aria-label", "Collapse Sidebar");
      }
    }
    try {
      localStorage.setItem("a1_sidebar_collapsed", isCollapsed ? "true" : "false");
    } catch (e) { }
  }

  // -------------------------------------------------------------------------
  // Shared Telemetry Table Renderer & Global Dialog
  // -------------------------------------------------------------------------
  let globalTelemetryCache = null;

  function formatActionBadge(action) {
    const a = (action || "unknown").toLowerCase();
    let badgeClass = "action-badge-default";
    if (a.includes("proc")) badgeClass = "action-badge-process";
    else if (a.includes("net")) badgeClass = "action-badge-network";
    else if (a.includes("file")) badgeClass = "action-badge-file";
    else if (a.includes("reg")) badgeClass = "action-badge-registry";
    return `<span class="action-badge ${badgeClass}">${escapeHtml(action || "unknown")}</span>`;
  }

  function setupTable(container, events, searchInput, countBadge, copyBtn) {
    if (!container) return;
    container.replaceChildren();

    if (!events || events.length === 0) {
      const empty = document.createElement("div");
      empty.className = "history-empty";
      empty.textContent = "No telemetry events to display";
      container.appendChild(empty);
      if (countBadge) countBadge.textContent = "0 events";
      return;
    }

    const table = document.createElement("table");
    table.className = "evidence-table";
    table.setAttribute("aria-label", "Telemetry events table");
    const caption = table.createCaption();
    caption.className = "sr-only";
    caption.textContent = "Telemetry events table";
    const columns = ["Time", "Event ID", "Host", "Action", "Process", "Summary"];
    const headerRow = table.createTHead().insertRow();
    columns.forEach((column) => {
      const header = document.createElement("th");
      header.scope = "col";
      header.textContent = column;
      headerRow.appendChild(header);
    });

    const tableBody = table.createTBody();
    const rowEntries = [];

    events.forEach((event) => {
      const details = event.details && typeof event.details === "object" ? event.details : {};
      const processName = event.process_name || details.name || details.process_name || "";
      const processId = event.process_entity_id || details.pid || "";
      const process = processName && processId
        ? `${processName} (${processId})`
        : processName || processId || "Unknown";

      const row = tableBody.insertRow();
      const timeCell = row.insertCell();
      timeCell.textContent = event.timestamp || "Time unavailable";

      const eventIdCell = row.insertCell();
      eventIdCell.textContent = event.event_id || "Unknown event";

      const hostCell = row.insertCell();
      hostCell.textContent = event.host_id || "Unknown host";

      const actionCell = row.insertCell();
      actionCell.innerHTML = formatActionBadge(event.action);

      const processCell = row.insertCell();
      processCell.textContent = process;

      const summaryCell = row.insertCell();
      summaryCell.textContent = event.summary || details.command_line || details.destination_ip || "No summary available";

      rowEntries.push({
        row,
        searchStr: `${event.timestamp || ""} ${event.event_id || ""} ${event.host_id || ""} ${event.action || ""} ${process} ${summaryCell.textContent}`.toLowerCase()
      });
    });

    container.appendChild(table);

    function updateFilter() {
      const query = (searchInput ? searchInput.value : "").trim().toLowerCase();
      let visibleCount = 0;
      rowEntries.forEach((entry) => {
        const match = !query || entry.searchStr.includes(query);
        entry.row.style.display = match ? "" : "none";
        if (match) visibleCount++;
      });
      if (countBadge) {
        countBadge.textContent = `${visibleCount} of ${events.length} event(s)`;
      }
    }

    if (searchInput) {
      searchInput.oninput = updateFilter;
      updateFilter();
    }

    if (copyBtn) {
      copyBtn.onclick = () => {
        const headers = ["Time", "Event ID", "Host", "Action", "Process", "Summary"];
        const csvLines = [headers.join(",")];
        events.forEach((e) => {
          const details = e.details && typeof e.details === "object" ? e.details : {};
          const pName = e.process_name || details.name || details.process_name || "";
          const pId = e.process_entity_id || details.pid || "";
          const proc = pName && pId ? `${pName} (${pId})` : pName || pId || "Unknown";
          const row = [
            JSON.stringify(e.timestamp || ""),
            JSON.stringify(e.event_id || ""),
            JSON.stringify(e.host_id || ""),
            JSON.stringify(e.action || ""),
            JSON.stringify(proc),
            JSON.stringify(e.summary || details.command_line || "")
          ];
          csvLines.push(row.join(","));
        });
        navigator.clipboard.writeText(csvLines.join("\n"));
        const span = copyBtn.querySelector("span");
        if (span) {
          const orig = span.textContent;
          span.textContent = "Copied CSV!";
          setTimeout(() => { span.textContent = orig; }, 2000);
        }
      };
    }
  }

  async function openGlobalTelemetryTable(eventsToDisplay, customTitle) {
    if (!elements.globalTableDialog) return;

    if (eventsToDisplay && Array.isArray(eventsToDisplay) && eventsToDisplay.length > 0) {
      if (elements.globalDialogTitle) elements.globalDialogTitle.textContent = customTitle || "Investigation Telemetry Events";
      if (elements.globalDialogMeta) elements.globalDialogMeta.textContent = `${eventsToDisplay.length} events retained from investigation`;
      setupTable(
        elements.globalDialogTableWrap,
        eventsToDisplay,
        elements.globalDialogSearchInput,
        elements.globalDialogCountBadge,
        elements.globalDialogCopyBtn
      );
      elements.globalTableDialog.showModal();
      return;
    }

    // Otherwise, fetch latest events from active database
    if (elements.globalDialogTitle) elements.globalDialogTitle.textContent = `Database Telemetry: ${state.currentDb || "Active DB"}`;
    if (elements.globalDialogMeta) elements.globalDialogMeta.textContent = "Loading events from database...";
    elements.globalTableDialog.showModal();

    try {
      const res = await fetch("/api/events?limit=200");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const events = data.events || [];
      globalTelemetryCache = events;
      if (elements.globalDialogMeta) elements.globalDialogMeta.textContent = `${events.length} events loaded from ${data.db_name || state.currentDb}`;
      if (elements.headerTableBadge) {
        elements.headerTableBadge.textContent = `${events.length}`;
      }
      setupTable(
        elements.globalDialogTableWrap,
        events,
        elements.globalDialogSearchInput,
        elements.globalDialogCountBadge,
        elements.globalDialogCopyBtn
      );
    } catch (err) {
      if (elements.globalDialogMeta) elements.globalDialogMeta.textContent = `Failed to load events: ${err.message}`;
    }
  }

  async function preloadEventCount() {
    try {
      const res = await fetch("/api/events?limit=50");
      if (res.ok) {
        const data = await res.json();
        if (elements.headerTableBadge && data.total) {
          elements.headerTableBadge.textContent = `${data.total}`;
        }
      }
    } catch (e) {
      // silent fallback
    }
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
      if (Array.isArray(data.ollama) && data.ollama.length > 0) {
        state.models.ollama = data.ollama;
      }
      if (Array.isArray(data.openai) && data.openai.length > 0) {
        state.models.openai = data.openai;
      }
      if (data.active) {
        if (data.active.provider) state.activeProvider = data.active.provider;
        if (data.active.model) state.activeModel = data.active.model;
        updateModelUI();
      }
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
  let currentMenuProvider = null;

  function toggleModelMenu(forceState) {
    const isCurrentlyOpen =
      elements.modelDropdownContainer.classList.contains("open") ||
      (elements.modelMenu && elements.modelMenu.classList.contains("open"));
    const shouldOpen =
      forceState !== undefined ? forceState : !isCurrentlyOpen;

    if (shouldOpen) {
      currentMenuProvider = state.activeProvider || "ollama";
      elements.modelDropdownContainer.classList.add("open");
      if (elements.modelMenu) elements.modelMenu.classList.add("open");
      elements.modelSelectorPill.setAttribute("aria-expanded", "true");
      updateMenuTabs();
      renderModelList();
      setTimeout(() => {
        if (elements.modelSearchInput) elements.modelSearchInput.focus();
      }, 50);
    } else {
      elements.modelDropdownContainer.classList.remove("open");
      if (elements.modelMenu) elements.modelMenu.classList.remove("open");
      elements.modelSelectorPill.setAttribute("aria-expanded", "false");
    }
  }

  function updateMenuTabs() {
    const prov = currentMenuProvider || state.activeProvider || "ollama";
    if (elements.tabOllama) {
      elements.tabOllama.classList.toggle("active", prov === "ollama");
    }
    if (elements.tabOpenai) {
      elements.tabOpenai.classList.toggle("active", prov === "openai");
    }
  }

  function updateModelUI() {
    if (elements.activeModelName) {
      elements.activeModelName.textContent = state.activeModel || "gemma4:31b";
    }
    if (elements.activeProviderBadge) {
      elements.activeProviderBadge.textContent = state.activeProvider || "ollama";
    }
    if (elements.inputMetaModel) {
      elements.inputMetaModel.textContent = state.activeModel || "gemma4:31b";
    }
    updateMenuTabs();
  }

  function renderModelList() {
    if (!elements.modelList) return;
    const provider = currentMenuProvider || state.activeProvider || "ollama";
    const filter = (elements.modelSearchInput?.value || "").toLowerCase().trim();
    const rawList = state.models[provider] || [];
    const list = [...rawList];

    // Ensure active model is present in the list if currently browsing its provider
    if (provider === state.activeProvider && state.activeModel && !list.includes(state.activeModel)) {
      list.unshift(state.activeModel);
    }

    elements.modelList.innerHTML = "";
    const filtered = list.filter((m) => m.toLowerCase().includes(filter));

    if (filtered.length === 0) {
      const empty = document.createElement("div");
      empty.className = "history-empty";
      empty.style.padding = "16px";
      empty.textContent = filter
        ? `No ${provider} models matching "${filter}"`
        : `No ${provider} models configured`;
      elements.modelList.appendChild(empty);
      return;
    }

    filtered.forEach((modelName) => {
      const isSelected = provider === state.activeProvider && modelName === state.activeModel;
      const item = document.createElement("div");
      item.className = "model-item" + (isSelected ? " selected" : "");
      item.onclick = (e) => {
        e.stopPropagation();
        selectModel(provider, modelName);
      };

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
    state.activeProvider = provider;
    state.activeModel = modelName;
    updateModelUI();
    toggleModelMenu(false);

    try {
      const res = await fetch("/api/models/set", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider, model: modelName }),
      });
      if (!res.ok) throw new Error("Failed to set model");
      const data = await res.json();
      if (data.active_llm) {
        state.activeProvider = data.active_llm.provider;
        state.activeModel = data.active_llm.model;
        updateModelUI();
      }
    } catch (err) {
      console.warn("Could not sync model to backend:", err);
    }
  }

  function handleCustomModelApply() {
    const custom = elements.customModelInput?.value.trim();
    if (!custom) return;
    const provider = currentMenuProvider || state.activeProvider || "ollama";
    if (state.models[provider] && !state.models[provider].includes(custom)) {
      state.models[provider].push(custom);
    }
    selectModel(provider, custom);
    if (elements.customModelInput) elements.customModelInput.value = "";
  }

  // -------------------------------------------------------------------------
  // Chat & Stream Handling
  // -------------------------------------------------------------------------
  function setupEventListeners() {
    elements.themeToggleBtn.addEventListener("click", toggleTheme);

    if (elements.sidebarCollapseBtn) {
      elements.sidebarCollapseBtn.addEventListener("click", () => toggleSidebar(false));
    }
    if (elements.sidebarToggleBtn) {
      elements.sidebarToggleBtn.addEventListener("click", () => toggleSidebar());
    }
    if (elements.sidebarViewTableBtn) {
      elements.sidebarViewTableBtn.addEventListener("click", () => openGlobalTelemetryTable());
    }

    // Global keyboard shortcuts (Ctrl+B / Cmd+B for sidebar, Esc to close dropdowns)
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        toggleModelMenu(false);
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "b") {
        e.preventDefault();
        toggleSidebar();
      }
    });

    elements.newChatBtn.addEventListener("click", startNewChat);
    elements.clearChatBtn.addEventListener("click", startNewChat);
    elements.clearHistoryBtn.addEventListener("click", clearAllHistory);

    elements.dbSelect.addEventListener("change", onDatabaseChange);

    // Model Dropdown
    if (elements.modelSelectorPill) {
      elements.modelSelectorPill.addEventListener("click", (e) => {
        e.stopPropagation();
        toggleModelMenu();
      });
    }

    if (elements.modelMenu) {
      elements.modelMenu.addEventListener("click", (e) => {
        e.stopPropagation();
      });
    }

    document.addEventListener("click", (e) => {
      if (
        elements.modelDropdownContainer &&
        !elements.modelDropdownContainer.contains(e.target) &&
        (!elements.modelMenu || !elements.modelMenu.contains(e.target))
      ) {
        toggleModelMenu(false);
      }
    });

    if (elements.tabOllama) {
      elements.tabOllama.addEventListener("click", (e) => {
        e.stopPropagation();
        currentMenuProvider = "ollama";
        updateMenuTabs();
        renderModelList();
      });
    }

    if (elements.tabOpenai) {
      elements.tabOpenai.addEventListener("click", (e) => {
        e.stopPropagation();
        currentMenuProvider = "openai";
        updateMenuTabs();
        renderModelList();
      });
    }

    if (elements.modelSearchInput) {
      elements.modelSearchInput.addEventListener("input", renderModelList);
    }

    if (elements.applyCustomModelBtn) {
      elements.applyCustomModelBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        handleCustomModelApply();
      });
    }

    if (elements.customModelInput) {
      elements.customModelInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          e.stopPropagation();
          handleCustomModelApply();
        }
      });
    }

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

    // Telemetry Table Header Button click
    if (elements.headerTableBtn) {
      elements.headerTableBtn.addEventListener("click", () => {
        if (activeEvidenceHandler) {
          activeEvidenceHandler.toggleOrOpenTable();
        } else if (latestEvidenceTimeline && latestEvidenceTimeline.length > 0) {
          openGlobalTelemetryTable(latestEvidenceTimeline, "Retrieved Evidence Events");
        } else {
          openGlobalTelemetryTable();
        }
      });
    }

    // Global dialog close button
    if (elements.globalDialogCloseBtn) {
      elements.globalDialogCloseBtn.addEventListener("click", () => {
        if (elements.globalTableDialog) elements.globalTableDialog.close();
      });
    }

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
    activeEvidenceHandler = null;
    latestEvidenceTimeline = null;
    if (elements.headerTableBadge) {
      elements.headerTableBadge.textContent = "Telemetry Table";
    }
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
    scrollToBottom(true);

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
        <div class="table-option-group" role="group" aria-label="Data table display options">
          <button class="action-pill-btn evidence-open-table-btn" type="button" title="Open Telemetry Table Modal">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="3" y="3" width="18" height="18" rx="2"></rect><path d="M3 9h18M3 15h18M9 3v18m6-18v18"></path></svg>
            <span>Telemetry Table</span>
          </button>
        </div>
      </div>
      <div class="evidence-hypotheses"></div>
    `;

    const btnOpenTable = evidenceBox.querySelector(".evidence-open-table-btn");
    btnOpenTable.addEventListener("click", () => {
      const timeline = internalState.evidencePack && Array.isArray(internalState.evidencePack.timeline)
        ? internalState.evidencePack.timeline
        : [];
      openGlobalTelemetryTable(timeline, "Retrieved Evidence Events");
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
        internalState.evidencePack = pack;
        const timeline = Array.isArray(pack.timeline) ? pack.timeline : [];
        latestEvidenceTimeline = timeline;

        activeEvidenceHandler = {
          toggleOrOpenTable: () => {
            openGlobalTelemetryTable(timeline, "Retrieved Evidence Events");
          }
        };

        const totalCount = pack.total_kept_events ?? timeline.length;
        if (elements.headerTableBadge) {
          elements.headerTableBadge.textContent = `${totalCount} events`;
        }

        evidenceBox.style.display = "block";
        const countText = `${totalCount} events retained; ${pack.excluded_count ?? 0} rows filtered`;
        const packMeta = evidenceBox.querySelector(".evidence-pack-meta");
        if (packMeta) packMeta.textContent = countText;

        const hypothesisList = evidenceBox.querySelector(".evidence-hypotheses");
        if (hypothesisList) {
          hypothesisList.replaceChildren();
          Object.entries(pack.hypotheses_evidence || {}).forEach(([hypothesis, evidence]) => {
            const row = document.createElement("div");
            row.className = "evidence-hypothesis";
            row.textContent = `${evidence.event_count || 0} candidate event(s): ${hypothesis}`;
            hypothesisList.appendChild(row);
          });
        }
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
        if (!text) return;
        const cleaned = String(text)
          .replace(/<\|?channel[^>]*\|?>/gi, "")
          .replace(/<\/?think>/gi, "")
          .replace(/<\/?thought>/gi, "")
          .trim();
        if (!cleaned) return;
        const rowEl = document.createElement("div");
        rowEl.className = "trace-reasoning";
        rowEl.textContent = cleaned;
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
        // Ensure activeEvidenceHandler and top bar button are hooked to the latest evidence
        if (assistantMsg.state?.evidencePack?.timeline) {
          latestEvidenceTimeline = assistantMsg.state.evidencePack.timeline;
          activeEvidenceHandler = {
            toggleOrOpenTable: () => {
              openGlobalTelemetryTable(latestEvidenceTimeline, "Retrieved Evidence Events");
            }
          };
          if (elements.headerTableBadge) {
            elements.headerTableBadge.textContent = `${latestEvidenceTimeline.length} events`;
          }
        }
        scrollToBottom(true);
        break;

      case "error":
        assistantMsg.setErrorMessage(event.message || "An unexpected error occurred.");
        break;
    }
    scrollToBottom(false);
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
      hypotheses: sessionState.hypotheses,
      evidencePack: sessionState.evidencePack,
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

    if (item.hypotheses && item.hypotheses.length) {
      assistantMsg.addHypotheses(item.hypotheses);
    }
    if (item.evidencePack) {
      assistantMsg.setEvidencePack(item.evidencePack);
      const timeline = Array.isArray(item.evidencePack.timeline) ? item.evidencePack.timeline : [];
      latestEvidenceTimeline = timeline;
      activeEvidenceHandler = {
        toggleOrOpenTable: () => {
          openGlobalTelemetryTable(timeline, "Retrieved Evidence Events");
        }
      };
      if (elements.headerTableBadge) {
        elements.headerTableBadge.textContent = `${item.evidencePack.total_kept_events ?? timeline.length} events`;
      }
    }
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

  function scrollToBottom(force = false) {
    if (!elements.chatStage) return;
    const threshold = 180;
    const isNearBottom =
      elements.chatStage.scrollHeight - elements.chatStage.scrollTop - elements.chatStage.clientHeight <= threshold;
    if (force || isNearBottom) {
      elements.chatStage.scrollTop = elements.chatStage.scrollHeight;
    }
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
