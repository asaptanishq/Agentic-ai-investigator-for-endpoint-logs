/**
 * A1 DFIR investigator — workbench controller.
 *
 * One case column and an on-demand evidence drawer. The drawer's map is an
 * entity tree (evidence-tree.js) built from TelemetryGraph; events and the
 * report sit beside it. Everything shown comes from /api/*.
 */
(function () {
  "use strict";

  var HISTORY_KEY = "a1_case_log_v2";
  var DRAWER_KEY = "a1_drawer_w";
  var DRAWER_MIN = 380;
  var DRAWER_MAX = 900;
  var MAX_HISTORY = 25;

  var STEPS = [
    ["prep", "prepare"],
    ["plan", "plan"],
    ["collect", "collect"],
    ["pack", "pack"],
    ["verdict", "verdict"],
  ];

  var SCENARIOS = [
    {
      db: "attack_lateral_movement.db", code: "ATK-A", host: "WS-OPS-01", category: "attack",
      title: "LSASS access, SMB recon, remote service install",
      query: "Investigate suspicious activity on WS-OPS-01: a process accessed lsass.exe memory and a dump file appeared in a user Temp directory, the same session then opened SMB connections to SRV-FILE-01, and repeated failed network logons for one account were followed by a successful one and a new Windows service installation. Determine whether this is credential dumping and lateral movement or benign administrative activity.",
    },
    {
      db: "attack_lateral_movement.db", code: "INC-A", host: "SRV-FILE-01", category: "ambiguous",
      title: "Unauthorized execution alert with missing telemetry",
      query: "Investigate an alert claiming unauthorized execution on SRV-FILE-01. Examine telemetry for the parent process, network flows, and authentication. If essential telemetry is absent to prove or disprove malicious activity, render an inconclusive outcome citing the specific missing telemetry.",
    },
    {
      db: "attack_data_exfiltration.db", code: "ATK-B", host: "WS-DEV-02", category: "attack",
      title: "PowerShell archiving, scheduled task, outbound HTTPS",
      query: "Investigate suspicious activity on WS-DEV-02: PowerShell spawned an archiver that staged the user's spreadsheets into a password-protected archive in Temp, then dropped a script and created a logon scheduled task, made repeated outbound HTTPS connections to an external address, and the archive was later deleted. Determine whether this is data exfiltration or benign software activity.",
    },
    {
      db: "ransomware_attack_complete_ecs.db", code: "ATK-C", host: "WS-ACCT-01", category: "attack",
      title: "Word document, vssadmin shadow copy deletion, LockBit",
      query: "Investigate suspicious ransomware activity on WS-ACCT-01: Microsoft Word opened invoice_2026-Q3.docx, hidden PowerShell invoked vssadmin.exe to delete shadow copies, and LockBit executed encrypting user documents with .locked extensions. Determine whether this is ransomware or benign activity.",
    },
    {
      db: "attack_lotl_fileless.db", code: "ATK-D", host: "WS-EXEC-02", category: "attack",
      title: "mshta encoded PowerShell, discovery, certutil staging, WMI",
      query: "Investigate suspicious Living-off-the-Land and fileless execution on WS-EXEC-02: mshta.exe spawned hidden encoded PowerShell establishing outbound C2, discovery LOLBins executed, certutil staged payloads, and remote WMI execution occurred against DC-AUTH-01. Determine whether this is a fileless intrusion or benign administrative activity.",
    },
    {
      db: "attack_lotl_fileless.db", code: "AMB-A", host: "WS-EXEC-02", category: "ambiguous",
      title: "certutil and flagged PowerShell during business hours",
      query: "Investigate command-line and utility activity on WS-EXEC-02: certutil.exe and PowerShell with flags were invoked during business hours. Evaluate whether this represents malicious C2 staging, dual-use developer activity, or benign administration, noting any ambiguity in intent.",
    },
    {
      db: "wazuh_lotl_attack_dataset.db", code: "ATK-E", host: "WS-DEV-01", category: "attack",
      title: "LOL PowerShell, SAM hive access, C2 beaconing",
      query: "Investigate suspicious Living-off-the-Land PowerShell execution and SAM registry access on WS-DEV-01 on 2026-10-15. Trace discovery commands, persistence tasks, and C2 exfiltration in Wazuh telemetry.",
    },
    {
      db: "suricata_c2_intrusion.db", code: "ATK-F", host: "WS-FINANCE-01", category: "attack",
      title: "CobaltStrike C2 beaconing to 203.0.113.88:8443",
      query: "Investigate critical Suricata NIDS alerts on WS-FINANCE-01:multiple ET MALWARE CobaltStrike C2 beaconing alerts to 203.0.113.88:8443 between 2026-10-16T14:00:00Z and 2026-10-16T16:02:00Z",
    },
    {
      db: "attack_supply_chain.db", code: "ATK-G", host: "WS-DEV-07", category: "attack",
      title: "CorpTools update, rogue local admin, Kerberos tickets",
      query: "Investigate a potential supply chain compromise on WS-DEV-07: the CorpTools application auto-updated and shortly after, discovery commands were executed, a new local administrator account appeared, Kerberos ticket requests targeted SQL service accounts, and WinRM sessions were established to WS-DBA-03 and DC-CORP-01. Determine whether this is a supply chain attack or legitimate software activity.",
    },
    {
      db: "benign_admin_activity.db", code: "BEN-A", host: "WS-ADMIN-05", category: "benign",
      title: "Backup verification script, SMB, W32Time check",
      query: "Investigate scheduled activity on WS-ADMIN-05: svchost.exe spawned PowerShell running backup_verification.ps1 under CORP\\sysadmin, which opened SMB connections to SRV-FILE-02, wrote to backup_audit_20260915.log, and checked W32Time registry settings. Determine whether this is an attack or benign administrative activity.",
    },
  ];

  var state = {
    provider: "",
    model: "",
    dbPath: "",
    databases: [],
    events: [],
    eventTotal: 0,
    graphData: { nodes: [], edges: [], meta: {} },
    nodeById: new Map(),
    hiddenTypes: new Set(),
    selectedId: null,
    scopeEventIds: null,
    models: { opencode: [], ollama: [], openai: [] },
    apiKeys: { opencode: false, ollama: false, openai: false },
    modelTab: "opencode",
    generating: false,
    abort: null,
    cancelled: false,
    sessionId: null,
    lastSessionId: null,
    currentQuery: "",
    history: [],
    drawerOpen: false,
    activeView: "graph",
    mapView: "graph",
    investigationRan: false,
    graphView: null,
    report: { md: "", verdict: "", at: "" },
    tableRows: [],
  };

  var els = {};
  function $(id) {
    return document.getElementById(id);
  }

  // ---------------------------------------------------------------- utilities

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function pad(n) {
    return n < 10 ? "0" + n : String(n);
  }

  function fmtClock(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso || "").slice(11, 19);
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  function fmtShort(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso || "").slice(0, 19);
    return pad(d.getDate()) + " " + d.toLocaleString("en", { month: "short" }) + " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
  }

  function fmtBytes(n) {
    n = Number(n) || 0;
    if (!n) return "";
    if (n > 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + " MB";
    if (n > 1024) return Math.round(n / 1024) + " KB";
    return n + " B";
  }

  function debounce(fn, ms) {
    var t;
    return function () {
      var args = arguments;
      clearTimeout(t);
      t = setTimeout(function () {
        fn.apply(null, args);
      }, ms);
    };
  }

  function clip(s, n) {
    s = String(s == null ? "" : s);
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  var toastTimer;
  function toast(msg, kind) {
    var t = els.toast;
    t.textContent = msg;
    t.dataset.kind = kind || "info";
    t.classList.add("is-on");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      t.classList.remove("is-on");
    }, kind === "error" ? 6000 : 3200);
  }

  async function copyText(text, label) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      toast((label || "Copied") + " to clipboard");
      return true;
    } catch (e) {
      toast("Clipboard blocked by the browser", "error");
      return false;
    }
  }

  async function api(path, opts) {
    opts = opts || {};
    var res;
    try {
      res = await fetch(path, opts);
    } catch (e) {
      throw new Error("Cannot reach the A1 backend — is the server running?");
    }
    var text = await res.text();
    var body = null;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch (e) {
        body = null;
      }
    }
    if (!res.ok) {
      var detail = (body && (body.detail || body.error)) || text || res.statusText;
      if (typeof detail !== "string") detail = JSON.stringify(detail);
      throw new Error(detail + " (HTTP " + res.status + ")");
    }
    return body;
  }

  function dbLabel(path) {
    if (!path) return "";
    var parts = String(path).split(/[\\/]/);
    return parts[parts.length - 1] || path;
  }

  function hostOfEvent(e) {
    var d = e.details || {};
    return d["host.name"] || d["host.hostname"] || d["agent.name"] || d["agent_name"] || e.host_id || "";
  }

  function eventTime(e) {
    return e.timestamp || (e.details && (e.details["@timestamp"] || e.details.timestamp)) || "";
  }

  // ---------------------------------------------------------------- model menu

  function setModelMenu(open) {
    els.modelMenu.hidden = !open;
    els.modelSelectorPill.setAttribute("aria-expanded", String(open));
    if (open) {
      setCaseMenu(false);
      renderModelList();
      setTimeout(function () {
        els.modelSearchInput.value = "";
        els.modelSearchInput.focus();
      }, 0);
    }
  }

  function modelMenuOpen() {
    return !els.modelMenu.hidden;
  }

  function providerLabel(p) {
    return { opencode: "OpenCode", ollama: "Ollama", openai: "OpenAI" }[p] || p;
  }

  function renderModelList() {
    var q = els.modelSearchInput.value.trim().toLowerCase();
    var list = state.models[state.modelTab] || [];
    var items = list.filter(function (m) {
      return !q || m.toLowerCase().indexOf(q) >= 0;
    });
    if (!items.length) {
      els.modelList.innerHTML = '<p class="menu-note">No models listed for ' + escapeHtml(providerLabel(state.modelTab)) + ".</p>";
      return;
    }
    els.modelList.innerHTML = items
      .map(function (m) {
        var active = m === state.model && state.provider === state.modelTab;
        return (
          '<button class="model-item' + (active ? " is-active" : "") + '" role="option" aria-selected="' + active + '" data-model="' +
          escapeHtml(m) + '"><span>' + escapeHtml(m) + "</span>" +
          (active ? '<span class="model-item-tag">active</span>' : "") +
          "</button>"
        );
      })
      .join("");
  }

  function setProviderTab(p) {
    state.modelTab = p;
    Array.prototype.forEach.call(els.providerTabs.querySelectorAll(".seg-btn"), function (b) {
      b.classList.toggle("is-active", b.dataset.provider === p);
    });
    updateApiKeyUI();
    renderModelList();
  }

  function updateApiKeyUI() {
    if (!els.apiKeyStatus) return;
    var p = state.modelTab;
    var name = providerLabel(p);
    if (p === "ollama") {
      els.apiKeyStatus.textContent = "Ollama runs locally; a key is optional.";
    } else if (state.apiKeys[p]) {
      els.apiKeyStatus.textContent = name + " API key is configured. Paste a new key to replace it.";
    } else {
      els.apiKeyStatus.textContent = name + " API key is not set.";
    }
    els.apiKeyInput.placeholder = "API key for " + name;
  }

  async function saveApiKey() {
    var key = els.apiKeyInput.value.trim();
    if (!key) {
      toast("Enter an API key first", "error");
      return;
    }
    try {
      var res = await api("/api/models/api-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: state.modelTab, api_key: key }),
      });
      state.apiKeys[state.modelTab] = true;
      els.apiKeyInput.value = "";
      if (res && res.models && res.models.has_opencode_key !== undefined) {
        state.apiKeys.opencode = !!res.models.has_opencode_key;
        state.apiKeys.openai = !!res.models.has_openai_key;
      }
      updateApiKeyUI();
      toast(providerLabel(state.modelTab) + " API key saved");
    } catch (e) {
      toast("Could not save API key: " + e.message, "error");
    }
  }

  function updateModelUI() {
    var label = state.model || "select model";
    els.activeModelName.textContent = label;
    els.activeProviderBadge.textContent = state.provider || "—";
    els.composerModel.textContent = state.provider ? state.provider + "/" + state.model : "no model";
    els.modelSelectorPill.title = "Model: " + label + " (" + (state.provider || "unset") + ")";
  }

  async function setModel(provider, model) {
    if (!provider || !model) return;
    try {
      await api("/api/models/set", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: provider, model: model }),
      });
      state.provider = provider;
      state.model = model;
      updateModelUI();
      renderModelList();
      setModelMenu(false);
      toast("Model set to " + provider + "/" + model);
    } catch (e) {
      toast("Could not set model: " + e.message, "error");
    }
  }

  // ---------------------------------------------------------------- datasets

  function setCaseMenu(open) {
    els.caseMenu.hidden = !open;
    els.caseBtn.setAttribute("aria-expanded", String(open));
    if (open) setModelMenu(false);
  }

  function caseMenuOpen() {
    return !els.caseMenu.hidden;
  }

  function renderDatabases() {
    els.dbList.innerHTML = state.databases
      .map(function (db) {
        var path = db.path || db;
        var name = db.name || dbLabel(path);
        var active = path === state.dbPath;
        return (
          '<div class="db-row' + (active ? " is-active" : "") + '">' +
          '<button class="db-pick" data-db="' + escapeHtml(path) + '" title="' + escapeHtml(path) + '">' +
          '<span class="db-name">' + escapeHtml(name) + "</span>" +
          '<span class="db-size">' + escapeHtml(fmtBytes(db.size_bytes)) + "</span>" +
          (active ? '<span class="db-current">current</span>' : "") +
          "</button>" +
          (active ? "" : '<button class="db-del" data-del-db="' + escapeHtml(path) + '" data-del-name="' + escapeHtml(name) + '" title="Delete dataset" aria-label="Delete ' + escapeHtml(name) + '">×</button>') +
          "</div>"
        );
      })
      .join("") || '<p class="menu-note">No datasets found.</p>';
  }

  async function deleteDatabase(path, name) {
    if (state.generating) {
      toast("Stop the current investigation before deleting a dataset", "error");
      return;
    }
    if (!window.confirm('Delete dataset "' + (name || dbLabel(path)) + '"? This cannot be undone.')) return;
    try {
      await api("/api/databases?path=" + encodeURIComponent(path), { method: "DELETE" });
      state.databases = state.databases.filter(function (db) { return (db.path || db) !== path; });
      renderDatabases();
      toast("Deleted " + (name || dbLabel(path)));
    } catch (e) {
      toast("Could not delete dataset: " + e.message, "error");
    }
  }

  function hostList() {
    var hosts = new Set();
    state.events.forEach(function (e) {
      var h = hostOfEvent(e);
      if (h) hosts.add(h);
    });
    return Array.from(hosts);
  }

  function spanLabel() {
    var times = state.events.map(eventTime).filter(Boolean).sort();
    if (!times.length) return "";
    var a = new Date(times[0]);
    var b = new Date(times[times.length - 1]);
    if (isNaN(a.getTime()) || isNaN(b.getTime())) return "";
    var day = function (d) {
      return pad(d.getDate()) + " " + d.toLocaleString("en", { month: "short" });
    };
    if (day(a) === day(b)) return day(a) + " " + pad(a.getHours()) + ":" + pad(a.getMinutes()) + " → " + pad(b.getHours()) + ":" + pad(b.getMinutes());
    return day(a) + " " + pad(a.getHours()) + ":" + pad(a.getMinutes()) + " → " + day(b) + " " + pad(b.getHours()) + ":" + pad(b.getMinutes());
  }

  function setDbChrome() {
    var name = dbLabel(state.dbPath);
    els.headerDbName.textContent = name || "no dataset";
    els.headerDbName.parentElement.title = state.dbPath || "No dataset selected";
    els.composerDb.textContent = name || "no dataset";
    var bits = [];
    if (state.eventTotal) bits.push(state.eventTotal.toLocaleString() + " events");
    var hosts = hostList();
    if (hosts.length) bits.push(hosts.length + (hosts.length === 1 ? " host" : " hosts"));
    var span = spanLabel();
    if (span) bits.push(span);
    els.headerDbMeta.textContent = bits.join(" · ");
    els.dbHint.textContent = state.events.length
      ? "indexed " + state.events.length.toLocaleString() + " of " + state.eventTotal.toLocaleString()
      : "no readable events";
  }

  function updateEmpty() {
    var name = dbLabel(state.dbPath);
    els.emptyTitle.textContent = name || "no dataset";
    var bits = [];
    if (state.eventTotal) bits.push(state.eventTotal.toLocaleString() + " events");
    var hosts = hostList();
    if (hosts.length) bits.push(hosts.length + (hosts.length === 1 ? " host" : " hosts"));
    var span = spanLabel();
    if (span) bits.push(span);
    els.emptyMeta.textContent = bits.join(" · ");
  }

  function renderExamples() {
    var name = dbLabel(state.dbPath);
    var items = SCENARIOS.filter(function (s) {
      return s.db === name;
    });
    els.examplesEmpty.hidden = items.length > 0;
    els.suggestionsList.innerHTML = items
      .map(function (s, i) {
        return (
          '<button class="example" data-example="' + i + '">' +
          '<span class="ex-code">' + escapeHtml(s.code) + "</span>" +
          '<span class="ex-body"><span class="ex-title">' + escapeHtml(s.title) + "</span>" +
          '<span class="ex-meta">' + escapeHtml(s.host) + " · " + escapeHtml(s.category) + "</span></span>" +
          "</button>"
        );
      })
      .join("");
    els.suggestionsList.dataset.db = name;
    state.exampleItems = items;
  }

  async function loadEvents() {
    try {
      var data = await api("/api/events?limit=2500");
      if (data && data.error) throw new Error(data.error);
      state.events = (data && data.events) || [];
      state.eventTotal = (data && data.total) || state.events.length;
      state.scopeEventIds = null;
      rebuildGraph();
      renderTelemetryTable();
      setDbChrome();
      updateEmpty();
    } catch (e) {
      state.events = [];
      state.eventTotal = 0;
      state.scopeEventIds = null;
      state.graphData = { nodes: [], edges: [], meta: {} };
      state.nodeById = new Map();
      renderLegend();
      renderMap();
      renderTelemetryTable();
      setDbChrome();
      updateEmpty();
      toast("Could not load telemetry: " + e.message, "error");
      els.dbHint.textContent = "load failed";
      els.globalDialogTableWrap.innerHTML = '<p class="table-empty">' + escapeHtml(e.message) + "</p>";
    }
  }

  async function switchDatabase(path) {
    if (!path || path === state.dbPath) return true;
    if (state.generating) {
      toast("Stop the current investigation before switching datasets", "error");
      return false;
    }
    var previous = state.dbPath;
    els.dbHint.textContent = "switching…";
    try {
      await api("/api/databases/set", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ db_path: path }),
      });
      state.dbPath = path;
      renderDatabases();
      newInvestigation({ keepPrompt: true, quiet: true });
      await loadEvents();
      renderExamples();
      setDbChrome();
      return true;
    } catch (e) {
      state.dbPath = previous;
      renderDatabases();
      toast("Could not switch dataset: " + e.message, "error");
      return false;
    }
  }

  function scenarioStem(name) {
    return name.replace(/\.[^.]+$/, "").replace(/[-_](?:wazuh|aminer|suricata|eve)$/i, "") || name.replace(/\.[^.]+$/, "");
  }

  function fileToBase64(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () { resolve(String(reader.result).split(",")[1] || ""); };
      reader.onerror = function () { reject(new Error("Could not read " + file.name)); };
      reader.readAsDataURL(file);
    });
  }

  async function uploadDatabase(file) {
    if (!file) return;
    if (state.generating) {
      toast("Stop the current investigation before uploading a dataset", "error");
      return;
    }
    if (!/(\.db|\.json|\.jsonl|\.ndjson|\.log|\.txt)$/i.test(file.name)) {
      toast("Choose a .db database or a .json/.jsonl/.ndjson/.log/.txt log file", "error");
      return;
    }
    if (file.size > 256 * 1024 * 1024) {
      toast("File exceeds the 256 MB upload limit", "error");
      return;
    }
    els.dbHint.textContent = "uploading…";
    try {
      var res = await api("/api/databases/upload?filename=" + encodeURIComponent(file.name), {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: file,
      });
      await loadStatus();
      renderDatabases();
      toast(res.status === "ingested"
        ? "Ingested " + res.rows + " " + res.source + " events into " + res.name
        : "Uploaded " + res.name);
      await switchDatabase(res.path);
    } catch (e) {
      setDbChrome();
      toast("Upload failed: " + e.message, "error");
    }
  }

  async function uploadFileGroup(files) {
    if (!files.length) return;
    if (state.generating) {
      toast("Stop the current investigation before uploading a dataset", "error");
      return;
    }
    for (var i = 0; i < files.length; i++) {
      if (!/\.(db|json|jsonl|ndjson|log|txt)$/i.test(files[i].name)) {
        toast("Choose a .db database or a .json/.jsonl/.ndjson/.log/.txt log file", "error");
        return;
      }
    }
    var dbs = files.filter(function (f) { return /\.db$/i.test(f.name); });
    var logs = files.filter(function (f) { return !/\.db$/i.test(f.name); });
    var totalBytes = files.reduce(function (s, f) { return s + f.size; }, 0);
    if (totalBytes > 256 * 1024 * 1024) {
      toast("Files exceed the 256 MB upload limit", "error");
      return;
    }
    if (logs.length <= 1 && dbs.length <= 1 && files.length === 1) {
      uploadDatabase(files[0]);
      return;
    }
    // Same scenario (e.g. santos_wazuh.json + santos_aminer.json): merge into one database.
    var groups = {};
    dbs.forEach(function (f) { groups[f.name] = [f]; });
    logs.forEach(function (f) {
      var stem = scenarioStem(f.name);
      (groups[stem] = groups[stem] || []).push(f);
    });
    els.dbHint.textContent = "uploading…";
    try {
      for (var key in groups) {
        var group = groups[key];
        if (group.length === 1) {
          await uploadDatabase(group[0]);
          continue;
        }
        var payload = [];
        for (var j = 0; j < group.length; j++) {
          payload.push({ filename: group[j].name, data_base64: await fileToBase64(group[j]) });
        }
        var res = await api("/api/databases/ingest-multi", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ files: payload }),
        });
        await loadStatus();
        renderDatabases();
        var parts = res.files.map(function (f) { return f.filename + " (" + f.source + ")"; }).join(" + ");
        toast("Ingested " + res.rows + " events from " + parts + " into " + res.name);
        await switchDatabase(res.path);
      }
    } catch (e) {
      setDbChrome();
      toast("Upload failed: " + e.message, "error");
    }
  }

  // ---------------------------------------------------------------- map / tree

  function markInvestigated() {
    if (state.investigationRan) return;
    state.investigationRan = true;
    rebuildGraph();
  }

  function rebuildGraph() {
    var source = state.events;
    if (state.scopeEventIds && state.scopeEventIds.size) {
      source = state.events.filter(function (e) {
        return state.scopeEventIds.has(e.event_id);
      });
    }
    state.graphData = window.TelemetryGraph.build(source, { assessRisk: state.investigationRan });
    state.nodeById = new Map();
    state.graphData.nodes.forEach(function (n) {
      state.nodeById.set(n.id, n);
    });
    state.selectedId = null;
    closeInspector();
    A1Tree.reset();
    renderLegend();
    renderMap();
    els.evidenceBadge.textContent = String(state.graphData.nodes.length);
  }

  function renderTree() {
    if (!window.A1Tree) return;
    A1Tree.render(els.graphCanvasContainer, state.graphData, {
      query: els.graphSearchInput ? els.graphSearchInput.value : "",
      hiddenTypes: state.hiddenTypes,
      selectedId: state.selectedId,
      evidenceScope: !!state.scopeEventIds,
      onSelect: selectNode,
    });
  }


  function ensureGraph() {
    if (!state.graphView && window.ForensicGraph && els.graphViewContainer) {
      state.graphView = new window.ForensicGraph(els.graphViewContainer, {
        onSelect: function (node) {
          if (node) selectNode(node.id, true);
        },
        onViewChange: updateMapStats,
      });
      state.graphView.setEmpty("No telemetry loaded.");
    }
    return state.graphView;
  }

  function renderGraph() {
    var g = ensureGraph();
    if (!g) return;
    if (g._a1Data !== state.graphData) {
      g.setData(state.graphData);
      g._a1Data = state.graphData;
      g.resize();
    }
    var types = new Set(
      window.TelemetryGraph.TYPE_ORDER.filter(function (t) {
        return !state.hiddenTypes.has(t);
      })
    );
    g.setTypes(types);
    g.setSearch(els.graphSearchInput ? els.graphSearchInput.value : "");
  }

  function renderMap() {
    var view = state.mapView;
    var graph = view === "graph";
    var links = view === "links";
    els.mapViewGraph.classList.toggle("is-active", graph);
    els.mapViewTree.classList.toggle("is-active", view === "tree");
    els.mapViewLinks.classList.toggle("is-active", links);
    els.mapViewGraph.setAttribute("aria-pressed", String(graph));
    els.mapViewTree.setAttribute("aria-pressed", String(view === "tree"));
    els.mapViewLinks.setAttribute("aria-pressed", String(links));
    els.graphViewContainer.hidden = !graph;
    els.graphCanvasContainer.hidden = view !== "tree";
    els.processLinksContainer.hidden = !links;
    els.treeCollapseBtn.hidden = view !== "tree";
    els.graphLegend.hidden = links;
    if (graph) {
      renderGraph();
    } else if (links) {
      if (window.A1Links) {
        A1Links.render(els.processLinksContainer, state.graphData, {
          query: els.graphSearchInput ? els.graphSearchInput.value : "",
          selectedId: state.selectedId,
          onSelect: selectNode,
        });
      }
    } else {
      renderTree();
    }
    updateMapStats();
  }
  function setMapView(view) {
    if (state.mapView === view) return;
    state.mapView = view;
    renderMap();
  }

  function renderLegend() {
    var counts = {};
    state.graphData.nodes.forEach(function (n) {
      counts[n.type] = (counts[n.type] || 0) + 1;
    });
    var order = window.TelemetryGraph.TYPE_ORDER.filter(function (t) {
      return counts[t];
    });
    var html = order
      .map(function (t) {
        var meta = window.TelemetryGraph.TYPES[t];
        var off = state.hiddenTypes.has(t);
        if (t === "host") {
          return '<span class="type-chip is-static"><i style="background:' + meta.color + '"></i>' + meta.label + "<b>" + counts[t] + "</b></span>";
        }
        return (
          '<button class="type-chip' + (off ? " is-off" : "") + '" data-type="' + t + '" aria-pressed="' + String(!off) + '">' +
          '<i style="background:' + meta.color + '"></i>' + meta.label + "<b>" + counts[t] + "</b></button>"
        );
      })
      .join("");
    var risk = { malicious: 0, suspicious: 0 };
    state.graphData.nodes.forEach(function (n) {
      if (n.risk && n.risk.level && risk[n.risk.level] != null) risk[n.risk.level]++;
    });
    if (risk.malicious) {
      html += '<span class="type-chip is-static risk-chip malicious"><i></i>malicious traces<b>' + risk.malicious + "</b></span>";
    }
    if (risk.suspicious) {
      html += '<span class="type-chip is-static risk-chip suspicious"><i></i>suspicious traces<b>' + risk.suspicious + "</b></span>";
    }
    els.graphLegend.innerHTML = html;
  }
  function updateMapStats() {
    var meta = state.graphData.meta || {};
    var view = state.mapView;
    var links = view === "links";
    var active = links ? els.processLinksContainer : els.graphCanvasContainer;
    var bits;
    if (links) {
      bits = [active.dataset.summary || "0 processes", (meta.hosts || 0) + (meta.hosts === 1 ? " host" : " hosts")];
    } else {
      bits = [
        state.graphData.nodes.length + " entities",
        state.graphData.edges.length + " links",
        (meta.hosts || 0) + (meta.hosts === 1 ? " host" : " hosts"),
      ];
      if (state.hiddenTypes.size) bits.push(state.hiddenTypes.size + " types hidden");
    }
    if (state.scopeEventIds) bits.push("scoped to " + state.scopeEventIds.size + " evidence events");
    var q = els.graphSearchInput.value.trim();
    if (q) {
      if (view === "graph" && state.graphView) bits.push(state.graphView.stats().visible + " matching");
      else bits.push((active.dataset.count || "0") + " matching");
    }
    els.graphStats.textContent = bits.join(" · ");
    els.scopeClearBtn.hidden = !state.scopeEventIds;
    els.graphNodeCountBadge.textContent = String(state.graphData.nodes.length);
  }
  function toggleType(type) {
    if (type === "host") return;
    if (state.hiddenTypes.has(type)) state.hiddenTypes.delete(type);
    else state.hiddenTypes.add(type);
    renderMap();
    renderLegend();
  }

  function selectNode(id, fromGraph) {
    var node = state.nodeById.get(id);
    if (!node) return;
    state.selectedId = id;
    if (window.A1Tree) A1Tree.selectOnly(els.graphCanvasContainer, id);
    if (window.A1Links) A1Links.select(id);
    if (!fromGraph && state.graphView && state.graphView.selectedId !== id) state.graphView.select(id);
    openInspector(node);
  }

  function openInspector(node) {
    var meta = window.TelemetryGraph.TYPES[node.type] || { label: node.type, color: "#8b98a5" };
    els.inspectorTypeBadge.textContent = meta.label;
    els.inspectorTypeBadge.style.color = meta.color;
    els.inspectorTitle.textContent = node.label;
    els.inspectorSubtitle.textContent = node.detail || "";

    var html = "";
    html += '<div class="inspector-actions"><button class="ghost-btn" data-inspector="copy">Copy entity</button></div>';

    if (node.attrs && node.attrs.length) {
      html += '<h3 class="inspector-h">Attributes</h3><table class="kv">';
      node.attrs.forEach(function (a) {
        if (!a[1]) return;
        html += "<tr><th>" + escapeHtml(a[0]) + "</th><td>" + escapeHtml(a[1]) + "</td></tr>";
      });
      html += "</table>";
    }

    var rels = state.graphData.edges.filter(function (e) {
      return e.from === node.id || e.to === node.id;
    });
    if (rels.length) {
      html += '<h3 class="inspector-h">Relations <span class="count">' + rels.length + "</span></h3><ul class=\"rels\">";
      rels.slice(0, 60).forEach(function (e) {
        var out = e.from === node.id;
        var otherId = out ? e.to : e.from;
        var other = state.nodeById.get(otherId);
        var otherMeta = other ? window.TelemetryGraph.TYPES[other.type] : null;
        html +=
          '<li><button class="rel" data-goto="' + escapeHtml(otherId) + '">' +
          '<span class="rel-dir">' + (out ? "→" : "←") + "</span>" +
          '<span class="rel-type">' + escapeHtml(e.label || e.rel) + "</span>" +
          '<span class="rel-target" style="color:' + (otherMeta ? otherMeta.color : "inherit") + '">' +
          escapeHtml(other ? other.label : otherId) + "</span>" +
          (e.count > 1 ? '<b class="rel-count">×' + e.count + "</b>" : "") +
          "</button></li>";
      });
      html += "</ul>";
    }

    if (node.events && node.events.length) {
      html += '<h3 class="inspector-h">Source events <span class="count">' + node.eventCount + "</span></h3><ul class=\"rel-events\">";
      node.events.slice(0, 20).forEach(function (ev) {
        html +=
          '<li><button class="rel ev-link" data-event="' + escapeHtml(ev.id) + '">' +
          '<span class="ev-time">' + escapeHtml(ev.ts ? fmtShort(ev.ts) : "") + "</span>" +
          '<span class="ev-action">' + escapeHtml(ev.action || "event") + "</span></button></li>";
      });
      html += "</ul>";
      if (node.eventCount > node.events.length) {
        html += '<p class="inspector-note">Showing ' + node.events.length + " of " + node.eventCount + " events.</p>";
      }
    }

    els.inspectorBody.innerHTML = html;
    els.graphInspectorDrawer.classList.add("is-open");
    els.graphInspectorDrawer.setAttribute("aria-hidden", "false");
  }

  function closeInspector() {
    els.graphInspectorDrawer.classList.remove("is-open");
    els.graphInspectorDrawer.setAttribute("aria-hidden", "true");
    if (window.A1Links) A1Links.select("");
  }

  async function scopeEvidence(ids) {
    var present = new Set(state.events.map(function (e) { return e.event_id; }));
    var missing = Array.from(ids).filter(function (id) { return !present.has(id); });
    if (missing.length) {
      try {
        var data = await api("/api/events/lookup", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ids: missing })
        });
        if (data && data.error) throw new Error(data.error);
        (data && data.events || []).forEach(function (e) {
          if (!present.has(e.event_id)) {
            present.add(e.event_id);
            state.events.push(e);
          }
        });
      } catch (e) {
        toast("Could not load evidence telemetry: " + e.message, "error");
        return;
      }
    }
    var real = new Set();
    ids.forEach(function (id) {
      if (present.has(id)) real.add(id);
    });
    if (!real.size) {
      toast("The evidence ids in this pack are not in the loaded telemetry", "error");
      return;
    }
    state.scopeEventIds = real;
    state.investigationRan = true;
    rebuildGraph();
    openDrawer("graph");
  }

  // ---------------------------------------------------------------- events table

  function eventRow(e) {
    var d = e.details || {};
    var host = hostOfEvent(e) || "—";
    var proc = d["process.name"] || d["process_name"] || d["data.win.eventdata.image"] || "—";
    var target =
      d["file.path"] ||
      d["registry.path"] ||
      d["data.win.eventdata.targetObject"] ||
      (d["destination.ip"] ? d["destination.ip"] + (d["destination.port"] ? ":" + d["destination.port"] : "") : "") ||
      (d["dest_ip"] ? (d["src_ip"] ? d["src_ip"] + " → " : "") + d["dest_ip"] + (d["dest_port"] ? ":" + d["dest_port"] : "") : "") ||
      d["dns.question.name"] ||
      d["dns.rrname"] ||
      "";
    var cmd = d["process.command_line"] || d["data.win.eventdata.commandLine"] || "";
    var summary = d["rule.description"] || d["alert.signature"] || target || (cmd ? cmd.slice(0, 100) : "");
    return {
      id: e.event_id || "",
      time: eventTime(e),
      host: String(host),
      action: String(e.action || d["event_type"] || "event"),
      proc: String(proc).replace(/^.*[\\/]/, ""),
      summary: String(summary),
      raw: rawJson(e),
    };
  }

  function rawJson(e) {
    var raw = e.raw_json;
    if (typeof raw === "string") {
      try {
        return JSON.stringify(JSON.parse(raw), null, 2);
      } catch (err) {
        return raw;
      }
    }
    if (raw && typeof raw === "object") {
      try {
        return JSON.stringify(raw, null, 2);
      } catch (err) {
        return "";
      }
    }
    try {
      return JSON.stringify(e.details || {}, null, 2);
    } catch (err) {
      return "";
    }
  }

  function renderTelemetryTable() {
    if (!state.events.length) {
      els.globalDialogTableWrap.innerHTML = '<p class="table-empty">No events loaded for this dataset.</p>';
      els.globalDialogMeta.textContent = "0 events";
      els.globalDialogCountBadge.textContent = "";
      state.tableRows = [];
      return;
    }
    els.globalDialogMeta.textContent = state.events.length + " of " + state.eventTotal + " events · newest first";
    filterTelemetryTable();
  }

  function filterTelemetryTable() {
    var q = els.globalDialogSearchInput.value.trim().toLowerCase();
    var rows = state.events.map(eventRow).filter(function (r) {
      if (!q) return true;
      return (r.host + " " + r.action + " " + r.proc + " " + r.summary + " " + r.id).toLowerCase().indexOf(q) >= 0;
    });
    state.tableRows = rows;
    els.globalDialogCountBadge.textContent = rows.length + (rows.length === 1 ? " event" : " events");
    if (!rows.length) {
      els.globalDialogTableWrap.innerHTML = '<p class="table-empty">No event matches “' + escapeHtml(q) + "”.</p>";
      els.globalDialogMeta.textContent = state.events.length + " of " + state.eventTotal + " events";
      return;
    }
    var body = rows
      .slice(0, 800)
      .map(function (r, i) {
        return (
          '<tr class="erow" data-i="' + i + '" tabindex="0" aria-expanded="false">' +
          '<td class="c-time" title="' + escapeHtml(r.time) + '">' + escapeHtml(fmtShort(r.time)) + "</td>" +
          '<td class="c-action">' + escapeHtml(r.action) + "</td>" +
          '<td class="c-host">' + escapeHtml(r.host) + "</td>" +
          '<td class="c-proc" title="' + escapeHtml(r.proc) + '">' + escapeHtml(r.proc) + "</td>" +
          '<td class="c-sum" title="' + escapeHtml(r.summary) + '">' + escapeHtml(r.summary) + "</td>" +
          '<td class="c-id">' + escapeHtml(r.id) + "</td>" +
          "</tr>" +
          '<tr class="eraw" hidden><td colspan="6"><pre>' + escapeHtml(clip(r.raw, 12000)) + "</pre></td></tr>"
        );
      })
      .join("");
    els.globalDialogTableWrap.innerHTML =
      '<table class="events"><thead><tr><th>time</th><th>action</th><th>host</th><th>process</th><th>summary</th><th>event</th></tr></thead><tbody>' +
      body +
      "</tbody></table>";
    if (rows.length > 800) {
      els.globalDialogTableWrap.insertAdjacentHTML("beforeend", '<p class="table-note">Showing first 800 of ' + rows.length + " matching events.</p>");
    }
  }

  function csvFromRows(rows) {
    var out = [["event_id", "timestamp", "host", "action", "process", "summary"]];
    rows.forEach(function (r) {
      out.push([r.id, r.time, r.host, r.action, r.proc, r.summary]);
    });
    return out
      .map(function (r) {
        return r
          .map(function (c) {
            return '"' + String(c).replace(/"/g, '""') + '"';
          })
          .join(",");
      })
      .join("\n");
  }

  // ---------------------------------------------------------------- markdown

  function renderMarkdown(md) {
    if (!md) return '<p class="empty-note">No content.</p>';
    try {
      if (window.marked && window.DOMPurify) {
        return window.DOMPurify.sanitize(window.marked.parse(md));
      }
    } catch (e) {
      /* plain fallback */
    }
    return escapeHtml(md).replace(/\n/g, "<br>");
  }

  // ---------------------------------------------------------------- report

  function setVerdictStamp(label, conf) {
    var v = String(label || "none").toLowerCase();
    els.verdictStamp.dataset.verdict = v;
    els.verdictStampLabel.textContent = v;
    els.verdictStampConf.textContent = conf != null ? conf + "%" : "";
  }

  function clearReport() {
    state.report = { md: "", verdict: "", at: "" };
    els.reportStageContent.innerHTML = '<p class="empty-note">No report yet. A completed investigation writes its report here.</p>';
    els.reportStageVerdictTag.textContent = "no verdict";
    els.reportStageVerdictTag.dataset.verdict = "none";
    els.reportStageVerdictTime.textContent = "";
  }

  function setReport(md, verdict) {
    if (!md) return;
    state.report = { md: md, verdict: verdict || "", at: new Date().toISOString() };
    els.reportStageContent.innerHTML = renderMarkdown(md);
    els.reportStageVerdictTag.textContent = String(verdict || "no verdict").toLowerCase();
    els.reportStageVerdictTag.dataset.verdict = String(verdict || "none").toLowerCase();
    els.reportStageVerdictTime.textContent = "generated " + fmtShort(new Date().toISOString());
  }

  // ---------------------------------------------------------------- turns

  function createTurn(mode) {
    var root = document.createElement("article");
    root.className = "turn turn-a1";
    root.dataset.mode = mode;
    root.innerHTML =
      '<div class="turn-head"><span class="who">a1</span><span class="turn-time">' + fmtClock(new Date().toISOString()) + "</span>" +
      '<span class="turn-state" data-state="running">' + (mode === "chat" ? "answering" : "working") + "</span></div>" +
      (mode === "investigate"
        ? '<ol class="steps">' + STEPS.map(function (s) {
            return '<li class="step" data-step="' + s[0] + '" data-state="idle"><i></i>' + s[1] + "</li>";
          }).join("") + "</ol>"
        : "") +
      '<details class="think" hidden><summary>reasoning <span class="think-count">0</span></summary><div class="think-body"></div></details>' +
      (mode === "investigate"
        ? '<details class="tools" hidden><summary><span>tools</span><span class="tools-count">0</span></summary><div class="tool-list"></div></details>'
        : "") +
      '<div class="hyp"></div>' +
      '<div class="evidence"></div>' +
      '<div class="reply"></div>' +
      '<div class="verdict"></div>' +
      '<div class="report"></div>' +
      '<div class="turn-error" hidden></div>';

    var t = {
      root: root,
      mode: mode,
      toolCount: 0,
      verdictData: null,

      setState: function (s, label) {
        var el = root.querySelector(".turn-state");
        el.dataset.state = s;
        el.textContent = label || s;
        if (s !== "running") {
          root.querySelectorAll('.step[data-state="run"]').forEach(function (li) {
            li.dataset.state = s === "failed" ? "failed" : "done";
          });
        }
      },

      setStep: function (key, st) {
        var li = root.querySelector('.step[data-step="' + key + '"]');
        if (li) li.dataset.state = st;
      },

      think: function (text) {
        if (!text) return;
        var box = root.querySelector(".think");
        var body = box.querySelector(".think-body");
        box.hidden = false;
        var p = document.createElement("p");
        p.textContent = text;
        body.appendChild(p);
        box.querySelector(".think-count").textContent = String(body.querySelectorAll("p").length);
      },

      toolCall: function (name, args) {
        var list = root.querySelector(".tool-list");
        root.querySelector(".tools").hidden = false;
        var d = document.createElement("details");
        d.className = "tool";
        d.dataset.tool = name;
        var argText = args && typeof args === "object" ? JSON.stringify(args) : String(args || "");
        d.innerHTML =
          '<summary><span class="tool-name">' + escapeHtml(name) + '</span><span class="tool-sum">' + escapeHtml(clip(argText, 90)) + "</span></summary>" +
          '<div class="tool-body"><pre class="tool-args">' + escapeHtml(argText) + '</pre><div class="tool-result"></div></div>';
        list.appendChild(d);
        t.toolCount++;
        root.querySelector(".tools-count").textContent = String(t.toolCount);
      },

      toolResult: function (name, summary, raw) {
        var list = root.querySelector(".tool-list");
        var found = null;
        Array.prototype.forEach.call(list.querySelectorAll(".tool"), function (d) {
          if (d.dataset.tool === name) found = d;
        });
        if (!found) {
          t.toolCall(name, "");
          found = list.lastElementChild;
        }
        var box = found.querySelector(".tool-result");
        if (summary) {
          var p = document.createElement("p");
          p.className = "tool-result-line";
          p.textContent = summary;
          box.appendChild(p);
        }
        if (raw) {
          var pre = document.createElement("pre");
          pre.className = "tool-raw";
          pre.textContent = clip(String(raw), 6000);
          box.appendChild(pre);
        }
      },

      hypotheses: function (list, evidenceMap) {
        var wrap = root.querySelector(".hyp");
        if (!list || !list.length) return;
        var html = '<h3 class="turn-h">Hypotheses</h3><ul class="hyp-list">';
        list.forEach(function (h) {
          var text = typeof h === "string" ? h : h.hypothesis || h.text || h.description || JSON.stringify(h);
          var info = evidenceMap && (evidenceMap[text] || evidenceMap[String(text).trim()]);
          var status = info && info.status ? String(info.status).toLowerCase() : "";
          var count = info ? info.event_count : null;
          var glyph = /confirm|support|true/.test(status) ? "✓" : /refut|false/.test(status) ? "✕" : /inconclusive/.test(status) ? "?" : "·";
          html +=
            '<li class="hyp-item" data-status="' + escapeHtml(status || "open") + '">' +
            '<span class="hyp-glyph">' + glyph + "</span>" +
            '<span class="hyp-text">' + escapeHtml(text) + "</span>" +
            (count != null ? '<span class="hyp-count">' + count + " ev</span>" : "") +
            "</li>";
        });
        html += "</ul>";
        wrap.innerHTML = html;
      },

      evidence: function (data) {
        var wrap = root.querySelector(".evidence");
        var timeline = data.timeline || [];
        var ids = new Set();
        timeline.forEach(function (e) {
          if (!e) return;
          var id = e.event_id || e.id;
          if (id) ids.add(id);
        });
        var kept = data.total_kept_events || ids.size;
        var html =
          '<h3 class="turn-h">Evidence <span class="count">' + kept + " kept</span></h3>" +
          '<p class="evidence-line">' + timeline.length + " timeline events · " + (data.excluded_count || 0) + " excluded by scope</p>" +
          '<div class="evidence-actions">' +
          '<button class="ghost-btn" data-ev="map">Map evidence</button>' +
          '<button class="ghost-btn" data-ev="events">Events</button>' +
          "</div>";
        if (timeline.length) {
          html += '<ul class="tl">';
          timeline.slice(0, 8).forEach(function (e) {
            html +=
              '<li><span class="tl-time">' + escapeHtml(e.timestamp ? fmtShort(e.timestamp) : "—") + "</span>" +
              '<span class="tl-host">' + escapeHtml(e.host_id || "") + "</span>" +
              '<span class="tl-sum">' + escapeHtml(e.summary || "") + "</span></li>";
          });
          html += "</ul>";
          if (timeline.length > 8) html += '<p class="evidence-line">+' + (timeline.length - 8) + " more in events.</p>";
        }
        wrap.innerHTML = html;
        var mapBtn = wrap.querySelector('[data-ev="map"]');
        var evBtn = wrap.querySelector('[data-ev="events"]');
        if (mapBtn) {
          mapBtn.addEventListener("click", function () {
            if (!ids.size) {
              toast("This pack carries no event ids to scope by", "error");
              return;
            }
            scopeEvidence(ids);
          });
        }
        if (evBtn) {
          evBtn.addEventListener("click", function () {
            openDrawer("telemetry");
          });
        }
      },

      reply: function (html) {
        root.querySelector(".reply").innerHTML = html;
      },

      verdict: function (v) {
        t.verdictData = v;
        var verdict = String(v.verdict || "UNKNOWN").toUpperCase();
        var conf = typeof v.confidence === "number" ? Math.round(v.confidence * 100) : null;
        root.querySelector(".verdict").innerHTML =
          '<div class="verdict-box" data-verdict="' + escapeHtml(verdict.toLowerCase()) + '">' +
          '<span class="verdict-label">' + escapeHtml(verdict) + "</span>" +
          (conf != null ? '<span class="verdict-conf">confidence ' + conf + "%</span>" : "") +
          (v.verdict_boundary ? '<span class="verdict-bound">' + escapeHtml(v.verdict_boundary) + "</span>" : "") +
          "</div>";
        setVerdictStamp(verdict, conf);
      },

      report: function (md, verdict) {
        var wrap = root.querySelector(".report");
        if (!md) return;
        wrap.innerHTML = '<button class="report-link">Read report <span aria-hidden="true">→</span></button>';
        wrap.querySelector(".report-link").addEventListener("click", function () {
          setReport(md, verdict);
          openDrawer("report");
        });
      },

      error: function (msg) {
        var el = root.querySelector(".turn-error");
        el.hidden = false;
        el.innerHTML = "<b>Run failed</b><span>" + escapeHtml(msg) + "</span>";
        t.setState("failed", "failed");
      },
    };
    return t;
  }

  function addUserTurn(text) {
    var art = document.createElement("article");
    art.className = "turn turn-user";
    art.innerHTML =
      '<div class="turn-head"><span class="who">you</span><span class="turn-time">' + fmtClock(new Date().toISOString()) + "</span></div>" +
      '<p class="user-text">' + escapeHtml(text) + "</p>";
    els.messagesContainer.appendChild(art);
  }

  // ---------------------------------------------------------------- investigation

  function handleStreamEvent(turn, payload) {
    var type = payload.type;
    var data = payload.data || payload;
    switch (type) {
      case "start":
        if (data.session_id) state.sessionId = data.session_id;
        turn.setStep("prep", "run");
        break;
      case "alert_prep":
        turn.setStep("prep", "done");
        turn.setStep("plan", "run");
        break;
      case "triage":
        turn.setStep("plan", "done");
        turn.setStep("collect", "run");
        turn.hypotheses(data.hypotheses || [], null);
        if (data.plan) turn.think(data.plan);
        break;
      case "loop":
        break;
      case "evidence_pack":
        turn.setStep("collect", "done");
        turn.setStep("pack", "done");
        turn.setStep("verdict", "run");
        turn.hypotheses(Object.keys(data.hypotheses_evidence || {}), data.hypotheses_evidence);
        turn.evidence(data);
        markInvestigated();
        break;
      case "tool_call":
        turn.toolCall(data.tool || data.name || "tool", data.args || data.arguments || "");
        break;
      case "tool_result":
        turn.toolResult(data.tool || data.name || "tool", data.summary || "", data.raw || data.output || "");
        break;
      case "thought":
      case "reasoning":
        turn.think(data.text || data.content || "");
        break;
      case "complete":
        if (typeof data.reply === "string" && !data.report) {
          turn.reply(renderMarkdown(data.reply));
          turn.setState("done", "answered");
          break;
        }
        turn.setStep("verdict", "done");
        markInvestigated();
        turn.verdict(data);
        if (data.report) {
          turn.report(data.report, data.verdict);
          setReport(data.report, data.verdict);
        }
        turn.setState("done", "complete");
        state.lastSessionId = state.sessionId || state.lastSessionId;
        saveHistory({
          id: state.sessionId,
          query: state.currentQuery,
          db: dbLabel(state.dbPath),
          verdict: data.verdict || "UNKNOWN",
          confidence: data.confidence,
          report: data.report || "",
          at: new Date().toISOString(),
        });
        break;
      case "error":
        turn.error(data.message || data.error || "Unknown backend error");
        toast(data.message || "The run failed", "error");
        break;
      case "cancelled":
        turn.setState("cancelled", "cancelled");
        break;
      default:
        break;
    }
    scrollStream(type === "complete" || type === "cancelled" || type === "error");
  }

  async function streamRequest(path, body, turn) {
    state.abort = new AbortController();
    var res;
    try {
      res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: state.abort.signal,
      });
    } catch (e) {
      throw new Error("Could not reach the A1 backend.");
    }
    if (!res.ok) {
      var text = await res.text();
      var msg = text;
      try {
        var j = JSON.parse(text);
        msg = j.detail || j.error || text;
      } catch (e) {
        /* plain text body */
      }
      throw new Error((msg || res.statusText) + " (HTTP " + res.status + ")");
    }
    if (!res.body) throw new Error("This browser cannot stream responses.");

    var reader = res.body.getReader();
    var decoder = new TextDecoder();
    var buffer = "";
    for (;;) {
      var chunk = await reader.read();
      if (chunk.done) break;
      buffer += decoder.decode(chunk.value, { stream: true });
      var idx;
      while ((idx = buffer.indexOf("\n\n")) >= 0) {
        var block = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        var lines = block.split("\n");
        var payload = [];
        for (var i = 0; i < lines.length; i++) {
          if (lines[i].indexOf("data:") === 0) payload.push(lines[i].slice(5).trim());
        }
        if (!payload.length) continue;
        var parsed;
        try {
          parsed = JSON.parse(payload.join("\n"));
        } catch (e) {
          continue;
        }
        handleStreamEvent(turn, parsed);
      }
    }
  }

  function setGenerating(on) {
    state.generating = on;
    els.sendBtn.classList.toggle("is-stop", on);
    els.sendBtn.setAttribute("aria-label", on ? "Stop investigation" : "Send investigation");
    els.newCaseBtn.disabled = on;
    els.promptInput.readOnly = on;
    els.composerHint.textContent = on ? "streaming · press stop to cancel" : "Enter to send · Shift+Enter for a new line";
  }

  async function submitPrompt(text) {
    if (state.generating) return;
    text = (text || "").trim();
    if (!text) {
      els.promptInput.focus();
      return;
    }
    if (!state.dbPath) {
      toast("Select a dataset first", "error");
      return;
    }
    els.welcomeScreen.hidden = true;
    addUserTurn(text);
    var isFollowUp = !!state.lastSessionId;
    var turn = createTurn(isFollowUp ? "chat" : "investigate");
    els.messagesContainer.appendChild(turn.root);
    scrollStream(true);
    state.currentQuery = text;
    state.sessionId = null;
    state.cancelled = false;
    setGenerating(true);
    els.promptInput.value = "";
    autosize();

    var path = isFollowUp ? "/api/chat" : "/api/investigate";
    var body = isFollowUp
      ? { message: text, session_id: state.lastSessionId, provider: state.provider, model: state.model, db_path: state.dbPath }
      : { query: text, provider: state.provider, model: state.model, db_path: state.dbPath };

    try {
      await streamRequest(path, body, turn);
      if (turn.root.querySelector(".turn-state").dataset.state === "running") {
        turn.setState("done", "stream closed");
      }
    } catch (e) {
      if (state.cancelled) {
        turn.setState("cancelled", "cancelled");
      } else {
        turn.error(e.message);
        toast("Investigation failed: " + e.message, "error");
      }
    } finally {
      state.generating = false;
      state.abort = null;
      setGenerating(false);
      scrollStream();
    }
  }

  async function stopRun() {
    if (!state.generating) return;
    state.cancelled = true;
    try {
      await api("/api/cancel", { method: "POST" });
    } catch (e) {
      toast("Cancel request failed: " + e.message, "error");
    }
    if (state.abort) state.abort.abort();
    setGenerating(false);
  }

  function scrollStream(force) {
    var el = els.stream;
    var near = el.scrollHeight - el.scrollTop - el.clientHeight < 160;
    if (force || near) el.scrollTop = el.scrollHeight;
  }

  // ---------------------------------------------------------------- history

  function loadHistory() {
    try {
      var raw = localStorage.getItem(HISTORY_KEY);
      state.history = raw ? JSON.parse(raw) : [];
    } catch (e) {
      state.history = [];
    }
    if (!Array.isArray(state.history)) state.history = [];
    renderHistory();
  }

  function saveHistory(entry) {
    if (!entry || !entry.query) return;
    state.history = state.history.filter(function (h) {
      return !(h.query === entry.query && (h.db || "") === (entry.db || ""));
    });
    state.history.unshift(entry);
    state.history = state.history.slice(0, MAX_HISTORY);
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(state.history));
    } catch (e) {
      toast("Case log is full — could not save this run", "error");
    }
    renderHistory();
  }

  function renderHistory() {
    if (!state.history.length) {
      els.historyList.innerHTML = '<p class="menu-note">No saved runs.</p>';
      return;
    }
    els.historyList.innerHTML = state.history
      .map(function (h, i) {
        return (
          '<div class="history-row">' +
          '<button class="history-item" data-history="' + i + '" title="' + escapeHtml(h.query) + '">' +
          '<span class="history-verdict" data-verdict="' + escapeHtml(String(h.verdict || "").toLowerCase()) + '"></span>' +
          '<span class="history-text">' + escapeHtml(h.query) + "</span>" +
          '<span class="history-meta">' + escapeHtml(h.db || "") + (h.at ? " · " + escapeHtml(fmtShort(h.at)) : "") + "</span>" +
          "</button>" +
          '<button class="history-del" data-del="' + i + '" aria-label="Delete saved run">×</button></div>'
        );
      })
      .join("");
  }

  async function openHistoryItem(i) {
    var h = state.history[i];
    if (!h || state.generating) return;
    if (h.db && h.db !== dbLabel(state.dbPath)) {
      var db = state.databases.find(function (d) {
        return (d.name || dbLabel(d.path || d)) === h.db;
      });
      if (db) {
        var ok = await switchDatabase(db.path || db);
        if (!ok) return;
      }
    }
    setCaseMenu(false);
    els.welcomeScreen.hidden = true;
    addUserTurn(h.query);
    var turn = createTurn("investigate");
    els.messagesContainer.appendChild(turn.root);
    STEPS.forEach(function (s) {
      turn.setStep(s[0], "done");
    });
    turn.setState("done", "restored");
    if (h.verdict) {
      turn.verdict({ verdict: h.verdict, confidence: h.confidence });
    }
    if (h.report) {
      turn.report(h.report, h.verdict);
      setReport(h.report, h.verdict);
    } else if (h.verdict) {
      setVerdictStamp(h.verdict, h.confidence);
    }
    if (h.report || h.verdict) {
      state.investigationRan = true;
      rebuildGraph();
    }
    if (h.report) openDrawer("report");
    scrollStream(true);
  }

  // ---------------------------------------------------------------- drawer / views

  function drawerMax() {
    return Math.max(DRAWER_MIN, Math.min(DRAWER_MAX, window.innerWidth - 420));
  }

  function applyDrawerWidth(px) {
    var width = Math.max(DRAWER_MIN, Math.min(drawerMax(), Number(px) || DRAWER_MIN));
    document.documentElement.style.setProperty("--drawer-w", Math.round(width) + "px");
    if (els.drawerGrip) els.drawerGrip.setAttribute("aria-valuenow", String(Math.round(width)));
    return width;
  }

  function openDrawer(view) {
    if (!state.drawerOpen) {
      state.drawerOpen = true;
      els.drawer.classList.add("is-open");
      els.drawer.setAttribute("aria-hidden", "false");
      els.drawerBackdrop.classList.add("is-open");
      document.body.classList.add("drawer-open");
      els.evidenceBtn.setAttribute("aria-pressed", "true");
      var saved = Number(localStorage.getItem(DRAWER_KEY));
      if (saved >= DRAWER_MIN) applyDrawerWidth(saved);
    }
    switchView(view || state.activeView);
  }

  function closeDrawer() {
    if (!state.drawerOpen) return;
    state.drawerOpen = false;
    els.drawer.classList.remove("is-open");
    els.drawer.setAttribute("aria-hidden", "true");
    els.drawerBackdrop.classList.remove("is-open");
    document.body.classList.remove("drawer-open");
    els.evidenceBtn.setAttribute("aria-pressed", "false");
    closeInspector();
  }
  function toggleDrawer() {
    if (state.drawerOpen) closeDrawer();
    else openDrawer(state.activeView);
  }

  function switchView(view) {
    state.activeView = view;
    var panes = { graph: els.graphStage, telemetry: els.telemetryStage, report: els.reportStage };
    var tabs = { graph: els.tabViewGraph, telemetry: els.tabViewTelemetry, report: els.tabViewReport };
    Object.keys(panes).forEach(function (k) {
      panes[k].hidden = k !== view;
      panes[k].classList.toggle("is-active", k === view);
      tabs[k].classList.toggle("is-active", k === view);
      tabs[k].setAttribute("aria-selected", String(k === view));
    });
    if (view === "telemetry" && !state.events.length) renderTelemetryTable();
    if (view === "report" && state.report.md) setReport(state.report.md, state.report.verdict);
    if (view === "graph" && state.mapView === "graph" && state.graphView) {
      requestAnimationFrame(function () {
        if (state.drawerOpen) state.graphView.resize();
      });
    }
  }

  function newInvestigation(opts) {
    opts = opts || {};
    if (state.generating && !opts.quiet) {
      toast("Stop the current investigation first", "error");
      return;
    }
    els.messagesContainer.innerHTML = "";
    els.welcomeScreen.hidden = false;
    setVerdictStamp("none", null);
    clearReport();
    state.sessionId = null;
    state.lastSessionId = null;
    state.selectedId = null;
    state.scopeEventIds = null;
    state.investigationRan = false;
    state.hiddenTypes = new Set();
    els.graphSearchInput.value = "";
    els.reportStageVerdictTime.textContent = "";
    closeInspector();
    A1Tree.reset();
    rebuildGraph();
    if (!opts.keepPrompt) {
      els.promptInput.value = "";
      autosize();
    }
    els.promptInput.focus();
    scrollStream(true);
  }

  // ---------------------------------------------------------------- wiring

  function autosize() {
    var ta = els.promptInput;
    ta.style.height = "auto";
    ta.style.height = Math.min(170, ta.scrollHeight) + "px";
  }

  function setupEvents() {
    els.newCaseBtn.addEventListener("click", function () {
      newInvestigation();
    });

    els.caseBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      setCaseMenu(!caseMenuOpen());
    });
    els.dbList.addEventListener("click", function (e) {
      var del = e.target.closest("[data-del-db]");
      if (del) {
        deleteDatabase(del.dataset.delDb, del.dataset.delName);
        return;
      }
      var b = e.target.closest("[data-db]");
      if (b) switchDatabase(b.dataset.db);
    });
    els.uploadDbBtn.addEventListener("click", function () {
      if (state.generating) {
        toast("Stop the current investigation before uploading a dataset", "error");
        return;
      }
      els.uploadDbInput.click();
    });
    els.uploadDbInput.addEventListener("change", function () {
      var files = Array.prototype.slice.call(els.uploadDbInput.files || []);
      els.uploadDbInput.value = "";
      uploadFileGroup(files);
    });
    els.clearHistoryBtn.addEventListener("click", function () {
      if (!state.history.length) {
        toast("Case log is already empty");
        return;
      }
      if (!window.confirm("Delete all " + state.history.length + " saved investigations?")) return;
      state.history = [];
      localStorage.removeItem(HISTORY_KEY);
      renderHistory();
      toast("Case log cleared");
    });
    els.historyList.addEventListener("click", function (e) {
      var del = e.target.closest("[data-del]");
      if (del) {
        state.history.splice(Number(del.dataset.del), 1);
        localStorage.setItem(HISTORY_KEY, JSON.stringify(state.history));
        renderHistory();
        return;
      }
      var item = e.target.closest("[data-history]");
      if (item) openHistoryItem(Number(item.dataset.history));
    });

    els.modelSelectorPill.addEventListener("click", function (e) {
      e.stopPropagation();
      setModelMenu(!modelMenuOpen());
    });
    els.providerTabs.addEventListener("click", function (e) {
      var b = e.target.closest("[data-provider]");
      if (b) setProviderTab(b.dataset.provider);
    });
    els.modelList.addEventListener("click", function (e) {
      var b = e.target.closest("[data-model]");
      if (b) setModel(state.modelTab, b.dataset.model);
    });
    els.modelSearchInput.addEventListener("input", renderModelList);
    els.saveApiKeyBtn.addEventListener("click", saveApiKey);
    els.apiKeyInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") saveApiKey();
    });
    els.modelSearchInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        var first = els.modelList.querySelector("[data-model]");
        if (first) setModel(state.modelTab, first.dataset.model);
      }
    });
    els.applyCustomModelBtn.addEventListener("click", function () {
      var v = els.customModelInput.value.trim();
      if (!v) {
        toast("Enter a model id first", "error");
        return;
      }
      setModel(state.modelTab, v);
      els.customModelInput.value = "";
    });

    document.addEventListener("click", function (e) {
      if (modelMenuOpen() && !els.modelDropdownContainer.contains(e.target)) setModelMenu(false);
      if (caseMenuOpen() && !els.caseBtn.parentElement.contains(e.target)) setCaseMenu(false);
    });

    els.promptInput.addEventListener("input", autosize);
    els.promptInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        if (!state.generating) submitPrompt(els.promptInput.value);
      }
    });
    els.sendBtn.addEventListener("click", function () {
      if (state.generating) stopRun();
      else submitPrompt(els.promptInput.value);
    });

    els.suggestionsList.addEventListener("click", async function (e) {
      var b = e.target.closest("[data-example]");
      if (!b) return;
      if (state.generating) {
        toast("An investigation is running — stop it first", "error");
        return;
      }
      var s = (state.exampleItems || [])[Number(b.dataset.example)];
      if (!s) return;
      if (dbLabel(state.dbPath) !== s.db) {
        var db = state.databases.find(function (d) {
          return (d.name || dbLabel(d.path || d)) === s.db;
        });
        if (!db) {
          toast("Dataset " + s.db + " is not available", "error");
          return;
        }
        var ok = await switchDatabase(db.path || db);
        if (!ok) return;
      }
      els.promptInput.value = s.query;
      autosize();
      submitPrompt(s.query);
    });

    els.evidenceBtn.addEventListener("click", toggleDrawer);
    els.mapCloseBtn.addEventListener("click", closeDrawer);
    els.scopeClearBtn.addEventListener("click", function () {
      state.scopeEventIds = null;
      rebuildGraph();
    });
    els.treeCollapseBtn.addEventListener("click", function () {
      A1Tree.collapseAll();
    });
    els.mapViewGraph.addEventListener("click", function () {
      setMapView("graph");
    });
    els.mapViewTree.addEventListener("click", function () {
      setMapView("tree");
    });
    els.mapViewLinks.addEventListener("click", function () {
      setMapView("links");
    });
    els.drawerBackdrop.addEventListener("click", closeDrawer);
    window.addEventListener("resize", debounce(function () {
      if (state.drawerOpen && window.innerWidth > 900) applyDrawerWidth(els.drawer.getBoundingClientRect().width);
    }, 100));

    els.tabViewGraph.addEventListener("click", function () { switchView("graph"); });
    els.tabViewTelemetry.addEventListener("click", function () { switchView("telemetry"); });
    els.tabViewReport.addEventListener("click", function () { switchView("report"); });

    els.graphSearchInput.addEventListener("input", debounce(renderMap, 120));
    els.graphLegend.addEventListener("click", function (e) {
      var b = e.target.closest("[data-type]");
      if (b) toggleType(b.dataset.type);
    });

    els.globalDialogSearchInput.addEventListener("input", debounce(filterTelemetryTable, 120));
    els.globalDialogCopyBtn.addEventListener("click", function () {
      if (!state.tableRows.length) {
        toast("No events to copy", "error");
        return;
      }
      copyText(csvFromRows(state.tableRows), "Events CSV");
    });

    els.globalDialogTableWrap.addEventListener("click", function (e) {
      var row = e.target.closest(".erow");
      if (!row) return;
      var raw = row.nextElementSibling;
      if (!raw) return;
      raw.hidden = !raw.hidden;
      row.setAttribute("aria-expanded", String(!raw.hidden));
    });
    els.globalDialogTableWrap.addEventListener("keydown", function (e) {
      if (e.key !== "Enter" && e.key !== " ") return;
      var row = e.target.closest(".erow");
      if (!row) return;
      e.preventDefault();
      row.click();
    });

    els.reportStageCopyBtn.addEventListener("click", function () {
      if (!state.report.md) {
        toast("No report to copy yet", "error");
        return;
      }
      copyText(state.report.md, "Report markdown");
    });

    els.inspectorCloseBtn.addEventListener("click", function () {
      closeInspector();
      state.selectedId = null;
      A1Tree.selectOnly(els.graphCanvasContainer, "");
    });
    els.inspectorBody.addEventListener("click", function (e) {
      var action = e.target.closest("[data-inspector]");
      if (action) {
        if (action.dataset.inspector === "copy" && state.selectedId) {
          copyText(state.selectedId.split(":").slice(1).join(":") || state.selectedId, "Entity");
        }
        return;
      }
      var go = e.target.closest("[data-goto]");
      if (go) {
        A1Tree.select(go.dataset.goto);
        return;
      }
      var ev = e.target.closest("[data-event]");
      if (ev) {
        openDrawer("telemetry");
        els.globalDialogSearchInput.value = ev.dataset.event;
        filterTelemetryTable();
      }
    });

    els.shortcutsBtn.addEventListener("click", function () {
      els.shortcutsPop.hidden = !els.shortcutsPop.hidden;
    });
    els.shortcutsCloseBtn.addEventListener("click", function () {
      els.shortcutsPop.hidden = true;
    });

    els.drawerGrip.addEventListener("pointerdown", function (e) {
      if (window.matchMedia("(max-width: 900px)").matches) return;
      e.preventDefault();
      var grip = els.drawerGrip;
      var startX = e.clientX;
      var startW = els.drawer.getBoundingClientRect().width;
      var width = startW;
      var max = drawerMax();
      document.body.classList.add("is-resizing");
      try {
        grip.setPointerCapture(e.pointerId);
      } catch (err) {
        /* pointer capture is best effort */
      }
      function move(ev) {
        width = Math.max(DRAWER_MIN, Math.min(max, startW + (startX - ev.clientX)));
        document.documentElement.style.setProperty("--drawer-w", Math.round(width) + "px");
      }
      function up() {
        document.removeEventListener("pointermove", move);
        document.removeEventListener("pointerup", up);
        document.removeEventListener("pointercancel", up);
        document.body.classList.remove("is-resizing");
        try {
          if (grip.hasPointerCapture(e.pointerId)) grip.releasePointerCapture(e.pointerId);
        } catch (err) {
          /* ignore */
        }
        try {
          localStorage.setItem(DRAWER_KEY, String(Math.round(width)));
        } catch (err) {
          /* storage may be unavailable */
        }
        // Let the table and inspector settle against the final width.
        requestAnimationFrame(function () {
          void els.drawer.offsetWidth;
        });
      }
      document.addEventListener("pointermove", move);
      document.addEventListener("pointerup", up);
      document.addEventListener("pointercancel", up);
    });

    els.drawerGrip.addEventListener("keydown", function (e) {
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      e.preventDefault();
      var width = applyDrawerWidth(els.drawer.getBoundingClientRect().width + (e.key === "ArrowLeft" ? 24 : -24));
      try {
        localStorage.setItem(DRAWER_KEY, String(Math.round(width)));
      } catch (err) {
        /* ignore */
      }
    });

    els.drawerGrip.addEventListener("dblclick", function () {
      var width = Math.min(620, Math.max(DRAWER_MIN, Math.round(window.innerWidth * 0.52)));
      applyDrawerWidth(width);
      try {
        localStorage.setItem(DRAWER_KEY, String(Math.round(width)));
      } catch (err) {
        /* ignore */
      }
    });

    document.addEventListener("keydown", function (e) {
      var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
      if (e.key === "Escape") {
        if (modelMenuOpen()) return setModelMenu(false);
        if (caseMenuOpen()) return setCaseMenu(false);
        if (!els.shortcutsPop.hidden) {
          els.shortcutsPop.hidden = true;
          return;
        }
        if (els.graphInspectorDrawer.classList.contains("is-open")) return closeInspector();
        if (state.drawerOpen) return closeDrawer();
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setModelMenu(!modelMenuOpen());
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "e") {
        e.preventDefault();
        toggleDrawer();
        return;
      }
      if (e.key === "?" && !typing) {
        els.shortcutsPop.hidden = !els.shortcutsPop.hidden;
        return;
      }
      if (e.key === "Enter" && !typing && !state.generating && !els.welcomeScreen.hidden) {
        els.promptInput.focus();
      }
    });
  }

  // ---------------------------------------------------------------- boot

  async function loadStatus() {
    try {
      var s = await api("/api/status");
      state.databases = s.databases || [];
      state.dbPath = s.current_db || (state.databases[0] ? state.databases[0].path : "");
      var llm = s.active_llm || {};
      state.provider = llm.provider || "";
      state.model = llm.model || "";
      els.railStatus.innerHTML = '<i class="dot"></i><span>' + escapeHtml((state.provider || "no provider") + " · local") + "</span>";
    } catch (e) {
      toast("Backend status unavailable: " + e.message, "error");
      els.railStatus.innerHTML = '<i class="dot is-bad"></i><span>backend offline</span>';
    }
    renderDatabases();
    updateApiKeyUI();
    updateModelUI();
    setDbChrome();
  }

  async function loadModels() {
    try {
      var m = await api("/api/models");
      state.models = {
        opencode: m.opencode || [],
        ollama: m.ollama || [],
        openai: m.openai || [],
      };
      state.apiKeys = {
        opencode: !!m.has_opencode_key,
        ollama: !!m.has_ollama_key,
        openai: !!m.has_openai_key,
      };
      if (state.provider && state.models[state.provider]) setProviderTab(state.provider);
      else setProviderTab("opencode");
    } catch (e) {
      els.modelList.innerHTML = '<p class="menu-note">Model catalog unavailable: ' + escapeHtml(e.message) + "</p>";
    }
  }

  function init() {
    [
      "newCaseBtn", "caseBtn", "caseMenu", "headerDbName", "dbHint", "dbList", "clearHistoryBtn",
      "uploadDbBtn", "uploadDbInput",
      "historyList", "railStatus", "headerDbMeta", "verdictStamp", "verdictStampLabel", "verdictStampConf",
      "evidenceBtn", "evidenceBadge", "modelDropdownContainer", "modelSelectorPill", "activeModelName",
      "activeProviderBadge", "modelMenu", "providerTabs", "modelSearchInput", "modelList", "customModelInput",
      "applyCustomModelBtn", "saveApiKeyBtn", "apiKeyInput", "apiKeyStatus", "shortcutsBtn", "stream", "welcomeScreen", "emptyTitle", "emptyMeta",
      "suggestionsList", "examplesEmpty", "messagesContainer", "promptInput", "inputCapsule", "composerModel",
      "composerDb", "composerHint", "sendBtn", "drawer", "drawerGrip", "tabViewGraph", "graphNodeCountBadge",
      "tabViewTelemetry", "tabViewReport", "mapCloseBtn", "graphStage", "graphSearchInput", "treeCollapseBtn",
      "graphLegend", "graphStats", "scopeClearBtn", "graphViewContainer", "graphCanvasContainer", "processLinksContainer",
      "mapViewGraph", "mapViewTree", "mapViewLinks", "graphInspectorDrawer", "drawerBackdrop",
      "inspectorTypeBadge", "inspectorCloseBtn", "inspectorTitle", "inspectorSubtitle", "inspectorBody",
      "telemetryStage", "globalDialogSearchInput", "globalDialogCopyBtn", "globalDialogMeta",
      "globalDialogCountBadge", "globalDialogTableWrap", "reportStage", "reportStageVerdictTag",
      "reportStageVerdictTime", "reportStageCopyBtn", "reportStageContent", "shortcutsPop",
      "shortcutsCloseBtn", "toast",
    ].forEach(function (id) {
      els[id] = $(id);
    });

    setupEvents();
    loadHistory();

    try {
      var savedW = Number(localStorage.getItem(DRAWER_KEY));
      if (savedW >= DRAWER_MIN) applyDrawerWidth(savedW);
    } catch (e) {
      /* ignore */
    }

    window.A1 = { state: state, tree: window.A1Tree };

    loadStatus().then(function () {
      renderDatabases();
      renderExamples();
      updateEmpty();
      if (state.dbPath) loadEvents();
    });
    loadModels();
    autosize();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
