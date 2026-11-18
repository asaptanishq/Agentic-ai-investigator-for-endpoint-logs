/**
 * A1 case map.
 *
 * Two parts:
 *   1. TelemetryGraph.build(events) — turns normalized endpoint telemetry rows into an
 *      entity graph. The entity types and relationships mirror src/a1/evidence_graph.py
 *      (EntityType / RelationshipType); nothing here invents node kinds.
 *   2. ForensicGraph — a dependency-free canvas renderer for that graph.
 *
 * The renderer is deliberately deterministic: the layout is computed once per data set,
 * there is no physics loop, and all per-frame work is O(nodes + edges) with viewport
 * culling. No label layout is done at render time, so 2k+ nodes stay responsive.
 */
(function () {
  "use strict";

  // ---------------------------------------------------------------- vocabulary

  // Type colours are low-chroma on purpose: hue identifies the entity kind, and
  // only `alert` competes for attention. Severity is a separate, small marker.
  var TYPES = {
    host: { label: "Host", color: "#8b98a5" },
    user: { label: "User", color: "#e08bc0" },
    process: { label: "Process", color: "#5b9df0" },
    file: { label: "File", color: "#4fb6a6" },
    registry_artifact: { label: "Registry", color: "#b6a04e" },
    ip_address: { label: "IP address", color: "#57c7d4" },
    domain: { label: "Domain", color: "#7fd1ac" },
    alert: { label: "Alert", color: "#e5664f" },
  };

  var TYPE_ORDER = [
    "alert",
    "host",
    "user",
    "process",
    "file",
    "registry_artifact",
    "ip_address",
    "domain",
  ];

  // RelationshipType names from evidence_graph.py, shortened only where the source
  // action already reads better on the edge label.
  var REL = {
    spawned: "spawned",
    parent_of: "parent_of",
    observed_on: "observed_on",
    executed: "executed",
    accessed: "accessed",
    created: "created",
    modified: "modified",
    connected_to: "connected_to",
    authenticated_to: "authenticated_to",
    resolved: "resolved",
    persisted_via: "persisted_via",
    associated_with: "associated_with",
  };

  var NODE_W = 182;
  var NODE_H = 46;
  var COL_W = 234;
  var ROW_H = 60;
  var MAX_RANK = 14;
  var MAX_ROWS_PER_COL = 12;
  // Maps beyond this are capped. Ordering below keeps the triage-relevant entities and
  // reports how many were left out, so nothing is silently hidden.
  var MAX_NODES = 700;

  // ---------------------------------------------------------------- helpers

  function get(obj, path) {
    if (obj == null) return undefined;
    if (Object.prototype.hasOwnProperty.call(obj, path)) return obj[path];
    var cur = obj;
    var parts = path.split(".");
    for (var i = 0; i < parts.length; i++) {
      if (cur == null || typeof cur !== "object") return undefined;
      cur = cur[parts[i]];
    }
    return cur;
  }

  function firstString(obj, paths) {
    for (var i = 0; i < paths.length; i++) {
      var v = get(obj, paths[i]);
      if (typeof v === "string" && v.trim()) return v.trim();
      if (typeof v === "number") return String(v);
    }
    return "";
  }

  function str(v) {
    if (v == null) return "";
    if (Array.isArray(v)) return v.join(", ");
    return String(v);
  }

  function parseTime(v) {
    if (!v) return 0;
    var t = Date.parse(v);
    return isNaN(t) ? 0 : t;
  }

  function basename(p) {
    if (!p) return "";
    var s = String(p).replace(/\\/g, "/");
    return s.substring(s.lastIndexOf("/") + 1) || s;
  }

  function clip(text, max) {
    var s = str(text);
    if (s.length <= max) return s;
    return s.slice(0, max - 1) + "\u2026";
  }

  // Normalize one /api/events row. The data set mixes flat ECS dotted keys,
  // nested ECS objects, Suricata and Wazuh shapes; everything downstream reads
  // this single shape instead of guessing per data set.
  function normalize(raw) {
    var d = raw.details || raw;
    var action = str(raw.action || get(d, "event.action") || get(d, "event_action") || get(d, "event_type"));
    var sigRaw = get(d, "process.code_signature.status");
    var out = {
      id: str(raw.event_id || get(d, "event.id") || ""),
      time: parseTime(raw.timestamp || get(d, "@timestamp") || get(d, "timestamp")),
      ts: str(raw.timestamp || get(d, "@timestamp") || get(d, "timestamp")),
      action: action,
      severity: Number(get(d, "event.severity") || get(d, "rule.level") || get(d, "alert.severity") || raw.severity || 0) || 0,
      host: firstString(d, ["host.name", "host.hostname", "host_id", "agent.name", "agent_name"]),
      hostIp: firstString(d, ["host.ip", "source.ip", "src_ip"]),
      user: firstString(d, ["user.name", "source_user", "data.win.eventdata.user", "user"]),
      procId: firstString(d, ["process.entity_id", "process_id"]),
      procName: firstString(d, ["process.name", "process_name", "data.win.eventdata.image"]),
      procPid: firstString(d, ["process.pid", "process_id", "data.win.eventdata.processId"]),
      procCmd: firstString(d, ["process.command_line", "process_cmdline", "data.win.eventdata.commandLine"]),
      procExe: firstString(d, ["process.executable", "process_path", "data.win.eventdata.image"]),
      parentId: firstString(d, ["process.parent.entity_id", "process_parent_id"]),
      parentName: firstString(d, ["process.parent.name", "process_parent_name", "data.win.eventdata.parentImage"]),
      targetName: firstString(d, ["process.target.name", "process.target.executable"]),
      targetId: firstString(d, ["process.target.entity_id", "process_target_id"]),
      targetPid: firstString(d, ["process.target.pid", "process_target_pid"]),
      grantedAccess: firstString(d, ["process.granted_access", "process_granted_access"]),
      sigStatus: typeof sigRaw === "string" ? sigRaw.trim() : "",
      hasSig: sigRaw !== undefined,
      filePath: firstString(d, ["file.path", "file_path", "file.name", "file_name"]),
      fileHash: firstString(d, ["file.hash.sha256", "file_hash", "process.hash.sha256", "process_hash"]),
      regPath: firstString(d, ["registry.path", "registry_path", "registry.key", "registry_key"]),
      regValue: firstString(d, ["registry.value", "registry_value"]),
      dstIp: firstString(d, ["destination.ip", "network_dst", "dest_ip"]),
      dstPort: firstString(d, ["destination.port", "network_dst_port", "dest_port"]),
      dstDomain: firstString(d, ["destination.domain", "dns_query", "dns.rrname"]),
      direction: firstString(d, ["network.direction"]),
      proto: firstString(d, ["network.protocol", "network_protocol", "proto", "app_proto"]),
      alertName: firstString(d, ["alert.signature", "rule.description", "alert_signature"]),
    };
    if (!out.id) out.id = out.ts + "|" + action + "|" + out.host;
    if (!out.procId) out.procId = out.host + "/" + (out.procName || "?") + ":" + out.procPid;
    return out;
  }

  // ---------------------------------------------------------------- builder

  var TelemetryGraph = {
    normalize: normalize,

    /** Build {nodes, edges, meta} from /api/events rows. */
    build: function (rawEvents) {
      var nodes = new Map();
      var edges = new Map();
      var events = (rawEvents || []).map(normalize);
      events.sort(function (a, b) {
        return a.time - b.time;
      });

      function upsert(type, key, label, detail) {
        var id = type + ":" + key;
        var n = nodes.get(id);
        if (!n) {
          n = {
            id: id,
            type: type,
            label: label || key,
            detail: detail || "",
            attrs: [],
            events: [],
            eventCount: 0,
            sev: 0,
            time: Infinity,
          };
          nodes.set(id, n);
        }
        return n;
      }

      function attr(n, k, v) {
        if (v == null || v === "") return;
        v = str(v);
        for (var i = 0; i < n.attrs.length; i++) {
          if (n.attrs[i][0] === k) return;
        }
        n.attrs.push([k, v]);
      }

      function link(a, b, rel, label) {
        if (!a || !b || a.id === b.id) return;
        var id = a.id + ">" + b.id + ":" + rel;
        var e = edges.get(id);
        if (e) {
          e.count++;
          return;
        }
        edges.set(id, { id: id, from: a.id, to: b.id, rel: rel, label: label || REL[rel] || rel, count: 1, time: 0 });
      }

      function touch(n, ev) {
        n.eventCount++;
        if (n.events.length < 40) n.events.push({ id: ev.id, ts: ev.ts, action: ev.action });
        if (ev.time && ev.time < n.time) n.time = ev.time;
        if (ev.severity > n.sev) n.sev = ev.severity;
      }

      // Behavioural risk for the process board. These are investigation leads, not
      // verdicts: strong signals (weights 2) mark malicious, two weak ones escalate.
      function addRisk(node, reason, weight) {
        if (!node) return;
        var risk = node.risk || (node.risk = { level: "suspicious", score: 0, reasons: [] });
        risk.score += weight || 0;
        if (risk.reasons.indexOf(reason) === -1) risk.reasons.push(reason);
        if (risk.score >= 2) risk.level = "malicious";
      }

      function assessProc(proc, ev) {
        if (!proc) return;
        var cmd = String(ev.procCmd || "").toLowerCase();
        var parent = String(ev.parentName || "").toLowerCase();
        if (ev.hasSig && ev.sigStatus !== "trusted") proc._unsigned = true;

        if (ev.action === "process_accessed") {
          var target = String(ev.targetName || "process memory").toLowerCase();
          var sensitive = /lsass|lsa|sam|security/.test(target);
          addRisk(proc, "accessed " + (ev.targetName || "process memory"), sensitive ? 2 : 1);
        }
        if (/procdump/.test(cmd) && /lsass/.test(cmd)) addRisk(proc, "LSASS credential dump", 2);
        if (/mimikatz|sekurlsa/.test(cmd)) addRisk(proc, "credential theft tool", 2);
        if (/-enc(?:odedcommand)?\b/.test(cmd) || /frombase64string/.test(cmd)) {
          addRisk(proc, "encoded command", 2);
        }
        if (/-executionpolicy\s+bypass|-exec\s+bypass/.test(cmd)) {
          addRisk(proc, "execution-policy bypass", 1);
        }
        if (/\bsc(?:\.exe)?\s+create\b/.test(cmd) && /binpath\s*=\s*.*temp/.test(cmd)) {
          addRisk(proc, "service installed from Temp", 2);
        }
        if (/(?:^|\s)-service\b/.test(cmd) && parent === "services.exe") {
          var unsignedService = ev.hasSig && ev.sigStatus !== "trusted";
          addRisk(proc, unsignedService ? "unsigned service binary" : "service execution", unsignedService ? 2 : 1);
        }
        if (/\bvssadmin(?:\.exe)?\s+delete\s+shadows|\bwbadmin(?:\.exe)?\b.*\bdelete|\bbcdedit(?:\.exe)?\b.*(?:recoveryenabled|ignoreallfailures)|\bcipher(?:\.exe)?\s+\/w\b/.test(cmd)) {
          addRisk(proc, "anti-recovery command", 2);
        }
        if (/\bmshta(?:\.exe)?\s+(?:vbscript:|javascript:)/.test(cmd)) {
          addRisk(proc, "script-host execution", 2);
        }
        if (/\breg(?:\.exe)?\s+add\b/.test(cmd) && /currentversion.*run/.test(cmd)) {
          addRisk(proc, "Run-key persistence", 1);
        }
        if (/\bschtasks(?:\.exe)?\s+\/create\b/.test(cmd) && /(?:-enc|-w\s+hidden|temp)/.test(cmd)) {
          addRisk(proc, "hidden scheduled task", 2);
        }
        if (/\bwmic(?:\.exe)?\b.*\bprocess\s+call\s+create\b/.test(cmd)) {
          addRisk(proc, "remote process creation", 1);
        }
        if (/\bcertutil(?:\.exe)?\b.*-urlcache/.test(cmd)) addRisk(proc, "certutil download", 1);
        if (/\bcertutil(?:\.exe)?\b.*-decode/.test(cmd)) addRisk(proc, "certutil decode", 1);
        if (/\bcurl(?:\.exe)?\b/.test(cmd) && /(?:--data-binary|--upload-file|-x\s+post)/.test(cmd)) {
          addRisk(proc, "data upload", 1);
        }
        if (/\b(?:7z|rar)(?:\.exe)?\b/.test(cmd) && /\s-p\S+/.test(cmd)) {
          addRisk(proc, "encrypted archive", 1);
        }
        if (/\bpowershell(?:\.exe)?\b/.test(cmd) && /(?:downloadstring|invoke-webrequest|\biwr\b|net\.webclient)/.test(cmd)) {
          addRisk(proc, "remote script download", 1);
        }
        if (/\bntdsutil\b|ntds\.dit/.test(cmd)) addRisk(proc, "credential database access", 2);
        if (/\b(?:psexec|paexec)\b/.test(cmd)) addRisk(proc, "remote execution tool", 1);
      }

      // Many datasets name a process only on its process_started row; file / network rows
      // carry the entity id alone. Resolve the image once so those rows join the same node
      // instead of creating "proc-abc123" placeholder nodes.
      var imageById = new Map();
      events.forEach(function (ev) {
        if (ev.procId && (ev.procName || ev.procExe)) imageById.set(ev.procId, ev.procName || basename(ev.procExe));
        if (ev.parentId && ev.parentName) imageById.set(ev.parentId, basename(ev.parentName));
      });
      function imageOf(ev) {
        return ev.procName || basename(ev.procExe) || imageById.get(ev.procId) || ev.procId;
      }

      events.forEach(function (ev) {
        var host = ev.host ? upsert("host", ev.host, ev.host, ev.hostIp) : null;
        if (host) {
          touch(host, ev);
          attr(host, "id", ev.host);
          attr(host, "ip", ev.hostIp);
        }

        // Processes aggregate per host + image: one telemetry row per process instance would
        // otherwise dominate the map (75 instances of the same image on one host). Instance
        // ids and command lines stay in the attributes and the source events.
        var proc = null;
        if (ev.procName || ev.procExe || imageById.has(ev.procId)) {
          proc = upsert("process", ev.host + "/" + imageOf(ev), imageOf(ev), "");
          touch(proc, ev);
          if (!proc.detail) proc.detail = "pid " + (ev.procPid || "?") + (ev.host ? " on " + ev.host : "");
          attr(proc, "image", ev.procExe);
          attr(proc, "entity id", ev.procId);
          attr(proc, "pid", ev.procPid);
          attr(proc, "command line", clip(ev.procCmd, 160));
          assessProc(proc, ev);
          if (host) link(proc, host, "observed_on");
        }

        if (ev.parentName || imageById.has(ev.parentId)) {
          var parentImage = ev.parentName ? basename(ev.parentName) : basename(imageById.get(ev.parentId) || "parent");
          var parent = upsert("process", ev.host + "/" + parentImage, parentImage, "");
          if (!parent.detail && ev.host) parent.detail = "parent process on " + ev.host;
          attr(parent, "entity id", ev.parentId);
          if (host) link(parent, host, "observed_on");
          if (proc) link(parent, proc, "spawned");
        }

        // Process-to-process access (e.g. procdump -> lsass) is a real link and the
        // strongest credential-theft signal in endpoint telemetry.
        if (proc && ev.targetName) {
          var targetImage = basename(ev.targetName);
          if (targetImage && targetImage.toLowerCase() !== imageOf(ev).toLowerCase()) {
            var target = upsert("process", ev.host + "/" + targetImage, targetImage, "");
            if (!target.detail) target.detail = "target process" + (ev.host ? " on " + ev.host : "");
            attr(target, "entity id", ev.targetId);
            attr(target, "pid", ev.targetPid);
            attr(target, "accessed by", imageOf(ev));
            attr(target, "granted access", ev.grantedAccess);
            if (host) link(target, host, "observed_on");
            link(proc, target, "accessed", "accessed");
          }
        }

        if (ev.user) {
          var user = upsert("user", ev.user, ev.user, "");
          touch(user, ev);
          if (host) link(user, host, "authenticated_to", ev.action.indexOf("logon") === 0 || ev.action.indexOf("auth") === 0 ? ev.action : "authenticated_to");
          if (proc) link(proc, user, "associated_with", "ran as");
        }

        if (ev.filePath) {
          var file = upsert("file", ev.filePath, basename(ev.filePath), ev.filePath.slice(0, ev.filePath.lastIndexOf("\\")) || ev.filePath);
          touch(file, ev);
          attr(file, "path", ev.filePath);
          attr(file, "sha256", ev.fileHash);
          var fileRel = /delete|remove|modif|write|rename|set/.test(ev.action) ? "modified" : /read|access|open/.test(ev.action) ? "accessed" : "created";
          if (proc) link(proc, file, fileRel, ev.action || fileRel);
          else if (host) link(host, file, fileRel, ev.action || fileRel);
        }

        if (ev.regPath) {
          var reg = upsert("registry_artifact", ev.regPath, ev.regPath.split("\\").slice(-2).join("\\"), ev.regPath);
          touch(reg, ev);
          attr(reg, "path", ev.regPath);
          attr(reg, "value", ev.regValue);
          var regRel = /set|creat|modif|writ/.test(ev.action) ? "modified" : "accessed";
          if (proc) link(proc, reg, regRel, ev.action || regRel);
          else if (host) link(host, reg, regRel, ev.action || regRel);
        }

        var endpoint = null;
        if (ev.dstIp || ev.dstDomain) {
          var isIp = !!ev.dstIp;
          endpoint = upsert(
            isIp ? "ip_address" : "domain",
            isIp ? ev.dstIp : ev.dstDomain,
            isIp ? ev.dstIp : ev.dstDomain,
            ev.dstPort ? "port " + ev.dstPort : ev.proto
          );
          touch(endpoint, ev);
          attr(endpoint, "address", ev.dstIp || ev.dstDomain);
          attr(endpoint, "port", ev.dstPort);
          attr(endpoint, "protocol", ev.proto);
          attr(endpoint, "direction", ev.direction);
          if (proc) link(proc, endpoint, "connected_to", ev.direction === "inbound" ? "inbound" : ev.dstPort ? ":" + ev.dstPort : "connected_to");
          else if (host) link(host, endpoint, "connected_to", ev.dstPort ? ":" + ev.dstPort : "connected_to");
        }

        if (ev.dstDomain && ev.dstIp) {
          var dom = upsert("domain", ev.dstDomain, ev.dstDomain, "");
          touch(dom, ev);
          link(dom, endpoint, "resolved");
        }

        if (ev.alertName || ev.action === "alert") {
          var alertKey = ev.alertName || ev.action;
          var alert = upsert("alert", alertKey, clip(alertKey, 44), ev.severity ? "severity " + ev.severity : "");
          touch(alert, ev);
          attr(alert, "signature", alertKey);
          attr(alert, "severity", ev.severity);
          var anchor = endpoint || proc || host;
          if (anchor) link(alert, anchor, "associated_with");
        }
      });

      var nodeList = Array.from(nodes.values());
      nodeList.forEach(function (n) {
        if (n.risk) {
          if (n._unsigned && n.risk.reasons.indexOf("unsigned binary") === -1) {
            n.risk.reasons.push("unsigned binary");
          }
          attr(n, "risk", n.risk.level + " · " + n.risk.reasons.join("; "));
        }
        delete n._unsigned;
        n.time = n.time === Infinity ? 0 : n.time;
      });

      var hidden = 0;
      if (nodeList.length > MAX_NODES) {
        var PRIORITY = { alert: 0, host: 1, user: 2, ip_address: 3, domain: 4, registry_artifact: 5, process: 6, file: 7 };
        nodeList.sort(function (a, b) {
          var pa = PRIORITY[a.type] == null ? 9 : PRIORITY[a.type];
          var pb = PRIORITY[b.type] == null ? 9 : PRIORITY[b.type];
          if (pa !== pb) return pa - pb;
          return b.eventCount - a.eventCount;
        });
        hidden = nodeList.length - MAX_NODES;
        nodeList = nodeList.slice(0, MAX_NODES);
        var kept = new Map();
        nodeList.forEach(function (n) {
          kept.set(n.id, true);
        });
        Array.from(edges.keys()).forEach(function (k) {
          var e = edges.get(k);
          if (!kept.has(e.from) || !kept.has(e.to)) edges.delete(k);
        });
      }

      var edgeList = Array.from(edges.values());
      edgeList.forEach(function (e) {
        var a = nodes.get(e.from);
        var b = nodes.get(e.to);
        e.time = Math.max(a ? a.time : 0, b ? b.time : 0);
      });

      return {
        nodes: nodeList,
        edges: edgeList,
        meta: {
          events: events.length,
          nodes: nodeList.length,
          hidden: hidden,
          hosts: nodeList.filter(function (n) { return n.type === "host"; }).length,
          alerts: nodeList.filter(function (n) { return n.type === "alert"; }).length,
        },
      };
    },

    TYPES: TYPES,
    TYPE_ORDER: TYPE_ORDER,
  };

  // ---------------------------------------------------------------- renderer

  function ForensicGraph(container, options) {
    this.container = container;
    this.options = options || {};
    this.nodes = [];
    this.byId = new Map();
    this.edges = [];
    this.adj = new Map();
    this.transform = { x: 0, y: 0, k: 1 };
    this.selectedId = null;
    this.hoverId = null;
    this.search = "";
    this.enabledTypes = null;
    this.isolated = null;
    this._width = 0;
    this._height = 0;
    this._dpr = 1;
    this._frame = 0;
    this._textWidth = new Map();
    this._drag = null;
    this._initDom();
    this._attachEvents();
    this._resize();
  }

  ForensicGraph.prototype._initDom = function () {
    var el = this.container;
    el.classList.add("cm-stage");
    el.innerHTML = "";
    this.canvas = document.createElement("canvas");
    this.canvas.className = "cm-canvas";
    this.canvas.tabIndex = 0;
    this.canvas.setAttribute("role", "application");
    this.canvas.setAttribute("aria-label", "Case map of hosts, users, processes, files, registry keys and network endpoints");
    el.appendChild(this.canvas);
    this.ctx = this.canvas.getContext("2d");
    this.emptyEl = document.createElement("div");
    this.emptyEl.className = "cm-empty";
    this.emptyEl.hidden = true;
    el.appendChild(this.emptyEl);
    if (typeof ResizeObserver !== "undefined") {
      var self = this;
      this._ro = new ResizeObserver(function () {
        self._resize();
      });
      this._ro.observe(el);
    }
  };

  ForensicGraph.prototype._attachEvents = function () {
    var self = this;
    var c = this.canvas;

    c.addEventListener(
      "wheel",
      function (ev) {
        ev.preventDefault();
        var r = c.getBoundingClientRect();
        var px = ev.clientX - r.left;
        var py = ev.clientY - r.top;
        var factor = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
        self._zoomAt(px, py, factor);
      },
      { passive: false }
    );

    c.addEventListener("pointerdown", function (ev) {
      c.focus();
      var pt = self._toWorld(ev.offsetX, ev.offsetY);
      var hit = self._hitTest(pt.x, pt.y);
      if (hit) {
        self._drag = { type: "node", id: hit.id, dx: pt.x - hit.x, dy: pt.y - hit.y, moved: false, sx: ev.clientX, sy: ev.clientY };
        self.select(hit.id);
      } else {
        self._drag = { type: "pan", x: ev.clientX, y: ev.clientY, moved: false };
      }
      c.setPointerCapture(ev.pointerId);
    });

    c.addEventListener("pointermove", function (ev) {
      var d = self._drag;
      if (d) {
        if (d.type === "pan") {
          self.transform.x += ev.clientX - d.x;
          self.transform.y += ev.clientY - d.y;
          d.x = ev.clientX;
          d.y = ev.clientY;
          d.moved = true;
          self._invalidate();
        } else {
          var pt = self._toWorld(ev.offsetX, ev.offsetY);
          var node = self.byId.get(d.id);
          if (node) {
            node.x = pt.x - d.dx;
            node.y = pt.y - d.dy;
            self._invalidate();
          }
        }
        return;
      }
      var hoverPt = self._toWorld(ev.offsetX, ev.offsetY);
      var hit = self._hitTest(hoverPt.x, hoverPt.y);
      var id = hit ? hit.id : null;
      if (id !== self.hoverId) {
        self.hoverId = id;
        c.style.cursor = id ? "pointer" : "grab";
        self._invalidate();
      }
    });

    function endDrag(ev) {
      var d = self._drag;
      self._drag = null;
      if (d && d.type === "pan" && !d.moved) {
        self.select(null);
      }
      if (c.hasPointerCapture && ev.pointerId != null && c.hasPointerCapture(ev.pointerId)) c.releasePointerCapture(ev.pointerId);
    }
    c.addEventListener("pointerup", endDrag);
    c.addEventListener("pointercancel", endDrag);

    c.addEventListener("dblclick", function (ev) {
      var pt = self._toWorld(ev.offsetX, ev.offsetY);
      var hit = self._hitTest(pt.x, pt.y);
      if (hit) self.focusNode(hit.id);
    });

    c.addEventListener("keydown", function (ev) {
      var step = 60;
      var handled = true;
      switch (ev.key) {
        case "ArrowLeft":
          self.transform.x += step;
          break;
        case "ArrowRight":
          self.transform.x -= step;
          break;
        case "ArrowUp":
          self.transform.y += step;
          break;
        case "ArrowDown":
          self.transform.y -= step;
          break;
        case "+":
        case "=":
          self._zoomAt(self._width / 2, self._height / 2, 1.15);
          break;
        case "-":
          self._zoomAt(self._width / 2, self._height / 2, 1 / 1.15);
          break;
        case "0":
          self.fit();
          break;
        case "Escape":
          self.select(null);
          break;
        default:
          handled = false;
      }
      if (handled) {
        ev.preventDefault();
        self._invalidate();
      }
    });
  };

  ForensicGraph.prototype._resize = function () {
    var rect = this.container.getBoundingClientRect();
    var w = Math.max(120, Math.round(rect.width));
    var h = Math.max(120, Math.round(rect.height));
    this._dpr = window.devicePixelRatio || 1;
    this._width = w;
    this._height = h;
    this.canvas.width = Math.round(w * this._dpr);
    this.canvas.height = Math.round(h * this._dpr);
    this.canvas.style.width = w + "px";
    this.canvas.style.height = h + "px";
    if (!this._fitted && this.nodes.length) this.fit();
    this._invalidate();
  };

  ForensicGraph.prototype._invalidate = function () {
    if (this._frame) return;
    var self = this;
    this._frame = requestAnimationFrame(function () {
      self._frame = 0;
      self._draw();
    });
  };

  ForensicGraph.prototype._toWorld = function (sx, sy) {
    var t = this.transform;
    return { x: (sx - t.x) / t.k, y: (sy - t.y) / t.k };
  };

  ForensicGraph.prototype._toScreen = function (wx, wy) {
    var t = this.transform;
    return { x: wx * t.k + t.x, y: wy * t.k + t.y };
  };

  ForensicGraph.prototype._zoomAt = function (sx, sy, factor) {
    var t = this.transform;
    var next = Math.min(2.4, Math.max(0.08, t.k * factor));
    if (next === t.k) return;
    var w = this._toWorld(sx, sy);
    t.k = next;
    t.x = sx - w.x * next;
    t.y = sy - w.y * next;
    this._invalidate();
  };

  // ---------------------------------------------------------------- data

  ForensicGraph.prototype.setData = function (data) {
    this.nodes = (data && data.nodes) || [];
    this.byId = new Map();
    for (var i = 0; i < this.nodes.length; i++) this.byId.set(this.nodes[i].id, this.nodes[i]);
    this.edges = (data && data.edges) || [];
    this.adj = new Map();
    for (var j = 0; j < this.edges.length; j++) {
      var e = this.edges[j];
      if (!this.adj.has(e.from)) this.adj.set(e.from, new Set());
      if (!this.adj.has(e.to)) this.adj.set(e.to, new Set());
      this.adj.get(e.from).add(e.to);
      this.adj.get(e.to).add(e.from);
    }
    this.selectedId = null;
    this.isolated = null;
    this._fitted = false;
    this._layout();
    this._syncEmpty();
    this.fit();
    this._invalidate();
  };

  ForensicGraph.prototype.clear = function () {
    this.setData({ nodes: [], edges: [] });
  };

  ForensicGraph.prototype.setEmpty = function (html) {
    this.emptyEl.innerHTML = html || "";
    this._syncEmpty();
  };

  ForensicGraph.prototype._syncEmpty = function () {
    var empty = this.nodes.length === 0;
    this.emptyEl.hidden = !empty;
    this.canvas.style.visibility = empty ? "hidden" : "visible";
  };

  ForensicGraph.prototype.stats = function () {
    return {
      nodes: this.nodes.length,
      edges: this.edges.length,
      visible: this.nodes.filter(this._isVisible, this).length,
    };
  };

  /**
   * Layout: one block per host, packed into shelves.
   *
   * DFIR triage is per-endpoint: an analyst asks "what happened on this host", not
   * "what is the global depth of the attack chain". So entities are grouped by the host
   * they were observed on (falling back to a NETWORK block for entities that carry no
   * host, e.g. Suricata flows) and each block is a grid with the host at its top-left.
   * Cross-host edges then draw as long lines, which is exactly the lateral-movement
   * signal worth seeing. This also keeps the aspect near the viewport instead of the
   * 40 000px single strip a depth-ranked layout produced for 600 processes.
   */
  ForensicGraph.prototype._layout = function () {
    var nodes = this.nodes;
    if (!nodes.length) return;

    var CELL_W = NODE_W + 20;
    var CELL_H = NODE_H + 26;
    var GAP = 34;

    // Which host each entity belongs to: direct host nodes, else the host of its
    // observed_on / authenticated_to attachment edge.
    var hostOf = new Map();
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].type === "host") hostOf.set(nodes[i].id, nodes[i].id);
    }
    for (var j = 0; j < this.edges.length; j++) {
      var e = this.edges[j];
      if (e.rel !== "observed_on" && e.rel !== "authenticated_to") continue;
      if (hostOf.has(e.to) && !hostOf.has(e.from)) hostOf.set(e.from, e.to);
    }

    var groups = new Map();
    for (var k = 0; k < nodes.length; k++) {
      var n = nodes[k];
      var key = hostOf.get(n.id) || "net";
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(n);
    }

    var blocks = Array.from(groups.keys()).map(function (key) {
      var members = groups.get(key);
      members.sort(function (a, b) {
        var ah = a.type === "host" ? -1 : 0;
        var bh = b.type === "host" ? -1 : 0;
        if (ah !== bh) return ah - bh;
        if (a.type !== b.type) return TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type);
        if (a.time !== b.time) return a.time - b.time;
        return a.label < b.label ? -1 : 1;
      });
      return { key: key, nodes: members };
    });
    blocks.sort(function (a, b) {
      if (a.key === "net" || b.key === "net") return a.key === "net" ? 1 : -1;
      return b.nodes.length - a.nodes.length;
    });

    var totalArea = 0;
    for (var b = 0; b < blocks.length; b++) {
      var members = blocks[b].nodes;
      blocks[b].cols = Math.max(1, Math.min(8, Math.ceil(Math.sqrt(members.length * 1.4))));
      blocks[b].rows = Math.ceil(members.length / blocks[b].cols);
      blocks[b].w = blocks[b].cols * CELL_W;
      blocks[b].h = blocks[b].rows * CELL_H;
      totalArea += (blocks[b].w + GAP) * (blocks[b].h + GAP);
    }

    var widthLimit = Math.max(1000, Math.sqrt(totalArea));
    var cursorX = 0;
    var cursorY = 0;
    var shelfH = 0;
    for (var bi = 0; bi < blocks.length; bi++) {
      var blk = blocks[bi];
      if (cursorX > 0 && cursorX + blk.w > widthLimit) {
        cursorX = 0;
        cursorY += shelfH + GAP;
        shelfH = 0;
      }
      for (var mi = 0; mi < blk.nodes.length; mi++) {
        var node = blk.nodes[mi];
        node.x = cursorX + (mi % blk.cols) * CELL_W + NODE_W / 2;
        node.y = cursorY + Math.floor(mi / blk.cols) * CELL_H + NODE_H / 2;
      }
      cursorX += blk.w + GAP;
      shelfH = Math.max(shelfH, blk.h);
    }

    // Block bounds drive the zoomed-out level of detail: below ~34% the map shows one
    // labelled block per host instead of 700 unreadable chips.
    this.blocks = [];
    for (var bj = 0; bj < blocks.length; bj++) {
      var block = blocks[bj];
      var hostNode = null;
      var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity, sev = 0;
      for (var bm = 0; bm < block.nodes.length; bm++) {
        var member = block.nodes[bm];
        if (member.type === "host" && !hostNode) hostNode = member;
        if (member.sev > sev) sev = member.sev;
        minX = Math.min(minX, member.x - NODE_W / 2);
        maxX = Math.max(maxX, member.x + NODE_W / 2);
        minY = Math.min(minY, member.y - NODE_H / 2);
        maxY = Math.max(maxY, member.y + NODE_H / 2);
      }
      this.blocks.push({
        id: block.key,
        label: hostNode ? hostNode.label : "NETWORK",
        x: minX - 14,
        y: minY - 14,
        w: maxX - minX + 28,
        h: maxY - minY + 28,
        count: block.nodes.length,
        sev: sev,
        nodes: block.nodes,
      });
      for (var bn = 0; bn < block.nodes.length; bn++) block.nodes[bn].block = this.blocks[this.blocks.length - 1];
    }
  };

  // ---------------------------------------------------------------- view state

  ForensicGraph.prototype.setTypes = function (types) {
    this.enabledTypes = types && types.size ? types : null;
    this._invalidate();
    if (this.options.onViewChange) this.options.onViewChange(this.stats());
  };

  ForensicGraph.prototype.setSearch = function (q) {
    this.search = (q || "").trim().toLowerCase();
    this._invalidate();
    if (this.options.onViewChange) this.options.onViewChange(this.stats());
  };

  ForensicGraph.prototype._matches = function (n) {
    if (!this.search) return true;
    if (n.label.toLowerCase().indexOf(this.search) >= 0) return true;
    if (n.detail && n.detail.toLowerCase().indexOf(this.search) >= 0) return true;
    if (n.type.indexOf(this.search) >= 0) return true;
    for (var i = 0; i < n.attrs.length; i++) {
      if (String(n.attrs[i][1]).toLowerCase().indexOf(this.search) >= 0) return true;
    }
    return false;
  };

  ForensicGraph.prototype._isVisible = function (n) {
    if (this.isolated) return this.isolated.has(n.id);
    return !this.enabledTypes || this.enabledTypes.has(n.type);
  };

  ForensicGraph.prototype.select = function (id) {
    if (id && !this.byId.has(id)) id = null;
    if (this.selectedId === id) {
      this._invalidate();
      return;
    }
    this.selectedId = id;
    this._invalidate();
    if (this.options.onSelect) this.options.onSelect(id ? this.byId.get(id) : null);
  };

  ForensicGraph.prototype.isolate = function (id) {
    var node = this.byId.get(id);
    if (!node) return;
    var keep = new Set([id]);
    var near = this.adj.get(id);
    if (near) near.forEach(function (x) { keep.add(x); });
    this.isolated = keep;
    this.selectedId = id;
    this._fitted = false;
    this.fit();
    if (this.options.onSelect) this.options.onSelect(node);
  };

  ForensicGraph.prototype.clearIsolation = function () {
    this.isolated = null;
    this._invalidate();
  };

  // Scope = the nodes carried by the evidence pack; unlike isolate it is not a
  // selection, so the inspector stays free.
  ForensicGraph.prototype.setScope = function (ids) {
    this.isolated = ids && ids.size ? new Set(ids) : null;
    this._fitted = false;
    this.fit();
    if (this.options.onViewChange) this.options.onViewChange(this.stats());
  };

  ForensicGraph.prototype.focusNode = function (id) {
    var n = this.byId.get(id);
    if (!n) return;
    var k = Math.max(0.9, this.transform.k);
    this.transform.k = k;
    this.transform.x = this._width / 2 - n.x * k;
    this.transform.y = this._height / 2 - n.y * k;
    this._invalidate();
  };

  ForensicGraph.prototype.fit = function () {
    if (!this.nodes.length) return;
    var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    var any = false;
    for (var i = 0; i < this.nodes.length; i++) {
      var n = this.nodes[i];
      if (!this._isVisible(n)) continue;
      any = true;
      minX = Math.min(minX, n.x - NODE_W / 2);
      maxX = Math.max(maxX, n.x + NODE_W / 2);
      minY = Math.min(minY, n.y - NODE_H / 2);
      maxY = Math.max(maxY, n.y + NODE_H / 2);
    }
    if (!any) return;
    // Block frames and their labels sit outside the node boxes; they must be inside the
    // fit or the first host block gets clipped by the pane edge.
    for (var b = 0; this.blocks && b < this.blocks.length; b++) {
      var blk = this.blocks[b];
      minX = Math.min(minX, blk.x);
      minY = Math.min(minY, blk.y);
      maxX = Math.max(maxX, blk.x + blk.w);
      maxY = Math.max(maxY, blk.y + blk.h);
    }
    var padX = 34, padY = 34;
    var k = Math.min(this._width / (maxX - minX + padX * 2), this._height / (maxY - minY + padY * 2));
    k = Math.min(1.4, Math.max(0.08, k));
    this.transform.k = k;
    this.transform.x = this._width / 2 - ((minX + maxX) / 2) * k;
    this.transform.y = this._height / 2 - ((minY + maxY) / 2) * k;
    this._fitted = true;
    this._invalidate();
  };

  ForensicGraph.prototype.zoomIn = function () {
    this._zoomAt(this._width / 2, this._height / 2, 1.2);
  };

  ForensicGraph.prototype.zoomOut = function () {
    this._zoomAt(this._width / 2, this._height / 2, 1 / 1.2);
  };

  ForensicGraph.prototype.reset = function () {
    this.isolated = null;
    this.setScope(null);
    this.enabledTypes = null;
    this.search = "";
    this.select(null);
    this._layout();
    this.fit();
  };

  // ---------------------------------------------------------------- hit test + draw

  ForensicGraph.prototype._drawBlock = function (ctx, block, k, t) {
    var x = block.x * k + t.x;
    var y = block.y * k + t.y;
    var w = block.w * k;
    var h = block.h * k;
    if (x > this._width || y > this._height || x + w < 0 || y + h < 0) return;
    ctx.globalAlpha = 1;
    ctx.fillStyle = block.sev >= 3 ? "rgba(217, 83, 79, 0.05)" : "rgba(255, 255, 255, 0.015)";
    ctx.fillRect(x, y, w, h);
    ctx.strokeStyle = block.sev >= 3 ? "rgba(217, 83, 79, 0.28)" : "rgba(255, 255, 255, 0.07)";
    ctx.lineWidth = 1;
    ctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
    if (w < 54) return;
    var size = Math.max(9, Math.min(12, w / 16));
    ctx.font = "600 " + size.toFixed(1) + "px ui-monospace, SFMono-Regular, Menlo, monospace";
    ctx.fillStyle = block.sev >= 3 ? "#e08a86" : "#98a0a8";
    var text = block.label + " · " + block.count;
    while (text.length > 3 && this._measure(text) > w - 12) text = text.slice(0, -1);
    ctx.fillText(text, x + 6, y + size + 3);
  };

  /** Fit one host block into the viewport (used when the map is at block level). */
  ForensicGraph.prototype._focusBlock = function (block) {
    var pad = 30;
    var k = Math.min(1.6, Math.min(this._width / (block.w + pad * 2), this._height / (block.h + pad * 2)));
    this.transform.k = k;
    this.transform.x = this._width / 2 - (block.x + block.w / 2) * k;
    this.transform.y = this._height / 2 - (block.y + block.h / 2) * k;
    this._invalidate();
    if (this.options.onViewChange) this.options.onViewChange(this.stats());
  };

  ForensicGraph.prototype._hitTest = function (wx, wy) {
    for (var i = this.nodes.length - 1; i >= 0; i--) {
      var n = this.nodes[i];
      if (!this._isVisible(n)) continue;
      if (wx >= n.x - NODE_W / 2 && wx <= n.x + NODE_W / 2 && wy >= n.y - NODE_H / 2 && wy <= n.y + NODE_H / 2) return n;
    }
    return null;
  };

  ForensicGraph.prototype._measure = function (text) {
    var w = this._textWidth.get(text);
    if (w === undefined) {
      w = this.ctx.measureText(text).width;
      if (this._textWidth.size > 4000) this._textWidth.clear();
      this._textWidth.set(text, w);
    }
    return w;
  };

  ForensicGraph.prototype._draw = function () {
    var ctx = this.ctx;
    var t = this.transform;
    var dpr = this._dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, this._width, this._height);
    ctx.fillStyle = "#0b0c0e";
    ctx.fillRect(0, 0, this._width, this._height);

    var sel = this.selectedId;
    var neighbors = sel && this.adj.get(sel) ? this.adj.get(sel) : null;
    var searching = !!this.search;

    function stateOf(n) {
      if (!n) return "dim";
      var visible = this._isVisible(n);
      if (!visible) return "hidden";
      if (searching && !this._matches(n)) return "dim";
      if (sel) {
        if (n.id === sel) return "sel";
        if (neighbors && neighbors.has(n.id)) return "near";
        return "dim";
      }
      return "on";
    }

    var k = t.k;
    var blockLevel = k < 0.34;

    if (this.blocks && this.blocks.length > 1) {
      for (var bix = 0; bix < this.blocks.length; bix++) {
        this._drawBlock(ctx, this.blocks[bix], k, t);
      }
      if (blockLevel) {
        // At this zoom the individual edges are noise, but which hosts talk to which is
        // the lateral-movement signal. Aggregate them per host pair.
        var pairs = new Map();
        for (var ei = 0; ei < this.edges.length; ei++) {
          var ed = this.edges[ei];
          var na = this.byId.get(ed.from);
          var nb = this.byId.get(ed.to);
          if (!na || !nb || !na.block || !nb.block || na.block === nb.block) continue;
          if (!this._isVisible(na) || !this._isVisible(nb)) continue;
          var key = na.block.id < nb.block.id ? na.block.id + "|" + nb.block.id : nb.block.id + "|" + na.block.id;
          var pair = pairs.get(key);
          if (!pair) pairs.set(key, { a: na.block, b: nb.block, n: 1 });
          else pair.n++;
        }
        ctx.lineWidth = 1;
        var self = this;
        pairs.forEach(function (pair) {
          var ax = (pair.a.x + pair.a.w / 2) * k + t.x;
          var ay = (pair.a.y + pair.a.h / 2) * k + t.y;
          var bx = (pair.b.x + pair.b.w / 2) * k + t.x;
          var by = (pair.b.y + pair.b.h / 2) * k + t.y;
          if (Math.max(ax, bx) < -40 || Math.min(ax, bx) > self._width + 40) return;
          if (Math.max(ay, by) < -40 || Math.min(ay, by) > self._height + 40) return;
          ctx.globalAlpha = Math.min(0.5, 0.14 + pair.n * 0.02);
          ctx.strokeStyle = "#7d868f";
          ctx.lineWidth = Math.min(3, 1 + Math.log2(pair.n));
          ctx.beginPath();
          ctx.moveTo(ax, ay);
          ctx.lineTo(bx, by);
          ctx.stroke();
        });
        ctx.globalAlpha = 1;
        return;
      }
    }

    var showLabels = k >= 0.36;
    var showDetail = k >= 0.72;
    var showEdgeLabels = k >= 0.8 && this.edges.length < 700;

    // edges
    ctx.lineWidth = 1;
    for (var i = 0; i < this.edges.length; i++) {
      var e = this.edges[i];
      var a = this.byId.get(e.from);
      var b = this.byId.get(e.to);
      if (!a || !b) continue;
      var as = stateOf.call(this, a);
      var bs = stateOf.call(this, b);
      if (as === "hidden" || bs === "hidden") continue;
      if (as === "dim" || bs === "dim") {
        if (as === "dim" && bs === "dim") continue;
      }
      var ax = a.x * k + t.x, ay = a.y * k + t.y;
      var bx = b.x * k + t.x, by = b.y * k + t.y;
      if (Math.max(ax, bx) < -80 || Math.min(ax, bx) > this._width + 80) continue;
      if (Math.max(ay, by) < -80 || Math.min(ay, by) > this._height + 80) continue;

      var type = this.byId.get(e.from).type;
      var color = (TYPES[type] || TYPES.host).color;
      var active = as === "sel" || bs === "sel" || as === "near" || bs === "near";
      ctx.globalAlpha = active ? 0.85 : this.selectedId || searching ? 0.06 : 0.24;
      ctx.strokeStyle = active ? color : "#6a7378";
      ctx.lineWidth = active ? 1.6 : 1;
      ctx.beginPath();
      ctx.moveTo(ax, ay);
      if (Math.abs(ay - by) < 1) {
        ctx.lineTo(bx, by);
      } else {
        var mx = (ax + bx) / 2;
        ctx.bezierCurveTo(mx, ay, mx, by, bx, by);
      }
      ctx.stroke();
      this._arrowHead(ctx, ax, ay, bx, by, active ? color : "#6a7378");

      if (active && showEdgeLabels) {
        var lx = (ax + bx) / 2;
        var ly = (ay + by) / 2 - 5;
        ctx.globalAlpha = 0.9;
        ctx.fillStyle = "#0b0c0e";
        ctx.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
        var text = e.count > 1 ? e.label + " \u00d7" + e.count : e.label;
        var tw = this._measure(text);
        ctx.fillRect(lx - tw / 2 - 3, ly - 8, tw + 6, 13);
        ctx.fillStyle = color;
        ctx.fillText(text, lx - tw / 2, ly + 1.5);
      }
    }
    ctx.globalAlpha = 1;

    // nodes, back to front
    for (var ni = 0; ni < this.nodes.length; ni++) {
      var n = this.nodes[ni];
      var st = stateOf.call(this, n);
      if (st === "hidden") continue;
      var sx = n.x * k + t.x;
      var sy = n.y * k + t.y;
      var hw = (NODE_W * k) / 2;
      var hh = (NODE_H * k) / 2;
      if (sx + hw < -20 || sx - hw > this._width + 20) continue;
      if (sy + hh < -20 || sy - hh > this._height + 20) continue;
      this._drawNode(ctx, n, sx, sy, k, st, showLabels, showDetail);
    }
    ctx.globalAlpha = 1;
  };

  ForensicGraph.prototype._arrowHead = function (ctx, ax, ay, bx, by, color) {
    var ang = Math.atan2(by - ay, bx - ax);
    // stop the head at the target node edge so arrowheads are not buried
    var scale = this.transform.k;
    var hw = (NODE_W * scale) / 2;
    var hh = (NODE_H * scale) / 2;
    var d = Math.min(Math.abs(hw / Math.cos(ang) || 1e6), Math.abs(hh / Math.sin(ang) || 1e6));
    var tx = bx - Math.cos(ang) * (d || 0);
    var ty = by - Math.sin(ang) * (d || 0);
    if ((tx - ax) * Math.cos(ang) + (ty - ay) * Math.sin(ang) < 0) {
      tx = bx;
      ty = by;
    }
    var size = 5.5;
    ctx.beginPath();
    ctx.moveTo(tx, ty);
    ctx.lineTo(tx - Math.cos(ang - 0.4) * size, ty - Math.sin(ang - 0.4) * size);
    ctx.moveTo(tx, ty);
    ctx.lineTo(tx - Math.cos(ang + 0.4) * size, ty - Math.sin(ang + 0.4) * size);
    ctx.strokeStyle = color;
    ctx.stroke();
  };

  ForensicGraph.prototype._drawNode = function (ctx, n, sx, sy, k, state, showLabels, showDetail) {
    var meta = TYPES[n.type] || TYPES.host;
    var w = NODE_W * k;
    var h = NODE_H * k;
    var x = sx - w / 2;
    var y = sy - h / 2;
    var dim = state === "dim";

    ctx.globalAlpha = dim ? 0.22 : 1;

    ctx.fillStyle = state === "sel" ? "#141a1f" : "#101214";
    ctx.strokeStyle = state === "sel" ? meta.color : "#2a2f34";
    ctx.lineWidth = state === "sel" ? 1.6 : 1;
    ctx.beginPath();
    if (ctx.roundRect) {
      ctx.roundRect(x, y, w, h, 3);
    } else {
      ctx.rect(x, y, w, h);
    }
    ctx.fill();
    ctx.stroke();

    // type stripe
    ctx.fillStyle = meta.color;
    ctx.fillRect(x + 1, y + 1, Math.max(2, 3 * k), h - 2);

    if (showLabels) {
      ctx.save();
      ctx.beginPath();
      ctx.rect(x + 10 * k, y, w - 16 * k, h);
      ctx.clip();
      ctx.fillStyle = dim ? "#8d969b" : "#e6e9eb";
      ctx.font = "500 " + Math.max(9, Math.round(11.5 * k)) + "px Inter, system-ui, sans-serif";
      ctx.textBaseline = "middle";
      ctx.fillText(clip(n.label, 34), x + 10 * k, showDetail ? sy - 7 * k : sy);
      if (showDetail) {
        ctx.fillStyle = dim ? "#5c6469" : "#8d969b";
        ctx.font = Math.max(8, Math.round(10 * k)) + "px ui-monospace, SFMono-Regular, Menlo, monospace";
        ctx.fillText(clip(n.detail || meta.label.toLowerCase(), 40), x + 10 * k, sy + 8 * k);
      }
      ctx.restore();
    } else {
      ctx.fillStyle = meta.color;
      ctx.fillRect(x + 6, y + 6, w - 12, Math.max(2, h - 12));
    }

    if (n.sev >= 3) {
      ctx.beginPath();
      ctx.arc(x + w - 7 * k, y + 7 * k, 2.6 * k, 0, Math.PI * 2);
      ctx.fillStyle = "#e5484d";
      ctx.fill();
    }
    ctx.globalAlpha = 1;
  };

  // ---------------------------------------------------------------- exports

  window.TelemetryGraph = TelemetryGraph;
  window.ForensicGraph = ForensicGraph;
  window.ForensicGraph.TYPES = TYPES;
})();
