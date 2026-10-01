/**
 * A1 DFIR Forensic Graph Engine
 * High-performance, zero-dependency SVG DAG and Process Tree layout.
 * Provides pan/zoom, node drag, lineage highlighting, entity inspection,
 * and category filtering.
 */

class ForensicGraph {
  constructor(containerEl, options = {}) {
    this.container = containerEl;
    this.options = Object.assign({
      onNodeSelect: null,
      onNodeDeselect: null,
      onExpansionChange: null,
    }, options);

    this.nodes = new Map(); // id -> node
    this.edges = [];        // [{ from, to, label, type }]
    this.rawEvents = [];

    // Node expansion & visibility state for tree exploration
    this.expandedNodeIds = new Set();
    this._visibleTreeIds = new Set();

    // Viewport transform state
    this.transform = { x: 80, y: 80, scale: 1.0 };
    this.isPanning = false;
    this.panStart = { x: 0, y: 0 };
    this.draggedNode = null;
    this.dragOffset = { x: 0, y: 0 };
    this.selectedNodeId = null;
    this.highlightedNodeIds = null; // Set or null
    this.activeFilter = "all";      // all, process, network, file, registry, alert
    this.searchQuery = "";

    this._initDom();
    this._attachEvents();
  }

  _initDom() {
    this.container.innerHTML = "";
    this.container.classList.add("fg-container");

    // SVG Canvas
    this.svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    this.svg.classList.add("fg-svg");
    this.svg.setAttribute("width", "100%");
    this.svg.setAttribute("height", "100%");

    // Defs for markers and filters
    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    defs.innerHTML = `
      <marker id="fg-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="var(--text-muted, #71717a)" />
      </marker>
      <marker id="fg-arrow-active" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
        <path d="M 0 1 L 9 5 L 0 9 z" fill="var(--accent-primary, #6366f1)" />
      </marker>
      <marker id="fg-arrow-alert" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
        <path d="M 0 1 L 9 5 L 0 9 z" fill="#f43f5e" />
      </marker>
    `;
    this.svg.appendChild(defs);

    // Background Interaction Rect (clean transparent surface for panning and deselecting)
    this.gridRect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    this.gridRect.setAttribute("width", "100%");
    this.gridRect.setAttribute("height", "100%");
    this.gridRect.setAttribute("fill", "transparent");
    this.svg.appendChild(this.gridRect);

    // Main Graph Viewport Group
    this.viewport = document.createElementNS("http://www.w3.org/2000/svg", "g");
    this.viewport.classList.add("fg-viewport");
    this.svg.appendChild(this.viewport);

    // Layers inside viewport: edges layer, then nodes layer
    this.edgesLayer = document.createElementNS("http://www.w3.org/2000/svg", "g");
    this.edgesLayer.classList.add("fg-edges-layer");
    this.viewport.appendChild(this.edgesLayer);

    this.nodesLayer = document.createElementNS("http://www.w3.org/2000/svg", "g");
    this.nodesLayer.classList.add("fg-nodes-layer");
    this.viewport.appendChild(this.nodesLayer);

    this.container.appendChild(this.svg);
    this._updateTransform();
  }

  _attachEvents() {
    // Wheel zoom
    this.svg.addEventListener("wheel", (e) => {
      e.preventDefault();
      const rect = this.svg.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      const zoomFactor = e.deltaY < 0 ? 1.15 : 0.87;
      const newScale = Math.min(Math.max(this.transform.scale * zoomFactor, 0.2), 3.0);

      // Zoom towards mouse pointer
      this.transform.x = mouseX - (mouseX - this.transform.x) * (newScale / this.transform.scale);
      this.transform.y = mouseY - (mouseY - this.transform.y) * (newScale / this.transform.scale);
      this.transform.scale = newScale;

      this._updateTransform();
    }, { passive: false });

    // Pointer down for pan or node drag
    this.svg.addEventListener("pointerdown", (e) => {
      const nodeEl = e.target.closest(".fg-node");
      if (nodeEl) {
        const nodeId = nodeEl.getAttribute("data-id");
        const node = this.nodes.get(nodeId);
        if (node) {
          this.draggedNode = node;
          this.dragOffset = {
            x: (e.clientX - this.transform.x) / this.transform.scale - node.x,
            y: (e.clientY - this.transform.y) / this.transform.scale - node.y,
          };
          this.svg.setPointerCapture(e.pointerId);
          return;
        }
      }

      // Background pan
      if (e.target === this.svg || e.target === this.gridRect || e.target.classList.contains("fg-edges-layer")) {
        this.isPanning = true;
        this.panStart = { x: e.clientX - this.transform.x, y: e.clientY - this.transform.y };
        this.svg.setPointerCapture(e.pointerId);
        this.container.classList.add("is-panning");
      }
    });

    this.svg.addEventListener("pointermove", (e) => {
      if (this.draggedNode) {
        const targetX = (e.clientX - this.transform.x) / this.transform.scale - this.dragOffset.x;
        const targetY = (e.clientY - this.transform.y) / this.transform.scale - this.dragOffset.y;
        this.draggedNode.x = targetX;
        this.draggedNode.y = targetY;
        this._updateNodePosition(this.draggedNode);
        this._renderEdges();
        return;
      }

      if (this.isPanning) {
        this.transform.x = e.clientX - this.panStart.x;
        this.transform.y = e.clientY - this.panStart.y;
        this._updateTransform();
      }
    });

    const stopDragOrPan = (e) => {
      if (this.draggedNode) {
        this.draggedNode = null;
        try { this.svg.releasePointerCapture(e.pointerId); } catch (_) {}
      }
      if (this.isPanning) {
        this.isPanning = false;
        this.container.classList.remove("is-panning");
        try { this.svg.releasePointerCapture(e.pointerId); } catch (_) {}
      }
    };

    this.svg.addEventListener("pointerup", stopDragOrPan);
    this.svg.addEventListener("pointercancel", stopDragOrPan);

    // Canvas click: deselect if background clicked
    this.svg.addEventListener("click", (e) => {
      if (e.target === this.svg || e.target === this.gridRect) {
        this.selectNode(null);
      }
    });
  }

  _updateTransform() {
    this.viewport.setAttribute(
      "transform",
      `translate(${this.transform.x.toFixed(2)}, ${this.transform.y.toFixed(2)}) scale(${this.transform.scale.toFixed(3)})`
    );
  }

  /**
   * Parse timeline events and populate the DAG.
   */
  loadTimeline(timelineEvents) {
    this.rawEvents = Array.isArray(timelineEvents) ? timelineEvents : [];
    this.nodes.clear();
    this.edges = [];
    this.selectedNodeId = null;
    this.highlightedNodeIds = null;

    if (this.rawEvents.length === 0) {
      this._renderEmpty();
      return;
    }

    const processMap = new Map(); // pid/name key -> process node
    const eventNodes = [];

    // Helper to format string safely
    const str = (v) => (v !== null && v !== undefined ? String(v).trim() : "");

    // 1. Process identification pass
    this.rawEvents.forEach((ev, idx) => {
      const action = str(ev.action).toLowerCase();
      const procName = str(ev.process_name || (ev.details && ev.details.process_name) || (ev.details && ev.details.name));
      const procId = str(ev.process_entity_id || (ev.details && ev.details.pid) || (ev.details && ev.details.process_id));
      const parentName = str(ev.parent_process_name || (ev.details && ev.details.parent_name) || (ev.details && ev.details.parent_process_name));
      const parentId = str(ev.parent_process_entity_id || (ev.details && ev.details.parent_pid) || (ev.details && ev.details.parent_entity_id));
      const cmdLine = str(ev.command_line || (ev.details && ev.details.command_line));
      const host = str(ev.host_id || "Unknown");
      const time = str(ev.timestamp || "");

      // Suspicious flag checks
      const isSuspicious = this._isSuspiciousEvent(ev, procName, cmdLine);

      if (procName || procId || action.includes("process")) {
        const nodeKey = `proc_${host}_${procId || procName || idx}`;
        if (!this.nodes.has(nodeKey)) {
          const procNode = {
            id: nodeKey,
            type: "process",
            name: procName || (action.includes("process") ? "process.exe" : "Process"),
            pid: procId || "N/A",
            parentName: parentName,
            parentId: parentId,
            cmdLine: cmdLine || ev.summary || "",
            host: host,
            timestamp: time,
            isSuspicious: isSuspicious,
            action: action || "process_active",
            raw: ev,
            childrenCount: 0,
          };
          this.nodes.set(nodeKey, procNode);
          processMap.set(`${host}_${procId}`, procNode);
          if (procName) processMap.set(`${host}_${procName.toLowerCase()}`, procNode);
        } else {
          // Merge details
          const existing = this.nodes.get(nodeKey);
          if (!existing.cmdLine && cmdLine) existing.cmdLine = cmdLine;
          if (isSuspicious) existing.isSuspicious = true;
        }
      }

      // Non-process event nodes (network, file, registry)
      if (action.includes("network") || ev.destination_ip || (ev.details && ev.details.destination_ip)) {
        const dstIp = str(ev.destination_ip || (ev.details && ev.details.destination_ip) || "0.0.0.0");
        const dstPort = str(ev.destination_port || (ev.details && ev.details.destination_port) || "");
        const netId = `net_${host}_${dstIp}_${dstPort}_${idx}`;
        const netNode = {
          id: netId,
          type: "network",
          name: `${dstIp}${dstPort ? ":" + dstPort : ""}`,
          ip: dstIp,
          port: dstPort,
          direction: str(ev.network_direction || (ev.details && ev.details.network_direction) || "Outbound"),
          host: host,
          timestamp: time,
          isSuspicious: isSuspicious || this._isSuspiciousIp(dstIp),
          action: action || "network_connection",
          raw: ev,
          parentProcKey: procId ? `${host}_${procId}` : (procName ? `${host}_${procName.toLowerCase()}` : null),
        };
        this.nodes.set(netId, netNode);
        eventNodes.push(netNode);
      } else if (action.includes("file") || ev.file_name || (ev.details && ev.details.file_name) || (ev.details && ev.details.path)) {
        const fileName = str(ev.file_name || (ev.details && ev.details.file_name) || (ev.details && ev.details.path) || "file");
        const fileId = `file_${host}_${fileName.replace(/[^a-zA-Z0-9_-]/g, "_")}_${idx}`;
        const fileNode = {
          id: fileId,
          type: "file",
          name: fileName.split(/[\\/]/).pop() || fileName,
          fullPath: fileName,
          fileAction: action || "file_modified",
          host: host,
          timestamp: time,
          isSuspicious: isSuspicious || fileName.endsWith(".locked") || fileName.includes("dmp"),
          action: action,
          raw: ev,
          parentProcKey: procId ? `${host}_${procId}` : (procName ? `${host}_${procName.toLowerCase()}` : null),
        };
        this.nodes.set(fileId, fileNode);
        eventNodes.push(fileNode);
      } else if (action.includes("registry") || ev.registry_key || (ev.details && ev.details.registry_key)) {
        const regKey = str(ev.registry_key || (ev.details && ev.details.registry_key) || "HKLM\\...");
        const regId = `reg_${host}_${regKey.replace(/[^a-zA-Z0-9_-]/g, "_")}_${idx}`;
        const regNode = {
          id: regId,
          type: "registry",
          name: regKey.split(/[\\/]/).pop() || regKey,
          fullPath: regKey,
          host: host,
          timestamp: time,
          isSuspicious: isSuspicious || regKey.toLowerCase().includes("run") || regKey.toLowerCase().includes("currentversion"),
          action: action,
          raw: ev,
          parentProcKey: procId ? `${host}_${procId}` : (procName ? `${host}_${procName.toLowerCase()}` : null),
        };
        this.nodes.set(regId, regNode);
        eventNodes.push(regNode);
      }
    });

    // 2. Initialize children and parents arrays on all nodes
    this.nodes.forEach((node) => {
      node.children = [];
      node.parents = [];
      node.childrenCount = 0;
    });

    const addEdge = (fromId, toId, label, type) => {
      const fromNode = this.nodes.get(fromId);
      const toNode = this.nodes.get(toId);
      if (!fromNode || !toNode || fromId === toId) return;

      this.edges.push({
        from: fromId,
        to: toId,
        label: label,
        type: type,
      });

      if (!fromNode.children.includes(toId)) {
        fromNode.children.push(toId);
        fromNode.childrenCount = fromNode.children.length;
      }
      if (!toNode.parents.includes(fromId)) {
        toNode.parents.push(fromId);
      }
    };

    // Process -> Child Process
    this.nodes.forEach((procNode) => {
      if (procNode.type === "process" && (procNode.parentId || procNode.parentName)) {
        let parentNode = null;
        if (procNode.parentId) {
          parentNode = processMap.get(`${procNode.host}_${procNode.parentId}`);
        }
        if (!parentNode && procNode.parentName) {
          parentNode = processMap.get(`${procNode.host}_${procNode.parentName.toLowerCase()}`);
        }
        if (parentNode && parentNode.id !== procNode.id) {
          addEdge(parentNode.id, procNode.id, "spawned", "process-child");
        }
      }
    });

    // Process -> Event nodes (network, file, registry)
    eventNodes.forEach((evNode) => {
      if (evNode.parentProcKey) {
        const parentProc = processMap.get(evNode.parentProcKey);
        if (parentProc) {
          let edgeLabel = "connected";
          if (evNode.type === "file") edgeLabel = "wrote";
          if (evNode.type === "registry") edgeLabel = "modified";
          addEdge(parentProc.id, evNode.id, edgeLabel, `proc-${evNode.type}`);
        }
      }
    });

    // If there are multiple hosts, identify lateral movement edges
    this._detectLateralEdges(addEdge);

    // Initial expansion state:
    // Small graphs (<= 15 nodes) start fully expanded for immediate overview.
    // Larger graphs start with root nodes expanded so users can click to drill down cleanly.
    this.expandedNodeIds.clear();
    if (this.nodes.size <= 16) {
      this.nodes.forEach((n) => {
        if (n.children && n.children.length > 0) {
          this.expandedNodeIds.add(n.id);
        }
      });
    } else {
      this.nodes.forEach((n) => {
        if (n.parents.length === 0 && n.children && n.children.length > 0) {
          this.expandedNodeIds.add(n.id);
        }
      });
    }

    this._visibleTreeIds = this._computeVisibleNodeIds();

    // 3. Layout calculation
    this._calculateLayout();

    // 4. Render
    this._render();
    this.fitToScreen();
  }

  _isSuspiciousEvent(ev, procName, cmdLine) {
    const text = `${procName} ${cmdLine} ${ev.summary || ""}`.toLowerCase();
    const badPatterns = [
      "vssadmin", "delete shadows", "lockbit", ".locked", "mimikatz", "procdump",
      "lsass", "powershell -nop", "-hidden", "-enc", "whoami", "certutil -urlcache",
      "schtasks /create", "cobaltstrike", "c2", "invoke-mimikatz", "winrm",
      "wmic process call create"
    ];
    return badPatterns.some(p => text.includes(p));
  }

  _isSuspiciousIp(ip) {
    if (!ip || ip === "127.0.0.1" || ip === "0.0.0.0") return false;
    // Private ranges are standard, public / test-net ips might be external C2
    return ip.startsWith("198.51.100.") || ip.startsWith("203.0.113.") || ip.startsWith("45.") || ip.startsWith("185.");
  }

  _detectLateralEdges(addEdge = null) {
    const hosts = new Set();
    this.nodes.forEach(n => hosts.add(n.host));
    if (hosts.size <= 1) return;

    // Detect WinRM or lateral process events
    this.rawEvents.forEach(ev => {
      const summary = (ev.summary || "").toLowerCase();
      if (summary.includes("lateral") || summary.includes("winrm") || summary.includes("remote")) {
        const srcHost = ev.host_id;
        // Find process on another host
        this.nodes.forEach(targetNode => {
          if (targetNode.host !== srcHost && targetNode.type === "process") {
            const hasExistingEdge = this.edges.some(e => e.to === targetNode.id && e.label === "lateral_exec");
            if (!hasExistingEdge) {
              // Connect from first process on srcHost
              const srcProc = Array.from(this.nodes.values()).find(n => n.host === srcHost && n.type === "process");
              if (srcProc) {
                if (addEdge) {
                  addEdge(srcProc.id, targetNode.id, "lateral_exec", "lateral");
                } else {
                  this.edges.push({
                    from: srcProc.id,
                    to: targetNode.id,
                    label: "lateral_exec",
                    type: "lateral",
                  });
                }
              }
            }
          }
        });
      }
    });
  }

  _computeVisibleNodeIds() {
    const visible = new Set();
    const roots = [];
    this.nodes.forEach((node, id) => {
      if (!node.parents || node.parents.length === 0) {
        roots.push(id);
      }
    });

    if (roots.length === 0 && this.nodes.size > 0) {
      roots.push(Array.from(this.nodes.keys())[0]);
    }

    const queue = [...roots];
    roots.forEach(r => visible.add(r));

    while (queue.length > 0) {
      const currId = queue.shift();
      const currNode = this.nodes.get(currId);
      if (!currNode) continue;

      if (this.expandedNodeIds.has(currId) && currNode.children) {
        for (const childId of currNode.children) {
          if (!visible.has(childId)) {
            visible.add(childId);
            queue.push(childId);
          }
        }
      }
    }

    return visible;
  }

  _calculateLayout() {
    // Only layout visible nodes matching current filters & expansion state
    const visibleNodes = new Map();
    this.nodes.forEach((n, id) => {
      if (this._isNodeVisible(n)) {
        visibleNodes.set(id, n);
      }
    });

    if (visibleNodes.size === 0) return;

    // Topological / Layered DAG layout on visible nodes
    const incomingCount = new Map();
    visibleNodes.forEach((n, id) => incomingCount.set(id, 0));
    this.edges.forEach(e => {
      if (visibleNodes.has(e.from) && visibleNodes.has(e.to)) {
        incomingCount.set(e.to, incomingCount.get(e.to) + 1);
      }
    });

    // Roots have 0 incoming edges among visible nodes
    const layers = [];
    const visited = new Set();
    let currentLayer = [];

    visibleNodes.forEach((n, id) => {
      if (incomingCount.get(id) === 0) {
        currentLayer.push(id);
        visited.add(id);
      }
    });

    if (currentLayer.length === 0 && visibleNodes.size > 0) {
      const first = Array.from(visibleNodes.keys())[0];
      currentLayer.push(first);
      visited.add(first);
    }

    layers.push(currentLayer);

    while (visited.size < visibleNodes.size) {
      const nextLayer = [];
      for (const currId of layers[layers.length - 1]) {
        for (const edge of this.edges) {
          if (edge.from === currId && visibleNodes.has(edge.to) && !visited.has(edge.to)) {
            nextLayer.push(edge.to);
            visited.add(edge.to);
          }
        }
      }
      if (nextLayer.length === 0) {
        // Collect unvisited nodes (e.g. disconnected components)
        visibleNodes.forEach((n, id) => {
          if (!visited.has(id)) {
            nextLayer.push(id);
            visited.add(id);
          }
        });
      }
      if (nextLayer.length > 0) {
        layers.push(nextLayer);
      } else {
        break;
      }
    }

    // Assign X, Y coordinates
    const layerSpacingX = 320;
    const nodeSpacingY = 110;
    const startX = 60;
    const startY = 60;

    layers.forEach((layer, layerIdx) => {
      const totalHeight = layer.length * nodeSpacingY;
      const offsetY = startY + Math.max(0, (500 - totalHeight) / 4);

      layer.forEach((nodeId, rowIdx) => {
        const node = this.nodes.get(nodeId);
        if (node) {
          node.x = startX + layerIdx * layerSpacingX;
          node.y = offsetY + rowIdx * nodeSpacingY;
          node.width = node.type === "process" ? 220 : 190;
          node.height = 70;
        }
      });
    });
  }

  _render() {
    this.edgesLayer.innerHTML = "";
    this.nodesLayer.innerHTML = "";

    this._renderEdges();
    this._renderNodes();
  }

  _renderNodes() {
    this.nodes.forEach((node) => {
      if (!this._isNodeVisible(node)) return;

      const isMatch = this._doesNodeMatchSearch(node);
      const hasChildren = node.children && node.children.length > 0;
      const isExpanded = this.expandedNodeIds.has(node.id);

      const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
      g.classList.add("fg-node", `fg-type-${node.type}`);
      g.setAttribute("data-id", node.id);
      g.setAttribute("transform", `translate(${node.x.toFixed(1)}, ${node.y.toFixed(1)})`);

      if (this.searchQuery && !isMatch) g.classList.add("fg-dimmed");
      if (this.selectedNodeId === node.id) g.classList.add("fg-selected");
      if (this.highlightedNodeIds && this.highlightedNodeIds.has(node.id)) g.classList.add("fg-highlighted");
      if (node.isSuspicious) g.classList.add("fg-threat");

      // Card Background Rect
      const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      rect.setAttribute("width", node.width);
      rect.setAttribute("height", node.height);
      rect.setAttribute("rx", "10");
      rect.setAttribute("ry", "10");
      rect.classList.add("fg-node-card");
      g.appendChild(rect);

      // Icon & Type Indicator
      const iconGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
      iconGroup.classList.add("fg-node-icon");
      iconGroup.setAttribute("transform", "translate(12, 16)");
      iconGroup.innerHTML = this._getNodeIconSvg(node.type);
      g.appendChild(iconGroup);

      // Title Text
      const textTitle = document.createElementNS("http://www.w3.org/2000/svg", "text");
      textTitle.setAttribute("x", "40");
      textTitle.setAttribute("y", "26");
      textTitle.classList.add("fg-node-title");
      textTitle.textContent = this._truncate(node.name, node.type === "process" ? 17 : 15);
      g.appendChild(textTitle);

      // Subtitle / Meta Text
      const textMeta = document.createElementNS("http://www.w3.org/2000/svg", "text");
      textMeta.setAttribute("x", "40");
      textMeta.setAttribute("y", "44");
      textMeta.classList.add("fg-node-meta");
      if (node.type === "process") {
        textMeta.textContent = `PID ${node.pid} · ${node.host}`;
      } else if (node.type === "network") {
        textMeta.textContent = `${node.direction} · ${node.host}`;
      } else if (node.type === "file") {
        textMeta.textContent = `${node.fileAction || 'file'} · ${node.host}`;
      } else {
        textMeta.textContent = node.host;
      }
      g.appendChild(textMeta);

      // Threat / Alert Badge if suspicious
      if (node.isSuspicious) {
        const threatBadge = document.createElementNS("http://www.w3.org/2000/svg", "g");
        threatBadge.setAttribute("transform", `translate(${node.width - 24}, 8)`);
        threatBadge.innerHTML = `
          <circle cx="8" cy="8" r="8" fill="#f43f5e" />
          <path d="M 8 4 L 8 9 M 8 11 L 8 12" stroke="#fff" stroke-width="1.8" stroke-linecap="round" />
        `;
        threatBadge.classList.add("fg-threat-badge");
        g.appendChild(threatBadge);
      }

      // Interactive Expand/Collapse Badge if node has connected children
      if (hasChildren) {
        const childCount = node.children.length;
        const expandBadge = document.createElementNS("http://www.w3.org/2000/svg", "g");
        expandBadge.classList.add("fg-expand-badge");
        if (isExpanded) expandBadge.classList.add("is-expanded");
        
        // Position badge on the right edge of node card
        expandBadge.setAttribute("transform", `translate(${node.width}, ${node.height / 2})`);
        expandBadge.setAttribute("role", "button");
        expandBadge.setAttribute("tabindex", "0");

        const bTitle = document.createElementNS("http://www.w3.org/2000/svg", "title");
        bTitle.textContent = isExpanded
          ? `Click to collapse ${childCount} connected entities`
          : `Click to expand ${childCount} connected entities`;
        expandBadge.appendChild(bTitle);

        const bCircle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        bCircle.setAttribute("cx", "0");
        bCircle.setAttribute("cy", "0");
        bCircle.setAttribute("r", "10");
        bCircle.classList.add("fg-expand-badge-bg");
        expandBadge.appendChild(bCircle);

        const bText = document.createElementNS("http://www.w3.org/2000/svg", "text");
        bText.setAttribute("x", "0");
        bText.setAttribute("y", isExpanded ? "3" : "3.5");
        bText.setAttribute("text-anchor", "middle");
        bText.classList.add("fg-expand-badge-text");
        bText.textContent = isExpanded ? "−" : `+${childCount}`;
        expandBadge.appendChild(bText);

        expandBadge.addEventListener("click", (e) => {
          e.stopPropagation();
          this.toggleNodeExpansion(node.id);
        });

        g.appendChild(expandBadge);
      }

      // Event listener: pressing node selects it AND expands connected nodes if collapsed
      g.addEventListener("click", (e) => {
        e.stopPropagation();
        this.selectNode(node.id);
        if (hasChildren && !this.expandedNodeIds.has(node.id)) {
          this.toggleNodeExpansion(node.id, true);
        }
      });

      // Double clicking toggles expansion
      g.addEventListener("dblclick", (e) => {
        e.stopPropagation();
        if (hasChildren) {
          this.toggleNodeExpansion(node.id);
        }
      });

      g.addEventListener("pointerenter", () => {
        this._highlightConnected(node.id);
      });

      g.addEventListener("pointerleave", () => {
        if (!this.selectedNodeId) {
          this._clearHighlights();
        } else {
          this._highlightConnected(this.selectedNodeId);
        }
      });

      this.nodesLayer.appendChild(g);
    });
  }

  _renderEdges() {
    this.edgesLayer.innerHTML = "";

    this.edges.forEach((edge) => {
      const fromNode = this.nodes.get(edge.from);
      const toNode = this.nodes.get(edge.to);
      if (!fromNode || !toNode) return;

      const isFromVisible = this._isNodeVisible(fromNode);
      const isToVisible = this._isNodeVisible(toNode);
      if (!isFromVisible || !isToVisible) return;

      // Start: center-right of fromNode
      const x1 = fromNode.x + fromNode.width;
      const y1 = fromNode.y + fromNode.height / 2;

      // End: center-left of toNode
      const x2 = toNode.x;
      const y2 = toNode.y + toNode.height / 2;

      // Cubic Bezier curve control points
      const dx = Math.max(Math.abs(x2 - x1) * 0.5, 40);
      const cx1 = x1 + dx;
      const cy1 = y1;
      const cx2 = x2 - dx;
      const cy2 = y2;

      const pathData = `M ${x1.toFixed(1)} ${y1.toFixed(1)} C ${cx1.toFixed(1)} ${cy1.toFixed(1)}, ${cx2.toFixed(1)} ${cy2.toFixed(1)}, ${x2.toFixed(1)} ${y2.toFixed(1)}`;

      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", pathData);
      path.classList.add("fg-edge", `fg-edge-${edge.type}`);

      const isLateral = edge.type === "lateral";
      const isThreat = fromNode.isSuspicious || toNode.isSuspicious;

      if (isThreat) {
        path.setAttribute("marker-end", "url(#fg-arrow-alert)");
        path.classList.add("fg-edge-threat");
      } else {
        path.setAttribute("marker-end", "url(#fg-arrow)");
      }

      if (isLateral) {
        path.classList.add("fg-edge-lateral");
      }

      this.edgesLayer.appendChild(path);

      // Edge relationship label badge at mid point
      if (edge.label) {
        const mx = (x1 + x2) / 2;
        const my = (y1 + y2) / 2;

        const badgeGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
        badgeGroup.setAttribute("transform", `translate(${mx.toFixed(1)}, ${my.toFixed(1)})`);
        badgeGroup.classList.add("fg-edge-badge-group");

        const badgeRect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        const textLen = edge.label.length * 6.5 + 12;
        badgeRect.setAttribute("x", -textLen / 2);
        badgeRect.setAttribute("y", -9);
        badgeRect.setAttribute("width", textLen);
        badgeRect.setAttribute("height", 18);
        badgeRect.setAttribute("rx", 9);
        badgeRect.classList.add("fg-edge-badge-bg");

        const badgeText = document.createElementNS("http://www.w3.org/2000/svg", "text");
        badgeText.setAttribute("x", 0);
        badgeText.setAttribute("y", 3);
        badgeText.setAttribute("text-anchor", "middle");
        badgeText.classList.add("fg-edge-badge-text");
        badgeText.textContent = edge.label;

        badgeGroup.appendChild(badgeRect);
        badgeGroup.appendChild(badgeText);
        this.edgesLayer.appendChild(badgeGroup);
      }
    });
  }

  _updateNodePosition(node) {
    const el = this.nodesLayer.querySelector(`.fg-node[data-id="${node.id}"]`);
    if (el) {
      el.setAttribute("transform", `translate(${node.x.toFixed(1)}, ${node.y.toFixed(1)})`);
    }
  }

  _highlightConnected(nodeId) {
    const set = new Set();
    set.add(nodeId);

    // Add ancestors (parents)
    const findParents = (id) => {
      this.edges.forEach(e => {
        if (e.to === id && !set.has(e.from)) {
          set.add(e.from);
          findParents(e.from);
        }
      });
    };

    // Add descendants (children)
    const findChildren = (id) => {
      this.edges.forEach(e => {
        if (e.from === id && !set.has(e.to)) {
          set.add(e.to);
          findChildren(e.to);
        }
      });
    };

    findParents(nodeId);
    findChildren(nodeId);

    this.highlightedNodeIds = set;
    this._applyHighlightClasses();
  }

  _clearHighlights() {
    this.highlightedNodeIds = null;
    this._applyHighlightClasses();
  }

  _applyHighlightClasses() {
    const allNodeEls = this.nodesLayer.querySelectorAll(".fg-node");
    allNodeEls.forEach(el => {
      const id = el.getAttribute("data-id");
      if (this.highlightedNodeIds) {
        if (this.highlightedNodeIds.has(id)) {
          el.classList.add("fg-highlighted");
          el.classList.remove("fg-dimmed");
        } else {
          el.classList.remove("fg-highlighted");
          el.classList.add("fg-dimmed");
        }
      } else {
        el.classList.remove("fg-highlighted");
        if (!this.searchQuery) {
          el.classList.remove("fg-dimmed");
        }
      }
    });
  }

  selectNode(nodeId) {
    this.selectedNodeId = nodeId;

    // Toggle selected class
    this.nodesLayer.querySelectorAll(".fg-node").forEach(el => {
      const id = el.getAttribute("data-id");
      if (id === nodeId) {
        el.classList.add("fg-selected");
      } else {
        el.classList.remove("fg-selected");
      }
    });

    if (nodeId) {
      this._highlightConnected(nodeId);
      const node = this.nodes.get(nodeId);
      if (this.options.onNodeSelect && node) {
        this.options.onNodeSelect(node);
      }
    } else {
      this._clearHighlights();
      if (this.options.onNodeDeselect) {
        this.options.onNodeDeselect();
      }
    }
  }

  setFilter(category) {
    this.activeFilter = category.toLowerCase();
    this._calculateLayout();
    this._render();
  }

  setSearch(query) {
    this.searchQuery = (query || "").trim().toLowerCase();
    this._render();
  }

  _doesNodeMatchFilter(node) {
    if (this.activeFilter === "all") return true;
    if (this.activeFilter === "process" && node.type === "process") return true;
    if (this.activeFilter === "network" && node.type === "network") return true;
    if (this.activeFilter === "file" && node.type === "file") return true;
    if (this.activeFilter === "registry" && node.type === "registry") return true;
    if (this.activeFilter === "alert" && node.isSuspicious) return true;
    return false;
  }

  _isNodeVisible(node) {
    if (!node) return false;
    if (!this._visibleTreeIds.has(node.id)) return false;
    return this._doesNodeMatchFilter(node);
  }

  toggleNodeExpansion(nodeId, forceExpand = null) {
    const node = this.nodes.get(nodeId);
    if (!node || !node.children || node.children.length === 0) return;

    const currentlyExpanded = this.expandedNodeIds.has(nodeId);
    const shouldExpand = forceExpand !== null ? forceExpand : !currentlyExpanded;

    if (shouldExpand) {
      this.expandedNodeIds.add(nodeId);
    } else {
      this.expandedNodeIds.delete(nodeId);
    }

    this._visibleTreeIds = this._computeVisibleNodeIds();
    this._calculateLayout();
    this._render();

    if (this.selectedNodeId) {
      const selNode = this.nodes.get(this.selectedNodeId);
      if (selNode && this._isNodeVisible(selNode)) {
        this._highlightConnected(this.selectedNodeId);
      }
    }

    if (this.options.onExpansionChange) {
      this.options.onExpansionChange(node, shouldExpand);
    }
  }

  expandAll() {
    this.nodes.forEach((n) => {
      if (n.children && n.children.length > 0) {
        this.expandedNodeIds.add(n.id);
      }
    });
    this._visibleTreeIds = this._computeVisibleNodeIds();
    this._calculateLayout();
    this._render();
    this.fitToScreen();
    if (this.options.onExpansionChange) {
      this.options.onExpansionChange(null, true);
    }
  }

  collapseAll() {
    this.expandedNodeIds.clear();
    this._visibleTreeIds = this._computeVisibleNodeIds();
    this._calculateLayout();
    this._render();
    this.fitToScreen();
    if (this.options.onExpansionChange) {
      this.options.onExpansionChange(null, false);
    }
  }

  getVisibleCount() {
    let count = 0;
    this.nodes.forEach(n => {
      if (this._isNodeVisible(n)) count++;
    });
    return count;
  }

  _doesNodeMatchSearch(node) {
    if (!this.searchQuery) return true;
    const q = this.searchQuery;
    const str = `${node.name} ${node.pid || ""} ${node.host || ""} ${node.cmdLine || ""} ${node.fullPath || ""} ${node.ip || ""}`.toLowerCase();
    return str.includes(q);
  }

  fitToScreen() {
    if (this.nodes.size === 0) return;

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    this.nodes.forEach(n => {
      if (this._isNodeVisible(n)) {
        minX = Math.min(minX, n.x);
        minY = Math.min(minY, n.y);
        maxX = Math.max(maxX, n.x + n.width);
        maxY = Math.max(maxY, n.y + n.height);
      }
    });

    if (!isFinite(minX)) return;

    const rect = this.svg.getBoundingClientRect();
    const padding = 80;
    const graphWidth = maxX - minX;
    const graphHeight = maxY - minY;

    const scaleX = (rect.width - padding * 2) / (graphWidth || 1);
    const scaleY = (rect.height - padding * 2) / (graphHeight || 1);
    const newScale = Math.min(Math.max(Math.min(scaleX, scaleY), 0.35), 1.2);

    this.transform.scale = newScale;
    this.transform.x = (rect.width - graphWidth * newScale) / 2 - minX * newScale;
    this.transform.y = (rect.height - graphHeight * newScale) / 2 - minY * newScale;

    this._updateTransform();
  }

  zoomIn() {
    this.transform.scale = Math.min(this.transform.scale * 1.25, 3.0);
    this._updateTransform();
  }

  zoomOut() {
    this.transform.scale = Math.max(this.transform.scale * 0.8, 0.25);
    this._updateTransform();
  }

  _renderEmpty() {
    this.edgesLayer.innerHTML = "";
    this.nodesLayer.innerHTML = "";
    const foreign = document.createElementNS("http://www.w3.org/2000/svg", "foreignObject");
    foreign.setAttribute("width", "100%");
    foreign.setAttribute("height", "100%");
    foreign.innerHTML = `
      <div class="fg-empty-state">
        <div class="fg-empty-title">Forensic Attack Graph Ready</div>
        <div class="fg-empty-desc">Run an investigation query or click a sample scenario to visually trace process trees, C2 connections, file drops, and lateral movement.</div>
      </div>
    `;
    this.viewport.appendChild(foreign);
  }

  _getNodeIconSvg(type) {
    switch (type) {
      case "process":
        return `<rect x="0" y="0" width="18" height="14" rx="2" fill="none" stroke="var(--badge-proc-text, #6366f1)" stroke-width="2"/><line x1="4" y1="4" x2="8" y2="4" stroke="var(--badge-proc-text, #6366f1)" stroke-width="2"/><line x1="4" y1="8" x2="12" y2="8" stroke="var(--badge-proc-text, #6366f1)" stroke-width="2"/>`;
      case "network":
        return `<circle cx="8" cy="8" r="7" fill="none" stroke="var(--badge-net-text, #0284c7)" stroke-width="2"/><path d="M1 8h14M8 1a10 10 0 0 1 0 14M8 1a10 10 0 0 0 0 14" stroke="var(--badge-net-text, #0284c7)" stroke-width="1.6"/>`;
      case "file":
        return `<path d="M2 1h8l4 4v10a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1z" fill="none" stroke="var(--badge-file-text, #059669)" stroke-width="2"/><path d="M10 1v4h4" stroke="var(--badge-file-text, #059669)" stroke-width="1.6"/>`;
      case "registry":
        return `<rect x="1" y="1" width="14" height="14" rx="2" fill="none" stroke="var(--badge-reg-text, #b45309)" stroke-width="2"/><circle cx="8" cy="8" r="3" stroke="var(--badge-reg-text, #b45309)" stroke-width="1.6"/>`;
      default:
        return `<circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="2"/>`;
    }
  }

  _truncate(str, maxLen) {
    if (!str) return "";
    return str.length > maxLen ? str.slice(0, maxLen - 1) + "…" : str;
  }
}

window.ForensicGraph = ForensicGraph;
