/**
 * A1 evidence tree.
 *
 * Renders TelemetryGraph.build() output as a per-host entity tree: alerts, the
 * parent → spawned process forest, the artifacts each process touched, and the
 * accounts seen on the host. Relationships come from the graph edges; nothing is
 * inferred from labels. DOM only — no canvas, no layout engine.
 */
(function () {
  "use strict";

  var ARTIFACT = { file: 1, registry_artifact: 1, ip_address: 1, domain: 1 };
  var collapsed = new Set();
  var current = null;

  function esc(s) {
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

  function clock(ts) {
    if (!ts) return "";
    var d = new Date(ts);
    if (isNaN(d.getTime())) return "";
    return pad(d.getHours()) + ":" + pad(d.getMinutes());
  }

  function colorOf(type) {
    var meta = window.TelemetryGraph.TYPES[type];
    return meta ? meta.color : "#8b98a5";
  }

  function labelOf(type) {
    var meta = window.TelemetryGraph.TYPES[type];
    return meta ? meta.label : type;
  }

  function typeOrder(type) {
    var i = window.TelemetryGraph.TYPE_ORDER.indexOf(type);
    return i < 0 ? 99 : i;
  }

  function ownerMap(nodes, edges, byId) {
    var owner = new Map();
    var hosts = nodes.filter(function (n) {
      return n.type === "host";
    });
    var adj = new Map();
    edges.forEach(function (e) {
      if (!adj.has(e.from)) adj.set(e.from, []);
      if (!adj.has(e.to)) adj.set(e.to, []);
      adj.get(e.from).push(e.to);
      adj.get(e.to).push(e.from);
    });
    var queue = [];
    hosts.forEach(function (h) {
      owner.set(h.id, h.id);
      queue.push(h.id);
    });
    while (queue.length) {
      var id = queue.shift();
      var host = owner.get(id);
      (adj.get(id) || []).forEach(function (other) {
        var n = byId.get(other);
        if (!n || owner.has(other) || n.type === "host") return;
        owner.set(other, host);
        queue.push(other);
      });
    }
    return owner;
  }

  function build(node, opts, ctx) {
    var kids = [];
    var hasKids = false;

    if (node.type === "process") {
      ctx.used.add(node.id);
      var children = ctx.procChildren.get(node.id) || [];
      children.forEach(function (child) {
        if (ctx.owner.get(child.id) !== ctx.host.id) return;
        if (ctx.hidden.has(child.type)) return;
        if (ctx.query && !ctx.visible.has(child.id)) return;
        if (ctx.used.has(child.id)) {
          kids.push(refRow(child, "process"));
        } else {
          kids.push(build(child, opts, ctx));
        }
      });
      kids = kids.concat(artifactRows(node, opts, ctx));
      hasKids = kids.length > 0;
    }

    if (node.type === "host") {
      hasKids = true;
    }

    var inner = kids.join("");
    var metaText = metaFor(node, opts);
    var title = node.detail || node.label;
    if (node.risk) title += " · " + node.risk.level + ": " + node.risk.reasons.join("; ");
    var detail = "";
    if (node.type === "ip_address" && node.detail) {
      detail = '<span class="tdetail">' + esc(node.detail) + "</span>";
    }

    var toggle = hasKids
      ? '<button type="button" class="twisty" tabindex="-1" aria-label="Toggle children"></button>'
      : '<span class="twisty is-leaf" aria-hidden="true"></span>';
    var collapsedNow = collapsed.has(node.id) && !ctx.query;
    var cls = "tnode";
    if (node.type === "host") cls += " is-host";
    if (node.risk) cls += " is-" + node.risk.level;
    if (collapsedNow) cls += " is-collapsed";
    if (opts.selectedId === node.id) cls += " is-selected";

    return (
      '<div class="' + cls + '" data-id="' + esc(node.id) + '" role="treeitem">' +
      '<div class="trow' + (node.type === "host" ? " trow-host" : "") + '" tabindex="0"' +
      (hasKids ? ' aria-expanded="' + String(!collapsedNow) + '"' : "") +
      ' title="' + esc(title) + '">' +
      toggle +
      '<span class="dot" style="background:' + colorOf(node.type) + '"></span>' +
      '<span class="tlabel">' + esc(node.label) + detail + "</span>" +
      (node.risk ? '<span class="trisk ' + node.risk.level + '" title="' + esc(node.risk.reasons.join("; ")) + '">!</span>' : "") +
      '<span class="tmeta">' + metaText + "</span>" +
      "</div>" +
      (hasKids ? '<div class="tkids">' + inner + "</div>" : "") +
      "</div>"
    );
  }

  function metaFor(node, opts) {
    if (node.type === "host") {
      var bits = [];
      var ip = "";
      (node.attrs || []).forEach(function (a) {
        if (a[0] === "ip") ip = a[1];
      });
      if (ip) bits.push(esc(ip));
      if (opts.evidenceScope) bits.push("scoped");
      bits.push(node.eventCount + " ev");
      return bits.join(" · ");
    }
    if (node.type === "alert") {
      return (node.sev ? "sev " + node.sev + " · " : "") + clock(node.time);
    }
    if (node.type === "user") {
      return node.eventCount + " ev";
    }
    if (node.type === "process") {
      if (!node.eventCount) return "parent";
      return "×" + node.eventCount + " · " + clock(node.time);
    }
    return "";
  }

  function artifactRows(node, opts, ctx) {
    var rows = [];
    var seen = new Set();
    var ipNodes = [];
    var edges = ctx.out.get(node.id) || [];
    edges.forEach(function (e) {
      var art = ctx.byId.get(e.to);
      if (!art || !ARTIFACT[art.type] || art.type === "domain") return;
      if (ctx.query && !ctx.visible.has(art.id)) return;
      if (seen.has(art.id) || ctx.used.has(art.id)) return;
      seen.add(art.id);
      ctx.used.add(art.id);
      if (art.type === "ip_address") ipNodes.push(art);
      rows.push(artifactRow(art, e.label, e.count, ctx));
    });

    // A domain is linked to its resolved IP, not to the process. Show it under the
    // process that made the connection so the pair reads together.
    ipNodes.forEach(function (ip) {
      (ctx.inc.get(ip.id) || []).forEach(function (e) {
        if (e.rel !== "resolved") return;
        var dom = ctx.byId.get(e.from);
        if (!dom || dom.type !== "domain" || seen.has(dom.id) || ctx.used.has(dom.id)) return;
        if (ctx.query && !ctx.visible.has(dom.id)) return;
        seen.add(dom.id);
        ctx.used.add(dom.id);
        rows.push(artifactRow(dom, "resolved", 1, ctx));
      });
    });
    return rows.sort(function (a, b) {
      return a.sort - b.sort;
    }).map(function (r) {
      return r.html;
    });
  }

  function artifactRow(node, verb, count, ctx) {
    if (ctx.hidden.has(node.type)) return { sort: 0, html: "" };
    var meta = verb || "seen";
    if (/^:\d+$/.test(meta)) meta = "port " + meta.slice(1);
    if (count > 1) meta += " ×" + count;
    var lateral = "";
    if (node.type === "ip_address" && ctx.hostByIp[node.label] && ctx.hostByIp[node.label].id !== ctx.host.id) {
      lateral = ' <span class="lateral">lateral → ' + esc(ctx.hostByIp[node.label].label) + "</span>";
    }
    var html =
      '<div class="tnode is-artifact" data-id="' + esc(node.id) + '" role="treeitem">' +
      '<div class="trow trow-artifact" tabindex="0" title="' + esc(node.detail || node.label) + '">' +
      '<span class="twisty is-leaf" aria-hidden="true"></span>' +
      '<span class="dot" style="background:' + colorOf(node.type) + '"></span>' +
      '<span class="tlabel">' + esc(node.label) + lateral + "</span>" +
      '<span class="tmeta">' + esc(meta) + "</span>" +
      "</div></div>";
    return { sort: typeOrder(node.type) * 100000 + (node.time || 0), html: html };
  }

  function refRow(node, type) {
    return (
      '<div class="tnode is-ref" data-ref="' + esc(node.id) + '">' +
      '<div class="trow trow-artifact" tabindex="0" title="Already shown above">' +
      '<span class="twisty is-leaf" aria-hidden="true"></span>' +
      '<span class="dot" style="background:' + colorOf(type) + '"></span>' +
      '<span class="tlabel">' + esc(node.label) + "</span>" +
      '<span class="tmeta">shown above</span>' +
      "</div></div>"
    );
  }

  function group(id, label, count, inner) {
    var cls = "tgroup" + (collapsed.has(id) ? " is-collapsed" : "");
    return (
      '<div class="' + cls + '" data-group="' + esc(id) + '">' +
      '<div class="tgroup-row" tabindex="0" role="button" aria-expanded="' + String(!collapsed.has(id)) + '">' +
      '<button type="button" class="twisty" tabindex="-1" aria-label="Toggle group"></button>' +
      '<span class="tgroup-label">' + esc(label) + "</span>" +
      '<span class="tgroup-count">' + count + "</span>" +
      "</div>" +
      '<div class="tkids">' + inner + "</div>" +
      "</div>"
    );
  }

  function haystack(node) {
    var parts = [node.label, node.detail, node.type, labelOf(node.type)];
    (node.attrs || []).forEach(function (a) {
      parts.push(a[0], a[1]);
    });
    (node.events || []).forEach(function (e) {
      parts.push(e.id, e.action);
    });
    return parts.join(" ").toLowerCase();
  }

  function matchesQuery(node, terms) {
    var hay = node._hay;
    if (hay == null) {
      hay = haystack(node);
      node._hay = hay;
    }
    for (var i = 0; i < terms.length; i++) {
      if (hay.indexOf(terms[i]) < 0) return false;
    }
    return true;
  }

  function render(container, data, opts) {
    opts = opts || {};
    var nodes = (data && data.nodes) || [];
    var edges = (data && data.edges) || [];
    var byId = new Map();
    nodes.forEach(function (n) {
      byId.set(n.id, n);
    });
    var out = new Map();
    var inc = new Map();
    edges.forEach(function (e) {
      if (!out.has(e.from)) out.set(e.from, []);
      if (!inc.has(e.to)) inc.set(e.to, []);
      out.get(e.from).push(e);
      inc.get(e.to).push(e);
    });
    var owner = ownerMap(nodes, edges, byId);

    var hostByIp = {};
    nodes.forEach(function (n) {
      if (n.type !== "host") return;
      (n.attrs || []).forEach(function (a) {
        if (a[0] === "ip" && a[1]) hostByIp[a[1]] = n;
      });
    });

    var query = (opts.query || "").trim().toLowerCase();
    var terms = query ? query.split(/\s+/) : [];
    var hidden = opts.hiddenTypes || new Set();
    var selectedId = opts.selectedId || null;

    var matching = new Set();
    if (terms.length) {
      nodes.forEach(function (n) {
        if (n.type === "host" || hidden.has(n.type)) return;
        if (matchesQuery(n, terms)) matching.add(n.id);
      });
    }

    var visible = new Set();
    if (terms.length) {
      matching.forEach(function (id) {
        var n = byId.get(id);
        if (!n) return;
        var guard = 0;
        var cur = n;
        while (cur && guard++ < 12) {
          visible.add(cur.id);
          if (cur.type === "host") break;
          var incoming = inc.get(cur.id) || [];
          var parentEdge = incoming.find(function (e) {
            var src = byId.get(e.from);
            return src && src.type === "process" && e.rel === "spawned";
          });
          if (!parentEdge && cur.type !== "process") {
            parentEdge = incoming.find(function (e) {
              var src = byId.get(e.from);
              return src && src.type === "process";
            });
          }
          if (parentEdge) {
            cur = byId.get(parentEdge.from);
            continue;
          }
          if (cur.type === "process" && cur.id !== n.id) break;
          var hostId = owner.get(cur.id);
          if (hostId && hostId !== cur.id) {
            visible.add(hostId);
          }
          break;
        }
      });
      // Every visible entity keeps its host section open, including entities whose
      // process chain was cut short by the ancestor walk above.
      visible.forEach(function (id) {
        var h = owner.get(id);
        if (h) visible.add(h);
      });
    }

    var procChildren = new Map();
    edges.forEach(function (e) {
      if (e.rel !== "spawned" && e.rel !== "parent_of") return;
      var parent = byId.get(e.from);
      var child = byId.get(e.to);
      if (!parent || !child || parent.type !== "process" || child.type !== "process") return;
      if (!procChildren.has(parent.id)) procChildren.set(parent.id, []);
      procChildren.get(parent.id).push(child);
    });
    procChildren.forEach(function (list) {
      list.sort(function (a, b) {
        return (a.time || 0) - (b.time || 0) || a.label.localeCompare(b.label);
      });
    });

    var hostNodes = nodes.filter(function (n) {
      return n.type === "host";
    });
    hostNodes.sort(function (a, b) {
      return (a.label || "").localeCompare(b.label || "");
    });

    var used = new Set();
    var html = [];

    hostNodes.forEach(function (host, hi) {
      if (hidden.has("host")) return;
      if (terms.length && !visible.has(host.id)) return;
      var hostNodesAll = nodes.filter(function (n) {
        return n.type !== "host" && owner.get(n.id) === host.id && !hidden.has(n.type);
      });
      if (!hostNodesAll.length) return;

      var ctx = {
        owner: owner,
        byId: byId,
        host: host,
        out: out,
        inc: inc,
        procChildren: procChildren,
        used: used,
        hidden: hidden,
        hostByIp: hostByIp,
        visible: visible,
        query: terms.length > 0,
        hostNodesAll: hostNodesAll,
      };

      var alerts = hostNodesAll
        .filter(function (n) {
          return n.type === "alert" && (!terms.length || visible.has(n.id));
        })
        .sort(function (a, b) {
          return (b.sev || 0) - (a.sev || 0) || (a.time || 0) - (b.time || 0);
        });
      alerts.forEach(function (n) {
        used.add(n.id);
      });

      var processes = hostNodesAll.filter(function (n) {
        return n.type === "process" && (!terms.length || visible.has(n.id));
      });
      var renderable = new Set(processes.map(function (n) { return n.id; }));
      var roots = processes.filter(function (n) {
        var parents = inc.get(n.id) || [];
        return !parents.some(function (e) {
          return e.rel === "spawned" && e.from !== n.id && renderable.has(e.from);
        });
      });
      roots.sort(function (a, b) {
        return (a.time || 0) - (b.time || 0) || a.label.localeCompare(b.label);
      });
      var procHtml = [];
      roots.forEach(function (p) {
        if (used.has(p.id)) return;
        procHtml.push(build(p, { selectedId: selectedId, evidenceScope: !!opts.evidenceScope }, ctx));
      });
      processes.forEach(function (p) {
        if (used.has(p.id)) return;
        procHtml.push(build(p, { selectedId: selectedId, evidenceScope: !!opts.evidenceScope }, ctx));
      });

      var users = hostNodesAll.filter(function (n) {
        return n.type === "user" && (!terms.length || visible.has(n.id));
      });
      users.sort(function (a, b) {
        return a.label.localeCompare(b.label);
      });
      var userHtml = users.map(function (u) {
        used.add(u.id);
        return build(u, { selectedId: selectedId }, ctx);
      });

      var hostArts = [];
      (out.get(host.id) || []).forEach(function (e) {
        var art = byId.get(e.to);
        if (!art || !ARTIFACT[art.type] || hidden.has(art.type) || used.has(art.id)) return;
        if (terms.length && !visible.has(art.id)) return;
        used.add(art.id);
        hostArts.push(artifactRow(art, e.label, e.count, ctx));
      });
      hostArts.sort(function (a, b) {
        return a.sort - b.sort;
      });

      var leftovers = hostNodesAll.filter(function (n) {
        return !used.has(n.id) && !hidden.has(n.type) && (!terms.length || visible.has(n.id));
      });
      leftovers.sort(function (a, b) {
        return typeOrder(a.type) - typeOrder(b.type) || (a.time || 0) - (b.time || 0);
      });

      var body = [];
      if (alerts.length) {
        body.push(group("host:" + host.id + ":alerts", "Alerts", alerts.length,
          alerts.map(function (n) { return build(n, { selectedId: selectedId }, ctx); }).join("")));
      }
      if (procHtml.length) body.push(procHtml.join(""));
      if (userHtml.length) body.push(group("host:" + host.id + ":users", "Accounts", userHtml.length, userHtml.join("")));
      if (hostArts.length) {
        body.push(group("host:" + host.id + ":activity", "Host activity", hostArts.length,
          hostArts.map(function (a) { return a.html; }).join("")));
      }
      if (leftovers.length) {
        body.push(group("host:" + host.id + ":other", "Other entities", leftovers.length,
          leftovers.map(function (n) { return build(n, { selectedId: selectedId }, ctx); }).join("")));
      }

      host._hay = haystack(host);
      var hostRow =
        '<div class="tnode is-host" data-id="' + esc(host.id) + '" role="treeitem">' +
        '<div class="trow trow-host" tabindex="0" aria-expanded="' + String(!collapsed.has(host.id)) + '" title="' + esc(host.label) + '">' +
        '<button type="button" class="twisty" tabindex="-1" aria-label="Toggle host"></button>' +
        '<span class="tlabel">' + esc(host.label) + "</span>" +
        '<span class="tmeta">' + esc(metaFor(host, opts)) + "</span>" +
        "</div>" +
        '<div class="tkids">' + body.join("") + "</div>" +
        "</div>";
      html.push(hostRow);
    });

    // Nodes that never reached a host (rare: datasets without host fields).
    var orphans = nodes.filter(function (n) {
      return n.type !== "host" && !owner.get(n.id) && !hidden.has(n.type) && (!terms.length || visible.has(n.id));
    });
    if (orphans.length) {
      var list = orphans.filter(function (n) {
        return n.type === "process";
      });
      list.sort(function (a, b) { return (a.time || 0) - (b.time || 0); });
      var orphanHtml = list.map(function (p) {
        return build(p, { selectedId: selectedId }, {
          owner: owner, byId: byId, host: { id: "__none", label: "unassigned", eventCount: 0 },
          out: out, inc: inc, procChildren: procChildren, used: used, hidden: hidden,
          hostByIp: hostByIp, visible: visible, query: terms.length > 0,
        });
      }).join("");
      var rest = orphans.filter(function (n) { return n.type !== "process"; });
      if (rest.length) {
        orphanHtml += group("orphans:other", "Unassigned", rest.length,
          rest.map(function (n) { return build(n, { selectedId: selectedId }, {
            owner: owner, byId: byId, host: { id: "__none", label: "unassigned", eventCount: 0 },
            out: out, inc: inc, procChildren: procChildren, used: used, hidden: hidden,
            hostByIp: hostByIp, visible: visible, query: terms.length > 0,
          }); }).join(""));
      }
      html.push(
        '<div class="tnode is-host is-unassigned">' +
        '<div class="trow trow-host"><span class="twisty" aria-hidden="true"></span><span class="tlabel">unassigned</span><span class="tmeta">' + orphans.length + " entities</span></div>" +
        '<div class="tkids">' + orphanHtml + "</div></div>"
      );
    }

    var count = terms.length ? matching.size : nodes.length;
    var empty = terms.length
      ? '<p class="tree-empty">No entity matches “' + esc(query) + '”.</p>'
      : '<p class="tree-empty">No host or entity in this dataset.</p>';
    container.innerHTML = html.length ? html.join("") : empty;

    current = { container: container, byId: byId, opts: opts, onSelect: opts.onSelect };
    container.dataset.count = String(count);

    container.onclick = function (e) {
      var tw = e.target.closest(".twisty");
      if (tw) {
        var holder = tw.closest(".tnode, .tgroup");
        if (holder && tw.classList.contains("twisty")) {
          toggle(holder);
          e.stopPropagation();
        }
        return;
      }
      var gr = e.target.closest(".tgroup-row");
      if (gr) {
        toggle(gr.closest(".tgroup"));
        return;
      }
      var ref = e.target.closest("[data-ref]");
      if (ref) {
        select(ref.dataset.ref);
        return;
      }
      var row = e.target.closest(".trow");
      if (row && row.parentElement.dataset.id) select(row.parentElement.dataset.id);
    };
    container.onkeydown = function (e) {
      if (e.key !== "Enter" && e.key !== " ") return;
      var row = e.target.closest(".trow, .tgroup-row");
      if (!row) return;
      e.preventDefault();
      if (row.classList.contains("tgroup-row")) {
        toggle(row.closest(".tgroup"));
        return;
      }
      var holder = row.parentElement;
      if (holder.dataset.ref) select(holder.dataset.ref);
      else if (holder.dataset.id) select(holder.dataset.id);
    };
  }

  function toggle(holder) {
    if (!holder) return;
    var isCollapsed = holder.classList.toggle("is-collapsed");
    var head = holder.querySelector(":scope > .trow, :scope > .tgroup-row");
    if (head && head.hasAttribute("aria-expanded")) head.setAttribute("aria-expanded", String(!isCollapsed));
    if (holder.dataset.id) {
      if (isCollapsed) collapsed.add(holder.dataset.id);
      else collapsed.delete(holder.dataset.id);
    }
    if (holder.dataset.group) {
      if (isCollapsed) collapsed.add(holder.dataset.group);
      else collapsed.delete(holder.dataset.group);
    }
  }

  function select(id) {
    if (!current) return;
    var old = current.container.querySelector(".trow.is-selected");
    if (old) old.classList.remove("is-selected");
    var node = current.container.querySelector('.tnode[data-id="' + cssEscape(id) + '"] > .trow');
    if (node) {
      node.classList.add("is-selected");
      reveal(id);
    }
    if (current.onSelect) current.onSelect(id);
  }

  function cssEscape(s) {
    if (window.CSS && window.CSS.escape) return window.CSS.escape(s);
    return String(s).replace(/["\\]/g, "\\$&");
  }

  function reveal(id) {
    if (!current) return false;
    var node = current.container.querySelector('.tnode[data-id="' + cssEscape(id) + '"]');
    if (!node) return false;
    var p = node.parentElement;
    while (p && p !== current.container) {
      if (p.classList.contains("is-collapsed")) {
        p.classList.remove("is-collapsed");
        var head = p.querySelector(":scope > .trow, :scope > .tgroup-row");
        if (head && head.hasAttribute("aria-expanded")) head.setAttribute("aria-expanded", "true");
        if (p.dataset.id) collapsed.delete(p.dataset.id);
      }
      p = p.parentElement;
    }
    node.scrollIntoView({ block: "center" });
    return true;
  }

  function collapseAll() {
    if (!current) return;
    Array.prototype.forEach.call(current.container.querySelectorAll(".tnode, .tgroup"), function (n) {
      if (!n.querySelector(".tkids")) return;
      n.classList.add("is-collapsed");
      if (n.dataset.id) collapsed.add(n.dataset.id);
      if (n.dataset.group) collapsed.add(n.dataset.group);
      var head = n.querySelector(":scope > .trow, :scope > .tgroup-row");
      if (head && head.hasAttribute("aria-expanded")) head.setAttribute("aria-expanded", "false");
    });
  }

  function reset() {
    collapsed.clear();
    current = null;
  }

  function selectOnly(container, id) {
    var old = container.querySelector(".trow.is-selected");
    if (old) old.classList.remove("is-selected");
    var row = container.querySelector('.tnode[data-id="' + cssEscape(id) + '"] > .trow');
    if (row) row.classList.add("is-selected");
  }

  window.A1Tree = {
    render: render,
    select: select,
    selectOnly: selectOnly,
    reveal: reveal,
    collapseAll: collapseAll,
    reset: reset,
  };
})();
