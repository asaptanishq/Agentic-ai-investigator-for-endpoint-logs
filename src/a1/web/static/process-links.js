/* Process link board: one lane per host, spawn chains plus process-access links. */
(function () {
  "use strict";

  var NODE_W = 150;
  var NODE_H = 30;
  var COL_W = 218;
  var ROW_H = 40;
  var PAD = 12;

  var root = null;
  var options = null;
  var bound = false;

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function clip(value, size) {
    value = String(value || "");
    return value.length > size ? value.slice(0, size - 1) + "\u2026" : value;
  }

  function attr(node, key) {
    for (var i = 0; i < (node.attrs || []).length; i++) {
      if (node.attrs[i][0] === key) return node.attrs[i][1];
    }
    return "";
  }

  function haystack(node) {
    var bits = [node.label, node.detail, node.type];
    (node.attrs || []).forEach(function (pair) {
      bits.push(pair[0] + " " + pair[1]);
    });
    (node.events || []).forEach(function (event) {
      bits.push(event.id + " " + event.action);
    });
    return bits.join(" ").toLowerCase();
  }

  function matches(node, query) {
    if (!query.length) return true;
    var hay = node._plHay || (node._plHay = haystack(node));
    return query.every(function (term) {
      return hay.indexOf(term) !== -1;
    });
  }

  function layout(graph) {
    var byId = new Map();
    var procs = [];
    graph.nodes.forEach(function (node) {
      byId.set(node.id, node);
      if (node.type === "process") procs.push(node);
    });

    var hostOf = new Map();
    var spawns = [];
    var accesses = [];
    graph.edges.forEach(function (edge) {
      var from = byId.get(edge.from);
      var to = byId.get(edge.to);
      if (!from || !to) return;
      if (edge.rel === "observed_on" && from.type === "process" && to.type === "host") {
        hostOf.set(from.id, to.id);
      }
      if (edge.rel === "spawned" && from.type === "process" && to.type === "process") {
        spawns.push(edge);
      }
      if (edge.rel === "accessed" && from.type === "process" && to.type === "process") {
        accesses.push(edge);
      }
    });

    // One layout parent per process keeps the board a forest. Extra parent edges are
    // still drawn if both ends land in the same host lane.
    var parent = new Map();
    spawns
      .slice()
      .sort(function (a, b) {
        return (b.count || 0) - (a.count || 0);
      })
      .forEach(function (edge) {
        if (parent.has(edge.to)) return;
        if (hostOf.get(edge.from) !== hostOf.get(edge.to)) return;
        parent.set(edge.to, edge.from);
      });

    // An accessed process with no spawn parent is placed as a child of its accessor.
    // The edge stays dashed so it is never mistaken for a spawn.
    accesses.forEach(function (edge) {
      if (parent.has(edge.to)) return;
      if (hostOf.get(edge.from) !== hostOf.get(edge.to)) return;
      parent.set(edge.to, edge.from);
    });

    // Break aggregate cycles such as a.exe -> b.exe -> a.exe.
    procs.forEach(function (node) {
      var seen = new Set();
      var cursor = node.id;
      while (cursor && parent.has(cursor)) {
        if (seen.has(cursor)) {
          parent.delete(cursor);
          break;
        }
        seen.add(cursor);
        cursor = parent.get(cursor);
      }
    });

    var kids = new Map();
    parent.forEach(function (par, child) {
      if (!kids.has(par)) kids.set(par, []);
      kids.get(par).push(child);
    });
    kids.forEach(function (list) {
      list.sort(function (a, b) {
        return String(byId.get(a).label).localeCompare(String(byId.get(b).label));
      });
    });

    var groups = new Map();
    procs.forEach(function (node) {
      var hostId = hostOf.get(node.id) || "host:unknown";
      if (!groups.has(hostId)) {
        groups.set(hostId, {
          id: hostId,
          host: byId.get(hostId) || null,
          procs: [],
          pos: new Map(),
          roots: [],
        });
      }
      groups.get(hostId).procs.push(node);
    });

    groups.forEach(function (group) {
      group.procs.sort(function (a, b) {
        return String(a.label).localeCompare(String(b.label));
      });
      var nextRow = 0;

      function place(id, depth, stack) {
        var children = (kids.get(id) || []).filter(function (child) {
          return !stack.has(child);
        });
        var ys = children.map(function (child) {
          var next = new Set(stack);
          next.add(id);
          return place(child, depth + 1, next);
        });
        var y = ys.length
          ? (Math.min.apply(null, ys) + Math.max.apply(null, ys)) / 2
          : nextRow++ * ROW_H;
        group.pos.set(id, { x: PAD + depth * COL_W, y: Math.round(y), depth: depth });
        return y;
      }

      group.roots = group.procs.filter(function (node) {
        return !parent.has(node.id);
      });
      group.roots.forEach(function (node) {
        place(node.id, 0, new Set());
      });
      group.procs.forEach(function (node) {
        if (!group.pos.has(node.id)) place(node.id, 0, new Set());
      });

      group.depth = 0;
      group.pos.forEach(function (pos) {
        if (pos.depth > group.depth) group.depth = pos.depth;
      });
      group.width = PAD * 2 + group.depth * COL_W + NODE_W;
      group.height = nextRow * ROW_H + PAD * 2;
    });

    return { byId: byId, groups: groups, spawns: spawns, accesses: accesses, parent: parent, kids: kids };
  }

  function alertCounts(graph) {
    var all = new Map();
    graph.nodes.forEach(function (node) {
      all.set(node.id, node);
    });
    var counts = new Map();
    graph.edges.forEach(function (edge) {
      if (edge.rel !== "associated_with") return;
      var from = all.get(edge.from);
      var to = all.get(edge.to);
      if (from && from.type === "alert" && to && to.type === "process") {
        counts.set(to.id, (counts.get(to.id) || 0) + 1);
      }
    });
    return counts;
  }

  function render(target, graph, opts) {
    root = target;
    options = opts || {};
    var query = String(options.query || "")
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean);
    var data = layout(graph || { nodes: [], edges: [] });
    var alerts = alertCounts(graph || { nodes: [], edges: [] });
    var selectedId = options.selectedId || "";

    if (!data.groups.size) {
      root.innerHTML = '<p class="pl-empty">No process links in this scope.</p>';
      root.dataset.count = "0";
      root.dataset.summary = "0 processes";
      return;
    }

    var laneList = Array.from(data.groups.values()).filter(function (group) {
      if (!query.length) return true;
      var hits = group.procs.filter(function (node) {
        return matches(node, query);
      }).length;
      group.matchCount = hits;
      return hits > 0;
    });
    laneList.sort(function (a, b) {
      var an = a.host ? a.host.label : "~";
      var bn = b.host ? b.host.label : "~";
      return String(an).localeCompare(String(bn));
    });

    if (!laneList.length) {
      root.innerHTML = '<p class="pl-empty">No process matches this filter.</p>';
      root.dataset.count = "0";
      root.dataset.summary = "0 matching processes";
      return;
    }

    var boardWidth = 0;
    laneList.forEach(function (group) {
      if (group.width > boardWidth) boardWidth = group.width;
    });
    boardWidth = Math.max(boardWidth, root.clientWidth || 0);

    var shownProcs = 0;
    var shownLinks = 0;
    var riskCounts = { malicious: 0, suspicious: 0 };
    var markup = ['<div class="pl-board" style="--pl-w:' + boardWidth + 'px">'];

    laneList.forEach(function (group, laneIndex) {
      var hostLabel = group.host ? group.host.label : "unassigned";
      var hostIp = group.host ? attr(group.host, "ip") : "";
      var laneEdges = [];
      var pos = group.pos;
      var matchSet = new Set();
      group.procs.forEach(function (node) {
        if (matches(node, query)) matchSet.add(node.id);
      });

      // Keep the matched process in context: its parent chain and direct children.
      var visible = new Set(matchSet);
      if (query.length) {
        matchSet.forEach(function (id) {
          var cursor = data.parent.get(id);
          var guard = 0;
          while (cursor && guard++ < 64) {
            visible.add(cursor);
            cursor = data.parent.get(cursor);
          }
          (data.kids.get(id) || []).forEach(function (child) {
            visible.add(child);
          });
        });
      } else {
        group.procs.forEach(function (node) {
          visible.add(node.id);
        });
      }
      group.visible = visible;
      group.matchCount = matchSet.size;

      data.spawns.concat(data.accesses).forEach(function (edge) {
        if (pos.has(edge.from) && pos.has(edge.to) && visible.has(edge.from) && visible.has(edge.to)) {
          laneEdges.push(edge);
        }
      });
      shownProcs += visible.size;
      shownLinks += laneEdges.length;

      markup.push('<section class="pl-lane" data-host="' + esc(group.id) + '">');
      markup.push(
        '<header class="pl-head"><span class="pl-hdot"></span><span class="pl-host">' +
          esc(hostLabel) +
          "</span>" +
          (hostIp ? '<span class="pl-hip">' + esc(hostIp) + "</span>" : "") +
          '<span class="pl-hmeta">' +
          (query.length ? visible.size + " of " + group.procs.length : String(group.procs.length)) +
          " processes \u00b7 " +
          laneEdges.length +
          " links</span></header>"
      );
      markup.push('<div class="pl-canvas" style="height:' + group.height + 'px">');

      var marker = "pl-arrow-" + laneIndex;
      var accessMarker = "pl-access-" + laneIndex;
      markup.push(
        '<svg class="pl-edges" width="100%" height="' +
          group.height +
          '" aria-hidden="true"><defs><marker id="' +
          marker +
          '" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" fill="#3b444c"/></marker>' +
          '<marker id="' + accessMarker + '" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" fill="#e06a5c"/></marker></defs>'
      );
      laneEdges.forEach(function (edge) {
        var from = pos.get(edge.from);
        var to = pos.get(edge.to);
        if (!from || !to) return;
        var x1 = from.x + NODE_W;
        var y1 = from.y + NODE_H / 2;
        var x2 = to.x;
        var y2 = to.y + NODE_H / 2;
        var mid = Math.max(30, (x2 - x1) / 2);
        var isAccess = edge.rel === "accessed";
        markup.push(
          '<path class="pl-edge' + (isAccess ? " is-access" : "") + '" data-from="' +
            esc(edge.from) +
            '" data-to="' +
            esc(edge.to) +
            '" data-rel="' +
            esc(edge.rel) +
            '" marker-end="url(#' +
            (isAccess ? accessMarker : marker) +
            ')" d="M' +
            x1 +
            "," +
            y1 +
            " C" +
            (x1 + mid) +
            "," +
            y1 +
            " " +
            (x2 - mid) +
            "," +
            y2 +
            " " +
            x2 +
            "," +
            y2 +
            '"/>'
        );
      });
      markup.push("</svg>");

      group.procs.forEach(function (node) {
        if (!visible.has(node.id)) return;
        var at = pos.get(node.id);
        var count = alerts.get(node.id) || 0;
        var riskText = node.risk ? node.risk.level + ": " + node.risk.reasons.join("; ") : "";
        var title = node.label + (node.detail ? " \u00b7 " + node.detail : "") + (riskText ? " \u00b7 " + riskText : "");
        if (node.risk) {
          if (node.risk.level === "malicious") riskCounts.malicious++;
          else riskCounts.suspicious++;
        }
        markup.push(
          '<button type="button" class="pl-node' +
            (node.id === selectedId ? " is-selected" : "") +
            (query.length && !matchSet.has(node.id) ? " is-context" : "") +
            (node.risk ? " is-" + node.risk.level : "") +
            '" data-node="' +
            esc(node.id) +
            '" style="left:' +
            at.x +
            "px;top:" +
            at.y +
            'px" title="' +
            esc(title) +
            '">' +
            '<span class="pl-pdot"></span><span class="pl-plabel">' +
            esc(clip(node.label, 18)) +
            "</span>" +
            (count ? '<span class="pl-alert" title="' + count + ' alerts"></span>' : "") +
            (node.risk ? '<span class="pl-risk ' + node.risk.level + '" title="' + esc(riskText) + '">!</span>' : "") +
            (node.eventCount ? '<span class="pl-pcount">' + node.eventCount + "</span>" : "") +
            "</button>"
        );
      });
      markup.push("</div></section>");
    });
    markup.push("</div>");
    markup.unshift(
      '<div class="pl-key">' +
        '<span><i class="pk-line"></i>spawned</span>' +
        '<span><i class="pk-line access"></i>process access</span>' +
        '<span><i class="pk-dot malicious"></i>malicious</span>' +
        '<span><i class="pk-dot suspicious"></i>suspicious</span>' +
      "</div>"
    );

    root.innerHTML = markup.join("");
    root.dataset.count = String(laneList.reduce(function (sum, group) {
      return sum + group.procs.filter(function (node) {
        return matches(node, query);
      }).length;
    }, 0));
    var riskBits = [];
    if (riskCounts.malicious) riskBits.push(riskCounts.malicious + " malicious");
    if (riskCounts.suspicious) riskBits.push(riskCounts.suspicious + " suspicious");
    root.dataset.summary = shownProcs + " processes \u00b7 " + shownLinks + " links" +
      (riskBits.length ? " \u00b7 " + riskBits.join(" \u00b7 ") : "");

    if (!bound) {
      bound = true;
      root.addEventListener("click", function (event) {
        var node = event.target.closest(".pl-node");
        if (!node || !root.contains(node)) return;
        if (options && options.onSelect) options.onSelect(node.dataset.node);
      });
    }

    if (selectedId) select(selectedId);
  }

  function select(id) {
    if (!root) return;
    var nodes = root.querySelectorAll(".pl-node");
    for (var i = 0; i < nodes.length; i++) {
      nodes[i].classList.toggle("is-selected", nodes[i].dataset.node === id);
    }
    var paths = root.querySelectorAll(".pl-edge");
    for (var j = 0; j < paths.length; j++) {
      paths[j].classList.toggle(
        "is-linked",
        !!id && (paths[j].dataset.from === id || paths[j].dataset.to === id)
      );
    }
  }

  window.A1Links = {
    render: render,
    select: select,
  };
})();
