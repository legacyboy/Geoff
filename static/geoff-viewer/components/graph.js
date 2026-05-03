(function() {
// Relationship graph — columnar layout (Accounts | Workstations | Servers | Mobile | Network | Services | Evidence)
// with edges for ownership, presence, lateral-movement, evidence sources, and exfiltration.

const {
  useEffect,
  useMemo,
  useRef,
  useState
} = React;

// Column layout constants — one source of truth so render and layout stay in sync.
const HEADER_Y = 70;
const FOOTER_Y = 40;
const MIN_ROW_H = 64;
const NODE_H = 44;
const USER_R = 26;
function classifyDevice(d) {
  const t = (d.device_type || "").toLowerCase();
  if (t.includes("server")) return "server";
  if (t.includes("mobile") || t.includes("ios") || t.includes("android")) return "mobile";
  if (t.includes("network") || t.includes("pcap")) return "network";
  return "pc"; // windows_pc, linux_pc, macos_workstation
}
function countFlags(flags) {
  const out = {
    total: 0,
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };
  for (const f of flags || []) {
    out.total++;
    if (out[f.severity] != null) out[f.severity]++;
  }
  return out;
}
function maxSev(counts) {
  if (counts.CRITICAL) return "CRITICAL";
  if (counts.HIGH) return "HIGH";
  if (counts.MEDIUM) return "MEDIUM";
  if (counts.LOW) return "LOW";
  return null;
}
function formatEvidenceType(t) {
  if (!t) return "Evidence";
  return t.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}
function guessEvidenceTypeFromPath(p) {
  const fname = (p || "").split("/").pop().toLowerCase();
  const ext = fname.includes(".") ? fname.split(".").pop() : "";
  if (["e01", "ex01", "aff", "aff4", "dd", "img", "raw", "vmdk", "vhdx"].includes(ext)) return "disk_images";
  if (ext === "evtx") return "evtx_logs";
  if (["mem", "lime", "vmem", "dmp"].includes(ext)) return "memory_dumps";
  if (["pcap", "pcapng"].includes(ext)) return "pcaps";
  if (ext === "log" || fname.endsWith("syslog") || fname.endsWith("auth.log")) return "syslogs";
  if (ext === "plist") return "plists";
  if (ext === "db" || ext === "sqlite" || fname === "manifest.db") return "databases";
  if (["dat", "reg", "hive"].includes(ext)) return "registry_hives";
  if (fname === "ntuser.dat" || fname === "system" || fname === "software" || fname === "security" || fname === "sam") return "registry_hives";
  if (ext === "ab") return "mobile_backups";
  return null;
}
function classifyExfilService(host) {
  const h = (host || "").toLowerCase();
  if (h.includes("mega.")) return "Mega.nz";
  if (h.includes("gmail") || h.includes("google")) return "Google";
  if (h.includes("onedrive") || h.includes("microsoft")) return "OneDrive";
  if (h.includes("dropbox")) return "Dropbox";
  if (h.includes("aol")) return "AOL";
  if (h.includes("yahoo")) return "Yahoo";
  if (h.includes("protonmail")) return "ProtonMail";
  if (h.includes("sharepoint")) return "SharePoint";
  if (h.includes("icloud")) return "iCloud";
  return null; // unknown — caller decides whether to bucket as "External"
}
function RelationshipGraph({
  report,
  selected,
  onSelect,
  hoverId,
  onHover,
  sevFilter
}) {
  const wrapRef = useRef(null);
  const [size, setSize] = useState({
    w: 900,
    h: 600
  });
  useEffect(() => {
    if (!wrapRef.current) return;
    const ro = new ResizeObserver(([e]) => {
      const r = e.contentRect;
      setSize({
        w: Math.max(600, r.width),
        h: Math.max(400, r.height)
      });
    });
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, []);
  const graph = useMemo(() => buildGraph(report, size), [report, size]);

  // relations set for highlight
  const neighbors = useMemo(() => {
    if (!selected) return null;
    const set = new Set([selected]);
    for (const e of graph.edges) {
      if (e.from === selected) set.add(e.to);
      if (e.to === selected) set.add(e.from);
    }
    return set;
  }, [selected, graph]);

  // Set of node ids that carry (or transitively touch) a flag of the filtered severity.
  const sevMatch = useMemo(() => {
    if (!sevFilter) return null;
    const set = new Set();
    const flagsByDev = report.behavioral_flags || {};
    Object.entries(flagsByDev).forEach(([devId, flags]) => {
      if ((flags || []).some(f => f.severity === sevFilter)) set.add("d:" + devId);
    });
    Object.entries(report.user_map || {}).forEach(([uname, u]) => {
      if ((u.devices || []).some(d => set.has("d:" + d))) set.add("u:" + uname);
    });
    return set;
  }, [sevFilter, report]);
  return /*#__PURE__*/React.createElement("div", {
    ref: wrapRef,
    className: "graph-stage"
  }, /*#__PURE__*/React.createElement("svg", {
    className: "graph-svg",
    width: "100%",
    height: graph.totalH,
    viewBox: `0 0 ${size.w} ${graph.totalH}`,
    preserveAspectRatio: "xMidYMin meet"
  }, graph.columns.map(col => /*#__PURE__*/React.createElement("g", {
    key: col.key
  }, /*#__PURE__*/React.createElement("text", {
    className: "col-header",
    x: col.x,
    y: 28,
    textAnchor: "middle"
  }, col.label.toUpperCase(), " \xB7 ", col.count), /*#__PURE__*/React.createElement("line", {
    className: "col-rule",
    x1: col.x,
    y1: 44,
    x2: col.x,
    y2: graph.totalH - 16
  }))), /*#__PURE__*/React.createElement("g", null, graph.edges.map((e, i) => {
    const n1 = graph.nodeById[e.from];
    const n2 = graph.nodeById[e.to];
    if (!n1 || !n2) return null;
    const d = edgePath(n1, n2);
    const hl = neighbors && neighbors.has(e.from) && neighbors.has(e.to);
    const dim = neighbors && !hl;
    let cls = "edge";
    if (e.kind === "owns") cls += " owns";else if (e.kind === "seen_on") cls += " seen-on";else if (e.kind === "lateral") cls += " lateral";else if (e.kind === "exfiltrated_to") cls += " exfil";else if (e.kind === "evidence_source") cls += " evidence-link";
    if (hl) cls += " highlighted";
    if (dim) cls += " dimmed";
    return /*#__PURE__*/React.createElement("path", {
      key: i,
      className: cls,
      d: d
    }, /*#__PURE__*/React.createElement("title", null, describeEdge(e, n1, n2)));
  })), /*#__PURE__*/React.createElement("g", null, graph.nodes.map(n => {
    const isSel = selected === n.id;
    const isHover = hoverId === n.id;
    const inNeighborhood = neighbors && neighbors.has(n.id);
    const sevDim = sevMatch && (n.kind === "user" || n.kind === "pc" || n.kind === "server" || n.kind === "mobile" || n.kind === "network") && !sevMatch.has(n.id);
    const dim = neighbors && !inNeighborhood || sevDim;
    let cls = "node node-" + n.kind;
    if (isSel || isHover) cls += " highlighted";
    if (dim) cls += " dimmed";
    return /*#__PURE__*/React.createElement("g", {
      key: n.id,
      className: cls,
      transform: `translate(${n.x}, ${n.y})`,
      onClick: () => onSelect(n.id),
      onMouseEnter: () => onHover(n.id),
      onMouseLeave: () => onHover(null),
      style: {
        color: n.accent
      }
    }, /*#__PURE__*/React.createElement("title", null, describeNode(n, report)), n.kind === "user" ? /*#__PURE__*/React.createElement("circle", {
      cx: 0,
      cy: 0,
      r: n.r,
      fill: "rgba(16,185,129,0.08)",
      stroke: n.accent,
      strokeWidth: isSel ? 2 : 1
    }) : n.kind === "evidence" ? /*#__PURE__*/React.createElement("rect", {
      x: -n.w / 2,
      y: -n.h / 2,
      width: n.w,
      height: n.h,
      rx: 4,
      fill: "rgba(6,182,212,0.15)",
      stroke: n.accent,
      strokeWidth: isSel ? 2 : 1,
      strokeDasharray: "4 2"
    }) : n.kind === "service" ? /*#__PURE__*/React.createElement("rect", {
      x: -n.w / 2,
      y: -n.h / 2,
      width: n.w,
      height: n.h,
      rx: 20,
      fill: "rgba(236,72,153,0.15)",
      stroke: n.accent,
      strokeWidth: isSel ? 2 : 1
    }) : /*#__PURE__*/React.createElement("rect", {
      x: -n.w / 2,
      y: -n.h / 2,
      width: n.w,
      height: n.h,
      rx: 6,
      fill: "rgba(30,41,59,0.9)",
      stroke: n.accent,
      strokeWidth: isSel ? 2 : 1
    }), /*#__PURE__*/React.createElement("text", {
      x: 0,
      y: n.kind === "user" ? 4 : -3,
      textAnchor: "middle"
    }, n.label || ""), n.sublabel && /*#__PURE__*/React.createElement("text", {
      x: 0,
      y: n.kind === "user" ? 18 : 12,
      textAnchor: "middle",
      className: "sublabel"
    }, n.sublabel), n.badge && /*#__PURE__*/React.createElement("g", {
      transform: `translate(${n.kind === "user" ? n.r - 4 : n.w / 2 - 6}, ${n.kind === "user" ? -n.r + 4 : -n.h / 2 + 6})`
    }, /*#__PURE__*/React.createElement("circle", {
      r: 8,
      className: `flag-badge ${n.badge.sev === "CRITICAL" ? "crit" : n.badge.sev === "HIGH" ? "high" : ""}`
    }), /*#__PURE__*/React.createElement("text", {
      className: "flag-badge-text"
    }, n.badge.count)));
  }))));
}
function edgePath(a, b) {
  // Curved connector between two nodes (horizontal S)
  const [from, to] = a.x < b.x ? [a, b] : [b, a];
  const sx = from.x + (from.kind === "user" ? from.r : from.w / 2);
  const ex = to.x - (to.kind === "user" ? to.r : to.w / 2);
  const sy = from.y,
    ey = to.y;
  const mx = (sx + ex) / 2;
  return `M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ey}, ${ex} ${ey}`;
}
function buildGraph(report, size) {
  const userMap = report.user_map || {};
  const deviceMap = report.device_map || {};
  const flagsByDevice = report.behavioral_flags || {};
  const users = Object.entries(userMap).map(([k, u]) => ({
    id: "u:" + k,
    kind: "user",
    raw: u || {},
    key: k
  }));
  const devs = Object.entries(deviceMap).map(([k, d]) => ({
    id: "d:" + k,
    kind: classifyDevice(d || {}),
    raw: d || {},
    key: k
  }));

  // Aggregate exfiltration services (one node per known service brand)
  const exfilServices = new Map();
  Object.entries(flagsByDevice).forEach(([devId, flags]) => {
    (flags || []).forEach(flag => {
      if (flag.flag_type !== "exfiltration" && flag.flag_type !== "c2_traffic") return;
      const evidence = flag.evidence || {};
      const dstHost = evidence.dst_host || evidence.dst_ip || "";
      if (!dstHost) return;
      const serviceType = classifyExfilService(dstHost) || "External";
      if (!exfilServices.has(serviceType)) {
        exfilServices.set(serviceType, {
          id: "s:" + serviceType,
          kind: "service",
          name: serviceType,
          hosts: []
        });
      }
      exfilServices.get(serviceType).hosts.push({
        host: dstHost,
        devId,
        flag
      });
    });
  });

  // Aggregate evidence by TYPE (one bucket per evidence_type — not per file).
  // This keeps the graph readable when devices have lots of evidence.
  const evidenceBuckets = new Map(); // type -> { type, devIds:Set, files:[{path,devId}] }
  const getBucket = t => {
    if (!evidenceBuckets.has(t)) {
      evidenceBuckets.set(t, {
        type: t,
        devIds: new Set(),
        files: []
      });
    }
    return evidenceBuckets.get(t);
  };
  Object.entries(deviceMap).forEach(([devId, dev]) => {
    const declared = dev && dev.evidence_types || [];
    const files = dev && dev.evidence_files || [];
    // Ensure each declared type has an edge to the device, even if no files match it
    declared.forEach(t => {
      getBucket(t).devIds.add(devId);
    });
    // Bucket each file by guessed type (fall back to first declared, then "other")
    files.forEach(fp => {
      const guessed = guessEvidenceTypeFromPath(fp);
      const t = guessed || declared[0] || "other";
      const b = getBucket(t);
      b.devIds.add(devId);
      b.files.push({
        path: fp,
        devId
      });
    });
  });
  const evidenceItems = Array.from(evidenceBuckets.values()).map(b => ({
    id: "e:" + b.type,
    kind: "evidence",
    type: b.type,
    devIds: Array.from(b.devIds),
    files: b.files
  }));
  const columns = [{
    key: "user",
    label: "Accounts",
    items: users
  }, {
    key: "pc",
    label: "Workstations",
    items: devs.filter(d => d.kind === "pc")
  }, {
    key: "server",
    label: "Servers",
    items: devs.filter(d => d.kind === "server")
  }, {
    key: "mobile",
    label: "Mobile",
    items: devs.filter(d => d.kind === "mobile")
  }, {
    key: "network",
    label: "Network",
    items: devs.filter(d => d.kind === "network")
  }, {
    key: "service",
    label: "Services",
    items: Array.from(exfilServices.values())
  }, {
    key: "evidence",
    label: "Evidence",
    items: evidenceItems
  }].filter(c => c.items.length > 0).map(c => ({
    ...c,
    count: c.items.length
  }));

  // Layout sizing — let the graph grow taller when a column has many items, so
  // the surrounding container scrolls instead of nodes being squashed on top of each other.
  const maxItems = Math.max(1, ...columns.map(c => c.items.length));
  const computedH = HEADER_Y + FOOTER_Y + maxItems * MIN_ROW_H;
  const totalH = Math.max(size.h, computedH);
  const colCount = columns.length;
  const padX = 32;
  const innerW = size.w - padX * 2;
  const colGap = innerW / colCount;
  // Node width adapts so columns don't visually overlap when there are 6–7 of them.
  const nodeW = Math.max(96, Math.min(150, colGap * 0.84));
  const labelChars = Math.max(10, Math.floor(nodeW / 8));
  const accentMap = {
    user: "#10B981",
    pc: "#3B82F6",
    server: "#A78BFA",
    mobile: "#F59E0B",
    network: "#64748B",
    service: "#EC4899",
    evidence: "#06B6D4"
  };
  const nodeById = {};
  const nodes = [];
  columns.forEach((col, ci) => {
    col.x = padX + colGap * ci + colGap / 2;
    const topY = HEADER_Y;
    const bottomY = totalH - FOOTER_Y;
    const gapY = (bottomY - topY) / Math.max(col.items.length, 1);
    col.items.forEach((item, ri) => {
      const y = topY + gapY * ri + gapY / 2;
      let label = "",
        sublabel = "",
        badge = null;
      const kind = item.kind;
      if (kind === "user") {
        const flags = aggregateUserFlags(report, item.key);
        const sev = maxSev(flags);
        label = item.raw && (item.raw.display_name || item.raw.username) || item.key;
        sublabel = item.raw && item.raw.role || "user";
        badge = flags.total > 0 ? {
          count: flags.total,
          sev
        } : null;
      } else if (kind === "evidence") {
        const fileCount = (item.files || []).length;
        const devCount = (item.devIds || []).length;
        label = formatEvidenceType(item.type);
        sublabel = `${fileCount} file${fileCount === 1 ? "" : "s"} · ${devCount} dev${devCount === 1 ? "" : "s"}`;
        badge = fileCount > 0 ? {
          count: fileCount,
          sev: null
        } : null;
      } else if (kind === "service") {
        label = item.name;
        sublabel = `${item.hosts.length} connection${item.hosts.length === 1 ? "" : "s"}`;
        badge = {
          count: item.hosts.length,
          sev: "HIGH"
        };
      } else {
        // device kinds: pc, server, mobile, network
        const flags = countFlags(flagsByDevice[item.key] || []);
        const sev = maxSev(flags);
        label = item.raw && item.raw.hostname || item.key;
        sublabel = osLabel(item.raw || {});
        badge = flags.total > 0 ? {
          count: flags.total,
          sev
        } : null;
      }
      const node = {
        id: item.id,
        kind,
        key: item.key || item.type || item.name,
        label: truncate(label, labelChars + 4),
        sublabel: truncate(sublabel, labelChars + 8),
        x: col.x,
        y,
        r: USER_R,
        w: nodeW,
        h: NODE_H,
        accent: accentMap[kind] || "#64748B",
        badge,
        raw: item.raw || item
      };
      nodes.push(node);
      nodeById[node.id] = node;
    });
  });

  // Build edges
  const edges = [];
  const seenEdge = new Set();
  const addEdge = e => {
    const k = `${e.from}|${e.to}|${e.kind}`;
    if (seenEdge.has(k)) return;
    seenEdge.add(k);
    edges.push(e);
  };

  // User <-> Device: distinguish ownership from presence.
  // Source 1: user_map[*].devices
  for (const [uname, u] of Object.entries(userMap)) {
    for (const devId of u && u.devices || []) {
      if (!nodeById["u:" + uname] || !nodeById["d:" + devId]) continue;
      const dev = deviceMap[devId] || {};
      const isOwner = dev.owner === uname;
      addEdge({
        from: "u:" + uname,
        to: "d:" + devId,
        kind: isOwner ? "owns" : "seen_on"
      });
    }
  }
  // Source 2: device_map[*].metadata.user_profiles_found — catches users who
  // appear on a device but aren't listed in their own user_map.devices entry.
  for (const [devId, dev] of Object.entries(deviceMap)) {
    const profiles = dev && dev.metadata && dev.metadata.user_profiles_found || [];
    for (const uname of profiles) {
      if (!nodeById["u:" + uname] || !nodeById["d:" + devId]) continue;
      const isOwner = dev.owner === uname;
      addEdge({
        from: "u:" + uname,
        to: "d:" + devId,
        kind: isOwner ? "owns" : "seen_on"
      });
    }
  }
  // Source 3: also accept the device's declared owner, even if user_map.devices missed it.
  for (const [devId, dev] of Object.entries(deviceMap)) {
    const owner = dev && dev.owner;
    if (owner && nodeById["u:" + owner] && nodeById["d:" + devId]) {
      addEdge({
        from: "u:" + owner,
        to: "d:" + devId,
        kind: "owns"
      });
    }
  }

  // Lateral movement: device <-> device
  for (const [uname, cu] of Object.entries(report.correlated_users || {})) {
    for (const ind of cu && cu.lateral_movement_indicators || []) {
      const a = "d:" + ind.from_device;
      const b = "d:" + ind.to_device;
      if (nodeById[a] && nodeById[b]) {
        addEdge({
          from: a,
          to: b,
          kind: "lateral",
          via: uname,
          method: ind.method
        });
      }
    }
  }

  // Exfiltration: device -> service
  Object.entries(flagsByDevice).forEach(([devId, flags]) => {
    (flags || []).forEach(flag => {
      if (flag.flag_type !== "exfiltration" && flag.flag_type !== "c2_traffic") return;
      const evidence = flag.evidence || {};
      const dstHost = evidence.dst_host || evidence.dst_ip || "";
      if (!dstHost) return;
      const serviceType = classifyExfilService(dstHost) || "External";
      const serviceNodeId = "s:" + serviceType;
      if (nodeById["d:" + devId] && nodeById[serviceNodeId]) {
        addEdge({
          from: "d:" + devId,
          to: serviceNodeId,
          kind: "exfiltrated_to",
          host: dstHost,
          bytes: evidence.bytes_sent,
          flag: flag.summary
        });
      }
    });
  });

  // Evidence: device -> type bucket
  evidenceBuckets.forEach((b, t) => {
    const eId = "e:" + t;
    if (!nodeById[eId]) return;
    b.devIds.forEach(devId => {
      if (nodeById["d:" + devId]) {
        addEdge({
          from: "d:" + devId,
          to: eId,
          kind: "evidence_source",
          evidence_type: t
        });
      }
    });
  });
  return {
    nodes,
    edges,
    nodeById,
    columns,
    totalH
  };
}
function aggregateUserFlags(report, username) {
  const user = (report.user_map || {})[username];
  if (!user) return {
    total: 0,
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };
  const agg = {
    total: 0,
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };
  for (const devId of user.devices || []) {
    const c = countFlags((report.behavioral_flags || {})[devId] || []);
    agg.total += c.total;
    agg.CRITICAL += c.CRITICAL;
    agg.HIGH += c.HIGH;
    agg.MEDIUM += c.MEDIUM;
    agg.LOW += c.LOW;
  }
  return agg;
}
function osLabel(d) {
  const t = (d.device_type || "").toLowerCase();
  if (t.includes("ios")) return "iOS " + (d.os_version || "");
  if (t.includes("android")) return "Android " + (d.os_version || "");
  if (t.includes("server")) return d.os_version || d.os_type || "server";
  if (d.os_type === "windows") return d.os_version || "Windows";
  if (d.os_type === "linux") return d.os_version || "Linux";
  if (d.os_type === "macos") return d.os_version || "macOS";
  return d.os_type || "device";
}
function truncate(s, n) {
  s = s == null ? "" : String(s);
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function describeNode(n, report) {
  const lines = [];
  if (n.kind === "user") {
    const u = (report.user_map || {})[n.key] || {};
    lines.push(`Account: ${u.display_name || n.key}`);
    if (u.role) lines.push(`Role: ${u.role}`);
    if ((u.aliases || []).length) lines.push(`Aliases: ${u.aliases.join(", ")}`);
    if (n.badge) lines.push(`Findings: ${n.badge.count}${n.badge.sev ? ` (max ${n.badge.sev})` : ""}`);
  } else if (n.kind === "evidence") {
    const item = n.raw || {};
    lines.push(`Evidence type: ${formatEvidenceType(item.type || n.key)}`);
    lines.push(`${(item.files || []).length} file(s) across ${(item.devIds || []).length} device(s)`);
  } else if (n.kind === "service") {
    const item = n.raw || {};
    lines.push(`External service: ${item.name || n.key}`);
    lines.push(`${(item.hosts || []).length} flagged connection(s)`);
  } else {
    const d = (report.device_map || {})[n.key] || {};
    lines.push(`Device: ${d.hostname || n.key}`);
    lines.push(`OS: ${osLabel(d)}`);
    if (d.owner) lines.push(`Owner: ${d.owner}${d.owner_confidence ? ` (${d.owner_confidence})` : ""}`);
    if (n.badge) lines.push(`Findings: ${n.badge.count}${n.badge.sev ? ` (max ${n.badge.sev})` : ""}`);
  }
  return lines.join("\n");
}
function describeEdge(e, n1, n2) {
  const a = n1.label || n1.key;
  const b = n2.label || n2.key;
  switch (e.kind) {
    case "owns":
      return `${a} owns ${b}`;
    case "seen_on":
      return `${a} seen on ${b} (not owner)`;
    case "lateral":
      return `Lateral movement: ${a} → ${b}${e.method ? `\nMethod: ${e.method}` : ""}${e.via ? `\nUser: ${e.via}` : ""}`;
    case "exfiltrated_to":
      {
        const parts = [`Exfil/C2: ${a} → ${b}`];
        if (e.host) parts.push(`Host: ${e.host}`);
        if (e.bytes) parts.push(`Bytes: ${e.bytes.toLocaleString()}`);
        if (e.flag) parts.push(`Flag: ${e.flag}`);
        return parts.join("\n");
      }
    case "evidence_source":
      return `Evidence source: ${a} → ${formatEvidenceType(e.evidence_type || "")}`;
    default:
      return `${a} ↔ ${b}`;
  }
}
window.RelationshipGraph = RelationshipGraph;
window.classifyDevice = classifyDevice;
window.countFlags = countFlags;
window.maxSev = maxSev;
window.aggregateUserFlags = aggregateUserFlags;
window.osLabel = osLabel;
window.formatEvidenceType = formatEvidenceType;
window.classifyExfilService = classifyExfilService;
window.guessEvidenceTypeFromPath = guessEvidenceTypeFromPath;

})();
