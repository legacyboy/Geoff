// Relationship graph — columnar layout (Users | Machines | Mobile | Network | Services)
// with edges for ownership, lateral-movement, evidence sources, and exfiltration.

const { useEffect, useMemo, useRef, useState } = React;

function classifyDevice(d) {
  const t = (d.device_type || "").toLowerCase();
  if (t.includes("server")) return "server";
  if (t.includes("mobile") || t.includes("ios") || t.includes("android")) return "mobile";
  if (t.includes("network") || t.includes("pcap")) return "network";
  return "pc"; // windows_pc, linux_pc, macos_workstation
}

function countFlags(flags) {
  const out = { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
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

function RelationshipGraph({ report, selected, onSelect, hoverId, onHover }) {
  const wrapRef = useRef(null);
  const [size, setSize] = useState({ w: 900, h: 600 });

  useEffect(() => {
    if (!wrapRef.current) return;
    const ro = new ResizeObserver(([e]) => {
      const r = e.contentRect;
      setSize({ w: Math.max(600, r.width), h: Math.max(400, r.height) });
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

  return (
    <div ref={wrapRef} className="graph-stage">
      <svg className="graph-svg" viewBox={`0 0 ${size.w} ${size.h}`} preserveAspectRatio="xMidYMid meet">
        {/* Column headers + rules */}
        {graph.columns.map((col) => (
          <g key={col.key}>
            <text className="col-header" x={col.x} y={28} textAnchor="middle">
              {col.label.toUpperCase()} · {col.count}
            </text>
            <line className="col-rule" x1={col.x} y1={44} x2={col.x} y2={size.h - 16} />
          </g>
        ))}

        {/* Edges */}
        <g>
          {graph.edges.map((e, i) => {
            const n1 = graph.nodeById[e.from];
            const n2 = graph.nodeById[e.to];
            if (!n1 || !n2) return null;
            const d = edgePath(n1, n2);
            const hl = neighbors && neighbors.has(e.from) && neighbors.has(e.to);
            const dim = neighbors && !hl;
            let cls = "edge";
            if (e.kind === "lateral") cls += " lateral";
            if (e.kind === "exfiltrated_to") cls += " exfil";
            if (e.kind === "evidence_source") cls += " evidence-link";
            if (hl) cls += " highlighted";
            if (dim) cls += " dimmed";
            return <path key={i} className={cls} d={d} />;
          })}
        </g>

        {/* Nodes */}
        <g>
          {graph.nodes.map((n) => {
            const isSel = selected === n.id;
            const isHover = hoverId === n.id;
            const inNeighborhood = neighbors && neighbors.has(n.id);
            const dim = neighbors && !inNeighborhood;
            let cls = "node";
            if (isSel || isHover) cls += " highlighted";
            if (dim) cls += " dimmed";
            return (
              <g
                key={n.id}
                className={cls}
                transform={`translate(${n.x}, ${n.y})`}
                onClick={() => onSelect(n.id)}
                onMouseEnter={() => onHover(n.id)}
                onMouseLeave={() => onHover(null)}
                style={{ color: n.accent }}
              >
                {n.kind === "user" ? (
                  <circle
                    cx={0} cy={0} r={n.r}
                    fill="rgba(16,185,129,0.08)"
                    stroke={n.accent}
                    strokeWidth={isSel ? 2 : 1}
                  />
                ) : n.kind === "evidence" ? (
                  <rect
                    x={-n.w / 2} y={-n.h / 2}
                    width={n.w} height={n.h} rx={4}
                    fill="rgba(6,182,212,0.15)"
                    stroke={n.accent}
                    strokeWidth={isSel ? 2 : 1}
                    strokeDasharray="4 2"
                  />
                ) : n.kind === "service" ? (
                  <rect
                    x={-n.w / 2} y={-n.h / 2}
                    width={n.w} height={n.h} rx={20}
                    fill="rgba(236,72,153,0.15)"
                    stroke={n.accent}
                    strokeWidth={isSel ? 2 : 1}
                  />
                ) : (
                  <rect
                    x={-n.w / 2} y={-n.h / 2}
                    width={n.w} height={n.h} rx={6}
                    fill="rgba(30,41,59,0.9)"
                    stroke={n.accent}
                    strokeWidth={isSel ? 2 : 1}
                  />
                )}
                <text x={0} y={n.kind === "user" ? 4 : -3} textAnchor="middle">
                  {n.label}
                </text>
                {n.sublabel && (
                  <text x={0} y={n.kind === "user" ? 18 : 12} textAnchor="middle" className="sublabel">
                    {n.sublabel}
                  </text>
                )}
                {/* Severity badge */}
                {n.badge && (
                  <g transform={`translate(${n.kind === "user" ? n.r - 4 : n.w / 2 - 6}, ${n.kind === "user" ? -n.r + 4 : -n.h / 2 + 6})`}>
                    <circle r={8} className={`flag-badge ${n.badge.sev === "CRITICAL" ? "crit" : ""}`} />
                    <text className="flag-badge-text">{n.badge.count}</text>
                  </g>
                )}
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}

function edgePath(a, b) {
  // Curved connector between two nodes (horizontal S)
  const x1 = a.x + (a.kind === "user" ? a.r : a.w / 2);
  const x2 = b.x - (b.kind === "user" ? b.r : b.w / 2);
  const [from, to] = a.x < b.x ? [a, b] : [b, a];
  const sx = from.x + (from.kind === "user" ? from.r : from.w / 2);
  const ex = to.x - (to.kind === "user" ? to.r : to.w / 2);
  const sy = from.y, ey = to.y;
  const mx = (sx + ex) / 2;
  return `M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ey}, ${ex} ${ey}`;
}

function buildGraph(report, size) {
  const users = Object.entries(report.user_map || {}).map(([k, u]) => ({ id: "u:" + k, kind: "user", raw: u, key: k }));
  const devs = Object.entries(report.device_map || {}).map(([k, d]) => ({ id: "d:" + k, kind: classifyDevice(d), raw: d, key: k }));

  // Add exfiltration service nodes if detected
  const exfilServices = new Map();
  Object.entries(report.behavioral_flags || {}).forEach(([devId, flags]) => {
    flags.forEach(flag => {
      if (flag.flag_type === 'exfiltration' || flag.flag_type === 'c2_traffic') {
        const evidence = flag.evidence || {};
        const dstHost = evidence.dst_host || evidence.dst_ip || '';
        if (dstHost) {
          // Detect service type
          let serviceType = 'external';
          if (dstHost.includes('mega') || dstHost.includes('mega.')) serviceType = 'Mega.nz';
          else if (dstHost.includes('gmail') || dstHost.includes('google')) serviceType = 'Google';
          else if (dstHost.includes('onedrive') || dstHost.includes('microsoft')) serviceType = 'OneDrive';
          else if (dstHost.includes('dropbox')) serviceType = 'Dropbox';
          else if (dstHost.includes('aol')) serviceType = 'AOL';
          else if (dstHost.includes('yahoo')) serviceType = 'Yahoo';
          else if (dstHost.includes('protonmail')) serviceType = 'ProtonMail';
          
          if (!exfilServices.has(serviceType)) {
            exfilServices.set(serviceType, { id: "s:" + serviceType, kind: "service", name: serviceType, hosts: [] });
          }
          exfilServices.get(serviceType).hosts.push({ host: dstHost, devId, flag });
        }
      }
    });
  });

// Add evidence source nodes for each device's evidence files
  const evidenceNodes = [];
  const evidenceFiles = new Map(); // path -> { device_ids: [], type }
  
  // Collect all evidence files and which devices they belong to
  Object.entries(report.device_map || {}).forEach(([devId, dev]) => {
    (dev.evidence_files || []).forEach(fpath => {
      const fname = fpath.split('/').pop();
      if (!evidenceFiles.has(fpath)) {
        evidenceFiles.set(fpath, { 
          filename: fname, 
          device_ids: [],
          type: dev.evidence_types?.[0] || 'unknown'
        });
      }
      evidenceFiles.get(fpath).device_ids.push(devId);
    });
  });

  const columns = [
    { key: "user", label: "Accounts", items: users },
    { key: "pc", label: "Workstations", items: devs.filter((d) => d.kind === "pc") },
    { key: "server", label: "Servers", items: devs.filter((d) => d.kind === "server") },
    { key: "mobile", label: "Mobile", items: devs.filter((d) => d.kind === "mobile") },
    { key: "network", label: "Network", items: devs.filter((d) => d.kind === "network") },
    { key: "service", label: "Services", items: Array.from(exfilServices.values()) },
    { key: "evidence", label: "Evidence", items: Array.from(evidenceFiles.entries()).map(([path, info]) => ({
      id: "e:" + path,
      kind: "evidence",
      path: path,
      ...info
    })) },
  ].filter((c) => c.items.length > 0).map((c) => ({ ...c, count: c.items.length }));

  const colCount = columns.length;
  const padX = 40;
  const innerW = size.w - padX * 2;
  const colGap = innerW / colCount;

  const accentMap = {
    user: "#10B981",
    pc: "#3B82F6",
    server: "#A78BFA",
    mobile: "#F59E0B",
    network: "#64748B",
    service: "#EC4899",
    evidence: "#06B6D4",
  };

  const nodeById = {};
  const nodes = [];

  // Add device/user nodes
  columns.filter(c => c.key !== 'service').forEach((col, ci) => {
    col.x = padX + colGap * ci + colGap / 2;
    const topY = 70;
    const bottomY = size.h - 40;
    const gapY = (bottomY - topY) / Math.max(col.items.length, 1);
    col.items.forEach((item, ri) => {
      const y = topY + gapY * ri + gapY / 2;
      const flags = item.kind === "user"
        ? aggregateUserFlags(report, item.key)
        : countFlags((report.behavioral_flags || {})[item.key] || []);
      const sev = maxSev(flags);
      const label = item.kind === "user"
        ? (item.raw.display_name || item.raw.username || item.key)
        : (item.raw.hostname || item.key);
      const sublabel = item.kind === "user"
        ? (item.raw.role || "user")
        : osLabel(item.raw);
      const node = {
        id: item.id,
        kind: item.kind,
        key: item.key,
        label: truncate(label, 18),
        sublabel: truncate(sublabel, 22),
        x: col.x,
        y,
        r: 28,           // for user circles
        w: 150, h: 44,   // for rectangles
        accent: accentMap[item.kind] || "#64748B",
        badge: flags.total > 0 ? { count: flags.total, sev } : null,
        raw: item.raw,
      };
      nodes.push(node);
      nodeById[node.id] = node;
    });
  });

  // Add service nodes
  const serviceCol = columns.find(c => c.key === 'service');
  if (serviceCol) {
    const topY = 70;
    const bottomY = size.h - 40;
    const gapY = (bottomY - topY) / Math.max(serviceCol.items.length, 1);
    serviceCol.items.forEach((item, ri) => {
      const y = topY + gapY * ri + gapY / 2;
      const node = {
        id: item.id,
        kind: "service",
        key: item.name,
        label: truncate(item.name, 18),
        sublabel: item.hosts.length + " connection(s)",
        x: serviceCol.x,
        y,
        r: 28,
        w: 150, h: 44,
        accent: accentMap.service,
        badge: { count: item.hosts.length, sev: "HIGH" },
        raw: { name: item.name, hosts: item.hosts }
      };
      nodes.push(node);
      nodeById[node.id] = node;
    });
  }

  // Build edges
  const edges = [];
  // ownership: user <-> device
  for (const [uname, u] of Object.entries(report.user_map || {})) {
    for (const devId of (u.devices || [])) {
      if (nodeById["u:" + uname] && nodeById["d:" + devId]) {
        edges.push({ from: "u:" + uname, to: "d:" + devId, kind: "owns" });
      }
    }
  }
  // lateral movement edges (device <-> device)
  for (const [uname, cu] of Object.entries(report.correlated_users || {})) {
    for (const ind of (cu.lateral_movement_indicators || [])) {
      const a = "d:" + ind.from_device;
      const b = "d:" + ind.to_device;
      if (nodeById[a] && nodeById[b]) {
        edges.push({ from: a, to: b, kind: "lateral", via: uname, method: ind.method });
      }
    }
  }
  // Exfiltration edges: device -> service
  Object.entries(report.behavioral_flags || {}).forEach(([devId, flags]) => {
    flags.forEach(flag => {
      if (flag.flag_type === 'exfiltration' || flag.flag_type === 'c2_traffic') {
        const evidence = flag.evidence || {};
        const dstHost = evidence.dst_host || evidence.dst_ip || '';
        if (dstHost) {
          let serviceType = 'external';
          if (dstHost.includes('mega') || dstHost.includes('mega.')) serviceType = 'Mega.nz';
          else if (dstHost.includes('gmail') || dstHost.includes('google')) serviceType = 'Google';
          else if (dstHost.includes('onedrive') || dstHost.includes('microsoft')) serviceType = 'OneDrive';
          else if (dstHost.includes('dropbox')) serviceType = 'Dropbox';
          else if (dstHost.includes('aol')) serviceType = 'AOL';
          else if (dstHost.includes('yahoo')) serviceType = 'Yahoo';
          else if (dstHost.includes('protonmail')) serviceType = 'ProtonMail';
          
          const serviceNodeId = "s:" + serviceType;
          if (nodeById["d:" + devId] && nodeById[serviceNodeId]) {
            edges.push({ 
              from: "d:" + devId, 
              to: serviceNodeId, 
              kind: "exfiltrated_to", 
              host: dstHost,
              bytes: evidence.bytes_sent,
              flag: flag.summary
            });
          }
        }
      }
    });
  });

  // Add evidence source edges: device -> evidence file
  evidenceFiles.forEach((info, path) => {
    info.device_ids.forEach(devId => {
      if (nodeById["d:" + devId] && nodeById["e:" + path]) {
        edges.push({
          from: "d:" + devId,
          to: "e:" + path,
          kind: "evidence_source",
          evidence_type: info.type
        });
      }
    });
  });

  return { nodes, edges, nodeById, columns };
}

function aggregateUserFlags(report, username) {
  const user = (report.user_map || {})[username];
  if (!user) return { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const agg = { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const devId of (user.devices || [])) {
    const c = countFlags((report.behavioral_flags || {})[devId] || []);
    agg.total += c.total; agg.CRITICAL += c.CRITICAL;
    agg.HIGH += c.HIGH; agg.MEDIUM += c.MEDIUM; agg.LOW += c.LOW;
  }
  return agg;
}

function osLabel(d) {
  const t = (d.device_type || "").toLowerCase();
  if (t.includes("ios")) return "iOS " + (d.os_version || "");
  if (t.includes("android")) return "Android " + (d.os_version || "");
  if (t.includes("server")) return d.os_version || d.os_type;
  if (d.os_type === "windows") return d.os_version || "Windows";
  if (d.os_type === "linux") return d.os_version || "Linux";
  if (d.os_type === "macos") return d.os_version || "macOS";
  return d.os_type || "device";
}

function truncate(s, n) { s = s || ""; return s.length > n ? s.slice(0, n - 1) + "…" : s; }

window.RelationshipGraph = RelationshipGraph;
window.classifyDevice = classifyDevice;
window.countFlags = countFlags;
window.maxSev = maxSev;
window.aggregateUserFlags = aggregateUserFlags;
window.osLabel = osLabel;
