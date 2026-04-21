// Relationship graph — columnar layout (Users | Machines | Mobile | Network | Indicators)
// with edges for ownership, lateral-movement, and device→IOC connections.

const { useEffect, useMemo, useRef, useState } = React;

function classifyDevice(d) {
  const t = (d.device_type || "").toLowerCase();
  if (t.includes("server")) return "server";
  if (t.includes("mobile") || t.includes("ios") || t.includes("android")) return "mobile";
  if (t.includes("network") || t.includes("pcap")) return "network";
  return "pc";
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

// Build deduplicated IOC items from report.iocs
function buildIocItems(report) {
  const iocs = report.iocs || {};
  const items = [];
  const addIoc = (val, subkind) => {
    const id = "i:" + val;
    items.push({ id, kind: "ioc", subkind, raw: val, key: val });
  };
  (iocs.ip_addresses    || []).slice(0, 6).forEach(v => addIoc(v, "ip"));
  (iocs.urls            || []).slice(0, 5).forEach(v => addIoc(v, "url"));
  (iocs.email_addresses || []).slice(0, 4).forEach(v => addIoc(v, "email"));
  return items;
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

        {/* Edges — IOC edges drawn first (behind) */}
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
            if (e.kind === "ioc")     cls += " ioc";
            if (hl)  cls += " highlighted";
            if (dim) cls += " dimmed";
            return <path key={i} className={cls} d={d} />;
          })}
        </g>

        {/* Nodes */}
        <g>
          {graph.nodes.map((n) => {
            const isSel    = selected === n.id;
            const isHover  = hoverId === n.id;
            const inNbhd   = neighbors && neighbors.has(n.id);
            const dim      = neighbors && !inNbhd;
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
                ) : n.kind === "ioc" ? (
                  <polygon
                    points={`0,${-n.r} ${n.r},0 0,${n.r} ${-n.r},0`}
                    fill="rgba(239,68,68,0.06)"
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
                <text
                  x={0}
                  y={n.kind === "user" || n.kind === "ioc" ? 4 : -3}
                  textAnchor="middle"
                >
                  {n.label}
                </text>
                {n.sublabel && (
                  <text
                    x={0}
                    y={n.kind === "user" || n.kind === "ioc" ? 18 : 12}
                    textAnchor="middle"
                    className="sublabel"
                  >
                    {n.sublabel}
                  </text>
                )}
                {/* Severity badge — not shown on IOC nodes */}
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
  const isCircular = n => n.kind === "user" || n.kind === "ioc";
  const [from, to] = a.x < b.x ? [a, b] : [b, a];
  const sx = from.x + (isCircular(from) ? from.r : from.w / 2);
  const ex = to.x   - (isCircular(to)   ? to.r   : to.w   / 2);
  const sy = from.y, ey = to.y;
  const mx = (sx + ex) / 2;
  return `M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ey}, ${ex} ${ey}`;
}

function buildGraph(report, size) {
  const users    = Object.entries(report.user_map   || {}).map(([k, u]) => ({ id: "u:" + k, kind: "user", raw: u, key: k }));
  const devs     = Object.entries(report.device_map || {}).map(([k, d]) => ({ id: "d:" + k, kind: classifyDevice(d), raw: d, key: k }));
  const iocItems = buildIocItems(report);

  const columns = [
    { key: "user",    label: "Accounts",    items: users },
    { key: "pc",      label: "Workstations",items: devs.filter((d) => d.kind === "pc") },
    { key: "server",  label: "Servers",     items: devs.filter((d) => d.kind === "server") },
    { key: "mobile",  label: "Mobile",      items: devs.filter((d) => d.kind === "mobile") },
    { key: "network", label: "Network",     items: devs.filter((d) => d.kind === "network") },
    { key: "ioc",     label: "Indicators",  items: iocItems },
  ].filter((c) => c.items.length > 0).map((c) => ({ ...c, count: c.items.length }));

  const colCount = columns.length;
  const padX     = 40;
  const innerW   = size.w - padX * 2;
  const colGap   = innerW / colCount;

  const accentMap = {
    user:    "#10B981",
    pc:      "#3B82F6",
    server:  "#A78BFA",
    mobile:  "#F59E0B",
    network: "#64748B",
    // IOC subkinds
    ip:      "#EF4444",
    url:     "#F97316",
    email:   "#EC4899",
  };

  const nodeById = {};
  const nodes    = [];

  columns.forEach((col, ci) => {
    col.x = padX + colGap * ci + colGap / 2;
    const topY    = 70;
    const bottomY = size.h - 40;
    const gapY    = (bottomY - topY) / Math.max(col.items.length, 1);

    col.items.forEach((item, ri) => {
      const y      = topY + gapY * ri + gapY / 2;
      const isIoc  = item.kind === "ioc";
      const isUser = item.kind === "user";

      const flags = isIoc  ? { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
                  : isUser ? aggregateUserFlags(report, item.key)
                  :          countFlags((report.behavioral_flags || {})[item.key] || []);
      const sev = maxSev(flags);

      const label    = isIoc  ? item.raw
                     : isUser ? (item.raw.display_name || item.raw.username || item.key)
                     :          (item.raw.hostname || item.key);
      const sublabel = isIoc  ? item.subkind.toUpperCase()
                     : isUser ? (item.raw.role || "user")
                     :          osLabel(item.raw);

      const accentKey = isIoc ? item.subkind : item.kind;
      const node = {
        id:       item.id,
        kind:     item.kind,
        subkind:  item.subkind,
        key:      item.key,
        label:    truncate(label, 18),
        sublabel: truncate(sublabel, 22),
        x: col.x,
        y,
        r: isIoc ? 22 : 28,     // diamond/circle radius
        w: 150, h: 44,          // rectangle dimensions (unused for user/ioc)
        accent: accentMap[accentKey] || "#64748B",
        badge:  (!isIoc && flags.total > 0) ? { count: flags.total, sev } : null,
        raw:    item.raw,
      };
      nodes.push(node);
      nodeById[node.id] = node;
    });
  });

  // Build edges
  const edges = [];

  // Ownership: user → device
  for (const [uname, u] of Object.entries(report.user_map || {})) {
    for (const devId of (u.devices || [])) {
      if (nodeById["u:" + uname] && nodeById["d:" + devId]) {
        edges.push({ from: "u:" + uname, to: "d:" + devId, kind: "owns" });
      }
    }
  }

  // Lateral movement: device → device (dashed amber)
  for (const [uname, cu] of Object.entries(report.correlated_users || {})) {
    for (const ind of (cu.lateral_movement_indicators || [])) {
      const a = "d:" + ind.from_device;
      const b = "d:" + ind.to_device;
      if (nodeById[a] && nodeById[b]) {
        edges.push({ from: a, to: b, kind: "lateral", via: uname, method: ind.method });
      }
    }
  }

  // Device → IOC: scan behavioral_flags evidence for matching IOC values
  if (iocItems.length > 0) {
    for (const [devId, flags] of Object.entries(report.behavioral_flags || {})) {
      const devKey  = "d:" + devId;
      if (!nodeById[devKey]) continue;
      const evText  = JSON.stringify(flags);
      for (const item of iocItems) {
        if (evText.includes(item.raw) && nodeById[item.id]) {
          if (!edges.some(e => e.from === devKey && e.to === item.id)) {
            edges.push({ from: devKey, to: item.id, kind: "ioc" });
          }
        }
      }
    }
  }

  return { nodes, edges, nodeById, columns };
}

function aggregateUserFlags(report, username) {
  const user = (report.user_map || {})[username];
  if (!user) return { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const agg = { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const devId of (user.devices || [])) {
    const c = countFlags((report.behavioral_flags || {})[devId] || []);
    agg.total += c.total; agg.CRITICAL += c.CRITICAL;
    agg.HIGH  += c.HIGH;  agg.MEDIUM   += c.MEDIUM; agg.LOW += c.LOW;
  }
  return agg;
}

function osLabel(d) {
  const t = (d.device_type || "").toLowerCase();
  if (t.includes("ios"))     return "iOS "     + (d.os_version || "");
  if (t.includes("android")) return "Android " + (d.os_version || "");
  if (t.includes("server"))  return d.os_version || d.os_type;
  if (d.os_type === "windows") return d.os_version || "Windows";
  if (d.os_type === "linux")   return d.os_version || "Linux";
  return d.os_type || "device";
}

function truncate(s, n) { s = s || ""; return s.length > n ? s.slice(0, n - 1) + "…" : s; }

window.RelationshipGraph   = RelationshipGraph;
window.classifyDevice      = classifyDevice;
window.countFlags          = countFlags;
window.maxSev              = maxSev;
window.aggregateUserFlags  = aggregateUserFlags;
window.osLabel             = osLabel;
