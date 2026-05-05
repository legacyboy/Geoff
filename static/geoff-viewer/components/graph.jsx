// Relationship graph — columnar layout (Accounts | Workstations | Servers | Mobile | Network | Services | Findings | MITRE | Indicators)
// with edges for ownership, lateral-movement, and device→IOC connections.

const { useEffect, useMemo, useRef, useState } = React;

// Column layout constants
const HEADER_Y = 70;
const FOOTER_Y = 40;
const MIN_ROW_H = 64;
const NODE_H = 44;
const USER_R = 26;

function classifyDevice(d) {
  const t = (d.device_type || "").toLowerCase();
  const h = (d.hostname || "").toLowerCase();
  // Check for server indicators - use word boundaries to avoid false matches
  if (t.includes("server") || h.includes("server") ||
      /\bsrv\b/.test(h) || /\bdc\b/.test(h)) return "server";
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
  return null;
}

function extractUsernameFromPath(filePath) {
  if (!filePath) return null;
  // Skip analysis machine paths - these are not evidence
  if (filePath.startsWith("/home/sansforensics/") ||
      filePath.startsWith("/home/claw/") ||
      filePath.startsWith("/mnt/") ||
      filePath.startsWith("/tmp/")) return null;
  // Windows paths: /Users/username/ or C:\Users\username\
  // These are evidence paths from the imaged system
  const winMatch = filePath.match(/[/\\]Users[/\\]([^/\\]+)/i);
  if (winMatch) {
    const u = winMatch[1];
    // Filter common system accounts
    if (["All Users", "Default", "Default User", "Public", "Administrator", "Guest"].includes(u)) return null;
    return u;
  }
  // Linux paths: /home/username/ - only from evidence, not analysis machine
  const linuxMatch = filePath.match(/[/\\]home[/\\]([^/\\]+)/i);
  if (linuxMatch) {
    const u = linuxMatch[1];
    if (["sansforensics", "claw", "root", "nobody", "daemon", "ubuntu", "pi", "vagrant"].includes(u.toLowerCase())) return null;
    return u;
  }
  return null;
}

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

// Build findings nodes from behavioral flags and threat indicators
function buildFindingsItems(report) {
  const findings = [];
  const flagsByDevice = report.behavioral_flags || {};
  const seenFindings = new Set();

  Object.entries(flagsByDevice).forEach(([devId, flags]) => {
    (flags || []).forEach(flag => {
      // Create node for each unique behavioral flag
      const flagId = "f:" + flag.flag_type + ":" + devId;
      if (!seenFindings.has(flagId)) {
        seenFindings.add(flagId);
        findings.push({
          id: flagId,
          kind: "finding",
          subkind: flag.flag_type || "behavioral",
          flagType: flag.flag_type,
          severity: flag.severity,
          summary: flag.summary,
          deviceId: devId,
          evidence: flag.evidence,
        });
      }

      // Extract MITRE ATT&CK techniques if present
      if (flag.mitre_techniques) {
        (flag.mitre_techniques || []).forEach(tech => {
          const techId = "m:" + tech.id;
          if (!seenFindings.has(techId)) {
            seenFindings.add(techId);
            findings.push({
              id: techId,
              kind: "mitre",
              subkind: "mitre",
              techniqueId: tech.id,
              name: tech.name || tech.id,
              severity: flag.severity,
            });
          }
        });
      }

      // Extract IOCs from flag evidence (with limits to avoid graph clutter)
      const evidence = flag.evidence || {};
      const iocCounts = { ip: 0, domain: 0, hash: 0, file_path: 0 };
      // Count existing IOCs by type
      findings.forEach(f => { if (f.kind === "ioc") iocCounts[f.subkind] = (iocCounts[f.subkind] || 0) + 1; });
      if (evidence.dst_ip && iocCounts.ip < 50) {
        const iocId = "i:" + evidence.dst_ip;
        if (!seenFindings.has(iocId)) {
          seenFindings.add(iocId);
          findings.push({ id: iocId, kind: "ioc", subkind: "ip", raw: evidence.dst_ip, key: evidence.dst_ip });
        }
      }
      if (evidence.dst_host && iocCounts.domain < 50) {
        const iocId = "i:" + evidence.dst_host;
        if (!seenFindings.has(iocId)) {
          seenFindings.add(iocId);
          findings.push({ id: iocId, kind: "ioc", subkind: "domain", raw: evidence.dst_host, key: evidence.dst_host });
        }
      }
      if (evidence.hash && iocCounts.hash < 50) {
        const iocId = "i:" + evidence.hash;
        if (!seenFindings.has(iocId)) {
          seenFindings.add(iocId);
          findings.push({ id: iocId, kind: "ioc", subkind: "hash", raw: evidence.hash, key: evidence.hash });
        }
      }
      if (evidence.file_path && iocCounts.file_path < 30) {
        // Skip analysis machine paths
        if (!evidence.file_path.startsWith("/home/sansforensics/") &&
            !evidence.file_path.startsWith("/home/claw/") &&
            !evidence.file_path.startsWith("/mnt/") &&
            !evidence.file_path.startsWith("/tmp/")) {
          const iocId = "i:" + evidence.file_path;
          if (!seenFindings.has(iocId)) {
            seenFindings.add(iocId);
            findings.push({ id: iocId, kind: "ioc", subkind: "file_path", raw: evidence.file_path, key: evidence.file_path });
          }
        }
      }
    });
  });

  return findings;
}

function aggregateUserFlags(report, username) {
  const user = (report.user_map || {})[username];
  if (!user) return { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const agg = { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
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
  if (t.includes("ios"))     return "iOS "     + (d.os_version || "");
  if (t.includes("android")) return "Android " + (d.os_version || "");
  if (t.includes("server")) return d.os_version || d.os_type || "server";
  if (d.os_type === "windows") return d.os_version || "Windows";
  if (d.os_type === "linux") return d.os_version || "Linux";
  if (d.os_type === "macos") return d.os_version || "macOS";
  return d.os_type || "device";
}

function truncate(s, n) { s = s == null ? "" : String(s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

function describeNode(n, report) {
  const lines = [];
  if (n.kind === "user") {
    const u = (report.user_map || {})[n.key] || {};
    lines.push(`Account: ${u.display_name || n.key}`);
    if (u.role) lines.push(`Role: ${u.role}`);
    if ((u.aliases || []).length) lines.push(`Aliases: ${u.aliases.join(", ")}`);
    if (n.badge) lines.push(`Findings: ${n.badge.count}${n.badge.sev ? ` (max ${n.badge.sev})` : ""}`);
  } else if (n.kind === "finding") {
    lines.push(`Finding: ${n.flagType || n.subkind}`);
    lines.push(`Severity: ${n.severity || "N/A"}`);
    if (n.summary) lines.push(`Summary: ${n.summary}`);
  } else if (n.kind === "mitre") {
    lines.push(`MITRE ATT&CK: ${n.techniqueId}`);
    if (n.name) lines.push(`Name: ${n.name}`);
  } else if (n.kind === "service") {
    lines.push(`Service: ${n.name || "External"}`);
    if (n.hosts) lines.push(`Hosts: ${n.hosts.length}`);
  } else if (n.kind === "ioc") {
    lines.push(`IOC: ${n.subkind.toUpperCase()}`);
    lines.push(`Value: ${n.raw}`);
  } else {
    const d = (report.device_map || {})[n.key] || {};
    lines.push(`Device: ${d.hostname || n.key}`);
    lines.push(`OS: ${osLabel(d)}`);
    if (d.owner) lines.push(`Owner: ${d.owner}`);
    else if (d.metadata && d.metadata.user_profiles_found && d.metadata.user_profiles_found.length > 0) {
      lines.push(`Users: ${d.metadata.user_profiles_found.join(", ")}`);
    }
    if (n.badge) lines.push(`Findings: ${n.badge.count}${n.badge.sev ? ` (max ${n.badge.sev})` : ""}`);
  }
  return lines.join("\n");
}

function describeEdge(e, n1, n2) {
  const a = n1.label || n1.key;
  const b = n2.label || n2.key;
  switch (e.kind) {
    case "owns": return `${a} owns ${b}`;
    case "seen_on": return `${a} seen on ${b} (not owner)`;
    case "lateral": return `Lateral movement: ${a} → ${b}${e.method ? `\nMethod: ${e.method}` : ""}${e.via ? `\nUser: ${e.via}` : ""}`;
    case "exfiltrated_to": {
      const parts = [`Exfil/C2: ${a} → ${b}`];
      if (e.host) parts.push(`Host: ${e.host}`);
      if (e.bytes) parts.push(`Bytes: ${e.bytes.toLocaleString()}`);
      if (e.flag) parts.push(`Flag: ${e.flag}`);
      return parts.join("\n");
    }
    case "has_finding": return `Finding on ${b}: ${e.flagType}`;
    case "mitre_technique": return `${b} uses technique ${e.techniqueId}`;
    case "ioc": return `${a} contains IOC ${b}`;
    default: return `${a} ↔ ${b}`;
  }
}

function edgePath(a, b) {
  const isCircular = n => n.kind === "user" || n.kind === "ioc" || n.kind === "finding" || n.kind === "mitre";
  const [from, to] = a.x < b.x ? [a, b] : [b, a];
  const sx = from.x + (isCircular(from) ? from.r : from.w / 2);
  const ex = to.x   - (isCircular(to)   ? to.r   : to.w   / 2);
  const sy = from.y, ey = to.y;
  const mx = (sx + ex) / 2;
  return `M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ey}, ${ex} ${ey}`;
}

function buildGraph(report, size) {
  const userMap = report.user_map || {};
  const deviceMap = report.device_map || {};
  const flagsByDevice = report.behavioral_flags || {};

  // Build user list - extract usernames from device evidence files if owner is null
  const users = Object.entries(userMap).map(([k, u]) => ({
    id: "u:" + k, kind: "user", raw: u || {}, key: k,
  }));

  // Extract additional users from device evidence file paths
  const extractedUsernames = new Set();
  Object.entries(deviceMap).forEach(([devId, dev]) => {
    const files = (dev && dev.evidence_files) || [];
    files.forEach(fp => {
      const username = extractUsernameFromPath(fp);
      if (username && !userMap[username] && !extractedUsernames.has(username)) {
        extractedUsernames.add(username);
        users.push({
          id: "u:" + username,
          kind: "user",
          raw: { username, display_name: username, devices: [devId] },
          key: username,
        });
      }
    });
  });

  const devs = Object.entries(deviceMap).map(([k, d]) => ({
    id: "d:" + k, kind: classifyDevice(d || {}), raw: d || {}, key: k,
  }));

  // Build findings items (behavioral flags, MITRE techniques, IOCs)
  const findingsItems = buildFindingsItems(report);

  // Aggregate exfiltration services
  const exfilServices = new Map();
  Object.entries(flagsByDevice).forEach(([devId, flags]) => {
    (flags || []).forEach(flag => {
      if (flag.flag_type !== "exfiltration" && flag.flag_type !== "c2_traffic") return;
      const evidence = flag.evidence || {};
      const dstHost = evidence.dst_host || evidence.dst_ip || "";
      if (!dstHost) return;
      const serviceType = classifyExfilService(dstHost) || "External";
      if (!exfilServices.has(serviceType)) {
        exfilServices.set(serviceType, { id: "s:" + serviceType, kind: "service", name: serviceType, hosts: [] });
      }
      exfilServices.get(serviceType).hosts.push({ host: dstHost, devId, flag });
    });
  });

  const columns = [
    { key: "user", label: "Accounts", items: users },
    { key: "pc", label: "Workstations", items: devs.filter(d => d.kind === "pc") },
    { key: "server", label: "Servers", items: devs.filter(d => d.kind === "server") },
    { key: "mobile", label: "Mobile", items: devs.filter(d => d.kind === "mobile") },
    { key: "network", label: "Network", items: devs.filter(d => d.kind === "network") },
    { key: "service", label: "Services", items: Array.from(exfilServices.values()) },
    { key: "finding", label: "Findings", items: findingsItems.filter(f => f.kind === "finding") },
    { key: "mitre", label: "MITRE", items: findingsItems.filter(f => f.kind === "mitre") },
    { key: "ioc", label: "Indicators", items: findingsItems.filter(f => f.kind === "ioc") },
  ].filter(c => c.items.length > 0).map(c => ({ ...c, count: c.items.length }));

  // Layout sizing
  const maxItems = Math.max(1, ...columns.map(c => c.items.length));
  const computedH = HEADER_Y + FOOTER_Y + maxItems * MIN_ROW_H;
  const totalH = Math.max(size.h, computedH);

  const colCount = columns.length;
  const padX = 40;
  const innerW = size.w - padX * 2;
  const colGap = innerW / colCount;
  const nodeW = Math.max(96, Math.min(150, colGap * 0.84));
  const labelChars = Math.max(10, Math.floor(nodeW / 8));

  const accentMap = {
    user: "#10B981",
    pc: "#3B82F6",
    server: "#A78BFA",
    mobile: "#F59E0B",
    network: "#64748B",
    finding: "#F59E0B",
    mitre: "#EF4444",
    ioc: "#EF4444",
    service: "#EC4899",
    ip: "#EF4444",
    url: "#F97316",
    email: "#EC4899",
    domain: "#8B5CF6",
    hash: "#10B981",
    file_path: "#6B7280",
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
      const kind = item.kind;
      const isIoc = kind === "ioc";
      const isUser = kind === "user";
      const isFinding = kind === "finding";
      const isMitre = kind === "mitre";

      const flags = isIoc ? { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
                  : isUser ? aggregateUserFlags(report, item.key)
                  :          countFlags((report.behavioral_flags || {})[item.deviceId] || []);
      const sev = maxSev(flags);

      let label, sublabel;
      if (isIoc) {
        label = truncate(item.raw, 18);
        sublabel = item.subkind.toUpperCase();
      } else if (isUser) {
        label = truncate((item.raw.display_name || item.raw.username || item.key), 18);
        sublabel = truncate((item.raw.role || "user"), 22);
      } else if (isFinding) {
        label = truncate(item.flagType || item.subkind, 18);
        sublabel = truncate(sev || "N/A", 22);
      } else if (isMitre) {
        label = truncate(item.techniqueId, 18);
        sublabel = truncate(item.name || "MITRE", 22);
      } else {
        label = truncate((item.raw.hostname || item.key), 18);
        sublabel = truncate(osLabel(item.raw), 22);
      }

      const accentKey = isIoc ? item.subkind : kind;
      const node = {
        id: item.id,
        kind: kind,
        subkind: item.subkind,
        key: item.key,
        label: label,
        sublabel: sublabel,
        x: col.x,
        y,
        r: isIoc || isFinding || isMitre ? 22 : (isUser ? USER_R : 28),
        w: isIoc || isFinding || isMitre ? 44 : nodeW,
        h: isIoc || isFinding || isMitre ? 44 : NODE_H,
        accent: accentMap[accentKey] || "#64748B",
        badge: (!isIoc && !isFinding && !isMitre && flags.total > 0) ? { count: flags.total, sev } : null,
        raw: item.raw,
        deviceId: item.deviceId,
        flagType: item.flagType,
        severity: item.severity,
        techniqueId: item.techniqueId,
      };
      nodes.push(node);
      nodeById[node.id] = node;
    });
  });

  // Build edges
  const edges = [];
  const seenEdge = new Set();
  const addEdge = (e) => {
    const k = `${e.from}|${e.to}|${e.kind}`;
    if (seenEdge.has(k)) return;
    seenEdge.add(k);
    edges.push(e);
  };

  // User <-> Device ownership
  for (const [uname, u] of Object.entries(userMap)) {
    for (const devId of (u.devices || [])) {
      if (!nodeById["u:" + uname] || !nodeById["d:" + devId]) continue;
      const dev = deviceMap[devId] || {};
      const isOwner = dev.owner === uname;
      addEdge({ from: "u:" + uname, to: "d:" + devId, kind: isOwner ? "owns" : "seen_on" });
    }
  }

  // Extracted users from file paths -> devices
  users.filter(u => !userMap[u.key]).forEach(u => {
    const devId = (u.raw.devices || [])[0];
    if (devId && nodeById["d:" + devId]) {
      addEdge({ from: u.id, to: "d:" + devId, kind: "seen_on" });
    }
  });

  // Lateral movement
  for (const [uname, cu] of Object.entries(report.correlated_users || {})) {
    for (const ind of (cu && cu.lateral_movement_indicators) || []) {
      const a = "d:" + ind.from_device;
      const b = "d:" + ind.to_device;
      if (nodeById[a] && nodeById[b]) {
        addEdge({ from: a, to: b, kind: "lateral", via: uname, method: ind.method });
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
          flag: flag.summary,
        });
      }
    });
  });

  // Findings -> Device edges
  findingsItems.forEach(f => {
    if (f.kind === "finding" && f.deviceId && nodeById["d:" + f.deviceId]) {
      addEdge({ from: f.id, to: "d:" + f.deviceId, kind: "has_finding", flagType: f.flagType });
    }
    if (f.kind === "mitre") {
      // Connect MITRE techniques to devices with related flags
      Object.entries(flagsByDevice).forEach(([devId, flags]) => {
        (flags || []).forEach(flag => {
          if (flag.mitre_techniques && flag.mitre_techniques.some(t => t.id === f.techniqueId)) {
            addEdge({ from: f.id, to: "d:" + devId, kind: "mitre_technique", techniqueId: f.techniqueId });
          }
        });
      });
    }
    if (f.kind === "ioc") {
      // Connect IOCs to devices
      Object.entries(flagsByDevice).forEach(([devId, flags]) => {
        (flags || []).forEach(flag => {
          const evidence = flag.evidence || {};
          const iocMatch = (
            evidence.dst_ip === f.raw ||
            evidence.dst_host === f.raw ||
            evidence.hash === f.raw ||
            evidence.file_path === f.raw
          );
          if (iocMatch && nodeById["d:" + devId]) {
            addEdge({ from: "d:" + devId, to: f.id, kind: "ioc" });
          }
        });
      });
    }
  });

  return { nodes, edges, nodeById, columns, totalH };
}

function RelationshipGraph({ report, selected, onSelect, hoverId, onHover, sevFilter }) {
  const wrapRef = useRef(null);
  const [size, setSize] = useState({ w: 900, h: 600 });
  const svgRef = useRef(null);

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

  // Initialize D3 zoom after render
  useEffect(() => {
    if (!svgRef.current || !window.d3) return;
    const svg = window.d3.select(svgRef.current);
    const zoom = window.d3.zoom()
      .scaleExtent([0.1, 4])
      .on("zoom", (event) => {
        svg.selectAll("g.graph-content").attr("transform", event.transform);
      });
    svg.call(zoom);
    // Double-click to reset zoom
    svg.on("dblclick.zoom", () => {
      svg.transition().duration(500).call(zoom.transform, window.d3.zoomIdentity);
    });
    
  }, [graph]);

  return (
    <div ref={wrapRef} className="graph-stage">
      <svg
        ref={svgRef}
        className="graph-svg"
        width="100%"
        height={graph.totalH}
        viewBox={`0 0 ${size.w} ${graph.totalH}`}
        preserveAspectRatio="xMidYMin meet"
      >
        <g className="graph-content">
          {/* Column headers + rules */}
          {graph.columns.map((col) => (
            <g key={col.key}>
              <text className="col-header" x={col.x} y={28} textAnchor="middle">
                {col.label.toUpperCase()} · {col.count}
              </text>
              <line className="col-rule" x1={col.x} y1={44} x2={col.x} y2={graph.totalH - 16} />
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
              if (e.kind === "owns") cls += " owns";
              else if (e.kind === "seen_on") cls += " seen-on";
              else if (e.kind === "lateral") cls += " lateral";
              else if (e.kind === "exfiltrated_to") cls += " exfil";
              else if (e.kind === "has_finding") cls += " finding-link";
              else if (e.kind === "mitre_technique") cls += " mitre-link";
              else if (e.kind === "ioc") cls += " ioc";
              if (hl) cls += " highlighted";
              if (dim) cls += " dimmed";
              return (
                <path key={i} className={cls} d={d}>
                  <title>{describeEdge(e, n1, n2)}</title>
                </path>
              );
            })}
          </g>

          {/* Nodes */}
          <g>
            {graph.nodes.map((n) => {
              const isSel = selected === n.id;
              const isHover = hoverId === n.id;
              const inNbhd = neighbors && neighbors.has(n.id);
              const sevDim = sevMatch && (n.kind === "user" || n.kind === "pc" || n.kind === "server" || n.kind === "mobile" || n.kind === "network") && !sevMatch.has(n.id);
              const dim = (neighbors && !inNbhd) || sevDim;
              let cls = "node node-" + n.kind;
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
                  <title>{describeNode(n, report)}</title>
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
                  ) : n.kind === "finding" ? (
                    <rect
                      x={-n.w / 2} y={-n.h / 2}
                      width={n.w} height={n.h} rx={8}
                      fill="rgba(245,158,11,0.15)"
                      stroke={n.accent}
                      strokeWidth={isSel ? 2 : 1}
                      strokeDasharray="4 2"
                    />
                  ) : n.kind === "service" ? (
                    <rect
                      x={-n.w / 2} y={-n.h / 2}
                      width={n.w} height={n.h} rx={12}
                      fill="rgba(236,72,153,0.1)"
                      stroke={n.accent}
                      strokeWidth={isSel ? 2 : 1}
                    />
                  ) : n.kind === "mitre" ? (
                    <rect
                      x={-n.w / 2} y={-n.h / 2}
                      width={n.w} height={n.h} rx={4}
                      fill="rgba(239,68,68,0.15)"
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
                  {n.badge && (
                    <g transform={`translate(${n.kind === "user" ? n.r - 4 : n.w / 2 - 6}, ${n.kind === "user" ? -n.r + 4 : -n.h / 2 + 6})`}>
                      <circle r={8} className={`flag-badge ${n.badge.sev === "CRITICAL" ? "crit" : n.badge.sev === "HIGH" ? "high" : ""}`} />
                      <text className="flag-badge-text">{n.badge.count}</text>
                    </g>
                  )}
                </g>
              );
            })}
          </g>
        </g>
      </svg>
    </div>
  );
}

window.RelationshipGraph = RelationshipGraph;
window.classifyDevice = classifyDevice;
window.countFlags = countFlags;
window.maxSev = maxSev;
window.aggregateUserFlags = aggregateUserFlags;
window.osLabel = osLabel;
window.extractUsernameFromPath = extractUsernameFromPath;
window.buildFindingsItems = buildFindingsItems;
