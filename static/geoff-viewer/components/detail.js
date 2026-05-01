(function() {
// Right-side detail panel — renders context-appropriate view for:
// selected user, selected device, or case overview (no selection).

const {
  Fragment
} = React;
function DetailPanel({
  report,
  selected,
  onSelect
}) {
  if (!selected) return /*#__PURE__*/React.createElement(CaseOverview, {
    report: report,
    onSelect: onSelect
  });
  if (selected.startsWith("u:")) {
    return /*#__PURE__*/React.createElement(UserDetail, {
      report: report,
      username: selected.slice(2),
      onSelect: onSelect
    });
  }
  if (selected.startsWith("d:")) {
    return /*#__PURE__*/React.createElement(DeviceDetail, {
      report: report,
      deviceId: selected.slice(2),
      onSelect: onSelect
    });
  }
  if (selected.startsWith("e:")) {
    return /*#__PURE__*/React.createElement(EvidenceDetail, {
      report: report,
      evidenceType: selected.slice(2),
      onSelect: onSelect
    });
  }
  if (selected.startsWith("s:")) {
    return /*#__PURE__*/React.createElement(ServiceDetail, {
      report: report,
      serviceName: selected.slice(2),
      onSelect: onSelect
    });
  }
  return null;
}
function EvidenceDetail({
  report,
  evidenceType,
  onSelect
}) {
  const devices = Object.entries(report.device_map || {});
  const matchingDevs = devices.filter(([, d]) => (d.evidence_types || []).includes(evidenceType));
  const files = [];
  devices.forEach(([devId, d]) => {
    (d.evidence_files || []).forEach(fp => {
      const guessed = window.guessEvidenceTypeFromPath && window.guessEvidenceTypeFromPath(fp) || (d.evidence_types || [])[0];
      if (guessed === evidenceType) files.push({
        path: fp,
        devId
      });
    });
  });
  // Devices contributing to this bucket = either declared the type or own a matching file
  const devIdSet = new Set(matchingDevs.map(([k]) => k));
  files.forEach(f => devIdSet.add(f.devId));
  return /*#__PURE__*/React.createElement("div", {
    className: "detail-scroll"
  }, /*#__PURE__*/React.createElement("div", {
    className: "entity-head"
  }, /*#__PURE__*/React.createElement("div", {
    className: "glyph",
    style: {
      background: "rgba(6,182,212,0.1)",
      color: "#06B6D4",
      border: "1px solid rgba(6,182,212,0.3)"
    }
  }, "\u25EB"), /*#__PURE__*/React.createElement("div", {
    className: "title-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kind"
  }, "Evidence type"), /*#__PURE__*/React.createElement("div", {
    className: "title"
  }, (window.formatEvidenceType || (s => s))(evidenceType)), /*#__PURE__*/React.createElement("div", {
    className: "sub"
  }, files.length, " file", files.length === 1 ? "" : "s", " across ", devIdSet.size, " device", devIdSet.size === 1 ? "" : "s"))), /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Source devices ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, devIdSet.size)), /*#__PURE__*/React.createElement("div", {
    className: "related-list"
  }, Array.from(devIdSet).map(devId => {
    const dev = (report.device_map || {})[devId];
    if (!dev) return null;
    const kind = classifyDevice(dev);
    return /*#__PURE__*/React.createElement("div", {
      key: devId,
      className: "related-item",
      onClick: () => onSelect("d:" + devId)
    }, /*#__PURE__*/React.createElement("span", {
      className: `bullet ${kind}`
    }), /*#__PURE__*/React.createElement("span", {
      className: "name"
    }, dev.hostname || devId), /*#__PURE__*/React.createElement("span", {
      className: "via"
    }, osLabel(dev)));
  }))), /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Files ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, files.length)), files.length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "empty",
    style: {
      padding: "12px 0"
    }
  }, "No individual files matched this type heuristic \u2014 devices declare it but evidence_files is empty or extension-less.") : files.map((f, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "evfile",
    title: f.path
  }, /*#__PURE__*/React.createElement("span", {
    className: "type-tag"
  }, extType(f.path)), /*#__PURE__*/React.createElement("span", {
    style: {
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap",
      flex: 1
    }
  }, f.path), /*#__PURE__*/React.createElement("span", {
    className: "via",
    style: {
      fontSize: 10,
      color: "var(--g-text-mute)"
    }
  }, f.devId)))));
}
function ServiceDetail({
  report,
  serviceName,
  onSelect
}) {
  // Reconstruct service nodes' contributing devices and traffic flags.
  const hits = []; // { devId, host, flag }
  Object.entries(report.behavioral_flags || {}).forEach(([devId, flags]) => {
    (flags || []).forEach(flag => {
      if (flag.flag_type !== "exfiltration" && flag.flag_type !== "c2_traffic") return;
      const dst = (flag.evidence || {}).dst_host || (flag.evidence || {}).dst_ip || "";
      if (!dst) return;
      const svc = window.classifyExfilService && window.classifyExfilService(dst) || "External";
      if (svc === serviceName) hits.push({
        devId,
        host: dst,
        flag
      });
    });
  });
  const devSet = new Set(hits.map(h => h.devId));
  return /*#__PURE__*/React.createElement("div", {
    className: "detail-scroll"
  }, /*#__PURE__*/React.createElement("div", {
    className: "entity-head"
  }, /*#__PURE__*/React.createElement("div", {
    className: "glyph",
    style: {
      background: "rgba(236,72,153,0.1)",
      color: "#EC4899",
      border: "1px solid rgba(236,72,153,0.3)"
    }
  }, "\u2197"), /*#__PURE__*/React.createElement("div", {
    className: "title-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kind"
  }, "External service"), /*#__PURE__*/React.createElement("div", {
    className: "title"
  }, serviceName), /*#__PURE__*/React.createElement("div", {
    className: "sub"
  }, hits.length, " flagged connection", hits.length === 1 ? "" : "s", " from ", devSet.size, " device", devSet.size === 1 ? "" : "s"))), /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Source devices ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, devSet.size)), /*#__PURE__*/React.createElement("div", {
    className: "related-list"
  }, Array.from(devSet).map(devId => {
    const dev = (report.device_map || {})[devId];
    if (!dev) return null;
    const kind = classifyDevice(dev);
    return /*#__PURE__*/React.createElement("div", {
      key: devId,
      className: "related-item",
      onClick: () => onSelect("d:" + devId)
    }, /*#__PURE__*/React.createElement("span", {
      className: `bullet ${kind}`
    }), /*#__PURE__*/React.createElement("span", {
      className: "name"
    }, dev.hostname || devId), /*#__PURE__*/React.createElement("span", {
      className: "via"
    }, osLabel(dev)));
  }))), /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Connections ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, hits.length)), hits.map((h, i) => /*#__PURE__*/React.createElement(FindingCard, {
    key: i,
    f: {
      ...h.flag,
      device_id: h.devId
    },
    showDevice: true
  }))));
}
function CaseOverview({
  report,
  onSelect
}) {
  const devCount = Object.keys(report.device_map || {}).length;
  const userCount = Object.keys(report.user_map || {}).length;
  let allFlags = 0,
    crit = 0,
    high = 0;
  for (const flags of Object.values(report.behavioral_flags || {})) {
    for (const f of flags) {
      allFlags++;
      if (f.severity === "CRITICAL") crit++;else if (f.severity === "HIGH") high++;
    }
  }
  const lateral = Object.values(report.correlated_users || {}).reduce((acc, u) => acc + (u.lateral_movement_indicators || []).length, 0);
  return /*#__PURE__*/React.createElement("div", {
    className: "detail-scroll"
  }, /*#__PURE__*/React.createElement("div", {
    className: "entity-head"
  }, /*#__PURE__*/React.createElement("div", {
    className: "glyph pc",
    style: {
      fontFamily: "var(--font-mono)"
    }
  }, "\u25C7"), /*#__PURE__*/React.createElement("div", {
    className: "title-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kind"
  }, "Case overview"), /*#__PURE__*/React.createElement("div", {
    className: "title"
  }, report.case_id || "—"), /*#__PURE__*/React.createElement("div", {
    className: "sub"
  }, report.title || ""))), /*#__PURE__*/React.createElement("div", {
    className: "overview-grid"
  }, /*#__PURE__*/React.createElement("div", {
    className: "metric"
  }, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Devices"), /*#__PURE__*/React.createElement("div", {
    className: "v"
  }, devCount)), /*#__PURE__*/React.createElement("div", {
    className: "metric"
  }, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Accounts"), /*#__PURE__*/React.createElement("div", {
    className: "v"
  }, userCount)), /*#__PURE__*/React.createElement("div", {
    className: `metric ${crit ? "crit" : high ? "high" : "ok"}`
  }, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Findings"), /*#__PURE__*/React.createElement("div", {
    className: "v"
  }, allFlags)), /*#__PURE__*/React.createElement("div", {
    className: `metric ${lateral ? "high" : ""}`
  }, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Lateral moves"), /*#__PURE__*/React.createElement("div", {
    className: "v"
  }, lateral))), /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Severity ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, report.severity || "INFO")), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--g-text-dim)",
      fontSize: 12,
      lineHeight: 1.55
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(SeverityChip, {
    sev: "CRITICAL"
  }), " ", crit, " critical finding", crit === 1 ? "" : "s"), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 4
    }
  }, /*#__PURE__*/React.createElement(SeverityChip, {
    sev: "HIGH"
  }), " ", high, " high-severity"), report.evil_found && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 10,
      color: "var(--g-red)",
      fontWeight: 500
    }
  }, "\u26A0 evil_found = true \u2014 compromise confirmed"))), /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Timeline ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, (report.timeline || []).length)), /*#__PURE__*/React.createElement(TimelineMini, {
    events: report.timeline || []
  })), /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Select an entity"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11.5,
      color: "var(--g-text-mute)",
      lineHeight: 1.55
    }
  }, "Click a node in the graph or an item in the left tree to see its evidence, related entities, and findings.")));
}
function SeverityChip({
  sev
}) {
  return /*#__PURE__*/React.createElement("span", {
    className: `sev-chip sev-${sev}`
  }, sev);
}
function TimelineMini({
  events
}) {
  const sorted = [...events].sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      borderLeft: "1px solid var(--g-border-soft)",
      marginLeft: 6
    }
  }, sorted.slice(0, 12).map((e, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      position: "relative",
      paddingLeft: 14,
      paddingBottom: 8
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      left: -4,
      top: 4,
      width: 8,
      height: 8,
      borderRadius: 2,
      background: sevColor(e.severity)
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10,
      color: "var(--g-text-mute)"
    }
  }, fmtTs(e.timestamp), " \xB7 ", e.device_id), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11.5,
      color: "var(--g-text)"
    }
  }, e.summary))));
}
function sevColor(s) {
  return {
    CRITICAL: "var(--sev-crit)",
    HIGH: "var(--sev-high)",
    MEDIUM: "var(--sev-med)",
    LOW: "var(--sev-low)",
    INFO: "var(--sev-info)"
  }[s] || "var(--sev-info)";
}
function fmtTs(ts) {
  if (!ts) return "—";
  return ts.replace("T", " ").replace("Z", "");
}
function UserDetail({
  report,
  username,
  onSelect
}) {
  const u = (report.user_map || {})[username];
  if (!u) return /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, "User not found");
  const cu = (report.correlated_users || {})[username] || {};
  const devices = u.devices || [];

  // All flags on their devices
  const flags = [];
  for (const d of devices) {
    for (const f of (report.behavioral_flags || {})[d] || []) {
      flags.push({
        ...f,
        device_id: d
      });
    }
  }
  flags.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
  const profile = cu.activity_profile || {};
  return /*#__PURE__*/React.createElement("div", {
    className: "detail-scroll"
  }, /*#__PURE__*/React.createElement("div", {
    className: "entity-head"
  }, /*#__PURE__*/React.createElement("div", {
    className: "glyph user"
  }, (u.display_name || username).charAt(0).toUpperCase()), /*#__PURE__*/React.createElement("div", {
    className: "title-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kind"
  }, "Account"), /*#__PURE__*/React.createElement("div", {
    className: "title"
  }, u.display_name || username), /*#__PURE__*/React.createElement("div", {
    className: "sub"
  }, "@", username, " \xB7 ", u.role || "user", /*#__PURE__*/React.createElement("span", {
    className: `conf conf-${u.confidence}`
  }, u.confidence)))), /*#__PURE__*/React.createElement("div", {
    className: "meta-grid"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Aliases"), /*#__PURE__*/React.createElement("div", {
    className: "v dim"
  }, (u.aliases || []).join(", ") || "—")), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Primary"), /*#__PURE__*/React.createElement("div", {
    className: "v"
  }, u.primary_device || "—")), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "First seen"), /*#__PURE__*/React.createElement("div", {
    className: "v dim"
  }, fmtTs(profile.first_seen))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Last seen"), /*#__PURE__*/React.createElement("div", {
    className: "v dim"
  }, fmtTs(profile.last_seen))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Events"), /*#__PURE__*/React.createElement("div", {
    className: "v"
  }, (profile.total_events || 0).toLocaleString())), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Active hours"), /*#__PURE__*/React.createElement("div", {
    className: "v dim"
  }, hoursRange(profile.typical_hours)))), /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Devices ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, devices.length)), /*#__PURE__*/React.createElement("div", {
    className: "related-list"
  }, devices.map(d => {
    const dev = (report.device_map || {})[d];
    if (!dev) return null;
    const kind = classifyDevice(dev);
    return /*#__PURE__*/React.createElement("div", {
      key: d,
      className: "related-item",
      onClick: () => onSelect("d:" + d)
    }, /*#__PURE__*/React.createElement("span", {
      className: `bullet ${kind}`
    }), /*#__PURE__*/React.createElement("span", {
      className: "name"
    }, dev.hostname || d), /*#__PURE__*/React.createElement("span", {
      className: "via"
    }, osLabel(dev)));
  }))), (cu.lateral_movement_indicators || []).length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Lateral movement ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, cu.lateral_movement_indicators.length)), cu.lateral_movement_indicators.map((l, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "finding sev-HIGH"
  }, /*#__PURE__*/React.createElement("div", {
    className: "finding-head"
  }, /*#__PURE__*/React.createElement("span", {
    className: "sev-chip sev-HIGH"
  }, "LATERAL"), /*#__PURE__*/React.createElement("span", {
    className: "finding-ts"
  }, fmtTs(l.timestamp))), /*#__PURE__*/React.createElement("div", {
    className: "finding-summary"
  }, l.from_device, " \u2192 ", l.to_device), /*#__PURE__*/React.createElement("div", {
    className: "finding-expl"
  }, l.method)))), (cu.anomalies || []).length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Anomalies ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, cu.anomalies.length)), cu.anomalies.map((a, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      fontSize: 11.5,
      color: "var(--g-text-dim)",
      padding: "4px 0",
      borderBottom: "1px dashed var(--g-border-soft)"
    }
  }, a))), /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Findings across devices ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, flags.length)), flags.length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "empty",
    style: {
      padding: "12px 0"
    }
  }, "No behavioral flags attributed.") : flags.map((f, i) => /*#__PURE__*/React.createElement(FindingCard, {
    key: i,
    f: f,
    showDevice: true
  }))), (profile.common_applications || []).length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Top applications"), (profile.common_applications || []).slice(0, 6).map(([name, count]) => /*#__PURE__*/React.createElement("div", {
    key: name,
    className: "evfile"
  }, /*#__PURE__*/React.createElement("span", {
    className: "type-tag"
  }, count), /*#__PURE__*/React.createElement("span", null, name)))));
}
function DeviceDetail({
  report,
  deviceId,
  onSelect
}) {
  const d = (report.device_map || {})[deviceId];
  if (!d) return /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, "Device not found");
  const kind = classifyDevice(d);
  const flags = [...((report.behavioral_flags || {})[deviceId] || [])];
  flags.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));

  // Related users (owner + anyone with this in their devices)
  const relatedUsers = [];
  for (const [uname, u] of Object.entries(report.user_map || {})) {
    if ((u.devices || []).includes(deviceId)) relatedUsers.push(uname);
  }

  // Timeline events tagged with this device
  const events = (report.timeline || []).filter(e => e.device_id === deviceId);
  return /*#__PURE__*/React.createElement("div", {
    className: "detail-scroll"
  }, /*#__PURE__*/React.createElement("div", {
    className: "entity-head"
  }, /*#__PURE__*/React.createElement("div", {
    className: `glyph ${kind}`
  }, kind === "server" ? "⌬" : kind === "mobile" ? "▯" : kind === "network" ? "≈" : "▣"), /*#__PURE__*/React.createElement("div", {
    className: "title-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kind"
  }, deviceTypeLabel(d)), /*#__PURE__*/React.createElement("div", {
    className: "title"
  }, d.hostname || d.device_id), /*#__PURE__*/React.createElement("div", {
    className: "sub"
  }, osLabel(d), d.owner && /*#__PURE__*/React.createElement("span", {
    className: `conf conf-${d.owner_confidence}`
  }, d.owner_confidence)))), /*#__PURE__*/React.createElement("div", {
    className: "meta-grid"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Device ID"), /*#__PURE__*/React.createElement("div", {
    className: "v"
  }, d.device_id)), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Owner"), /*#__PURE__*/React.createElement("div", {
    className: "v"
  }, d.owner || "—")), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "First seen"), /*#__PURE__*/React.createElement("div", {
    className: "v dim"
  }, fmtTs(d.first_seen))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Last seen"), /*#__PURE__*/React.createElement("div", {
    className: "v dim"
  }, fmtTs(d.last_seen))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Discovery"), /*#__PURE__*/React.createElement("div", {
    className: "v dim"
  }, (d.discovery_method || "").replace(/_/g, " "))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "k"
  }, "Evidence types"), /*#__PURE__*/React.createElement("div", {
    className: "v dim"
  }, (d.evidence_types || []).length))), relatedUsers.length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Associated accounts ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, relatedUsers.length)), /*#__PURE__*/React.createElement("div", {
    className: "related-list"
  }, relatedUsers.map(uname => {
    const u = (report.user_map || {})[uname];
    const isOwner = d.owner === uname;
    return /*#__PURE__*/React.createElement("div", {
      key: uname,
      className: "related-item",
      onClick: () => onSelect("u:" + uname)
    }, /*#__PURE__*/React.createElement("span", {
      className: "bullet user"
    }), /*#__PURE__*/React.createElement("span", {
      className: "name"
    }, u?.display_name || uname), /*#__PURE__*/React.createElement("span", {
      className: "via"
    }, isOwner ? "owner" : "seen here"));
  }))), /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Findings ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, flags.length)), flags.length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "empty",
    style: {
      padding: "12px 0"
    }
  }, "No behavioral flags.") : flags.map((f, i) => /*#__PURE__*/React.createElement(FindingCard, {
    key: i,
    f: f
  }))), events.length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Events on this device ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, events.length)), /*#__PURE__*/React.createElement(TimelineMini, {
    events: events
  })), /*#__PURE__*/React.createElement("div", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-title"
  }, "Evidence files ", /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, (d.evidence_files || []).length)), (d.evidence_files || []).map((f, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "evfile",
    title: f
  }, /*#__PURE__*/React.createElement("span", {
    className: "type-tag"
  }, extType(f)), /*#__PURE__*/React.createElement("span", {
    style: {
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap"
    }
  }, f)))));
}
function FindingCard({
  f,
  showDevice
}) {
  const [open, setOpen] = React.useState(false);
  return /*#__PURE__*/React.createElement("div", {
    className: `finding sev-${f.severity}`,
    onClick: () => setOpen(!open)
  }, /*#__PURE__*/React.createElement("div", {
    className: "finding-head"
  }, /*#__PURE__*/React.createElement("span", {
    className: `sev-chip sev-${f.severity}`
  }, f.severity), /*#__PURE__*/React.createElement("span", {
    className: "finding-type"
  }, f.flag_type), /*#__PURE__*/React.createElement("span", {
    className: "finding-ts"
  }, fmtTs(f.timestamp))), showDevice && /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10,
      color: "var(--g-text-mute)",
      marginBottom: 4
    }
  }, "on ", f.device_id), /*#__PURE__*/React.createElement("div", {
    className: "finding-summary"
  }, f.summary), /*#__PURE__*/React.createElement("div", {
    className: "finding-expl"
  }, f.explanation), open && f.evidence && /*#__PURE__*/React.createElement("div", {
    className: "finding-evidence"
  }, Object.entries(f.evidence).map(([k, v]) => /*#__PURE__*/React.createElement(Fragment, {
    key: k
  }, /*#__PURE__*/React.createElement("div", {
    className: "ek"
  }, k), /*#__PURE__*/React.createElement("div", {
    className: "ev"
  }, String(v).length > 180 ? String(v).slice(0, 180) + "…" : String(v))))), (f.mitre_att_ck || []).length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "finding-mitre"
  }, f.mitre_att_ck.map(t => /*#__PURE__*/React.createElement("span", {
    key: t,
    className: "mitre-tag"
  }, t))));
}
function sevRank(s) {
  return {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4
  }[s] ?? 5;
}
function hoursRange(h) {
  if (!h || !h.length) return "—";
  return `${String(Math.min(...h)).padStart(2, "0")}:00–${String(Math.max(...h)).padStart(2, "0")}:59`;
}
function deviceTypeLabel(d) {
  const t = (d.device_type || "device").replace(/_/g, " ");
  return t;
}
function extType(path) {
  const m = path.match(/\.([^./\\]+)$/);
  if (m) return m[1].toLowerCase();
  if (path.endsWith("/")) return "dir";
  return "file";
}
window.DetailPanel = DetailPanel;
window.FindingCard = FindingCard;
window.fmtTs = fmtTs;
window.sevRank = sevRank;

})();
