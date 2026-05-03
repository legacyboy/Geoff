(function() {
// Left-pane entity tree + filter chips.

function EntityTree({
  report,
  selected,
  onSelect,
  search,
  setSearch,
  sevFilter,
  setSevFilter
}) {
  const users = Object.entries(report.user_map || {});
  const devices = Object.entries(report.device_map || {});
  const q = (search || "").toLowerCase().trim();
  const matches = s => !q || (s || "").toLowerCase().includes(q);

  // Whole-finding text search — JSON-stringify each device's flags so a query
  // like "185.243" or a hash matches anything captured in evidence fields.
  const deviceFlagText = devId => {
    const flags = (report.behavioral_flags || {})[devId] || [];
    if (!flags.length) return "";
    return JSON.stringify(flags).toLowerCase();
  };
  const matchesDevice = (devId, dev) => {
    if (!q) return true;
    if (matches(devId) || matches(dev.hostname) || matches(dev.owner)) return true;
    return deviceFlagText(devId).includes(q);
  };
  const matchesUser = (uname, u) => {
    if (!q) return true;
    if (matches(uname) || matches(u.display_name) || matches((u.aliases || []).join(" "))) return true;
    // user matches if any of their devices match (e.g., user owns device that has the IOC)
    return (u.devices || []).some(d => {
      const dev = (report.device_map || {})[d];
      return dev && matchesDevice(d, dev);
    });
  };
  const passSev = flagsArr => {
    if (!sevFilter) return true;
    return (flagsArr || []).some(f => f.severity === sevFilter);
  };

  // Group devices
  const groups = [{
    label: "Workstations",
    items: devices.filter(([, d]) => classifyDevice(d) === "pc")
  }, {
    label: "Servers",
    items: devices.filter(([, d]) => classifyDevice(d) === "server")
  }, {
    label: "Mobile",
    items: devices.filter(([, d]) => classifyDevice(d) === "mobile")
  }, {
    label: "Network",
    items: devices.filter(([, d]) => classifyDevice(d) === "network")
  }];

  // Derive Services from exfil/c2 flags (matches what graph.js does)
  const serviceMap = new Map();
  Object.entries(report.behavioral_flags || {}).forEach(([devId, flags]) => {
    (flags || []).forEach(flag => {
      if (flag.flag_type !== "exfiltration" && flag.flag_type !== "c2_traffic") return;
      const dst = (flag.evidence || {}).dst_host || (flag.evidence || {}).dst_ip || "";
      if (!dst) return;
      const svc = window.classifyExfilService && window.classifyExfilService(dst) || "External";
      if (!serviceMap.has(svc)) serviceMap.set(svc, {
        name: svc,
        hits: 0
      });
      serviceMap.get(svc).hits++;
    });
  });
  const services = Array.from(serviceMap.values());

  // Derive Evidence types (matches graph.js bucketing)
  const evidenceTypes = new Map();
  Object.entries(report.device_map || {}).forEach(([devId, dev]) => {
    const declared = dev && dev.evidence_types || [];
    const files = dev && dev.evidence_files || [];
    declared.forEach(t => {
      if (!evidenceTypes.has(t)) evidenceTypes.set(t, {
        type: t,
        files: 0,
        devs: new Set()
      });
      evidenceTypes.get(t).devs.add(devId);
    });
    files.forEach(fp => {
      const guessed = window.guessEvidenceTypeFromPath && window.guessEvidenceTypeFromPath(fp) || declared[0] || "other";
      if (!evidenceTypes.has(guessed)) evidenceTypes.set(guessed, {
        type: guessed,
        files: 0,
        devs: new Set()
      });
      evidenceTypes.get(guessed).files++;
      evidenceTypes.get(guessed).devs.add(devId);
    });
  });
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "pane-header"
  }, /*#__PURE__*/React.createElement("span", null, "Entities"), /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, users.length + devices.length + services.length + evidenceTypes.size)), /*#__PURE__*/React.createElement("div", {
    className: "search-box"
  }, /*#__PURE__*/React.createElement("input", {
    id: "entity-search",
    placeholder: "Search accounts, hosts, IOCs, findings\u2026",
    value: search,
    onChange: e => setSearch(e.target.value)
  })), /*#__PURE__*/React.createElement("div", {
    className: "filter-row"
  }, ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => /*#__PURE__*/React.createElement("button", {
    key: s,
    className: `filter-chip ${sevFilter === s ? "active" : ""}`,
    onClick: () => setSevFilter(sevFilter === s ? null : s)
  }, s))), /*#__PURE__*/React.createElement("div", {
    className: "entity-tree"
  }, /*#__PURE__*/React.createElement("div", {
    className: "tree-group"
  }, /*#__PURE__*/React.createElement("div", {
    className: "tree-group-label"
  }, /*#__PURE__*/React.createElement("span", null, "Accounts"), /*#__PURE__*/React.createElement("span", {
    className: "line"
  }), /*#__PURE__*/React.createElement("span", null, users.length)), users.filter(([k, u]) => matchesUser(k, u) && passSev(userFlagsAgg(report, k))).map(([k, u]) => {
    const counts = aggregateUserFlags(report, k);
    const sev = maxSev(counts);
    return /*#__PURE__*/React.createElement("div", {
      key: k,
      className: `tree-item ${selected === "u:" + k ? "active" : ""}`,
      onClick: () => onSelect("u:" + k),
      title: `@${k}${u.role ? " · " + u.role : ""}${counts.total ? " · " + counts.total + " findings" : ""}`
    }, /*#__PURE__*/React.createElement("span", {
      className: "bullet user"
    }), /*#__PURE__*/React.createElement("span", {
      className: "label"
    }, u.display_name || k), counts.total > 0 && /*#__PURE__*/React.createElement("span", {
      className: `flag-count ${sev === "CRITICAL" ? "crit" : sev === "HIGH" ? "high" : ""}`
    }, counts.total));
  })), groups.map(g => {
    const items = g.items.filter(([k, d]) => matchesDevice(k, d) && passSev((report.behavioral_flags || {})[k] || []));
    if (items.length === 0) return null;
    return /*#__PURE__*/React.createElement("div", {
      className: "tree-group",
      key: g.label
    }, /*#__PURE__*/React.createElement("div", {
      className: "tree-group-label"
    }, /*#__PURE__*/React.createElement("span", null, g.label), /*#__PURE__*/React.createElement("span", {
      className: "line"
    }), /*#__PURE__*/React.createElement("span", null, items.length)), items.map(([k, d]) => {
      const counts = countFlags((report.behavioral_flags || {})[k] || []);
      const sev = maxSev(counts);
      const kind = classifyDevice(d);
      return /*#__PURE__*/React.createElement("div", {
        key: k,
        className: `tree-item ${selected === "d:" + k ? "active" : ""}`,
        onClick: () => onSelect("d:" + k),
        title: `${d.hostname || k} · ${osLabel(d)}${d.owner ? " · owner " + d.owner : ""}`
      }, /*#__PURE__*/React.createElement("span", {
        className: `bullet ${kind}`
      }), /*#__PURE__*/React.createElement("span", {
        className: "label"
      }, d.hostname || k), counts.total > 0 && /*#__PURE__*/React.createElement("span", {
        className: `flag-count ${sev === "CRITICAL" ? "crit" : sev === "HIGH" ? "high" : ""}`
      }, counts.total));
    }));
  }), services.length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "tree-group"
  }, /*#__PURE__*/React.createElement("div", {
    className: "tree-group-label"
  }, /*#__PURE__*/React.createElement("span", null, "Services"), /*#__PURE__*/React.createElement("span", {
    className: "line"
  }), /*#__PURE__*/React.createElement("span", null, services.length)), services.filter(s => matches(s.name)).map(s => /*#__PURE__*/React.createElement("div", {
    key: s.name,
    className: `tree-item ${selected === "s:" + s.name ? "active" : ""}`,
    onClick: () => onSelect("s:" + s.name),
    title: `External service · ${s.hits} flagged connection(s)`
  }, /*#__PURE__*/React.createElement("span", {
    className: "bullet service"
  }), /*#__PURE__*/React.createElement("span", {
    className: "label"
  }, s.name), /*#__PURE__*/React.createElement("span", {
    className: "flag-count high"
  }, s.hits)))), evidenceTypes.size > 0 && /*#__PURE__*/React.createElement("div", {
    className: "tree-group"
  }, /*#__PURE__*/React.createElement("div", {
    className: "tree-group-label"
  }, /*#__PURE__*/React.createElement("span", null, "Evidence"), /*#__PURE__*/React.createElement("span", {
    className: "line"
  }), /*#__PURE__*/React.createElement("span", null, evidenceTypes.size)), Array.from(evidenceTypes.values()).filter(b => matches(b.type) || matches(window.formatEvidenceType ? window.formatEvidenceType(b.type) : b.type)).map(b => /*#__PURE__*/React.createElement("div", {
    key: b.type,
    className: `tree-item ${selected === "e:" + b.type ? "active" : ""}`,
    onClick: () => onSelect("e:" + b.type),
    title: `${b.files} file(s) across ${b.devs.size} device(s)`
  }, /*#__PURE__*/React.createElement("span", {
    className: "bullet evidence"
  }), /*#__PURE__*/React.createElement("span", {
    className: "label"
  }, (window.formatEvidenceType || (s => s))(b.type)), /*#__PURE__*/React.createElement("span", {
    className: "flag-count"
  }, b.files || b.devs.size))))));
}
function userFlagsAgg(report, username) {
  const u = (report.user_map || {})[username];
  if (!u) return [];
  const all = [];
  for (const d of u.devices || []) {
    for (const f of (report.behavioral_flags || {})[d] || []) all.push(f);
  }
  return all;
}
window.EntityTree = EntityTree;

})();
