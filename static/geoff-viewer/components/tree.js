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
  const passSev = flagsArr => {
    if (!sevFilter) return true;
    return (flagsArr || []).some(f => f.severity === sevFilter);
  };

  // Group devices
  const groups = [{
    label: "Workstations",
    items: devices.filter(([, d]) => window.classifyDevice(d) === "pc")
  }, {
    label: "Servers",
    items: devices.filter(([, d]) => window.classifyDevice(d) === "server")
  }, {
    label: "Mobile",
    items: devices.filter(([, d]) => window.classifyDevice(d) === "mobile")
  }, {
    label: "Network",
    items: devices.filter(([, d]) => window.classifyDevice(d) === "network")
  }];
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "pane-header"
  }, /*#__PURE__*/React.createElement("span", null, "Entities"), /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, users.length + devices.length)), /*#__PURE__*/React.createElement("div", {
    className: "search-box"
  }, /*#__PURE__*/React.createElement("input", {
    placeholder: "Search accounts, hosts, IOCs\u2026",
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
  }), /*#__PURE__*/React.createElement("span", null, users.length)), users.filter(([k, u]) => {
    if (!matches(k) && !matches(u.display_name) && !matches((u.aliases || []).join(" "))) return false;
    return passSev(window.aggregateUserFlags(report, k));
  }).map(([k, u]) => {
    const counts = window.aggregateUserFlags(report, k);
    const sev = window.maxSev(counts);
    return /*#__PURE__*/React.createElement("div", {
      key: k,
      className: `tree-item ${selected === "u:" + k ? "active" : ""}`,
      onClick: () => onSelect("u:" + k)
    }, /*#__PURE__*/React.createElement("span", {
      className: "bullet user"
    }), /*#__PURE__*/React.createElement("span", {
      className: "label"
    }, u.display_name || k), counts.total > 0 && /*#__PURE__*/React.createElement("span", {
      className: `flag-count ${sev === "CRITICAL" ? "crit" : sev === "HIGH" ? "high" : ""}`
    }, counts.total));
  })), groups.map(g => {
    const items = g.items.filter(([k, d]) => {
      if (!matches(k) && !matches(d.hostname) && !matches(d.owner)) return false;
      return passSev((report.behavioral_flags || {})[k] || []);
    });
    if (items.length === 0) return null;
    return /*#__PURE__*/React.createElement("div", {
      className: "tree-group",
      key: g.label
    }, /*#__PURE__*/React.createElement("div", {
      className: "tree-group-label"
    }, /*#__PURE__*/React.createElement("span", null, g.label), /*#__PURE__*/React.createElement("span", {
      className: "line"
    }), /*#__PURE__*/React.createElement("span", null, items.length)), items.map(([k, d]) => {
      const counts = window.countFlags((report.behavioral_flags || {})[k] || []);
      const sev = window.maxSev(counts);
      const kind = window.classifyDevice(d);
      return /*#__PURE__*/React.createElement("div", {
        key: k,
        className: `tree-item ${selected === "d:" + k ? "active" : ""}`,
        onClick: () => onSelect("d:" + k)
      }, /*#__PURE__*/React.createElement("span", {
        className: `bullet ${kind}`
      }), /*#__PURE__*/React.createElement("span", {
        className: "label"
      }, d.hostname || k), counts.total > 0 && /*#__PURE__*/React.createElement("span", {
        className: `flag-count ${sev === "CRITICAL" ? "crit" : sev === "HIGH" ? "high" : ""}`
      }, counts.total));
    }));
  })));
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
