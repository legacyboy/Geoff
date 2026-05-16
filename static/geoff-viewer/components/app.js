(function() {
const {
  useState,
  useEffect,
  useCallback
} = React;

// Read API key injected by server into <meta name="geoff-api-key"> so that
// authenticated Geoff instances work without exposing the key in JS source.
const _geoffApiKey = document.querySelector('meta[name="geoff-api-key"]')?.content || '';
function authFetch(url, opts = {}) {
  if (_geoffApiKey) {
    opts.headers = Object.assign({}, opts.headers || {}, {'X-API-Key': _geoffApiKey});
  }
  return fetch(url, opts);
}
function App() {
  const [report, setReport] = useState(null);
  const [selected, setSelected] = useState(null);
  const [hoverId, setHoverId] = useState(null);
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState(null);
  const [dropActive, setDropActive] = useState(false);
  const [fileName, setFileName] = useState("sample_report.js (demo)");

  // Load report from URL params or API on mount, and restore selection from URL.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const caseDir = params.get('case');
    const initialSel = params.get('sel');
    if (initialSel) setSelected(initialSel);
    if (caseDir) {
      authFetch(`/reports/${encodeURIComponent(caseDir)}/json`).then(res => {
        if (!res.ok) throw new Error('Report not found');
        return res.json();
      }).then(data => {
        setReport(data);
        setFileName(caseDir);
      }).catch(err => {
        setFileName(caseDir);
        setReport(window.GEOFF_SAMPLE);
      });
      return;
    }
    setReport(window.GEOFF_SAMPLE);
  }, []);

  // Sync selection to URL so views are bookmarkable / shareable.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (selected) params.set('sel', selected);else params.delete('sel');
    const qs = params.toString();
    const url = window.location.pathname + (qs ? '?' + qs : '');
    window.history.replaceState({}, '', url);
  }, [selected]);

  // Keyboard: Esc to deselect, "/" to focus search.
  useEffect(() => {
    const onKey = e => {
      const tag = e.target && e.target.tagName || "";
      const editing = tag === "INPUT" || tag === "TEXTAREA" || e.target && e.target.isContentEditable;
      if (e.key === "Escape") {
        if (editing && tag === "INPUT" && e.target.id === "entity-search") {
          if (e.target.value) {
            setSearch("");
            e.target.value = "";
          } else e.target.blur();
        } else if (!editing) {
          setSelected(null);
        }
      } else if (e.key === "/" && !editing) {
        const input = document.getElementById("entity-search");
        if (input) {
          e.preventDefault();
          input.focus();
          input.select();
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Drag-and-drop JSON file handling
  useEffect(() => {
    const onDragOver = e => {
      e.preventDefault();
      setDropActive(true);
    };
    const onDragLeave = e => {
      if (e.target === document.body || e.clientX <= 0 || e.clientY <= 0) setDropActive(false);
    };
    const onDrop = async e => {
      e.preventDefault();
      setDropActive(false);
      const f = e.dataTransfer.files[0];
      if (!f) return;
      try {
        const txt = await f.text();
        const json = JSON.parse(txt);
        setReport(json);
        setFileName(f.name);
        setSelected(null);
      } catch (err) {
        alert("Could not parse JSON: " + err.message);
      }
    };
    window.addEventListener("dragover", onDragOver);
    window.addEventListener("dragleave", onDragLeave);
    window.addEventListener("drop", onDrop);
    return () => {
      window.removeEventListener("dragover", onDragOver);
      window.removeEventListener("dragleave", onDragLeave);
      window.removeEventListener("drop", onDrop);
    };
  }, []);
  const loadFile = useCallback(() => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json,application/json";
    input.onchange = async () => {
      const f = input.files[0];
      if (!f) return;
      try {
        const txt = await f.text();
        setReport(JSON.parse(txt));
        setFileName(f.name);
        setSelected(null);
      } catch (e) {
        alert("Parse error: " + e.message);
      }
    };
    input.click();
  }, []);
  const loadDemo = useCallback(() => {
    setReport(window.GEOFF_SAMPLE);
    setFileName("sample_report.js (demo)");
    setSelected(null);
    // Clear URL params
    window.history.pushState({}, '', window.location.pathname);
  }, []);
  const exportSelection = useCallback(() => {
    const data = selected ? extractEntityReport(report, selected) : report;
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json"
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = selected ? `${selected.replace(":", "_")}.json` : `${report.case_id || "case"}.json`;
    a.click();
  }, [report, selected]);
  const openMitreMatrix = useCallback(() => {
    const chain = (report && report.attack_chain) || {};
    const techs = chain.mitre_techniques_observed || [];
    const phases = chain.kill_chain_phases || [];
    const params = new URLSearchParams();
    params.set('techs', techs.join(','));
    params.set('phases', phases.join(','));
    params.set('label', report.case_id || '');
    window.open('/reports/mitre-matrix?' + params.toString(), '_blank');
  }, [report]);
  if (!report) return /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, "No report loaded.");
  const sev = report.severity || "INFO";
  const sevColors = {
    CRITICAL: {
      bg: "rgba(239,68,68,0.15)",
      fg: "#EF4444",
      bd: "rgba(239,68,68,0.4)"
    },
    HIGH: {
      bg: "rgba(245,158,11,0.15)",
      fg: "#F59E0B",
      bd: "rgba(245,158,11,0.4)"
    },
    MEDIUM: {
      bg: "rgba(96,165,250,0.15)",
      fg: "#60A5FA",
      bd: "rgba(96,165,250,0.4)"
    },
    LOW: {
      bg: "rgba(148,163,184,0.15)",
      fg: "#94A3B8",
      bd: "rgba(148,163,184,0.3)"
    },
    INFO: {
      bg: "rgba(100,116,139,0.15)",
      fg: "#94A3B8",
      bd: "rgba(100,116,139,0.3)"
    }
  }[sev] || {};
  const devCount = Object.keys(report.device_map || {}).length;
  const userCount = Object.keys(report.user_map || {}).length;
  let flagCount = 0;
  for (const flags of Object.values(report.behavioral_flags || {})) flagCount += flags.length;
  return /*#__PURE__*/React.createElement("div", {
    className: "app"
  }, /*#__PURE__*/React.createElement("div", {
    className: "topbar"
  }, /*#__PURE__*/React.createElement("div", {
    className: "brand"
  }, /*#__PURE__*/React.createElement("span", {
    className: "logo"
  }, "G.E.O.F.F."), /*#__PURE__*/React.createElement("span", {
    className: "tag"
  }, "DFIR \xB7 Evidence Graph")), /*#__PURE__*/React.createElement("div", {
    className: "case-meta"
  }, /*#__PURE__*/React.createElement("span", {
    className: "case-id"
  }, report.case_id || "—"), /*#__PURE__*/React.createElement("span", null, "\xB7"), /*#__PURE__*/React.createElement("span", {
    title: report.title
  }, truncateStr(report.title || "", 52)), /*#__PURE__*/React.createElement("span", {
    className: "sev-pill",
    style: {
      background: sevColors.bg,
      color: sevColors.fg,
      borderColor: sevColors.bd
    }
  }, sev), report.evil_found && /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 10,
      letterSpacing: 0.5,
      color: "var(--g-red)"
    }
  }, "\u26A0 evil_found")), /*#__PURE__*/React.createElement("div", {
    className: "spacer"
  }), /*#__PURE__*/React.createElement("button", {
    className: "action",
    onClick: loadDemo
  }, "Demo data"), /*#__PURE__*/React.createElement("button", {
    className: "action primary",
    onClick: loadFile
  }, "Load JSON\u2026"), /*#__PURE__*/React.createElement("button", {
    className: "action",
    onClick: exportSelection
  }, "Export"), /*#__PURE__*/React.createElement("button", {
    className: "action",
    onClick: openMitreMatrix,
    title: "Open MITRE ATT&CK visual matrix"
  }, "\uD83D\uDC41 MITRE")), /*#__PURE__*/React.createElement("div", {
    className: "workspace"
  }, /*#__PURE__*/React.createElement("aside", {
    className: "pane-left"
  }, /*#__PURE__*/React.createElement(EntityTree, {
    report: report,
    selected: selected,
    onSelect: setSelected,
    search: search,
    setSearch: setSearch,
    sevFilter: sevFilter,
    setSevFilter: setSevFilter
  })), /*#__PURE__*/React.createElement("section", {
    className: "pane-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "graph-toolbar"
  }, /*#__PURE__*/React.createElement("button", {
    className: "tab active"
  }, "Relationship graph"), /*#__PURE__*/React.createElement("div", {
    className: "spacer"
  }), /*#__PURE__*/React.createElement("div", {
    className: "legend"
  }, /*#__PURE__*/React.createElement("span", {
    className: "li"
  }, /*#__PURE__*/React.createElement("span", {
    className: "sw",
    style: {
      background: "var(--ent-user)",
      borderRadius: "50%"
    }
  }), " account"), /*#__PURE__*/React.createElement("span", {
    className: "li"
  }, /*#__PURE__*/React.createElement("span", {
    className: "sw",
    style: {
      background: "var(--ent-pc)"
    }
  }), " pc"), /*#__PURE__*/React.createElement("span", {
    className: "li"
  }, /*#__PURE__*/React.createElement("span", {
    className: "sw",
    style: {
      background: "var(--ent-server)"
    }
  }), " server"), /*#__PURE__*/React.createElement("span", {
    className: "li"
  }, /*#__PURE__*/React.createElement("span", {
    className: "sw",
    style: {
      background: "var(--ent-mobile)"
    }
  }), " mobile"), /*#__PURE__*/React.createElement("span", {
    className: "li"
  }, /*#__PURE__*/React.createElement("span", {
    className: "sw",
    style: {
      background: "var(--ent-network)"
    }
  }), " network"), /*#__PURE__*/React.createElement("span", {
    className: "li"
  }, /*#__PURE__*/React.createElement("span", {
    className: "sw",
    style: {
      background: "var(--ent-service)",
      borderRadius: "50%"
    }
  }), " service"), /*#__PURE__*/React.createElement("span", {
    className: "li"
  }, /*#__PURE__*/React.createElement("span", {
    className: "sw",
    style: {
      background: "var(--ent-evidence)"
    }
  }), " evidence"), /*#__PURE__*/React.createElement("span", {
    className: "li",
    style: {
      marginLeft: 6
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "18",
    height: "6"
  }, /*#__PURE__*/React.createElement("line", {
    x1: "0",
    y1: "3",
    x2: "18",
    y2: "3",
    stroke: "var(--ent-user)"
  })), "owns"), /*#__PURE__*/React.createElement("span", {
    className: "li"
  }, /*#__PURE__*/React.createElement("svg", {
    width: "18",
    height: "6"
  }, /*#__PURE__*/React.createElement("line", {
    x1: "0",
    y1: "3",
    x2: "18",
    y2: "3",
    stroke: "var(--g-text-mute)",
    strokeDasharray: "1 4"
  })), "seen-on"), /*#__PURE__*/React.createElement("span", {
    className: "li"
  }, /*#__PURE__*/React.createElement("svg", {
    width: "18",
    height: "6"
  }, /*#__PURE__*/React.createElement("line", {
    x1: "0",
    y1: "3",
    x2: "18",
    y2: "3",
    stroke: "var(--sev-high)",
    strokeDasharray: "4 3"
  })), "lateral"), /*#__PURE__*/React.createElement("span", {
    className: "li"
  }, /*#__PURE__*/React.createElement("svg", {
    width: "18",
    height: "6"
  }, /*#__PURE__*/React.createElement("line", {
    x1: "0",
    y1: "3",
    x2: "18",
    y2: "3",
    stroke: "#EC4899",
    strokeDasharray: "2 2"
  })), "exfil"))), /*#__PURE__*/React.createElement(RelationshipGraph, {
    report: report,
    selected: selected,
    onSelect: setSelected,
    hoverId: hoverId,
    onHover: setHoverId,
    sevFilter: sevFilter
  })), /*#__PURE__*/React.createElement("aside", {
    className: "pane-right"
  }, /*#__PURE__*/React.createElement("div", {
    className: "pane-header"
  }, /*#__PURE__*/React.createElement("span", null, "Detail"), /*#__PURE__*/React.createElement("span", {
    className: "count"
  }, selected ? selected.replace(":", " · ") : "case overview")), /*#__PURE__*/React.createElement(DetailPanel, {
    report: report,
    selected: selected,
    onSelect: setSelected,
    onSearch: setSearch
  }))), /*#__PURE__*/React.createElement("div", {
    className: "statusbar"
  }, /*#__PURE__*/React.createElement("span", {
    className: "stat"
  }, /*#__PURE__*/React.createElement("span", {
    className: "dot"
  }), " ", /*#__PURE__*/React.createElement("strong", null, "source"), " ", /*#__PURE__*/React.createElement("span", {
    className: "v"
  }, fileName)), /*#__PURE__*/React.createElement("span", {
    className: "stat"
  }, /*#__PURE__*/React.createElement("strong", null, "devices"), " ", /*#__PURE__*/React.createElement("span", {
    className: "v"
  }, devCount)), /*#__PURE__*/React.createElement("span", {
    className: "stat"
  }, /*#__PURE__*/React.createElement("strong", null, "accounts"), " ", /*#__PURE__*/React.createElement("span", {
    className: "v"
  }, userCount)), /*#__PURE__*/React.createElement("span", {
    className: "stat"
  }, /*#__PURE__*/React.createElement("strong", null, "findings"), " ", /*#__PURE__*/React.createElement("span", {
    className: "v"
  }, flagCount)), /*#__PURE__*/React.createElement("span", {
    className: "stat"
  }, /*#__PURE__*/React.createElement("strong", null, "elapsed"), " ", /*#__PURE__*/React.createElement("span", {
    className: "v"
  }, fmtElapsed(report.elapsed_seconds))), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto"
    }
  }, "drop a find_evil_report.json anywhere to load")), /*#__PURE__*/React.createElement("div", {
    className: `drop-overlay ${dropActive ? "active" : ""}`
  }, /*#__PURE__*/React.createElement("div", {
    className: "drop-card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "headline"
  }, "Drop find_evil_report.json"), /*#__PURE__*/React.createElement("div", {
    className: "sub"
  }, "parsed entirely client-side \u2014 no upload"))));
}
function truncateStr(s, n) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function fmtElapsed(sec) {
  if (!sec) return "—";
  const m = Math.floor(sec / 60),
    s = sec % 60;
  return `${m}m${String(s).padStart(2, "0")}s`;
}
function extractEntityReport(report, sel) {
  if (sel.startsWith("u:")) {
    const k = sel.slice(2);
    const u = (report.user_map || {})[k];
    const devs = {};
    const flags = {};
    for (const d of u?.devices || []) {
      if (report.device_map?.[d]) devs[d] = report.device_map[d];
      if (report.behavioral_flags?.[d]) flags[d] = report.behavioral_flags[d];
    }
    return {
      user: u,
      devices: devs,
      behavioral_flags: flags,
      correlated: report.correlated_users?.[k]
    };
  }
  if (sel.startsWith("d:")) {
    const k = sel.slice(2);
    return {
      device: (report.device_map || {})[k],
      flags: (report.behavioral_flags || {})[k]
    };
  }
  return report;
}
const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(/*#__PURE__*/React.createElement(App, null));

})();
