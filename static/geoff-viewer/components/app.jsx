const { useState, useEffect, useCallback } = React;

function App() {
  const [report, setReport] = useState(null);
  const [selected, setSelected] = useState(null);
  const [hoverId, setHoverId] = useState(null);
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState(null);
  const [dropActive, setDropActive] = useState(false);
  const [fileName, setFileName] = useState("sample_report.js (demo)");

  // Load report from URL params or API on mount
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const caseDir = params.get('case');
    if (caseDir) {
      // Fetch report JSON from Geoff API
      fetch(`/reports/${encodeURIComponent(caseDir)}/json`)
        .then(res => {
          if (!res.ok) throw new Error('Report not found');
          return res.json();
        })
        .then(data => {
          setReport(data);
          setFileName(caseDir);
        })
        .catch(err => {
          setFileName(caseDir);
          // Fall back to demo data
          setReport(window.GEOFF_SAMPLE);
        });
      return;
    }
    setReport(window.GEOFF_SAMPLE);
  }, []);

  // Drag-and-drop JSON file handling
  useEffect(() => {
    const onDragOver = (e) => { e.preventDefault(); setDropActive(true); };
    const onDragLeave = (e) => {
      if (e.target === document.body || e.clientX <= 0 || e.clientY <= 0) setDropActive(false);
    };
    const onDrop = async (e) => {
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
      } catch (e) { alert("Parse error: " + e.message); }
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
    const data = selected
      ? extractEntityReport(report, selected)
      : report;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = selected ? `${selected.replace(":", "_")}.json` : `${report.case_id || "case"}.json`;
    a.click();
  }, [report, selected]);

  if (!report) return <div className="empty">No report loaded.</div>;

  const sev = report.severity || "INFO";
  const sevColors = {
    CRITICAL: { bg: "rgba(239,68,68,0.15)", fg: "#EF4444", bd: "rgba(239,68,68,0.4)" },
    HIGH:     { bg: "rgba(245,158,11,0.15)", fg: "#F59E0B", bd: "rgba(245,158,11,0.4)" },
    MEDIUM:   { bg: "rgba(96,165,250,0.15)", fg: "#60A5FA", bd: "rgba(96,165,250,0.4)" },
    LOW:      { bg: "rgba(148,163,184,0.15)", fg: "#94A3B8", bd: "rgba(148,163,184,0.3)" },
    INFO:     { bg: "rgba(100,116,139,0.15)", fg: "#94A3B8", bd: "rgba(100,116,139,0.3)" },
  }[sev] || {};

  const devCount = Object.keys(report.device_map || {}).length;
  const userCount = Object.keys(report.user_map || {}).length;
  let flagCount = 0;
  for (const flags of Object.values(report.behavioral_flags || {})) flagCount += flags.length;

  return (
    <div className="app">
      <div className="topbar">
        <div className="brand">
          <span className="logo">G.E.O.F.F.</span>
          <span className="tag">DFIR · Evidence Graph</span>
        </div>
        <div className="case-meta">
          <span className="case-id">{report.case_id || "—"}</span>
          <span>·</span>
          <span title={report.title}>{truncateStr(report.title || "", 52)}</span>
          <span
            className="sev-pill"
            style={{ background: sevColors.bg, color: sevColors.fg, borderColor: sevColors.bd }}
          >{sev}</span>
          {report.evil_found && (
            <span style={{ fontSize: 10, letterSpacing: 0.5, color: "var(--g-red)" }}>⚠ evil_found</span>
          )}
        </div>
        <div className="spacer" />
        <button className="action" onClick={loadDemo}>Demo data</button>
        <button className="action primary" onClick={loadFile}>Load JSON…</button>
        <button className="action" onClick={exportSelection}>Export</button>
      </div>

      <div className="workspace">
        <aside className="pane-left">
          <EntityTree
            report={report}
            selected={selected}
            onSelect={setSelected}
            search={search}
            setSearch={setSearch}
            sevFilter={sevFilter}
            setSevFilter={setSevFilter}
          />
        </aside>

        <section className="pane-center">
          <div className="graph-toolbar">
            <button className="tab active">Relationship graph</button>
            <div className="spacer" />
            <div className="legend">
              <span className="li"><span className="sw" style={{ background: "var(--ent-user)", borderRadius: "50%" }} /> account</span>
              <span className="li"><span className="sw" style={{ background: "var(--ent-pc)" }} /> pc</span>
              <span className="li"><span className="sw" style={{ background: "var(--ent-server)" }} /> server</span>
              <span className="li"><span className="sw" style={{ background: "var(--ent-mobile)" }} /> mobile</span>
              <span className="li"><span className="sw" style={{ background: "var(--ent-network)" }} /> network</span>
              <span className="li" style={{ marginLeft: 6 }}>
                <svg width="18" height="6"><line x1="0" y1="3" x2="18" y2="3" stroke="var(--sev-high)" strokeDasharray="4 3" /></svg>
                lateral
              </span>
            </div>
          </div>
          <RelationshipGraph
            report={report}
            selected={selected}
            onSelect={setSelected}
            hoverId={hoverId}
            onHover={setHoverId}
          />
        </section>

        <aside className="pane-right">
          <div className="pane-header">
            <span>Detail</span>
            <span className="count">{selected ? selected.replace(":", " · ") : "case overview"}</span>
          </div>
          <DetailPanel report={report} selected={selected} onSelect={setSelected} />
        </aside>
      </div>

      <div className="statusbar">
        <span className="stat"><span className="dot" /> <strong>source</strong> <span className="v">{fileName}</span></span>
        <span className="stat"><strong>devices</strong> <span className="v">{devCount}</span></span>
        <span className="stat"><strong>accounts</strong> <span className="v">{userCount}</span></span>
        <span className="stat"><strong>findings</strong> <span className="v">{flagCount}</span></span>
        <span className="stat"><strong>elapsed</strong> <span className="v">{fmtElapsed(report.elapsed_seconds)}</span></span>
        <span style={{ marginLeft: "auto" }}>drop a find_evil_report.json anywhere to load</span>
      </div>

      <div className={`drop-overlay ${dropActive ? "active" : ""}`}>
        <div className="drop-card">
          <div className="headline">Drop find_evil_report.json</div>
          <div className="sub">parsed entirely client-side — no upload</div>
        </div>
      </div>
    </div>
  );
}

function truncateStr(s, n) { return s.length > n ? s.slice(0, n - 1) + "…" : s; }
function fmtElapsed(sec) {
  if (!sec) return "—";
  const m = Math.floor(sec / 60), s = sec % 60;
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
    return { user: u, devices: devs, behavioral_flags: flags, correlated: report.correlated_users?.[k] };
  }
  if (sel.startsWith("d:")) {
    const k = sel.slice(2);
    return { device: (report.device_map || {})[k], flags: (report.behavioral_flags || {})[k] };
  }
  return report;
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
