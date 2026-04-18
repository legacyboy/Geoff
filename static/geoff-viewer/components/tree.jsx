// Left-pane entity tree + filter chips.

function EntityTree({ report, selected, onSelect, search, setSearch, sevFilter, setSevFilter }) {
  const users = Object.entries(report.user_map || {});
  const devices = Object.entries(report.device_map || {});

  const q = (search || "").toLowerCase().trim();
  const matches = (s) => !q || (s || "").toLowerCase().includes(q);

  const passSev = (flagsArr) => {
    if (!sevFilter) return true;
    return (flagsArr || []).some((f) => f.severity === sevFilter);
  };

  // Group devices
  const groups = [
    { label: "Workstations", items: devices.filter(([, d]) => classifyDevice(d) === "pc") },
    { label: "Servers", items: devices.filter(([, d]) => classifyDevice(d) === "server") },
    { label: "Mobile", items: devices.filter(([, d]) => classifyDevice(d) === "mobile") },
    { label: "Network", items: devices.filter(([, d]) => classifyDevice(d) === "network") },
  ];

  return (
    <>
      <div className="pane-header">
        <span>Entities</span>
        <span className="count">{users.length + devices.length}</span>
      </div>

      <div className="search-box">
        <input
          placeholder="Search accounts, hosts, IOCs…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="filter-row">
        {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
          <button
            key={s}
            className={`filter-chip ${sevFilter === s ? "active" : ""}`}
            onClick={() => setSevFilter(sevFilter === s ? null : s)}
          >{s}</button>
        ))}
      </div>

      <div className="entity-tree">
        <div className="tree-group">
          <div className="tree-group-label">
            <span>Accounts</span>
            <span className="line" />
            <span>{users.length}</span>
          </div>
          {users.filter(([k, u]) => {
            if (!matches(k) && !matches(u.display_name) && !matches((u.aliases || []).join(" "))) return false;
            return passSev(userFlagsAgg(report, k));
          }).map(([k, u]) => {
            const counts = aggregateUserFlags(report, k);
            const sev = maxSev(counts);
            return (
              <div
                key={k}
                className={`tree-item ${selected === "u:" + k ? "active" : ""}`}
                onClick={() => onSelect("u:" + k)}
              >
                <span className="bullet user" />
                <span className="label">{u.display_name || k}</span>
                {counts.total > 0 && (
                  <span className={`flag-count ${sev === "CRITICAL" ? "crit" : sev === "HIGH" ? "high" : ""}`}>{counts.total}</span>
                )}
              </div>
            );
          })}
        </div>

        {groups.map((g) => {
          const items = g.items.filter(([k, d]) => {
            if (!matches(k) && !matches(d.hostname) && !matches(d.owner)) return false;
            return passSev((report.behavioral_flags || {})[k] || []);
          });
          if (items.length === 0) return null;
          return (
            <div className="tree-group" key={g.label}>
              <div className="tree-group-label">
                <span>{g.label}</span>
                <span className="line" />
                <span>{items.length}</span>
              </div>
              {items.map(([k, d]) => {
                const counts = countFlags((report.behavioral_flags || {})[k] || []);
                const sev = maxSev(counts);
                const kind = classifyDevice(d);
                return (
                  <div
                    key={k}
                    className={`tree-item ${selected === "d:" + k ? "active" : ""}`}
                    onClick={() => onSelect("d:" + k)}
                  >
                    <span className={`bullet ${kind}`} />
                    <span className="label">{d.hostname || k}</span>
                    {counts.total > 0 && (
                      <span className={`flag-count ${sev === "CRITICAL" ? "crit" : sev === "HIGH" ? "high" : ""}`}>{counts.total}</span>
                    )}
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>
    </>
  );
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
