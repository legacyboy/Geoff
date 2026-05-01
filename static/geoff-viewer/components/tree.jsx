// Left-pane entity tree + filter chips.

function EntityTree({ report, selected, onSelect, search, setSearch, sevFilter, setSevFilter }) {
  const users = Object.entries(report.user_map || {});
  const devices = Object.entries(report.device_map || {});

  const q = (search || "").toLowerCase().trim();
  const matches = (s) => !q || (s || "").toLowerCase().includes(q);

  // Whole-finding text search — JSON-stringify each device's flags so a query
  // like "185.243" or a hash matches anything captured in evidence fields.
  const deviceFlagText = (devId) => {
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

  // Derive Services from exfil/c2 flags (matches what graph.js does)
  const serviceMap = new Map();
  Object.entries(report.behavioral_flags || {}).forEach(([devId, flags]) => {
    (flags || []).forEach(flag => {
      if (flag.flag_type !== "exfiltration" && flag.flag_type !== "c2_traffic") return;
      const dst = (flag.evidence || {}).dst_host || (flag.evidence || {}).dst_ip || "";
      if (!dst) return;
      const svc = (window.classifyExfilService && window.classifyExfilService(dst)) || "External";
      if (!serviceMap.has(svc)) serviceMap.set(svc, { name: svc, hits: 0 });
      serviceMap.get(svc).hits++;
    });
  });
  const services = Array.from(serviceMap.values());

  // Derive Evidence types (matches graph.js bucketing)
  const evidenceTypes = new Map();
  Object.entries(report.device_map || {}).forEach(([devId, dev]) => {
    const declared = (dev && dev.evidence_types) || [];
    const files = (dev && dev.evidence_files) || [];
    declared.forEach(t => {
      if (!evidenceTypes.has(t)) evidenceTypes.set(t, { type: t, files: 0, devs: new Set() });
      evidenceTypes.get(t).devs.add(devId);
    });
    files.forEach(fp => {
      const guessed = (window.guessEvidenceTypeFromPath && window.guessEvidenceTypeFromPath(fp)) || declared[0] || "other";
      if (!evidenceTypes.has(guessed)) evidenceTypes.set(guessed, { type: guessed, files: 0, devs: new Set() });
      evidenceTypes.get(guessed).files++;
      evidenceTypes.get(guessed).devs.add(devId);
    });
  });

  return (
    <>
      <div className="pane-header">
        <span>Entities</span>
        <span className="count">{users.length + devices.length + services.length + evidenceTypes.size}</span>
      </div>

      <div className="search-box">
        <input
          id="entity-search"
          placeholder="Search accounts, hosts, IOCs, findings…"
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
          {users.filter(([k, u]) => matchesUser(k, u) && passSev(userFlagsAgg(report, k))).map(([k, u]) => {
            const counts = aggregateUserFlags(report, k);
            const sev = maxSev(counts);
            return (
              <div
                key={k}
                className={`tree-item ${selected === "u:" + k ? "active" : ""}`}
                onClick={() => onSelect("u:" + k)}
                title={`@${k}${u.role ? " · " + u.role : ""}${counts.total ? " · " + counts.total + " findings" : ""}`}
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
          const items = g.items.filter(([k, d]) => matchesDevice(k, d) && passSev((report.behavioral_flags || {})[k] || []));
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
                    title={`${d.hostname || k} · ${osLabel(d)}${d.owner ? " · owner " + d.owner : ""}`}
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

        {services.length > 0 && (
          <div className="tree-group">
            <div className="tree-group-label">
              <span>Services</span>
              <span className="line" />
              <span>{services.length}</span>
            </div>
            {services.filter(s => matches(s.name)).map(s => (
              <div
                key={s.name}
                className={`tree-item ${selected === "s:" + s.name ? "active" : ""}`}
                onClick={() => onSelect("s:" + s.name)}
                title={`External service · ${s.hits} flagged connection(s)`}
              >
                <span className="bullet service" />
                <span className="label">{s.name}</span>
                <span className="flag-count high">{s.hits}</span>
              </div>
            ))}
          </div>
        )}

        {evidenceTypes.size > 0 && (
          <div className="tree-group">
            <div className="tree-group-label">
              <span>Evidence</span>
              <span className="line" />
              <span>{evidenceTypes.size}</span>
            </div>
            {Array.from(evidenceTypes.values())
              .filter(b => matches(b.type) || matches((window.formatEvidenceType ? window.formatEvidenceType(b.type) : b.type)))
              .map(b => (
                <div
                  key={b.type}
                  className={`tree-item ${selected === "e:" + b.type ? "active" : ""}`}
                  onClick={() => onSelect("e:" + b.type)}
                  title={`${b.files} file(s) across ${b.devs.size} device(s)`}
                >
                  <span className="bullet evidence" />
                  <span className="label">{(window.formatEvidenceType || ((s) => s))(b.type)}</span>
                  <span className="flag-count">{b.files || b.devs.size}</span>
                </div>
              ))}
          </div>
        )}
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
