// Right-side detail panel — renders context-appropriate view for:
// selected user, selected device, or case overview (no selection).

const { Fragment } = React;

function DetailPanel({ report, selected, onSelect }) {
  if (!selected) return <CaseOverview report={report} onSelect={onSelect} />;
  if (selected.startsWith("u:")) {
    return <UserDetail report={report} username={selected.slice(2)} onSelect={onSelect} />;
  }
  if (selected.startsWith("d:")) {
    return <DeviceDetail report={report} deviceId={selected.slice(2)} onSelect={onSelect} />;
  }
  if (selected.startsWith("i:")) {
    return <IocDetail report={report} iocId={selected.slice(2)} onSelect={onSelect} />;
  }
  return null;
}

function CaseOverview({ report, onSelect }) {
  const devCount = Object.keys(report.device_map || {}).length;
  const userCount = Object.keys(report.user_map || {}).length;
  let allFlags = 0, crit = 0, high = 0;
  for (const flags of Object.values(report.behavioral_flags || {})) {
    for (const f of flags) {
      allFlags++;
      if (f.severity === "CRITICAL") crit++;
      else if (f.severity === "HIGH") high++;
    }
  }
  const lateral = Object.values(report.correlated_users || {})
    .reduce((acc, u) => acc + (u.lateral_movement_indicators || []).length, 0);

  return (
    <div className="detail-scroll">
      <div className="entity-head">
        <div className="glyph pc" style={{ fontFamily: "var(--font-mono)" }}>◇</div>
        <div className="title-wrap">
          <div className="kind">Case overview</div>
          <div className="title">{report.case_id || "—"}</div>
          <div className="sub">{report.title || ""}</div>
        </div>
      </div>

      <div className="overview-grid">
        <div className="metric"><div className="k">Devices</div><div className="v">{devCount}</div></div>
        <div className="metric"><div className="k">Accounts</div><div className="v">{userCount}</div></div>
        <div className={`metric ${crit ? "crit" : high ? "high" : "ok"}`}>
          <div className="k">Findings</div><div className="v">{allFlags}</div>
        </div>
        <div className={`metric ${lateral ? "high" : ""}`}>
          <div className="k">Lateral moves</div><div className="v">{lateral}</div>
        </div>
      </div>

      <div className="section">
        <div className="section-title">Severity <span className="count">{report.severity || "INFO"}</span></div>
        <div style={{ color: "var(--g-text-dim)", fontSize: 12, lineHeight: 1.55 }}>
          <div><SeverityChip sev="CRITICAL" /> {crit} critical finding{crit === 1 ? "" : "s"}</div>
          <div style={{ marginTop: 4 }}><SeverityChip sev="HIGH" /> {high} high-severity</div>
          {report.evil_found && (
            <div style={{ marginTop: 10, color: "var(--g-red)", fontWeight: 500 }}>
              ⚠ evil_found = true — compromise confirmed
            </div>
          )}
        </div>
      </div>

      <div className="section">
        <div className="section-title">Timeline <span className="count">{(report.timeline || []).length}</span></div>
        <TimelineMini events={report.timeline || []} />
      </div>

      <div className="section">
        <div className="section-title">Select an entity</div>
        <div style={{ fontSize: 11.5, color: "var(--g-text-mute)", lineHeight: 1.55 }}>
          Click a node in the graph or an item in the left tree to see its evidence, related entities, and findings.
        </div>
      </div>
    </div>
  );
}

function SeverityChip({ sev }) {
  return <span className={`sev-chip sev-${sev}`}>{sev}</span>;
}

function TimelineMini({ events }) {
  const sorted = [...events].sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
  return (
    <div style={{ borderLeft: "1px solid var(--g-border-soft)", marginLeft: 6 }}>
      {sorted.slice(0, 12).map((e, i) => (
        <div key={i} style={{ position: "relative", paddingLeft: 14, paddingBottom: 8 }}>
          <div style={{
            position: "absolute", left: -4, top: 4,
            width: 8, height: 8, borderRadius: 2,
            background: sevColor(e.severity)
          }} />
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--g-text-mute)" }}>
            {fmtTs(e.timestamp)} · {e.device_id}
          </div>
          <div style={{ fontSize: 11.5, color: "var(--g-text)" }}>{e.summary}</div>
        </div>
      ))}
    </div>
  );
}

function sevColor(s) {
  return {
    CRITICAL: "var(--sev-crit)", HIGH: "var(--sev-high)", MEDIUM: "var(--sev-med)",
    LOW: "var(--sev-low)", INFO: "var(--sev-info)",
  }[s] || "var(--sev-info)";
}

function fmtTs(ts) {
  if (!ts) return "—";
  return ts.replace("T", " ").replace("Z", "");
}

function UserDetail({ report, username, onSelect }) {
  const u = (report.user_map || {})[username];
  if (!u) return <div className="empty">User not found</div>;
  const cu = (report.correlated_users || {})[username] || {};
  const devices = u.devices || [];

  // All flags on their devices
  const flags = [];
  for (const d of devices) {
    for (const f of (report.behavioral_flags || {})[d] || []) {
      flags.push({ ...f, device_id: d });
    }
  }
  flags.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));

  const profile = cu.activity_profile || {};

  return (
    <div className="detail-scroll">
      <div className="entity-head">
        <div className="glyph user">{(u.display_name || username).charAt(0).toUpperCase()}</div>
        <div className="title-wrap">
          <div className="kind">Account</div>
          <div className="title">{u.display_name || username}</div>
          <div className="sub">
            @{username} · {u.role || "user"}
            <span className={`conf conf-${u.confidence}`}>{u.confidence}</span>
          </div>
        </div>
      </div>

      <div className="meta-grid">
        <div>
          <div className="k">Aliases</div>
          <div className="v dim">{(u.aliases || []).join(", ") || "—"}</div>
        </div>
        <div>
          <div className="k">Primary</div>
          <div className="v">{u.primary_device || "—"}</div>
        </div>
        <div>
          <div className="k">First seen</div>
          <div className="v dim">{fmtTs(profile.first_seen)}</div>
        </div>
        <div>
          <div className="k">Last seen</div>
          <div className="v dim">{fmtTs(profile.last_seen)}</div>
        </div>
        <div>
          <div className="k">Events</div>
          <div className="v">{(profile.total_events || 0).toLocaleString()}</div>
        </div>
        <div>
          <div className="k">Active hours</div>
          <div className="v dim">{hoursRange(profile.typical_hours)}</div>
        </div>
      </div>

      <div className="section">
        <div className="section-title">Devices <span className="count">{devices.length}</span></div>
        <div className="related-list">
          {devices.map((d) => {
            const dev = (report.device_map || {})[d];
            if (!dev) return null;
            const kind = classifyDevice(dev);
            return (
              <div key={d} className="related-item" onClick={() => onSelect("d:" + d)}>
                <span className={`bullet ${kind}`} />
                <span className="name">{dev.hostname || d}</span>
                <span className="via">{osLabel(dev)}</span>
              </div>
            );
          })}
        </div>
      </div>

      {(cu.lateral_movement_indicators || []).length > 0 && (
        <div className="section">
          <div className="section-title">Lateral movement <span className="count">{cu.lateral_movement_indicators.length}</span></div>
          {cu.lateral_movement_indicators.map((l, i) => (
            <div key={i} className="finding sev-HIGH">
              <div className="finding-head">
                <span className="sev-chip sev-HIGH">LATERAL</span>
                <span className="finding-ts">{fmtTs(l.timestamp)}</span>
              </div>
              <div className="finding-summary">
                {l.from_device} → {l.to_device}
              </div>
              <div className="finding-expl">{l.method}</div>
            </div>
          ))}
        </div>
      )}

      {(cu.anomalies || []).length > 0 && (
        <div className="section">
          <div className="section-title">Anomalies <span className="count">{cu.anomalies.length}</span></div>
          {cu.anomalies.map((a, i) => (
            <div key={i} style={{ fontSize: 11.5, color: "var(--g-text-dim)", padding: "4px 0", borderBottom: "1px dashed var(--g-border-soft)" }}>
              {a}
            </div>
          ))}
        </div>
      )}

      <div className="section">
        <div className="section-title">Findings across devices <span className="count">{flags.length}</span></div>
        {flags.length === 0
          ? <div className="empty" style={{ padding: "12px 0" }}>No behavioral flags attributed.</div>
          : flags.map((f, i) => <FindingCard key={i} f={f} showDevice />)}
      </div>

      {(profile.common_applications || []).length > 0 && (
        <div className="section">
          <div className="section-title">Top applications</div>
          {(profile.common_applications || []).slice(0, 6).map(([name, count]) => (
            <div key={name} className="evfile">
              <span className="type-tag">{count}</span>
              <span>{name}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function DeviceDetail({ report, deviceId, onSelect }) {
  const d = (report.device_map || {})[deviceId];
  if (!d) return <div className="empty">Device not found</div>;
  const kind = classifyDevice(d);
  const flags = [...((report.behavioral_flags || {})[deviceId] || [])];
  flags.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));

  // Related users (owner + anyone with this in their devices)
  const relatedUsers = [];
  for (const [uname, u] of Object.entries(report.user_map || {})) {
    if ((u.devices || []).includes(deviceId)) relatedUsers.push(uname);
  }

  // Timeline events tagged with this device
  const events = (report.timeline || []).filter((e) => e.device_id === deviceId);

  return (
    <div className="detail-scroll">
      <div className="entity-head">
        <div className={`glyph ${kind}`}>
          {kind === "server" ? "⌬" : kind === "mobile" ? "▯" : kind === "network" ? "≈" : "▣"}
        </div>
        <div className="title-wrap">
          <div className="kind">{deviceTypeLabel(d)}</div>
          <div className="title">{d.hostname || d.device_id}</div>
          <div className="sub">
            {osLabel(d)}
            {d.owner && <span className={`conf conf-${d.owner_confidence}`}>{d.owner_confidence}</span>}
          </div>
        </div>
      </div>

      <div className="meta-grid">
        <div>
          <div className="k">Device ID</div>
          <div className="v">{d.device_id}</div>
        </div>
        <div>
          <div className="k">Owner</div>
          <div className="v">{d.owner || "—"}</div>
        </div>
        <div>
          <div className="k">First seen</div>
          <div className="v dim">{fmtTs(d.first_seen)}</div>
        </div>
        <div>
          <div className="k">Last seen</div>
          <div className="v dim">{fmtTs(d.last_seen)}</div>
        </div>
        <div>
          <div className="k">Discovery</div>
          <div className="v dim">{(d.discovery_method || "").replace(/_/g, " ")}</div>
        </div>
        <div>
          <div className="k">Evidence types</div>
          <div className="v dim">{(d.evidence_types || []).length}</div>
        </div>
      </div>

      {relatedUsers.length > 0 && (
        <div className="section">
          <div className="section-title">Associated accounts <span className="count">{relatedUsers.length}</span></div>
          <div className="related-list">
            {relatedUsers.map((uname) => {
              const u = (report.user_map || {})[uname];
              const isOwner = d.owner === uname;
              return (
                <div key={uname} className="related-item" onClick={() => onSelect("u:" + uname)}>
                  <span className="bullet user" />
                  <span className="name">{u?.display_name || uname}</span>
                  <span className="via">{isOwner ? "owner" : "seen here"}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="section">
        <div className="section-title">Findings <span className="count">{flags.length}</span></div>
        {flags.length === 0
          ? <div className="empty" style={{ padding: "12px 0" }}>No behavioral flags.</div>
          : flags.map((f, i) => <FindingCard key={i} f={f} />)}
      </div>

      {events.length > 0 && (
        <div className="section">
          <div className="section-title">Events on this device <span className="count">{events.length}</span></div>
          <TimelineMini events={events} />
        </div>
      )}

      <div className="section">
        <div className="section-title">Evidence files <span className="count">{(d.evidence_files || []).length}</span></div>
        {(d.evidence_files || []).map((f, i) => (
          <div key={i} className="evfile" title={f}>
            <span className="type-tag">{extType(f)}</span>
            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingCard({ f, showDevice }) {
  const [open, setOpen] = React.useState(false);
  return (
    <div className={`finding sev-${f.severity}`} onClick={() => setOpen(!open)}>
      <div className="finding-head">
        <span className={`sev-chip sev-${f.severity}`}>{f.severity}</span>
        <span className="finding-type">{f.flag_type}</span>
        <span className="finding-ts">{fmtTs(f.timestamp)}</span>
      </div>
      {showDevice && <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--g-text-mute)", marginBottom: 4 }}>on {f.device_id}</div>}
      <div className="finding-summary">{f.summary}</div>
      <div className="finding-expl">{f.explanation}</div>

      {open && f.evidence && (
        <div className="finding-evidence">
          {Object.entries(f.evidence).map(([k, v]) => (
            <Fragment key={k}>
              <div className="ek">{k}</div>
              <div className="ev">{String(v).length > 180 ? String(v).slice(0, 180) + "…" : String(v)}</div>
            </Fragment>
          ))}
        </div>
      )}

      {(f.mitre_att_ck || []).length > 0 && (
        <div className="finding-mitre">
          {f.mitre_att_ck.map((t) => <span key={t} className="mitre-tag">{t}</span>)}
        </div>
      )}
    </div>
  );
}

function sevRank(s) {
  return { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }[s] ?? 5;
}
function hoursRange(h) {
  if (!h || !h.length) return "—";
  return `${String(Math.min(...h)).padStart(2,"0")}:00–${String(Math.max(...h)).padStart(2,"0")}:59`;
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

function getIocSubkind(report, val) {
  const iocs = report.iocs || {};
  if ((iocs.ip_addresses    || []).includes(val)) return "ip";
  if ((iocs.urls            || []).includes(val)) return "url";
  if ((iocs.email_addresses || []).includes(val)) return "email";
  return "ioc";
}

function IocDetail({ report, iocId, onSelect }) {
  const subkind = getIocSubkind(report, iocId);
  const subkindLabel = { ip: "IP ADDRESS", url: "URL", email: "EMAIL", ioc: "INDICATOR" }[subkind] || "INDICATOR";
  const accent = { ip: "#EF4444", url: "#F97316", email: "#EC4899" }[subkind] || "#EF4444";

  const referencingDevices = [];
  for (const [devId, flags] of Object.entries(report.behavioral_flags || {})) {
    if (JSON.stringify(flags).includes(iocId)) {
      referencingDevices.push({ devId, flags });
    }
  }

  return (
    <div className="detail-scroll">
      <div className="entity-head">
        <div className="glyph" style={{ background: `rgba(239,68,68,0.1)`, color: accent, border: `1px solid ${accent}55`, fontFamily: "var(--font-mono)", fontSize: 20 }}>◆</div>
        <div className="title-wrap">
          <div className="kind">Indicator · {subkindLabel}</div>
          <div className="title" style={{ wordBreak: "break-all", fontSize: 12 }}>{iocId}</div>
        </div>
      </div>

      <div className="section">
        <div className="section-title">Referenced by <span className="count">{referencingDevices.length}</span></div>
        {referencingDevices.length === 0
          ? <div className="empty" style={{ padding: "12px 0" }}>No device evidence links this indicator.</div>
          : (
            <div className="related-list">
              {referencingDevices.map(({ devId }) => {
                const dev = (report.device_map || {})[devId];
                if (!dev) return null;
                const kind = classifyDevice(dev);
                return (
                  <div key={devId} className="related-item" onClick={() => onSelect("d:" + devId)}>
                    <span className={`bullet ${kind}`} />
                    <span className="name">{dev.hostname || devId}</span>
                    <span className="via">{osLabel(dev)}</span>
                  </div>
                );
              })}
            </div>
          )}
      </div>

      {referencingDevices.map(({ devId, flags }) => {
        const relevantFlags = flags.filter(f => JSON.stringify(f.evidence || {}).includes(iocId));
        if (relevantFlags.length === 0) return null;
        const dev = (report.device_map || {})[devId];
        return (
          <div className="section" key={devId}>
            <div className="section-title">
              Findings on {dev?.hostname || devId}
              <span className="count">{relevantFlags.length}</span>
            </div>
            {relevantFlags.map((f, i) => <FindingCard key={i} f={f} />)}
          </div>
        );
      })}
    </div>
  );
}

window.DetailPanel = DetailPanel;
window.FindingCard = FindingCard;
window.fmtTs = fmtTs;
window.sevRank = sevRank;
