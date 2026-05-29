/* ============================================================
   GEOFF Main — Find Evil operations console (real API)
   ============================================================ */
(function () {
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, html) => { const n = document.createElement(tag); if (cls) n.className = cls; if (html != null) n.innerHTML = html; return n; };

  /* ---------- server-injected config ---------- */
  const EVIDENCE_DIR = window.GEOFF_EVIDENCE_BASE_DIR || '';
  const API_KEY = document.querySelector('meta[name="geoff-api-key"]')?.content || '';

  function apiFetch(url, opts = {}) {
    if (API_KEY) opts.headers = { ...(opts.headers || {}), 'X-API-Key': API_KEY };
    return fetch(url, opts);
  }

  /* ---------- static phases ---------- */
  const PHASES = [
    { id: "discover",  name: "Discover",  desc: "Enumerate evidence, build device & user maps" },
    { id: "triage",    name: "Triage",    desc: "Hash, signature & indicator sweep" },
    { id: "timeline",  name: "Timeline",  desc: "Build super-timeline from logs & filesystem" },
    { id: "correlate", name: "Correlate", desc: "Attribute devices to users, link sessions" },
    { id: "hunt",      name: "Hunt",      desc: "Behavioral analysis & MITRE-mapped detections" },
    { id: "report",    name: "Report",    desc: "Score severity, assemble incident report" },
  ];

  function pctToPhase(pct) {
    if (pct < 12) return 0;
    if (pct < 28) return 1;
    if (pct < 46) return 2;
    if (pct < 64) return 3;
    if (pct < 84) return 4;
    return 5;
  }

  /* ---------- static playbooks ---------- */
  const PLAYBOOKS = [
    { id: "full",  name: "full-spectrum", steps: 142, on: true },
    { id: "quick", name: "quick-triage",  steps: 38 },
    { id: "mem",   name: "memory-deep",   steps: 64 },
    { id: "net",   name: "network-hunt",  steps: 51 },
  ];
  let activePlaybook = PLAYBOOKS[0];

  function renderPlaybooks() {
    const wrap = $("playbooks"); wrap.innerHTML = "";
    PLAYBOOKS.forEach(p => {
      const n = el("div", "pb-opt" + (p.on ? " active" : ""));
      n.innerHTML = `<span class="rb"></span><span>${p.name}</span><small>${p.steps}</small>`;
      n.onclick = () => { PLAYBOOKS.forEach(x => x.on = false); p.on = true; activePlaybook = p; renderPlaybooks(); $("pb-name").textContent = p.name; };
      wrap.appendChild(n);
    });
  }

  /* ---------- manifest ---------- */
  const artLabel = { disk_images: "DISK", memory_dumps: "MEM", registry_hives: "REG",
    evtx_logs: "EVTX", syslogs: "SYS", pcaps: "PCAP", mobile_backups: "BACKUP" };

  function renderManifestFromDeviceMap(deviceMap) {
    const wrap = $("manifest"); wrap.innerHTML = "";
    let totalFiles = 0;
    Object.entries(deviceMap).forEach(([id, d]) => {
      // d may be raw device_map entry: {os, owner, evidence_files, ...} or our extended shape
      const files = d.evidence_files || d.evidence || 0;
      totalFiles += files;
      const kinds = d.evidence_types || d.ev_types || [];
      const kind = d.kind || inferKind(d);
      const n = el("div", "man-host"); n.dataset.host = id;
      n.innerHTML = `<div class="mh-top">
          <span class="edot ${kind}"></span>
          <span class="mh-name">${id}</span>
          <span class="mh-chk">·</span>
        </div>
        <div class="mh-arts">${kinds.map(t => `<span class="art-chip">${artLabel[t] || t}</span>`).join("")}
          ${files ? `<span class="art-chip">${files} files</span>` : ''}</div>`;
      wrap.appendChild(n);
    });
    $("man-cnt").textContent = totalFiles || Object.keys(deviceMap).length;
  }

  function inferKind(d) {
    const os = (d.os || d.operating_system || '').toLowerCase();
    if (os.includes('ios') || os.includes('android') || os.includes('mobile')) return 'mobile';
    if (os.includes('server') || (d.role || '').toLowerCase().includes('server')) return 'server';
    return 'pc';
  }

  function renderManifestPlaceholder() {
    const wrap = $("manifest"); wrap.innerHTML = "";
    const dirName = (EVIDENCE_DIR || '/evidence').split('/').filter(Boolean).pop() || 'evidence';
    const n = el("div", "man-host");
    n.innerHTML = `<div class="mh-top">
        <span class="mh-name" style="color:var(--g-text-mute)">${dirName}</span>
        <span class="mh-chk">·</span>
      </div>
      <div class="mh-arts"><span class="art-chip">awaiting inventory</span></div>`;
    wrap.appendChild(n);
    $("man-cnt").textContent = "—";
  }

  function markIndexed(hostname) {
    const n = $("manifest") && $("manifest").querySelector(`[data-host="${hostname}"]`);
    if (n && !n.classList.contains("indexed")) {
      n.classList.add("indexed");
      const chk = n.querySelector(".mh-chk");
      if (chk) chk.textContent = "✓ indexed";
    }
  }

  function resetManifest() {
    $("manifest").querySelectorAll(".man-host").forEach(n => {
      n.classList.remove("indexed");
      const chk = n.querySelector(".mh-chk");
      if (chk) chk.textContent = "·";
    });
  }

  /* ---------- phase tracker ---------- */
  function renderPhases() {
    const wrap = $("phases"); wrap.innerHTML = "";
    PHASES.forEach(p => {
      const n = el("div", "phase"); n.dataset.id = p.id;
      n.innerHTML = `<div class="bar"><i></i></div><div class="dot">✓</div>
        <div class="pn">${p.name}</div><div class="pd">${p.desc}</div>`;
      wrap.appendChild(n);
    });
  }

  function setPhase(idx, state) {
    const nodes = $("phases").children;
    for (let i = 0; i < nodes.length; i++) {
      nodes[i].classList.toggle("done", i < idx || (i === idx && state === "done"));
      nodes[i].classList.toggle("active", i === idx && state !== "done");
    }
  }

  /* ---------- entity renderer ---------- */
  function addEntity(id, kind, os, flagCount, topSev) {
    const list = $("ent-list");
    if ([...list.children].some(c => c.querySelector(".nm")?.textContent === id)) return;
    const fcCls = topSev === "CRITICAL" ? "crit" : topSev === "HIGH" ? "high" : "";
    const n = el("div", "ent-item");
    n.innerHTML = `<span class="edot ${kind}"></span>
      <div style="flex:1;min-width:0;"><div class="nm">${id}</div><div class="role">${kindWord(kind)} · ${os || ''}</div></div>
      <span class="fc ${fcCls}">${flagCount || 0}</span>`;
    list.appendChild(n);
    $("ent-cnt").textContent = list.children.length;
  }

  function kindWord(k) {
    return ({ pc: 'Workstation', server: 'Server', mobile: 'Mobile', user: 'User', service: 'Service' }[k] || k);
  }

  /* ---------- log line ---------- */
  function addLog(text) {
    const feed = $("feed");
    const n = el("div", "logline");
    n.innerHTML = `<span class="tk">${new Date().toISOString().slice(11, 19)}</span><span class="ar">›</span><span>${escHtml(text)}</span>`;
    feed.appendChild(n);
    scrollFeed();
  }

  function escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  /* ---------- finding card from behavioral flag ---------- */
  function addFlagCard(devId, flag) {
    const feed = $("feed");
    const sev = (flag.severity || 'MEDIUM').toUpperCase();
    const mitreTags = (flag.mitre_techniques || flag.mitre || []).map(m =>
      `<span class="mitre-tag">${escHtml(m)}</span>`).join('');
    const evEntries = Object.entries(flag.evidence || {}).slice(0, 3)
      .map(([k, v]) => `<span class="tag-mono">${escHtml(k)}: ${escHtml(String(v))}</span>`).join('');
    const n = el("div", `find-card sev-${sev}`);
    n.innerHTML = `
      <div class="rail"><span class="sev-pill ${sev}">${sev}</span></div>
      <div>
        <div class="fh">
          <span class="ft">${escHtml(flag.flag_type || 'finding')}</span>
          <span class="fts">${escHtml(devId)}</span>
        </div>
        <div class="fs">${escHtml(flag.summary || '')}</div>
        <div class="fe">${escHtml(flag.explanation || flag.description || '')}</div>
        <div style="margin-top:9px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
          <span class="fdev"><span class="edot ${inferKind({ os: '' })}"></span>${escHtml(devId)}</span>
          ${mitreTags}
        </div>
        ${evEntries ? `<div class="ftags">${evEntries}</div>` : ''}
      </div>`;
    feed.appendChild(n);
    scrollFeed();
    bumpSeverity(sev);
  }

  function scrollFeed() { const w = $("feed-wrap"); if (w) w.scrollTop = w.scrollHeight; }

  /* ---------- severity counters ---------- */
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const sevId = { CRITICAL: "c-crit", HIGH: "c-high", MEDIUM: "c-med", LOW: "c-low" };

  function bumpSeverity(sev) {
    if (!(sev in counts)) return;
    counts[sev]++;
    const node = $(sevId[sev]);
    if (!node) return;
    node.textContent = counts[sev];
    node.animate([{ transform: "scale(1.35)" }, { transform: "scale(1)" }], { duration: 280, easing: "ease-out" });
    updateThreat();
  }

  function updateThreat() {
    let level = 0;
    if (counts.LOW) level = Math.max(level, 22);
    if (counts.MEDIUM) level = Math.max(level, 48);
    if (counts.HIGH) level = Math.max(level, 78);
    if (counts.CRITICAL) level = Math.max(level, 96);
    const fill = $("threat-fill");
    if (fill) fill.style.width = level + "%";
  }

  /* ---------- job state ---------- */
  let currentJobId = null;
  let pollTimer = null;
  let seenLogCount = 0;
  let t0 = 0;
  let elapsedTimer = null;
  let lastPct = 0;
  let shownFlags = new Set(); // track rendered finding ids to avoid duplicates

  function fmtElapsed(ms) {
    const s = Math.floor(ms / 1000);
    return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  }

  function resetRun() {
    counts.CRITICAL = counts.HIGH = counts.MEDIUM = counts.LOW = 0;
    ["c-crit", "c-high", "c-med", "c-low"].forEach(id => { const n = $(id); if (n) n.textContent = "0"; });
    const feed = $("feed"); if (feed) feed.innerHTML = "";
    const el2 = $("ent-list"); if (el2) el2.innerHTML = "";
    const cnt = $("ent-cnt"); if (cnt) cnt.textContent = "0";
    const tf = $("threat-fill"); if (tf) tf.style.width = "0%";
    const pf = $("pbar-fill"); if (pf) pf.style.width = "0%";
    const pp = $("pbar-pct"); if (pp) pp.textContent = "0%";
    const ps = $("pbar-steps"); if (ps) ps.textContent = "0 / — steps";
    const sp = $("op-sevpill"); if (sp) sp.style.opacity = "0";
    const vb = $("verdict-box"); if (vb) vb.classList.remove("evil");
    const vbadge = $("vbadge"); if (vbadge) vbadge.textContent = "— — —";
    const vs = $("v-sevpill"); if (vs) { vs.textContent = "PENDING"; vs.className = "sev-pill"; vs.style.opacity = ".3"; }
    renderPhases();
    seenLogCount = 0;
    lastPct = 0;
    shownFlags = new Set();
    resetManifest();
  }

  /* ---------- start run ---------- */
  async function runFindEvil() {
    if (currentJobId && pollTimer) return; // already running

    const evdir = $("evdir")?.value?.trim() || EVIDENCE_DIR;
    if (!evdir) { alert("Enter an evidence path first."); return; }

    resetRun();
    $("runbtn").textContent = "■ Running…";
    $("runbtn").style.opacity = ".7";
    const live = $("op-live"); if (live) live.style.display = "inline-flex";
    t0 = Date.now();
    elapsedTimer = setInterval(() => {
      const el2 = $("op-elapsed"); if (el2) el2.textContent = "elapsed " + fmtElapsed(Date.now() - t0);
    }, 1000);

    // Update case display
    const titleEl = $("op-title"); if (titleEl) {
      const dirName = evdir.split('/').filter(Boolean).pop() || evdir;
      titleEl.textContent = dirName;
    }
    const caseEl = $("op-case"); if (caseEl) caseEl.textContent = evdir;

    addLog("Starting Find Evil — " + evdir);

    let resp, data;
    try {
      resp = await apiFetch('/find-evil', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ evidence_dir: evdir }),
      });
      data = await resp.json();
    } catch (e) {
      finishRunError("Network error: " + e.message);
      return;
    }

    if (!resp.ok || data.status === 'error') {
      finishRunError(data.error || data.message || 'Failed to start job');
      return;
    }

    currentJobId = data.job_id;
    addLog("Job started — " + currentJobId);
    pollStatus();
  }

  /* ---------- poll ---------- */
  function pollStatus() {
    if (!currentJobId) return;
    pollTimer = setTimeout(async () => {
      try {
        const resp = await apiFetch('/find-evil/status/' + currentJobId);
        const data = await resp.json();
        handleStatus(data);
      } catch (e) {
        addLog("Poll error: " + e.message);
        pollStatus(); // retry
      }
    }, 1500);
  }

  function handleStatus(data) {
    const pct = Math.round(data.progress_pct || 0);
    const status = data.status;

    // Update progress bar
    if (pct > lastPct) {
      lastPct = pct;
      const pf = $("pbar-fill"); if (pf) pf.style.width = pct + "%";
      const pp = $("pbar-pct"); if (pp) pp.textContent = pct + "%";
      const ps = $("pbar-steps"); if (ps) ps.textContent = `${data.current_playbook || ''} · ${data.current_step || ''}`.replace(/^ · | · $/, '') || (pct + "%");
    }

    // Update phase
    const phaseIdx = pct >= 100 ? PHASES.length - 1 : pctToPhase(pct);
    setPhase(phaseIdx, status === 'complete' ? "done" : "active");

    // Drain new log entries
    const log = data.log || [];
    for (let i = seenLogCount; i < log.length; i++) {
      const entry = log[i];
      addLog(entry.msg || entry);
    }
    seenLogCount = log.length;

    if (status === 'complete') {
      finishRunSuccess(data.result || {});
    } else if (status === 'error') {
      finishRunError(data.error || 'Investigation failed');
    } else {
      // keep polling
      pollStatus();
    }
  }

  /* ---------- finish ---------- */
  function finishRunSuccess(result) {
    clearInterval(elapsedTimer);
    pollTimer = null;
    currentJobId = null;

    const live = $("op-live"); if (live) live.style.display = "none";
    const rb = $("runbtn"); if (rb) { rb.textContent = "↻ Replay Run"; rb.style.opacity = "1"; }

    const pf = $("pbar-fill"); if (pf) pf.style.width = "100%";
    const pp = $("pbar-pct"); if (pp) pp.textContent = "100%";
    setPhase(PHASES.length - 1, "done");

    const evilFound = result.evil_found;
    const sev = (result.severity || 'INFO').toUpperCase();
    const classification = result.classification || '';
    const stepsCompleted = result.steps_completed || '—';
    const stepsFailed = result.steps_failed || 0;
    const elapsed = result.elapsed_seconds ? Math.round(result.elapsed_seconds) : null;

    const ps = $("pbar-steps");
    if (ps) ps.textContent = `${stepsCompleted} steps · ${stepsFailed} failed`;

    const elEl = $("op-elapsed");
    if (elEl && elapsed) elEl.textContent = `elapsed ${Math.floor(elapsed / 60).toString().padStart(2,"0")}:${(elapsed % 60).toString().padStart(2,"0")}`;

    // Verdict panel
    const vb = $("verdict-box");
    const vbadge = $("vbadge");
    const vs = $("v-sevpill");
    const sp = $("op-sevpill");

    if (evilFound) {
      if (vb) vb.classList.add("evil");
      if (vbadge) vbadge.textContent = "EVIL FOUND";
    } else {
      if (vbadge) vbadge.textContent = evilFound === false ? "CLEAN" : "COMPLETE";
    }

    if (sp) { sp.style.opacity = "1"; sp.className = `sev-pill ${sev}`; sp.textContent = sev; }
    if (vs) { vs.textContent = sev; vs.className = `sev-pill ${sev}`; vs.style.opacity = "1"; }
    if ($("threat-fill")) updateThreat();

    // Render behavioral flags as finding cards
    const behavioralFlags = result.behavioral_flags || {};
    let totalFindings = 0;
    Object.entries(behavioralFlags).forEach(([devId, flags]) => {
      if (!Array.isArray(flags)) return;
      // infer device kind from device_map if available
      const dm = result.device_map || {};
      const devInfo = dm[devId] || {};
      const devKind = inferKind(devInfo);
      // add entity
      const topFlag = flags.reduce((top, f) => {
        const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        return (order[f.severity] || 0) > (order[top.severity] || 0) ? f : top;
      }, {});
      addEntity(devId, devKind, devInfo.os || '', flags.length, topFlag.severity);
      // add flag cards (CRITICAL/HIGH first, up to 10 per device)
      const sorted = [...flags].sort((a, b) => {
        const o = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        return (o[b.severity] || 0) - (o[a.severity] || 0);
      });
      sorted.slice(0, 10).forEach(flag => {
        const fid = devId + ':' + (flag.flag_id || flag.summary);
        if (!shownFlags.has(fid)) { shownFlags.add(fid); addFlagCard(devId, flag); totalFindings++; }
      });
    });

    // Also populate manifest from device_map
    const deviceMap = result.device_map || {};
    if (Object.keys(deviceMap).length > 0) {
      renderManifestFromDeviceMap(deviceMap);
      Object.keys(deviceMap).forEach(markIndexed);
    }

    // Summary card
    const feed = $("feed");
    if (feed) {
      const card = el("div", "complete-card");
      const clsText = classification ? ` — ${classification}` : '';
      const findingCount = totalFindings || Object.values(behavioralFlags).reduce((s, f) => s + (Array.isArray(f) ? f.length : 0), 0);
      const hostCount = Object.keys(behavioralFlags).length || Object.keys(deviceMap).length;
      card.innerHTML = `<div class="verdict">${evilFound ? "EVIL" : evilFound === false ? "CLEAN" : "DONE"}</div>
        <div class="ct">
          <div style="font-size:14px;font-weight:600;color:var(--g-text);">Investigation complete${clsText} — ${findingCount} findings across ${hostCount} hosts</div>
          <div class="cl">${result.executive_summary || result.summary || 'See reports for full narrative.'}</div>
        </div>
        <a class="btn primary" href="/reports/viewer">View full report →</a>`;
      feed.appendChild(card);
      scrollFeed();
    }

    // Chat notification
    const sevLabel = sev === 'CRITICAL' ? `<b style="color:var(--sev-crit)">evil</b>` : evilFound ? `<b>evil</b>` : 'nothing malicious';
    pushChat("geoff", `<b>GEOFF</b>Run complete. ${evilFound ? `I found ${sevLabel} — ${counts.CRITICAL} critical, ${counts.HIGH} high.` : 'No evil found.'} Open the report for the full narrative.`);
  }

  function finishRunError(msg) {
    clearInterval(elapsedTimer);
    pollTimer = null;
    currentJobId = null;

    const live = $("op-live"); if (live) live.style.display = "none";
    const rb = $("runbtn"); if (rb) { rb.textContent = "◎ Run Find Evil"; rb.style.opacity = "1"; }

    addLog("ERROR: " + msg);
    pushChat("geoff", `<b>GEOFF</b>Investigation failed: ${escHtml(msg)}`);
  }

  /* ---------- chat ---------- */
  function pushChat(who, html) {
    const s = $("chat-scroll");
    if (!s) return;
    const m = el("div", "msg " + who, html);
    s.appendChild(m);
    s.scrollTop = s.scrollHeight;
  }

  async function sendChat() {
    const input = $("chat-input");
    const txt = input?.value?.trim();
    if (!txt) return;
    pushChat("user", escHtml(txt));
    if (input) input.value = "";

    try {
      const resp = await apiFetch('/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: txt }),
      });
      const data = await resp.json();
      const reply = data.response || data.message || 'No response.';
      pushChat("geoff", `<b>GEOFF</b>${escHtml(reply)}`);

      // If investigation was triggered from chat, start polling
      if (data.investigation_started && data.job_id && !currentJobId) {
        currentJobId = data.job_id;
        addLog("Investigation started from chat — " + currentJobId);
        t0 = Date.now();
        elapsedTimer = setInterval(() => {
          const el2 = $("op-elapsed"); if (el2) el2.textContent = "elapsed " + fmtElapsed(Date.now() - t0);
        }, 1000);
        pollStatus();
      }
    } catch (e) {
      pushChat("geoff", `<b>GEOFF</b>Error: ${escHtml(e.message)}`);
    }
  }

  /* ---------- load cases for manifest ---------- */
  async function loadManifest() {
    renderManifestPlaceholder();
    try {
      const resp = await apiFetch('/cases');
      if (!resp.ok) return;
      const data = await resp.json();
      // cases is an object of case_name → {evil_found, severity, ...}
      // If there are completed cases, show the most recent's device info if available
      // Otherwise keep placeholder
      const cases = data.cases || data || {};
      if (typeof cases === 'object' && Object.keys(cases).length > 0) {
        // show case list counts but keep placeholder — devices only known post-run
        $("man-cnt").textContent = Object.keys(cases).length + " cases";
      }
    } catch (e) {
      // silent — manifest stays as placeholder
    }
  }

  /* ---------- init ---------- */
  renderPlaybooks();
  renderPhases();
  if ($("evdir") && EVIDENCE_DIR) $("evdir").value = EVIDENCE_DIR;
  $("runbtn").onclick = runFindEvil;

  const sendBtn = $("chat-send"); if (sendBtn) sendBtn.onclick = sendChat;
  const chatInput = $("chat-input");
  if (chatInput) chatInput.addEventListener("keydown", e => { if (e.key === "Enter") sendChat(); });

  $("nav-evidence").onclick = (e) => {
    e.preventDefault();
    window.location.href = '/cases';
  };

  loadManifest();
})();
