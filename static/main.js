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

  // Maps current_playbook values emitted by the backend pipeline to UI phase index.
  const PLAYBOOK_PHASE = {
    initializing: 0, validation: 0, extraction: 0, revalidation: 0,
    discovery: 0, inventory: 0, setup: 0,
    'PB-SIFT-000': 1,
    'PB-SIFT-001': 2, 'PB-SIFT-002': 2, 'PB-SIFT-003': 2,
    'PB-SIFT-004': 2, 'PB-SIFT-005': 2, 'PB-SIFT-006': 2,
    'PB-SIFT-007': 2, 'PB-SIFT-008': 2, 'PB-SIFT-009': 2,
    'PB-SIFT-010': 2, 'PB-SIFT-011': 2, 'PB-SIFT-012': 2,
    'PB-SIFT-013': 2, 'PB-SIFT-014': 2, 'PB-SIFT-015': 2,
    'PB-SIFT-016': 2, 'PB-SIFT-017': 2, 'PB-SIFT-018': 2,
    'PB-SIFT-019': 2, 'PB-SIFT-020': 2, 'PB-SIFT-021': 2,
    'PB-SIFT-022': 2, 'PB-SIFT-023': 2, 'PB-SIFT-024': 2,
    'super-timeline': 3, 'timeline-intel': 3, 'manager-review': 3,
    pass2: 3, 'batch-critic': 3, replay: 3,
    behavioral: 4, correlation: 4, 'network-map': 4, reporting: 4,
    email_extract: 5, ioc_validation: 5, narrative: 5,
    mitre_mapping: 5, complete: 5,
  };

  function playbookToPhase(pb, pct) {
    if (pb && Object.prototype.hasOwnProperty.call(PLAYBOOK_PHASE, pb)) {
      return PLAYBOOK_PHASE[pb];
    }
    if (pct < 9)  return 0;
    if (pct < 10) return 1;
    if (pct < 68) return 2;
    if (pct < 85) return 3;
    if (pct < 95) return 4;
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
    const wrap = $("playbooks"); if (!wrap) return;
    wrap.innerHTML = "";
    PLAYBOOKS.forEach(p => {
      const n = el("div", "pb-opt" + (p.on ? " active" : ""));
      n.innerHTML = `<span class="rb"></span><span>${p.name}</span><small>${p.steps}</small>`;
      n.onclick = () => { PLAYBOOKS.forEach(x => x.on = false); p.on = true; activePlaybook = p; renderPlaybooks(); const pbName = $("pb-name"); if (pbName) pbName.textContent = p.name; };
      wrap.appendChild(n);
    });
  }

  /* ---------- manifest ---------- */
  const artLabel = { disk_images: "DISK", memory_dumps: "MEM", registry_hives: "REG",
    evtx_logs: "EVTX", syslogs: "SYS", pcaps: "PCAP", mobile_backups: "BACKUP" };

  function renderManifestFromDeviceMap(deviceMap) {
    const wrap = $("manifest"); if (!wrap) return;
    wrap.innerHTML = "";
    let totalFiles = 0;
    Object.entries(deviceMap).forEach(([id, d]) => {
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
    const cnt = $("man-cnt"); if (cnt) cnt.textContent = totalFiles || Object.keys(deviceMap).length;
  }

  function inferKind(d) {
    const os = (d.os || d.operating_system || '').toLowerCase();
    if (os.includes('ios') || os.includes('android') || os.includes('mobile')) return 'mobile';
    if (os.includes('server') || (d.role || '').toLowerCase().includes('server')) return 'server';
    return 'pc';
  }

  function renderManifestPlaceholder() {
    const wrap = $("manifest"); if (!wrap) return;
    wrap.innerHTML = "";
    const dirName = (EVIDENCE_DIR || '/evidence').split('/').filter(Boolean).pop() || 'evidence';
    const n = el("div", "man-host");
    n.innerHTML = `<div class="mh-top">
        <span class="mh-name" style="color:var(--g-text-mute)">${dirName}</span>
        <span class="mh-chk">·</span>
      </div>
      <div class="mh-arts"><span class="art-chip">awaiting inventory</span></div>`;
    wrap.appendChild(n);
    const cnt = $("man-cnt"); if (cnt) cnt.textContent = "—";
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
    const mf = $("manifest"); if (!mf) return;
    mf.querySelectorAll(".man-host").forEach(n => {
      n.classList.remove("indexed");
      const chk = n.querySelector(".mh-chk");
      if (chk) chk.textContent = "·";
    });
  }

  /* ---------- phase tracker ---------- */
  function renderPhases() {
    const wrap = $("phases"); if (!wrap) return;
    wrap.innerHTML = "";
    PHASES.forEach(p => {
      const n = el("div", "phase"); n.dataset.id = p.id;
      n.innerHTML = `<div class="bar"><i></i></div><div class="dot">✓</div>
        <div class="pn">${p.name}</div><div class="pd">${p.desc}</div>`;
      wrap.appendChild(n);
    });
  }

  function setPhase(idx, state) {
    const nodes = $("phases")?.children;
    if (!nodes) return;
    for (let i = 0; i < nodes.length; i++) {
      nodes[i].classList.toggle("done", i < idx || (i === idx && state === "done"));
      nodes[i].classList.toggle("active", i === idx && state !== "done");
    }
  }

  /* ---------- entity renderer ---------- */
  function addEntity(id, kind, os, flagCount, topSev) {
    const list = $("ent-list"); if (!list) return;
    if ([...list.children].some(c => c.querySelector(".nm")?.textContent === id)) return;
    const fcCls = topSev === "CRITICAL" ? "crit" : topSev === "HIGH" ? "high" : "";
    const n = el("div", "ent-item");
    n.innerHTML = `<span class="edot ${kind}"></span>
      <div style="flex:1;min-width:0;"><div class="nm">${id}</div><div class="role">${kindWord(kind)} · ${os || ''}</div></div>
      <span class="fc ${fcCls}">${flagCount || 0}</span>`;
    list.appendChild(n);
    const cnt = $("ent-cnt"); if (cnt) cnt.textContent = list.children.length;
  }

  function kindWord(k) {
    return ({ pc: 'Workstation', server: 'Server', mobile: 'Mobile', user: 'User', service: 'Service' }[k] || k);
  }

  /* ---------- log line ---------- */
  function addLog(text) {
    const feed = $("feed"); if (!feed) return;
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
    const feed = $("feed"); if (!feed) return;
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
  let lastLogTs = '';
  let t0 = 0;
  let elapsedTimer = null;
  let lastPct = 0;
  let shownFlags = new Set();

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
    lastLogTs = '';
    lastPct = 0;
    shownFlags = new Set();
    resetManifest();
  }

  /* ---------- start run ---------- */
  async function runFindEvil() {
    if (currentJobId && pollTimer) return;

    const evdir = $("evdir")?.value?.trim() || EVIDENCE_DIR;
    if (!evdir) { alert("Enter an evidence path first."); return; }

    resetRun();
    const runbtn = $("runbtn"); if (runbtn) { runbtn.textContent = "■ Running…"; runbtn.style.opacity = ".7"; }
    const live = $("op-live"); if (live) live.style.display = "inline-flex";
    t0 = Date.now();
    elapsedTimer = setInterval(() => {
      const el2 = $("op-elapsed"); if (el2) el2.textContent = "elapsed " + fmtElapsed(Date.now() - t0);
    }, 1000);

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
    showJobBanner(data.job_id, evdir, 0, "initializing", "");
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
        pollStatus();
      }
    }, 1500);
  }

  function handleStatus(data) {
    const pct = Math.round(data.progress_pct || 0);
    const status = data.status;

    if (pct > lastPct) {
      lastPct = pct;
      const pf = $("pbar-fill"); if (pf) pf.style.width = pct + "%";
      const pp = $("pbar-pct"); if (pp) pp.textContent = pct + "%";
      const ps = $("pbar-steps"); if (ps) ps.textContent = `${data.current_playbook || ''} · ${data.current_step || ''}`.replace(/^ · | · $/, '') || (pct + "%");
    }

    const phaseIdx = pct >= 100 ? PHASES.length - 1 : playbookToPhase(data.current_playbook, pct);
    setPhase(phaseIdx, status === 'complete' ? "done" : "active");

    const log = data.log || [];
    for (const entry of log) {
      const ts = typeof entry === 'string' ? '' : (entry.time || '');
      if (ts > lastLogTs || !lastLogTs) {
        addLog(entry.msg || entry);
      }
    }
    if (log.length > 0) {
      const last = log[log.length - 1];
      lastLogTs = typeof last === 'string' ? '' : (last.time || '');
    }

    // Update job banner
    updateJobBanner(pct, data.current_playbook, data.current_step);

    if (status === 'complete') {
      finishRunSuccess(data.result || {});
    } else if (status === 'error') {
      finishRunError(data.error || 'Investigation failed');
    } else {
      pollStatus();
    }
  }

  /* ---------- job banner ---------- */
  function showJobBanner(jobId, evidenceDir, pct, playbook, step) {
    currentJobId = jobId;
    const banner = $("job-banner"); if (!banner) return;
    banner.classList.add("active");
    updateJobBanner(pct, playbook, step);
    const info = $("jb-info");
    if (info) info.textContent = evidenceDir || 'unknown';
  }

  function updateJobBanner(pct, playbook, step) {
    const jbPct = $("jb-pct");
    if (jbPct) jbPct.textContent = pct + "%";
    const jbInfo = $("jb-info");
    if (jbInfo && playbook) jbInfo.textContent = (playbook + (step ? ' · ' + step : '')).replace(/^ · | · $/, '');
  }

  function hideJobBanner() {
    const banner = $("job-banner"); if (!banner) return;
    banner.classList.remove("active");
  }

  /* ---------- finish ---------- */
  function finishRunSuccess(result) {
    clearInterval(elapsedTimer);
    pollTimer = null;
    currentJobId = null;
    hideJobBanner();

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

    const behavioralFlags = result.behavioral_flags || {};
    let totalFindings = 0;
    Object.entries(behavioralFlags).forEach(([devId, flags]) => {
      if (!Array.isArray(flags)) return;
      const dm = result.device_map || {};
      const devInfo = dm[devId] || {};
      const devKind = inferKind(devInfo);
      const topFlag = flags.reduce((top, f) => {
        const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        return (order[f.severity] || 0) > (order[top.severity] || 0) ? f : top;
      }, {});
      addEntity(devId, devKind, devInfo.os || '', flags.length, topFlag.severity);
      const sorted = [...flags].sort((a, b) => {
        const o = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        return (o[b.severity] || 0) - (o[a.severity] || 0);
      });
      sorted.slice(0, 10).forEach(flag => {
        const fid = devId + ':' + (flag.flag_id || flag.summary);
        if (!shownFlags.has(fid)) { shownFlags.add(fid); addFlagCard(devId, flag); totalFindings++; }
      });
    });

    const deviceMap = result.device_map || {};
    if (Object.keys(deviceMap).length > 0) {
      renderManifestFromDeviceMap(deviceMap);
      Object.keys(deviceMap).forEach(markIndexed);
    }

    const feed = $("feed");
    if (feed) {
      const card = el("div", "complete-card");
      const clsText = classification ? ` — ${classification}` : '';
      const findingCount = totalFindings || Object.values(behavioralFlags).reduce((s, f) => s + (Array.isArray(f) ? f.length : 0), 0);
      const hostCount = Object.keys(behavioralFlags).length || Object.keys(deviceMap).length;

      // Build viewer URL: extract case directory name from result.case_work_dir
      let viewerUrl = '/reports/viewer';
      if (result.case_work_dir) {
        const caseDirName = result.case_work_dir.split('/').filter(Boolean).pop();
        viewerUrl += '?case=' + encodeURIComponent(caseDirName);
      }

      card.innerHTML = `<div class="verdict">${evilFound ? "EVIL" : evilFound === false ? "CLEAN" : "DONE"}</div>
        <div class="ct">
          <div style="font-size:14px;font-weight:600;color:var(--g-text);">Investigation complete${clsText} — ${findingCount} findings across ${hostCount} hosts</div>
          <div class="cl">${result.executive_summary || result.summary || 'See reports for full narrative.'}</div>
        </div>
        <a class="btn primary" href="${viewerUrl}">View full report →</a>`;
      feed.appendChild(card);
      scrollFeed();
    }

    const sevLabel = sev === 'CRITICAL' ? `<b style="color:var(--sev-crit)">evil</b>` : evilFound ? `<b>evil</b>` : 'nothing malicious';
    pushChat("geoff", `<b>GEOFF</b>Run complete. ${evilFound ? `I found ${sevLabel} — ${counts.CRITICAL} critical, ${counts.HIGH} high.` : 'No evil found.'} Open the report for the full narrative.`);
  }

  function finishRunError(msg) {
    clearInterval(elapsedTimer);
    pollTimer = null;
    currentJobId = null;
    hideJobBanner();

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

      if (data.investigation_started && data.job_id && !currentJobId) {
        currentJobId = data.job_id;
        addLog("Investigation started from chat — " + currentJobId);
        showJobBanner(data.job_id, $("evdir")?.value?.trim() || EVIDENCE_DIR, 0, "initializing", "");
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

  /* ============================================================
     TAB SWITCHING — Evidence / Reports / Console
     ============================================================ */
  let activeTab = 'console';

  function switchTab(tab) {
    if (activeTab === tab) return;
    activeTab = tab;

    // Update nav links
    document.querySelectorAll('.navlink').forEach(n => n.classList.remove('active'));
    const navEl = document.getElementById('nav-' + tab);
    if (navEl) navEl.classList.add('active');

    // Show/hide panels
    const consoleView = $("tab-console");
    const evidenceView = $("tab-evidence");
    const reportsView = $("tab-reports");

    if (consoleView) consoleView.style.display = (tab === 'console') ? 'flex' : 'none';
    if (evidenceView) { evidenceView.classList.toggle('active', tab === 'evidence'); }
    if (reportsView) { reportsView.classList.toggle('active', tab === 'reports'); }

    // Load data on first view
    if (tab === 'evidence') loadEvidencePanel();
    if (tab === 'reports') loadReportsPanel();
  }

  /* ============================================================
     EVIDENCE PANEL — FETCH & RENDER CASES FROM /cases
     ============================================================ */
  let evidenceLoaded = false;

  async function loadEvidencePanel() {
    if (evidenceLoaded) return;
    evidenceLoaded = true;
    const body = $("ev-panel-body");
    if (!body) return;
    body.innerHTML = '<div class="case-empty">Loading cases…</div>';

    try {
      const resp = await apiFetch('/cases');
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const data = await resp.json();
      const cases = data.cases || data || {};
      const caseNames = Object.keys(cases);

      if (caseNames.length === 0) {
        body.innerHTML = '<div class="case-empty">No evidence directories found in ' + escHtml(EVIDENCE_DIR || 'evidence base') + '</div>';
        const cnt = $("ev-cnt"); if (cnt) cnt.textContent = '0 cases';
        return;
      }

      const cnt = $("ev-cnt"); if (cnt) cnt.textContent = caseNames.length + ' cases';
      body.innerHTML = '';

      // Sort case names
      const sorted = caseNames.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));

      sorted.forEach(caseName => {
        const items = Array.isArray(cases[caseName]) ? cases[caseName] : [];
        const itemCount = items.length;
        const dirs = items.filter(i => i.startsWith('[DIR]')).length;
        const files = itemCount - dirs;

        const card = el("div", "case-card");
        card.innerHTML = `
          <div class="cc-top">
            <span class="edot" style="margin-right:4px;"></span>
            <span class="cc-name">${escHtml(caseName)}</span>
            <span class="sev-pill" style="font-size:9px;opacity:.6;">CASE</span>
          </div>
          <div class="cc-meta">
            <span>${itemCount} items</span>
            <span>${dirs} dirs</span>
            <span>${files} files</span>
          </div>
          <div class="cc-items" style="display:none;" id="cc-items-${escHtml(caseName)}">
            ${items.slice(0, 50).map(i => {
              const isDir = i.startsWith('[DIR]');
              const cls = isDir ? 'dir' : '';
              return `<div class="ci ${cls}">${escHtml(isDir ? i.substring(6) : i)}</div>`;
            }).join('')}
            ${itemCount > 50 ? `<div class="ci" style="color:var(--g-text-mute);">… and ${itemCount - 50} more items</div>` : ''}
          </div>
        `;
        card.onclick = () => {
          const itemsDiv = card.querySelector('.cc-items');
          if (itemsDiv) itemsDiv.style.display = itemsDiv.style.display === 'none' ? 'flex' : 'none';
          // Also set active directory for chat context
          apiFetch('/active-directory', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ directory: EVIDENCE_DIR + '/' + caseName }),
          }).catch(() => {});
        };
        body.appendChild(card);
      });
    } catch (e) {
      body.innerHTML = '<div class="case-empty">Failed to load cases: ' + escHtml(e.message) + '</div>';
    }
  }

  /* ============================================================
     REPORTS PANEL — FETCH & RENDER REPORTS FROM /reports
     ============================================================ */
  let reportsLoaded = false;

  async function loadReportsPanel() {
    if (reportsLoaded) return;
    reportsLoaded = true;
    const body = $("rp-panel-body");
    if (!body) return;
    body.innerHTML = '<div class="case-empty">Loading reports…</div>';

    try {
      const resp = await apiFetch('/reports');
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const data = await resp.json();
      const reports = data.reports || [];
      const sorted = [...reports].sort((a, b) => {
        // Sort by timestamp descending
        return (b.timestamp || '').localeCompare(a.timestamp || '');
      });

      if (sorted.length === 0) {
        body.innerHTML = '<div class="case-empty">No completed reports found. Run Find Evil on an evidence directory to generate one.</div>';
        const cnt = $("rp-cnt"); if (cnt) cnt.textContent = '0 reports';
        return;
      }

      const cnt = $("rp-cnt"); if (cnt) cnt.textContent = sorted.length + ' reports';
      body.innerHTML = '';

      sorted.forEach(rpt => {
        const isEvil = rpt.evil_found;
        const sev = (rpt.severity || 'INFO').toUpperCase();
        const elapsed = rpt.elapsed_seconds ? Math.round(rpt.elapsed_seconds) : 0;
        const elapsedStr = elapsed >= 60
          ? Math.floor(elapsed / 60) + 'm ' + (elapsed % 60) + 's'
          : elapsed + 's';
        const dateStr = rpt.timestamp
          ? rpt.timestamp.substring(0, 4) + '-' + rpt.timestamp.substring(4, 6) + '-' + rpt.timestamp.substring(6, 8) +
            ' ' + (rpt.timestamp.substring(9, 11) || '00') + ':' + (rpt.timestamp.substring(11, 13) || '00')
          : 'unknown';

        const card = el("div", "rpt-card " + (isEvil ? "evil" : "clean"));
        card.innerHTML = `
          <div class="rt-top">
            <span class="rt-name">${escHtml(rpt.case_name || rpt.dir)}</span>
            <span class="sev-pill ${sev}">${sev}</span>
            ${isEvil ? '<span class="sev-pill CRITICAL" style="font-size:9px;">EVIL</span>' : '<span class="sev-pill" style="font-size:9px;background:var(--g-green);color:var(--g-bg);">CLEAN</span>'}
          </div>
          <div class="rt-meta">
            <span>${dateStr}</span>
            <span>${elapsedStr}</span>
            <span>${rpt.classification || 'unclassified'}</span>
          </div>
          <div class="rt-desc">${escHtml(rpt.evidence_dir || '')}</div>
        `;
        card.onclick = () => {
          const caseDir = encodeURIComponent(rpt.dir);
          window.open('/reports/viewer?case=' + caseDir, '_blank');
        };
        body.appendChild(card);
      });
    } catch (e) {
      body.innerHTML = '<div class="case-empty">Failed to load reports: ' + escHtml(e.message) + '</div>';
    }
  }

  /* ============================================================
     LIVE JOB DETECTION — CHECK FOR RUNNING JOBS ON PAGE LOAD
     ============================================================ */
  async function checkActiveJobs() {
    try {
      const resp = await apiFetch('/find-evil/active');
      if (!resp.ok) return;
      const data = await resp.json();
      const jobs = data.active_jobs || [];

      if (jobs.length === 0) return;

      // Found a running job — show banner and start polling
      const job = jobs[0]; // take the most recent
      currentJobId = job.job_id;
      showJobBanner(job.job_id, job.evidence_dir || 'unknown', job.progress_pct, job.current_playbook, job.current_step);

      // Set up the console
      const evdir = job.evidence_dir || EVIDENCE_DIR;
      if (evdir && $("evdir")) $("evdir").value = evdir;
      const titleEl = $("op-title"); if (titleEl) {
        const dirName = evdir.split('/').filter(Boolean).pop() || evdir;
        titleEl.textContent = dirName;
      }
      const caseEl = $("op-case"); if (caseEl) caseEl.textContent = evdir;
      const live = $("op-live"); if (live) live.style.display = "inline-flex";

      // Estimate elapsed from started_at
      if (job.started_at) {
        const startedMs = new Date(job.started_at).getTime();
        t0 = Date.now() - (Date.now() - startedMs); // adjust t0
      } else {
        t0 = Date.now();
      }
      elapsedTimer = setInterval(() => {
        const el2 = $("op-elapsed"); if (el2) el2.textContent = "elapsed " + fmtElapsed(Date.now() - t0);
      }, 1000);

      const runbtn = $("runbtn"); if (runbtn) { runbtn.textContent = "■ Running…"; runbtn.style.opacity = ".7"; }
      addLog("Detected running job — " + job.job_id);
      addLog("Evidence: " + (job.evidence_dir || 'unknown'));
      pollStatus();

      // Wire banner resume button
      const resumeBtn = $("jb-resume");
      if (resumeBtn) {
        resumeBtn.onclick = () => switchTab('console');
      }
    } catch (e) {
      // Silent — no active jobs is normal
    }
  }

  /* ---------- evidence manifest initialization ---------- */
  async function loadManifest() {
    renderManifestPlaceholder();
    try {
      const resp = await apiFetch('/cases');
      if (!resp.ok) return;
      const data = await resp.json();
      const cases = data.cases || data || {};
      if (typeof cases === 'object' && Object.keys(cases).length > 0) {
        const cnt = $("man-cnt"); if (cnt) cnt.textContent = Object.keys(cases).length + " cases";
      }
    } catch (e) {
      // silent
    }
  }

  /* ============================================================
     INIT
     ============================================================ */
  renderPlaybooks();
  renderPhases();
  if ($("evdir") && EVIDENCE_DIR) $("evdir").value = EVIDENCE_DIR;

  // Run button
  const runBtn = $("runbtn"); if (runBtn) runBtn.onclick = runFindEvil;

  // Chat
  const sendBtn = $("chat-send"); if (sendBtn) sendBtn.onclick = sendChat;
  const chatInput = $("chat-input");
  if (chatInput) chatInput.addEventListener("keydown", e => { if (e.key === "Enter") sendChat(); });

  // Tab switching
  const navConsole = $("nav-console");
  const navEvidence = $("nav-evidence");
  const navReports = $("nav-reports");
  if (navConsole) navConsole.onclick = (e) => { e.preventDefault(); switchTab('console'); };
  if (navEvidence) navEvidence.onclick = (e) => { e.preventDefault(); switchTab('evidence'); };
  if (navReports) navReports.onclick = (e) => { e.preventDefault(); switchTab('reports'); };

  // Job banner resume button
  const jbResume = $("jb-resume");
  if (jbResume) jbResume.onclick = () => switchTab('console');

  loadManifest();

  // Check for active jobs on page load
  checkActiveJobs();
})();
