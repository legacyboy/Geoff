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
    n.animate([{ background: 'rgba(76,141,255,.1)' }, { background: 'rgba(76,141,255,0)' }], { duration: 900, easing: 'ease-out' });
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
    n.animate([{ background: 'rgba(76,141,255,.1)' }, { background: 'rgba(76,141,255,0)' }], { duration: 1100, easing: 'ease-out' });
    scrollFeed();
    bumpSeverity(sev);
  }

  function scrollFeed() {
    if (!autoScroll) return;
    const w = $("feed-wrap");
    if (!w) return;
    w.scrollTo({ top: w.scrollHeight, behavior: 'smooth' });
  }

  /* ---------- severity counters ---------- */
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const sevId = { CRITICAL: "c-crit", HIGH: "c-high", MEDIUM: "c-med", LOW: "c-low" };

  function initScrollLock() {
    const wrap = $("feed-wrap");
    const btn = $("scroll-lock-btn");
    if (!wrap || !btn) return;
    wrap.addEventListener('scroll', () => {
      if (!autoScroll) return;
      const nearBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 80;
      if (!nearBottom) {
        autoScroll = false;
        btn.textContent = '⏸ PAUSED';
        btn.classList.add('locked');
      }
    });
    btn.addEventListener('click', () => {
      autoScroll = !autoScroll;
      if (autoScroll) {
        btn.textContent = '⬇ AUTO';
        btn.classList.remove('locked');
        const w = $("feed-wrap");
        if (w) w.scrollTo({ top: w.scrollHeight, behavior: 'smooth' });
      } else {
        btn.textContent = '⏸ PAUSED';
        btn.classList.add('locked');
      }
    });
  }

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
  let lastLogIdx = -1;
  let t0 = 0;
  let elapsedTimer = null;
  let lastPct = 0;
  let shownFlags = new Set();
  let autoScroll = true;

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
    lastLogIdx = -1;
    lastPct = 0;
    shownFlags = new Set();
    autoScroll = true;
    const lockBtn = $("scroll-lock-btn");
    if (lockBtn) { lockBtn.textContent = '⬇ AUTO'; lockBtn.classList.remove('locked'); }
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
    pollTimer = setTimeout(async () => {
      try {
        const resp = await apiFetch('/find-evil/active');
        const data = await resp.json();
        handleStatus(data);
      } catch (e) {
        addLog("Poll error: " + e.message);
        pollStatus();
      }
    }, 1500);
  }

  function handleStatus(data) {
    // New format from /find-evil/active: {active_jobs: [...], count: N}
    if (data.active_jobs !== undefined) {
      if (data.count === 0) {
        // No active jobs — fall back to /find-evil/status/ for latest completed
        apiFetch('/find-evil/status/').then(r => r.json()).then(d => handleStatus(d)).catch(() => {});
        return;
      }
      const jobs = data.active_jobs;
      const lead = jobs.reduce((a, b) => (b.progress_pct > a.progress_pct ? b : a), jobs[0]);
      if (lead.job_id) currentJobId = lead.job_id;
      const pct = Math.round(lead.progress_pct || 0);

      if (pct > lastPct) {
        lastPct = pct;
        const pf = $("pbar-fill"); if (pf) pf.style.width = pct + "%";
        const pp = $("pbar-pct"); if (pp) pp.textContent = pct + "%";
        const ps = $("pbar-steps"); if (ps) ps.textContent = (`${lead.current_playbook || ''} · ${lead.current_step || ''}`).replace(/^ · | · $/, '') || (pct + "%");
      }

      const phaseIdx = pct >= 100 ? PHASES.length - 1 : playbookToPhase(lead.current_playbook, pct);
      setPhase(phaseIdx, "active");

      const log = lead.log || [];
      for (let i = lastLogIdx + 1; i < log.length; i++) {
        const entry = log[i];
        addLog(entry.msg || entry);
      }
      if (log.length > 0) lastLogIdx = log.length - 1;

      updateJobBanner(jobs);

      const vbadgeEl = $("vbadge");
      const vsEl = $("v-sevpill");
      if (vbadgeEl) {
        const pb = lead.current_playbook || '';
        vbadgeEl.textContent = pb ? pb.toUpperCase() : (pct >= 50 ? 'ANALYZING' : 'SCANNING');
      }
      if (vsEl) { vsEl.textContent = 'SCANNING'; vsEl.className = 'sev-pill'; vsEl.style.opacity = '1'; }
      updateThreat();
      pollStatus();
      return;
    }

    // Old format: single job object (from /find-evil/status/ fallback for completed jobs)
    if (data.job_id) currentJobId = data.job_id;
    const pct = Math.round(data.progress_pct || 0);
    const status = data.status;

    if (pct > lastPct) {
      lastPct = pct;
      const pf = $("pbar-fill"); if (pf) pf.style.width = pct + "%";
      const pp = $("pbar-pct"); if (pp) pp.textContent = pct + "%";
      const ps = $("pbar-steps"); if (ps) ps.textContent = (`${data.current_playbook || ''} · ${data.current_step || ''}`).replace(/^ · | · $/, '') || (pct + "%");
    }

    const phaseIdx = pct >= 100 ? PHASES.length - 1 : playbookToPhase(data.current_playbook, pct);
    setPhase(phaseIdx, status === 'complete' ? "done" : "active");

    const log = data.log || [];
    for (let i = lastLogIdx + 1; i < log.length; i++) {
      const entry = log[i];
      addLog(entry.msg || entry);
    }
    if (log.length > 0) lastLogIdx = log.length - 1;

    updateJobBanner([data]);

    if (status === 'complete') {
      const titleEl = $("op-title");
      if (titleEl) {
        const res = data.result || {};
        const dirName = (res.case_work_dir || res.evidence_dir || '').split('/').filter(Boolean).pop();
        titleEl.textContent = dirName || "Find Evil";
      }
      finishRunSuccess(data.result || {});
    } else if (status === 'error') {
      const titleEl = $("op-title"); if (titleEl) titleEl.textContent = "Find Evil";
      finishRunError(data.error || 'Investigation failed');
    } else {
      const vbadgeEl = $("vbadge");
      const vsEl = $("v-sevpill");
      if (vbadgeEl) {
        const pb = data.current_playbook || '';
        vbadgeEl.textContent = pb ? pb.toUpperCase() : (pct >= 50 ? 'ANALYZING' : 'SCANNING');
      }
      if (vsEl) { vsEl.textContent = 'SCANNING'; vsEl.className = 'sev-pill'; vsEl.style.opacity = '1'; }
      updateThreat();
      pollStatus();
    }
  }

  /* ---------- job banner ---------- */
  function showJobBanner(jobId, evidenceDir, pct, playbook, step) {
    currentJobId = jobId;
    const banner = $("job-banner"); if (!banner) return;
    banner.classList.add("active");
    updateJobBanner([{job_id: jobId, evidence_dir: evidenceDir, progress_pct: pct, current_playbook: playbook, current_step: step}]);
  }

  function updateJobBanner(jobs) {
    if (!jobs || jobs.length === 0) return;
    const banner = $("job-banner"); if (!banner) return;
    banner.classList.add("active");
    if (jobs.length === 1) {
      const job = jobs[0];
      const pct = Math.round(job.progress_pct || 0);
      const jbPct = $("jb-pct"); if (jbPct) jbPct.textContent = pct + "%";
      const jbInfo = $("jb-info");
      const playbook = job.current_playbook || '';
      const step = job.current_step || '';
      if (jbInfo) jbInfo.textContent = (playbook + (step ? ' · ' + step : '')).replace(/^ · | · $/, '') || (job.evidence_dir || '');
      const cards = $("jb-cards"); if (cards) cards.remove();
    } else {
      const jbPct = $("jb-pct"); if (jbPct) jbPct.textContent = jobs.length + " jobs";
      const jbInfo = $("jb-info"); if (jbInfo) jbInfo.textContent = "";
      let cards = $("jb-cards");
      if (!cards) {
        cards = document.createElement("div");
        cards.id = "jb-cards";
        cards.className = "jb-cards";
        const resume = $("jb-resume");
        if (resume) banner.insertBefore(cards, resume);
        else banner.appendChild(cards);
      }
      cards.innerHTML = "";
      for (const job of jobs) {
        const pct = Math.round(job.progress_pct || 0);
        const evName = (job.evidence_dir || 'unknown').split('/').filter(Boolean).pop() || 'unknown';
        const playbook = job.current_playbook || '';
        const step = job.current_step || '';
        const label = (playbook + (step ? ' · ' + step : '')).replace(/^ · | · $/, '');
        const elapsed = job.elapsed_seconds ? fmtElapsed(job.elapsed_seconds * 1000) : '—';
        const card = document.createElement("div");
        card.className = "jb-card";
        card.innerHTML = `<div class="jbc-head"><span class="jbc-name">${escHtml(evName)}</span><span class="jbc-pct">${pct}%</span></div>` +
          `<div class="jbc-bar"><i style="width:${pct}%"></i></div>` +
          `<div class="jbc-meta">${escHtml(label) || '—'}<span class="jbc-elapsed">${elapsed}</span></div>`;
        cards.appendChild(card);
      }
    }
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
    const caseEl = $("op-case"); if (caseEl) caseEl.textContent = "Ready";

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
      let viewerUrl = '/reports/narrative';
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
    const caseEl2 = $("op-case"); if (caseEl2) caseEl2.textContent = "Ready";

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
    const executionView = $("tab-execution");
    const settingsView = $("tab-settings");
    const queueView = $("tab-queue");

    if (consoleView) consoleView.style.display = (tab === 'console') ? 'flex' : 'none';
    if (evidenceView) { evidenceView.classList.toggle('active', tab === 'evidence'); }
    if (reportsView) { reportsView.classList.toggle('active', tab === 'reports'); }
    if (executionView) { executionView.classList.toggle('active', tab === 'execution'); }
    if (settingsView) { settingsView.classList.toggle('active', tab === 'settings'); }
    if (queueView) { queueView.classList.toggle('active', tab === 'queue'); }

    // Load data on first view
    if (tab === 'evidence') loadEvidencePanel();
    if (tab === 'reports') loadReportsPanel();
    if (tab === 'execution') loadExecutionPanel();
    if (tab === 'settings') loadSettingsPanel();
    if (tab === 'queue') loadQueue();
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

        // Clicking the case name populates the find-evil path input
        const nameEl = card.querySelector('.cc-name');
        if (nameEl) {
          nameEl.style.cursor = 'pointer';
          nameEl.title = 'Click to set as Find Evil target';
          nameEl.onclick = (e) => {
            e.stopPropagation();
            const evdirInput = $("evdir");
            if (evdirInput) evdirInput.value = EVIDENCE_DIR ? EVIDENCE_DIR + '/' + caseName : caseName;
            switchTab('console');
          };
        }
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
        const caseName = rpt.case_name || rpt.dir;
        card.innerHTML = `
          <div class="rt-top">
            <span class="rt-name">${escHtml(caseName)}</span>
            <span class="sev-pill ${sev}">${sev}</span>
            ${isEvil ? '<span class="sev-pill CRITICAL" style="font-size:9px;">EVIL</span>' : '<span class="sev-pill" style="font-size:9px;background:var(--g-green);color:var(--g-bg);">CLEAN</span>'}
          </div>
          <div class="rt-meta">
            <span>${dateStr}</span>
            <span>${elapsedStr}</span>
            <span>${rpt.classification || 'unclassified'}</span>
          </div>
          <div class="rt-desc">${escHtml(rpt.evidence_dir || '')}</div>
          <div class="rt-actions">
            <span class="rt-chat-btn" data-dir="${escHtml(rpt.dir)}" data-name="${escHtml(caseName)}">&#128172; Ask GEOFF</span>
          </div>
        `;
        card.querySelector('.rt-chat-btn').addEventListener('click', (e) => {
          e.stopPropagation();
          selectReportForChat(rpt.dir, caseName);
        });
        card.onclick = () => {
          const caseDir = encodeURIComponent(rpt.dir);
          window.open('/reports/narrative?case=' + caseDir, '_blank');
        };
        body.appendChild(card);
      });
    } catch (e) {
      body.innerHTML = '<div class="case-empty">Failed to load reports: ' + escHtml(e.message) + '</div>';
    }
  }

  /* ============================================================
     REPORTS TAB CHAT
     ============================================================ */
  let rpChatCase = null;
  let rpChatCaseName = '';

  window.toggleRpChat = function() {
    const dock = $('rp-chat-dock');
    const tog = $('rp-chat-toggle');
    if (!dock) return;
    dock.classList.toggle('collapsed');
    if (tog) tog.textContent = dock.classList.contains('collapsed') ? '▲' : '▼';
  };

  function rpPushMsg(who, html) {
    const s = $('rp-chat-scroll');
    if (!s) return null;
    const m = el('div', 'rp-msg ' + who);
    m.innerHTML = html;
    s.appendChild(m);
    s.scrollTop = s.scrollHeight;
    return m;
  }

  function selectReportForChat(dir, name) {
    rpChatCase = dir;
    rpChatCaseName = name;
    // Deselect all cards, select this one
    document.querySelectorAll('#rp-panel-body .rpt-card').forEach(c => c.classList.remove('rp-selected'));
    const btn = document.querySelector(`.rt-chat-btn[data-dir="${CSS.escape(dir)}"]`);
    if (btn) btn.closest('.rpt-card').classList.add('rp-selected');
    // Show and expand dock
    const dock = $('rp-chat-dock');
    if (dock) { dock.classList.remove('hidden'); dock.classList.remove('collapsed'); }
    const label = $('rp-chat-label');
    if (label) label.textContent = 'GEOFF — ' + name;
    // Reset messages
    const scroll = $('rp-chat-scroll');
    if (scroll) {
      scroll.innerHTML = '';
      rpPushMsg('geoff', '<b>GEOFF</b>Loaded <em>' + escHtml(name) + '</em>. Ask me anything about this investigation.');
    }
    const input = $('rp-chat-input');
    if (input) input.focus();
  }

  async function rpSendChat() {
    const input = $('rp-chat-input');
    const txt = input && input.value.trim();
    if (!txt || !rpChatCase) return;
    rpPushMsg('user', escHtml(txt));
    input.value = '';
    const thinking = rpPushMsg('geoff', '<b>GEOFF</b><span style="color:var(--g-text-faint)">thinking…</span>');

    try {
      const resp = await apiFetch('/reports/' + encodeURIComponent(rpChatCase) + '/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: txt }),
      });
      const data = await resp.json();
      if (thinking) thinking.remove();
      const answer = data.answer || data.response || 'No response.';
      const msgDiv = rpPushMsg('geoff', '<b>GEOFF</b>' + escHtml(answer));
      if (data.suggest_playbook && msgDiv) {
        const btn = document.createElement('button');
        btn.className = 'dig-deeper-btn';
        btn.innerHTML = '&#128269; Dig Deeper [' + escHtml(data.suggest_playbook) + ']';
        btn.onclick = () => rpDigDeeper(rpChatCase, data.suggest_playbook);
        msgDiv.appendChild(btn);
      }
    } catch (e) {
      if (thinking) thinking.remove();
      rpPushMsg('geoff', '<b>GEOFF</b>Error: ' + escHtml(e.message));
    }
  }

  async function rpDigDeeper(caseDir, playbookId) {
    const msg = rpPushMsg('geoff', '<b>GEOFF</b>&#128269; Running deeper analysis [' + escHtml(playbookId) + ']…');
    try {
      const resp = await apiFetch('/replay-playbook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case: caseDir, playbook_id: playbookId }),
      });
      const data = await resp.json();
      if (msg) msg.remove();
      if (data.status === 'complete') {
        rpPushMsg('geoff', '<b>GEOFF</b>✓ Re-analysis complete. Found <b>' + (data.new_findings || 0) + '</b> new findings from ' + escHtml(playbookId) + '.');
      } else {
        rpPushMsg('geoff', '<b>GEOFF</b>Re-analysis result: ' + escHtml(data.error || data.message || JSON.stringify(data)));
      }
    } catch (e) {
      if (msg) msg.remove();
      rpPushMsg('geoff', '<b>GEOFF</b>Error during re-analysis: ' + escHtml(e.message));
    }
  }

  // Wire up Reports tab chat events
  (function() {
    const sendBtn = $('rp-chat-send');
    const chatInput = $('rp-chat-input');
    if (sendBtn) sendBtn.addEventListener('click', rpSendChat);
    if (chatInput) chatInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); rpSendChat(); }
    });
  })();

  /* ============================================================
     LIVE JOB DETECTION — CHECK FOR RUNNING JOBS ON PAGE LOAD
     ============================================================ */
  async function checkActiveJobs() {
    try {
      const resp = await apiFetch('/find-evil/active');
      if (!resp.ok) return;
      const data = await resp.json();
      const jobs = data.active_jobs || [];

      if (jobs.length === 0) {
        const titleEl = $("op-title"); if (titleEl) titleEl.textContent = "Find Evil";
        return;
      }

      // Found running jobs — show banner for all, use most advanced as lead
      const lead = jobs.reduce((a, b) => (b.progress_pct > a.progress_pct ? b : a), jobs[0]);
      currentJobId = lead.job_id;
      updateJobBanner(jobs);
      const banner = $("job-banner"); if (banner) banner.classList.add("active");

      const live = $("op-live"); if (live) live.style.display = "inline-flex";

      if (lead.started_at) {
        const startedMs = new Date(lead.started_at).getTime();
        t0 = Date.now() - (Date.now() - startedMs);
      } else {
        t0 = Date.now();
      }
      elapsedTimer = setInterval(() => {
        const el2 = $("op-elapsed"); if (el2) el2.textContent = "elapsed " + fmtElapsed(Date.now() - t0);
      }, 1000);

      const runbtn = $("runbtn"); if (runbtn) { runbtn.textContent = "■ Running…"; runbtn.style.opacity = ".7"; }
      addLog(`Detected ${jobs.length} running job${jobs.length > 1 ? 's' : ''} — ${jobs.map(j => j.job_id).join(', ')}`);
      jobs.forEach(j => addLog("Evidence: " + (j.evidence_dir || 'unknown')));
      pollStatus();
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
  const navExecution = $("nav-execution");
  if (navConsole) navConsole.onclick = (e) => { e.preventDefault(); switchTab('console'); };
  if (navEvidence) navEvidence.onclick = (e) => { e.preventDefault(); switchTab('evidence'); };
  if (navReports) navReports.onclick = (e) => { e.preventDefault(); switchTab('reports'); };
  if (navExecution) navExecution.onclick = (e) => { e.preventDefault(); switchTab('execution'); };
  const navSettings = $("nav-settings");
  if (navSettings) navSettings.onclick = (e) => { e.preventDefault(); switchTab('settings'); };
  const navQueue = $("nav-queue");
  if (navQueue) navQueue.onclick = (e) => { e.preventDefault(); switchTab('queue'); };

  // Job banner resume button
  const jbResume = $("jb-resume");
  if (jbResume) jbResume.onclick = () => {
    switchTab('console');
    const path = $("evdir")?.value?.trim();
    if (path) runFindEvil();
  };

  loadManifest();

  // Check for active jobs on page load
  checkActiveJobs();
  initScrollLock();

  /* ============================================================
     EXECUTION LOG TAB
     ============================================================ */

  let executionLoaded = false;

  async function loadExecutionPanel() {
    const body = $("exec-body");
    if (!body) return;
    if (executionLoaded) return;
    executionLoaded = true;

    body.innerHTML = '<div class="case-empty">Loading cases…</div>';
    try {
      const resp = await apiFetch('/reports');
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const data = await resp.json();
      const reports = (data.reports || []).filter(r => r.elapsed_seconds > 0);
      const label = $("exec-case-label");

      if (reports.length === 0) {
        body.innerHTML = '<div class="case-empty">No completed investigations found. Run Find Evil first.</div>';
        return;
      }
      if (label) label.textContent = reports.length + ' cases';
      body.innerHTML = '';

      const sorted = [...reports].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      sorted.forEach(rpt => {
        const isEvil = rpt.evil_found;
        const sev = (rpt.severity || 'INFO').toUpperCase();
        const elapsed = rpt.elapsed_seconds ? Math.round(rpt.elapsed_seconds) : 0;
        const elapsedStr = elapsed >= 60
          ? Math.floor(elapsed / 60) + 'm ' + (elapsed % 60) + 's'
          : elapsed + 's';
        const card = el("div", "rpt-card " + (isEvil ? "evil" : "clean"));
        card.innerHTML = `
          <div class="rt-top">
            <span class="rt-name">${escHtml(rpt.case_name || rpt.dir)}</span>
            <span class="sev-pill ${isEvil ? sev : ''}">${isEvil ? 'EVIL FOUND' : 'CLEAN'}</span>
          </div>
          <div class="rt-meta">
            <span>${escHtml(elapsedStr)}</span>
            <span>${escHtml(rpt.classification || 'unclassified')}</span>
          </div>
          <div class="rt-desc">${escHtml(rpt.evidence_dir || rpt.dir || '')}</div>
        `;
        card.onclick = () => loadExecutionCase(rpt.dir);
        body.appendChild(card);
      });
    } catch (e) {
      const b = $("exec-body");
      if (b) b.innerHTML = '<div class="case-empty">Failed to load cases: ' + escHtml(e.message) + '</div>';
    }
  }

  async function loadExecutionCase(caseDir) {
    const body = $("exec-body");
    const label = $("exec-case-label");
    if (!body) return;
    body.innerHTML = '<div class="case-empty">Loading execution log…</div>';
    if (label) label.textContent = 'Loading…';
    try {
      const resp = await apiFetch('/reports/execution/' + encodeURIComponent(caseDir));
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ error: 'HTTP ' + resp.status }));
        throw new Error(err.error || 'HTTP ' + resp.status);
      }
      const data = await resp.json();
      renderExecutionLog(data, caseDir);
    } catch (e) {
      const b = $("exec-body");
      if (b) b.innerHTML = '<div class="case-empty" style="color:var(--sev-crit)">Error: ' + escHtml(e.message) + '</div>';
      if (label) label.textContent = 'Error';
    }
  }

  // Expose for back button (called from inline onclick)
  window._execGoBack = function() {
    executionLoaded = false;
    const label = $("exec-case-label");
    if (label) label.textContent = 'Select a case';
    loadExecutionPanel();
  };

  function renderExecutionLog(data, caseDir) {
    const body = $("exec-body");
    const label = $("exec-case-label");
    if (!body) return;
    const meta = data.metadata || {};
    if (label) label.textContent = meta.case_id || caseDir;

    const elapsed = meta.elapsed_seconds ? Math.round(meta.elapsed_seconds) : 0;
    const elapsedStr = elapsed >= 60
      ? Math.floor(elapsed / 60) + 'm ' + (elapsed % 60) + 's'
      : elapsed + 's';
    const isEvil = meta.evil_found;
    const sev = (meta.severity || '').toUpperCase();

    body.innerHTML = '';

    // Back button
    const back = el("div", "");
    back.style.cssText = "display:flex;align-items:center;gap:10px;padding:0 0 14px;";
    back.innerHTML = `<button class="btn" onclick="window._execGoBack()" style="font-size:11px;padding:5px 12px;">← Cases</button>
      <span style="font-family:var(--font-mono);font-size:11px;color:var(--g-text-mute)">${escHtml(caseDir)}</span>`;
    body.appendChild(back);

    // Case header
    const hdr = el("div", "exec-case-hdr");
    hdr.innerHTML = `
      <div class="ech-top">
        ${isEvil
          ? `<span class="sev-pill ${sev}" style="font-size:12px;">${escHtml(sev || 'EVIL')}</span>`
          : '<span class="sev-pill" style="font-size:12px;background:var(--g-green);color:var(--g-bg);">CLEAN</span>'}
        <span class="ech-id">${escHtml(meta.case_id || caseDir)}</span>
        ${meta.verdict ? `<span class="tag-mono">${escHtml(meta.verdict)}</span>` : ''}
      </div>
      ${meta.evidence_dir ? `<div class="ech-path">${escHtml(meta.evidence_dir)}</div>` : ''}
      <div class="ech-meta">
        ${elapsed ? `<span>Runtime: ${escHtml(elapsedStr)}</span>` : ''}
        ${meta.total_evidence_items ? `<span>Evidence: ${escHtml(String(meta.total_evidence_items))} items</span>` : ''}
        ${meta.classification ? `<span>${escHtml(meta.classification)}</span>` : ''}
      </div>
    `;
    body.appendChild(hdr);

    // Phase timeline from audit trail
    const phaseSec = _execPhaseTimeline(data.audit_trail);
    if (phaseSec) body.appendChild(phaseSec);

    // Download bar
    body.appendChild(_execDownloadBar(caseDir));

    // Collapsible sections
    body.appendChild(_execSection('Agent Trace',
      data.agent_trace ? data.agent_trace.length : null,
      data.agent_trace, _renderExecAgentTrace));
    body.appendChild(_execSection('Chain of Custody',
      data.custody ? data.custody.length : null,
      data.custody, _renderExecCustody));
    body.appendChild(_execSection('Critic Assessment & Manager Decision',
      null, data, _renderExecCritic));
    body.appendChild(_execSection('Audit Trail',
      data.audit_trail ? data.audit_trail.length : null,
      data.audit_trail, _renderExecAuditTrail));
    body.appendChild(_execSection('Findings',
      data.findings ? data.findings.length : null,
      data.findings, _renderExecFindings));
  }

  function _execPhaseTimeline(auditTrail) {
    if (!auditTrail || !auditTrail.length) return null;
    const seenEvents = new Set(auditTrail.map(r => (r.event || '').toUpperCase()));
    const phaseMap = [
      { label: 'Inventory',  key: 'INVENTORY' },
      { label: 'Triage',     key: 'TRIAGE' },
      { label: 'Analysis',   key: 'PLAYBOOK' },
      { label: 'Critic',     key: 'BATCH_CRITIC' },
      { label: 'Manager',    key: 'MANAGER' },
      { label: 'Report',     key: 'NARRATIVE' },
    ];
    const wrap = el("div", "");
    wrap.style.cssText = "padding:0 0 16px;";
    const phasesDiv = el("div", "phases");
    phasesDiv.style.cssText = "padding:0 0 4px;overflow:visible;";
    phaseMap.forEach(p => {
      const done = [...seenEvents].some(e => e.includes(p.key));
      const ph = el("div", "phase" + (done ? " done" : ""));
      ph.innerHTML = `<div class="bar"><i></i></div><div class="dot">✓</div><div class="pn">${escHtml(p.label)}</div>`;
      phasesDiv.appendChild(ph);
    });
    wrap.appendChild(phasesDiv);
    return wrap;
  }

  function _execDownloadBar(caseDir) {
    const bar = el("div", "exec-dl-bar");
    const enc = encodeURIComponent(caseDir);
    [
      { label: '↓ Narrative MD', url: `/reports/${enc}/download/markdown` },
      { label: '↓ Report JSON',  url: `/reports/${enc}/download/json` },
      { label: '↓ Summary',      url: `/reports/${enc}/download/summary` },
      { label: '↓ Audit Trail',  url: `/reports/${enc}/download/audit_trail` },
    ].forEach(d => {
      const a = el("a", "exec-dl-btn");
      a.href = d.url; a.textContent = d.label; a.target = '_blank';
      bar.appendChild(a);
    });
    const regen = el("button", "exec-dl-btn");
    regen.textContent = '↺ Regenerate Report';
    regen.title = 'Re-run narrative report generation using saved find_evil_report.json (no full re-investigation)';
    regen.addEventListener('click', () => {
      regen.textContent = '↺ Regenerating…';
      regen.disabled = true;
      apiFetch(`/reports/${enc}/regenerate`, { method: 'POST' })
        .then(r => r.json())
        .then(data => {
          if (data.ok) {
            regen.textContent = '✓ Report regenerated';
            setTimeout(() => location.reload(), 800);
          } else {
            regen.textContent = '✗ Failed';
            regen.title = data.error || 'Unknown error';
            regen.disabled = false;
          }
        })
        .catch(e => {
          regen.textContent = '✗ Error';
          regen.title = String(e);
          regen.disabled = false;
        });
    });
    bar.appendChild(regen);
    return bar;
  }

  function _execSection(title, count, data, renderFn) {
    const sec = el("div", "exec-section");
    const hasData = data !== null && data !== undefined &&
      (Array.isArray(data) ? data.length > 0 : (typeof data === 'object'));
    const countStr = count !== null && count !== undefined ? ` (${count})` : '';
    const avail = hasData ? countStr : ' — not available';
    sec.innerHTML = `
      <div class="exec-section-head">
        <span class="esh-title">${escHtml(title)}</span>
        <span class="esh-cnt">${escHtml(avail)}</span>
        <span class="esh-arrow">▶</span>
      </div>
      <div class="exec-section-body"></div>
    `;
    const head = sec.querySelector('.exec-section-head');
    const bodyEl = sec.querySelector('.exec-section-body');
    let rendered = false;
    head.onclick = () => {
      if (!hasData) return;
      const isOpen = sec.classList.toggle('open');
      if (isOpen && !rendered) {
        rendered = true;
        bodyEl.appendChild(renderFn(data));
      }
    };
    return sec;
  }

  function _renderExecAgentTrace(records) {
    const wrap = el("div", "");
    const MAX = 300;
    records.slice(0, MAX).forEach(r => {
      const row = el("div", "exec-trace-row");
      const ts = (r.ts || r.timestamp || '').replace('T', ' ').slice(0, 19);
      const agent = r.agent || r.role || '—';
      const event = r.event || r.event_type || '—';
      const msg = String(r.msg || r.message || r.summary || '').slice(0, 220);
      const detail = JSON.stringify(r, null, 2);
      row.innerHTML = `
        <span class="etr-ts">${escHtml(ts)}</span>
        <span class="etr-agent">${escHtml(agent)}</span>
        <span class="etr-event">${escHtml(event)}</span>
        <span class="etr-msg">${escHtml(msg)}</span>
        <span class="etr-expand">▶</span>
      `;
      let detailEl = null;
      row.querySelector('.etr-expand').onclick = (e) => {
        e.stopPropagation();
        const btn = row.querySelector('.etr-expand');
        if (!detailEl) {
          detailEl = el("div", "");
          detailEl.style.cssText = "grid-column:1/-1;margin-top:8px;background:var(--g-surface-2);border-radius:var(--radius-sm);padding:10px;color:var(--g-text-dim);font-family:var(--font-mono);font-size:10.5px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:280px;overflow-y:auto;";
          detailEl.textContent = detail;
          row.appendChild(detailEl);
          btn.textContent = '▼';
        } else {
          detailEl.remove(); detailEl = null;
          btn.textContent = '▶';
        }
      };
      wrap.appendChild(row);
    });
    if (records.length > MAX) {
      const more = el("div", "");
      more.style.cssText = "padding:10px 16px;font-family:var(--font-mono);font-size:11px;color:var(--g-text-mute);";
      more.textContent = '… ' + (records.length - MAX) + ' more records (see agent_trace.jsonl for full log)';
      wrap.appendChild(more);
    }
    return wrap;
  }

  function _renderExecCustody(records) {
    const wrap = el("div", "");
    records.forEach(r => {
      const row = el("div", "exec-cust-row");
      const stepKey = r.step_key || (r._filename || '').replace('.json', '') || '—';
      const hash = r.evidence_sha256 || r.sha256 || r.hash || '—';
      const ts = (r.timestamp || r.committed_at || '').replace('T', ' ').slice(0, 19);
      const hashShort = String(hash).slice(0, 20) + (String(hash).length > 20 ? '…' : '');
      row.innerHTML = `
        <span class="ecr-key">${escHtml(stepKey)}</span>
        <span class="ecr-hash" title="${escHtml(String(hash))}">${escHtml(hashShort)}</span>
        <span class="ecr-ts">${escHtml(ts)}</span>
      `;
      wrap.appendChild(row);
    });
    return wrap;
  }

  function _renderExecCritic(data) {
    const wrap = el("div", "exec-critic-grid");
    const ca = data.critic_assessment || {};
    const md = data.manager_decision || {};

    const criticBox = el("div", "exec-critic-box");
    const qColor = ca.overall_quality === 'GOOD' ? 'var(--g-green)' :
                   ca.overall_quality === 'POOR' ? 'var(--sev-crit)' : 'var(--g-text)';
    criticBox.innerHTML = `
      <span class="ecb-label">Batch Critic Assessment</span>
      ${ca.overall_quality ? `<div class="ecb-big" style="color:${qColor}">${escHtml(ca.overall_quality)}</div>` : ''}
      <div class="ecb-val" style="margin-top:10px;">${ca.assessment_summary ? escHtml(ca.assessment_summary) : '<span style="color:var(--g-text-faint)">Not available</span>'}</div>
      ${ca.hallucination_flags && ca.hallucination_flags.length
        ? `<div class="ecb-val" style="margin-top:8px;color:var(--sev-med);">&#9888; ${escHtml(String(ca.hallucination_flags.length))} hallucination flag(s)</div>` : ''}
      ${ca.sufficient_for_report !== undefined
        ? `<div class="ecb-val" style="margin-top:6px;">Sufficient for report: ${ca.sufficient_for_report ? 'Yes' : 'No'}</div>` : ''}
      ${ca.critic_executed === false
        ? `<div class="ecb-val" style="margin-top:6px;color:var(--g-text-mute);">Critic unavailable: ${escHtml(ca.critic_unavailable_reason || 'unknown')}</div>` : ''}
    `;

    const manBox = el("div", "exec-critic-box");
    const aColor = md.action === 'approve' ? 'var(--g-green)' :
                   md.action === 'replay'  ? 'var(--sev-med)' :
                   md.action === 'flag'    ? 'var(--sev-high)' : 'var(--g-text)';
    manBox.innerHTML = `
      <span class="ecb-label">Manager Decision</span>
      ${md.action ? `<div class="ecb-big" style="color:${aColor}">${escHtml(md.action.toUpperCase())}</div>` : ''}
      <div class="ecb-val" style="margin-top:10px;">${md.reasoning ? escHtml(md.reasoning) : '<span style="color:var(--g-text-faint)">Not available</span>'}</div>
      ${md.auto_approved ? `<div class="ecb-val" style="margin-top:6px;color:var(--g-text-mute);">Auto-approved: ${escHtml(md.auto_approve_reason || 'unknown')}</div>` : ''}
    `;

    wrap.appendChild(criticBox);
    wrap.appendChild(manBox);
    return wrap;
  }

  function _renderExecAuditTrail(records) {
    const wrap = el("div", "");
    records.forEach(r => {
      const row = el("div", "exec-audit-row");
      const ts = (r.ts || r.timestamp || '').replace('T', ' ').slice(0, 19);
      const event = r.event || '—';
      const detail = Object.entries(r)
        .filter(([k]) => !['ts', 'timestamp', 'event'].includes(k))
        .map(([k, v]) => `${k}=${typeof v === 'object'
          ? JSON.stringify(v).slice(0, 80)
          : String(v).slice(0, 80)}`)
        .join('  ');
      row.innerHTML = `
        <span class="ear-ts">${escHtml(ts)}</span>
        <span class="ear-event">${escHtml(event)}</span>
        <span class="ear-detail">${escHtml(detail)}</span>
      `;
      wrap.appendChild(row);
    });
    return wrap;
  }

  function _renderExecFindings(records) {
    const SEV_COLOR = {
      CRITICAL: 'var(--sev-crit)', HIGH: 'var(--sev-high)',
      MEDIUM: 'var(--sev-med)', LOW: 'var(--sev-low)', INFO: 'var(--g-text-mute)',
    };
    const wrap = el("div", "");
    records.forEach(r => {
      const row = el("div", "exec-finding-row");
      const obs = r.observation || r.result || {};
      const sev = (obs.significance || obs.severity || r.significance || '').toUpperCase();
      const sevColor = SEV_COLOR[sev] || 'var(--g-text-mute)';
      const note = obs.analyst_note || obs.description || obs.summary || r.analyst_note || '';
      const iocs = obs.threat_indicators || obs.iocs || r.threat_indicators || [];
      const stepKey = r.step_key || (r.module && r.function ? `${r.module}.${r.function}` : '—');
      row.innerHTML = `
        <div class="efr-head">
          ${sev ? `<span class="sev-pill" style="background:${sevColor};font-size:10px;">${escHtml(sev)}</span>` : ''}
          <span style="font-family:var(--font-mono);font-size:11px;color:var(--g-text-dim)">${escHtml(stepKey)}</span>
        </div>
        ${note ? `<div class="efr-note">${escHtml(note)}</div>` : ''}
        ${iocs.length ? `<div class="efr-iocs">${
          iocs.slice(0, 10).map(ioc => `<span class="tag-mono" style="font-size:9.5px;">${escHtml(String(ioc))}</span>`).join('')
          }${iocs.length > 10 ? `<span style="font-family:var(--font-mono);font-size:9.5px;color:var(--g-text-faint)">&nbsp;+${iocs.length - 10} more</span>` : ''}</div>` : ''}
      `;
      wrap.appendChild(row);
    });
    return wrap;
  }


  // =====================================================================
  // Queue Tab
  // =====================================================================
  (function () {
    const $ = (id) => document.getElementById(id);
    const el = (tag, cls, html) => {
      const n = document.createElement(tag); if (cls) n.className = cls; if (html != null) n.innerHTML = html; return n;
    };

    let _pollTimer = null;
    let _dragSrcId = null;

    function fmtElapsed(secs) {
      if (!secs) return '0m';
      secs = Math.round(secs);
      const h = Math.floor(secs / 3600);
      const m = Math.floor((secs % 3600) / 60);
      const s = secs % 60;
      if (h > 0) return `${h}h ${m}m`;
      if (m > 0) return `${m}m ${s}s`;
      return `${s}s`;
    }

    function fmtTime(iso) {
      if (!iso) return '—';
      try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
      catch { return iso.slice(11, 16); }
    }

    function fmtDate(iso) {
      if (!iso) return '—';
      try {
        const d = new Date(iso);
        const today = new Date();
        if (d.toDateString() === today.toDateString()) return fmtTime(iso);
        return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + fmtTime(iso);
      } catch { return iso.slice(0, 16); }
    }

    function statusIcon(status) {
      return { queued: '⏳', running: '🔄', completed: '✅', failed: '❌', cancelled: '⊘' }[status] || '·';
    }

    // ----- Drag reorder helpers -----
    function attachDrag(card, item, items) {
      card.draggable = true;
      card.addEventListener('dragstart', e => {
        _dragSrcId = item.id;
        card.style.opacity = '0.5';
        e.dataTransfer.effectAllowed = 'move';
      });
      card.addEventListener('dragend', () => { card.style.opacity = ''; });
      card.addEventListener('dragover', e => { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; card.style.outline = '1px solid var(--g-blue)'; });
      card.addEventListener('dragleave', () => { card.style.outline = ''; });
      card.addEventListener('drop', e => {
        e.preventDefault(); card.style.outline = '';
        if (_dragSrcId && _dragSrcId !== item.id) {
          reorderItems(_dragSrcId, item.id, items);
        }
        _dragSrcId = null;
      });
    }

    function reorderItems(srcId, dstId, items) {
      const queued = items.filter(i => i.status === 'queued');
      const srcIdx = queued.findIndex(i => i.id === srcId);
      const dstIdx = queued.findIndex(i => i.id === dstId);
      if (srcIdx < 0 || dstIdx < 0) return;
      // Reassign priorities: give moved item the dst priority
      apiFetch(`/queue/${srcId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ priority: queued[dstIdx].priority }),
      }).then(() => apiFetch(`/queue/${dstId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ priority: queued[srcIdx].priority }),
      })).then(() => loadQueue()).catch(() => loadQueue());
    }

    // ----- Render sections -----
    function renderRunning(item) {
      const wrap = $('queue-running-section'); if (!wrap) return;
      wrap.innerHTML = '';
      if (!item) return;
      const card = el('div', 'queue-card queue-running');
      const pct = Math.round(item.progress_pct || 0);
      const pb = item.current_playbook || '';
      const step = item.current_step || '';
      card.innerHTML = `
        <div class="qc-head">
          <span class="qc-icon">🔄</span>
          <span class="qc-name">${escHtml(item.display_name)}</span>
          <span class="qc-pct">${pct}%</span>
          <button class="btn" style="font-size:11px;padding:4px 10px;color:var(--sev-crit);border-color:rgba(255,77,94,.3);" data-action="cancel" data-id="${escHtml(item.id)}">Cancel</button>
        </div>
        <div class="qc-progress">
          <div class="qc-pbar"><i style="width:${pct}%"></i></div>
        </div>
        <div class="qc-meta">
          ${pb ? `<span class="qc-badge">${escHtml(pb)}</span>` : ''}
          ${step ? `<span style="color:var(--g-text-mute);font-size:11px;">${escHtml(step.slice(0, 80))}</span>` : ''}
        </div>
        <div class="qc-footer">
          <span>Started ${fmtTime(item.started_at)}</span>
          <span>Elapsed ${fmtElapsed(item.elapsed_seconds)}</span>
          <span style="font-family:var(--font-mono);font-size:10px;color:var(--g-text-faint);">${escHtml(item.job_id || '')}</span>
        </div>`;
      card.querySelector('[data-action="cancel"]').onclick = () => cancelItem(item.id);
      const sect = el('div', '');
      sect.innerHTML = '<div class="queue-section-head"><span class="eyebrow" style="color:var(--g-blue-soft);">Running</span></div>';
      sect.appendChild(card);
      wrap.appendChild(sect);
    }

    function renderQueued(items, allItems) {
      const wrap = $('queue-queued-section'); if (!wrap) return;
      wrap.innerHTML = '';
      const queued = items.filter(i => i.status === 'queued').sort((a, b) => a.priority - b.priority);
      if (!queued.length) return;
      const sect = el('div', '');
      sect.innerHTML = `<div class="queue-section-head"><span class="eyebrow">Queued (drag to reorder)</span><span class="cnt">${queued.length}</span></div>`;
      queued.forEach((item, idx) => {
        const card = el('div', 'queue-card queue-queued');
        card.innerHTML = `
          <div class="qc-head">
            <span class="qc-drag" title="Drag to reorder">⠿⠿</span>
            <span class="qc-pos">#${idx + 1}</span>
            <span class="qc-name">${escHtml(item.display_name)}</span>
            <span style="flex:1;"></span>
            <span style="font-family:var(--font-mono);font-size:10px;color:var(--g-text-faint);">${escHtml(item.evidence_path)}</span>
            <button class="btn ghost" style="font-size:11px;padding:4px 10px;" data-action="remove" data-id="${escHtml(item.id)}">Remove</button>
          </div>
          <div class="qc-footer">
            <span>Queued ${fmtDate(item.queued_at)}</span>
            <span>Priority ${item.priority}</span>
          </div>`;
        card.querySelector('[data-action="remove"]').onclick = () => removeItem(item.id);
        attachDrag(card, item, allItems);
        sect.appendChild(card);
      });
      wrap.appendChild(sect);
    }

    function renderCompleted(items) {
      const wrap = $('queue-done-section'); if (!wrap) return;
      wrap.innerHTML = '';
      const done = items.filter(i => i.status === 'completed');
      if (!done.length) return;
      const sect = el('div', '');
      sect.innerHTML = `<div class="queue-section-head"><span class="eyebrow" style="color:var(--g-green);">Completed</span><span class="cnt">${done.length}</span></div>`;
      done.forEach(item => {
        const card = el('div', 'queue-card queue-done');
        const summary = item.result_summary || '';
        card.innerHTML = `
          <div class="qc-head">
            <span class="qc-icon">✅</span>
            <span class="qc-name">${escHtml(item.display_name)}</span>
            <span style="flex:1;"></span>
            ${summary ? `<span class="qc-badge" style="background:rgba(37,211,150,.12);color:var(--g-green);border-color:rgba(37,211,150,.3);">${escHtml(summary)}</span>` : ''}
          </div>
          <div class="qc-footer">
            <span>Finished ${fmtDate(item.completed_at)}</span>
            <span>Elapsed ${fmtElapsed(item.elapsed_seconds)}</span>
          </div>`;
        sect.appendChild(card);
      });
      wrap.appendChild(sect);
    }

    function renderFailed(items) {
      const wrap = $('queue-failed-section'); if (!wrap) return;
      wrap.innerHTML = '';
      const failed = items.filter(i => i.status === 'failed' || i.status === 'cancelled');
      if (!failed.length) return;
      const sect = el('div', '');
      sect.innerHTML = `<div class="queue-section-head"><span class="eyebrow" style="color:var(--sev-crit);">Failed / Cancelled</span><span class="cnt">${failed.length}</span></div>`;
      failed.forEach(item => {
        const card = el('div', 'queue-card queue-failed');
        card.innerHTML = `
          <div class="qc-head">
            <span class="qc-icon">${item.status === 'cancelled' ? '⊘' : '❌'}</span>
            <span class="qc-name">${escHtml(item.display_name)}</span>
            <span style="flex:1;"></span>
            <button class="btn" style="font-size:11px;padding:4px 10px;" data-action="retry" data-path="${escHtml(item.evidence_path)}">Retry</button>
          </div>
          ${item.error ? `<div style="font-family:var(--font-mono);font-size:11px;color:var(--sev-crit);margin-top:4px;">${escHtml(item.error.slice(0, 200))}</div>` : ''}
          <div class="qc-footer"><span>${fmtDate(item.completed_at || item.queued_at)}</span></div>`;
        card.querySelector('[data-action="retry"]').onclick = () => enqueueEvidence(item.evidence_path);
        sect.appendChild(card);
      });
      wrap.appendChild(sect);
    }

    function renderQueue(data) {
      const items = data.items || [];
      const running = data.running || null;
      const cntEl = $('queue-cnt');
      if (cntEl) {
        const q = items.filter(i => i.status === 'queued').length;
        cntEl.textContent = running ? `1 running · ${q} queued` : `${q} queued`;
      }
      renderRunning(running);
      renderQueued(items, items);
      renderCompleted(items);
      renderFailed(items);
    }

    // ----- API calls -----
    function loadQueue() {
      apiFetch('/queue').then(r => r.json()).then(data => {
        if (data.status === 'ok') renderQueue(data);
        schedulePoll(data);
      }).catch(() => {});
    }

    function schedulePoll(data) {
      clearTimeout(_pollTimer);
      const items = data.items || [];
      const hasRunning = items.some(i => i.status === 'running');
      if (hasRunning) {
        _pollTimer = setTimeout(loadQueue, 5000);
      }
    }

    function cancelItem(id) {
      if (!confirm('Cancel this job and clean up its resources?')) return;
      apiFetch(`/queue/${id}/cancel`, { method: 'POST' })
        .then(() => loadQueue()).catch(e => alert('Cancel failed: ' + e));
    }

    function removeItem(id) {
      apiFetch(`/queue/${id}`, { method: 'DELETE' })
        .then(() => loadQueue()).catch(e => alert('Remove failed: ' + e));
    }

    function enqueueEvidence(path) {
      if (!path) return;
      const msgEl = $('queue-enqueue-msg');
      apiFetch('/queue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ evidence_dir: path }),
      }).then(r => r.json()).then(data => {
        if (data.status === 'queued') {
          if (msgEl) msgEl.textContent = '✓ Enqueued: ' + (data.item && data.item.display_name);
          const inp = $('queue-path-input'); if (inp) inp.value = '';
          loadQueue();
        } else {
          if (msgEl) msgEl.textContent = '✗ ' + (data.error || 'Failed');
        }
      }).catch(e => { if (msgEl) msgEl.textContent = '✗ ' + e; });
    }

    // ----- Init -----
    function initQueue() {
      // Enqueue button
      const btn = $('queue-enqueue-btn');
      if (btn) btn.onclick = () => {
        const inp = $('queue-path-input');
        enqueueEvidence(inp ? inp.value.trim() : '');
      };
      const inp = $('queue-path-input');
      if (inp) inp.addEventListener('keydown', e => { if (e.key === 'Enter') btn && btn.click(); });

      // Force advance button
      const advBtn = $('queue-advance-btn');
      if (advBtn) advBtn.onclick = () => {
        if (!confirm('Force advance: cancel the running job and start the next queued item?')) return;
        apiFetch('/queue/advance', { method: 'POST' })
          .then(() => loadQueue()).catch(e => alert('Advance failed: ' + e));
      };
    }

    // Hook into tab switching
    function onQueueTabActivated() {
      loadQueue();
    }

    // Patch tab switch to trigger queue load
    const origNavSetup = window._geoffNavSetup;
    document.addEventListener('click', e => {
      const link = e.target.closest('[data-tab="queue"]');
      if (link) setTimeout(onQueueTabActivated, 50);
    });

    // Also expose for nav handler
    window._queueTabActivated = onQueueTabActivated;

    initQueue();
  })();

})();
