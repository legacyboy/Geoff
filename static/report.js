/* ============================================================
   GEOFF Report — narrative incident report (real data)
   ============================================================ */
(function () {
  const esc = (s) => String(s ?? '').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  const $ = (id) => document.getElementById(id);

  const API_KEY = document.querySelector('meta[name="geoff-api-key"]')?.content || '';
  function apiFetch(url) {
    return fetch(url, API_KEY ? { headers: { 'X-API-Key': API_KEY } } : {});
  }

  // current case dir from query string
  const caseDir = new URLSearchParams(location.search).get('case');

  /* -------- case picker -------- */
  async function showPicker() {
    document.title = 'Geoff — Reports';
    const h = $('h-title'); if (h) h.textContent = 'Investigation Reports';
    const vt = $('verdict-tag'); if (vt) vt.style.display = 'none';

    const content = $('content');
    content.innerHTML = '<div style="color:var(--g-text-mute);padding:20px 0">Loading cases…</div>';
    try {
      const resp = await apiFetch('/reports');
      const data = await resp.json();
      const reports = data.reports || [];
      if (!reports.length) {
        content.innerHTML = '<p style="color:var(--g-text-mute)">No completed investigations yet. Run <a href="/" style="color:var(--g-blue)">Find Evil</a> first.</p>';
        return;
      }
      content.innerHTML = `
        <div style="margin-bottom:24px">
          <div class="sec-head"><span class="n">—</span><h2>Completed Investigations</h2><span class="sub">${reports.length} cases</span></div>
        </div>
        <div style="display:flex;flex-direction:column;gap:10px;">
          ${reports.map(r => {
            const sevCls = r.evil_found ? (r.severity === 'CRITICAL' ? 'sev-CRITICAL' : r.severity === 'HIGH' ? 'sev-HIGH' : 'sev-MEDIUM') : 'sev-LOW';
            return `<a href="/reports/narrative?case=${encodeURIComponent(r.dir)}" style="text-decoration:none;">
              <div style="border:1px solid var(--g-border-soft);border-radius:var(--radius);padding:16px 20px;background:var(--g-surface-2);transition:border-color .14s;cursor:pointer;" onmouseover="this.style.borderColor='var(--g-border)'" onmouseout="this.style.borderColor='var(--g-border-soft)'">
                <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                  <span class="sev-pill ${sevCls}" style="font-size:11px;">${esc(r.evil_found ? 'EVIL FOUND' : 'CLEAN')}</span>
                  <span style="font-family:var(--font-mono);font-size:13px;color:var(--g-text)">${esc(r.case_name)}</span>
                  ${r.classification ? `<span class="tag-mono">${esc(r.classification)}</span>` : ''}
                  <span style="margin-left:auto;font-family:var(--font-mono);font-size:11px;color:var(--g-text-mute)">${esc(r.timestamp ? r.timestamp.replace('T',' ').slice(0,16) : '')}</span>
                </div>
                ${r.evidence_dir ? `<div style="margin-top:8px;font-family:var(--font-mono);font-size:11px;color:var(--g-text-faint)">${esc(r.evidence_dir)}</div>` : ''}
              </div>
            </a>`;
          }).join('')}
        </div>`;
    } catch (e) {
      content.innerHTML = `<p style="color:var(--sev-crit)">Failed to load reports: ${esc(e.message)}</p>`;
    }
  }

  /* -------- full narrative report -------- */
  async function showReport(dir) {
    const content = $('content');
    content.innerHTML = '<div style="color:var(--g-text-mute);padding:20px 0">Loading report…</div>';
    let data;
    try {
      const resp = await apiFetch(`/reports/${encodeURIComponent(dir)}/json`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      data = await resp.json();
    } catch (e) {
      content.innerHTML = `<p style="color:var(--sev-crit)">Failed to load report: ${esc(e.message)}</p>`;
      return;
    }

    // ---- hero ----
    const caseName = dir.split('_findevil_')[0] || dir;
    const evDir = data.evidence_dir || '';
    document.title = `Geoff — ${esc(caseName)}`;
    $('h-case').textContent = caseName;
    $('h-title').textContent = evDir ? evDir.split('/').filter(Boolean).pop() + ' — investigation report' : caseName;
    const vt = $('verdict-tag');
    const evilFound = data.evil_found;
    const sev = (data.severity || 'INFO').toUpperCase();
    if (vt) {
      vt.style.display = '';
      vt.querySelector('.blip').style.background = evilFound ? 'var(--sev-crit)' : 'var(--g-green)';
      vt.querySelector('.label').textContent = evilFound ? 'EVIL FOUND' : 'CLEAN';
    }
    const sevPill = $('h-sevpill');
    if (sevPill) { sevPill.className = `sev-pill ${sev}`; sevPill.textContent = sev + ' SEVERITY'; }
    const dl_json = $('dl-json');
    if (dl_json) dl_json.href = `/reports/${encodeURIComponent(dir)}/download/json`;
    const dl_md = $('dl-md');
    if (dl_md) dl_md.href = `/reports/${encodeURIComponent(dir)}/download/markdown`;

    // meta strip
    const devMap = data.device_map || {};
    const userMap = data.user_map || {};
    const flags = data.behavioral_flags || {};
    const elapsed = data.elapsed_seconds ? formatElapsed(data.elapsed_seconds) : '—';
    const stepsC = data.steps_completed || '—';
    const sevCounts = countSeverities(flags);
    $('metastrip').innerHTML = [
      ['Classification', data.classification || '—'],
      ['Devices', Object.keys(devMap).length + ' / ' + Object.keys(userMap).length + ' users'],
      ['Findings', `<span style="color:var(--sev-crit)">${sevCounts.CRITICAL}C</span> / ${sevCounts.HIGH}H / ${sevCounts.MEDIUM}M / ${sevCounts.LOW}L`],
      ['Runtime', `${elapsed} · ${stepsC} steps`],
      ['Case Dir', `<span style="font-size:11px">${esc(dir)}</span>`],
    ].map(([k, v]) => `<div class="m"><div class="k">${k}</div><div class="v">${v}</div></div>`).join('');

    // ---- build section list ----
    const sections = [
      { id: 'summary',  num: '01', title: 'Executive Summary',           render: (r) => renderSummary(r, data) },
      { id: 'timeline', num: '02', title: 'Super Timeline',              render: (r) => renderTimeline(r, data) },
      { id: 'findings', num: '03', title: 'Findings by Device',          render: (r) => renderFindings(r, data) },
      { id: 'mitre',    num: '04', title: 'MITRE ATT&CK Coverage',  render: (r) => renderMitreLink(r, dir) },
      { id: 'iocs',     num: '05', title: 'Indicators of Compromise',    render: (r) => renderIocs(r, data) },
    ];

    // TOC
    $('toc').innerHTML = `<span class="eyebrow">Contents</span>` +
      sections.map(s => `<a href="#${s.id}" data-sec="${s.id}"><span class="num">${s.num}</span>${s.title}</a>`).join('');

    // sections
    content.innerHTML = '';
    sections.forEach(s => {
      const sec = document.createElement('section');
      sec.id = s.id;
      sec.innerHTML = `<div class="sec-head"><span class="n">${s.num}</span><h2>${s.title}</h2></div><div class="sbody"></div>`;
      content.appendChild(sec);
      s.render(sec.querySelector('.sbody'));
    });

    // TOC scroll-spy
    $('toc').querySelectorAll('a').forEach(a => a.addEventListener('click', e => {
      e.preventDefault();
      const t = document.getElementById(a.dataset.sec);
      if (t) window.scrollTo({ top: t.getBoundingClientRect().top + window.scrollY - 72, behavior: 'smooth' });
    }));
    const links = {}; $('toc').querySelectorAll('a').forEach(a => links[a.dataset.sec] = a);
    const obs = new IntersectionObserver(entries => {
      entries.forEach(en => { if (en.isIntersecting) {
        Object.values(links).forEach(l => l.classList.remove('active'));
        links[en.target.id]?.classList.add('active');
      }});
    }, { rootMargin: '-74px 0px -70% 0px', threshold: 0 });
    sections.forEach(s => { const el = document.getElementById(s.id); if (el) obs.observe(el); });
  }

  /* ============ section renderers ============ */

  function renderSummary(root, data) {
    const execSummary = data.executive_summary;
    const narrative = data.narrative_report;

    let summaryHtml = '';
    if (execSummary) {
      // narrative_report.json executive_summary — may be a string or object with sections
      if (typeof execSummary === 'string') {
        summaryHtml = `<p class="narrative">${esc(execSummary).replace(/\n\n/g, '</p><p class="narrative">').replace(/\n/g, '<br>')}</p>`;
      } else if (typeof execSummary === 'object') {
        const text = execSummary.narrative || execSummary.summary || execSummary.text || JSON.stringify(execSummary);
        summaryHtml = `<p class="narrative">${esc(String(text)).replace(/\n\n/g, '</p><p class="narrative">').replace(/\n/g, '<br>')}</p>`;
      }
    } else if (narrative) {
      // Markdown text — extract first paragraph(s) before first ## heading
      const intro = narrative.split(/^##\s/m)[0].replace(/^#[^#].*\n/m, '').trim();
      summaryHtml = `<p class="narrative">${esc(intro).replace(/\n\n/g, '</p><p class="narrative">').replace(/\n/g, '<br>')}</p>`;
    } else {
      // Fallback: synthesise from available data
      const ac = data.attack_chain || {};
      const devMap = data.device_map || {};
      const evilFound = data.evil_found;
      const sev = data.severity || 'UNKNOWN';
      const cls = data.classification || '';
      const devices = Object.keys(devMap).join(', ') || '—';
      const mitre = (ac.mitre_techniques_observed || []).slice(0, 5).join(', ') || '—';
      const dwell = ac.dwell_days != null ? `Dwell time: ~${Math.round(ac.dwell_days)} days.` : '';
      summaryHtml = `<p class="narrative">
        ${evilFound ? `<b style="color:var(--sev-crit)">Evil found</b> — Severity: <b>${esc(sev)}</b>. Classification: <b>${esc(cls)}</b>.` : `<b>No evil found.</b>`}
        ${devices ? `Devices analysed: ${esc(devices)}.` : ''} ${dwell}
        ${mitre ? `MITRE techniques observed: ${esc(mitre)}.` : ''}
      </p>`;
    }

    // key facts grid
    const ac = data.attack_chain || {};
    const flags = data.behavioral_flags || {};
    const sevCounts = countSeverities(flags);
    const facts = [
      ['Verdict', data.evil_found ? 'EVIL FOUND' : (data.evil_found === false ? 'CLEAN' : '—'), data.evil_found ? 'crit' : ''],
      ['Classification', data.classification || '—'],
      ['Severity', data.severity || '—', data.severity === 'CRITICAL' ? 'crit' : ''],
      ['Dwell Time', ac.dwell_days != null ? `~${Math.round(ac.dwell_days)} days` : '—'],
      ['Findings', `${sevCounts.CRITICAL}C / ${sevCounts.HIGH}H / ${sevCounts.MEDIUM}M`, ''],
      ['Techniques', (ac.mitre_techniques_observed || []).length + ' MITRE', ''],
    ];
    root.innerHTML = summaryHtml + `<div class="keyfacts">${facts.map(([k, v, c]) =>
      `<div class="kf"><div class="k">${k}</div><div class="v ${c || ''}">${esc(v)}</div></div>`).join('')}</div>`;
  }

  function renderTimeline(root, data) {
    const timeline = data.timeline || [];
    if (!timeline.length) {
      root.innerHTML = '<div class="info-box"><p>No timeline entries were generated for this case. This can happen when the pipeline completed without producing timeline data.</p></div>';
      return;
    }
    const rows = events.map(ev => {
      const ts = ev.timestamp || '';
      const devId = ev.device_id || ev.device || '';
      const sev = (ev.severity || 'INFO').toUpperCase();
      const devKind = inferKindFromMap(devId, data.device_map || {});
      return `<div class="tl-row">
        <div class="when"><span class="d">${fmtDate(ts)}</span><br>${fmtClock(ts)} UTC</div>
        <div class="tl-rail"><div class="tl-dot s-${sev}"></div></div>
        <div class="tl-card">
          <div class="top"><span class="sev-pill ${sev}" style="font-size:9px;padding:2px 7px;">${sev}</span></div>
          <div class="sum">${esc(ev.summary || ev.event_type || '')}</div>
          <div class="meta">
            <span class="dv"><span class="edot ${devKind}"></span>${esc(devId)}</span>
            ${ev.owner ? `<span>${esc(ev.owner)}</span>` : ''}
            ${ev.suspicion_reason ? `<span style="color:var(--g-text-mute);font-size:10px;">${esc(ev.suspicion_reason.slice(0, 80))}</span>` : ''}
          </div>
        </div>
      </div>`;
    }).join('');
    root.innerHTML = `<div class="tl">${rows}</div>`;
  }

  function renderFindings(root, data) {
    const flags = data.behavioral_flags || {};
    const devMap = data.device_map || {};
    const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    const devices = Object.keys(flags).sort((a, b) => {
      const top = (dev) => {
        const fs = flags[dev] || [];
        if (!fs.length) return 99;
        return Math.min(...fs.map(f => sevRank[f.severity] ?? 4));
      };
      return top(a) - top(b);
    });

    if (!devices.length) { root.innerHTML = '<p style="color:var(--g-text-mute)">No behavioral findings.</p>'; return; }

    let html = '';
    devices.forEach(devId => {
      const devFlags = (flags[devId] || []).sort((a, b) => (sevRank[a.severity] ?? 4) - (sevRank[b.severity] ?? 4));
      if (!devFlags.length) return;
      const devInfo = devMap[devId] || {};
      const kind = inferKindFromMap(devId, devMap);
      const topSev = devFlags[0]?.severity || 'INFO';
      const cards = devFlags.map(f => {
        const sev = (f.severity || 'MEDIUM').toUpperCase();
        const ev = Object.entries(f.evidence || {}).slice(0, 3)
          .map(([k, v]) => `<span class="tag-mono">${esc(k)}: ${esc(String(v))}</span>`).join('');
        const mitre = (f.mitre_techniques || f.mitre || []).map(m => `<span class="mitre-tag">${esc(m)}</span>`).join('');
        return `<div class="fcard s-${sev}">
          <div class="rail"><span class="sev-pill ${sev}">${sev}</span></div>
          <div>
            <div class="fh"><span class="ft">${esc(f.flag_type || '')}</span></div>
            <div class="fs">${esc(f.summary || '')}</div>
            <div class="fe">${esc(f.explanation || f.description || '')}</div>
            ${mitre ? `<div class="ftags">${mitre}</div>` : ''}
            ${ev ? `<div class="evrow">${ev}</div>` : ''}
          </div>
        </div>`;
      }).join('');
      html += `<div class="dev-block">
        <div class="dev-head">
          <div class="dev-glyph ${kind}">${kind === 'server' ? 'SRV' : kind === 'mobile' ? 'MOB' : 'PC'}</div>
          <div><div class="nm">${esc(devId)}</div><div class="ro">${esc(devInfo.os || devInfo.operating_system || kind)} · ${devFlags.length} finding${devFlags.length !== 1 ? 's' : ''}</div></div>
          <div class="right">
            ${devInfo.owner ? `<span class="tag-mono">owner: ${esc(devInfo.owner)}</span>` : ''}
            <span class="sev-pill ${topSev}" style="font-size:9px;padding:2px 7px;">${topSev}</span>
            <span class="chev">▼</span>
          </div>
        </div>
        <div class="dev-findings">${cards}</div>
      </div>`;
    });
    root.innerHTML = html || '<p style="color:var(--g-text-mute)">No findings.</p>';
    root.querySelectorAll('.dev-head').forEach(h => h.addEventListener('click', () => h.parentElement.classList.toggle('collapsed')));
  }

  function renderMitreLink(root, dir) {
    const link = encodeURIComponent(dir);
    root.innerHTML = `<div class="mitre-card"><p>Full MITRE ATT&CK coverage matrix with technique heatmap available.</p><a class="btn primary" href="/reports/mitre-heatmap?case=${link}" target="_blank">View MITRE ATT&CK Matrix →</a></div>`;
  }

  function renderIocs(root, data) {
    // iocs from narrative_report.json (if available) or from pipeline iocs field
    let iocs = data.iocs || {};

    // iocs may be a nested object with category → list, or flat lists
    // Normalise to { label: [value, ...] }
    const normalised = {};

    if (typeof iocs === 'object' && !Array.isArray(iocs)) {
      Object.entries(iocs).forEach(([k, v]) => {
        if (Array.isArray(v) && v.length) normalised[k] = v.map(String);
        else if (typeof v === 'object' && v !== null) {
          // nested structure — flatten
          Object.entries(v).forEach(([k2, v2]) => {
            if (Array.isArray(v2) && v2.length) normalised[`${k} / ${k2}`] = v2.map(String);
          });
        }
      });
    }

    // Also collect from behavioral_flags evidence fields
    const flags = data.behavioral_flags || {};
    const ipSet = new Set(), domSet = new Set(), hashSet = new Set(), pathSet = new Set();
    const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
    const DOMAIN_RE = /(?:[a-z0-9-]+\.)+[a-z]{2,}/i;
    Object.values(flags).forEach(devFlags => {
      (devFlags || []).forEach(f => {
        Object.values(f.evidence || {}).forEach(v => {
          const s = String(v);
          if (IP_RE.test(s)) ipSet.add(s.match(IP_RE)[0]);
          if (/^[a-f0-9]{32,}$/i.test(s)) hashSet.add(s);
          if (s.startsWith('%') || s.startsWith('C:\\') || s.startsWith('/')) pathSet.add(s.slice(0, 120));
        });
      });
    });

    if (ipSet.size && !normalised['IP Address']) normalised['IP Address'] = [...ipSet];
    if (hashSet.size && !normalised['File Hash']) normalised['File Hash'] = [...hashSet];
    if (pathSet.size && !normalised['File Path']) normalised['File Path'] = [...pathSet].slice(0, 10);

    if (!Object.keys(normalised).length) {
      root.innerHTML = '<p style="color:var(--g-text-mute)">No IOC data available.</p>';
      return;
    }

    const groups = Object.entries(normalised).map(([label, vals]) => `<div class="ioc-group">
      <div class="gl">${esc(label)}<span class="c">${vals.length}</span></div>
      ${vals.map(v => `<div class="ioc-row"><span class="val">${esc(v)}</span><button class="cp" title="copy" data-v="${esc(v)}">⧉</button></div>`).join('')}
    </div>`).join('');
    root.innerHTML = `<div class="ioc-grid">${groups}</div>`;
    root.querySelectorAll('.cp').forEach(b => b.addEventListener('click', () => {
      navigator.clipboard?.writeText(b.dataset.v);
      const o = b.textContent; b.textContent = '✓'; b.style.color = 'var(--g-green)';
      setTimeout(() => { b.textContent = o; b.style.color = ''; }, 1100);
    }));
  }

  /* -------- helpers -------- */
  function inferKindFromMap(devId, devMap) {
    const d = devMap[devId] || {};
    const os = (d.os || d.operating_system || '').toLowerCase();
    if (os.includes('ios') || os.includes('android') || os.includes('mobile')) return 'mobile';
    if (os.includes('server') || (d.role || '').toLowerCase().includes('server')) return 'server';
    return 'pc';
  }

  function countSeverities(flags) {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    Object.values(flags).forEach(fs => (fs || []).forEach(f => {
      const s = (f.severity || 'LOW').toUpperCase();
      if (s in c) c[s]++;
    }));
    return c;
  }

  function fmtDate(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }); } catch { return iso.slice(0, 10); }
  }
  function fmtClock(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toISOString().slice(11, 16); } catch { return ''; }
  }
  function formatElapsed(s) {
    const m = Math.floor(s / 60);
    return m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m}m ${Math.round(s % 60)}s`;
  }

  /* -------- entry -------- */
  if (caseDir) showReport(caseDir);
  else showPicker();
})();
