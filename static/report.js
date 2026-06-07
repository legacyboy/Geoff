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

  /* -------- text/paragraph rendering helper -------- */
  function renderTextBlock(text) {
    if (!text) return '<p style="color:var(--g-text-mute)">No data available.</p>';
    if (typeof text === 'string') {
      const escaped = esc(text);
      return escaped
        .replace(/\n\n+/g, '</p><p class="narrative">')
        .replace(/\n/g, '<br>')
        .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>')
        .replace(/\*(.*?)\*/g, '<i>$1</i>')
        .replace(/`([^`]+)`/g, '<code style="background:var(--g-surface-2);padding:1px 4px;border-radius:3px;font-size:12px;">$1</code>');
    }
    return `<pre style="white-space:pre-wrap;font-size:12px;">${esc(JSON.stringify(text, null, 2))}</pre>`;
  }

  /* -------- full narrative report (markdown-ish to HTML) -------- */
  function renderMarkdown(md) {
    if (!md) return '';
    const lines = md.split('\n');
    let html = '';
    let inList = false;
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('### ')) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h4 style="margin:16px 0 8px;color:var(--g-text)">${esc(trimmed.slice(4))}</h4>`;
      } else if (trimmed.startsWith('## ')) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h3 style="margin:20px 0 10px;color:var(--g-text);border-bottom:1px solid var(--g-border-soft);padding-bottom:6px;">${esc(trimmed.slice(3))}</h3>`;
      } else if (trimmed.startsWith('# ')) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h2 style="margin:20px 0 10px;color:var(--g-text)">${esc(trimmed.slice(2))}</h2>`;
      } else if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
        if (!inList) { html += '<ul style="margin:8px 0;padding-left:20px;">'; inList = true; }
        html += `<li>${esc(trimmed.slice(2)).replace(/\*\*(.*?)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code style="background:var(--g-surface-2);padding:1px 4px;border-radius:3px;font-size:12px;">$1</code>')}</li>`;
      } else if (trimmed === '') {
        if (inList) { html += '</ul>'; inList = false; }
        html += '<br>';
      } else {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<p class="narrative">${esc(trimmed).replace(/\*\*(.*?)\*\*/g, '<b>$1</b>').replace(/\*(.*?)\*/g, '<i>$1</i>').replace(/`([^`]+)`/g, '<code style="background:var(--g-surface-2);padding:1px 4px;border-radius:3px;font-size:12px;">$1</code>')}</p>`;
      }
    }
    if (inList) html += '</ul>';
    return html;
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
      { id: 'email-phishing', num: '03.5', title: 'Phishing & Email Threats', render: (r) => { r.innerHTML = renderMarkdown(data.email_phishing || ''); } },
      { id: 'mitre',    num: '04', title: 'MITRE ATT&CK Coverage',      render: (r) => renderMitreLink(r, dir) },
      { id: 'iocs',     num: '05', title: 'Indicators of Compromise',   render: (r) => renderIocs(r, data) },
      // --- New narrative sections ---
      { id: 'attack-chain', num: '06', title: 'Attack Chain / Attack Narrative', render: (r) => renderAttackChain(r, data) },
      { id: 'kill-chain-timeline', num: '07', title: 'Kill Chain & Timeline Reconstruction', render: (r) => renderKillChainTimeline(r, data) },
      { id: 'devices-users', num: '08', title: 'Devices & Users', render: (r) => renderDevicesUsers(r, data) },
      { id: 'blast-radius', num: '09', title: 'Blast Radius & Business Impact', render: (r) => renderBlastRadius(r, data) },
      { id: 'dwell-time', num: '10', title: 'Dwell Time & Lateral Movement', render: (r) => renderDwellTime(r, data) },
      { id: 'evidence-confidence', num: '11', title: 'Evidence Confidence & Gaps', render: (r) => renderEvidenceConfidence(r, data) },
      { id: 'conclusion', num: '12', title: 'Conclusion & Recommendations', render: (r) => renderConclusion(r, data) },
      { id: 'user-narratives', num: '13', title: 'User Activity Narratives', render: (r) => renderUserNarratives(r, data) },
      { id: 'significant-events', num: '14', title: 'Significant Events Timeline', render: (r) => renderSignificantEvents(r, data) },
      { id: 'full-report', num: '15', title: 'Full Written Report', render: (r) => renderFullReport(r, data) },
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
    const caseDir = new URLSearchParams(location.search).get('case');
    root.innerHTML = '<div class="mitre-card" style="margin-bottom:16px;">' +
      '<p>Full super-timeline with all ' + timeline.length + ' events available in a dedicated view.</p>' +
      '<a class="btn primary" href="/reports/' + encodeURIComponent(caseDir) + '/supertimeline" target="_blank">Open Super Timeline &rarr;</a>' +
    '</div>';
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
        if (Array.isArray(v) && v.length) {
          if (k === 'file_hashes' && typeof v[0] === 'object' && v[0].hash) {
            normalised[k] = v.map(function(item) { return item.hash + (item.algorithm ? ' (' + item.algorithm + ')' : '') + (item.filename ? ' - ' + item.filename : ''); });
          } else {
            normalised[k] = v.map(String);
          }
        } else if (typeof v === 'object' && v !== null) {
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

  /* -------- new narrative section renderers -------- */

  function renderAttackChain(root, data) {
    // If we have the narrative text version, use that instead
    if (data.attack_chain_narrative && typeof data.attack_chain_narrative === 'string') {
      root.innerHTML = renderMarkdown(data.attack_chain_narrative);
      return;
    }
    const ac = data.attack_chain;
    if (!ac) {
      root.innerHTML = '<p style="color:var(--g-text-mute)">No attack chain data available.</p>';
      return;
    }
    // attack_chain may be a dict (from pipeline) or a string (from narrative JSON)
    if (typeof ac === 'string') {
      root.innerHTML = renderTextBlock(ac);
      return;
    }
    // Structured attack_chain object
    let html = '';
    if (ac.dwell_days != null) {
      html += `<div class="keyfacts"><div class="kf"><div class="k">Dwell Time</div><div class="v">~${Math.round(ac.dwell_days)} days</div></div>`;
      if (ac.first_seen_ts) html += `<div class="kf"><div class="k">First Seen</div><div class="v">${esc(ac.first_seen_ts)}</div></div>`;
      if (ac.last_seen_ts) html += `<div class="kf"><div class="k">Last Seen</div><div class="v">${esc(ac.last_seen_ts)}</div></div>`;
      html += `</div>`;
    }
    if (ac.lateral_movement_path && ac.lateral_movement_path.length) {
      html += `<h4 style="margin:12px 0 6px;">Lateral Movement Path</h4><div style="font-family:var(--font-mono);font-size:13px;">${ac.lateral_movement_path.map(p => esc(p)).join(' → ')}</div>`;
    }
    if (ac.mitre_techniques_observed && ac.mitre_techniques_observed.length) {
      html += `<h4 style="margin:12px 0 6px;">MITRE ATT&CK Techniques</h4><div style="display:flex;flex-wrap:wrap;gap:6px;">${ac.mitre_techniques_observed.map(t => `<span class="mitre-tag">${esc(t)}</span>`).join('')}</div>`;
    }
    if (ac.kill_chain_phases && ac.kill_chain_phases.length) {
      html += `<h4 style="margin:12px 0 6px;">Kill Chain Phases</h4><div style="display:flex;flex-wrap:wrap;gap:8px;">${ac.kill_chain_phases.map(p => `<div style="padding:6px 12px;background:var(--g-surface-2);border:1px solid var(--g-border-soft);border-radius:var(--radius);font-size:12px;">${esc(typeof p === 'string' ? p : p.phase || p.name || JSON.stringify(p))}</div>`).join('')}</div>`;
    }
    root.innerHTML = html || '<p style="color:var(--g-text-mute)">No attack chain data available.</p>';
  }

  function renderKillChainTimeline(root, data) {
    const kct = data.kill_chain_timeline;
    if (!kct) {
      root.innerHTML = '<p style="color:var(--g-text-mute)">No kill chain timeline data available.</p>';
      return;
    }
    if (typeof kct === 'string' && kct.trim().startsWith('<')) {
      root.innerHTML = kct;
    } else {
      root.innerHTML = renderTextBlock(kct);
    }
  }

  function renderDevicesUsers(root, data) {
    const du = data.devices_and_users;
    if (!du) {
      root.innerHTML = '<p style="color:var(--g-text-mute)">No devices & users data available.</p>';
      return;
    }
    // If it's a string (from narrative JSON), render as text
    if (typeof du === 'string') {
      root.innerHTML = renderTextBlock(du);
      return;
    }
    // If it's an object, render structured
    root.innerHTML = `<pre style="white-space:pre-wrap;font-size:12px;">${esc(JSON.stringify(du, null, 2))}</pre>`;
  }

  function renderBlastRadius(root, data) {
    const br = data.blast_radius;
    if (!br) {
      root.innerHTML = '<p style="color:var(--g-text-mute)">No blast radius data available.</p>';
      return;
    }
    // If backend already returned rendered HTML, use it directly
    if (typeof br === 'string' && br.trim().startsWith('<')) {
      root.innerHTML = br;
      return;
    }
    // Parse markdown/text blast radius into structured CIA cards
    const text = typeof br === 'string' ? br : JSON.stringify(br, null, 2);
    const ciaLevels = { HIGH: '#f85149', MEDIUM: '#d29922', LOW: '#3fb950' };
    const ciaBar = { HIGH: 90, MEDIUM: 55, LOW: 20 };
    // Extract CIA dimensions
    const ciaRows = ['Confidentiality', 'Integrity', 'Availability'].map(dim => {
      const rx = new RegExp(dim + '[\\s\\S]*?(?:HIGH|MEDIUM|LOW)', 'i');
      const m = text.match(rx);
      let level = 'MEDIUM';
      if (m) {
        const lvlM = m[0].match(/HIGH|MEDIUM|LOW/i);
        if (lvlM) level = lvlM[0].toUpperCase();
      }
      const color = ciaLevels[level] || '#8b949e';
      const pct = ciaBar[level] || 20;
      const rationaleRx = new RegExp(dim + '[^\\n]*?(HIGH|MEDIUM|LOW)[\\s\\S]*?[—:\\-]\\s*([^\\n]+)', 'i');
      const rm = text.match(rationaleRx);
      const rationale = rm ? rm[2].trim().slice(0, 100) : '';
      return `<div style="margin-bottom:12px;">
        <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
          <span style="color:var(--g-text);font-weight:bold;">${dim}</span>
          <span style="color:${color};font-weight:bold;background:var(--g-surface-2);border:1px solid ${color};border-radius:4px;padding:1px 8px;font-size:0.85em;">${level}</span>
        </div>
        <div style="background:var(--g-surface-2);border-radius:4px;height:8px;overflow:hidden;">
          <div style="background:${color};width:${pct}%;height:100%;border-radius:4px;"></div>
        </div>
        ${rationale ? `<div style="color:var(--g-text-mute);font-size:0.85em;margin-top:4px;">${esc(rationale)}</div>` : ''}
      </div>`;
    }).join('');
    // Extract assets/data lines from text
    const assetLines = text.split('\n').filter(l => /device|user|data|asset|scope/i.test(l) && l.trim().length > 4)
      .slice(0, 5).map(l => `<li style="color:var(--g-text-dim);margin-bottom:4px;">${esc(l.replace(/^[-*#\s]+/, '').trim())}</li>`).join('');
    // Extract worst-case line
    const wcMatch = text.match(/worst[- ]case[^:\n]*[:]\s*([^\n]+)/i);
    const worstCase = wcMatch ? wcMatch[1].trim() : '';
    root.innerHTML = `
      <div style="background:var(--g-surface-2);border:1px solid var(--g-border-soft);border-radius:8px;padding:20px;">
        ${assetLines ? `<h4 style="color:var(--g-blue-soft);margin:0 0 10px;font-size:0.85em;text-transform:uppercase;letter-spacing:0.05em;">Affected Assets</h4>
        <ul style="margin:0 0 20px;padding-left:20px;list-style:none;">${assetLines}</ul>` : ''}
        <h4 style="color:var(--g-blue-soft);margin:0 0 12px;font-size:0.85em;text-transform:uppercase;letter-spacing:0.05em;">CIA Impact Assessment</h4>
        ${ciaRows}
        ${worstCase ? `<div style="background:var(--g-surface);border:1px solid var(--sev-crit);border-radius:6px;padding:12px 16px;margin-top:12px;">
          <div style="color:var(--sev-crit);font-weight:bold;margin-bottom:4px;">Worst-Case Projection</div>
          <div style="color:var(--g-text-dim);">${esc(worstCase)}</div>
        </div>` : ''}
      </div>`;
  }

  function renderDwellTime(root, data) {
    const dt = data.dwell_time;
    if (!dt) {
      root.innerHTML = '<p style="color:var(--g-text-mute)">No dwell time data available.</p>';
      return;
    }
    if (typeof dt === 'string' && dt.trim().startsWith('<')) {
      root.innerHTML = dt;
    } else {
      root.innerHTML = renderTextBlock(dt);
    }
  }

  function renderEvidenceConfidence(root, data) {
    const ec = data.evidence_confidence;
    if (!ec) {
      root.innerHTML = '<p style="color:var(--g-text-mute)">No evidence confidence data available.</p>';
      return;
    }
    if (typeof ec === 'string' && ec.trim().startsWith('<')) {
      root.innerHTML = ec;
    } else {
      root.innerHTML = renderTextBlock(ec);
    }
  }

  function renderConclusion(root, data) {
    const c = data.conclusion;
    if (!c) {
      root.innerHTML = '<p style="color:var(--g-text-mute)">No conclusion data available.</p>';
      return;
    }
    root.innerHTML = renderTextBlock(c);
  }

  function renderUserNarratives(root, data) {
    const un = data.user_narratives;
    if (!un) {
      root.innerHTML = '<p style="color:var(--g-text-mute)">No user narratives available.</p>';
      return;
    }
    if (typeof un === 'string') {
      root.innerHTML = renderTextBlock(un);
      return;
    }
    // Object with user → narrative text
    let html = '';
    Object.entries(un).forEach(([user, narrative]) => {
      html += `<div style="margin-bottom:16px;"><h4 style="margin:8px 0 4px;color:var(--g-blue);font-size:14px;">${esc(user)}</h4>`;
      html += `<div>${renderTextBlock(narrative)}</div></div>`;
    });
    root.innerHTML = html || '<p style="color:var(--g-text-mute)">No user narratives available.</p>';
  }

  function renderSignificantEvents(root, data) {
    const se = data.significant_events;
    if (!se) {
      root.innerHTML = '<p style="color:var(--g-text-mute)">No significant events data available.</p>';
      return;
    }
    root.innerHTML = renderTextBlock(se);
  }

  function renderFullReport(root, data) {
    const fr = data.full_written_report;
    if (!fr) {
      // Fallback: try narrative_report (markdown)
      const nr = data.narrative_report;
      if (nr) {
        root.innerHTML = renderMarkdown(nr);
        return;
      }
      root.innerHTML = '<p style="color:var(--g-text-mute)">No full written report available.</p>';
      return;
    }
    // full_written_report is likely markdown text
    root.innerHTML = renderMarkdown(fr);
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

  /* -------- report chat dock -------- */
  window.toggleReportChat = function() {
    const dock = document.getElementById('report-chat');
    const tog = document.getElementById('rc-toggle');
    if (!dock) return;
    dock.classList.toggle('collapsed');
    if (tog) tog.textContent = dock.classList.contains('collapsed') ? '▲' : '▼';
  };

  function pushReportChat(who, html) {
    const s = document.getElementById('report-chat-scroll');
    if (!s) return;
    const m = document.createElement('div');
    m.className = 'rc-msg ' + who;
    m.innerHTML = html;
    s.appendChild(m);
    s.scrollTop = s.scrollHeight;
  }

  async function sendReportChat() {
    const input = document.getElementById('report-chat-input');
    const txt = input && input.value.trim();
    if (!txt) return;
    pushReportChat('user', esc(txt));
    if (input) input.value = '';
    pushReportChat('geoff', '<b>GEOFF</b><span class="rc-thinking" style="color:var(--g-text-faint)">thinking…</span>');
    try {
      const body = { message: txt };
      if (caseDir) body.evidence_dir = caseDir;
      const resp = await fetch('/chat', {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, API_KEY ? { 'X-API-Key': API_KEY } : {}),
        body: JSON.stringify(body),
      });
      const data = await resp.json();
      const reply = data.response || data.message || 'No response.';
      const scroll = document.getElementById('report-chat-scroll');
      if (scroll) {
        const thinking = scroll.querySelector('.rc-thinking');
        if (thinking && thinking.parentElement) thinking.parentElement.remove();
      }
      pushReportChat('geoff', `<b>GEOFF</b>${esc(reply)}`);
    } catch (e) {
      pushReportChat('geoff', `<b>GEOFF</b>Error: ${esc(e.message)}`);
    }
  }

  document.addEventListener('DOMContentLoaded', function() {
    const sendBtn = document.getElementById('report-chat-send');
    const chatInput = document.getElementById('report-chat-input');
    if (sendBtn) sendBtn.addEventListener('click', sendReportChat);
    if (chatInput) chatInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendReportChat(); }
    });
  });

  /* -------- entry -------- */
  if (caseDir) showReport(caseDir);
  else showPicker();
})();