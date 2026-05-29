# -*- coding: utf-8 -*-
"""Geoff DFIR — Embedded HTML/JS/CSS templates (pure string constants).

Module 2 in the refactoring plan.  Leaf module — no internal dependencies.
"""

# ---------------------------------------------------------------------------
# HTML Template (redesigned Find Evil console)
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Geoff — Find Evil</title>
<!-- GEOFF_API_KEY_META -->
<link rel="stylesheet" href="/static/tokens.css">
<style>
  html, body { height: 100%; overflow: hidden; }
  .app { display: flex; flex-direction: column; height: 100vh; position: relative; z-index: 1; }

  /* ---- operation sub-bar ---- */
  .opbar {
    display: flex; align-items: center; gap: 14px;
    padding: 12px 22px; border-bottom: 1px solid var(--g-border-soft);
    background: rgba(12,19,34,.55);
  }
  .opbar .evfield {
    flex: 1; display: flex; align-items: center; gap: 10px;
    background: var(--g-surface-2); border: 1px solid var(--g-border);
    border-radius: var(--radius-sm); padding: 0 12px; height: 42px; max-width: 560px;
    transition: border-color .15s, box-shadow .15s;
  }
  .opbar .evfield:focus-within { border-color: var(--g-blue); box-shadow: var(--glow-blue); }
  .opbar .evfield .ic { color: var(--g-text-mute); font-family: var(--font-mono); font-size: 13px; }
  .opbar .evfield input {
    flex: 1; background: none; border: none; outline: none; color: var(--g-text);
    font-family: var(--font-mono); font-size: 13px; letter-spacing: .2px;
  }
  .opbar .pb {
    display: flex; flex-direction: column; gap: 2px; padding: 0 4px;
  }
  .opbar .pb .k { font-size: 9.5px; letter-spacing: 1.4px; text-transform: uppercase; color: var(--g-text-mute); }
  .opbar .pb .v { font-family: var(--font-mono); font-size: 12.5px; color: var(--g-text-dim); }

  /* ---- 3-col workspace ---- */
  .work { flex: 1; display: grid; grid-template-columns: 256px 1fr 340px; min-height: 0; }
  .col { min-height: 0; display: flex; flex-direction: column; }
  .col.left  { border-right: 1px solid var(--g-border-soft); background: rgba(12,19,34,.4); }
  .col.right { border-left: 1px solid var(--g-border-soft); background: rgba(12,19,34,.4); }
  .col-h {
    padding: 14px 16px 10px; display: flex; align-items: center; justify-content: space-between;
  }
  .col-h .eyebrow { font-size: 10px; }
  .col-h .cnt { font-family: var(--font-mono); font-size: 11px; color: var(--g-text-mute); }

  /* left rail */
  .recent { overflow-y: auto; padding: 4px 10px 16px; }
  .man-host {
    border: 1px solid var(--g-border-soft); border-radius: var(--radius-sm);
    padding: 9px 11px; margin-bottom: 7px; background: var(--g-surface-2); transition: all .14s;
  }
  .man-host:hover { border-color: var(--g-border); }
  .man-host.indexed { border-color: rgba(31,200,219,.28); }
  .man-host .mh-top { display: flex; align-items: center; gap: 8px; }
  .man-host .mh-name { font-family: var(--font-mono); font-size: 11.5px; color: var(--g-text); flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .man-host .mh-chk { font-family: var(--font-mono); font-size: 10px; color: var(--g-text-faint); transition: color .3s; }
  .man-host.indexed .mh-chk { color: var(--g-cyan); }
  .man-host .mh-arts { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 8px; }
  .art-chip {
    font-family: var(--font-mono); font-size: 8.5px; letter-spacing: .4px; padding: 2px 6px;
    border-radius: 3px; color: var(--g-text-mute); background: var(--g-surface-3); border: 1px solid var(--g-border-soft); white-space: nowrap;
  }
  .rail-label { padding: 14px 16px 6px; }

  .playbooks { padding: 2px 12px 8px; display: flex; flex-direction: column; gap: 6px; }
  .pb-opt {
    display: flex; align-items: center; gap: 9px; padding: 8px 10px; border-radius: var(--radius-sm);
    border: 1px solid var(--g-border-soft); font-size: 12px; color: var(--g-text-dim); cursor: pointer; transition: all .14s;
  }
  .pb-opt:hover { color: var(--g-text); border-color: var(--g-border); }
  .pb-opt.active { color: var(--g-text); border-color: rgba(76,141,255,.45); background: rgba(76,141,255,.07); }
  .pb-opt .rb { width: 13px; height: 13px; border-radius: 50%; border: 2px solid var(--g-border); flex-shrink: 0; }
  .pb-opt.active .rb { border-color: var(--g-blue); background: radial-gradient(circle, var(--g-blue) 40%, transparent 46%); }
  .pb-opt small { margin-left: auto; font-family: var(--font-mono); font-size: 9.5px; color: var(--g-text-faint); }

  /* center column */
  .stage { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  .op-head { padding: 18px 26px 0; }
  .op-title { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .op-title h1 { margin: 0; font-size: 21px; font-weight: 600; letter-spacing: -.2px; white-space: nowrap; }
  .op-sub { margin: 6px 0 0; display: flex; align-items: center; gap: 16px; color: var(--g-text-dim); font-size: 12px; white-space: nowrap; overflow: hidden; }
  .op-sub .mono { font-family: var(--font-mono); overflow: hidden; text-overflow: ellipsis; max-width: 380px; }
  .op-sub .liveflag { display: inline-flex; align-items: center; gap: 6px; color: var(--g-blue-soft); font-family: var(--font-mono); font-size: 11px; flex-shrink: 0; }
  .op-sub .liveflag .d { width: 6px; height: 6px; border-radius: 50%; background: var(--g-blue); animation: pulse 1.1s infinite; }

  /* phase tracker */
  .phases { display: flex; gap: 0; padding: 18px 26px 6px; }
  .phase { flex: 1; position: relative; padding-top: 22px; }
  .phase .bar { position: absolute; top: 7px; left: 0; right: 0; height: 3px; background: var(--g-line); border-radius: 2px; overflow: hidden; }
  .phase .bar i { display: block; height: 100%; width: 0; background: linear-gradient(90deg, var(--g-blue), var(--g-cyan)); transition: width .5s ease; }
  .phase.done .bar i { width: 100%; }
  .phase.active .bar i { background: linear-gradient(90deg, var(--g-blue), var(--g-cyan)); }
  .phase .dot {
    position: absolute; top: 1px; left: -1px; width: 15px; height: 15px; border-radius: 50%;
    background: var(--g-bg-2); border: 2px solid var(--g-border); z-index: 2; transition: all .3s;
    display: grid; place-items: center; font-size: 8px; color: transparent;
  }
  .phase.active .dot { border-color: var(--g-blue); box-shadow: 0 0 0 4px rgba(76,141,255,.18); }
  .phase.done .dot { border-color: var(--g-cyan); background: var(--g-cyan); color: var(--g-bg); }
  .phase .pn { font-size: 12px; font-weight: 600; color: var(--g-text-mute); transition: color .3s; }
  .phase.active .pn { color: var(--g-text); }
  .phase.done .pn { color: var(--g-text-dim); }
  .phase .pd { font-size: 10.5px; color: var(--g-text-faint); margin-top: 2px; line-height: 1.35; padding-right: 14px; }

  /* progress strip */
  .progress-row { display: flex; align-items: center; gap: 14px; padding: 8px 26px 14px; }
  .pbar { flex: 1; height: 6px; border-radius: 4px; background: var(--g-line); overflow: hidden; }
  .pbar i { display: block; height: 100%; width: 0; background: linear-gradient(90deg, var(--g-blue), var(--g-cyan)); transition: width .5s ease; border-radius: 4px; }
  .progress-row .pct { font-family: var(--font-mono); font-size: 12px; color: var(--g-text-dim); min-width: 38px; text-align: right; }
  .progress-row .steps { font-family: var(--font-mono); font-size: 11px; color: var(--g-text-mute); overflow: hidden; text-overflow: ellipsis; max-width: 280px; white-space: nowrap; }

  /* feed */
  .feed-wrap { flex: 1; min-height: 0; overflow-y: auto; padding: 4px 26px 26px; }
  .feed-head { display: flex; align-items: center; gap: 10px; margin: 6px 0 12px; }
  .feed-head .eyebrow { font-size: 10px; }
  .feed-head .line { flex: 1; height: 1px; background: var(--g-border-soft); }

  .logline {
    display: flex; align-items: baseline; gap: 10px; padding: 5px 0;
    font-family: var(--font-mono); font-size: 12px; color: var(--g-text-dim);
  }
  .logline .tk { color: var(--g-text-faint); flex-shrink: 0; }
  .logline .ar { color: var(--g-cyan); flex-shrink: 0; }
  .logline span:last-child { overflow-wrap: anywhere; }

  .find-card {
    display: grid; grid-template-columns: auto 1fr; gap: 0 14px;
    border: 1px solid var(--g-border-soft); border-left: 3px solid var(--sev-med);
    border-radius: var(--radius-sm); background: var(--g-surface);
    padding: 13px 15px; margin-bottom: 10px;
    box-shadow: var(--shadow-1);
  }
  .find-card.sev-CRITICAL { border-left-color: var(--sev-crit); }
  .find-card.sev-HIGH     { border-left-color: var(--sev-high); }
  .find-card.sev-MEDIUM   { border-left-color: var(--sev-med); }
  .find-card.sev-LOW      { border-left-color: var(--sev-low); }
  .find-card .rail { grid-row: 1 / span 3; align-self: start; }
  .find-card .fh { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
  .find-card .ft { font-family: var(--font-mono); font-size: 11px; color: var(--g-text-dim); letter-spacing: .2px; }
  .find-card .fts { margin-left: auto; font-family: var(--font-mono); font-size: 10.5px; color: var(--g-text-faint); }
  .find-card .fdev { display: inline-flex; align-items: center; gap: 6px; font-family: var(--font-mono); font-size: 11px; color: var(--g-text-dim); }
  .find-card .fs { font-size: 14px; color: var(--g-text); font-weight: 600; margin: 7px 0 4px; }
  .find-card .fe { font-size: 12.5px; color: var(--g-text-dim); line-height: 1.5; }
  .find-card .ftags { margin-top: 9px; display: flex; gap: 5px; flex-wrap: wrap; }

  .complete-card {
    border: 1px solid rgba(255,77,94,.35); border-radius: var(--radius);
    background: linear-gradient(180deg, rgba(255,77,94,.08), rgba(255,77,94,.02));
    padding: 18px 20px; margin: 4px 0 14px; display: flex; align-items: center; gap: 18px;
  }
  .complete-card .verdict { font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--sev-crit); letter-spacing: 1px; }
  .complete-card .ct { flex: 1; }
  .complete-card .ct .cl { font-size: 12.5px; color: var(--g-text-dim); margin-top: 3px; }

  /* right rail telemetry */
  .tele { overflow-y: auto; flex: 1; padding: 2px 16px 18px; }
  .tele-sec { margin-bottom: 18px; }
  .tele-sec .eyebrow { display: block; margin-bottom: 10px; }

  .verdict-box {
    border: 1px solid var(--g-border); border-radius: var(--radius); overflow: hidden;
    background: var(--g-surface-2);
  }
  .verdict-box .vtop { padding: 14px 16px; display: flex; align-items: center; gap: 12px; }
  .verdict-box .vbadge {
    font-family: var(--font-mono); font-weight: 700; font-size: 15px; letter-spacing: .5px;
    padding: 7px 12px; border-radius: var(--radius-sm); color: var(--g-text-mute);
    background: var(--g-surface-3); transition: all .4s;
  }
  .verdict-box.evil .vbadge { color: var(--sev-crit); background: rgba(255,77,94,.14); box-shadow: inset 0 0 0 1px rgba(255,77,94,.4); }
  .verdict-box .vlabel { font-size: 11px; color: var(--g-text-mute); }
  .verdict-box .vsev { margin-top: 3px; }
  .threatmeter { padding: 0 16px 16px; }
  .threatmeter .track { height: 8px; border-radius: 5px; background: var(--g-line); overflow: hidden; }
  .threatmeter .track i { display: block; height: 100%; width: 0;
    background: linear-gradient(90deg, var(--g-green), var(--g-amber) 55%, var(--g-red)); transition: width 1.1s cubic-bezier(.2,.7,.2,1); }
  .threatmeter .scale { display: flex; justify-content: space-between; margin-top: 5px; font-family: var(--font-mono); font-size: 9px; color: var(--g-text-faint); letter-spacing: .5px; }

  .sevgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .sevstat { border: 1px solid var(--g-border-soft); border-radius: var(--radius-sm); padding: 10px 12px; background: var(--g-surface-2); }
  .sevstat .n { font-family: var(--font-mono); font-size: 22px; font-weight: 600; line-height: 1; transition: color .3s; }
  .sevstat .l { font-size: 9.5px; letter-spacing: 1px; text-transform: uppercase; color: var(--g-text-mute); margin-top: 5px; }
  .sevstat.crit .n { color: var(--sev-crit); } .sevstat.high .n { color: var(--sev-high); }
  .sevstat.med  .n { color: var(--sev-med);  } .sevstat.low  .n { color: var(--sev-low);  }

  .ent-item { display: flex; align-items: center; gap: 9px; padding: 7px 4px; border-bottom: 1px solid var(--g-line); }
  .ent-item:last-child { border-bottom: none; }
  .ent-item .nm { font-family: var(--font-mono); font-size: 11.5px; color: var(--g-text); flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .ent-item .role { font-size: 10px; color: var(--g-text-mute); }
  .ent-item .fc { font-family: var(--font-mono); font-size: 10px; padding: 1px 6px; border-radius: 3px; color: var(--g-text-dim); background: var(--g-surface-3); flex-shrink: 0; }
  .ent-item .fc.crit { color: var(--sev-crit); background: rgba(255,77,94,.12); }
  .ent-item .fc.high { color: var(--sev-high); background: rgba(251,181,52,.12); }

  /* chat dock */
  .chat-dock { border-top: 1px solid var(--g-border-soft); background: rgba(8,13,24,.6); display: flex; flex-direction: column; }
  .chat-scroll { max-height: 168px; overflow-y: auto; padding: 12px 16px; display: flex; flex-direction: column; gap: 10px; }
  .msg { font-size: 12.5px; line-height: 1.5; max-width: 92%; }
  .msg.user { align-self: flex-end; background: rgba(76,141,255,.14); border: 1px solid rgba(76,141,255,.3); color: var(--g-text); padding: 8px 12px; border-radius: 12px 12px 3px 12px; }
  .msg.geoff { align-self: flex-start; color: var(--g-text-dim); }
  .msg.geoff b { color: var(--g-blue-soft); font-family: var(--font-mono); font-weight: 600; font-size: 11px; letter-spacing: .5px; display: block; margin-bottom: 2px; }
  .chat-in { display: flex; gap: 8px; padding: 10px 14px 14px; border-top: 1px solid var(--g-line); }
  .chat-in input { flex: 1; background: var(--g-surface-2); border: 1px solid var(--g-border); border-radius: 999px; padding: 9px 14px; font-size: 12.5px; outline: none; transition: border-color .15s; }
  .chat-in input:focus { border-color: var(--g-blue); }
  .chat-in button { width: 38px; height: 38px; border-radius: 50%; background: var(--g-blue); color: #fff; display: grid; place-items: center; flex-shrink: 0; }
  .chat-in button:hover { filter: brightness(1.1); }
</style>
</head>
<body>
<div class="grid-tex"></div>
<div class="app">

  <!-- brand bar -->
  <header class="brandbar">
    <div class="brand">
      <div class="mark">G</div>
      <div class="wordmark"><b>GEOFF</b><span>Forensic Framework</span></div>
    </div>
    <nav style="display:flex;gap:4px;">
      <a class="navlink active">Find Evil</a>
      <a class="navlink" id="nav-evidence" href="/cases">Evidence</a>
      <a class="navlink" href="/reports/narrative">Reports</a>
    </nav>
    <div class="spacer"></div>
    <div class="online"><span class="dot"></span>ENGINE ONLINE</div>
  </header>

  <!-- operation bar -->
  <div class="opbar">
    <div class="evfield">
      <span class="ic">▸</span>
      <input id="evdir" value="" spellcheck="false" placeholder="Evidence path…">
    </div>
    <div class="pb"><span class="k">Playbook</span><span class="v" id="pb-name">full-spectrum</span></div>
    <div class="pb"><span class="k">Engine</span><span class="v">Geoff Triad</span></div>
    <button class="btn primary" id="runbtn">◎ Run Find Evil</button>
  </div>

  <!-- workspace -->
  <div class="work">

    <!-- LEFT: playbook selector + evidence manifest -->
    <aside class="col left">
      <div class="rail-label"><span class="eyebrow">Playbook</span></div>
      <div class="playbooks" id="playbooks"></div>
      <div class="col-h" style="margin-top:6px;">
        <span class="eyebrow">Evidence Manifest</span>
        <span class="cnt" id="man-cnt">—</span>
      </div>
      <div class="recent" id="manifest"></div>
    </aside>

    <!-- CENTER: live run console -->
    <main class="col stage">
      <div class="op-head">
        <div class="op-title">
          <h1 id="op-title">Find Evil</h1>
          <span class="sev-pill" id="op-sevpill" style="opacity:0;">PENDING</span>
        </div>
        <div class="op-sub">
          <span class="mono" id="op-case">Ready</span>
          <span class="liveflag" id="op-live" style="display:none;"><span class="d"></span>LIVE</span>
          <span class="mono" id="op-elapsed">elapsed 00:00</span>
        </div>
      </div>

      <div class="phases" id="phases"></div>

      <div class="progress-row">
        <div class="pbar"><i id="pbar-fill"></i></div>
        <span class="pct" id="pbar-pct">0%</span>
        <span class="steps" id="pbar-steps">—</span>
      </div>

      <div class="feed-wrap" id="feed-wrap">
        <div class="feed-head"><span class="eyebrow">Live Findings</span><span class="line"></span></div>
        <div id="feed"></div>
      </div>
    </main>

    <!-- RIGHT: telemetry + chat -->
    <aside class="col right">
      <div class="tele">
        <div class="tele-sec">
          <span class="eyebrow">Verdict</span>
          <div class="verdict-box" id="verdict-box">
            <div class="vtop">
              <div class="vbadge" id="vbadge">— — —</div>
              <div>
                <div class="vlabel">Determination</div>
                <div class="vsev"><span class="sev-pill" id="v-sevpill" style="opacity:.3;">PENDING</span></div>
              </div>
            </div>
            <div class="threatmeter">
              <div class="track"><i id="threat-fill"></i></div>
              <div class="scale"><span>NONE</span><span>LOW</span><span>MED</span><span>HIGH</span><span>CRIT</span></div>
            </div>
          </div>
        </div>

        <div class="tele-sec">
          <span class="eyebrow">Findings by Severity</span>
          <div class="sevgrid">
            <div class="sevstat crit"><div class="n" id="c-crit">0</div><div class="l">Critical</div></div>
            <div class="sevstat high"><div class="n" id="c-high">0</div><div class="l">High</div></div>
            <div class="sevstat med" ><div class="n" id="c-med" >0</div><div class="l">Medium</div></div>
            <div class="sevstat low" ><div class="n" id="c-low" >0</div><div class="l">Low</div></div>
          </div>
        </div>

        <div class="tele-sec">
          <span class="eyebrow">Discovered Entities <span style="color:var(--g-text-faint);font-family:var(--font-mono);">(<span id="ent-cnt">0</span>)</span></span>
          <div id="ent-list"></div>
        </div>
      </div>

      <!-- chat -->
      <div class="chat-dock">
        <div class="chat-scroll" id="chat-scroll">
          <div class="msg geoff"><b>GEOFF</b>Engine online. Drop an evidence path above and hit Run, or ask me anything about the case.</div>
        </div>
        <div class="chat-in">
          <input id="chat-input" placeholder="Ask Geoff about this case…" autocomplete="off">
          <button id="chat-send" aria-label="Send">→</button>
        </div>
      </div>
    </aside>

  </div>
</div>

<script>window.GEOFF_EVIDENCE_BASE_DIR = '<!-- GEOFF_EVIDENCE_BASE_DIR -->';</script>
<script src="/static/main.js"></script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Narrative Report HTML (served at /reports/narrative)
# ---------------------------------------------------------------------------

NARRATIVE_REPORT_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Geoff — Reports</title>
<!-- GEOFF_API_KEY_META -->
<link rel="stylesheet" href="/static/tokens.css">
<style>
  body { overflow-x: hidden; }
  .page { position: relative; z-index: 1; }
  .brandbar { position: sticky; top: 0; z-index: 30; }

  .hero { padding: 30px 48px 26px; border-bottom: 1px solid var(--g-border-soft);
    background: linear-gradient(180deg, rgba(255,77,94,.05), transparent 70%); }
  .hero .crumb { display: flex; align-items: center; gap: 8px; font-family: var(--font-mono);
    font-size: 11px; color: var(--g-text-mute); margin-bottom: 14px; letter-spacing: .3px; }
  .hero .crumb a { color: inherit; text-decoration: none; }
  .hero .crumb a:hover { color: var(--g-text-dim); }
  .hero-top { display: flex; align-items: flex-start; gap: 20px; flex-wrap: wrap; }
  .hero h1 { margin: 0; font-size: 30px; font-weight: 600; letter-spacing: -.5px; line-height: 1.15; max-width: 760px; }
  .verdict-tag { display: inline-flex; align-items: center; gap: 9px; padding: 8px 14px; border-radius: var(--radius-sm);
    font-family: var(--font-mono); font-weight: 700; font-size: 14px; letter-spacing: .5px;
    color: var(--sev-crit); background: rgba(255,77,94,.12); box-shadow: inset 0 0 0 1px rgba(255,77,94,.4); }
  .verdict-tag .blip { width: 9px; height: 9px; border-radius: 50%; background: var(--sev-crit); box-shadow: 0 0 0 4px rgba(255,77,94,.18); }
  .hero-actions { margin-left: auto; display: flex; gap: 8px; }

  .metastrip { display: flex; flex-wrap: wrap; gap: 30px; margin-top: 22px; }
  .metastrip .m .k { font-size: 10px; letter-spacing: 1.4px; text-transform: uppercase; color: var(--g-text-mute); margin-bottom: 4px; }
  .metastrip .m .v { font-family: var(--font-mono); font-size: 13.5px; color: var(--g-text); }
  .metastrip .m .v.crit { color: var(--sev-crit); }

  .report-body { display: grid; grid-template-columns: 232px minmax(0,1fr); gap: 0; max-width: 1320px; margin: 0 auto; }
  .toc { position: sticky; top: 58px; align-self: start; height: calc(100vh - 58px); overflow-y: auto;
    padding: 30px 18px 30px 48px; }
  .toc .eyebrow { display: block; margin-bottom: 14px; }
  .toc a { display: flex; align-items: center; gap: 10px; padding: 7px 10px; border-radius: var(--radius-sm);
    font-size: 12.5px; color: var(--g-text-mute); border-left: 2px solid transparent; transition: all .14s;
    text-decoration: none; }
  .toc a:hover { color: var(--g-text-dim); }
  .toc a.active { color: var(--g-text); border-left-color: var(--g-blue); background: rgba(76,141,255,.07); }
  .toc a .num { font-family: var(--font-mono); font-size: 10px; color: var(--g-text-faint); }

  .content { padding: 30px 48px 90px 30px; min-width: 0; }
  section { margin-bottom: 46px; scroll-margin-top: 74px; }
  .sec-head { display: flex; align-items: baseline; gap: 12px; margin-bottom: 18px; padding-bottom: 12px; border-bottom: 1px solid var(--g-border-soft); }
  .sec-head .n { font-family: var(--font-mono); font-size: 12px; color: var(--g-blue); }
  .sec-head h2 { margin: 0; font-size: 18px; font-weight: 600; letter-spacing: -.2px; }
  .sec-head .sub { margin-left: auto; font-size: 12px; color: var(--g-text-mute); }

  .narrative { font-size: 15.5px; line-height: 1.72; color: var(--g-text-dim); max-width: 760px; }
  .narrative b { color: var(--g-text); font-weight: 600; }

  .keyfacts { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1px; margin-top: 24px;
    background: var(--g-border-soft); border: 1px solid var(--g-border-soft); border-radius: var(--radius); overflow: hidden; }
  .keyfacts .kf { background: var(--g-surface-2); padding: 14px 16px; }
  .keyfacts .kf .k { font-size: 10px; letter-spacing: 1.2px; text-transform: uppercase; color: var(--g-text-mute); margin-bottom: 6px; }
  .keyfacts .kf .v { font-family: var(--font-mono); font-size: 14px; color: var(--g-text); }
  .keyfacts .kf .v.crit { color: var(--sev-crit); }

  .tl { position: relative; padding-left: 4px; }
  .tl-row { display: grid; grid-template-columns: 124px 30px 1fr; gap: 0; align-items: start; }
  .tl-row .when { text-align: right; padding: 10px 14px 10px 0; font-family: var(--font-mono); font-size: 11px; color: var(--g-text-mute); }
  .tl-row .when .d { color: var(--g-text-dim); }
  .tl-rail { position: relative; display: flex; justify-content: center; }
  .tl-rail::before { content:""; position: absolute; top: 0; bottom: 0; width: 2px; background: var(--g-border-soft); }
  .tl-row:first-child .tl-rail::before { top: 16px; }
  .tl-row:last-child .tl-rail::before { bottom: calc(100% - 16px); }
  .tl-dot { position: relative; z-index: 2; width: 13px; height: 13px; border-radius: 50%; margin-top: 12px; background: var(--g-bg); border: 2px solid var(--sev-med); }
  .tl-dot.s-CRITICAL { border-color: var(--sev-crit); background: var(--sev-crit); box-shadow: 0 0 0 4px rgba(255,77,94,.16); }
  .tl-dot.s-HIGH { border-color: var(--sev-high); } .tl-dot.s-MEDIUM { border-color: var(--sev-med); }
  .tl-dot.s-LOW { border-color: var(--sev-low); } .tl-dot.s-INFO { border-color: var(--g-text-faint); }
  .tl-card { margin: 6px 0 12px 6px; background: var(--g-surface); border: 1px solid var(--g-border-soft); border-radius: var(--radius-sm); padding: 11px 14px; }
  .tl-card .top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .tl-card .sum { font-size: 13.5px; color: var(--g-text); margin-top: 6px; }
  .tl-card .meta { display: flex; align-items: center; gap: 10px; margin-top: 8px; font-family: var(--font-mono); font-size: 10.5px; color: var(--g-text-mute); flex-wrap: wrap; }
  .tl-card .meta .dv { display: inline-flex; align-items: center; gap: 5px; }

  .dev-block { border: 1px solid var(--g-border-soft); border-radius: var(--radius); margin-bottom: 14px; overflow: hidden; background: var(--g-surface-2); }
  .dev-head { display: flex; align-items: center; gap: 13px; padding: 14px 16px; cursor: pointer; transition: background .14s; }
  .dev-head:hover { background: var(--g-surface); }
  .dev-glyph { width: 38px; height: 38px; border-radius: 9px; display: grid; place-items: center; font-family: var(--font-mono); font-weight: 600; font-size: 11px; flex-shrink: 0; }
  .dev-glyph.pc { color: var(--ent-pc); background: rgba(76,141,255,.12); box-shadow: inset 0 0 0 1px rgba(76,141,255,.3); }
  .dev-glyph.server { color: var(--ent-server); background: rgba(167,139,250,.12); box-shadow: inset 0 0 0 1px rgba(167,139,250,.3); }
  .dev-glyph.mobile { color: var(--ent-mobile); background: rgba(251,181,52,.12); box-shadow: inset 0 0 0 1px rgba(251,181,52,.3); }
  .dev-head .nm { font-family: var(--font-mono); font-size: 13.5px; color: var(--g-text); }
  .dev-head .ro { font-size: 11.5px; color: var(--g-text-mute); margin-top: 2px; }
  .dev-head .right { margin-left: auto; display: flex; align-items: center; gap: 10px; }
  .dev-head .chev { color: var(--g-text-mute); font-size: 11px; transition: transform .2s; font-family: var(--font-mono); }
  .dev-block.collapsed .chev { transform: rotate(-90deg); }
  .dev-findings { padding: 2px 16px 14px; display: flex; flex-direction: column; gap: 9px; }
  .dev-block.collapsed .dev-findings { display: none; }

  .fcard { display: grid; grid-template-columns: auto 1fr; gap: 0 14px; border: 1px solid var(--g-border-soft);
    border-left: 3px solid var(--sev-med); border-radius: var(--radius-sm); background: var(--g-surface); padding: 12px 14px; }
  .fcard.s-CRITICAL { border-left-color: var(--sev-crit); } .fcard.s-HIGH { border-left-color: var(--sev-high); }
  .fcard.s-MEDIUM { border-left-color: var(--sev-med); } .fcard.s-LOW { border-left-color: var(--sev-low); }
  .fcard .rail { grid-row: 1 / span 4; }
  .fcard .fh { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
  .fcard .ft { font-family: var(--font-mono); font-size: 11px; color: var(--g-text-dim); }
  .fcard .fts { margin-left: auto; font-family: var(--font-mono); font-size: 10.5px; color: var(--g-text-faint); }
  .fcard .fs { font-size: 14px; font-weight: 600; color: var(--g-text); margin: 7px 0 4px; }
  .fcard .fe { font-size: 12.5px; color: var(--g-text-dim); line-height: 1.5; }
  .fcard .evrow { margin-top: 10px; padding-top: 9px; border-top: 1px dashed var(--g-border-soft); display: flex; gap: 6px; flex-wrap: wrap; }
  .fcard .ftags { margin-top: 9px; display: flex; gap: 5px; flex-wrap: wrap; }

  .mitre-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(168px, 1fr)); gap: 10px; }
  .mitre-col { border: 1px solid var(--g-border-soft); border-radius: var(--radius-sm); background: var(--g-surface-2); padding: 11px 12px; }
  .mitre-col .tac { font-size: 11px; font-weight: 600; color: var(--g-text-dim); margin-bottom: 9px; letter-spacing: .2px; }
  .mitre-col .tech { display: flex; flex-direction: column; gap: 6px; }
  .tcell { border-radius: 5px; padding: 7px 9px; background: var(--g-surface); border: 1px solid var(--g-border-soft); border-left: 3px solid var(--sev-low); }
  .tcell.s-CRITICAL { border-left-color: var(--sev-crit); background: rgba(255,77,94,.06); }
  .tcell.s-HIGH { border-left-color: var(--sev-high); background: rgba(251,181,52,.05); }
  .tcell.s-MEDIUM { border-left-color: var(--sev-med); background: rgba(76,141,255,.05); }
  .tcell .tid { font-family: var(--font-mono); font-size: 11px; color: var(--g-text); }
  .tcell .tn { font-size: 10.5px; color: var(--g-text-mute); margin-top: 2px; line-height: 1.3; }

  .ioc-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }
  .ioc-group { border: 1px solid var(--g-border-soft); border-radius: var(--radius-sm); background: var(--g-surface-2); overflow: hidden; }
  .ioc-group .gl { display: flex; align-items: center; gap: 8px; padding: 9px 12px; border-bottom: 1px solid var(--g-border-soft);
    font-size: 10.5px; letter-spacing: 1px; text-transform: uppercase; color: var(--g-text-mute); }
  .ioc-group .gl .c { margin-left: auto; font-family: var(--font-mono); color: var(--g-text-dim); }
  .ioc-row { display: flex; align-items: center; gap: 8px; padding: 7px 12px; border-top: 1px dashed var(--g-line); }
  .ioc-row:first-of-type { border-top: none; }
  .ioc-row .val { flex: 1; font-family: var(--font-mono); font-size: 11.5px; color: var(--g-text); word-break: break-all; }
  .ioc-row .cp { flex-shrink: 0; font-family: var(--font-mono); font-size: 13px; color: var(--g-text-faint); padding: 2px 6px; border-radius: 4px; cursor: pointer; }
  .ioc-row .cp:hover { color: var(--g-text-dim); background: var(--g-surface); }

  @media (max-width: 920px) {
    .report-body { grid-template-columns: 1fr; }
    .toc { display: none; }
    .hero, .content { padding-left: 24px; padding-right: 24px; }
  }
</style>
</head>
<body>
<div class="grid-tex"></div>
<div class="page">

  <header class="brandbar">
    <div class="brand"><div class="mark">G</div><div class="wordmark"><b>GEOFF</b><span>Forensic Framework</span></div></div>
    <nav style="display:flex;gap:4px;">
      <a class="navlink" href="/">Find Evil</a>
      <a class="navlink" href="/">Evidence</a>
      <a class="navlink active" href="/reports/narrative">Reports</a>
    </nav>
    <div class="spacer"></div>
    <div class="online"><span class="dot"></span>REPORT · FINALIZED</div>
  </header>

  <div class="hero">
    <div class="crumb"><a href="/reports/narrative">Cases</a> <span>/</span> <span id="h-case"></span></div>
    <div class="hero-top">
      <div><h1 id="h-title">Reports</h1></div>
      <div class="hero-actions">
        <a class="btn" id="dl-md" href="#">↓ Markdown</a>
        <a class="btn" id="dl-json" href="#">↓ JSON</a>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:12px;margin-top:18px;">
      <span class="verdict-tag" id="verdict-tag"><span class="blip"></span><span class="label">EVIL FOUND</span></span>
      <span class="sev-pill" id="h-sevpill" style="font-size:12px;padding:6px 12px;"></span>
    </div>
    <div class="metastrip" id="metastrip"></div>
  </div>

  <div class="report-body">
    <nav class="toc" id="toc"><span class="eyebrow">Contents</span></nav>
    <main class="content" id="content"></main>
  </div>

</div>
<script src="/static/report.js"></script>
</body>
</html>
"""
