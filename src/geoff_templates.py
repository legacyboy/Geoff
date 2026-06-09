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

  @keyframes slidein { from { transform: translateY(7px); opacity: 0; } to { transform: none; opacity: 1; } }

  .logline {
    display: flex; align-items: baseline; gap: 10px; padding: 5px 0;
    font-family: var(--font-mono); font-size: 12px; color: var(--g-text-dim);
    animation: slidein .35s ease;
  }
  .logline .tk { color: var(--g-text-faint); flex-shrink: 0; }
  .logline .ar { color: var(--g-cyan); flex-shrink: 0; }
  .logline span:last-child { overflow-wrap: anywhere; }

  .find-card {
    display: grid; grid-template-columns: auto 1fr; gap: 0 14px;
    border: 1px solid var(--g-border-soft); border-left: 3px solid var(--sev-med);
    border-radius: var(--radius-sm); background: var(--g-surface);
    padding: 13px 15px; margin-bottom: 10px;
    box-shadow: var(--shadow-1); animation: slidein .4s ease;
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
    animation: slidein .5s ease;
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

  .ent-item { display: flex; align-items: center; gap: 9px; padding: 7px 4px; border-bottom: 1px solid var(--g-line); animation: slidein .35s ease; }
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

  /* ---- evidence panel ---- */
  .panel-view { display: none; flex: 1; min-height: 0; flex-direction: column; background: rgba(8,13,24,.3); }
  .panel-view.active { display: flex; }
  .panel-view .panel-head {
    padding: 18px 26px 12px; display: flex; align-items: center; gap: 16px;
    border-bottom: 1px solid var(--g-border-soft);
  }
  .panel-view .panel-head h2 { margin: 0; font-size: 20px; font-weight: 600; letter-spacing: -.2px; }
  .panel-view .panel-head .cnt { font-family: var(--font-mono); font-size: 12px; color: var(--g-text-mute); }
  .panel-view .panel-body { flex: 1; overflow-y: auto; padding: 16px 26px 26px; }

  /* ---- case cards ---- */
  .case-card {
    border: 1px solid var(--g-border-soft); border-radius: var(--radius);
    padding: 16px 20px; margin-bottom: 12px; background: var(--g-surface);
    transition: all .14s; cursor: pointer;
  }
  .case-card:hover { border-color: var(--g-border); box-shadow: var(--shadow-1); }
  .case-card .cc-top { display: flex; align-items: center; gap: 12px; }
  .case-card .cc-name { font-family: var(--font-mono); font-size: 14px; font-weight: 600; color: var(--g-text); flex: 1; }
  .case-card .cc-meta { display: flex; gap: 10px; align-items: center; margin-top: 6px; }
  .case-card .cc-meta span { font-family: var(--font-mono); font-size: 10.5px; color: var(--g-text-mute); }
  .case-card .cc-items { margin-top: 10px; display: flex; flex-direction: column; gap: 2px; }
  .case-card .cc-items .ci { font-family: var(--font-mono); font-size: 10.5px; color: var(--g-text-dim); padding: 2px 0; }
  .case-card .cc-items .ci.dir { color: var(--g-blue-soft); }
  .case-empty { padding: 32px 0; text-align: center; color: var(--g-text-mute); font-size: 14px; }

  /* ---- report cards ---- */
  .rpt-card {
    border: 1px solid var(--g-border-soft); border-left: 3px solid var(--g-border);
    border-radius: var(--radius); padding: 16px 20px; margin-bottom: 12px;
    background: var(--g-surface); transition: all .14s; cursor: pointer;
  }
  .rpt-card:hover { border-color: var(--g-border); box-shadow: var(--shadow-1); }
  .rpt-card.evil { border-left-color: var(--sev-crit); }
  .rpt-card.clean { border-left-color: var(--g-green); }
  .rpt-card .rt-top { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .rpt-card .rt-name { font-family: var(--font-mono); font-size: 14px; font-weight: 600; color: var(--g-text); flex: 1; }
  .rpt-card .rt-meta { display: flex; gap: 10px; align-items: center; margin-top: 6px; flex-wrap: wrap; }
  .rpt-card .rt-meta span { font-family: var(--font-mono); font-size: 10.5px; color: var(--g-text-mute); }
  .rpt-card .rt-desc { font-size: 12.5px; color: var(--g-text-dim); margin-top: 6px; line-height: 1.45; }
  .rpt-card .rt-actions { display: flex; gap: 6px; margin-top: 10px; }
  .rpt-card .rt-chat-btn { display: inline-flex; align-items: center; gap: 5px; padding: 4px 10px;
    background: rgba(76,141,255,.1); border: 1px solid rgba(76,141,255,.25); border-radius: 5px;
    font-family: var(--font-mono); font-size: 10.5px; color: var(--g-blue-soft); cursor: pointer;
    transition: all .14s; }
  .rpt-card .rt-chat-btn:hover { background: rgba(76,141,255,.2); border-color: var(--g-blue); }
  .rpt-card.rp-selected { border-color: var(--g-blue); box-shadow: 0 0 0 1px var(--g-blue); }

  /* ---- report chat dock (Reports tab) ---- */
  .rp-chat-dock { border-top: 2px solid var(--g-border-soft); background: rgba(8,13,24,.7);
    display: flex; flex-direction: column; flex-shrink: 0; }
  .rp-chat-dock.hidden { display: none; }
  .rp-chat-head { display: flex; align-items: center; gap: 9px; padding: 9px 16px;
    cursor: pointer; user-select: none; border-bottom: 1px solid var(--g-border-soft); }
  .rp-chat-head:hover { background: rgba(76,141,255,.06); }
  .rp-chat-head .rp-chat-label { font-family: var(--font-mono); font-size: 12px; font-weight: 600;
    color: var(--g-text-dim); letter-spacing: .4px; flex: 1; }
  .rp-chat-body { display: flex; flex-direction: column; }
  .rp-chat-scroll { height: 200px; overflow-y: auto; padding: 12px 14px;
    display: flex; flex-direction: column; gap: 8px; }
  .rp-msg { font-size: 12.5px; line-height: 1.5; max-width: 94%; }
  .rp-msg.user { align-self: flex-end; background: rgba(76,141,255,.14);
    border: 1px solid rgba(76,141,255,.3); color: var(--g-text); padding: 7px 11px;
    border-radius: 12px 12px 3px 12px; }
  .rp-msg.geoff { align-self: flex-start; color: var(--g-text-dim); }
  .rp-msg.geoff b { color: var(--g-blue-soft); font-family: var(--font-mono); font-weight: 600;
    font-size: 11px; letter-spacing: .5px; display: block; margin-bottom: 2px; }
  .rp-chat-in { display: flex; gap: 7px; padding: 8px 12px 12px;
    border-top: 1px solid var(--g-border-soft); }
  .rp-chat-in input { flex: 1; background: var(--g-surface-2); border: 1px solid var(--g-border);
    border-radius: 999px; padding: 8px 13px; font-size: 12px; outline: none;
    color: var(--g-text); transition: border-color .15s; }
  .rp-chat-in input:focus { border-color: var(--g-blue); }
  .rp-chat-in button { width: 34px; height: 34px; border-radius: 50%; background: var(--g-blue);
    color: #fff; display: grid; place-items: center; flex-shrink: 0; font-size: 14px; }
  .rp-chat-in button:hover { filter: brightness(1.15); }
  .rp-chat-dock.collapsed .rp-chat-body { display: none; }
  .dig-deeper-btn { display: inline-flex; align-items: center; gap: 5px; margin-top: 7px;
    padding: 5px 11px; background: rgba(76,141,255,.1); border: 1px solid rgba(76,141,255,.28);
    border-radius: 5px; font-family: var(--font-mono); font-size: 11px; color: var(--g-blue-soft);
    cursor: pointer; transition: all .14s; }
  .dig-deeper-btn:hover { background: rgba(76,141,255,.22); border-color: var(--g-blue); }

  /* ---- live job banner ---- */
  .job-banner {
    display: none; align-items: center; gap: 14px;
    padding: 12px 22px; border-bottom: 1px solid var(--g-border-soft);
    background: linear-gradient(90deg, rgba(76,141,255,.08), rgba(31,200,219,.04), transparent);
  }
  .job-banner.active { display: flex; }
  .job-banner .liveflag { display: inline-flex; align-items: center; gap: 6px; color: var(--g-blue-soft); font-family: var(--font-mono); font-size: 12px; flex-shrink: 0; }
  .job-banner .liveflag .d { width: 7px; height: 7px; border-radius: 50%; background: var(--g-blue); animation: pulse 1.1s infinite; }
  .job-banner .jb-info { flex: 1; font-family: var(--font-mono); font-size: 12px; color: var(--g-text-dim); }
  .job-banner .jb-pct { font-family: var(--font-mono); font-size: 13px; color: var(--g-blue-soft); font-weight: 600; }
  /* ---- settings panel ---- */
  .settings-section { margin-bottom: 32px; }
  .settings-section h3 { font-size: 13px; letter-spacing: 1.2px; text-transform: uppercase; color: var(--g-text-mute); margin: 0 0 14px; border-bottom: 1px solid var(--g-border-soft); padding-bottom: 8px; }
  .settings-row { display: flex; align-items: center; gap: 14px; margin-bottom: 12px; }
  .settings-row label { width: 160px; font-size: 12.5px; color: var(--g-text-dim); flex-shrink: 0; }
  .settings-select, .settings-input {
    flex: 1; max-width: 360px; background: var(--g-surface-2); border: 1px solid var(--g-border);
    border-radius: var(--radius-sm); color: var(--g-text); font-family: var(--font-mono); font-size: 12.5px;
    padding: 8px 12px; outline: none; transition: border-color .15s, box-shadow .15s;
  }
  .settings-select:focus, .settings-input:focus { border-color: var(--g-blue); box-shadow: var(--glow-blue); }
  .settings-save-btn {
    font-size: 11.5px; padding: 7px 16px; cursor: pointer;
    background: rgba(76,141,255,.12); border: 1px solid rgba(76,141,255,.35);
    border-radius: var(--radius-sm); color: var(--g-blue-soft); transition: all .14s;
  }
  .settings-save-btn:hover { background: rgba(76,141,255,.22); border-color: var(--g-blue); }
  .settings-save-btn.saved { background: rgba(34,197,94,.12); border-color: rgba(34,197,94,.45); color: #4ade80; }
  .settings-hint { font-size: 11px; color: var(--g-text-faint); margin-top: 4px; }

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
      <a class="navlink active" data-tab="console" id="nav-console">Find Evil</a>
      <a class="navlink" data-tab="evidence" id="nav-evidence">Evidence</a>
      <a class="navlink" data-tab="reports" id="nav-reports" href="/reports/narrative">Reports</a>
      <a class="navlink" data-tab="settings" id="nav-settings">&#9881; Settings</a>
    </nav>
    <div class="spacer"></div>
    <div class="online"><span class="dot"></span>ENGINE ONLINE</div>
  </header>

  <!-- live job banner (hidden until a running job is detected) -->
  <div class="job-banner" id="job-banner">
    <span class="liveflag"><span class="d"></span>LIVE JOB</span>
    <span class="jb-info" id="jb-info">—</span>
    <span class="jb-pct" id="jb-pct">0%</span>
    <button class="btn primary" id="jb-resume" style="font-size:12px;padding:6px 14px;">Resume</button>
  </div>

  <!-- Tab: Find Evil console -->
  <div class="tab-view" id="tab-console" style="display:flex;flex-direction:column;flex:1;min-height:0;">
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
  </div><!-- /#tab-console -->

  <!-- Tab: Evidence browser -->
  <div class="panel-view" id="tab-evidence">
    <div class="panel-head">
      <h2>Evidence</h2>
      <span class="cnt" id="ev-cnt">—</span>
      <span style="flex:1;"></span>
      <span class="eyebrow" style="color:var(--g-text-mute);">Base: <!-- GEOFF_EVIDENCE_BASE_DIR --></span>
    </div>
    <div class="panel-body" id="ev-panel-body">
      <div class="case-empty">Loading cases…</div>
    </div>
  </div>

  <!-- Tab: Reports browser -->
  <div class="panel-view" id="tab-reports">
    <div class="panel-head">
      <h2>Reports</h2>
      <span class="cnt" id="rp-cnt">—</span>
    </div>
    <div class="panel-body" id="rp-panel-body">
      <div class="case-empty">Loading reports…</div>
    </div>
    <!-- Report Chat Dock -->
    <div class="rp-chat-dock hidden" id="rp-chat-dock">
      <div class="rp-chat-head" onclick="toggleRpChat()">
        <span class="rc-dot"></span>
        <span class="rp-chat-label" id="rp-chat-label">GEOFF &mdash; Select a report to chat</span>
        <span id="rp-chat-toggle" style="font-family:var(--font-mono);font-size:11px;color:var(--g-text-mute);">&#9660;</span>
      </div>
      <div class="rp-chat-body">
        <div class="rp-chat-scroll" id="rp-chat-scroll">
          <div class="rp-msg geoff"><b>GEOFF</b>Ask me anything about this investigation.</div>
        </div>
        <div class="rp-chat-in">
          <input id="rp-chat-input" placeholder="Ask about this case…" autocomplete="off">
          <button id="rp-chat-send" aria-label="Send">&#10148;</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Tab: Settings -->
  <div class="panel-view" id="tab-settings">
    <div class="panel-head">
      <h2>&#9881; Settings</h2>
    </div>
    <div class="panel-body">

      <!-- Model Selection -->
      <div class="settings-section">
        <h3>Agent Models</h3>
        <div class="settings-row">
          <label>Manager Model</label>
          <select class="settings-select" id="sel-manager"></select>
        </div>
        <div class="settings-row">
          <label>Forensicator Model</label>
          <select class="settings-select" id="sel-forensicator"></select>
        </div>
        <div class="settings-row">
          <label>Critic Model</label>
          <select class="settings-select" id="sel-critic"></select>
        </div>
        <div class="settings-row">
          <label></label>
          <button class="settings-save-btn" id="save-models-btn">Save Models</button>
          <span class="settings-hint" id="models-feedback"></span>
        </div>
      </div>

      <!-- API Keys -->
      <div class="settings-section">
        <h3>API Keys</h3>
        <div class="settings-row">
          <label>OpenAI API Key</label>
          <input class="settings-input" type="password" id="key-openai" placeholder="sk-…" autocomplete="new-password">
        </div>
        <div class="settings-row">
          <label>Anthropic / Claude Key</label>
          <input class="settings-input" type="password" id="key-claude" placeholder="sk-ant-…" autocomplete="new-password">
        </div>
        <div class="settings-row">
          <label>Ollama API Key</label>
          <input class="settings-input" type="password" id="key-ollama" placeholder="ollama-…" autocomplete="new-password">
        </div>
        <div class="settings-row">
          <label>DeepSeek API Key</label>
          <input class="settings-input" type="password" id="key-deepseek" placeholder="sk-…" autocomplete="new-password">
        </div>
        <div class="settings-row">
          <label></label>
          <button class="settings-save-btn" id="save-keys-btn">Save All Keys</button>
          <span class="settings-hint" id="keys-feedback"></span>
        </div>
        <p class="settings-hint" style="margin-top:8px;">Keys are stored server-side with 0600 permissions. Only the last 4 characters are shown after saving.</p>
      </div>

    </div>
  </div>

</div>

<script>window.GEOFF_EVIDENCE_BASE_DIR = '<!-- GEOFF_EVIDENCE_BASE_DIR -->';</script>
<script src="/static/main.js"></script>
<script>
(function() {
  function $(id){return document.getElementById(id);}
/* ============================================================
     SETTINGS TAB
     ============================================================ */
  let _settingsLoaded = false;

  function loadSettingsPanel() {
    if (_settingsLoaded) return;
    fetch('/api/settings')
      .then(r => r.json())
      .then(data => {
        _settingsLoaded = true;
        const opts = data.model_options || [];
        const models = data.models || {};
        const keys = data.keys || {};

        ['manager', 'forensicator', 'critic'].forEach(role => {
          const sel = document.getElementById('sel-' + role);
          if (!sel) return;
          sel.innerHTML = '';
          opts.forEach(o => {
            const opt = document.createElement('option');
            opt.value = o; opt.textContent = o;
            if (o === models[role]) opt.selected = true;
            sel.appendChild(opt);
          });
          // If current value not in list, add it
          if (models[role] && !opts.includes(models[role])) {
            const opt = document.createElement('option');
            opt.value = models[role]; opt.textContent = models[role]; opt.selected = true;
            sel.insertBefore(opt, sel.firstChild);
          }
        });

        // Show masked key values as placeholder
        const keyMap = {openai: 'key-openai', claude: 'key-claude', ollama: 'key-ollama', deepseek: 'key-deepseek'};
        Object.entries(keyMap).forEach(([k, id]) => {
          const el = document.getElementById(id);
          if (el && keys[k + '_key']) el.placeholder = keys[k + '_key'];
        });
      })
      .catch(() => {});
  }

  function flashSaved(btnId, feedbackId, msg) {
    const btn = document.getElementById(btnId);
    const fb = document.getElementById(feedbackId);
    if (btn) { btn.textContent = 'Saved ✓'; btn.classList.add('saved'); setTimeout(() => { btn.textContent = btnId === 'save-models-btn' ? 'Save Models' : 'Save All Keys'; btn.classList.remove('saved'); }, 2000); }
    if (fb) { fb.textContent = msg || ''; }
  }

  const saveModelsBtn = $('save-models-btn');
  if (saveModelsBtn) saveModelsBtn.onclick = () => {
    const body = {
      manager: document.getElementById('sel-manager')?.value,
      forensicator: document.getElementById('sel-forensicator')?.value,
      critic: document.getElementById('sel-critic')?.value,
    };
    fetch('/api/settings/models', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) })
      .then(r => r.json())
      .then(d => { if (d.status === 'ok') flashSaved('save-models-btn', 'models-feedback', 'Models updated'); else document.getElementById('models-feedback').textContent = d.error || 'Error'; })
      .catch(() => { document.getElementById('models-feedback').textContent = 'Network error'; });
  };

  const saveKeysBtn = $('save-keys-btn');
  if (saveKeysBtn) saveKeysBtn.onclick = () => {
    const body = {
      openai_key: document.getElementById('key-openai')?.value || undefined,
      claude_key: document.getElementById('key-claude')?.value || undefined,
      ollama_key: document.getElementById('key-ollama')?.value || undefined,
      deepseek_key: document.getElementById('key-deepseek')?.value || undefined,
    };
    // Only send non-empty values
    Object.keys(body).forEach(k => { if (!body[k]) delete body[k]; });
    if (Object.keys(body).length === 0) { document.getElementById('keys-feedback').textContent = 'Enter at least one key'; return; }
    fetch('/api/settings/keys', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) })
      .then(r => r.json())
      .then(d => {
        if (d.status === 'ok') {
          flashSaved('save-keys-btn', 'keys-feedback', 'Keys saved');
          _settingsLoaded = false; // force reload to update placeholders
          loadSettingsPanel();
          ['key-openai','key-claude','key-ollama','key-deepseek'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
        } else { document.getElementById('keys-feedback').textContent = d.error || 'Error'; }
      })
      .catch(() => { document.getElementById('keys-feedback').textContent = 'Network error'; });
  };
})();
</script>
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

  /* report chat dock */
  .report-chat { position: fixed; bottom: 0; right: 24px; width: 380px; z-index: 100;
    background: var(--g-surface); border: 1px solid var(--g-border-soft); border-bottom: none;
    border-radius: 12px 12px 0 0; box-shadow: 0 -4px 24px rgba(0,0,0,.35);
    transition: all .2s ease; }
  .report-chat.maximized { top: 0; left: 0; right: 0; bottom: 0; width: 100%; border-radius: 0;
    border: none; z-index: 200; }
  .report-chat-head { display: flex; align-items: center; gap: 10px; padding: 10px 14px;
    border-bottom: 1px solid var(--g-border-soft); cursor: pointer; }
  .report-chat-head .rc-label { font-family: var(--font-mono); font-size: 12px; font-weight: 600;
    color: var(--g-text-dim); letter-spacing: .4px; flex: 1; }
  .report-chat-head .rc-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--g-blue); }
  .report-chat-head .rc-action-btn { background: rgba(76,141,255,.08); border: 1px solid var(--g-border);
    border-radius: 4px; color: var(--g-text-dim); font-size: 13px; padding: 3px 8px; cursor: pointer;
    font-family: var(--font-mono); line-height: 1.4; flex-shrink: 0; }
  .report-chat-head .rc-action-btn:hover { color: #fff; background: var(--g-blue); border-color: var(--g-blue); }
  .report-chat-body { display: flex; flex-direction: column; }
  .report-chat-scroll { height: 180px; overflow-y: auto; padding: 12px 14px; display: flex;
    flex-direction: column; gap: 8px; }
  .report-chat.maximized .report-chat-scroll { height: calc(100vh - 108px); }
  .rc-msg { font-size: 12.5px; line-height: 1.5; max-width: 94%; }
  .rc-msg.user { align-self: flex-end; background: rgba(76,141,255,.14);
    border: 1px solid rgba(76,141,255,.3); color: var(--g-text); padding: 7px 11px;
    border-radius: 12px 12px 3px 12px; }
  .rc-msg.geoff { align-self: flex-start; color: var(--g-text-dim); }
  .rc-msg.geoff b { color: var(--g-blue-soft); font-family: var(--font-mono); font-weight: 600;
    font-size: 11px; letter-spacing: .5px; display: block; margin-bottom: 2px; }
  .rc-section-link { color: var(--g-blue-soft); text-decoration: underline;
    text-decoration-style: dotted; cursor: pointer; }
  .rc-section-link:hover { color: var(--g-blue); }
  .report-chat-in { display: flex; gap: 7px; padding: 8px 12px 12px;
    border-top: 1px solid var(--g-line); }
  .report-chat-in input { flex: 1; background: var(--g-surface-2); border: 1px solid var(--g-border);
    border-radius: 999px; padding: 8px 13px; font-size: 12px; outline: none;
    color: var(--g-text); transition: border-color .15s; }
  .report-chat-in input:focus { border-color: var(--g-blue); }
  .report-chat-in button { width: 34px; height: 34px; border-radius: 50%; background: var(--g-blue);
    color: #fff; display: grid; place-items: center; flex-shrink: 0; font-size: 14px; }
  .report-chat-in button:hover { filter: brightness(1.1); }
  .report-chat.collapsed .report-chat-body { display: none; }
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
        <button class="btn" id="btn-ip-map" onclick="openIPMap()" style="cursor:pointer;">&#9671; IP Map</button>
        <a class="btn" id="dl-md" href="#">↓ Markdown</a>
        <a class="btn" id="dl-json" href="#">↓ JSON</a>
        <button class="btn" id="btn-exec-log" style="cursor:pointer;" title="View every command Geoff ran">⎘ Commands</button>
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

<!-- IP Map Modal -->
<div id="ip-map-modal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;z-index:2000;background:rgba(5,10,20,.88);backdrop-filter:blur(6px);align-items:center;justify-content:center;">
  <div style="width:92vw;height:90vh;max-width:1400px;background:var(--g-surface);border:1px solid var(--g-border);border-radius:var(--radius);display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.5);">
    <div style="display:flex;align-items:center;gap:16px;padding:14px 20px;border-bottom:1px solid var(--g-border-soft);flex-shrink:0;">
      <span style="font-family:var(--font-mono);font-size:13px;font-weight:600;color:var(--g-text);">&#9671; IP Connection Map</span>
      <span id="ip-map-stats" style="font-family:var(--font-mono);font-size:11px;color:var(--g-text-mute);"></span>
      <label style="display:flex;align-items:center;gap:7px;margin-left:auto;font-size:12px;color:var(--g-text-dim);cursor:pointer;">
        <input type="checkbox" id="ipm-toggle-ext" checked style="accent-color:var(--sev-crit);"> Show external IPs
      </label>
      <label style="display:flex;align-items:center;gap:7px;font-size:12px;color:var(--g-text-dim);cursor:pointer;">
        <input type="checkbox" id="ipm-toggle-int" checked style="accent-color:#22c55e;"> Show internal IPs
      </label>
      <button onclick="closeIPMap()" style="background:none;border:none;color:var(--g-text-mute);font-size:18px;cursor:pointer;padding:0 4px;line-height:1;" title="Close">&times;</button>
    </div>
    <div style="display:flex;flex:1;min-height:0;">
      <div id="ip-network" style="flex:1;min-width:0;background:var(--g-bg);"></div>
      <div id="ip-node-info" style="display:none;width:260px;flex-shrink:0;border-left:1px solid var(--g-border-soft);padding:16px;overflow-y:auto;font-size:13px;">
        <div style="font-size:10px;letter-spacing:1.2px;text-transform:uppercase;color:var(--g-text-mute);margin-bottom:12px;">Selected Node</div>
        <div id="ip-node-info-body"></div>
      </div>
    </div>
    <div style="padding:8px 20px;border-top:1px solid var(--g-border-soft);font-family:var(--font-mono);font-size:10px;color:var(--g-text-faint);flex-shrink:0;">
      Click a node to inspect · Scroll to zoom · Drag to pan · Internal (green) left · External (red) right
    </div>
  </div>
</div>

<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<script>
(function() {
  var _ipNetwork = null;
  var _ipAllNodes = null;
  var _ipAllEdges = null;
  var _ipRawData = null;

  window.openIPMap = function() {
    var modal = document.getElementById('ip-map-modal');
    modal.style.display = 'flex';
    if (!_ipRawData) {
      var caseDir = new URLSearchParams(location.search).get('case');
      if (!caseDir) {
        document.getElementById('ip-network').innerHTML =
          '<div style="color:var(--g-text-mute);text-align:center;padding:60px;font-family:var(--font-mono);font-size:13px;">No case selected.</div>';
        return;
      }
      loadIPMap(caseDir);
    }
  };

  window.closeIPMap = function() {
    document.getElementById('ip-map-modal').style.display = 'none';
  };

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeIPMap();
  });

  function apiKey() {
    var m = document.querySelector('meta[name="geoff-api-key"]');
    return m ? m.content : '';
  }

  async function loadIPMap(caseDir) {
    var net = document.getElementById('ip-network');
    net.innerHTML = '<div style="color:var(--g-text-mute);text-align:center;padding:60px;font-family:var(--font-mono);font-size:13px;">Loading IP map...</div>';
    try {
      var key = apiKey();
      var resp = await fetch('/reports/' + encodeURIComponent(caseDir) + '/ip-map',
        key ? {headers: {'X-API-Key': key}} : {});
      var data = await resp.json();
      _ipRawData = data;
      renderIPMap();
    } catch(e) {
      document.getElementById('ip-network').innerHTML =
        '<div style="color:var(--sev-crit);text-align:center;padding:60px;font-family:var(--font-mono);font-size:13px;">Error loading IP map: ' + e.message + '</div>';
    }
  }

  function renderIPMap() {
    var data = _ipRawData;
    if (!data || !data.nodes) return;

    var showExt = document.getElementById('ipm-toggle-ext').checked;
    var showInt = document.getElementById('ipm-toggle-int').checked;

    var filtered = data.nodes.filter(function(n) {
      return (n.group === 'external' && showExt) || (n.group === 'internal' && showInt);
    });

    if (filtered.length === 0) {
      document.getElementById('ip-network').innerHTML =
        '<div style="color:var(--g-text-mute);text-align:center;padding:60px;font-family:var(--font-mono);font-size:13px;">No IP data available for this case.</div>';
      document.getElementById('ip-map-stats').textContent = '';
      return;
    }

    var nodeSet = new Set(filtered.map(function(n) { return n.id; }));
    var maxConns = Math.max.apply(null, filtered.map(function(n) { return n.connections || 1; }));

    var visNodes = new vis.DataSet(filtered.map(function(n) {
      var isInt = n.group === 'internal';
      var size = 12 + Math.round((n.connections || 0) / Math.max(maxConns, 1) * 26);
      return {
        id: n.id,
        label: n.label || n.id,
        title: (n.hostname ? 'Host: ' + n.hostname + '\n' : '') +
          'IP: ' + n.id + '\nGroup: ' + n.group +
          '\nConnections: ' + n.connections +
          '\nFindings: ' + n.findings_count,
        group: n.group,
        size: size,
        x: isInt ? -350 + (Math.random() - 0.5) * 80 : 350 + (Math.random() - 0.5) * 80,
        color: {
          background: isInt ? '#166534' : '#7f1d1d',
          border: isInt ? '#22c55e' : '#ef4444',
          highlight: {background: isInt ? '#22c55e' : '#ef4444', border: isInt ? '#86efac' : '#fca5a5'}
        },
        font: {color: '#e2e8f0', size: 11, face: 'monospace'},
        shape: isInt ? 'dot' : 'diamond',
      };
    }));

    var visEdges = new vis.DataSet(
      (data.edges || []).filter(function(e) { return nodeSet.has(e.source) && nodeSet.has(e.target); })
      .map(function(e) {
        var lbl = e.port ? (e.protocol || 'TCP') + ':' + e.port : (e.protocol || '');
        return {
          from: e.source, to: e.target,
          label: lbl,
          arrows: {to: {enabled: true, scaleFactor: 0.6}},
          color: {color: '#334155', highlight: '#64748b', hover: '#64748b'},
          font: {color: '#64748b', size: 9, face: 'monospace', align: 'middle'},
          smooth: {type: 'curvedCW', roundness: 0.1},
        };
      })
    );

    document.getElementById('ip-map-stats').textContent =
      filtered.length + ' nodes · ' + visEdges.length + ' edges';

    var container = document.getElementById('ip-network');
    container.innerHTML = '';

    var network = new vis.Network(container, {nodes: visNodes, edges: visEdges}, {
      physics: {
        enabled: true,
        barnesHut: {
          gravitationalConstant: -4000,
          centralGravity: 0.15,
          springLength: 180,
          springConstant: 0.04,
          damping: 0.15,
        },
        stabilization: {iterations: 120},
      },
      interaction: {hover: true, tooltipDelay: 120, navigationButtons: true, keyboard: false},
      layout: {improvedLayout: false, randomSeed: 42},
    });

    _ipNetwork = network;

    network.on('click', function(params) {
      if (params.nodes.length === 0) return;
      var nodeId = params.nodes[0];
      var node = data.nodes.find(function(n) { return n.id === nodeId; });
      if (!node) return;
      var isInt = node.group === 'internal';
      var body = document.getElementById('ip-node-info-body');
      body.innerHTML =
        '<div style="font-family:var(--font-mono);font-size:13px;color:var(--g-text);margin-bottom:10px;">' + node.id + '</div>' +
        (node.hostname ? '<div style="font-size:12px;color:var(--g-text-dim);margin-bottom:6px;">&#8594; ' + node.hostname + '</div>' : '') +
        '<div style="display:inline-block;padding:3px 8px;border-radius:4px;font-size:10px;font-family:var(--font-mono);background:' +
          (isInt ? 'rgba(34,197,94,.15)' : 'rgba(239,68,68,.15)') + ';color:' +
          (isInt ? '#22c55e' : '#ef4444') + ';margin-bottom:12px;">' +
          node.group.toUpperCase() + '</div>' +
        '<div style="font-size:11px;color:var(--g-text-mute);">Connections: <span style="color:var(--g-text);">' + node.connections + '</span></div>' +
        '<div style="font-size:11px;color:var(--g-text-mute);margin-top:4px;">Findings: <span style="color:var(--g-text);">' + node.findings_count + '</span></div>';
      document.getElementById('ip-node-info').style.display = 'block';
    });

    network.on('stabilized', function() {
      network.fit({animation: {duration: 800, easingFunction: 'easeInOutQuad'}});
    });
  }

  document.getElementById('ipm-toggle-ext').addEventListener('change', renderIPMap);
  document.getElementById('ipm-toggle-int').addEventListener('change', renderIPMap);
})();
</script>

<!-- Report Chat Dock -->
<div class="report-chat" id="report-chat">
  <div class="report-chat-head" onclick="toggleReportChat()">
    <span class="rc-dot"></span>
    <span class="rc-label">GEOFF &mdash; Ask about this case</span>
    <button class="rc-action-btn" id="rc-maximize" title="Maximize chat" onclick="event.stopPropagation();toggleMaximizeReportChat()">&#x26F6;</button>
    <span id="rc-toggle" style="font-family:var(--font-mono);font-size:11px;color:var(--g-text-mute);">&#9660;</span>
  </div>
  <div class="report-chat-body">
    <div class="report-chat-scroll" id="report-chat-scroll">
      <div class="rc-msg geoff"><b>GEOFF</b>Ask me anything about this investigation.</div>
    </div>
    <div class="report-chat-in">
      <input id="report-chat-input" placeholder="Ask about this case…" autocomplete="off">
      <button id="report-chat-send" aria-label="Send">&#10148;</button>
    </div>
  </div>
</div>

<script src="/static/report.js?v=2"></script>
</body>
</html>
"""
