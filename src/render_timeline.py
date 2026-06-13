#!/usr/bin/env python3
"""render_timeline.py — Render Geoff audit_trail.jsonl as a single-page HTML timeline.

Usage: python3 render_timeline.py --input <jsonl_path> --output <html_path>

Reads audit_trail.jsonl and renders:
  - Timeline with trace_ids on X axis, steps on Y
  - Collapsible nodes for hypotheses, evidence, verifications
  - Color-coded by type (hypothesis=blue, recovery_arc=orange,
    correlation=green, verification=purple, investigation_start=gray)

Uses only the Python standard library (html module, no Jinja/React).
"""

import argparse
import html
import json
import sys
from pathlib import Path


TYPE_COLORS = {
    "hypothesis": "#4a90d9",           # blue  🔍
    "recovery_arc": "#f5a623",          # orange 🔄
    "correlation_event": "#9b59b6",    # purple 🔗
    "claim_verification": "#27ae60",   # green (VERIFIED default) ✅
    "investigation_start": "#7f8c8d",  # gray  ⚙️
    "case_init": "#7f8c8d",            # gray  ⚙️
}

TYPE_EMOJIS = {
    "hypothesis": "🔍",
    "recovery_arc": "🔄",
    "correlation_event": "🔗",
    "investigation_start": "⚙️",
    "case_init": "⚙️",
}

TYPE_LABELS = {
    "hypothesis": "Hypothesis",
    "recovery_arc": "Recovery Arc",
    "correlation_event": "Correlation",
    "claim_verification": "Claim Verification",
    "investigation_start": "Investigation Start",
    "case_init": "Case Init",
}

VERIFICATION_COLORS = {
    "VERIFIED": "#27ae60",     # green  ✅
    "HALLUCINATED": "#e74c3c", # red    ❌
    "UNSUPPORTED": "#f39c12",  # yellow ⚠️
}

VERIFICATION_EMOJIS = {
    "VERIFIED": "✅",
    "HALLUCINATED": "❌",
    "UNSUPPORTED": "⚠️",
}


def _esc(s):
    return html.escape(str(s) if s is not None else "")


def read_records(jsonl_path: str) -> list:
    records = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                records.append(rec)
            except json.JSONDecodeError:
                pass
    return records


def render_html(records: list, output_path: str) -> None:
    # Group records by type
    by_type = {}
    for rec in records:
        rtype = rec.get("type", "unknown")
        if rtype not in by_type:
            by_type[rtype] = []
        by_type[rtype].append(rec)

    hypotheses = by_type.get("hypothesis", [])
    recovery_arcs = by_type.get("recovery_arc", [])
    correlations = by_type.get("correlation_event", [])
    verifications = by_type.get("claim_verification", [])

    # Build summary stats
    ver_counts = {s: sum(1 for v in verifications if v.get("verification_status") == s)
                  for s in ("VERIFIED", "HALLUCINATED", "UNSUPPORTED")}
    corr_types = {}
    for c in correlations:
        rt = c.get("relationship_type", "UNKNOWN")
        corr_types[rt] = corr_types.get(rt, 0) + 1

    def make_detail_rows(rec: dict, exclude=("type",)) -> str:
        rows = []
        for k, v in rec.items():
            if k in exclude:
                continue
            if isinstance(v, (dict, list)):
                val_str = json.dumps(v, default=str)
            else:
                val_str = str(v)
            rows.append(
                f"<tr><td class='dk'>{_esc(k)}</td>"
                f"<td class='dv'>{_esc(val_str[:300])}</td></tr>"
            )
        return "".join(rows)

    def make_node(rec: dict, idx: int) -> str:
        rtype = rec.get("type", "unknown")
        color = TYPE_COLORS.get(rtype, "#7f8c8d")
        label = TYPE_LABELS.get(rtype, rtype)
        emoji = TYPE_EMOJIS.get(rtype, "⚙️")
        trace_id = rec.get("trace_id", "")
        ts = rec.get("ts", "")
        short_id = trace_id[:8] if trace_id else f"rec-{idx}"

        # For claim_verification, use per-status color
        if rtype == "claim_verification":
            vs = rec.get("verification_status", "")
            color = VERIFICATION_COLORS.get(vs, "#95a5a6")
            emoji = VERIFICATION_EMOJIS.get(vs, "⚠️")

        # Verification badge
        badge = ""
        if rtype == "claim_verification":
            vs = rec.get("verification_status", "")
            bcol = VERIFICATION_COLORS.get(vs, "#95a5a6")
            badge = f" <span class='badge' style='background:{bcol}'>{_esc(vs)}</span>"

        # Confidence badge for correlations
        if rtype == "correlation_event":
            conf = rec.get("confidence", 0)
            badge = f" <span class='badge' style='background:{color};opacity:0.8'>{conf:.0%}</span>"

        summary_text = ""
        if rtype == "hypothesis":
            summary_text = _esc(str(rec.get("hypothesis", ""))[:80])
        elif rtype == "recovery_arc":
            summary_text = _esc(str(rec.get("failure_reason", ""))[:80])
        elif rtype == "correlation_event":
            summary_text = _esc(str(rec.get("description", ""))[:80])
        elif rtype == "claim_verification":
            summary_text = _esc(str(rec.get("claim_text", ""))[:80])

        node_id = f"node-{idx}"
        return f"""
<div class='node' style='border-left:4px solid {color}'>
  <div class='node-header' onclick="toggleNode('{node_id}')">
    <span class='node-emoji'>{emoji}</span>
    <span class='node-type' style='color:{color}'>{_esc(label)}</span>{badge}
    <span class='node-id'>#{_esc(short_id)}</span>
    <span class='node-ts'>{_esc(ts[:19] if ts else '')}</span>
    <span class='node-summary'>{summary_text}</span>
    <span class='toggle-icon' id='icon-{node_id}'>▶</span>
  </div>
  <div class='node-body' id='{node_id}' style='display:none'>
    <table class='detail-table'>{make_detail_rows(rec)}</table>
  </div>
</div>"""

    # Build all nodes for each section
    def section_nodes(recs: list, offset: int) -> tuple:
        html_parts = []
        for i, rec in enumerate(recs):
            html_parts.append(make_node(rec, offset + i))
        return "".join(html_parts), offset + len(recs)

    hyp_html, idx = section_nodes(hypotheses, 0)
    rec_html, idx = section_nodes(recovery_arcs, idx)
    corr_html, idx = section_nodes(correlations, idx)
    ver_html, idx = section_nodes(verifications, idx)

    # Build timeline SVG strip (simplified: X = time order, Y = type)
    type_order = ["investigation_start", "case_init", "hypothesis", "recovery_arc",
                  "correlation_event", "claim_verification"]
    timeline_records = [r for r in records if r.get("type") in type_order][:200]

    svg_width = max(800, len(timeline_records) * 18 + 40)
    svg_height = 120
    svg_parts = [f'<svg width="{svg_width}" height="{svg_height}" class="timeline-svg">']
    # Y lanes
    lane_y = {t: 20 + i * 18 for i, t in enumerate(type_order)}
    for i, rec in enumerate(timeline_records):
        rtype = rec.get("type", "unknown")
        x = 20 + i * 18
        y = lane_y.get(rtype, 90)
        color = TYPE_COLORS.get(rtype, "#bdc3c7")
        tid_short = (rec.get("trace_id") or "")[:8]
        svg_parts.append(
            f'<circle cx="{x}" cy="{y}" r="6" fill="{color}" opacity="0.85">'
            f'<title>{_esc(rtype)}: {_esc(tid_short)}</title></circle>'
        )
    # Lane labels
    for rtype, y in lane_y.items():
        label = TYPE_LABELS.get(rtype, rtype)
        svg_parts.append(
            f'<text x="4" y="{y+4}" font-size="9" fill="#555" font-family="monospace">'
            f'{_esc(label[:16])}</text>'
        )
    svg_parts.append("</svg>")
    svg_html = "".join(svg_parts)

    total = len(records)
    hyp_count = len(hypotheses)
    rec_count = len(recovery_arcs)
    corr_count = len(correlations)
    ver_count = len(verifications)

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Geoff Audit Trail — Cognitive Trace Timeline</title>
<style>
  body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 16px; }}
  h1 {{ color: #4a90d9; margin-bottom: 4px; }}
  .subtitle {{ color: #888; font-size: 13px; margin-bottom: 16px; }}
  .stats {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }}
  .stat {{ background: #16213e; border-radius: 6px; padding: 8px 14px; font-size: 13px; }}
  .stat b {{ font-size: 20px; display: block; }}
  .timeline-wrap {{ overflow-x: auto; background: #16213e; border-radius: 8px; padding: 8px; margin-bottom: 20px; }}
  .timeline-svg {{ display: block; }}
  .section {{ margin-bottom: 20px; }}
  .section-title {{ font-size: 15px; font-weight: bold; padding: 6px 10px; border-radius: 4px; margin-bottom: 6px; cursor: pointer; }}
  .node {{ background: #16213e; border-radius: 6px; margin-bottom: 6px; overflow: hidden; }}
  .node-header {{ padding: 8px 12px; cursor: pointer; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
  .node-header:hover {{ background: #0f3460; }}
  .node-type {{ font-weight: bold; font-size: 12px; min-width: 120px; }}
  .node-id {{ color: #888; font-size: 11px; }}
  .node-ts {{ color: #888; font-size: 11px; }}
  .node-summary {{ color: #ccc; font-size: 12px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .toggle-icon {{ color: #888; font-size: 11px; margin-left: auto; }}
  .node-body {{ padding: 8px 12px; background: #0a0a1a; }}
  .detail-table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  .dk {{ color: #888; padding: 2px 8px 2px 0; vertical-align: top; white-space: nowrap; }}
  .dv {{ color: #ddd; padding: 2px 0; word-break: break-all; }}
  .badge {{ border-radius: 3px; padding: 1px 6px; font-size: 11px; color: white; }}
  .empty {{ color: #555; font-style: italic; padding: 8px; }}
  .section-toggle {{ display: none; }}
  .node-emoji {{ font-size: 14px; margin-right: 2px; }}
  .instructions {{ background: #0f3460; border: 1px solid #4a90d9; border-radius: 6px; padding: 10px 14px; margin-bottom: 16px; font-size: 12px; line-height: 1.7; }}
  .instructions code {{ background: #1a1a2e; padding: 1px 4px; border-radius: 3px; }}
</style>
</head>
<body>
<h1>Geoff — Cognitive Trace Timeline</h1>
<div class="subtitle">audit_trail.jsonl — {total} records total</div>

<div class="instructions">
  <strong>For judges:</strong>
  To verify <strong>C2 accuracy</strong>, look for <span style="color:#27ae60">✅ claim_verification</span> records — each shows VERIFIED / HALLUCINATED / UNSUPPORTED status.<br>
  To trace <strong>C1 reasoning</strong>, follow <code>parent_trace_id</code> chains — every hypothesis, recovery arc, and step links back to the root investigation.<br>
  To verify <strong>C3 cross-source correlation</strong>, look for <span style="color:#9b59b6">🔗 correlation_event</span> records — CAUSAL / CORRELATED / IDENTITY relationships.<br>
  Color legend:
  <span style="color:#4a90d9">🔍 Hypothesis</span> •
  <span style="color:#f5a623">🔄 Recovery Arc</span> •
  <span style="color:#9b59b6">🔗 Correlation</span> •
  <span style="color:#27ae60">✅ Verified</span> <span style="color:#e74c3c">❌ Hallucinated</span> <span style="color:#f39c12">⚠️ Unsupported</span> •
  <span style="color:#7f8c8d">⚙️ Tool Step</span>
</div>

<div class="stats">
  <div class="stat" style="border-top:3px solid #4a90d9">
    <b style="color:#4a90d9">{hyp_count}</b>Hypotheses
  </div>
  <div class="stat" style="border-top:3px solid #f5a623">
    <b style="color:#f5a623">{rec_count}</b>Recovery Arcs
  </div>
  <div class="stat" style="border-top:3px solid #7ed321">
    <b style="color:#7ed321">{corr_count}</b>Correlations
  </div>
  <div class="stat" style="border-top:3px solid #9b59b6">
    <b style="color:#9b59b6">{ver_count}</b>Claim Verifications
  </div>
  <div class="stat" style="border-top:3px solid #27ae60">
    <b style="color:#27ae60">{ver_counts.get("VERIFIED", 0)}</b>Verified
  </div>
  <div class="stat" style="border-top:3px solid #e74c3c">
    <b style="color:#e74c3c">{ver_counts.get("HALLUCINATED", 0)}</b>Hallucinated
  </div>
</div>

<div class="timeline-wrap">
  <div style="color:#888;font-size:11px;margin-bottom:4px">Timeline strip — each dot is one trace record (hover for type:id)</div>
  {svg_html}
</div>

<div class="section">
  <div class="section-title" style="background:#1a3a5c;color:#4a90d9" onclick="toggleSection('hyp-section')">
    ▶ Hypotheses ({hyp_count})
  </div>
  <div id="hyp-section">
    {hyp_html if hyp_html else '<div class="empty">No hypothesis records</div>'}
  </div>
</div>

<div class="section">
  <div class="section-title" style="background:#3a2a0a;color:#f5a623" onclick="toggleSection('rec-section')">
    ▶ Recovery Arcs ({rec_count})
  </div>
  <div id="rec-section">
    {rec_html if rec_html else '<div class="empty">No recovery arc records</div>'}
  </div>
</div>

<div class="section">
  <div class="section-title" style="background:#1a2a0a;color:#7ed321" onclick="toggleSection('corr-section')">
    ▶ Correlations ({corr_count})
  </div>
  <div id="corr-section">
    {corr_html if corr_html else '<div class="empty">No correlation records</div>'}
  </div>
</div>

<div class="section">
  <div class="section-title" style="background:#2a1a3a;color:#9b59b6" onclick="toggleSection('ver-section')">
    ▶ Claim Verifications ({ver_count})
  </div>
  <div id="ver-section">
    {ver_html if ver_html else '<div class="empty">No claim verification records</div>'}
  </div>
</div>

<script>
function toggleNode(id) {{
  var el = document.getElementById(id);
  var icon = document.getElementById('icon-' + id);
  if (el.style.display === 'none') {{
    el.style.display = 'block';
    icon.textContent = '▼';
  }} else {{
    el.style.display = 'none';
    icon.textContent = '▶';
  }}
}}
function toggleSection(id) {{
  var el = document.getElementById(id);
  if (el.style.display === 'none') {{
    el.style.display = 'block';
  }} else {{
    el.style.display = 'none';
  }}
}}
</script>
</body>
</html>"""

    Path(output_path).write_text(page, encoding="utf-8")
    print(f"Rendered {total} records → {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Render Geoff audit_trail.jsonl as HTML timeline")
    parser.add_argument("--input", required=True, help="Path to audit_trail.jsonl")
    parser.add_argument("--output", required=True, help="Output HTML file path")
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"ERROR: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    records = read_records(args.input)
    render_html(records, args.output)


if __name__ == "__main__":
    main()
