#!/usr/bin/env python3
"""Add _render_job_log method to narrative_report.py"""
f = "/home/sansforensics/Geoff/src/narrative_report.py"
with open(f) as fh:
    content = fh.read()

old = '        return "".join(lines)\n\n    def _render_failed_steps(self, report_json: dict) -> str:'

new = '''        return "".join(lines)

    def _render_job_log(self, report_json: dict) -> str:
        """Render the job execution log from the case work directory."""
        case_work_dir = report_json.get("case_work_dir", "")
        if not case_work_dir:
            return ""
        log_path = Path(str(case_work_dir)) / "reports" / "job_log.jsonl"
        if not log_path.exists():
            return ""
        try:
            entries = []
            with open(log_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
            if not entries:
                return ""
            lines = [
                "## Job Execution Log",
                "",
                f"**{len(entries)} log entries** from the live execution window.",
                "",
                "| Time | Message |",
                "|------|---------|",
            ]
            for entry in entries:
                ts = entry.get("time", "")
                msg = entry.get("msg", "")
                msg = msg.replace("|", "\\|")
                lines.append(f"| {ts} | {msg} |")
            lines.append("")
            return "\\n".join(lines)
        except Exception:
            return ""

    def _render_failed_steps(self, report_json: dict) -> str:'''

if old in content:
    content = content.replace(old, new)
    with open(f, "w") as fh:
        fh.write(content)
    print("_render_job_log method added")
else:
    print("NOT FOUND")
