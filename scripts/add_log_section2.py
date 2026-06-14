#!/usr/bin/env python3
"""Add job log section generation to narrative_report.py"""
f = "/home/sansforensics/Geoff/src/narrative_report.py"
with open(f) as fh:
    content = fh.read()

old = """        # 11b. Unprocessed Evidence Files
        sections["unprocessed_files"] = self._render_unprocessed_section(report_json)

        # 12. Conclusion & Recommendations"""

new = """        # 11b. Unprocessed Evidence Files
        sections["unprocessed_files"] = self._render_unprocessed_section(report_json)

        # 11c. Job Execution Log
        sections["job_log"] = self._render_job_log(report_json)

        # 12. Conclusion & Recommendations"""

if old in content:
    content = content.replace(old, new)
    with open(f, "w") as fh:
        fh.write(content)
    print("Job log section generation added")
else:
    print("NOT FOUND")
