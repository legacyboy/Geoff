#!/usr/bin/env python3
"""Add job log route registration to geoff_routes.py"""
f = "/home/sansforensics/Geoff/src/geoff_routes.py"
with open(f) as fh:
    content = fh.read()

old = "app.add_url_rule('/cases/<case_name>/report', 'get_case_report', _require_auth(get_case_report))"
new = "app.add_url_rule('/cases/<case_name>/report', 'get_case_report', _require_auth(get_case_report))\n    app.add_url_rule('/cases/<case_name>/log', 'get_case_job_log', _require_auth(get_case_job_log))"

if old in content:
    content = content.replace(old, new)
    with open(f, "w") as fh:
        fh.write(content)
    print("Route registration added")
else:
    print("NOT FOUND")
