#!/usr/bin/env python3
"""Add job log route to geoff_routes.py"""
import re

f = "/home/sansforensics/Geoff/src/geoff_routes.py"
with open(f) as fh:
    content = fh.read()

old = """return jsonify({'error': 'Unable to read report'}), 500


def graph_viewer():"""

new = """return jsonify({'error': 'Unable to read report'}), 500


def get_case_job_log(case_name):
    \"\"\"GET /cases/<case_name>/log — Return the job execution log for a completed Find Evil case.\"\"\"
    safe_name = re.sub(r'[^a-zA-Z0-9_\\-]', '_', case_name)
    if not safe_name:
        return jsonify({'error': 'Invalid case name'}), 400
    cases_root = Path(CASES_WORK_DIR)
    log_path = None
    if cases_root.exists():
        pattern = re.compile(r'^' + re.escape(safe_name) + r'(_findevil_|$)')
        for candidate in sorted(cases_root.iterdir(), reverse=True):
            if candidate.is_dir() and pattern.match(re.sub(r"[^a-zA-Z0-9_\\-]", "", candidate.name)):
                candidate_log = candidate / "reports" / "job_log.jsonl"
                if candidate_log.exists():
                    log_path = candidate_log
                    break
    if not log_path:
        return jsonify({'error': 'Job log not found'}), 404
    try:
        entries = []
        with open(log_path) as lf:
            for line in lf:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return jsonify({'job_log': entries, 'count': len(entries)})
    except Exception as e:
        _log_error("Failed to read job log", e)
        return jsonify({'error': 'Unable to read job log'}), 500


def graph_viewer():"""

if old in content:
    content = content.replace(old, new)
    with open(f, "w") as fh:
        fh.write(content)
    print("Job log route added successfully")
else:
    print("NOT FOUND - checking exact match...")
    m = re.search(r"return jsonify\(\{'error': 'Unable to read report'\}\), 500\n\ndef graph_viewer\(\):", content)
    if m:
        print(f"Found at {m.start()}")
        print(repr(m.group(0)))
    else:
        print("Could not find anchor")
