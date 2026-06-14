#!/usr/bin/env python3
"""Add job log section to narrative report markdown renderer"""
f = "/home/sansforensics/Geoff/src/narrative_report.py"
with open(f) as fh:
    content = fh.read()

old = """{sections.get('unprocessed_files', '')}

## Conclusion & Recommendations"""

new = """{sections.get('unprocessed_files', '')}

## Job Execution Log

{sections.get('job_log', 'No job log available.')}

## Conclusion & Recommendations"""

if old in content:
    content = content.replace(old, new)
    with open(f, "w") as fh:
        fh.write(content)
    print("Job log section added to markdown renderer")
else:
    print("NOT FOUND")
