#!/usr/bin/env python3
"""Fix newline escape in geoff_pipeline.py"""
f = "/home/sansforensics/Geoff/src/geoff_pipeline.py"
with open(f) as fh:
    content = fh.read()

old = 'jlf.write(json.dumps(_entry, default=str) + "\n")'
new = 'jlf.write(json.dumps(_entry, default=str) + "\\n")'

if old in content:
    content = content.replace(old, new)
    with open(f, "w") as fh:
        fh.write(content)
    print("Fixed newline escape")
else:
    print("NOT FOUND")
    import re
    m = re.search(r'jlf\.write.*json\.dumps.*_entry', content)
    if m:
        print(repr(m.group(0)))
