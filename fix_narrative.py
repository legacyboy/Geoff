with open('/home/sansforensics/Geoff/src/geoff_integrated.py', 'r') as f:
    content = f.read()

old = "                viewer.innerHTML = graphBtn + _renderReportHtml(report, title || caseDir);"
new = """                const narrativeLink = '/cases/' + encodeURIComponent(caseDir) + '/report';
                const narrativeBtn = '<a href="' + narrativeLink + '" target="_blank" style="margin-bottom:12px;margin-left:8px;padding:6px 14px;background:rgba(34,197,94,0.15);border:1px solid #22c55e;border-radius:4px;color:#4ade80;cursor:pointer;font-size:12px;text-decoration:none;display:inline-block;">📄 View Narrative Report</a>';
                viewer.innerHTML = graphBtn + narrativeBtn + _renderReportHtml(report, title || caseDir);"""

if old in content:
    content = content.replace(old, new)
    with open('/home/sansforensics/Geoff/src/geoff_integrated.py', 'w') as f:
        f.write(content)
    print('Narrative report link added')
else:
    print('Could not find target line')
    idx = content.find('viewer.innerHTML = graphBtn')
    if idx >= 0:
        print(repr(content[idx-50:idx+200]))
