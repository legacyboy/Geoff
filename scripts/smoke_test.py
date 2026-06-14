#!/usr/bin/env python3
"""Geoff post-deployment smoke test. Run after any code changes."""
import re, urllib.request, json, sys

HOST = "http://localhost:8080"
errors = []

def check(label, condition, detail=""):
    if condition:
        print(f"  ✅ {label}")
    else:
        msg = f"❌ {label}"
        if detail:
            msg += f": {detail}"
        print(msg)
        errors.append(msg)

print("=== Geoff Post-Deployment Smoke Test ===\n")

# 1. Health endpoint
try:
    resp = urllib.request.urlopen(f"{HOST}/health")
    check("Health endpoint returns 200", resp.status == 200)
except Exception as e:
    check("Health endpoint", False, str(e))

# 2. HTML loads and has key elements
try:
    resp = urllib.request.urlopen(HOST)
    html = resp.read().decode("utf-8")
    
    # Check key functions exist
    check("switchTab function defined", "function switchTab" in html)
    check("loadReports function defined", "function loadReports" in html)
    check("loadEvidence function defined", "function loadEvidence" in html)
    check("viewReport function defined", "function viewReport" in html)
    check("authFetch function defined", "function authFetch" in html)
    
    # Check tab onclick handlers pass 'this'
    check("FindEvil tab handler passes this", "switchTab('findevil', this)" in html)
    check("Evidence tab handler passes this", "switchTab('evidence', this)" in html)
    check("Reports tab handler passes this", "switchTab('reports', this)" in html)
    
    # Check JS parsing (basic brace/paren match)
    js_match = re.search(r"<script>(.*?)</script>", html, re.DOTALL)
    if js_match:
        js = js_match.group(1)
        braces = (js.count("{"), js.count("}"))
        parens = (js.count("("), js.count(")"))
        brackets = (js.count("["), js.count("]"))
        check(f"JS braces match ({braces[0]}/{braces[1]})", braces[0] == braces[1])
        check(f"JS parens match ({parens[0]}/{parens[1]})", parens[0] == parens[1])
        check(f"JS brackets match ({brackets[0]}/{brackets[1]})", brackets[0] == brackets[1])
    else:
        check("Script tag found", False)
except Exception as e:
    check("HTML page loads", False, str(e))

# 3. Reports API
try:
    resp = urllib.request.urlopen(f"{HOST}/reports")
    data = json.loads(resp.read())
    reports = data.get("reports", [])
    check(f"Reports API: {len(reports)} reports", len(reports) > 0)
    if reports:
        first = reports[0]
        check("Report has dir", "dir" in first)
        check("Report has severity", "severity" in first)
        check("Report has evil_found", "evil_found" in first)
except Exception as e:
    check("Reports API", False, str(e))

# 4. MITRE matrix endpoint
try:
    resp = urllib.request.urlopen(f"{HOST}/reports/mitre-matrix")
    check("MITRE matrix endpoint", resp.status == 200)
except Exception as e:
    check("MITRE matrix endpoint", False, str(e))

# 5. Report JSON endpoint (first available case)
if reports:
    case_dir = reports[0]["dir"]
    try:
        resp = urllib.request.urlopen(f"{HOST}/reports/{case_dir}/json")
        report = json.loads(resp.read())
        check(f"Report JSON for {case_dir}", resp.status == 200)
        check("Report has severity", "severity" in report)
        check("Report has evidence_inventory", "evidence_inventory" in report)
        check("Report has device_map", "device_map" in report)
    except Exception as e:
        check("Report JSON endpoint", False, str(e))

# Summary
print(f"\n{'='*40}")
print(f"Results: {len(errors)} failures, ", end="")
print(f"{13 - len(errors)}/{13} checks passed" if not errors else "some checks failed")
if errors:
    print("\nFailures:")
    for e in errors:
        print(f"  {e}")
    sys.exit(1)
else:
    print("All checks passed! ✅")
