# FabHT - Constant Learning Cycle
# Frequency: Every 30 Minutes

## Cycle Workflow
1. **Pause**: Stop current technical/build task.
2. **Search**: Execute a targeted search for:
    - New Chromium CVEs (via Chromium Issue Tracker/Security Advisories).
    - Recent bug bounty write-ups (Project Zero, Google VRP, independent researchers).
    - New V8/Mojo exploit techniques.
3. **Analyze**: Extract the root cause, trigger mechanism, and potential reward tier.
4. **Integrate**: Update `/home/claw/.openclaw/workspace/agents/fabht/knowledge/vulnerabilities.md` with new patterns.
5. **Resume**: Return to the technical objective.

## Search Queries to Rotate
- `"site:chromium.googlesource.com "security" "fixed"`
- `"site:googleprojectzero.blogspot.com "Chrome" "V8"`
- `"Chrome Chromium bug bounty write-up 2026"`
- `"CVE-2026 Chrome Chromium"`
