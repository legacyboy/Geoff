# Bug Hunting Team - Multi-Agent Setup

## Team Members

### 1. fabht-researcher-1 (qwen3-coder-next:cloud)
- Host: Runs on OpenClaw host
- Target: fabht VM via SSH (localhost:2223)
- Specialty: JIT/compiler bugs, V8 TurboFan
- Schedule: Every 30 minutes
- Findings: ~/chromium/findings/agent1/

### 2. fabht-researcher-2 (glm-5.1:cloud)
- Host: Runs on OpenClaw host
- Target: fabht VM via SSH (localhost:2223)
- Specialty: GC/sandbox bugs, verification
- Schedule: Every 30 minutes
- Findings: ~/chromium/findings/agent2/

### 3. Claude Code (Claude-4.6 Sonnet)
- Location: /home/claw/.openclaw/workspace/bug-hunting-team/
- Access: SSH to fabht VM
- Specialty: Deep analysis, complex chains, exploit dev
- Usage: Interactive sessions for deep dives

## Targets
1. **Chromium/V8** - ~/chromium/src (29GB)
2. **Firefox/SpiderMonkey** - ~/firefox/mozilla-central (downloading)

## Workflow
1. fabht agents hunt continuously (30min cycles)
2. Promising findings → Claude does deep analysis
3. Claude develops PoCs and exploit chains
4. All findings cross-verified before submission

## Claude Code Usage

```bash
# Set API key
export ANTHROPIC_API_KEY=$(cat ~/.config/claude/api_key)

# Start Claude for bug hunting
cd ~/chromium/src && claude --model sonnet

# Or with specific task
cd ~/chromium/src && claude --model sonnet "Analyze src/compiler/turbofan/ for type confusion bugs"

# Opus for maximum analysis power
cd ~/chromium/src && claude --model opus "Deep analysis of V8 JIT compilation pipeline"
```

## HackerOne Integration

**Client:** `hackerone_rest_client.py`

**Setup:**
```bash
python3 hackerone_rest_client.py setup
# Enter your username and API token from https://hackerone.com/settings/api_token
```

**Commands:**
```bash
# List your accessible programs
python3 hackerone_rest_client.py programs

# Get program scope
python3 hackerone_rest_client.py scope google

# List your reports
python3 hackerone_rest_client.py reports

# Show popular targets
python3 hackerone_rest_client.py targets
```

**Submission Workflow:**
```python
from hackerone_rest_client import HackerOneClient, VulnerabilityReporter

client = HackerOneClient()
reporter = VulnerabilityReporter(client)

# Format report
report = reporter.format_chrome_vrp_report(
    bug_type="Type Confusion",
    affected_component="V8 TurboFan JIT",
    description="...",
    root_cause="...",
    poc="...",
    impact="RCE via crafted JavaScript"
)

# Submit to Chrome VRP
result = reporter.submit_to_chrome("V8 Type Confusion in TurboFan", report, severity="high")
```

## Top Bug Bounty Targets

| Program | Scope | Max Bounty |
|---------|-------|------------|
| **Chrome VRP** | Chrome, V8, PDF | $250,000 |
| **Google VRP** | All Google products | $151,515 |
| **Mozilla** | Firefox, SpiderMonkey | $10,000 |
| **Internet Bug Bounty** | Core infrastructure | Varies |

## Current Status
- ✅ Chromium source: 29GB downloaded
- ⏳ Firefox source: In progress
- ✅ Claude Code: Installed v2.1.96
- ✅ fabht agents: Running every 30 min
- ⏳ HackerOne API: Configured (needs token verification)
