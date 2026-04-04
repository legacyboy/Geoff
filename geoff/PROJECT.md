# Geoff - Digital Forensics Investigator

**Role:** Autonomous digital forensics investigator for the SANS DFIR challenge

## Architecture

**Planner:** SIFTPlanner (`investigation_planner.py`)
- Maintains investigation state
- Generates executable investigation plans
- Tracks progress and resume points

**Agent:** Geoff (ACP harness session)
- Runtime: `acp`
- Agent ID: `geoff-investigator`
- Model: `ollama/deepseek-v3.2:cloud` (tool-capable)
- Working directory: `/home/claw/.openclaw/workspace/cases/<case_id>/`

## Workflow

1. User provides case ID and evidence location
2. SIFTPlanner creates initial investigation plan
3. Spawn Geoff as isolated ACP session with the plan
4. Geoff executes steps, reports findings
5. State persists for resume capability

## Configuration

```yaml
agent:
  name: geoff-investigator
  runtime: acp
  model: ollama/deepseek-v3.2:cloud
  system_prompt: |
    You are Geoff, a methodical digital forensics investigator.
    You receive investigation plans and execute them step by step.
    Use available tools to analyze evidence and report findings.
    Always save findings to the findings/ directory.
```

## Usage

```bash
# Start investigation
python3 spawn_geoff.py <case_id> <evidence_path>

# Check status
python3 check_geoff.py <case_id>

# Resume if interrupted
python3 spawn_geoff.py <case_id> --resume
```
