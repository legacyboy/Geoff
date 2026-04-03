# Investigation Planner - Resume from State

## Purpose
Resume forensic investigation workflow from saved state.

## State Persistence
- JSON state file: `investigation_{id}_state.json`
- Auto-loads on initialization
- Resumes from last completed step
- Commits each step to git

## Workflow Steps
1. autopsy → parse_mft → verify_hash → carve_deleted → generate_timeline → export_report

## Resume Logic
```python
# Automatic on planner creation
planner = InvestigationPlanner(investigation_id)  # loads existing state

# Resume remaining steps
planner.run_all()  # continues from saved position
```

## State Format
```json
{
  "investigation_id": "3EB03F77A9E6E641FCD2FE",
  "current_step": 3,  // resumed position
  "steps": [
    {"index": 0, "status": "completed"},
    {"index": 1, "status": "completed"},
    {"index": 2, "status": "completed"},
    {"index": 3, "status": "current"},  // resumed here
    // ... remaining steps
  ]
}
```

## Key Points
- Each step commits: `git commit -m "[3EB03F77A9E6E641FCD2FE] Step N: action"`
- Resume on crash: reload state, continue from last completed
