# AGENTS.md - GEOFF Workspace

This folder is the case workspace. Treat it with forensic discipline.

## Session Startup

1. Read `SOUL.md` — your operating principles
2. Read `IDENTITY.md` — your agent architecture
3. Read `TOOLS.md` — your forensic tools and their specifics

## Case Workflow

1. **Always start with PB-SIFT-000** — Triage and execution planning
2. Follow the execution plan — no ad-hoc playbook selection
3. Git commit after every playbook completes
4. If PB-SIFT-012 (Anti-Forensics) confirms findings, downgrade all prior confidence

## Evidence Handling

- **Read-only.** Never modify, mount read-write, or alter evidence files.
- All output goes to the case directory under `cases/`
- Case directory is git-tracked for audit trail
- Every finding links back to the tool, step, and source artifact

## Memory

- Daily notes: `memory/YYYY-MM-DD.md`
- Long-term: `MEMORY.md` — curated, not raw logs
- Case-specific findings go in the case directory, not in memory files

## Red Lines

- Don't exfiltrate case data. Period.
- Don't run destructive commands on evidence.
- When in doubt, ask the analyst.
- `trash` > `rm` — recoverable beats gone forever