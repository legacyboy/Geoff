# GEOFF — Architecture

**Git-backed Evidence Operations Forensic Framework** — a multi-agent DFIR platform that
plans, executes, validates, and self-corrects an entire forensic investigation autonomously,
with every step git-committed for chain of custody.

![GEOFF architecture diagram](architecture.svg)

High-resolution exports: [`architecture.svg`](architecture.svg) (vector, print-ready) ·
[`architecture.png`](architecture.png) (2580 px raster).

---

## How the components connect

```mermaid
flowchart TB
    AN(["Analyst"]) --> IF
    MC(["MCP clients<br/>Claude Desktop · Claude Code"]) --> MCPS

    subgraph IF["Interfaces"]
        direction LR
        CLI["CLI<br/>bin/geoff-find-evil"]
        WEB["Web UI<br/>Flask :8080"]
        API["HTTP API<br/>POST /find-evil"]
        MCPS["MCP Server :9999 / stdio<br/>geoff_mcp_server.py · 17 tools"]
    end

    subgraph EV["Evidence sources (read-only)"]
        E1["Disk images · memory dumps · PCAPs<br/>registry hives · event logs<br/>mobile backups · browser DBs · email"]
    end

    subgraph TRIAD["Geoff Triad — autonomous agent loop (src/geoff_pipeline.py::find_evil)"]
        TR["Preflight &amp; Triage<br/>PB-SIFT-000"]
        MGR["MANAGER<br/>plans · gates · approve / flag / replay"]
        FOR["FORENSICATOR<br/>runs steps · analyst notes + evidence chain"]
        CRIT["DUAL CRITIC + BATCH CRITIC<br/>2 models · confidence VERY_HIGH→LOW"]
        HEAL["HEALER<br/>HealDecision · patched params"]
    end

    subgraph SIFT["SIFT tool layer — 53+ playbooks · 20+ specialist modules"]
        PB["Playbooks PB-SIFT-000…104 (MITRE ATT&amp;CK-mapped)"]
        TOOLS["SleuthKit · Volatility 3 · Plaso · RegRipper · Zimmerman<br/>tshark · YARA · REMnux · PhotoRec · iLEAPP/ALEAPP<br/>browser · email · VSS · stego · hash"]
    end

    OLL["LLM backend<br/>Ollama :11434 · profiles.json (cloud ⇄ local)"]
    NSRL["NSRL hash API<br/>hash.nsrl.nist.gov"]

    subgraph OUT["Output pipeline"]
        CUST["Per-step custody<br/>git commits · custody/*.json · findings.jsonl"]
        ENR["Behavioral Analyzer · Super Timeline · Host Correlator · IP map"]
        PROV["ProvenanceDAG + confidence calibration"]
        NARR["Narrative report generator (Manager-gated)"]
    end

    ART["Case artifacts — case_work_dir/reports/<br/>find_evil_report.json · narrative_report.md/.html<br/>mitre_matrix.html · ip_map.html · audit_trail.jsonl · custody/"]

    IF -->|"1 · goal: find evil"| TR
    EV -->|"2 · inventory"| TR
    EV -->|read-only| SIFT
    TR -->|proposed plan| MGR
    MGR -->|"3 · approved plan"| FOR
    FOR -->|"4 · invoke {module, function, params}"| SIFT
    SIFT -->|raw tool output| FOR
    FOR -->|findings| CRIT
    CRIT -->|"6 · assessment"| MGR
    MGR -.->|"7 · replay (patched steps)"| FOR
    CRIT -.->|failures| HEAL
    HEAL -.->|patched params| FOR
    OLL ---|LLM calls| TRIAD
    SIFT -.->|hash lookups| NSRL
    TRIAD -->|"5 · per-step custody commit"| CUST
    CUST --> ENR
    ENR -->|"8"| PROV
    PROV --> NARR
    MGR -->|approve gate| NARR
    NARR -->|"9 · write"| ART
    ART -->|served back| IF
```

## Execution flow

1. **Submit** — the analyst hands Geoff a goal ("find evil in this evidence") via CLI, Web UI, HTTP API, or MCP.
2. **Triage** — preflight inventories evidence (SHA-256 manifest, device discovery) and runs PB-SIFT-000 to propose an execution plan.
3. **Plan** — the **Manager** reviews, reorders, and approves the plan.
4. **Execute** — the **Forensicator** runs every playbook step, invoking SIFT specialist modules and turning raw tool output into structured analyst notes with evidence chains.
5. **Custody** — each completed step is git-committed with a `custody/<step>.json` SHA-256 sidecar and streamed to `findings.jsonl` before the pipeline advances.
6. **Validate** — the **Dual Critic Pool** (two independent models) checks every finding for hallucinations; a **Batch Critic** then reviews all findings holistically. Agreement drives the confidence grade (VERY_HIGH → LOW).
7. **Decide** — the **Manager** approves, flags, or orders an incremental replay of affected steps with patched parameters. Failed tool runs are diagnosed by the **Healer** (deterministic fix first, LLM `HealDecision` second).
8. **Enrich** — Behavioral Analyzer, Super Timeline, Host Correlator, and ProvenanceDAG add cross-device correlation, lineage, and calibrated confidence.
9. **Report** — the Manager-gated narrative generator writes the MITRE-mapped report; all artifacts are served back through the Web UI, HTTP API, and MCP tools.

## Component reference

| Component | Role | Key files |
|---|---|---|
| Pipeline entry | Orchestrates the whole investigation | `src/geoff_pipeline.py::find_evil()` |
| Manager | Plan approval, post-critic decision (approve/flag/replay) | `src/geoff_self_heal.py::_manager_review_execution_plan`, `src/geoff_pipeline.py::_manager_post_critic_decision` |
| Forensicator | Tool execution + structured analyst notes | `src/geoff_forensicator.py::call_forensicator_llm` |
| Critics | Per-step dual validation + holistic batch review | `src/geoff_critic.py`, `src/geoff_gaps_novel.py::GeoffCriticPool`, `src/geoff_pipeline.py::_batch_critic_review_all_playbooks` |
| Healer | Error diagnosis and recovery (`HealDecision`) | `src/geoff_self_heal.py::_attempt_heal` |
| SIFT specialists | 20+ tool wrapper modules (disk, memory, timeline, registry, network, malware, mobile, …) | `src/sift_specialists*.py` |
| Playbooks | 53+ MITRE-mapped step definitions | `playbooks/PB-SIFT-*.md` |
| LLM backend | Ollama, cloud ⇄ local model profiles | `src/geoff_llm_client.py`, `profiles.json` |
| MCP server | 17 tools (`start_find_evil`, `chat`, `*_analyze`, reports) on 127.0.0.1:9999 or stdio | `src/geoff_mcp_server.py` |
| Web UI / API | Flask app on :8080 | `src/geoff_integrated.py`, `src/geoff_routes.py` |
| Custody & audit | Per-step git commits, SHA-256 sidecars, audit trail | `src/geoff_pipeline.py::_commit_step_with_custody` |
| Enrichment | Behavior, timeline, correlation, provenance | `src/behavioral_analyzer.py`, `src/super_timeline.py`, `src/host_correlator.py`, `src/geoff_gaps_novel.py::ProvenanceDAG` |
| Narrative reports | Manager-gated MD/HTML report generation | `src/narrative_report.py` |
| External service | NSRL known-file hash elimination | `src/geoff_gaps_novel.py::HASH_Specialist` |

## Design guarantees

- **Chain of custody** — every step is git-committed with a SHA-256 sidecar before the pipeline advances.
- **Hallucination defense** — two independent critic models must agree; disagreement lowers confidence.
- **Self-healing** — deterministic fixes first, LLM-diagnosed `HealDecision` second, targeted replay last.
- **Evidence safety** — sources are processed read-only with a SHA-256 manifest taken at intake.
- **Reproducibility** — `audit_trail.jsonl` and the ProvenanceDAG trace every finding back to its source artifact.
