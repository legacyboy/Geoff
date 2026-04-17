# Geoff DFIR Framework — Validation Report
**Date:** 2026-04-16 03:00 CDT  
**Method:** 6 validation passes across 3 reviewers (qwen3-coder, glm-5.1, manual verification)  
**Commit:** baee566

---

## Pass 1: Tool Coverage (Playbook → Specialist Method Mapping)

Every module.function pair in `PLAYBOOK_STEPS` maps to a real specialist method that exists and is callable. ✅

**Gap found:**

| ID | Gap | Severity |
|----|-----|----------|
| TC-1 | `sleuthkit.list_deleted` is used in PB-SIFT-010 but NOT listed in `SLEUTHKIT_Specialist.get_available_tools()` response (which only lists: analyze_partition_table, analyze_filesystem, list_files, list_files_mactime, extract_file, list_inodes, get_file_info). Method exists but API reporting is incomplete. | LOW |
| TC-2 | `sleuthkit.list_deleted` and `sleuthkit.analyze_filesystem` used in playbooks but `list_deleted` is missing from `ExtendedOrchestrator.get_available_tools()` sleuthkit functions list | LOW |

---

## Pass 2: Playbook Step Integrity

### PB-SIFT-020 — Missing Playbook Markdown File

| ID | Gap | Severity |
|----|-----|----------|
| PS-1 | `PB-SIFT-020` ("Timeline Analysis") exists in `PLAYBOOK_STEPS` and `PLAYBOOK_NAMES` code but has NO corresponding playbook markdown file in `playbooks/`. All other PB-SIFT-000 through PB-SIFT-019 have markdown files. `PLAYBOOK_INDEX.md` also does not list PB-SIFT-020. | **HIGH** |

### Playbook Step Definitions — Completeness Check

Each step in `PLAYBOOK_STEPS` has: module, function, params. Steps in the markdown playbooks describe *what to look for* in natural language — they're guidance docs for the LLM, not step definitions. The `PLAYBOOK_STEPS` dict is the actual executable mapping.

| ID | Gap | Severity |
|----|-----|----------|
| PS-2 | PB-SIFT-000 (Triage) only has `memory_dumps` steps. No disk image, pcap, evtx, or registry triage despite these evidence types being inventoried. The triage playbook should scan all evidence types for initial indicators. | MEDIUM |
| PS-3 | PB-SIFT-004 (Privilege Escalation) references `registry.extract_autoruns` but autoruns are a persistence indicator, not privilege escalation. Minor mismatch. | LOW |
| PS-4 | PB-SIFT-016 (Cross-Image Correlation) only has `disk_images` steps with plaso timeline creation. No actual correlation logic in the steps — correlation is left entirely to the LLM analysis phase. | MEDIUM |

---

## Pass 3: Cross-Reference Consistency

| ID | Gap | Severity |
|----|-----|----------|
| CR-1 | PB-SIFT-000's triage indicator scanning (`_scan_triage_indicators`) can add PB-SIFT-020 to the execution plan, but PB-SIFT-020 has no playbook markdown doc. The LLM won't have guidance for what Timeline Analysis should look for. | **HIGH** |
| CR-2 | PB-SIFT-012 (Anti-Forensics) mentions a "confidence downgrade directive" but its PLAYBOOK_STEPS entry has no special flag or handler. The actual downgrade logic is inline in `find_evil()` (lines ~2268-2303), not declarative in the playbook definition. | LOW |
| CR-3 | PB-SIFT-017 and PB-SIFT-018 are conditionally included (suspicious binary surfaced during triage), but the condition check is in the triage code, not in the playbook markdown or PLAYBOOK_INDEX.md documentation. | LOW |
| CR-4 | PLAYBOOK_INDEX.md says "Location: `/opt/geoff/playbooks/`" but actual location is project-relative `playbooks/`. No `/opt/geoff/` directory exists. | LOW |

---

## Pass 4: Specialist Method Coverage

### Orphan Methods (exist in specialists but no playbook uses them)

| ID | Method | Specialist | Severity |
|----|--------|------------|----------|
| MC-1 | `extract_file()` | SLEUTHKIT_Specialist | LOW |
| MC-2 | `list_inodes()` | SLEUTHKIT_Specialist | LOW |
| MC-3 | `get_file_info()` | SLEUTHKIT_Specialist | LOW |
| MC-4 | `scan_registry()` | VOLATILITY_Specialist | LOW |
| MC-5 | `dump_process()` | VOLATILITY_Specialist | LOW |
| MC-6 | `extract_user_assist()` | REGISTRY_Specialist | MEDIUM |
| MC-7 | `extract_shellbags()` | REGISTRY_Specialist | MEDIUM |
| MC-8 | `extract_mounted_devices()` | REGISTRY_Specialist | MEDIUM |
| MC-9 | `extract_usb_devices()` | REGISTRY_Specialist | MEDIUM |
| MC-10 | `scan_all_hives()` | REGISTRY_Specialist | MEDIUM |
| MC-11 | `sort_timeline()` | PLASO_Specialist | LOW |
| MC-12 | `analyze_storage()` | PLASO_Specialist | LOW |
| MC-13 | `extract_flows()` | NETWORK_Specialist | LOW (only used in PB-SIFT-006 and PB-SIFT-019) |
| MC-14 | `analyze_ios_backup()` | MOBILE_Specialist | MEDIUM |
| MC-15 | `analyze_android()` | MOBILE_Specialist | MEDIUM |
| MC-16 | `parse_syslog()` | LOGS_Specialist | LOW |
| MC-17 | All REMnux methods except die_scan, clamav_scan, floss_strings, exiftool_scan (which are in PB-SIFT-017) | REMNUX | LOW |

### Methods Referenced in Playbooks but Not in Specialist

| ID | Gap | Severity |
|----|-----|----------|
| MC-18 | No gaps found — all PLAYBOOK_STEPS module.function pairs resolve to existing methods | — |

---

## Pass 5: Error Handling & Edge Cases

| ID | Gap | Severity |
|----|-----|----------|
| EH-1 | `device_map`, `user_map`, `correlated_users`, `all_behavioral_flags` use `dir()` checks (`'variable' in dir()`) instead of proper None/default initialization. If a try block above fails, these variables may be unbound, causing `NameError` in report construction. `None` would also pass the `dir()` check but propagate incorrectly. | **HIGH** |
| EH-2 | `FindingsWriter.all_records()` only returns in-memory records (capped at 50,000). If the cap is exceeded, findings beyond 50k are written to JSONL on disk but NOT included in the report or passed to `HostCorrelator.correlate()`. | **HIGH** |
| EH-3 | `NarrativeReportGenerator.generate()` receives `super_timeline_path` as a string, but `SuperTimeline.build()` returns `(path, events)`. If timeline build fails and returns `(None, [])`, the generator may crash trying to read a None path. | MEDIUM |
| EH-4 | No crash recovery: `find_evil()` writes `device_map.json` and `user_map.json` to case dir but on restart only reads JSONL findings — doesn't reload device_map/user_map from disk. | MEDIUM |
| EH-5 | `ForensicatorAgent._execute_command()` trusts LLM-parsed tool names. While `subprocess.run()` with a list avoids shell injection, `tool: "bash"` with `args: ["-c", "malicious"]` would execute arbitrary commands. | **HIGH** |

---

## Pass 6: Configuration & Integration

| ID | Gap | Severity |
|----|-----|----------|
| CI-1 | **HTML_TEMPLATE Unicode escape warning**: JavaScript Unicode escapes (`\u2014`, `\u2139`, `\ufe0f`, `\u25b2`, `\u2026`) and regex escapes (`\d+`) inside a non-raw Python triple-quoted string trigger `SyntaxWarning: invalid escape sequence '\*'` at runtime on Python 3.12. Works but produces warnings on every import. | LOW |
| CI-2 | **Hardcoded path**: `chat()` endpoint spawns `/home/sansforensics/geoff_worker.py` via `subprocess.Popen`. This file doesn't exist at that path (it's at `src/geoff_worker.py` in the project). Dead code path. | **CRITICAL** |
| CI-3 | **Hardcoded path**: `geoff_investigation_worker.py` hardcodes `CASES_WORK_DIR` and `EVIDENCE_BASE_DIR` to `/home/sansforensics/evidence-storage/` without `_resolve_dir()` fallback. | **HIGH** |
| CI-4 | **Hardcoded path**: `geoff_worker.py` hardcodes same paths without fallback. | **HIGH** |
| CI-5 | **Hardcoded path**: `geoff_critic.py::commit_validation()` defaults `base_path` to `/home/claw/.openclaw/workspace/geoff-private` — developer-specific. | MEDIUM |
| CI-6 | **Dead code**: `ForensicatorAgent.execute_task()` is called from the `chat()` endpoint's tool detection path (line ~3591), but this code path is dead since `geoff_worker.py` is the one that would invoke it via the old worker. The find-evil pipeline uses `ExtendedOrchestrator` exclusively. | MEDIUM |
| CI-7 | **Dead code**: `geoff_worker.py` and `geoff_investigation_worker.py` are entirely superseded by `find_evil()` in `geoff_integrated.py`. Both contain YARA references (removed from framework), use different device discovery, and bypass behavioral analysis/timeline modules. | **HIGH** |
| CI-8 | **`/investigation/status/<case>` endpoint** references old `InvestigationWorker` — incompatible status file format with current `find_evil()` pipeline. | **HIGH** |
| CI-9 | **`/run-tool` endpoint** bypasses Critic validation entirely — direct tool execution skips the Manager→Forensicator→Critic pipeline. | MEDIUM |
| CI-10 | **`geoff_critic.py`** defaults model to `"qwen3-coder-next:cloud"` instead of using `AGENT_MODELS["critic"]`. | LOW |
| CI-11 | **`CASES_WORK_DIR`** defaults to `/home/sansforensics/evidence-storage/cases` which was not writable on the SIFT VM. Geoff fell back to `/tmp/geoff-cases` silently. | LOW |

---

## Security Findings (from architect review)

| ID | Gap | Severity |
|----|-----|----------|
| SEC-1 | Path traversal: `_validate_evidence_path()` blocks shell metacharacters but doesn't prevent traversal like `../../../etc/passwd`. `_sanitize_path()` exists but isn't called by `_validate_evidence_path()`. An absolute path like `/etc/passwd` (no metacharacters) would pass validation. | **HIGH** |
| SEC-2 | No rate limiting on API endpoints. `/find-evil` spawns threads + runs forensic tools — burst requests could exhaust resources. | MEDIUM |
| SEC-3 | `/chat` endpoint processes arbitrary user messages through `detect_tool_request()` which can trigger tool execution. Combined with Forensicator's LLM-trusted command generation, this creates indirect attack surface. | MEDIUM |
| SEC-4 | API auth disabled when `GEOFF_API_KEY` env var is unset (backwards compatibility for local use). | LOW |

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 8 |
| MEDIUM | 11 |
| LOW | 12 |

### Top Priority (CRITICAL + HIGH)

1. **CI-2** (CRITICAL): Hardcoded `/home/sansforensics/geoff_worker.py` subprocess path — dead code, will fail at runtime
2. **CI-7** (HIGH): `geoff_worker.py` and `geoff_investigation_worker.py` are dead code with YARA references and bypass the current pipeline
3. **CI-8** (HIGH): `/investigation/status/<case>` uses old worker, incompatible with find_evil()
4. **EH-1** (HIGH): Fragile `dir()` checks for device_map/user_map/correlated_users — can cause NameError
5. **EH-2** (HIGH): FindingsWriter 50k cap means large investigations lose findings from reports
6. **EH-5** (HIGH): Forensicator LLM-trusted command generation can execute arbitrary commands
7. **SEC-1** (HIGH): Path traversal vulnerability in evidence path validation
8. **CI-3/CI-4** (HIGH): Hardcoded paths in old workers without fallback
9. **PS-1/CR-1** (HIGH): PB-SIFT-020 has no playbook markdown file