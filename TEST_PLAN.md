# G.E.O.F.F. Test Plan

**Version:** 0.1  
**Last Updated:** 2026-04-13  
**Status:** Draft  

---

## Overview

This document defines the test strategy for the G.E.O.F.F. (Git-backed Evidence Operations Forensic Framework) platform. It covers five test categories aligned with the system's core capabilities:

1. **Find Evil** — End-to-end autonomous triage pipeline
2. **Q&A** — Conversational LLM-driven forensic chat
3. **Playbook** — PB-SIFT investigation protocol execution
4. **Web UI** — Browser-based interface (chat, evidence, tools, find-evil)
5. **Install** — One-command installer and service lifecycle

Each section includes test cases, expected results, and acceptance criteria. Tests assume a clean environment unless otherwise noted.

---

## Test Environment Requirements

### Minimum Hardware
- 8 GB RAM (16 GB recommended for memory dump analysis)
- 20 GB free disk space
- x86-64 architecture

### Software Dependencies
- Ubuntu 22.04+ or Debian 12+ (primary); macOS 14+ (secondary)
- Python 3.10+
- Node.js 22.x
- Ollama v0.6.5+ with `gemma3:4b` model pulled
- SleuthKit, Volatility 3, YARA, Plaso (for specialist tool tests)

### Test Evidence
| Artifact | Purpose | Size |
|----------|---------|------|
| `test.dd` (raw disk image, 50 MB) | Disk analysis tests | Small |
| `test.vmem` (memory dump, 100 MB) | Volatility tests | Medium |
| `test.pcap` (network capture) | Network analysis tests | Small |
| `test.evtx` (Windows Event Log) | Log parsing tests | Small |
| `NTUSER.DAT`, `SYSTEM` (registry hives) | Registry analysis tests | Small |
| Ransomware sim directory (`*.locked` files) | Indicator triage tests | Minimal |

### Environment Variables
```
GEOFF_EVIDENCE_DIR=/tmp/geoff-test-evidence
GEOFF_CASES_DIR=/tmp/geoff-test-cases
OLLAMA_URL=http://127.0.0.1:11434
```

---

## 1. Find Evil Tests

The `find_evil()` function is an autonomous triage-to-findings pipeline. Tests verify each phase: inventory → classification → playbook selection → specialist execution → critic validation → report generation.

### 1.1 Evidence Inventory

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| FE-001 | Empty directory | Empty evidence dir | Report with `evil_found: false`, empty inventory, `evidence_score: 0.0` | P1 |
| FE-002 | Single disk image | Evidence dir with `test.dd` | `inventory.disk_images` contains path, `has_disk: true`, `evidence_score ≥ 0.4` | P1 |
| FE-003 | Single memory dump | Evidence dir with `test.vmem` | `inventory.memory_dumps` contains path, `has_memory: true`, `evidence_score ≥ 0.3` | P1 |
| FE-004 | Mixed evidence | Dir with `.dd`, `.vmem`, `.pcap`, `.evtx`, `NTUSER.DAT` | All categories populated, `evidence_score: 1.0` | P1 |
| FE-005 | Large file size counting | Dir with files totaling >1 GB | `total_size_bytes` accurate, inventory complete | P2 |
| FE-006 | Nested subdirectories | Evidence in `subdir1/subdir2/file.raw` | `rglob` finds files in nested paths | P2 |
| FE-007 | Symlinks | Symlink to evidence file | Symlinks followed or skipped gracefully (no crash) | P3 |
| FE-008 | Permission-denied files | Evidence dir with `chmod 000` file | `OSError` caught, size=0, file still inventoried | P2 |
| FE-009 | Mixed case extensions | `Image.E01`, `dump.VMEM` | Case-insensitive detection works correctly | P2 |

### 1.2 OS Classification & Indicator Triage

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| FE-010 | Windows indicators | `windows_server.E01`, `NTUSER.DAT` | `os_type: "windows"`, registry hives detected | P1 |
| FE-011 | Linux indicators | `ubuntu_image.dd`, `syslog` | `os_type: "linux"`, syslog detected | P1 |
| FE-012 | macOS indicators | `macos_dump.raw` | `os_type: "macos"` | P2 |
| FE-013 | Mobile indicators | `Info.plist`, `Manifest.db` | `os_type: "mobile"`, mobile backups detected | P2 |
| FE-014 | Unknown OS | Generic `.dd` with no OS hints | `os_type: "unknown"`, defaults to triage-only | P2 |
| FE-015 | Ransomware indicators | Files named `*.locked`, `README_DECRYPT.txt` | `indicator_hits` includes `("ransomware", ...)` | P1 |
| FE-016 | Credential theft indicators | `mimikatz.exe`, `lsass.dmp` | `indicator_hits` includes `("credential_theft", ...)` | P1 |
| FE-017 | Lateral movement indicators | `psexec.exe`, `wmic.log` | `indicator_hits` includes `("lateral_movement", ...)` | P1 |
| FE-018 | Persistence indicators | `autorun.bat`, `scheduled_task.xml` | `indicator_hits` includes `("persistence", ...)` | P2 |
| FE-019 | Anti-forensics indicators | `wevtutil cl` in filenames | `indicator_hits` includes `("anti_forensics", ...)` | P2 |
| FE-020 | Web shell indicators | `c99.php`, `cmd=exec` in filenames | `indicator_hits` includes `("web_shell", ...)` | P2 |
| FE-021 | LOLBIN indicators | `certutil.exe`, `bitsadmin.exe` | `indicator_hits` includes `("lolbin", ...)` | P2 |
| FE-022 | Multiple indicator categories | Mix of ransomware + persistence + LOLBIN | All categories detected, severity ordering correct | P1 |
| FE-023 | No indicators present | Clean evidence with no malicious patterns | `indicator_hits: []`, triage-only playbook selected | P1 |

### 1.3 Playbook Selection Logic

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| FE-024 | Default playbook selection | Any evidence | `PB-SIFT-016` (triage) always selected first | P1 |
| FE-025 | Ransomware playbook mapping | Ransomware indicators | `PB-SIFT-002` and/or `PB-SIFT-008` in `selected_playbooks` | P1 |
| FE-026 | Disk image auto-includes PB-SIFT-001 | Disk image present | `PB-SIFT-001` (malware hunting) included | P1 |
| FE-027 | OS-specific playbook | Linux evidence | `PB-SIFT-012` included | P1 |
| FE-028 | Multi-host correlation | Multiple disk images | `PB-SIFT-017` included | P2 |
| FE-029 | Deduplication | Same playbook triggered by multiple indicators | Playbook appears once in `selected_playbooks` | P1 |
| FE-030 | Severity ordering | Mixed CRITICAL/HIGH/MEDIUM indicators | CRITICAL-ordered playbooks appear before MEDIUM ones | P2 |

### 1.4 Specialist Execution

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| FE-031 | Memory analysis steps | `.vmem` file in evidence | Volatility `process_list`, `network_scan`, `find_malware` steps executed | P1 |
| FE-032 | Disk analysis steps | `.dd` file in evidence | SleuthKit `analyze_partition_table`, `analyze_filesystem`, `list_files` executed | P1 |
| FE-033 | Registry analysis steps | `NTUSER.DAT`, `SYSTEM` in evidence | Correct registry functions called per hive name | P1 |
| FE-034 | Network analysis steps | `.pcap` in evidence | `analyze_pcap`, `extract_http`, `extract_flows` executed | P1 |
| FE-035 | Log analysis steps | `.evtx` in evidence | `parse_evtx` executed | P1 |
| FE-036 | YARA scan steps | Disk or memory in evidence | `yara.scan_file` executed, limited to 5 targets | P2 |
| FE-037 | String extraction steps | Disk image in evidence | `strings.extract_strings` executed, limited to 3 images | P2 |
| FE-038 | Timeline creation steps | Disk image in evidence | `plaso.create_timeline` executed, limited to 2 images | P2 |
| FE-039 | Step failure handling | Specialist tool not installed | Step status `"failed"` with error, pipeline continues | P1 |
| FE-040 | All specialists missing | No forensic tools installed | All steps fail gracefully, report still generated | P2 |

### 1.5 Critic Validation

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| FE-041 | Critic runs on each step | Normal find-evil run | Each step has `"critic"` field with validation result | P1 |
| FE-042 | Critic approval percentage | Mix of valid/invalid results | `critic_approval_pct` calculated correctly (approved/total × 100) | P1 |
| FE-043 | Critic error handling | LLM unavailable during critic | `critic_error` field populated, pipeline continues | P2 |

### 1.6 Report Generation

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| FE-044 | Report file creation | Any evidence dir | `find_evil_report.json` written to `case_work_dir/reports/` | P1 |
| FE-045 | Report content completeness | Full evidence set | Report contains all keys: title, inventory, classification, findings, critic_summary, severity_distribution | P1 |
| FE-046 | Git commit of report | Any run | Report committed to git with message `[FIND-EVIL] Report for {case_name}` | P1 |
| FE-047 | Severity distribution | Ransomware + LOLBIN indicators | `CRITICAL` and `MEDIUM` counts > 0 | P1 |
| FE-048 | Evil found flag | Ransomware indicators present | `evil_found: true` | P1 |
| FE-049 | No evil found | Clean evidence | `evil_found: false` | P1 |
| FE-050 | Elapsed time tracking | Any run | `elapsed_seconds` present and > 0 | P2 |
| FE-051 | Case work directory creation | Evidence dir named `incident-2024` | Case dir `{CASES_WORK_DIR}/incident-2024_findevil_{timestamp}` created | P1 |
| FE-052 | Permission error on case dir | Read-only parent directory | Falls back to `/tmp/geoff-cases/`, logs fallback message | P2 |

### 1.7 API Endpoint Tests

| ID | Test Case | Method/Endpoint | Input | Expected Result | Priority |
|----|-----------|-----------------|-------|-----------------|----------|
| FE-053 | POST /find-evil | `POST /find-evil` | `{"evidence_dir": "/valid/path"}` | 200, full report JSON | P1 |
| FE-054 | POST /find-evil missing dir | `POST /find-evil` | `{"evidence_dir": "/nonexistent"}` | 404, error JSON | P1 |
| FE-055 | POST /find-evil empty body | `POST /find-evil` | `{}` | 200, uses default `EVIDENCE_BASE_DIR` | P2 |
| FE-056 | GET /find-evil info | `GET /find-evil` | — | 200, JSON with name, description, usage, supported_evidence | P1 |

---

## 2. Q&A Tests

Tests for the `/chat` endpoint and conversational LLM interactions, including tool detection, case context, and multi-agent orchestration.

### 2.1 Basic Chat

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| QA-001 | Empty message | `{"message": ""}` | Response: "What would you like to look at?" | P1 |
| QA-002 | General greeting | `{"message": "Hello Geoff"}` | LLM responds with Geoff persona greeting | P2 |
| QA-003 | Forensic question | `{"message": "What is SleuthKit?"}` | Informative response about forensic tools | P2 |
| QA-004 | Long message | Message > 10,000 chars | Handled gracefully, truncated in context | P3 |

### 2.2 Tool Detection (`detect_tool_request`)

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| QA-005 | Partition table request | "Show me the partition table" | `detect_tool_request` returns `sleuthkit.analyze_partition_table` | P1 |
| QA-006 | Process list request | "List processes from memory dump" | Returns `volatility.process_list` | P1 |
| QA-007 | YARA scan request | "Run YARA scan on this file" | Returns `yara.scan_file` or `yara.scan_directory` | P1 |
| QA-008 | Registry autoruns request | "Check autoruns in SOFTWARE hive" | Returns `registry.extract_autoruns` | P1 |
| QA-009 | No tool detected | "Tell me about ransomware" | `detect_tool_request` returns null/empty | P1 |
| QA-010 | Ambiguous tool request | "Analyze this" | Best-effort tool match or null | P2 |

### 2.3 Case Context & Evidence Resolution

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| QA-011 | Case name in message | "Look at the incident-2024 case" | Case matched, files loaded into context | P1 |
| QA-012 | Case not found | "Analyze the nonexistent case" | No case match, graceful handling | P1 |
| QA-013 | Multiple cases | "Check incident-alpha" when similar cases exist | Correct case selected (exact match preferred) | P2 |
| QA-014 | Evidence file resolution | Case with `.E01` file | `.E01` file found and passed to tool params | P1 |
| QA-015 | No evidence file in case | Empty case directory | Tool execution skipped or handled gracefully | P2 |

### 2.4 Multi-Agent Orchestration

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| QA-016 | Forensicator invocation | Tool request + evidence file | `geoff_forensicator.execute_task()` called | P1 |
| QA-017 | Critic validation after tool | Successful tool execution | `geoff_critic.validate_tool_output()` called, result included | P1 |
| QA-018 | Critic commit | Any validated tool output | `geoff_critic.commit_validation()` called | P2 |
| QA-019 | Full investigation trigger | "Run full investigation on case" | `run_full_investigation()` called, `investigation_started: true` in response | P1 |
| QA-020 | Investigation skip LLM | Investigation started | LLM not called, direct status response returned | P2 |

### 2.5 Context Management

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| QA-021 | Token estimation | 1000-word message | `estimate_tokens()` returns reasonable count | P2 |
| QA-022 | Context truncation | Very large case with many files | Context trimmed to fit model context window | P1 |
| QA-023 | Conversation history | Multiple sequential messages | `context_manager.add_exchange()` records history | P2 |
| QA-024 | History overflow | 50+ exchanges | Oldest exchanges truncated, recent context preserved | P2 |
| QA-025 | Clear history | After conversation reset | `context_manager.clear_history()` empties state | P3 |

### 2.6 Error Handling

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| QA-026 | LLM unavailable | Ollama server down | Error response with message, not crash | P1 |
| QA-027 | Forensicator exception | Tool execution fails | Error logged via `action_logger`, response returned | P1 |
| QA-028 | Critic exception | Validation fails mid-pipeline | Tool result still returned, `critic_validation` may be missing | P2 |
| QA-029 | Malformed request | `{"message": null}` | Handled gracefully, no 500 error | P1 |

---

## 3. Playbook Tests

Tests for the 19 PB-SIFT playbook protocols and their execution through the specialist pipeline.

### 3.1 Playbook Index & Loading

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| PB-001 | All playbooks loadable | All 19 PB-SIFT files | Each parses to valid steps with module, function, params | P1 |
| PB-002 | Playbook index matches | PLAYBOOK_INDEX.md vs actual files | Index entries match files in `playbooks/` directory | P1 |
| PB-003 | Invalid playbook ID | `"PB-SIFT-999"` | Graceful error or skip, no crash | P1 |

### 3.2 Specialist Module Availability

| ID | Test Case | Expected Result | Priority |
|----|-----------|-----------------|----------|
| PB-004 | SleuthKit available | `mmls`, `fls`, `fsstat`, `icat`, `istat`, `ils` callable | P1 |
| PB-005 | Volatility available | `process_list`, `network_scan`, `find_malware`, `registry_scan`, `process_dump` callable | P1 |
| PB-006 | YARA available | `scan_file`, `scan_directory` callable | P1 |
| PB-007 | Registry available | `parse_hive`, `extract_user_assist`, `extract_shellbags`, `extract_usb_devices`, `extract_services`, `extract_mounted_devices`, `extract_autoruns` callable | P1 |
| PB-008 | Timeline available | `create_timeline`, `sort_timeline` callable | P2 |
| PB-009 | Network available | `analyze_pcap`, `extract_http`, `extract_flows` callable | P2 |
| PB-010 | Logs available | `parse_evtx`, `parse_syslog` callable | P2 |
| PB-011 | Strings available | `extract_strings` with IOC extraction callable | P2 |
| PB-012 | Mobile available | `analyze_ios_backup`, `analyze_android_data` callable | P3 |
| PB-013 | Tool status endpoint | `GET /tools` | Returns all 9 modules with availability status | P1 |

### 3.3 Playbook Execution (Key Playbooks)

| ID | Playbook | Evidence Required | Key Steps | Expected Outcome | Priority |
|----|----------|-------------------|-----------|-------------------|----------|
| PB-014 | PB-SIFT-001 (Malware Hunting) | Disk image | SleuthKit partition/filesystem analysis, YARA scan, string extraction | Malware indicators identified or ruled out | P1 |
| PB-015 | PB-SIFT-002 (Ransomware) | Disk image + `.locked` files | File extension analysis, ransom note detection, timeline | Ransomware classification and encryption method | P1 |
| PB-016 | PB-SIFT-003 (Network) | `.pcap` file | Flow analysis, HTTP extraction, DNS queries | C2 infrastructure and exfiltration patterns | P1 |
| PB-017 | PB-SIFT-005 (Persistence) | Registry hives | Autorun extraction, scheduled tasks, service analysis | Persistence mechanisms documented | P1 |
| PB-018 | PB-SIFT-016 (Triage) | Any evidence | Rapid inventory + classification + playbook selection | Triage report with severity assessment | P1 |
| PB-019 | PB-SIFT-019 (Malware Analysis) | Suspicious binary | Static analysis (strings, hash, type), dynamic analysis guidance | Capability mapping, IOC extraction | P1 |

### 3.4 Playbook Step Execution (`run_playbook_step`)

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| PB-020 | Valid step | `{module: "sleuthkit", function: "analyze_partition_table", params: {disk_image: "test.dd"}}` | `status: "success"`, result contains partition info | P1 |
| PB-021 | Missing tool | `{module: "volatility", function: "process_list", params: {memory_dump: "test.vmem"}}` when Volatility not installed | `status: "error"` with message about missing tool | P1 |
| PB-022 | Invalid params | `{module: "sleuthkit", function: "mmls", params: {}}` | Error handling, no crash | P2 |
| PB-023 | Large output truncation | Step producing >100 KB output | Output truncated to manageable size, not OOM | P2 |

### 3.5 Orchestrator Integration

| ID | Test Case | Expected Result | Priority |
|----|-----------|-----------------|----------|
| PB-024 | `orchestrator.run_playbook_step()` routes correctly | Correct specialist module invoked | P1 |
| PB-025 | `orchestrator.get_available_tools()` returns status | Each module shows available/unavailable | P1 |
| PB-026 | Playbook step with git commit | Action logged and committed | P2 |

---

## 4. Web UI Tests

Tests for the Flask web interface, API endpoints, and frontend JavaScript.

### 4.1 Page Load & Rendering

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| UI-001 | Load index page | `GET /` | 200, HTML with chat, evidence, tools tabs | P1 |
| UI-002 | CSS loaded | Check `<link>` or `<style>` | Dark theme (GitHub-inspired), responsive layout | P2 |
| UI-003 | JavaScript loaded | Check `<script>` | Chat functions, tab switching, evidence loading present | P2 |
| UI-004 | Mobile viewport | Browser width 375px | Layout reflows, no horizontal scroll | P2 |

### 4.2 Chat Tab

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| UI-005 | Send message | Type "Hello" → click Send | Message appears, Geoff responds | P1 |
| UI-006 | Enter-to-send | Press Enter in input | Message sent (Shift+Enter for newline) | P1 |
| UI-007 | System greeting | Page load | "G.E.O.F.F. initialized" message visible | P2 |
| UI-008 | Tool output display | Request that triggers a tool | Tool output shown in separate styled block | P1 |
| UI-009 | Typing indicator | After sending message, before response | Three-dot animation visible | P3 |
| UI-010 | Connection status | Page load | "● Online" indicator visible | P2 |
| UI-011 | Error handling | Server returns 500 | Error message shown in chat, no crash | P1 |

### 4.3 Evidence Tab

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| UI-012 | Load cases | Click Evidence tab | Cases listed with file counts | P1 |
| UI-013 | No cases | Empty evidence directory | "No cases found" message | P1 |
| UI-014 | Case file listing | Click on case name | Files displayed with type indicators | P2 |
| UI-015 | File type icons | Various file types | Correct icons/badges for `.E01`, `.vmem`, `.pcap`, `.evtx` | P3 |

### 4.4 Tools Tab

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| UI-016 | Load tools | Click Tools tab | 9 specialist modules listed with availability status | P1 |
| UI-017 | Available tool | Installed tool (e.g., SleuthKit) | Green "Available" status | P1 |
| UI-018 | Unavailable tool | Missing tool (e.g., Volatility) | "Not Available" status with icon | P1 |
| UI-019 | Tool function listing | Expand module | Functions listed under category | P2 |

### 4.5 API Endpoints

| ID | Test Case | Method/Endpoint | Expected Result | Priority |
|----|-----------|-----------------|-----------------|----------|
| UI-020 | `GET /cases` | List all cases | JSON with cases and files | P1 |
| UI-021 | `GET /tools` | List available tools | JSON with 9 modules, each with availability | P1 |
| UI-022 | `POST /run-tool` | Run SleuthKit step | JSON result with `status` field | P1 |
| UI-023 | `POST /run-tool` missing params | `{module: "sleuthkit"}` (no function) | Error response, no crash | P1 |
| UI-024 | `POST /chat` | Standard chat | JSON with `response` field | P1 |
| UI-025 | `POST /chat` with tool | "Show partition table for case X" | JSON with `response` + `tool_result` | P1 |
| UI-026 | `POST /find-evil` | `{"evidence_dir": "/path"}` | Full report JSON (see FE-053) | P1 |
| UI-027 | `GET /find-evil` | — | Usage info JSON | P1 |
| UI-028 | `POST /critic/validate` | Tool output validation | Validation result with `valid` boolean | P2 |
| UI-029 | `GET /critic/summary/{id}` | Investigation ID | Summary JSON with approval stats | P2 |
| UI-030 | `GET /investigation/status/{case}` | Running investigation | Status JSON with progress | P1 |

### 4.6 WebSocket & Real-Time Updates

| ID | Test Case | Expected Result | Priority |
|----|-----------|-----------------|----------|
| UI-031 | WebSocket connection | Connection established, chat works over WS | P2 |
| UI-032 | HTTP fallback | When WS unavailable, HTTP POST still works | P1 |
| UI-033 | Investigation progress polling | `/investigation/status/{case}` updates every 10s | P2 |

### 4.7 Standalone UI Server (Node.js)

| ID | Test Case | Expected Result | Priority |
|----|-----------|-----------------|----------|
| UI-034 | `server.js` starts | Express server on port 8080, WebSocket proxy to OpenClaw | P1 |
| UI-035 | `GET /api/health` | Health check returns 200 | P1 |
| UI-036 | `POST /api/chat` | Proxied to OpenClaw gateway | P1 |
| UI-037 | `POST /api/upload` | File uploaded, base64 encoded, saved to evidence dir | P2 |
| UI-038 | `GET /api/evidence` | Lists evidence files | P2 |
| UI-039 | `GET/POST /api/config` | Configuration read/set (Ollama mode, evidence path, etc.) | P2 |
| UI-040 | `POST /api/restart` | Services restarted | P3 |
| UI-041 | Drag-and-drop upload | File dropped into upload zone → upload initiated | P2 |
| UI-042 | Config persistence | Settings saved to `ui-config.json`, survive restart | P2 |

---

## 5. Install Tests

Tests for the installer script (`installer/install.sh`), service creation, and `geoff` launcher commands.

### 5.1 Pre-Flight Checks

| ID | Test Case | Input | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| IN-001 | RAM check | System with 4 GB RAM | Installer warns about minimum RAM | P2 |
| IN-002 | curl check | System without `curl` | Installer reports missing dependency | P1 |
| IN-003 | jq check | System without `jq` | Installer reports missing dependency | P1 |
| IN-004 | Sufficient resources | System with ≥8 GB RAM, curl, jq | Installer proceeds past pre-flight | P1 |

### 5.2 Ollama Installation

| ID | Test Case | Expected Result | Priority |
|----|-----------|-----------------|----------|
| IN-005 | Ollama download | v0.6.5 binary downloaded to `~/.local/bin/ollama` | P1 |
| IN-006 | Ollama service start | `systemctl start ollama` succeeds | P1 |
| IN-007 | Ollama model pull | `gemma3:4b` model available | P1 |
| IN-008 | Ollama already installed | Skip download, use existing installation | P2 |
| IN-009 | Ollama health check | `curl http://localhost:11434/api/tags` returns 200 | P1 |

### 5.3 Node.js & OpenClaw

| ID | Test Case | Expected Result | Priority |
|----|-----------|-----------------|----------|
| IN-010 | Node.js 22.x install | `node --version` returns v22.x | P1 |
| IN-011 | OpenClaw install | `~/.npm-global/bin/openclaw` available | P1 |
| IN-012 | OpenClaw config | `~/.openclaw/config.yaml` created with Ollama settings | P1 |
| IN-013 | OpenClaw workspace | `~/.openclaw/agents/` structure created | P2 |

### 5.4 Geoff Source & UI Deployment

| ID | Test Case | Expected Result | Priority |
|----|-----------|-----------------|----------|
| IN-014 | Source files deployed | `~/.geoff/src/geoff_integrated.py` exists | P1 |
| IN-015 | UI files deployed | `~/.geoff/ui/{index.html, styles.css, app.js, server.js}` exist | P1 |
| IN-016 | Playbooks deployed | `~/.geoff/playbooks/*.md` files exist (19 files) | P1 |
| IN-017 | Scripts deployed | `~/.geoff/scripts/*.py` files exist | P2 |

### 5.5 Systemd Services

| ID | Test Case | Expected Result | Priority |
|----|-----------|-----------------|----------|
| IN-018 | ollama.service | `systemctl status ollama` shows active | P1 |
| IN-019 | openclaw.service | `systemctl status openclaw` shows active | P1 |
| IN-020 | geoff-ui.service | `systemctl status geoff-ui` shows active | P2 |
| IN-021 | Services start on boot | `systemctl is-enabled` returns `enabled` for all three | P1 |
| IN-022 | Service restart | `systemctl restart ollama && systemctl restart geoff-ui` succeeds | P2 |

### 5.6 Launcher Commands

| ID | Test Case | Command | Expected Result | Priority |
|----|-----------|---------|-----------------|----------|
| IN-023 | Start | `geoff start` | Ollama, OpenClaw, UI all started | P1 |
| IN-024 | Stop | `geoff stop` | All services stopped | P1 |
| IN-025 | Restart | `geoff restart` | All services restarted | P1 |
| IN-026 | Status | `geoff status` | Shows status of all three services | P1 |
| IN-027 | Chat | `geoff chat` | Launches terminal chat interface | P2 |
| IN-028 | UI | `geoff ui` | Opens browser to `http://localhost:8080` | P2 |
| IN-029 | Logs | `geoff logs` | Shows combined service logs | P2 |
| IN-030 | Update | `geoff update` | Updates OpenClaw to latest version | P3 |

### 5.7 Geoff Flask Server

| ID | Test Case | Expected Result | Priority |
|----|-----------|-----------------|----------|
| IN-031 | Server start | `python3 geoff_integrated.py` starts on port 5000 | P1 |
| IN-032 | Health check | `curl http://localhost:5000/` returns 200 | P1 |
| IN-033 | Chat endpoint | `curl -X POST http://localhost:5000/chat -d '{"message":"hello"}'` returns JSON | P1 |
| IN-034 | Cases endpoint | `curl http://localhost:5000/cases` returns JSON | P1 |
| IN-035 | Port 8080 (UI server) | `curl http://localhost:8080/` returns HTML | P1 |

### 5.8 Start Script (`start-geoff.sh`)

| ID | Test Case | Expected Result | Priority |
|----|-----------|-----------------|----------|
| IN-036 | Source file check | Exits with error if `~/.geoff/src/geoff_integrated.py` missing | P1 |
| IN-037 | Kill existing server | `pkill -f geoff_integrated.py` before starting new | P2 |
| IN-038 | Port 8080 check | Reports if port already in use | P2 |
| IN-039 | PID file creation | `/tmp/geoff-server.pid` written | P3 |
| IN-040 | Log file creation | `/tmp/geoff-server.log` written | P3 |

### 5.9 End-to-End Install

| ID | Test Case | Expected Result | Priority |
|----|-----------|-----------------|----------|
| IN-041 | Full install on clean Ubuntu 22.04 | All services running, web UI accessible | P1 |
| IN-042 | Full install on clean Debian 12 | All services running, web UI accessible | P2 |
| IN-043 | Re-install over existing | Idempotent — no errors, services restart | P1 |
| IN-044 | Uninstall | Manual cleanup removes all installed files and services | P3 |

---

## Test Execution Strategy

### Smoke Tests (Pre-Release)

Run these before any release:
- FE-001, FE-010, FE-015, FE-024, FE-044, FE-053
- QA-001, QA-005, QA-011, QA-016
- PB-001, PB-004, PB-014, PB-018
- UI-001, UI-005, UI-012, UI-020, UI-024
- IN-004, IN-005, IN-014, IN-018, IN-023, IN-031, IN-041

### Regression Tests

Run on every commit to `main`:
- All P1 test cases

### Full Suite

Run before milestone releases:
- All P1 and P2 test cases
- P3 test cases as time permits

### Automation Notes

- Find Evil tests (FE-*) can be automated with pytest + Flask test client
- Q&A tests (QA-*) require running Ollama with a model loaded
- Playbook tests (PB-*) require forensic tools installed
- Web UI tests (UI-*) can use Selenium or Playwright for browser automation
- Install tests (IN-*) require clean VM snapshots for each test run

---

## Test Evidence Prep Script

```bash
#!/bin/bash
# Create test evidence directory structure
TEST_EVIDENCE="/tmp/geoff-test-evidence"
mkdir -p "$TEST_EVIDENCE/ransomware-sim"
mkdir -p "$TEST_EVIDENCE/windows-case"

# Ransomware indicators
touch "$TEST_EVIDENCE/ransomware-sim/README_DECRYPT.txt"
touch "$TEST_EVIDENCE/ransomware-sim/document.docx.locked"
touch "$TEST_EVIDENCE/ransomware-sim/photo.jpg.encrypted"

# Windows case
# (Use real disk image / memory dump for full testing)
# dd if=/dev/zero of="$TEST_EVIDENCE/windows-case/disk.dd" bs=1M count=50
# touch "$TEST_EVIDENCE/windows-case/NTUSER.DAT"
# touch "$TEST_EVIDENCE/windows-case/SYSTEM"

echo "Test evidence prepared at $TEST_EVIDENCE"
```

---

## Appendix: PB-SIFT Playbook Reference

| ID | Name | Focus |
|----|------|-------|
| PB-SIFT-001 | Malware Hunting | Disk image malware detection |
| PB-SIFT-002 | Ransomware Investigation | Encryption + ransom note analysis |
| PB-SIFT-003 | Network Forensics | PCAP analysis, C2 detection |
| PB-SIFT-004 | Credential Theft | Mimikatz, LSASS, SAM detection |
| PB-SIFT-005 | Persistence Mechanisms | Autoruns, scheduled tasks, services |
| PB-SIFT-006 | Data Exfiltration | DNS tunneling, large transfers |
| PB-SIFT-007 | Living Off The Land | LOLBIN analysis |
| PB-SIFT-008 | Web Shell Investigation | Web shell detection and analysis |
| PB-SIFT-009 | Insider Threat | Unusual access patterns |
| PB-SIFT-010 | Anti-Forensics Detection | Log clearing, timestomping |
| PB-SIFT-011 | Cloud Forensics | AWS/Azure/GCP log analysis |
| PB-SIFT-012 | Linux Server Intrusion | syslog, auth.log analysis |
| PB-SIFT-013 | macOS Incident Response | macOS-specific artifacts |
| PB-SIFT-014 | IoT Forensics | IoT device analysis |
| PB-SIFT-015 | Mobile Device Analysis | iOS/Android backup analysis |
| PB-SIFT-016 | Rapid Triage | Quick triage and classification |
| PB-SIFT-017 | Multi-Host Correlation | Cross-host timeline correlation |
| PB-SIFT-018 | Memory Forensics | Deep memory analysis |
| PB-SIFT-019 | Malware Analysis SOP | Safe malware analysis protocol |