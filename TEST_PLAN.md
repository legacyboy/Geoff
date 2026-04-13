# Geoff Test Plan

**Version:** 2.0  
**Last Updated:** 2026-04-13  
**Project:** GEOFF — Git-backed Evidence Operations Forensic Framework  
**Test Environment:** SIFT Workstation (Ubuntu) with forensic evidence at `/home/sansforensics/evidence-storage/evidence/Dell/`

---

## 1. Find Evil Tests

### 1.1 Basic Find Evil Execution

| Field | Value |
|-------|-------|
| **Objective** | Verify Find Evil runs end-to-end and returns a valid JSON report |
| **Endpoint** | `POST /find-evil` |
| **Request** | `{"evidence_dir": "/home/sansforensics/evidence-storage/evidence/Dell"}` |
| **Steps** | 1. Start Geoff server (`python3 src/geoff_integrated.py`). 2. Send POST request. 3. Wait for response (may take several minutes with large evidence). 4. Validate JSON structure. |
| **Expected** | JSON response containing `evil_found`, `evidence_score`, `severity_distribution`, `playbooks_run`, `findings_detail`, `critic_approval_pct`, `case_work_dir` |
| **Pass Criteria** | Response is valid JSON; all top-level keys present; `findings_detail` is a non-empty array; `elapsed_seconds` > 0 |

### 1.2 OS Detection — Windows

| Field | Value |
|-------|-------|
| **Objective** | Verify Find Evil correctly identifies Windows evidence |
| **Steps** | Run Find Evil on the NIST Dell image directory. Check `os_type` field in response. |
| **Expected** | `os_type` = `"windows"` |
| **Pass Criteria** | OS type matches the actual evidence OS |

### 1.3 OS Detection — Linux Evidence

| Field | Value |
|-------|-------|
| **Objective** | Verify Linux image detection |
| **Steps** | Create a temp directory with a file named `linux_image.dd`. Run Find Evil on that directory. |
| **Expected** | `os_type` = `"linux"` |
| **Pass Criteria** | OS detection heuristics identify Linux images by filename patterns |

### 1.4 OS Detection — macOS Evidence

| Field | Value |
|-------|-------|
| **Objective** | Verify macOS image detection |
| **Steps** | Create a temp directory with a file named `macos_image.raw`. Run Find Evil on that directory. |
| **Expected** | `os_type` = `"macos"` |
| **Pass Criteria** | OS detection heuristics identify macOS images |

### 1.5 Partition Table Analysis (SleuthKit mmls)

| Field | Value |
|-------|-------|
| **Objective** | Verify SleuthKit mmls integration within Find Evil |
| **Steps** | Run Find Evil on Windows disk image evidence. Inspect `findings_detail` for a step with `module: "sleuthkit"` and `function: "analyze_partition_table"`. |
| **Expected** | Step completes with `status: "completed"`. Raw output contains partition offsets. |
| **Pass Criteria** | mmls step succeeded, partition data present in result |

### 1.6 Filesystem Analysis (SleuthKit fsstat)

| Field | Value |
|-------|-------|
| **Objective** | Verify filesystem analysis runs against detected partitions |
| **Steps** | Run Find Evil with disk image. Check for `function: "analyze_filesystem"` in findings. |
| **Expected** | At least one filesystem step completes with `status: "completed"`. NTFS filesystem details in output. |
| **Pass Criteria** | fsstat step succeeded; filesystem type identified |

### 1.7 File Listing (SleuthKit fls)

| Field | Value |
|-------|-------|
| **Objective** | Verify recursive file listing |
| **Steps** | Run Find Evil with disk image. Check for `function: "list_files"` in findings. |
| **Expected** | File listing populated; Windows directories (Documents and Settings, Windows, etc.) visible |
| **Pass Criteria** | fls step completed; file listing contains expected Windows directory names |

### 1.8 Evidence Inventory — Disk Images

| Field | Value |
|-------|-------|
| **Objective** | Verify Find Evil correctly inventories disk images (.E01, .dd, .raw, .img) |
| **Steps** | Run Find Evil on the NIST Dell directory containing E01 files. Check `inventory.disk_images` in response. |
| **Expected** | `disk_images` array contains paths ending in `.E01` or `.E02` |
| **Pass Criteria** | At least 1 disk image file detected and listed |

### 1.9 Evidence Inventory — Multiple Types

| Field | Value |
|-------|-------|
| **Objective** | Verify multi-type evidence inventory (pcaps, logs, registry) |
| **Steps** | Create a temp directory with a `.pcap` file, a `.evtx` file, and a `NTUSER.DAT` file. Run Find Evil. |
| **Expected** | `inventory.pcaps`, `inventory.evtx_logs`, and `inventory.registry_hives` each contain entries |
| **Pass Criteria** | All evidence categories correctly classified |

### 1.10 Evidence Quality Score

| Field | Value |
|-------|-------|
| **Objective** | Verify evidence scoring produces meaningful values |
| **Steps** | Run Find Evil on disk image evidence. Check `evidence_score` in response. |
| **Expected** | `evidence_score` > 0.0 (disk images contribute 0.4, so score should be ≥ 0.4) |
| **Pass Criteria** | Score is a float between 0.0 and 1.0; disk image evidence yields ≥ 0.4 |

### 1.11 Indicator Triage — Ransomware Patterns

| Field | Value |
|-------|-------|
| **Objective** | Verify ransomware indicator detection |
| **Steps** | Create a temp directory with files named `readme_decrypt.txt` and `photo.jpg.locky`. Run Find Evil. |
| **Expected** | `indicator_hits` contains category `"ransomware"` with matching patterns. `severity_distribution.CRITICAL` > 0. |
| **Pass Criteria** | Ransomware indicators detected and classified as CRITICAL |

### 1.12 Indicator Triage — LOLBin Patterns

| Field | Value |
|-------|-------|
| **Objective** | Verify LOLBin (Living-off-the-Land) indicator detection |
| **Steps** | Create a temp directory with files named `certutil.exe` and `mshta.exe`. Run Find Evil. |
| **Expected** | `indicator_hits` contains category `"lolbin"`. `severity_distribution.MEDIUM` > 0. |
| **Pass Criteria** | LOLBin patterns detected and classified as MEDIUM severity |

### 1.13 Playbook Selection — Disk Images

| Field | Value |
|-------|-------|
| **Objective** | Verify correct playbook selection for disk image evidence |
| **Steps** | Run Find Evil on the NIST Dell disk image. Check `playbooks_run` in response. |
| **Expected** | `playbooks_run` includes `"PB-SIFT-016"` (Triage — always runs) and `"PB-SIFT-001"` (Malware Hunting — disk image trigger) |
| **Pass Criteria** | Both PB-SIFT-016 and PB-SIFT-001 present in playbooks_run |

### 1.14 Playbook Selection — Multi-Host Correlation

| Field | Value |
|-------|-------|
| **Objective** | Verify PB-SIFT-017 is selected when multiple disk images exist |
| **Steps** | Create a temp directory with two `.E01` files. Run Find Evil. |
| **Expected** | `playbooks_run` includes `"PB-SIFT-017"` |
| **Pass Criteria** | Correlation playbook triggered by multi-host evidence |

### 1.15 Severity Distribution

| Field | Value |
|-------|-------|
| **Objective** | Verify severity counts are calculated correctly |
| **Steps** | Run Find Evil on evidence with known ransomware indicators. Check `severity_distribution`. |
| **Expected** | `severity_distribution` contains keys `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`; CRITICAL > 0 for ransomware indicators |
| **Pass Criteria** | Severity distribution matches indicator category mapping |

### 1.16 Evil Found Flag

| Field | Value |
|-------|-------|
| **Objective** | Verify `evil_found` is set correctly |
| **Steps** | Run Find Evil on evidence with HIGH/CRITICAL indicators. Check `evil_found`. |
| **Expected** | `evil_found` = `true` |
| **Pass Criteria** | `evil_found` is `true` when CRITICAL or HIGH severity indicators are present |

### 1.17 Find Evil — Nonexistent Directory

| Field | Value |
|-------|-------|
| **Objective** | Verify graceful error handling for missing evidence directory |
| **Steps** | Send `POST /find-evil` with `{"evidence_dir": "/nonexistent/path"}` |
| **Expected** | JSON response with `status: "error"` and descriptive error message |
| **Pass Criteria** | Returns 404 or error JSON; no server crash; no unhandled exception |

### 1.18 Find Evil — Empty Directory

| Field | Value |
|-------|-------|
| **Objective** | Verify Find Evil handles an empty evidence directory |
| **Steps** | Create an empty temp directory. Run Find Evil on it. |
| **Expected** | Response completes without error. `evidence_score` = 0.0. No disk/memory/pcap artifacts in inventory. `playbooks_run` contains only `"PB-SIFT-016"` (triage baseline). |
| **Pass Criteria** | Clean response with no crashes; evidence score reflects empty state |

### 1.19 Critic Validation Pipeline

| Field | Value |
|-------|-------|
| **Objective** | Verify each Find Evil step is validated by the Critic |
| **Steps** | Run Find Evil with disk image evidence. Check `findings_detail` for `critic` or `critic_error` fields on each step. Check `critic_approval_pct`. |
| **Expected** | Each completed step has a `critic` validation object. `critic_approval_pct` is a number between 0–100. |
| **Pass Criteria** | Critic validation objects present on steps; approval percentage calculated |

### 1.20 YARA Scanning Integration

| Field | Value |
|-------|-------|
| **Objective** | Verify YARA scans run on disk images or memory dumps |
| **Steps** | Run Find Evil on evidence with disk images. Check for `module: "yara"` steps in `findings_detail`. |
| **Expected** | YARA scan steps present with `status: "completed"` or `status: "failed"` (if YARA not installed) |
| **Pass Criteria** | YARA module is invoked; graceful handling if YARA is unavailable |

### 1.21 Memory Dump Analysis

| Field | Value |
|-------|-------|
| **Objective** | Verify Volatility3 integration when memory dumps are present |
| **Steps** | Create a temp directory with a `.vmem` file. Run Find Evil. |
| **Expected** | `findings_detail` contains steps with `module: "volatility"` (process_list, network_scan, find_malware) |
| **Pass Criteria** | Volatility steps attempted; memory-first rapid analysis triggered |

### 1.22 Registry Hive Analysis

| Field | Value |
|-------|-------|
| **Objective** | Verify registry analysis runs when hives are present |
| **Steps** | Create a temp directory with `NTUSER.DAT` and `SYSTEM` files. Run Find Evil. |
| **Expected** | Steps with `module: "registry"` for UserAssist, ShellBags, USB, Services extraction |
| **Pass Criteria** | Registry specialist steps present in findings |

### 1.23 Network PCAP Analysis

| Field | Value |
|-------|-------|
| **Objective** | Verify tshark/tcpflow analysis on pcap files |
| **Steps** | Create a temp directory with a `.pcap` file. Run Find Evil. |
| **Expected** | Steps with `module: "network"` for analyze_pcap, extract_http, extract_flows |
| **Pass Criteria** | Network analysis steps present in findings |

### 1.24 Git-Backed Audit Trail

| Field | Value |
|-------|-------|
| **Objective** | Verify Find Evil creates a git-backed case directory |
| **Steps** | Run Find Evil. Check `case_work_dir` in response. Navigate to that directory and run `git log`. |
| **Expected** | Case directory exists with `output/`, `reports/`, `validations/` subdirectories. Git history contains at least one commit. `find_evil_report.json` present in `reports/`. |
| **Pass Criteria** | Git repo initialized; report file written; at least one commit referencing Find Evil |

### 1.25 Report Generation

| Field | Value |
|-------|-------|
| **Objective** | Verify Find Evil generates a complete JSON report |
| **Steps** | Run Find Evil. Read the report file from `case_work_dir/reports/find_evil_report.json`. |
| **Expected** | Report contains all required fields: `title`, `generated_at`, `evidence_dir`, `evidence_score`, `os_type`, `evil_found`, `severity_distribution`, `indicator_hits`, `playbooks_run`, `specialist_steps_executed`, `steps_succeeded`, `steps_failed`, `critic_approval_pct`, `findings_detail`, `elapsed_seconds`, `case_work_dir` |
| **Pass Criteria** | All fields present; JSON parses correctly; values are non-null |

---

## 2. Q&A (Chat) Tests

### 2.1 Chat Endpoint — Basic Response

| Field | Value |
|-------|-------|
| **Objective** | Verify chat endpoint returns a response |
| **Endpoint** | `POST /chat` |
| **Steps** | Send `{"message": "Hello, what can you do?"}` |
| **Expected** | JSON response with `response` key containing a string |
| **Pass Criteria** | Response is non-empty; no errors |

### 2.2 Chat — Forensic Tool Request (mmls)

| Field | Value |
|-------|-------|
| **Objective** | Verify chat detects and routes forensic tool requests |
| **Steps** | Send `{"message": "Run mmls on the Dell disk image"}` |
| **Expected** | Response includes tool detection; `detect_tool_request` identifies `sleuthkit.analyze_partition_table` |
| **Pass Criteria** | Tool request detected; specialist module invoked; `tool_result` present in response |

### 2.3 Chat — Forensic Tool Request (strings)

| Field | Value |
|-------|-------|
| **Objective** | Verify string extraction detection |
| **Steps** | Send `{"message": "Extract strings from the malware sample"}` |
| **Expected** | Tool request detected as `strings.extract_strings` |
| **Pass Criteria** | Correct module and function identified |

### 2.4 Chat — Forensic Tool Request (YARA)

| Field | Value |
|-------|-------|
| **Objective** | Verify YARA scan detection |
| **Steps** | Send `{"message": "Scan for malware using YARA"}` |
| **Expected** | Tool request detected as `yara.scan_file` |
| **Pass Criteria** | YARA module correctly identified |

### 2.5 Chat — Investigation Trigger

| Field | Value |
|-------|-------|
| **Objective** | Verify full investigation trigger detection |
| **Steps** | Send `{"message": "Run full investigation on the Dell case"}` with a valid case name |
| **Expected** | Tool request detected as `orchestrator.run_full_investigation`; `investigation_started` flag in response |
| **Pass Criteria** | Investigation initiated; background worker spawned; case work directory created |

### 2.6 Chat — Case Context Resolution

| Field | Value |
|-------|-------|
| **Objective** | Verify chat resolves case names from evidence directory |
| **Steps** | Send `{"message": "Show me the files in the Dell case"}` with Dell evidence present in `EVIDENCE_BASE_DIR` |
| **Expected** | Case name "Dell" resolved from available cases; file listing included in context |
| **Pass Criteria** | Case matched; evidence files referenced in response |

### 2.7 Chat — Volatility Request

| Field | Value |
|-------|-------|
| **Objective** | Verify memory forensics detection |
| **Steps** | Send `{"message": "Run volatility process list on the memory dump"}` |
| **Expected** | Tool request detected as `volatility.process_list` |
| **Pass Criteria** | Volatility module and function correctly identified |

### 2.8 Chat — Registry Request

| Field | Value |
|-------|-------|
| **Objective** | Verify registry analysis detection |
| **Steps** | Send `{"message": "Parse the NTUSER.DAT registry hive"}` |
| **Expected** | Tool request detected as `registry.parse_hive` |
| **Pass Criteria** | Registry module correctly identified |

### 2.9 Chat — Timeline Request

| Field | Value |
|-------|-------|
| **Objective** | Verify Plaso/timeline detection |
| **Steps** | Send `{"message": "Create a timeline with log2timeline"}` |
| **Expected** | Tool request detected as `plaso.create_timeline` |
| **Pass Criteria** | Plaso module correctly identified |

### 2.10 Chat — Network Request

| Field | Value |
|-------|-------|
| **Objective** | Verify PCAP/network forensics detection |
| **Steps** | Send `{"message": "Analyze the pcap for network connections"}` |
| **Expected** | Tool request detected as `network.analyze_pcap` |
| **Pass Criteria** | Network module correctly identified |

### 2.11 Chat — Critic Validation on Tool Results

| Field | Value |
|-------|-------|
| **Objective** | Verify Critic validates chat-initiated tool results |
| **Steps** | Send a tool request via chat. Check response for `critic_validation` and `critic_approved` keys. |
| **Expected** | `critic_validation` object present; `critic_approved` boolean indicating pass/fail |
| **Pass Criteria** | Critic pipeline runs on interactive tool results |

### 2.12 Chat — Empty Message

| Field | Value |
|-------|-------|
| **Objective** | Verify graceful handling of empty messages |
| **Steps** | Send `{"message": ""}` |
| **Expected** | JSON response with a default/prompting message (e.g., "What would you like to look at?") |
| **Pass Criteria** | No server error; reasonable default response |

### 2.13 Chat — Action Logging

| Field | Value |
|-------|-------|
| **Objective** | Verify chat interactions are logged to JSONL |
| **Steps** | Send a chat message. Check the JSONL action log file for a `CHAT` entry. |
| **Expected** | JSONL file contains entry with `action_type: "CHAT"`, `user_message`, and timestamp |
| **Pass Criteria** | Chat interaction logged with correct fields |

### 2.14 Chat — Context Manager Window

| Field | Value |
|-------|-------|
| **Objective** | Verify context window management prevents overflow |
| **Steps** | Send multiple chat messages with long case file lists. Verify responses remain coherent and don't exceed token limits. |
| **Expected** | Context manager truncates large inputs; LLM still responds; `MAX_CONTEXT_TOKENS = 24000` respected |
| **Pass Criteria** | No context overflow errors; conversation history limited to `max_history_turns = 5` |

### 2.15 Chat — LLM Unavailable

| Field | Value |
|-------|-------|
| **Objective** | Verify graceful degradation when Ollama is down |
| **Steps** | Stop Ollama service. Send a chat message. |
| **Expected** | Response contains connection error message (e.g., "Having trouble connecting to Ollama"); no server crash |
| **Pass Criteria** | Server stays up; user-facing error message; 500 error not returned |

---

## 3. Playbook Tests

### 3.1 Playbook File Completeness

| Field | Value |
|-------|-------|
| **Objective** | Verify all 19 PB-SIFT playbook files exist |
| **Steps** | List `playbooks/` directory; verify files PB-SIFT-001 through PB-SIFT-019 are present |
| **Expected** | 19 `.md` files, one for each PB-SIFT-XXX identifier |
| **Pass Criteria** | All 19 playbook files exist and are non-empty |

### 3.2 Playbook Index Consistency

| Field | Value |
|-------|-------|
| **Objective** | Verify PLAYBOOK_INDEX.md matches actual playbook files |
| **Steps** | Read `playbooks/PLAYBOOK_INDEX.md`. Extract all playbook IDs. Compare against actual filenames. |
| **Expected** | Every ID in the index has a corresponding `.md` file; every file has an index entry |
| **Pass Criteria** | Index and files are in 1:1 correspondence |

### 3.3 Triage Playbook (PB-SIFT-016) Execution

| Field | Value |
|-------|-------|
| **Objective** | Verify triage playbook always runs first in Find Evil |
| **Steps** | Run Find Evil on any evidence. Check that `PB-SIFT-016` is the first entry in `playbooks_run`. |
| **Expected** | `playbooks_run[0]` = `"PB-SIFT-016"` |
| **Pass Criteria** | Triage playbook is always first; it's the baseline for all evidence types |

### 3.4 Ransomware Playbook (PB-SIFT-002) Triggering

| Field | Value |
|-------|-------|
| **Objective** | Verify ransomware playbook triggers on ransomware indicators |
| **Steps** | Create temp directory with files containing ransom note patterns (`readme_decrypt.txt`, `.locked` extension). Run Find Evil. |
| **Expected** | `playbooks_run` includes `"PB-SIFT-002"` and `"PB-SIFT-008"` |
| **Pass Criteria** | Ransomware indicators correctly trigger both ransomware and initial access playbooks |

### 3.5 Credential Theft Playbook (PB-SIFT-004) Triggering

| Field | Value |
|-------|-------|
| **Objective** | Verify credential theft playbook triggers |
| **Steps** | Create temp directory with files named `mimikatz.exe`, `lsass.dmp`. Run Find Evil. |
| **Expected** | `playbooks_run` includes `"PB-SIFT-004"` and `"PB-SIFT-003"` |
| **Pass Criteria** | Credential theft and lateral movement playbooks triggered |

### 3.6 Persistence Playbook (PB-SIFT-005) Triggering

| Field | Value |
|-------|-------|
| **Objective** | Verify persistence playbook triggers |
| **Steps** | Create temp directory with files containing `autorun` and `scheduled_task` patterns. Run Find Evil. |
| **Expected** | `playbooks_run` includes `"PB-SIFT-005"` and `"PB-SIFT-001"` |
| **Pass Criteria** | Persistence and malware hunting playbooks triggered |

### 3.7 Anti-Forensics Playbook (PB-SIFT-010) Triggering

| Field | Value |
|-------|-------|
| **Objective** | Verify anti-forensics playbook triggers |
| **Steps** | Create temp directory with files named `ccleaner.exe`, containing `eventlog_clear` patterns. Run Find Evil. |
| **Expected** | `playbooks_run` includes `"PB-SIFT-010"` and `"PB-SIFT-001"` |
| **Pass Criteria** | Anti-forensics playbook triggered |

### 3.8 Web Shell Playbook (PB-SIFT-008) Triggering

| Field | Value |
|-------|-------|
| **Objective** | Verify initial access / web shell playbook triggers |
| **Steps** | Create temp directory with files containing `c99` and `base64_decode` patterns. Run Find Evil. |
| **Expected** | `playbooks_run` includes `"PB-SIFT-008"` |
| **Pass Criteria** | Web shell indicators detected; initial access playbook triggered |

### 3.9 Linux Playbook (PB-SIFT-012) Triggering

| Field | Value |
|-------|-------|
| **Objective** | Verify Linux-specific playbook triggers |
| **Steps** | Create temp directory with a file named `linux_server.dd`. Run Find Evil. |
| **Expected** | `playbooks_run` includes `"PB-SIFT-012"` |
| **Pass Criteria** | Linux image detection triggers Linux playbook |

### 3.10 macOS Playbook (PB-SIFT-013) Triggering

| Field | Value |
|-------|-------|
| **Objective** | Verify macOS-specific playbook triggers |
| **Steps** | Create temp directory with a file named `macos_image.raw`. Run Find Evil. |
| **Expected** | `playbooks_run` includes `"PB-SIFT-013"` |
| **Pass Criteria** | macOS image detection triggers macOS playbook |

### 3.11 Mobile Playbook (PB-SIFT-015) Triggering

| Field | Value |
|-------|-------|
| **Objective** | Verify mobile backup playbook triggers |
| **Steps** | Create temp directory with `Info.plist` and `Manifest.db` files. Run Find Evil. |
| **Expected** | `os_type` = `"mobile"`; `playbooks_run` includes `"PB-SIFT-015"` |
| **Pass Criteria** | Mobile backup indicators detected; mobile playbook triggered |

### 3.12 Playbook — No Duplicates

| Field | Value |
|-------|-------|
| **Objective** | Verify playbook list has no duplicates |
| **Steps** | Run Find Evil on evidence with multiple indicator types. Check `playbooks_run` for duplicates. |
| **Expected** | Each playbook ID appears at most once |
| **Pass Criteria** | `len(playbooks_run) == len(set(playbooks_run))` |

### 3.13 Playbook — Deduplication with Overlapping Indicators

| Field | Value |
|-------|-------|
| **Objective** | Verify overlapping indicators don't cause duplicate playbooks |
| **Steps** | Create evidence with both ransomware and persistence indicators. Multiple categories may map to PB-SIFT-001. |
| **Expected** | PB-SIFT-001 appears only once despite being triggered by multiple categories |
| **Pass Criteria** | No duplicate playbook entries even with overlapping triggers |

### 3.14 Playbook Severity Ordering

| Field | Value |
|-------|-------|
| **Objective** | Verify playbooks are ordered by severity (CRITICAL first) |
| **Steps** | Create evidence with multiple indicator categories (ransomware + LOLBin). Run Find Evil. |
| **Expected** | CRITICAL-triggered playbooks (PB-SIFT-002) appear before MEDIUM-triggered playbooks (PB-SIFT-007) |
| **Pass Criteria** | Playbook order reflects severity priority |

### 3.15 Playbook Markdown Structure

| Field | Value |
|-------|-------|
| **Objective** | Verify each playbook file has required sections |
| **Steps** | For each PB-SIFT-XXX.md file, verify it contains Phase sections and checkable items (`- [ ]`) |
| **Expected** | Each playbook has: Title, Objective, at least one Phase, checkable steps |
| **Pass Criteria** | All 19 playbooks have consistent structure with phases and checkboxes |

---

## 4. Web UI Tests

### 4.1 Main Page Load

| Field | Value |
|-------|-------|
| **Objective** | Verify web UI loads successfully |
| **Endpoint** | `GET /` |
| **Steps** | `curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/` |
| **Expected** | HTTP 200; HTML content with Geoff branding |
| **Pass Criteria** | Status code 200; response contains "Geoff" and "DFIR" |

### 4.2 Find Evil Info Endpoint (GET)

| Field | Value |
|-------|-------|
| **Objective** | Verify GET /find-evil returns usage documentation |
| **Endpoint** | `GET /find-evil` |
| **Steps** | `curl http://localhost:8080/find-evil` |
| **Expected** | JSON with `name`, `description`, `usage`, `supported_evidence` array, `playbooks` array, `pipeline` array |
| **Pass Criteria** | All documentation fields present; playbooks array has 15+ entries |

### 4.3 Find Evil Execute Endpoint (POST)

| Field | Value |
|-------|-------|
| **Objective** | Verify POST /find-evil executes and returns results |
| **Endpoint** | `POST /find-evil` |
| **Steps** | `curl -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{"evidence_dir": "/home/sansforensics/evidence-storage/evidence/Dell"}'` |
| **Expected** | Full JSON report with inventory, classification, findings |
| **Pass Criteria** | Response is valid JSON; contains all required report fields |

### 4.4 Find Evil — Default Evidence Path

| Field | Value |
|-------|-------|
| **Objective** | Verify POST /find-evil uses default path when evidence_dir is empty |
| **Endpoint** | `POST /find-evil` |
| **Steps** | `curl -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{}'` |
| **Expected** | Uses `EVIDENCE_BASE_DIR` default (`/home/sansforensics/evidence-storage`); runs Find Evil on default path |
| **Pass Criteria** | Returns results from default evidence directory or error if it doesn't exist (graceful) |

### 4.5 Cases List Endpoint

| Field | Value |
|-------|-------|
| **Objective** | Verify GET /cases returns evidence directory listing |
| **Endpoint** | `GET /cases` |
| **Steps** | `curl http://localhost:8080/cases` |
| **Expected** | JSON with `cases` object mapping case names to file lists |
| **Pass Criteria** | Valid JSON; `cases` key present |

### 4.6 Tools Status Endpoint

| Field | Value |
|-------|-------|
| **Objective** | Verify GET /tools returns forensic tool availability |
| **Endpoint** | `GET /tools` |
| **Steps** | `curl http://localhost:8080/tools` |
| **Expected** | JSON with `tools` object listing each specialist module and availability status |
| **Pass Criteria** | Valid JSON; tools object present; each module has `available` and `functions` fields |

### 4.7 Run Tool API

| Field | Value |
|-------|-------|
| **Objective** | Verify POST /run-tool executes a specialist function |
| **Endpoint** | `POST /run-tool` |
| **Steps** | `curl -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{"module": "sleuthkit", "function": "analyze_partition_table", "params": {"disk_image": "/path/to/image.E01"}}'` |
| **Expected** | JSON result with `status`, `tool`, `stdout`/`stderr` |
| **Pass Criteria** | Tool execution attempted; result has valid structure |

### 4.8 Critic Validation API

| Field | Value |
|-------|-------|
| **Objective** | Verify POST /critic/validate accepts validation requests |
| **Endpoint** | `POST /critic/validate` |
| **Steps** | `curl -X POST http://localhost:8080/critic/validate -H 'Content-Type: application/json' -d '{"tool_name": "sleuthkit.mmls", "tool_output": "DOS partition...", "geoff_analysis": "NTFS partition detected"}'` |
| **Expected** | JSON validation result with `valid`, `confidence`, `issues` |
| **Pass Criteria** | Critic validation endpoint responds; validation object returned |

### 4.9 Critic Summary API

| Field | Value |
|-------|-------|
| **Objective** | Verify GET /critic/summary/:investigation_id returns validation summary |
| **Endpoint** | `GET /critic/summary/test-investigation` |
| **Steps** | `curl http://localhost:8080/critic/summary/test-investigation` |
| **Expected** | JSON summary or error for non-existent investigation |
| **Pass Criteria** | Endpoint responds without server error; valid JSON structure |

### 4.10 Investigation Status API

| Field | Value |
|-------|-------|
| **Objective** | Verify GET /investigation/status/:case_name returns status |
| **Endpoint** | `GET /investigation/status/test-case` |
| **Steps** | `curl http://localhost:8080/investigation/status/test-case` |
| **Expected** | 404 JSON for non-existent case, or status object for active case |
| **Pass Criteria** | Returns valid JSON (even for 404); no server crash |

### 4.11 Chat API — Method Not Allowed

| Field | Value |
|-------|-------|
| **Objective** | Verify GET /chat returns method not allowed |
| **Endpoint** | `GET /chat` |
| **Steps** | `curl -X GET http://localhost:8080/chat` |
| **Expected** | HTTP 405 Method Not Allowed (Flask default for POST-only route) |
| **Pass Criteria** | Correct HTTP status code; no server error |

### 4.12 Web UI — HTML Structure

| Field | Value |
|-------|-------|
| **Objective** | Verify HTML template contains required UI elements |
| **Steps** | Fetch `GET /`. Inspect HTML for: chat input, send button, tabs (Chat, Evidence), status indicator |
| **Expected** | HTML contains `#chat-input`, `send-btn`, `.tab` elements, and JavaScript functions (`sendChat`, `loadEvidence`) |
| **Pass Criteria** | All UI elements present in rendered HTML |

### 4.13 Web UI — Evidence Tab

| Field | Value |
|-------|-------|
| **Objective** | Verify Evidence tab loads case data via API |
| **Steps** | Load web UI. Click "Evidence" tab. Verify `loadEvidence()` function calls `/cases` endpoint. |
| **Expected** | Case cards rendered with case names and file counts |
| **Pass Criteria** | Evidence tab populates from `/cases` API data |

### 4.14 Web UI — JavaScript Chat Flow

| Field | Value |
|-------|-------|
| **Objective** | Verify chat JavaScript sends messages and displays responses |
| **Steps** | Load web UI. Type a message. Verify `sendChat()` posts to `/chat` and appends response. |
| **Expected** | User message appears in chat; Geoff response appears; tool results shown if applicable |
| **Pass Criteria** | Chat messages rendered correctly; API integration works |

### 4.15 Service Status

| Field | Value |
|-------|-------|
| **Objective** | Verify Geoff Flask service runs as systemd service |
| **Steps** | `systemctl status geoff` |
| **Expected** | `active (running)`; port 8080 listening |
| **Pass Criteria** | Service is active; `ss -tlnp | grep 8080` shows LISTEN |

### 4.16 CORS Headers

| Field | Value |
|-------|-------|
| **Objective** | Verify CORS is configured for cross-origin requests |
| **Steps** | `curl -s -I -X OPTIONS http://localhost:8080/chat -H "Origin: http://localhost:3000"` |
| **Expected** | Response includes `Access-Control-Allow-Origin` header |
| **Pass Criteria** | CORS headers present; Flask-CORS configured correctly |

---

## 5. Install Tests

### 5.1 Clean Installation

| Field | Value |
|-------|-------|
| **Objective** | Verify install.sh runs on a clean Ubuntu/Debian system |
| **Steps** | 1. Start a clean Ubuntu container/VM. 2. `git clone https://github.com/legacyboy/Geoff.git`. 3. `cd Geoff/installer && ./install.sh` |
| **Expected** | All 7 steps complete: requirements check, Ollama install, model pull, Node.js install, OpenClaw install, workspace setup, systemd services |
| **Pass Criteria** | Script exits 0; no errors; Geoff service running |

### 5.2 Install — Requirements Check

| Field | Value |
|-------|-------|
| **Objective** | Verify install checks for required tools and installs missing ones |
| **Steps** | On a minimal system missing `curl` and `jq`, run install.sh |
| **Expected** | `curl` and `jq` installed automatically; YARA installation attempted |
| **Pass Criteria** | Missing dependencies installed; install continues |

### 5.3 Install — YARA Installation

| Field | Value |
|-------|-------|
| **Objective** | Verify YARA is installed during setup |
| **Steps** | Check `which yara` after install; `yara --version` |
| **Expected** | YARA binary available; version number displayed |
| **Pass Criteria** | `yara --version` returns a version string |

### 5.4 Install — Ollama Binary

| Field | Value |
|-------|-------|
| **Objective** | Verify Ollama is installed to `~/.local/bin/` |
| **Steps** | `ls -la ~/.local/bin/ollama`; `~/.local/bin/ollama --version` |
| **Expected** | Ollama binary present; version matches v0.6.5 |
| **Pass Criteria** | Binary exists; version command succeeds |

### 5.5 Install — Ollama Model

| Field | Value |
|-------|-------|
| **Objective** | Verify gemma3:4b model is pulled |
| **Steps** | `~/.local/bin/ollama list | grep gemma3` |
| **Expected** | `gemma3:4b` model listed with correct digest |
| **Pass Criteria** | Model available; digest matches `aeda25e63ebd` |

### 5.6 Install — Node.js Version

| Field | Value |
|-------|-------|
| **Objective** | Verify Node.js 22.x is installed |
| **Steps** | `node -v` |
| **Expected** | Version string starts with `v22.` |
| **Pass Criteria** | Node.js ≥ 18 installed (22.x preferred) |

### 5.7 Install — OpenClaw

| Field | Value |
|-------|-------|
| **Objective** | Verify OpenClaw is installed globally |
| **Steps** | `which openclaw`; `openclaw --version` |
| **Expected** | OpenClaw binary in PATH; version displayed |
| **Pass Criteria** | `openclaw` command available |

### 5.8 Install — Workspace Directories

| Field | Value |
|-------|-------|
| **Objective** | Verify all workspace directories are created |
| **Steps** | Check for: `~/.geoff/`, `~/.geoff/evidence/`, `~/.geoff/src/`, `~/.geoff/ui/`, `~/.openclaw/`, `~/.openclaw/workspace/` |
| **Expected** | All directories exist |
| **Pass Criteria** | `ls -d` succeeds for each directory |

### 5.9 Install — Python Source Files

| Field | Value |
|-------|-------|
| **Objective** | Verify Python source is deployed to `~/.geoff/src/` |
| **Steps** | `ls ~/.geoff/src/*.py` |
| **Expected** | `geoff_integrated.py`, `geoff_critic.py`, `geoff_forensicator.py`, `sift_specialists.py`, `sift_specialists_extended.py` present |
| **Pass Criteria** | All source files deployed |

### 5.10 Install — Playbooks Deployed

| Field | Value |
|-------|-------|
| **Objective** | Verify playbooks are deployed to `~/.geoff/playbooks/` |
| **Steps** | `ls ~/.geoff/playbooks/PB-SIFT-*.md | wc -l` |
| **Expected** | 19 playbook files |
| **Pass Criteria** | All playbook markdown files copied |

### 5.11 Install — Flask Dependencies

| Field | Value |
|-------|-------|
| **Objective** | Verify Python Flask and requests packages are installed |
| **Steps** | `python3 -c "import flask; import requests; print('OK')"` |
| **Expected** | `OK` printed without error |
| **Pass Criteria** | Both `flask` and `requests` importable |

### 5.12 Install — Systemd Services

| Field | Value |
|-------|-------|
| **Objective** | Verify systemd services are created and enabled |
| **Steps** | `systemctl list-unit-files | grep -E 'ollama|geoff'` |
| **Expected** | `ollama.service` and `geoff.service` (or `geoff-ui.service`) enabled |
| **Pass Criteria** | Both services listed as `enabled` |

### 5.13 Install — Geoff Launcher

| Field | Value |
|-------|-------|
| **Objective** | Verify `geoff` launcher command is available |
| **Steps** | `which geoff`; `geoff help` or `geoff` |
| **Expected** | Launcher script at `~/.local/bin/geoff`; help output displayed |
| **Pass Criteria** | Command available; shows usage with start/stop/status/chat/ui/logs/update subcommands |

### 5.14 Install — Service Auto-Start

| Field | Value |
|-------|-------|
| **Objective** | Verify services start automatically after install |
| **Steps** | After install, check `systemctl is-active ollama` and `systemctl is-active geoff` |
| **Expected** | Both services `active` |
| **Pass Criteria** | Services running without manual start |

### 5.15 Install — Configuration Files

| Field | Value |
|-------|-------|
| **Objective** | Verify OpenClaw configuration is created |
| **Steps** | Check `~/.openclaw/config.yaml` and `~/.openclaw/openclaw.json` |
| **Expected** | `config.yaml` contains model config with `gemma3:4b`; `openclaw.json` contains gateway config with port 18789 |
| **Pass Criteria** | Both config files exist with correct model and gateway settings |

### 5.16 Install — Environment Variables

| Field | Value |
|-------|-------|
| **Objective** | Verify PATH and environment are set |
| **Steps** | `echo $PATH | grep .local/bin`; `env | grep OLLAMA` |
| **Expected** | `~/.local/bin` in PATH; `OLLAMA_API_KEY` set |
| **Pass Criteria** | PATH includes `.local/bin`; OLLAMA_API_KEY environment variable set |

### 5.17 Install — Idempotent Reinstall

| Field | Value |
|-------|-------|
| **Objective** | Verify running install.sh again doesn't break the installation |
| **Steps** | Run install.sh a second time on the same system |
| **Expected** | Existing installations detected; skipped where already installed; no errors |
| **Pass Criteria** | Script completes without errors; services still running |

### 5.18 Install — Start-Stop-Restart

| Field | Value |
|-------|-------|
| **Objective** | Verify `geoff start`, `geoff stop`, `geoff restart` work |
| **Steps** | 1. `geoff stop` — verify services stop. 2. `geoff start` — verify services start. 3. `geoff restart` — verify services restart. |
| **Expected** | Each command changes service state correctly |
| **Pass Criteria** | `geoff status` reflects correct state after each command |

### 5.19 Install — Port 8080 Binding

| Field | Value |
|-------|-------|
| **Objective** | Verify Geoff binds to port 8080 after start |
| **Steps** | `geoff start`; `sleep 3`; `ss -tlnp | grep 8080` |
| **Expected** | Port 8080 in LISTEN state |
| **Pass Criteria** | Geoff Flask server listening on 8080 |

### 5.20 Install — Unprivileged Execution

| Field | Value |
|-------|-------|
| **Objective** | Verify install refuses to run as root |
| **Steps** | `sudo bash install.sh` |
| **Expected** | Script exits with error: "Do not run as root" |
| **Pass Criteria** | Root execution blocked; non-root user required |

---

## Test Execution Checklist

### Find Evil Tests
- [ ] 1.1 Basic Find Evil Execution
- [ ] 1.2 OS Detection — Windows
- [ ] 1.3 OS Detection — Linux
- [ ] 1.4 OS Detection — macOS
- [ ] 1.5 Partition Table Analysis
- [ ] 1.6 Filesystem Analysis
- [ ] 1.7 File Listing
- [ ] 1.8 Evidence Inventory — Disk Images
- [ ] 1.9 Evidence Inventory — Multiple Types
- [ ] 1.10 Evidence Quality Score
- [ ] 1.11 Indicator Triage — Ransomware
- [ ] 1.12 Indicator Triage — LOLBin
- [ ] 1.13 Playbook Selection — Disk Images
- [ ] 1.14 Playbook Selection — Multi-Host
- [ ] 1.15 Severity Distribution
- [ ] 1.16 Evil Found Flag
- [ ] 1.17 Find Evil — Nonexistent Directory
- [ ] 1.18 Find Evil — Empty Directory
- [ ] 1.19 Critic Validation Pipeline
- [ ] 1.20 YARA Scanning Integration
- [ ] 1.21 Memory Dump Analysis
- [ ] 1.22 Registry Hive Analysis
- [ ] 1.23 Network PCAP Analysis
- [ ] 1.24 Git-Backed Audit Trail
- [ ] 1.25 Report Generation

### Q&A (Chat) Tests
- [ ] 2.1 Chat Endpoint — Basic Response
- [ ] 2.2 Chat — Forensic Tool Request (mmls)
- [ ] 2.3 Chat — Forensic Tool Request (strings)
- [ ] 2.4 Chat — Forensic Tool Request (YARA)
- [ ] 2.5 Chat — Investigation Trigger
- [ ] 2.6 Chat — Case Context Resolution
- [ ] 2.7 Chat — Volatility Request
- [ ] 2.8 Chat — Registry Request
- [ ] 2.9 Chat — Timeline Request
- [ ] 2.10 Chat — Network Request
- [ ] 2.11 Chat — Critic Validation on Tool Results
- [ ] 2.12 Chat — Empty Message
- [ ] 2.13 Chat — Action Logging
- [ ] 2.14 Chat — Context Manager Window
- [ ] 2.15 Chat — LLM Unavailable

### Playbook Tests
- [ ] 3.1 Playbook File Completeness
- [ ] 3.2 Playbook Index Consistency
- [ ] 3.3 Triage Playbook (PB-SIFT-016) Execution
- [ ] 3.4 Ransomware Playbook (PB-SIFT-002) Triggering
- [ ] 3.5 Credential Theft Playbook (PB-SIFT-004) Triggering
- [ ] 3.6 Persistence Playbook (PB-SIFT-005) Triggering
- [ ] 3.7 Anti-Forensics Playbook (PB-SIFT-010) Triggering
- [ ] 3.8 Web Shell Playbook (PB-SIFT-008) Triggering
- [ ] 3.9 Linux Playbook (PB-SIFT-012) Triggering
- [ ] 3.10 macOS Playbook (PB-SIFT-013) Triggering
- [ ] 3.11 Mobile Playbook (PB-SIFT-015) Triggering
- [ ] 3.12 Playbook — No Duplicates
- [ ] 3.13 Playbook — Deduplication with Overlapping Indicators
- [ ] 3.14 Playbook Severity Ordering
- [ ] 3.15 Playbook Markdown Structure

### Web UI Tests
- [ ] 4.1 Main Page Load
- [ ] 4.2 Find Evil Info Endpoint (GET)
- [ ] 4.3 Find Evil Execute Endpoint (POST)
- [ ] 4.4 Find Evil — Default Evidence Path
- [ ] 4.5 Cases List Endpoint
- [ ] 4.6 Tools Status Endpoint
- [ ] 4.7 Run Tool API
- [ ] 4.8 Critic Validation API
- [ ] 4.9 Critic Summary API
- [ ] 4.10 Investigation Status API
- [ ] 4.11 Chat API — Method Not Allowed
- [ ] 4.12 Web UI — HTML Structure
- [ ] 4.13 Web UI — Evidence Tab
- [ ] 4.14 Web UI — JavaScript Chat Flow
- [ ] 4.15 Service Status
- [ ] 4.16 CORS Headers

### Install Tests
- [ ] 5.1 Clean Installation
- [ ] 5.2 Install — Requirements Check
- [ ] 5.3 Install — YARA Installation
- [ ] 5.4 Install — Ollama Binary
- [ ] 5.5 Install — Ollama Model
- [ ] 5.6 Install — Node.js Version
- [ ] 5.7 Install — OpenClaw
- [ ] 5.8 Install — Workspace Directories
- [ ] 5.9 Install — Python Source Files
- [ ] 5.10 Install — Playbooks Deployed
- [ ] 5.11 Install — Flask Dependencies
- [ ] 5.12 Install — Systemd Services
- [ ] 5.13 Install — Geoff Launcher
- [ ] 5.14 Install — Service Auto-Start
- [ ] 5.15 Install — Configuration Files
- [ ] 5.16 Install — Environment Variables
- [ ] 5.17 Install — Idempotent Reinstall
- [ ] 5.18 Install — Start-Stop-Restart
- [ ] 5.19 Install — Port 8080 Binding
- [ ] 5.20 Install — Unprivileged Execution

---

## Results Summary

| Test Category | Total | Pass | Fail | Blocked |
|--------------|-------|------|------|---------|
| Find Evil | 25 | — | — | — |
| Q&A (Chat) | 15 | — | — | — |
| Playbook | 15 | — | — | — |
| Web UI | 16 | — | — | — |
| Install | 20 | — | — | — |
| **Total** | **91** | — | — | — |

---

## Known Issues

1. **Critic Approval 0%** — JSON parsing in Critic validation needs improvement; `critic_approval_pct` may show 0% even when steps succeed
2. **Null Severity** — Some findings may have null severity due to parsing gaps
3. **YARA Default Install** — YARA is not installed by default on SIFT; installer now includes it but some systems may not have it
4. **Large Evidence Timeout** — Very large disk images may cause timeouts in SleuthKit operations (5-minute default)
5. **Ollama Connection** — If Ollama is not running, chat responses return error strings but the server stays up
6. **RegRipper Dependency** — Registry analysis requires RegRipper at `/usr/local/bin/rip.pl`; may not be present on all systems
7. **Volatility3 Path** — Memory forensics requires `vol.py` in PATH; depends on SIFT/REMnux installation

---

## Environment Notes

- **Test Host:** SIFT Workstation (Ubuntu-based)
- **Evidence:** NIST Hacking Case — Dell Latitude CPI E01 images at `/home/sansforensics/evidence-storage/evidence/Dell/`
- **Ollama:** Must be running on `localhost:11434` with models pulled (gemma3:4b at minimum; deepseek-r1:70b, qwen2.5-coder:32b, qwen3:30b for full multi-agent)
- **Python:** 3.10+
- **Port:** 8080 (Geoff Flask server)