# Geoff QA Test Results
Started: 2026-04-16 18:36:22 CDT

## Batch 1: Find Evil Job Results
### [FindEvil] Hacking Case job status — 2026-04-16 18:36:24 CDT
**Result:** complete

### [FindEvil] Data Leakage job status — 2026-04-16 18:36:26 CDT
**Result:** 

### [FindEvil] Report file exists — 2026-04-16 18:36:26 CDT
**Result:** 

### [FindEvil] Narrative report exists — 2026-04-16 18:36:27 CDT
**Result:** 

### [FindEvil] Timeline file exists — 2026-04-16 18:36:27 CDT
**Result:** 

### [FindEvil] device_map/user_map populated (EH-1 fix) — 2026-04-16 18:36:27 CDT
**Result:** 

## Batch 2: API Endpoint Tests
### [API] GET / — 2026-04-16 18:36:27 CDT
**Result:** FAIL
**Detail:** Got: 

### [API] GET /cases — 2026-04-16 18:36:28 CDT
**Result:** PASS
**Detail:** 2 cases found

### [API] GET /tools — 2026-04-16 18:36:28 CDT
**Result:** PASS

### [API] POST /chat (forensic question) — 2026-04-16 18:36:28 CDT
**Result:** PASS

### [API] GET /find-evil/status/nonexistent — 2026-04-16 18:36:28 CDT
**Result:** 404
**Detail:** Should be 404

### [API] GET /investigation/status/evidence (CI-8 fix) — 2026-04-16 18:36:28 CDT
**Result:** 

## Batch 3: Security Tests
### [Security] Path traversal in evidence_path (SEC-1) — 2026-04-16 18:36:29 CDT
**Result:** ALLOWED - BUG!

### [Security] Command injection in evidence_path — 2026-04-16 18:36:29 CDT
**Result:** ALLOWED - BUG!

### [Security] Path traversal via /run-tool (SEC-1) — 2026-04-16 18:36:29 CDT
**Result:** 

## Batch 4: Tool Allowlist Tests
### [Allowlist] bash tool blocked (EH-5) — 2026-04-16 18:36:29 CDT
**Result:** 

### [Allowlist] mmls tool allowed (EH-5) — 2026-04-16 18:36:29 CDT
**Result:** 

## Batch 5: Edge Cases
### [EdgeCase] Find Evil on empty directory — 2026-04-16 18:36:30 CDT
**Result:** Job started: fe-98f13892f55d

### [EdgeCase] Empty dir job progress — 2026-04-16 18:36:40 CDT
**Result:** 0.0%

### [EdgeCase] Find Evil on non-existent path — 2026-04-16 18:36:40 CDT
**Result:** running

## Batch 6: Specialist Methods
### [Specialist] list_deleted (TC-1/2 fix) — 2026-04-16 18:36:40 CDT
**Result:** 

### [Specialist] analyze_partition_table on hacking case — 2026-04-16 18:36:41 CDT
**Result:** 

### [Specialist] analyze_filesystem on hacking case — 2026-04-16 18:36:41 CDT
**Result:** 

## Batch 7: FindingsWriter Cap Test
### [FindingsWriter] all_records() with 60k records (EH-2 fix) — 2026-04-16 18:36:43 CDT
**Result:** [GEOFF] FindingsWriter: in-memory cap (50000) reached; further findings written to disk only.

### [FindingsWriter] all_records() with 60k records (EH-2 fix) — 2026-04-16 18:36:43 CDT
**Result:** [GEOFF] FindingsWriter: in-memory cap (50000) reached; further findings written to disk only.

### [FindingsWriter] all_records() with 60k records (EH-2 fix) — 2026-04-16 18:36:43 CDT
**Result:** [GEOFF] FindingsWriter: in-memory cap (50000) reached; further findings written to disk only.

### [FindingsWriter] all_records() with 60k records (EH-2 fix) — 2026-04-16 18:36:43 CDT
**Result:** RESULT: 60000 records returned (expected 60000)

### [FindingsWriter] all_records() with 60k records (EH-2 fix) — 2026-04-16 18:36:43 CDT
**Result:** EH2_FIX: PASS

## Batch 8: Report Analysis
- File "<string>", line 5
- print(f'Severity: {r.get(severity,?)}')
- ^
- SyntaxError: f-string: expecting '=', or '!', or ':', or '}'

## Summary
Completed: 2026-04-16 18:36:43 CDT
Total test batches: 8

## Batch 9: Corrected Security Tests (proper JSON key: evidence_dir)
### [Security] Path traversal via evidence_dir (SEC-1) — $(date)
**Result:** BLOCKED ✅ — "Evidence path resolves outside allowed directories: '../../../etc/passwd' → /etc/passwd"

### [Security] Command injection via evidence_dir — $(date)
**Result:** BLOCKED ✅ — "Evidence path contains unsafe characters and will not be processed: '/tmp; rm -rf /'"

### [Security] Absolute path outside allowed dirs — $(date)
**Result:** BLOCKED
**Detail:** Evidence path resolves outside allowed directories: '/etc/passwd' → /etc/passwd

- Severity: CRITICAL
- Steps completed: 64
- Steps failed: 31
- device_map entries: 2
- user_map entries: 0
- Narrative path: /home/sansforensics/evidence-storage/cases/evidence_findevil_20260416_232800/reports/narrative_report.md
- Playbooks run: 15
- Git commits: 8

## Batch 9+ completed: Thu 16 Apr 2026 06:37:14 PM CDT

---
## QA Run: 2026-04-16 19:31:02 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-b7030cabf8c6","message":"Find Evil job started. Poll /find-evil/status/fe-b7030cabf8c6 for progress.","status":"running"}


---
## QA Run: 2026-04-16 19:45:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-16 20:00:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-16 20:15:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-16 20:30:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-0aa8aa9b75c4","message":"Find Evil job started. Poll /find-evil/status/fe-0aa8aa9b75c4 for progress.","status":"running"}


---
## QA Run: 2026-04-16 20:45:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '../../../etc/passwd' \u2192 /etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-17T01:45:02.015527","tool":"fls"}


---
## QA Run: 2026-04-16 21:00:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp' \u2192 /tmp","status":"error"}


---
## QA Run: 2026-04-16 21:15:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-564d23df9e42","message":"Find Evil job started. Poll /find-evil/status/fe-564d23df9e42 for progress.","status":"running"}


---
## QA Run: 2026-04-16 21:30:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-16 21:45:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-16 22:00:02 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '../../../etc/passwd' \u2192 /etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-17T03:00:02.262805","tool":"fls"}


---
## QA Run: 2026-04-16 22:15:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-41a4ae6875c1","message":"Find Evil job started. Poll /find-evil/status/fe-41a4ae6875c1 for progress.","status":"running"}


---
## QA Run: 2026-04-16 22:30:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-16 22:45:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-e45af14a0b3b","message":"Find Evil job started. Poll /find-evil/status/fe-e45af14a0b3b for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-276b6885e569","message":"Find Evil job started. Poll /find-evil/status/fe-276b6885e569 for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-88ef5520d436","message":"Find Evil job started. Poll /find-evil/status/fe-88ef5520d436 for progress.","status":"running"}


---
## QA Run: 2026-04-16 23:00:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 0
- **Result:** {"response":"```\nG.E.O.F.F. FORENSIC REPORT - PARTITION ANALYSIS\nCase: Hacking Case Evidence\nTool: SleuthKit/mmls\nExecution Time: [TIMESTAMP]\nGit Commit Hash: [AUTO-GENERATED]\n==================================================\n\nCOMMAND EXECUTED:\nmmls -t dos -b hacking_case_evidence.dd\n\nOUTPUT:\nDOS Partition Table\nOffset Sector: 0\nUnits are in 512-byte sectors\n\n      Slot      Start        End          Length       Description\n000:  Meta      0000000000   0000000000   0000000001 


---
## QA Run: 2026-04-16 23:15:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '../../../etc/passwd' \u2192 /etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-17T04:15:01.419215","tool":"fls"}


---
## QA Run: 2026-04-16 23:30:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '../../../etc/passwd' \u2192 /etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-17T04:30:02.174489","tool":"fls"}


---
## QA Run: 2026-04-16 23:45:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-17 00:00:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 28
- **Result:** 

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-17 00:15:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 7
- **Result:** 

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 00:30:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 7
- **Result:** 

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 00:45:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 7
- **Result:** 

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 01:00:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 01:15:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 7
- **Result:** 

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 01:30:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.analyze_partition_table
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"analyze_partition_table\", \"params\": {\"disk_image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\"}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 01:45:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 02:00:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.analyze_filesystem
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"analyze_filesystem\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 02:15:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 02:30:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 02:45:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 7
- **Result:** 

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 03:00:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 7
- **Result:** 

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 03:15:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 03:30:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 03:45:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 04:00:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 04:15:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 7
- **Result:** 

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 04:30:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 04:45:02 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 7
- **Result:** 

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 05:00:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 05:15:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 05:30:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"How do I detect timestomping?\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 05:45:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 06:00:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 06:15:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 06:30:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 06:45:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 7
- **Result:** 

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 07:00:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 07:15:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 07:30:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_files
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 07:45:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"How do I detect timestomping?\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 08:00:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 08:15:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_deleted
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_deleted\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 08:30:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 7
- **Result:** 

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 08:45:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 7
- **Result:** 

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 09:00:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What is the difference between mmls and fsstat?\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 09:15:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 09:30:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 09:45:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 10:00:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-17 10:15:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-4bd897c81f3a","message":"Find Evil job started. Poll /find-evil/status/fe-4bd897c81f3a for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-c2ee1b36a85a","message":"Find Evil job started. Poll /find-evil/status/fe-c2ee1b36a85a for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-f9c5e4d82bee","message":"Find Evil job started. Poll /find-evil/status/fe-f9c5e4d82bee for progress.","status":"running"}


---
## QA Run: 2026-04-17 10:30:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '../../../etc/passwd' \u2192 /etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-17T15:30:02.000168","tool":"fls"}


---
## QA Run: 2026-04-17 10:45:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 7
- **Result:** 

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 200
