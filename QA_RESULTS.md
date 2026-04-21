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

---
## QA Run: 2026-04-17 11:00:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-d0d90b128d30","message":"Find Evil job started. Poll /find-evil/status/fe-d0d90b128d30 for progress.","status":"running"}


---
## QA Run: 2026-04-17 11:15:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found

---
## QA Run: 2026-04-17 11:30:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-17 11:45:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-17 12:00:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found

---
## QA Run: 2026-04-17 12:15:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 0
- **Result:** {"response":"```\nG.E.O.F.F. FORENSIC REPORT - PARTITION ANALYSIS\nCase: Hacking Case Evidence\nTool: SleuthKit mmls v4.6.3\nExecution Time: 2024-01-15 14:30:22 UTC\nGit Commit: 8f3a2c1b\n\n==================================================\nPARTITION TABLE ANALYSIS - MMLS OUTPUT\n==================================================\n\nDOS Partition Table\nOffset Sector: 0\nUnits are in 512-byte sectors\n\n      Slot      Start        End          Length       Description\n000:  Meta      00000000


---
## QA Run: 2026-04-17 12:30:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-17 12:45:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 0
- **Result:** {"response":"---\n**G.E.O.F.F. FORENSIC REPORT - PARTITION ANALYSIS**\n**Case:** Hacking Case Evidence  \n**Tool:** SleuthKit (`mmls`)  \n**Action:** Partition table examination of disk evidence  \n**Timestamp:** `$(date -u)`  \n\n---\n\n### **EXECUTION LOG**\n```bash\nmmls -t dos -o 0 ./evidence.dd\n```\n\n### **FINDINGS: DOS/MBR PARTITION TABLE**\n```\nDOS Partition Table\nOffset Sector: 0\nUnits are in 512-byte sectors\n\n      Slot      Start        End          Length       Description\n000


---
## QA Run: 2026-04-17 13:00:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-70d3314dbdc9","message":"Find Evil job started. Poll /find-evil/status/fe-70d3314dbdc9 for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-b0135b7cf59c","message":"Find Evil job started. Poll /find-evil/status/fe-b0135b7cf59c for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-e96369308513","message":"Find Evil job started. Poll /find-evil/status/fe-e96369308513 for progress.","status":"running"}


---
## QA Run: 2026-04-17 13:15:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_files_mactime
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files_mactime\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Cannot determine file system type\n","stdout":"","timestamp":"2026-04-17T18:15:02.222093","tool":"fls"}


---
## QA Run: 2026-04-17 13:30:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp' \u2192 /tmp","status":"error"}


---
## QA Run: 2026-04-17 13:45:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_deleted
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_deleted\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Cannot determine file system type\n","stdout":"","timestamp":"2026-04-17T18:45:01.721722","tool":"fls"}


---
## QA Run: 2026-04-17 14:00:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-57414fa69d67","message":"Find Evil job started. Poll /find-evil/status/fe-57414fa69d67 for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-6a4cde948cee","message":"Find Evil job started. Poll /find-evil/status/fe-6a4cde948cee for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-0e91f7a78328","message":"Find Evil job started. Poll /find-evil/status/fe-0e91f7a78328 for progress.","status":"running"}


---
## QA Run: 2026-04-17 14:15:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '../../../etc/passwd' \u2192 /etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-17T19:15:01.902912","tool":"fls"}


---
## QA Run: 2026-04-17 14:30:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-17 14:45:01 CDT — Scenario: report_analysis
### Report analysis
- **Command:** `ssh -p 2222 sansforensics@localhost "python3 -c \"
import json
with open('/home/sansforensics/evidence-storage/cases/hacking-case_findevil_20260417_180010/reports/find_evil_report.json') as f:
    r = json.load(f)
print(f'Severity: {r.get(\"severity\",\"?\")}')
print(f'Steps: {r.get(\"steps_completed\",0)} ok, {r.get(\"steps_failed\",0)} fail')
print(f'device_map: {len(r.get(\"device_map\",{}))} entries')
print(f'user_map: {len(r.get(\"user_map\",{}))} entries')
print(f'Narrative: {\"yes\" if r.get(\"narrative_report_path\") else \"MISSING\"}')
print(f'Playbooks: {r.get(\"playbooks_total\",0)}')
\""`
- **Exit code:** 1
- **Result:**   File "<string>", line 5
    print(f'Severity: {r.get(severity,?)}')
                            ^
SyntaxError: f-string: expecting '=', or '!', or ':', or '}'


---
## QA Run: 2026-04-17 15:00:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-a9aa51e64daa","message":"Find Evil job started. Poll /find-evil/status/fe-a9aa51e64daa for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-b99bde988312","message":"Find Evil job started. Poll /find-evil/status/fe-b99bde988312 for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-f0b02fb57460","message":"Find Evil job started. Poll /find-evil/status/fe-f0b02fb57460 for progress.","status":"running"}


---
## QA Run: 2026-04-17 15:15:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-c22fe1398f8d","message":"Find Evil job started. Poll /find-evil/status/fe-c22fe1398f8d for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-57e5ccf4ca14","message":"Find Evil job started. Poll /find-evil/status/fe-57e5ccf4ca14 for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-e397617f0047","message":"Find Evil job started. Poll /find-evil/status/fe-e397617f0047 for progress.","status":"running"}


---
## QA Run: 2026-04-17 15:30:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 28
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 200

---
## QA Run: 2026-04-17 15:45:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-17 16:00:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-17 16:15:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 200

---
## QA Run: 2026-04-17 16:30:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Explain the MITRE ATT&CK kill chain\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-17 16:45:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Explain the MITRE ATT&CK kill chain\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-17 17:00:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What IOCs should I look for in a ransomware case?\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-17 17:15:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-fb61d00db364","message":"Find Evil job started. Poll /find-evil/status/fe-fb61d00db364 for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-15a459e2284a","message":"Find Evil job started. Poll /find-evil/status/fe-15a459e2284a for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-de7a8ac1ac99","message":"Find Evil job started. Poll /find-evil/status/fe-de7a8ac1ac99 for progress.","status":"running"}


---
## QA Run: 2026-04-17 17:30:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-17c56dd9bc3e","message":"Find Evil job started. Poll /find-evil/status/fe-17c56dd9bc3e for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-2340c0b20ad7","message":"Find Evil job started. Poll /find-evil/status/fe-2340c0b20ad7 for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-d00ef05e9787","message":"Find Evil job started. Poll /find-evil/status/fe-d00ef05e9787 for progress.","status":"running"}


---
## QA Run: 2026-04-17 17:45:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-17 18:00:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_deleted
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_deleted\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Cannot determine file system type\n","stdout":"","timestamp":"2026-04-17T23:00:01.935291","tool":"fls"}


---
## QA Run: 2026-04-17 18:15:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 28
- **Result:** 

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-7154e5d2b234","message":"Find Evil job started. Poll /find-evil/status/fe-7154e5d2b234 for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-368f73dc6210","message":"Find Evil job started. Poll /find-evil/status/fe-368f73dc6210 for progress.","status":"running"}


---
## QA Run: 2026-04-17 18:30:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp' \u2192 /tmp","status":"error"}


---
## QA Run: 2026-04-17 18:45:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 28
- **Result:** 

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-17 19:00:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-17 19:15:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.analyze_filesystem
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"analyze_filesystem\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Cannot determine file system type\n","stdout":"","timestamp":"2026-04-18T00:15:01.991952","tool":"fsstat"}


---
## QA Run: 2026-04-17 19:30:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-17 19:45:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-17 20:00:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-6d6fe4a6ed9f","message":"Find Evil job started. Poll /find-evil/status/fe-6d6fe4a6ed9f for progress.","status":"running"}


---
## QA Run: 2026-04-17 20:15:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-17 20:30:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp' \u2192 /tmp","status":"error"}


---
## QA Run: 2026-04-17 20:45:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What is the difference between mmls and fsstat?\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-17 21:00:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-3834574c5445","message":"Find Evil job started. Poll /find-evil/status/fe-3834574c5445 for progress.","status":"running"}


---
## QA Run: 2026-04-17 21:15:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-f97af72d6f61","message":"Find Evil job started. Poll /find-evil/status/fe-f97af72d6f61 for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-d4e7596f566a","message":"Find Evil job started. Poll /find-evil/status/fe-d4e7596f566a for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-48d772bf4bb9","message":"Find Evil job started. Poll /find-evil/status/fe-48d772bf4bb9 for progress.","status":"running"}


---
## QA Run: 2026-04-17 21:30:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-17 21:45:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 0
- **Result:** {"response":"**G.E.O.F.F. Forensic Analysis Report**\n\n**Case:** Hacking Case Evidence  \n**Operation:** Partition Table Analysis  \n**Tool:** SleuthKit mmls (media management list)  \n**Evidence:** Disk image (assumed raw/dd format)\n\n---\n\n### **Command Executed**\n`mmls -t dos -i raw [evidence_file]`\n\n### **Findings**\n\nThe partition table analysis reveals the following disk structure:\n\n```\nDOS Partition Table\nOffset Sector: 0\nUnits are in 512-byte sectors\n\n      Slot      Start 


---
## QA Run: 2026-04-17 22:00:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-17 22:15:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found

---
## QA Run: 2026-04-17 22:30:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-17 22:45:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-17 23:00:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-17 23:15:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-d840cfb8f0ad","message":"Find Evil job started. Poll /find-evil/status/fe-d840cfb8f0ad for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-11b6ac4bb2e5","message":"Find Evil job started. Poll /find-evil/status/fe-11b6ac4bb2e5 for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-a6f935143275","message":"Find Evil job started. Poll /find-evil/status/fe-a6f935143275 for progress.","status":"running"}


---
## QA Run: 2026-04-17 23:30:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-3883464d0d2d","message":"Find Evil job started. Poll /find-evil/status/fe-3883464d0d2d for progress.","status":"running"}


---
## QA Run: 2026-04-17 23:45:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-18 00:00:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-4ef3373c1f52","message":"Find Evil job started. Poll /find-evil/status/fe-4ef3373c1f52 for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-4a7fa2b195b9","message":"Find Evil job started. Poll /find-evil/status/fe-4a7fa2b195b9 for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-a46180bf5c33","message":"Find Evil job started. Poll /find-evil/status/fe-a46180bf5c33 for progress.","status":"running"}


---
## QA Run: 2026-04-18 00:15:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-504fcd9360f6","message":"Find Evil job started. Poll /find-evil/status/fe-504fcd9360f6 for progress.","status":"running"}


---
## QA Run: 2026-04-18 00:30:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-18 00:45:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_files
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Cannot determine file system type\n","stdout":"","timestamp":"2026-04-18T05:45:01.931445","tool":"fls"}


---
## QA Run: 2026-04-18 01:00:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found

---
## QA Run: 2026-04-18 01:15:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-18 01:30:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-19 01:15:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 01:30:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 01:45:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 02:00:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_files
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 02:15:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 02:30:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 02:45:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What is the difference between mmls and fsstat?\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 03:00:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 03:15:01 CDT — Scenario: allowlist_bypass
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
## QA Run: 2026-04-19 03:30:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 03:45:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 04:00:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 04:15:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 04:30:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_files_mactime
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files_mactime\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 04:45:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 05:00:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 05:15:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 05:30:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_deleted
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_deleted\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 05:45:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 06:00:01 CDT — Scenario: allowlist_bypass
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
## QA Run: 2026-04-19 06:15:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 06:30:01 CDT — Scenario: concurrent_jobs
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
## QA Run: 2026-04-19 06:45:01 CDT — Scenario: allowlist_bypass
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
## QA Run: 2026-04-19 07:00:01 CDT — Scenario: command_injection
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
## QA Run: 2026-04-19 07:15:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 07:30:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What artifacts indicate persistence on Windows?\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 07:45:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 08:00:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 08:15:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 08:30:01 CDT — Scenario: command_injection
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
## QA Run: 2026-04-19 08:45:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 09:00:01 CDT — Scenario: concurrent_jobs
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
## QA Run: 2026-04-19 09:15:01 CDT — Scenario: concurrent_jobs
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
## QA Run: 2026-04-19 09:30:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 09:45:01 CDT — Scenario: command_injection
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
## QA Run: 2026-04-19 10:00:01 CDT — Scenario: path_traversal
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
## QA Run: 2026-04-19 10:15:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 10:30:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 10:45:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_files_mactime
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files_mactime\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 11:00:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 11:15:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 11:30:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 11:45:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 12:00:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"How do I detect timestomping?\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 12:15:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 12:30:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 12:45:01 CDT — Scenario: path_traversal
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
## QA Run: 2026-04-19 13:00:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 13:15:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 13:30:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 13:45:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What IOCs should I look for in a ransomware case?\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 14:00:01 CDT — Scenario: concurrent_jobs
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
## QA Run: 2026-04-19 14:15:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 14:30:01 CDT — Scenario: concurrent_jobs
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
## QA Run: 2026-04-19 14:45:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 15:00:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 15:15:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 15:30:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 15:45:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_files_mactime
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files_mactime\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 16:00:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 16:15:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 16:30:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What artifacts indicate persistence on Windows?\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 16:45:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 17:00:01 CDT — Scenario: command_injection
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
## QA Run: 2026-04-19 17:15:01 CDT — Scenario: command_injection
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
## QA Run: 2026-04-19 17:30:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 17:45:01 CDT — Scenario: allowlist_bypass
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
## QA Run: 2026-04-19 18:00:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_deleted
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_deleted\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 18:15:01 CDT — Scenario: path_traversal
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
## QA Run: 2026-04-19 18:30:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 18:45:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 19:00:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.analyze_filesystem
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"analyze_filesystem\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 19:15:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 19:30:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 19:45:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"How do I detect timestomping?\"}'"`
- **Exit code:** 7
- **Result:** 

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 20:00:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 20:15:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-19 20:30:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 255
- **Result:** ssh: connect to host localhost port 2222: Connection refused

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 
- Attempting restart...
- Restart result: HTTP 

---
## QA Run: 2026-04-19 20:45:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 255
- **Result:** ssh: connect to host localhost port 2222: Connection refused

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 255
- **Result:** ssh: connect to host localhost port 2222: Connection refused

### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 
- Attempting restart...
- Restart result: HTTP 

---
## QA Run: 2026-04-19 21:00:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 
- Attempting restart...
- Restart result: HTTP 

---
## QA Run: 2026-04-19 21:15:01 CDT — Scenario: command_injection
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
## QA Run: 2026-04-19 21:30:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found

---
## QA Run: 2026-04-19 21:45:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/home/sansforensics/evidence-storage/evidence/../../../etc/passwd' \u2192 /home/etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-20T02:45:01.640997","tool":"fls"}


---
## QA Run: 2026-04-19 22:00:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What artifacts indicate persistence on Windows?\"}'"`
- **Exit code:** 0
- **Result:** {"response":"Having trouble connecting to Ollama. Check OLLAMA_URL setting and ensure Ollama is running."}


---
## QA Run: 2026-04-19 22:15:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-19 22:30:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-19 22:45:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-02525e1fd026","message":"Find Evil job started. Poll /find-evil/status/fe-02525e1fd026 for progress.","status":"running"}


---
## QA Run: 2026-04-19 23:00:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.list_files
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Cannot determine file system type\n","stdout":"","timestamp":"2026-04-20T04:00:01.997520","tool":"fls"}


---
## QA Run: 2026-04-19 23:15:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-1dc44e9fcd4b","message":"Find Evil job started. Poll /find-evil/status/fe-1dc44e9fcd4b for progress.","status":"running"}


---
## QA Run: 2026-04-19 23:30:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-2746f6273c4c","message":"Find Evil job started. Poll /find-evil/status/fe-2746f6273c4c for progress.","status":"running"}


---
## QA Run: 2026-04-19 23:45:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.analyze_filesystem
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"analyze_filesystem\", \"params\": {\"image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\", \"offset\": 0}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Cannot determine file system type\n","stdout":"","timestamp":"2026-04-20T04:45:02.153208","tool":"fsstat"}


---
## QA Run: 2026-04-20 00:00:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-20 00:15:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found

---
## QA Run: 2026-04-20 00:30:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-20 00:45:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-20 01:00:01 CDT — Scenario: single_dd_image
### Find Evil on single DD image
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-d090e5201f4f","message":"Find Evil job started. Poll /find-evil/status/fe-d090e5201f4f for progress.","status":"running"}


---
## QA Run: 2026-04-20 01:15:01 CDT — Scenario: individual_specialist
### Specialist: sleuthkit.analyze_partition_table
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"analyze_partition_table\", \"params\": {\"disk_image\": \"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001\"}}'"`
- **Exit code:** 0
- **Result:** {"disk_image":"/home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001","partition_count":1,"partitions":[{"description":"NTFS / exFAT (0x07)","end_sector":9510479,"length_sectors":9510417,"start_sector":63}],"raw_output":"DOS Partition Table\nOffset Sector: 0\nUnits are in 512-byte sectors\n\n      Slot      Start        End          Length       Description\n000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n001:  -------   0000000000   0000000062   00000


---
## QA Run: 2026-04-20 17:30:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-20 17:45:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Explain the MITRE ATT&CK kill chain\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-20 18:00:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-20 18:15:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-20 18:30:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What IOCs should I look for in a ransomware case?\"}'"`
- **Exit code:** 0
- **Result:** {"response":"**Hypothesis 1:** Testing whether specific ransomware Indicators of Compromise (IOCs) (such as specific file extensions, ransom note filenames, or malicious IP addresses) can be identified from the current context.\n\n**Evidence:** Review of the provided context reveals only a list of available forensic capabilities and tools (e.g., SleuthKit, Volatility, Strings, RegRipper, REMnux). No case data, disk images, memory dumps, log files, or specific artifact outputs have been supplied.


---
## QA Run: 2026-04-20 18:45:02 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-20 19:00:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp' \u2192 /tmp","status":"error"}


---
## QA Run: 2026-04-20 19:15:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-4302be136fcb","message":"Find Evil job started. Poll /find-evil/status/fe-4302be136fcb for progress.","status":"running"}


---
## QA Run: 2026-04-20 19:30:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-20 19:45:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-20 20:00:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/home/sansforensics/evidence-storage/evidence/../../../etc/passwd' \u2192 /home/etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-21T01:00:02.049717","tool":"fls"}


---
## QA Run: 2026-04-20 20:15:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What IOCs should I look for in a ransomware case?\"}'"`
- **Exit code:** 0
- **Result:** {"response":"**Hypothesis 1:** Testing whether specific ransomware Indicators of Compromise (IOCs)\u2014such as exact ransom note filenames, encrypted file extensions, or specific destructive commands\u2014can be identified.\n\n**Evidence:** The current context provides a list of available forensic capabilities and tools (e.g., SleuthKit, Volatility, RegRipper, Strings), but contains no specific case data, disk images, memory captures, or actual forensic artifacts. \n\n**Assessment:** The curren


---
## QA Run: 2026-04-20 20:30:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-20 20:45:01 CDT — Scenario: individual_specialist

---
## QA Run: 2026-04-20 21:00:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-20 21:15:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-20 21:30:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-20 21:45:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 0
- **Result:** {"response":"Error: [Errno 2] No such file or directory: '/tmp/geoff-validations/validations'"}


---
## QA Run: 2026-04-20 22:00:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp' \u2192 /tmp","status":"error"}


---
## QA Run: 2026-04-20 22:15:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 0
- **Result:** {"response":"Error: [Errno 2] No such file or directory: '/tmp/geoff-validations/validations'"}


---
## QA Run: 2026-04-20 22:30:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-20 22:45:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-2da5799a79a8","message":"Find Evil job started. Poll /find-evil/status/fe-2da5799a79a8 for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-10de00b16c8e","message":"Find Evil job started. Poll /find-evil/status/fe-10de00b16c8e for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-98ec565fb390","message":"Find Evil job started. Poll /find-evil/status/fe-98ec565fb390 for progress.","status":"running"}


---
## QA Run: 2026-04-20 23:00:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/home/sansforensics/evidence-storage/evidence/../../../etc/passwd' \u2192 /home/etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-21T04:00:01.838844","tool":"fls"}


---
## QA Run: 2026-04-20 23:15:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/home/sansforensics/evidence-storage/evidence/../../../etc/passwd' \u2192 /home/etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-21T04:15:01.415156","tool":"fls"}


---
## QA Run: 2026-04-20 23:30:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-785dc207fb3f","message":"Find Evil job started. Poll /find-evil/status/fe-785dc207fb3f for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-01e3cfac79e7","message":"Find Evil job started. Poll /find-evil/status/fe-01e3cfac79e7 for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-49fce141ef88","message":"Find Evil job started. Poll /find-evil/status/fe-49fce141ef88 for progress.","status":"running"}


---
## QA Run: 2026-04-20 23:45:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-21 00:00:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What artifacts indicate persistence on Windows?\"}'"`
- **Exit code:** 0
- **Result:** {"response":"Error: [Errno 2] No such file or directory: '/tmp/geoff-validations/validations'"}


---
## QA Run: 2026-04-21 00:15:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/home/sansforensics/evidence-storage/evidence/../../../etc/passwd' \u2192 /home/etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-21T05:15:01.668598","tool":"fls"}


---
## QA Run: 2026-04-21 00:30:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-5b520982029e","message":"Find Evil job started. Poll /find-evil/status/fe-5b520982029e for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-d31236923459","message":"Find Evil job started. Poll /find-evil/status/fe-d31236923459 for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-60564cb9cc98","message":"Find Evil job started. Poll /find-evil/status/fe-60564cb9cc98 for progress.","status":"running"}


---
## QA Run: 2026-04-21 00:45:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp' \u2192 /tmp","status":"error"}


---
## QA Run: 2026-04-21 01:00:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 01:15:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-21 01:30:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-21 01:45:01 CDT — Scenario: concurrent_jobs
### Concurrent job 1 (hacking case)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/hacking-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/hacking-case","job_id":"fe-b914b3747f7a","message":"Find Evil job started. Poll /find-evil/status/fe-b914b3747f7a for progress.","status":"running"}

### Concurrent job 2 (data leakage)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-0b2984befd0e","message":"Find Evil job started. Poll /find-evil/status/fe-0b2984befd0e for progress.","status":"running"}

### Concurrent job 3 (full evidence dir)
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence","job_id":"fe-894435b02474","message":"Find Evil job started. Poll /find-evil/status/fe-894435b02474 for progress.","status":"running"}


---
## QA Run: 2026-04-21 02:00:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-21 02:15:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 02:30:01 CDT — Scenario: chat_tool_request
### Chat: tool request
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"Run mmls on the hacking case evidence\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-21 02:45:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/home/sansforensics/evidence-storage/evidence/../../../etc/passwd' \u2192 /home/etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-21T07:45:01.611953","tool":"fls"}


---
## QA Run: 2026-04-21 03:00:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 03:15:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 03:30:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What artifacts indicate persistence on Windows?\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-21 03:45:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-21 04:00:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp' \u2192 /tmp","status":"error"}


---
## QA Run: 2026-04-21 04:15:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"How do I detect timestomping?\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-21 04:30:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 04:45:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-21 05:00:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-21 05:15:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 05:30:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-21 05:45:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 06:00:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"How do I detect timestomping?\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-21 06:15:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-2c0fe5e1591f","message":"Find Evil job started. Poll /find-evil/status/fe-2c0fe5e1591f for progress.","status":"running"}


---
## QA Run: 2026-04-21 06:30:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 06:45:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-f99dfc467c92","message":"Find Evil job started. Poll /find-evil/status/fe-f99dfc467c92 for progress.","status":"running"}


---
## QA Run: 2026-04-21 07:00:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-21 07:15:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-21 07:30:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-21 07:45:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-21 08:00:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-21 08:15:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp' \u2192 /tmp","status":"error"}


---
## QA Run: 2026-04-21 08:30:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-21 08:45:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-21 09:00:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 09:15:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-21 09:30:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/home/sansforensics/evidence-storage/evidence/../../../etc/passwd' \u2192 /home/etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-21T14:30:02.092175","tool":"fls"}


---
## QA Run: 2026-04-21 09:45:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 10:00:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-74a024aacf78","message":"Find Evil job started. Poll /find-evil/status/fe-74a024aacf78 for progress.","status":"running"}


---
## QA Run: 2026-04-21 10:15:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-21 10:30:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-21 10:45:02 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 11:00:01 CDT — Scenario: edge_case_non_image
### Find Evil on non-image file
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp' \u2192 /tmp","status":"error"}


---
## QA Run: 2026-04-21 11:15:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found
### ⚠️ GEOFF HEALTH CHECK FAILED
- HTTP status: 000
- Attempting restart...
- Restart result: HTTP 000

---
## QA Run: 2026-04-21 11:30:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-21 11:45:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-21 12:00:01 CDT — Scenario: path_traversal
### Path traversal attempt
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"../../../etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/home/sansforensics/evidence-storage/evidence/../../../etc/passwd' \u2192 /home/etc/passwd","status":"error"}

### Path traversal via run-tool
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/shadow\"}}'"`
- **Exit code:** 0
- **Result:** {"returncode":1,"status":"error","stderr":"Error opening image file (raw_open: file \"/etc/shadow\" - Permission denied)\n","stdout":"","timestamp":"2026-04-21T17:00:02.381232","tool":"fls"}


---
## QA Run: 2026-04-21 12:15:01 CDT — Scenario: command_injection
### Command injection in evidence_dir
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp; cat /etc/passwd\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp; cat /etc/passwd'","status":"error"}

### Command injection via pipe
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp | id\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path contains unsafe characters and will not be processed: '/tmp | id'","status":"error"}


---
## QA Run: 2026-04-21 12:30:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found

---
## QA Run: 2026-04-21 12:45:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What is the difference between mmls and fsstat?\"}'"`
- **Exit code:** 0
- **Result:** {"response":"**Hypothesis** \u2014 Testing whether `mmls` and `fsstat` serve distinct forensic functions based on the provided system documentation.\n\n**Evidence** \u2014 \n1. Under \"Available forensic tools,\" the context explicitly defines `mmls` with the descriptor \"(partition)\" and `fsstat` with the descriptor \"(filesystem)\".\n2. Under \"Disk Forensics (SleuthKit),\" the system capabilities are listed as \"Partition analysis\" and \"filesystem statistics,\" corresponding to the respect


---
## QA Run: 2026-04-21 13:00:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-21 13:15:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-21 13:30:01 CDT — Scenario: empty_directory
### Find Evil on empty directory
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/tmp/qa_empty_*\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/tmp/qa_empty_*' \u2192 /tmp/qa_empty_*","status":"error"}


---
## QA Run: 2026-04-21 13:45:01 CDT — Scenario: report_analysis
- **SKIPPED:** No recent reports found

---
## QA Run: 2026-04-21 14:00:01 CDT — Scenario: command_injection
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
## QA Run: 2026-04-21 14:15:01 CDT — Scenario: missing_evidence
### Find Evil on non-existent path
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/nonexistent/path/xyz123\"}'"`
- **Exit code:** 0
- **Result:** {"error":"Evidence path resolves outside allowed directories: '/nonexistent/path/xyz123' \u2192 /nonexistent/path/xyz123","status":"error"}


---
## QA Run: 2026-04-21 14:30:01 CDT — Scenario: allowlist_bypass
### Allowlist: bash bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"bash\", \"args\": [\"-c\", \"id\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}

### Allowlist: python bypass
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/run-tool -H 'Content-Type: application/json' -d '{\"module\": \"sleuthkit\", \"function\": \"list_files\", \"params\": {\"image\": \"/etc/passwd\", \"tool\": \"python3\", \"args\": [\"-c\", \"import os; os.system('id')\"]}}'"`
- **Exit code:** 0
- **Result:** {"error":"SLEUTHKIT_Specialist.list_files() got an unexpected keyword argument 'tool'","status":"error"}


---
## QA Run: 2026-04-21 14:45:01 CDT — Scenario: single_dd_image
- **SKIPPED:** No DD images found

---
## QA Run: 2026-04-21 15:00:01 CDT — Scenario: e01_segments
### Find Evil on E01 segments
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/home/sansforensics/evidence-storage/evidence/data-leakage-case\"}'"`
- **Exit code:** 0
- **Result:** {"evidence_dir":"/home/sansforensics/evidence-storage/evidence/data-leakage-case","job_id":"fe-0dbfadd0bedb","message":"Find Evil job started. Poll /find-evil/status/fe-0dbfadd0bedb for progress.","status":"running"}


---
## QA Run: 2026-04-21 15:15:01 CDT — Scenario: chat_forensic_question
### Chat: forensic question
- **Command:** `ssh -p 2222 sansforensics@localhost "curl -s -m 120 -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\": \"What artifacts indicate persistence on Windows?\"}'"`
- **Exit code:** 28
- **Result:** 


---
## QA Run: 2026-04-21 15:30:01 CDT — Scenario: allowlist_bypass
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
