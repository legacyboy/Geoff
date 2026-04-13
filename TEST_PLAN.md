# Geoff Test Plan

## Overview
This document outlines the test cases for Project Geoff (GEOFF - Git-backed Evidence Operations Forensic Framework).

---

## 1. Find Evil Feature Tests

### Test 1.1: Basic Find Evil Execution
**Objective:** Verify Find Evil runs on EnCase image
**Evidence:** `/home/sansforensics/evidence-storage/evidence/Dell/`
**Steps:**
1. Run: `curl -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{"evidence_dir": "/home/sansforensics/evidence-storage/evidence/Dell"}'`
2. Check response contains `evil_found`, `playbooks_run`, `findings_detail`
**Expected:** JSON response with findings
**Pass Criteria:** Response is valid JSON, contains required fields

### Test 1.2: Windows Detection
**Objective:** Verify OS detection works
**Steps:** Run Find Evil, check `os_type` field
**Expected:** `os_type` = "windows" for Windows XP image
**Pass Criteria:** OS correctly identified

### Test 1.3: Partition Table Analysis
**Objective:** Verify SleuthKit mmls works
**Steps:** Run Find Evil, check for partition findings
**Expected:** NTFS partition detected at correct offset (sector 63)
**Pass Criteria:** Partition table successfully parsed

### Test 1.4: Filesystem Analysis
**Objective:** Verify fsstat works on mounted image
**Steps:** Run Find Evil, check filesystem findings
**Expected:** NTFS filesystem details extracted
**Pass Criteria:** Filesystem metadata extracted

### Test 1.5: File Listing
**Objective:** Verify fls works
**Steps:** Run Find Evil, check file listings
**Expected:** Windows directories listed (Documents and Settings, etc.)
**Pass Criteria:** File listing populated

### Test 1.6: String Extraction
**Objective:** Verify strings extraction
**Steps:** Run Find Evil, check for extracted strings
**Expected:** Strings output present
**Pass Criteria:** Strings extracted from image

### Test 1.7: Evidence Score
**Objective:** Verify evidence scoring
**Steps:** Run Find Evil on valid evidence
**Expected:** `evidence_score` > 0
**Pass Criteria:** Score calculated

### Test 1.8: Playbook Selection
**Objective:** Verify appropriate playbooks selected
**Steps:** Run Find Evil on Windows disk image
**Expected:** PB-SIFT-016 (Triage) and PB-SIFT-001 (Malware Hunting) run
**Pass Criteria:** Correct playbooks triggered

---

## 2. Interactive Q&A Tests

### Test 2.1: Chat Endpoint Exists
**Objective:** Verify chat API exists
**Steps:** `curl http://localhost:8080/chat`
**Expected:** JSON response or HTML interface
**Pass Criteria:** Endpoint responds

### Test 2.2: Chat with Evidence
**Objective:** Verify can ask questions about evidence
**Steps:** POST question about evidence to chat endpoint
**Expected:** Response with analysis
**Pass Criteria:** Chat returns coherent response

---

## 3. Playbook Execution Tests

### Test 3.1: Triage Playbook (PB-SIFT-016)
**Objective:** Verify triage playbook runs
**Steps:** Run Find Evil, check `playbooks_run` includes "PB-SIFT-016"
**Expected:** PB-SIFT-016 in playbooks list
**Pass Criteria:** Triage playbook executed

### Test 3.2: Malware Hunting Playbook (PB-SIFT-001)
**Objective:** Verify malware playbook runs on disk image
**Steps:** Run Find Evil, check `playbooks_run` includes "PB-SIFT-001"
**Expected:** PB-SIFT-001 in playbooks list
**Pass Criteria:** Malware playbook executed

### Test 3.3: All Playbooks Present
**Objective:** Verify all 19 playbooks exist
**Steps:** List `playbooks/` directory
**Expected:** 19 playbook files (PB-SIFT-001 through PB-SIFT-019)
**Pass Criteria:** All playbooks numbered and present

---

## 4. Web UI Tests

### Test 4.1: Main Page
**Objective:** Verify web UI loads
**Steps:** `curl http://localhost:8080/`
**Expected:** HTML page loads
**Pass Criteria:** HTTP 200 with HTML content

### Test 4.2: Find Evil Endpoint (GET)
**Objective:** Verify GET /find-evil returns info
**Steps:** `curl http://localhost:8080/find-evil`
**Expected:** JSON with endpoint description and playbooks list
**Pass Criteria:** Valid JSON with `name` and `playbooks`

### Test 4.3: Find Evil Endpoint (POST)
**Objective:** Verify POST /find-evil executes
**Steps:** `curl -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{"evidence_dir": "/tmp/test"}'`
**Expected:** JSON results
**Pass Criteria:** Valid JSON response

### Test 4.4: Service Status
**Objective:** Verify systemd service is running
**Steps:** `systemctl status geoff`
**Expected:** `active (running)`
**Pass Criteria:** Service shows active

---

## 5. Installation/Deployment Tests

### Test 5.1: Clean Installation
**Objective:** Verify install.sh works on clean system
**Steps:**
1. `rm -rf ~/geoff`
2. `git clone https://github.com/legacyboy/Geoff.git ~/geoff`
3. `cd ~/geoff/installer && ./install.sh`
**Expected:** All 7 steps complete, service started
**Pass Criteria:** No errors, service running

### Test 5.2: Dependencies Installed
**Objective:** Verify all required tools present
**Steps:** Check for `python3`, `curl`, `git`, `yara`
**Expected:** All tools available
**Pass Criteria:** `which yara`, `which python3` return paths

### Test 5.3: Service Auto-Start
**Objective:** Verify service enabled for auto-start
**Steps:** `systemctl is-enabled geoff`
**Expected:** `enabled`
**Pass Criteria:** Service will start on boot

---

## 6. Security/Forensics Tools Tests

### Test 6.1: SleuthKit Tools
**Objective:** Verify TSK tools work
**Steps:**
- `mmls --help`
- `fsstat --help`
- `fls --help`
**Expected:** Help output displayed
**Pass Criteria:** Tools execute without error

### Test 6.2: YARA Scanning
**Objective:** Verify YARA installed
**Steps:** `yara --version`
**Expected:** Version number displayed
**Pass Criteria:** YARA functional

### Test 6.3: Plaso log2timeline
**Objective:** Verify Plaso installed
**Steps:** `log2timeline.py --version`
**Expected:** Version displayed
**Pass Criteria:** Plaso functional

---

## 7. NIST Hacking Case Integration

### Test 7.1: Load NIST Evidence
**Objective:** Verify EnCase images load correctly
**Evidence:** `4Dell_Latitude_CPi.E01`, `4Dell_Latitude_CPi.E02`
**Expected:** Both files present, valid E01 format
**Pass Criteria:** Images detected by `file` command

### Test 7.2: Detect Windows XP
**Objective:** Verify Windows XP detected
**Expected:** OS type = "windows"
**Pass Criteria:** Correct OS identified

### Test 7.3: Detect NTFS Filesystem
**Objective:** Verify NTFS detected
**Expected:** Filesystem type = "NTFS"
**Pass Criteria:** NTFS correctly identified

### Test 7.4: Find Dell Directory Structure
**Objective:** Verify Windows directories detected
**Expected:** "Documents and Settings", "All Users" in file listing
**Pass Criteria:** Standard Windows dirs found

---

## Test Execution Checklist

- [ ] Test 1.1: Basic Find Evil
- [ ] Test 1.2: Windows Detection
- [ ] Test 1.3: Partition Table
- [ ] Test 1.4: Filesystem Analysis
- [ ] Test 1.5: File Listing
- [ ] Test 1.6: String Extraction
- [ ] Test 1.7: Evidence Score
- [ ] Test 1.8: Playbook Selection
- [ ] Test 2.1: Chat Endpoint
- [ ] Test 3.3: All Playbooks Present
- [ ] Test 4.1: Main Page
- [ ] Test 4.2: Find Evil GET
- [ ] Test 4.3: Find Evil POST
- [ ] Test 4.4: Service Status
- [ ] Test 5.1: Clean Install
- [ ] Test 5.2: Dependencies
- [ ] Test 5.3: Service Auto-Start
- [ ] Test 6.1: SleuthKit
- [ ] Test 6.2: YARA
- [ ] Test 6.3: Plaso
- [ ] Test 7.1: NIST Evidence
- [ ] Test 7.2: Windows XP Detection
- [ ] Test 7.3: NTFS Detection
- [ ] Test 7.4: Directory Detection

---

## Expected Results Summary

| Test Category | Total | Pass | Fail |
|--------------|-------|------|------|
| Find Evil | 8 | TBD | TBD |
| Q&A | 2 | TBD | TBD |
| Playbooks | 3 | TBD | TBD |
| Web UI | 4 | TBD | TBD |
| Installation | 3 | TBD | TBD |
| Tools | 3 | TBD | TBD |
| NIST Integration | 4 | TBD | TBD |
| **Total** | **27** | | |

---

## Known Issues

1. Critic Approval shows 0% - JSON parsing needs improvement
2. Some findings have null severity - parsing logic needs work
3. YARA not installed by default on SIFT - added to installer
