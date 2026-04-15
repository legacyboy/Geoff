# PB-SIFT-000: Triage Prioritization Meta-Playbook
## Case Intake & Playbook Selection

**Objective:** Autonomous assessment of available evidence to score quality, determine incident type, and generate a weighted, optimized execution plan for all subsequent SIFT playbooks. This is the mandatory entry point for every case — no other playbook may run until PB-SIFT-000 completes and emits its execution plan.

---

### Phase 1 — Evidence Inventory & Quality Scoring
- [ ] **Asset Catalog:** Catalogue all submitted evidence (disk images, memory dumps, log archives, config exports, PCAP, mobile backups).
- [ ] **OS Identification:** Identify OS type for each image (Windows, Linux, macOS, Network Device) to route to OS-specific playbooks.
- [ ] **Acquisition Audit:** Identify acquisition method/tool and note any limitations.
- [ ] **Quality Scoring:** Assign confidence score per host:
    - **HIGH:** Full physical image + memory dump + logs.
    - **MEDIUM-HIGH:** Full physical image + logs (no memory).
    - **MEDIUM:** Logical acquisition only.
    - **LOW:** Logs only.
    - **VERY LOW:** Single artifact type.
- [ ] **Temporal Baseline:** Document image timestamps (acquisition time, system time, timezone offset).
- [ ] **Gap Analysis:** Flag missing expected evidence (e.g., missing registry hives or memory dumps).
- [ ] **Host Count:** Document number of hosts; if multi-host, queue **PB-SIFT-016** after individual runs.
- [ ] **Confidence Application:** Apply quality score to all subsequent findings.

---

### Phase 2 — Clock Skew Detection & Normalization
- [ ] **Timezone Extraction:** Extract system timezone and last known time sync status.
- [ ] **Reference Comparison:** Compare system clock against external references (email headers, network logs, NTP records).
- [ ] **Skew Calculation:** Calculate and document the clock skew offset for each host.
- [ ] **Anomaly Detection:** 
    - Flag skew > 5 mins as **ANOMALOUS** (potential timestomping).
    - Flag skew > 30 mins as **CRITICAL** (likely deliberate manipulation).
- [ ] **Normalization:** Apply normalization offset to all timestamps before timeline building.
- [ ] **Verification Status:** Mark timestamps as **UNVERIFIED** if skew cannot be determined.

---

### Phase 3 — Memory-First Rapid Analysis (CTF Technique)
When memory dump available, perform quick-win analysis before deep disk forensics:
- [ ] **Process Snapshot:** Run `vol.py windows.pslist.PsList` to get active process list.
- [ ] **Parent-Child Mapping:** Identify process trees; flag processes with unusual parents (e.g., `powershell.exe` under `winword.exe`).
- [ ] **Network State:** Run `vol.py windows.netscan.NetScan` to capture established connections at acquisition time.
- [ ] **Command Line History:** Run `vol.py windows.cmdline.CmdLine` to see command-line arguments (reveals encoded PowerShell, suspicious paths).
- [ ] **User Activity:** Run `vol.py windows.registry.userassist.UserAssist` to find recently executed programs.
- [ ] **Credential Extraction:** If suspicious privileged processes found, run `vol.py windows.hashdump.Hashdump`.
- [ ] **Suspicious Process Memory:** Flag processes with:
    - No legitimate parent (PPID = 0 except system processes)
    - Network connections to uncommon ports
    - Command lines with encoded commands (Base64, -enc, -encodedcommand)
    - Recently executed but not in standard locations
- [ ] **Memory Hash Validation:** Calculate MD5 of suspicious process memory dumps for IoC matching.
- [ ] **Acquisition Time Correlation:** Compare memory acquisition timestamp with `windows.info.Info` to detect VM snapshot attacks.

**Memory-First Pivot Indicators:**
- Web shell processes (`w3wp.exe`, `httpd.exe`) with suspicious command lines → **PB-SIFT-001** priority.
- RDP/remote access tools (`mstsc.exe`, `AnyDesk.exe`) → **PB-SIFT-004** priority.
- Credential access (`mimikatz.exe`, `lsass.exe` dumping) → **PB-SIFT-005** priority.
- LOLBins with encoded commands (`powershell.exe`, `cmd.exe`, `certutil.exe`) → **PB-SIFT-010** priority.

---

### Phase 4 — Evidence Compatibility Matrix
Validate required evidence before queuing playbooks:

| Playbook | Disk Image | Memory | Logs | Network |
| :--- | :---: | :---: | :---: | :---: |
| **000 C2** | OPT | REC | YES | YES |
| **001 Initial Access** | YES | OPT | REC | OPT |
| **002 Execution** | YES | REC | REC | OPT |
| **003 Persistence** | YES | OPT | OPT | NO |
| **004 Priv Esc** | YES | REC | OPT | OPT |
| **005 Cred Theft** | YES | REC | REC | OPT |
| **006 Lateral Mov.** | YES | OPT | YES | OPT |
| **007 Exfiltration** | YES | OPT | REC | OPT |
| **008 Malware** | YES | REC | REC | OPT |
| **009 Ransomware** | YES | OPT | REC | OPT |
| **010 LOTL** | YES | OPT | REC | OPT |
| **011 Web Shell** | YES | OPT | REC | OPT |
| **012 Anti-Forensics** | YES | OPT | YES | NO |
| **013 Insider Threat** | YES | OPT | REC | OPT |
| **014 Linux** | YES | REC | YES | OPT |
| **015 Data Staging** | OPT | OPT | YES | YES |
| **016 Cross-Image** | NO | NO | NO | NO |
| **017 REMnux** | YES | NO | NO | NO |
| **018 Malware SOP** | YES | NO | NO | NO |

- [ ] **Execution Guard:** Mark playbooks as **UNABLE TO RUN** if required evidence is absent.
- [ ] **Confidence Note:** Note reduced confidence for playbooks where optional evidence is missing.

---

### Phase 5 — Rapid Indicator Triage
Perform quick pattern scans to pivot priority:
- [ ] **Ransomware:** Flag ransom notes/encrypted extensions → Priority: **PB-SIFT-009**.
- [ ] **Cred Theft:** Flag credential dumping tools in prefetch/ShimCache → Priority: **PB-SIFT-005**.
- [ ] **Anti-Forensics:** Flag log clearing (EID 1102/104) → Priority: **PB-SIFT-012**.
- [ ] **External Breach:** Flag web shells in web-dirs → Priority: **PB-SIFT-001**.
- [ ] **Exfil/Insider:** Flag bulk file access/archives in temp dirs → Priority: **PB-SIFT-007 / 013**.
- [ ] **Cloud Pivot:** Flag cloud CLI/token cache → Priority: **PB-SIFT-007**.
- [ ] **LOTL:** Flag encoded PowerShell/LOLBin chains → Priority: **PB-SIFT-010**.
- [ ] **Lateral Movement:** Flag lateral movement tools → Priority: **PB-SIFT-006**.
- [ ] **Mobile:** Flag mobile device connection → Add **PB-SIFT-015**.
- [ ] **Web Server Compromise (CTF):** Flag XAMPP/DVWA, suspicious access.log entries, PHP web shells with cmd parameter → Priority: **PB-SIFT-001, 008**.
- [ ] **SQL Injection Activity (CTF):** Flag sqlmap user-agent, SQLi payloads in logs, INTO OUTFILE attempts → Priority: **PB-SIFT-001, 012**.
- [ ] **XSS Attack (CTF):** Flag `<script>` tags in web logs, eval(window.name) payloads → Priority: **PB-SIFT-001**.
- [ ] **LFI Exploitation (CTF):** Flag file inclusion attempts (/etc/hosts, /windows/system32/drivers/etc/hosts) → Priority: **PB-SIFT-001, 012**.
- [ ] **RDP Enablement (CTF):** Flag `netsh` commands enabling remotedesktop in cmdscan output → Priority: **PB-SIFT-004**.
- [ ] **Malicious File Upload (CTF):** Flag PHP uploaders, files with version checks (e.g., PHP 4.1.0), suspicious temp paths → Priority: **PB-SIFT-001, 008**.

---

### Phase 6 — Case Classification & Weighted Selection
Assign classification and execution order:

| Indicator Pattern | Classification | Priority Order | Severity Weight |
| :--- | :--- | :--- | :--- |
| Ransom notes + Encrypted files | Ransomware | 009, 008, 006, 007, 012 | **CRITICAL** |
| Cred dump tools + LSASS access | Credential Theft | 005, 006, 003, 001 | **HIGH** |
| Encoded PS + LOLBin + C2 | Malware / APT | 008, 010, 003, 001, 012 | **HIGH** |
| Bulk access + USB + Cloud sync | Insider Threat | 013, 007, 012 | **HIGH** |
| Log cleared + Timestomping | Anti-Forensics | 012, 008, 006, 005 | **HIGH** |
| Web shell + Exploit logs | External Breach | 001, 006, 008, 003 | **HIGH** |
| Cloud tokens + M365 CLI | Cloud Pivot | 013, 007, 005 | **HIGH** |
| Linux image + SUID/Cron | Linux Compromise | 014, 003, 005 | **HIGH** |
| macOS image + dylib injection | macOS Compromise | 015, 003, 005 | **HIGH** |
| Net config + Firmware mismatch | Net Device Comp. | 015 | **HIGH** |

---

### Phase 7 — Parallel Execution Grouping
Group playbooks to minimize analysis time:

- [ ] **Group D (Timeline):** Build Super Timeline first (Dependency for all).
- [ ] **Group A (Memory):** Memory phases of 008, 006, 005, 010 (Symmetric/Parallel).
- [ ] **Group B (Disk):** Disk phases of 008, 003, 010, 001 (Symmetric/Parallel).
- [ ] **Group C (Logs):** Log phases of 009, 006, 005, 013, 012 (Symmetric/Parallel).
- [ ] **Group E (Specialist):** 014, 015 (Independent).
- [ ] **Group F (Correlation):** **PB-SIFT-016** (Post-all execution).

---

### Phase 8 — SLA & Escalation Management
- [ ] **Time Estimation:** Calculate total analysis time based on size and playbook count.
- [ ] **SLA Tiers:**
    - **CRITICAL:** 2h initial / 8h full.
    - **HIGH:** 4h initial / 24h full.
    - **MEDIUM:** 8h initial / 48h full.
- [ ] **SLA Breach Handling:** Prioritize CRITICAL/HIGH playbooks; defer MEDIUM/LOW.
- [ ] **Interim Reporting:** Emit findings after each playbook completes; do not wait for total run.
- [ ] **Critical Alerts:** Notify analyst via webhook immediately on any CRITICAL finding.

---

### Phase 9 — Re-Triage Trigger Conditions
Re-evaluate plan if any of the following are discovered mid-run:
- [ ] **Lateral Movement:** Add all hosts to **PB-SIFT-016**.
- [ ] **Cloud Tokens:** Add **PB-SIFT-007**.
- [ ] **Anti-Forensics:** Downgrade confidence of all completed findings to **POSSIBLE**.
- [ ] **Mobile Connection:** Add **PB-SIFT-015**.
- [ ] **New OS Partition:** Add appropriate OS-specific playbook.
- [ ] **Insider Threat:** Move case to restricted handling queue.
- [ ] **Additional Hosts:** Request images for referenced hosts.

---

### Phase 10 — Confidence Scoring Framework
Adjust findings based on evidence quality:

| Condition | Adjustment |
| :--- | :--- |
| Full Physical + Memory + Logs | Baseline (No adjustment) |
| No Memory Dump | Reduce memory findings to **POSSIBLE** |
| Log Clearing confirmed | Reduce all findings to **POSSIBLE** |
| Timestomping confirmed | Reduce timeline findings to **POSSIBLE** |
| Logical Acquisition only | Reduce all findings by one severity tier |
| Unresolvable Clock Skew | Mark timestamp findings as **UNVERIFIED** |
| Evidence Hash Mismatch | Mark all findings as **UNVERIFIED** |

---

### Phase 11 — Case Handoff Checklist
- [ ] **Queue Completion:** All playbooks completed, skipped, or failed (with log).
- [ ] **Findings Generation:** Unified `findings.json` with severity, confidence, and source.
- [ ] **Normalization Doc:** Clock skew normalization documented.
- [ ] **Quality Score:** Evidence quality score recorded.
- [ ] **Critical Alerts:** All CRITICAL findings reported.
- [ ] **Restricted Handling:** Insider threat findings isolated.
- [ ] **Correlation:** Cross-image report generated (if multi-host).
- [ ] **Executive Summary:** Incident type, affected hosts, and next actions.
- [ ] **Audit Trail:** Triage plan JSON archived.

---

### Phase 12 — Execution Plan Output
Before any other playbook runs, PB-SIFT-000 must emit a structured JSON execution plan. This plan is authoritative — no playbook outside this list may be executed.

**Required output format:**

```json
{
  "case_id": "<string>",
  "evidence_quality": "<HIGH|MEDIUM-HIGH|MEDIUM|LOW|VERY LOW>",
  "clock_skew_offset": "<offset in seconds or UNVERIFIED>",
  "classification": "<string>",
  "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "execution_plan": ["PB-SIFT-XXX", "PB-SIFT-XXX"],
  "skipped_playbooks": [
    {"id": "PB-SIFT-XXX", "reason": "<string>"}
  ],
  "confidence_modifiers": ["<string>"]
}
```

**Rules:**
- The `execution_plan` array is the authoritative ordered list of playbooks Geoff will run.
- No playbook outside this list may be executed.
- **PB-SIFT-016** (Cross-Image Correlation) must always be the last entry if more than one host is in scope.
- **PB-SIFT-017** (REMnux) and **PB-SIFT-018** (Malware SOP) are only included if a suspicious binary is surfaced during triage.
- Playbooks marked as **UNABLE TO RUN** in the Evidence Compatibility Matrix (Phase 4) must appear in `skipped_playbooks` with a reason.