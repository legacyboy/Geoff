# PB-SIFT-016: Triage Prioritization Meta-Playbook
## Case Intake & Playbook Selection

**Objective:** Autonomous assessment of available evidence to score quality, determine incident type, and generate a weighted, optimized execution plan for all subsequent SIFT playbooks. This is the primary decision engine that runs first on every case.

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
- [ ] **Host Count:** Document number of hosts; if multi-host, queue **PB-SIFT-017** after individual runs.
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

### Phase 3 — Evidence Compatibility Matrix
Validate required evidence before queuing playbooks:

| Playbook | Disk Image | Memory | Logs | Network |
| :--- | :---: | :---: | :---: | :---: |
| **001 Malware** | YES | REC | REC | OPT |
| **002 Ransomware** | YES | OPT | REC | OPT |
| **003 Lateral Mov.** | YES | OPT | YES | OPT |
| **004 Cred Theft** | YES | REC | REC | OPT |
| **005 Persistence** | YES | OPT | OPT | NO |
| **006 Exfiltration** | YES | OPT | REC | OPT |
| **007 LOTL** | YES | OPT | REC | OPT |
| **008 Initial Access** | YES | OPT | REC | OPT |
| **009 Insider Threat** | YES | OPT | REC | OPT |
| **010 Anti-Forensics** | YES | OPT | YES | NO |
| **011 Cloud/SaaS** | YES | OPT | OPT | OPT |
| **012 Linux** | YES | REC | YES | OPT |
| **013 macOS** | YES | REC | YES | OPT |
| **014 Network Dev.** | NO | NO | YES | YES |
| **015 Mobile** | OPT | NO | OPT | OPT |
| **017 Cross-Image** | NO | NO | NO | NO |

- [ ] **Execution Guard:** Mark playbooks as **UNABLE TO RUN** if required evidence is absent.
- [ ] **Confidence Note:** Note reduced confidence for playbooks where optional evidence is missing.

---

### Phase 4 — Rapid Indicator Triage
Perform quick pattern scans to pivot priority:
- [ ] **Ransomware:** Flag ransom notes/encrypted extensions $\rightarrow$ Priority: **PB-SIFT-002**.
- [ ] **Cred Theft:** Flag credential dumping tools in prefetch/ShimCache $\rightarrow$ Priority: **PB-SIFT-004**.
- [ ] **Anti-Forensics:** Flag log clearing (EID 1102/104) $\rightarrow$ Priority: **PB-SIFT-010**.
- [ ] **External Breach:** Flag web shells in web-dirs $\rightarrow$ Priority: **PB-SIFT-008**.
- [ ] **Exfil/Insider:** Flag bulk file access/archives in temp dirs $\rightarrow$ Priority: **PB-SIFT-006 / 009**.
- [ ] **Cloud Pivot:** Flag cloud CLI/token cache $\rightarrow$ Priority: **PB-SIFT-011**.
- [ ] **LOTL:** Flag encoded PowerShell/LOLBin chains $\rightarrow$ Priority: **PB-SIFT-007**.
- [ ] **Lateral Movement:** Flag lateral movement tools $\rightarrow$ Priority: **PB-SIFT-003**.
- [ ] **Mobile:** Flag mobile device connection $\rightarrow$ Add **PB-SIFT-015**.

---

### Phase 5 — Case Classification & Weighted Selection
Assign classification and execution order:

| Indicator Pattern | Classification | Priority Order | Severity Weight |
| :--- | :--- | :--- | :--- |
| Ransom notes + Encrypted files | Ransomware | 002, 008, 003, 006, 010 | **CRITICAL** |
| Cred dump tools + LSASS access | Credential Theft | 004, 003, 005, 008 | **HIGH** |
| Encoded PS + LOLBin + C2 | Malware / APT | 001, 007, 005, 008, 010 | **HIGH** |
| Bulk access + USB + Cloud sync | Insider Threat | 009, 006, 010 | **HIGH** |
| Log cleared + Timestomping | Anti-Forensics | 010, 001, 003, 004 | **HIGH** |
| Web shell + Exploit logs | External Breach | 008, 003, 001, 005 | **HIGH** |
| Cloud tokens + M365 CLI | Cloud Pivot | 011, 006, 004 | **HIGH** |
| Linux image + SUID/Cron | Linux Compromise | 012, 005, 004 | **HIGH** |
| macOS image + dylib injection | macOS Compromise | 013, 005, 004 | **HIGH** |
| Net config + Firmware mismatch | Net Device Comp. | 014 | **HIGH** |
| Mobile backup + Spyware sigs | Mobile Threat | 015, 009 | **HIGH** |

---

### Phase 6 — Parallel Execution Grouping
Group playbooks to minimize analysis time:

- [ ] **Group D (Timeline):** Build Super Timeline first (Dependency for all).
- [ ] **Group A (Memory):** Memory phases of 001, 003, 004, 007 (Symmetric/Parallel).
- [ ] **Group B (Disk):** Disk phases of 001, 005, 007, 008 (Symmetric/Parallel).
- [ ] **Group C (Logs):** Log phases of 002, 003, 004, 009, 010 (Symmetric/Parallel).
- [ ] **Group E (Specialist):** 011, 012, 013, 014, 015 (Independent).
- [ ] **Group F (Correlation):** **PB-SIFT-017** (Post-all execution).

---

### Phase 7 — SLA & Escalation Management
- [ ] **Time Estimation:** Calculate total analysis time based on size and playbook count.
- [ ] **SLA Tiers:**
    - **CRITICAL:** 2h initial / 8h full.
    - **HIGH:** 4h initial / 24h full.
    - **MEDIUM:** 8h initial / 48h full.
- [ ] **SLA Breach Handling:** Prioritize CRITICAL/HIGH playbooks; defer MEDIUM/LOW.
- [ ] **Interim Reporting:** Emit findings after each playbook completes; do not wait for total run.
- [ ] **Critical Alerts:** Notify analyst via webhook immediately on any CRITICAL finding.

---

### Phase 8 — Re-Triage Trigger Conditions
Re-evaluate plan if any of the following are discovered mid-run:
- [ ] **Lateral Movement:** Add all hosts to **PB-SIFT-017**.
- [ ] **Cloud Tokens:** Add **PB-SIFT-011**.
- [ ] **Anti-Forensics:** Downgrade confidence of all completed findings to **POSSIBLE**.
- [ ] **Mobile Connection:** Add **PB-SIFT-015**.
- [ ] **New OS Partition:** Add appropriate OS-specific playbook.
- [ ] **Insider Threat:** Move case to restricted handling queue.
- [ ] **Additional Hosts:** Request images for referenced hosts.

---

### Phase 9 — Confidence Scoring Framework
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

### Phase 10 — Case Handoff Checklist
- [ ] **Queue Completion:** All playbooks completed, skipped, or failed (with log).
- [ ] **Findings Generation:** Unified `findings.json` with severity, confidence, and source.
- [ ] **Normalization Doc:** Clock skew normalization documented.
- [ ] **Quality Score:** Evidence quality score recorded.
- [ ] **Critical Alerts:** All CRITICAL findings reported.
- [ ] **Restricted Handling:** Insider threat findings isolated.
- [ ] **Correlation:** Cross-image report generated (if multi-host).
- [ ] **Executive Summary:** Incident type, affected hosts, and next actions.
- [ ] **Audit Trail:** Triage plan JSON archived.
