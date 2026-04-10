# PB-SIFT-017: Cross-Image Correlation Playbook
## Multi-Host Analysis & Attack Path Reconstruction

**Objective:** Correlate findings across multiple forensic images to reconstruct the full kill chain, identify the "Patient Zero" host, calculate total dwell time, and determine the overall blast radius of a campaign.

---

### Phase 1 — Multi-Host Inventory
- [ ] **Host Catalog:** Document all hosts (hostname, OS, role, acquisition time).
- [ ] **Network Mapping:** Map subnet membership, trust relationships, and AD domain membership.
- [ ] **Scope Gap Analysis:** Flag hosts referenced in artifacts that are missing from the provided evidence.
- [ ] **Findings Integration:** Load all individual `findings.json` files into a unified correlation workspace.
- [ ] **Confidence Baseline:** Apply evidence quality scores from **PB-SIFT-016** to adjust correlation confidence.

---

### Phase 2 — Clock Skew Normalization
- [ ] **Offset Retrieval:** Load clock skew offsets for each host from triage output.
- [ ] **Cross-Host Normalization:** Apply offsets to merge timestamps into a single UTC reference.
- [ ] **Skew Estimation:** For hosts with unknown skew, estimate offsets by correlating events (e.g., network logs) with known-time hosts.
- [ ] **Uncertainty Mapping:** Flag hosts with unresolvable skew as **TIME-UNVERIFIED**.
- [ ] **Case Uncertainty:** Calculate the maximum time uncertainty across the case; flag > 30 mins as **HIGH**.

---

### Phase 3 — Unified Timeline Merging
- [ ] **Super Timeline Merge:** Create a single case-wide timeline tagged by source host.
- [ ] **Case Zero Identification:** Identify the earliest suspicious event across all hosts.
- [ ] **Pattern Detection:** 
    - Flag simultaneous activity gaps (coordinated anti-forensics).
    - Flag identical attacker actions appearing on multiple hosts within minutes (automated spread).
    - Flag "quiet-then-burst" patterns across the network.

---

### Phase 4 — IOC Pivoting & Cross-Host Correlation
- [ ] **IOC Harvesting:** Extract all IPs, domains, hashes, and accounts from all findings.
- [ ] **Intersection Analysis:** Flag any IOC appearing on two or more hosts.
- [ ] **Binary Correlation:** Match malware hashes across hosts to confirm lateral tool transfer.
- [ ] **Infrastructure Mapping:** Identify shared C2 destinations and attacker infrastructure.
- [ ] **Fingerprinting:** Identify shared mutexes, named pipes, or tool names (ShimCache/Prefetch).
- [ ] **Frequency Scoring:** Assign higher confidence/severity to IOCs appearing on multiple hosts.

---

### Phase 5 — Lateral Movement Chain Reconstruction
- [ ] **Pivot Mapping:** Use **PB-SIFT-003** findings to map the sequence of hops (Source $\rightarrow$ Pivot $\rightarrow$ Target).
- [ ] **Logon Correlation:** Match outbound explicit credential logons on Host A to inbound network logons on Host B.
- [ ] **Drop-to-Exec Correlation:** Match file write timestamps on Target Host to remote execution events on Source Host.
- [ ] **Blast Radius Mapping:** Identify all hosts with confirmed attacker presence.
- [ ] **Failed Pivot Detection:** Flag hosts that were probed/scanned but not successfully compromised.
- [ ] **Crown Jewel Audit:** Specifically confirm if the Domain Controller (DC) was accessed.

---

### Phase 6 — Credential Reuse & Account Correlation
- [ ] **Account Mapping:** Flag accounts appearing on multiple hosts (especially service/admin accounts).
- [ ] **Credential Theft Linkage:** Correlate theft timestamps from **PB-SIFT-004** with the first use of those credentials on other hosts.
- [ ] **Tactic Identification:** Flag Pass-the-Hash or Pass-the-Ticket indicators across the environment.
- [ ] **Privilege Escalation:** Identify the highest-privilege account used (e.g., Domain Admin) and its movement path.
- [ ] **Account Spread:** Map the timeline of attacker-created accounts appearing on multiple hosts.

---

### Phase 7 — Persistence & GPO Correlation
- [ ] **Technique Synchronization:** Flag identical persistence techniques (e.g., same service name) across hosts.
- [ ] **Automation Detection:** Identify identical scheduled task names or registry values (indicates scripted deployment).
- [ ] **Domain-Level Persistence:** 
    - Audit GPO modifications reflected across multiple host registry hives.
    - Analyze AD object modifications in DC event logs.
- [ ] **Staging Analysis:** Distinguish between persistence installed *before* lateral movement vs. *after* (consolidation).

---

### Phase 8 — Attacker Dwell Time Calculation
- [ ] **Start/End Benchmarks:** Identify the first and last attacker artifacts across the entire environment.
- [ ] **Global Dwell Calculation:**
    - **SHORT (< 24h):** Likely opportunistic.
    - **MEDIUM (1-7 days):** Targeted.
    - **LONG (7-30 days):** Deliberate reconnaissance.
    - **EXTENDED (> 30 days):** APT / Critical.
- [ ] **Per-Host Dwell:** Calculate dwell time for each individual host.
- [ ] **Re-entry Detection:** Identify evidence of attacker returning after an apparent eviction.

---

### Phase 9 — Campaign Fingerprinting
- [ ] **TTP Profiling:** Map the collective TTPs of all hosts to the MITRE ATT&CK framework.
- [ ] **Actor Attribution:** Compare the TTP profile against known threat actor groups.
- [ ] **Tooling Uniqueness:** Flag rare tool combinations or custom implant characteristics.
- [ ] **C2 Analysis:** Compare infrastructure against known campaign data.
- [ ] **Victimology Fit:** Assess if the targeting matches known sector-specific campaigns.

---

### Phase 10 — Crown Jewel Impact Scoring
Assign impact based on the most critical system compromised:

| System / Data Type | Impact Score |
| :--- | :--- |
| Domain Controller / CA | **CRITICAL** |
| Enterprise/Domain Admin Account | **CRITICAL** |
| Backup Infrastructure | **CRITICAL** |
| Core Financial / Banking Systems | **CRITICAL** |
| Customer PII / Financial Data | **HIGH** |
| HR / Executive Data | **HIGH** |
| Source Code Repositories | **HIGH** |
| Email Server | **HIGH** |
| Standard Workstations (No Lateral) | **LOW** |

- [ ] **Impact Summary:** Identify all compromised crown jewels and their associated data exposure.

---

### Phase 11 — Evidence Gap Mapping
- [ ] **Missing Host Audit:** Document hosts referenced in artifacts but not provided as images.
- [ ] **Artifact Gaps:** Assess the impact of missing memory dumps or logs on correlation confidence.
- [ ] **Anti-Forensics Impact:** Document how host-level anti-forensics reduce the overall case confidence.
- [ ] **Scope Bound:** Define the minimum and maximum possible attack scope based on evidence.

---

### Phase 12 — Score & Report
- [ ] **Findings Generation:** Output the unified `multi_host_correlation.json`.
- [ ] **MITRE Mapping:**
    - **T1570:** Remote Services — Lateral Tool Transfer
    - **T1021.002:** Remote Services — SMB/Windows Admin Shares
    - **T1550.002:** Pass the Hash
    - **T1550.003:** Pass the Ticket
    - **T1087.002:** Domain Account Discovery
    - **T1482:** Domain Trust Discovery
    - **T1018:** Remote System Discovery
    - **T1135:** Network Share Discovery
    - **T1484.001:** GPO Modification
    - **T1039:** Data from Network Shared Drive
- [ ] **Case Severity Matrix:**
    - **CRITICAL:** Crown jewel compromised, 4+ HIGH findings, Domain Admin used, or Dwell > 30 days.
    - **HIGH:** 2-3 HIGH findings.
    - **MEDIUM/LOW:** Single host, no lateral movement, no crown jewels.
- [ ] **Narrative Construction:** Produce the full kill chain narrative from Patient Zero to final impact.
- [ ] **Attack Graph:** Generate the node list (Source $\rightarrow$ Pivot $\rightarrow$ Target) with timestamps.
- [ ] **Executive Summary:** Generate summary for management/legal review.
