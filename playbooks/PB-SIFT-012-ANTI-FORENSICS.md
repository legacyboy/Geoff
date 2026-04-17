# PB-SIFT-012: Anti-Forensics Indicators Playbook
## Anti-Forensics Indicators — Static Image Analysis

**Objective:** High-fidelity detection of attempts to hinder, deceive, or destroy forensic evidence, including log tampering, file wiping, timestomping, and defense evasion.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding — evidence tampering is itself a primary anti-forensics indicator.

---

### Phase 2 — Memory Analysis
- [ ] **Wiping Tool Detection:** Check for secure deletion or wiping tool processes — flag `sdelete`, `eraser`, `bleachbit`, `cipher` in process list or command lines.
- [ la **Log Tampering:** Check for log tampering tools in memory — flag processes with handles to event log files or the event log service.
- [ ] **Security Tool Interference:** Flag any process attempting to terminate or suspend security tooling — AV, EDR, or logging agents.
- [ ] **Destruction Patterns:** Check command lines for evidence destruction patterns — `del /f /q`, `rd /s /q`, `format`, `cipher /w`.
- [ ] **Log Bypass:** Flag processes that clear PowerShell history or disable script block logging at runtime.

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline across all artifact sources.
- [ ] **Artifact Gaps:** Flag gaps in the timeline — absence of expected artifacts during a known active period is a primary anti-forensics indicator.
- [ ] **Mass Deletion:** Flag mass file deletion events — large number of files deleted in a short window.
- [ ] **Log Correlation:** Flag log clearing events and correlate with activity gaps immediately before or after.
- [ ] **Timestomping Detection:** Flag timestomping — files modified but timeline shows no corresponding system activity around that timestamp.
- [ ] **Self-Deletion:** Flag tool execution immediately followed by self-deletion — flag prefetch entry with no corresponding binary on disk.
- [ ] **Dead Zone Identification:** Identify dead zones — periods where attacker was likely active but left minimal artifacts.

---

### Phase 4 — Disk Artifacts

#### 4.1 — Log Tampering
- [ ] **Log Integrity:** Check Windows Event Log files for truncation, corruption, or unexpected small file sizes.
- [ ] **Sequence Breaks:** Flag gaps in event log sequence numbers — deleted records leave sequence breaks.
- [ ] **App Log Audit:** Check for deletion or modification of IIS, web server, or application logs.
- [ ] **Tool Use:** Flag `wevtutil cl` usage in prefetch or ShimCache — command-line log clearing tool.
- [ ] **Sysmon Audit:** Check Sysmon operational log — flag if Sysmon is installed but log is empty or missing.

#### 4.2 — File Deletion & Wiping
- [ ] **Recycle Bin:** Check recycle bin artifacts — flag deleted files relevant to the investigation window.
- [ ] **MFT Analysis:** Check MFT for file deletion patterns — `$FILE_NAME` entries with no corresponding `$DATA` stream.
- [ ] **Wiping Tool Execution:** Flag use of `sdelete`, `eraser`, `bleachbit`, or `cipher /w` in prefetch or ShimCache.
- [ ] **Unallocated Space:** Check for overwritten disk sectors in unallocated space — wiping tools leave recognizable patterns.
- [ ] **Prefetch Purge:** Flag deletion of prefetch files themselves — attacker removing execution evidence.
- [ ] **Recovery Sabotage:** Check for VSS deletion — `vssadmin delete shadows`, `wmic shadowcopy delete` — removes recovery points and prior file versions.

#### 4.3 — Timestomping
- [ ] **MFT Discrepancy:** Compare `$STANDARD_INFO` timestamps against `$FILE_NAME` timestamps in MFT — discrepancy indicates tampering.
- [ ] **Impossible Timestamps:** Flag files with `$STANDARD_INFO` timestamps predating the OS installation date.
- [ ] **Bulk Stomping:** Flag files with creation timestamps identical to the second across multiple files — bulk timestomp indicator.
- [ ] **Timestamp Mismatch:** Check prefetch timestamps against MFT timestamps for the same binary — inconsistency confirms stomping.
- [ ] **Logical Impossibility:** Flag files with last modified time earlier than creation time.

#### 4.4 — Tool & Artifact Removal
- [ ] **Ghost Binaries:** Check for self-deleting scripts or executables — flag LNK or prefetch entries with no binary present.
- [ ] **User Trail Destruction:** Check for removal of browser history, cookies, or cache — `RunMRU`, `TypedURLs`, history files wiped.
- [ ] **Activity Purge:** Flag clearing of `UserAssist`, `RecentDocs`, `Shellbags`, or jump lists.
- [ ] **Temp Purge:** Check for deletion of `%TEMP%` contents correlated with attacker activity window.
- [ ] **Persistence Cleanup:** Flag removal of scheduled tasks or services after use.
- [ ] **RAT Uninstallation:** Check for uninstallation of remote access tools after use — `anydesk`, `atera`, `screenconnect` uninstall artifacts.

#### 4.5 — Defense Evasion on Disk
- [ ] **AV Tampering:** Flag disabled or tampered Windows Defender — check registry for policy overrides.
- [ ] **Exclusion Paths:** Flag exclusion paths added to AV/EDR — attacker adding working directory to scan exclusions.
- [ ] **Firewall Modification:** Check for tampered host firewall rules — flag rules added to allow C2 traffic.
- [ ] **Audit Disabling:** Flag disabled audit policies — `HKLM\SYSTEM\CurrentControlSet\Services\EventLog` tampering.
- [ ] **AMSI Bypass:** Check for AMSI bypass artifacts — registry patches or DLL tampering targeting `amsi.dll`.

---

### Phase 5 — Event Log Analysis
- [ ] **Critical Log Clears:** Flag log clearing events — EID 1102 (Security log cleared) and EID 104 (System log cleared) — **CRITICAL**.
- [ ] **Policy Changes:** Flag audit policy changes (EID 4719) — attacker disabling logging before activity.
- [ ] **Service Disruption:** Flag event log service stops or crashes (EID 6005 / 6006) — may indicate forced termination.
- [ ] **Event Gaps:** Flag gaps in expected high-frequency events — missing logon/logoff pairs, missing process creation chains.
- [ ] **Tool Execution:** Flag `wevtutil`, `powershell Clear-EventLog`, or `auditpol` execution (EID 4688).
- [ ] **Defense Disabling:** Flag Windows Defender tamper protection events or real-time protection disable events.
- [ ] **Security Tool Termination:** Flag security tool service stops (EID 7036) — EDR, AV, or Sysmon service terminated.

---

---

### Phase 6 — Artifact Recovery Attempts
- [ ] **Carving:** Carve deleted files from unallocated space — attempt recovery of wiped tools or staging files.
- [ ] **Snapshot Recovery:** Extract VSS snapshots if any remain — prior snapshot may predate anti-forensics activity.
- [ ] **Log Reconstruction:** Recover deleted event log records from unallocated MFT space where possible.
- [ ] **Memory Cross-Ref:** Check memory dump for artifacts that were deleted from disk — memory may retain what disk does not.
- [ ] **Prefetch Recovery:** Recover deleted prefetch files — prefetch directory may have remnants in unallocated space.

---

### Phase 7 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mapping:** Identify technique per MITRE ATT&CK:
    - **T1070.001:** Indicator Removal — Event Log Clear
    - **T1070.004:** Indicator Removal — File Deletion
    - **T1070.006:** Indicator Removal — Timestomp
    - **T1070.005:** Indicator Removal — Network Share
    - **T1562.001:** Impair Defenses — Disable AV
    - **T1562.010:** Impair Defenses — AMSI Bypass
    - **T1562.002:** Impair Defenses — Disable Logging
    - **T1497:** Virtualization / Sandbox Evasion
    - **T1485:** Secure Deletion Tools
- [ ] **Limitations Documentation:** Document what artifacts are missing or unrecoverable — establishes evidentiary limitations for analyst.
- [ ] **Confidence Assessment:** Assess confidence impact — anti-forensics activity reduces confidence in completeness of all other playbook findings; note this explicitly.
- [ ] **Severity Scoring:** Score by severity — any confirmed anti-forensics activity elevates overall case severity to **HIGH** minimum.
- [ ] **Confidence Downgrade Directive:** If any anti-forensics finding is scored **HIGH** or **CRITICAL**, emit a confidence downgrade directive in the findings output. This directive must set the confidence modifier **ANTI-FORENSICS-CONFIRMED** and must be read by the orchestrator. Upon receiving this modifier, the orchestrator must retroactively re-score all findings already emitted in the current case from **CONFIRMED** to **POSSIBLE** and from **POSSIBLE** to **UNVERIFIED**. Flag this downgrade explicitly in the final report.
- [ ] **Final Output:** Output structured findings file for analyst handoff.

## VSS Anti-Forensics Detection

- [ ] **VSS Deletion Check:** Run `vss.list_vss(image)` — if no VSS snapshots exist on a system that should have them, flag as potential anti-forensics (vssadmin delete shadows).
- [ ] **VSS Timeline Analysis:** Run `vss.analyze_vss_timeline(image)` on surviving shadow copies to reconstruct pre-deletion file state.

## PhotoRec for Deleted Files

- [ ] **Deep Carving:** Run `photorec.recover_files(image, output_dir)` to recover files that were securely deleted or wiped — PhotoRec carves from raw blocks, bypassing filesystem metadata.
