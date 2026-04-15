# PB-SIFT-013: Insider Threat Indicators Playbook
## Insider Threat Indicators — Static Image Analysis

**Objective:** High-fidelity detection of unauthorized data access, hoarding, and exfiltration by an internal user (insider threat) using the SIFT Workstation toolset.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — Memory Analysis
- [ ] **Process Enumeration:** Check running processes — flag personal cloud sync clients, file transfer tools, or unapproved applications running at time of image capture.
- [ ] **Command Line Audit:** Check command lines — flag bulk copy, archive creation, or data staging commands targeting sensitive directories.
- [ ] **Session Analysis:** Flag browser sessions open to personal webmail, cloud storage, or job search sites.
- [ ] **Monitoring Tools:** Check for screen capture or keylogger processes — insider may be harvesting data for external party.
- [ ] **Scope Violations:** Flag any attempts to access directories outside the user's normal job function scope.

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline across all artifact sources.
- [ ] **Off-Hours Activity:** Flag activity outside business hours — early morning, late night, weekends, or holidays.
- [ ] **Bulk Access:** Flag bulk file access events — large number of files opened in a short window across sensitive directories.
- [ ] **Hoarding Patterns:** Flag data hoarding pattern — files copied to local staging area over days or weeks prior to departure or termination.
- [ ] **Role Violations:** Flag access to sensitive directories not related to the user's role — HR, Finance, Executive, Legal, source code.
- [ ] **HR Correlation:** Flag correlation between HR events and data access spikes — resignation, termination notice, performance review.
- [ ] **Media Sync:** Flag personal device connection timestamps — USB insertions correlated with bulk file access.

---

### Phase 4 — Disk Artifacts

#### 4.1 — Data Staging & Transfer
- [ ] **Cloud Sync:** Check for personal cloud sync clients installed or run — Dropbox, Google Drive, OneDrive personal, Mega, Box.
- [ ] **Archive Search:** Check for archive files created in user profile, desktop, or temp locations — flag size and contents if recoverable.
- [ ] **MFT Analysis:** Check MFT for bulk file copy operations to removable media or network locations.
- [ ] **Config Audit:** Check `rclone` or `winscp` config files in user profile — flag any personal or non-corporate destinations.
- [ ] **Suspicious Archives:** Flag split archive sequences or encrypted archives with no business justification.

#### 4.2 — Removable Media
- [ ] **USB Logs:** Check `setupapi.dev.log` — flag all USB device connections with timestamps.
- [ ] **Registry Audit:** Check registry for historical device connections — `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`.
- [ ] **Timeline Sync:** Cross-reference USB connection timestamps with bulk file access events in the timeline.
- [ ] **Portable Tools:** Check for portable executable launchers or tools run directly from USB — flag no install footprint.
- [ ] **Device Types:** Flag connection of personal phones as MTP/PTP storage devices.

#### 4.3 — Browser Artifacts
- [ ] **History Audit:** Check browser history — flag personal webmail (Gmail, Hotmail, Yahoo), file sharing, and job search sites.
- [ ] **Upload History:** Check browser upload history — flag files uploaded to personal cloud or webmail during business hours.
- [ ] **Competitive Intelligence:** Flag access to competitor websites, recruiting platforms, or external job boards.
- [ ] **Stored Secrets:** Check for saved credentials to non-corporate services in browser profile.
- [ ] **Departure Patterns:** Flag access to internal systems or documentation immediately before resignation or termination.

#### 4.4 — Application & Communication Artifacts
- [ ] **Unapproved Tools:** Check for unapproved communication tools — personal Slack, Telegram, Signal, WhatsApp desktop.
- [ ] **Email Forwarding:** Flag forwarding rules in email client artifacts — auto-forward to personal email is a **CRITICAL** indicator.
- [ ] **Print Audit:** Check print spooler artifacts — flag large or sensitive document print jobs.
- [ ] **Capture Tools:** Check for screen capture tools or document export activity in application logs.
- [ ] **Privileged Access:** Flag access to source code repositories, password vaults, or privileged systems outside normal patterns.

#### 4.5 — User Activity Artifacts
- [ ] **UserAssist:** Check `UserAssist` — flag applications launched that are inconsistent with job role.
- [ ] **Recent Files:** Check `RecentDocs` and jump lists — flag recently accessed sensitive files across departments.
- [ ] **LNK Analysis:** Check `LNK` files — flag access to file shares or directories outside normal scope.
- [ ] **Shellbags:** Check `Shellbags` — flag directory browsing into sensitive or restricted areas.
- [ ] **Search Index:** Flag searches for sensitive terms in Windows Search index artifacts.

---

### Phase 5 — Event Log Analysis
- [ ] **Temporal Anomalies:** Flag logons outside business hours (EID 4624) — especially to sensitive systems.
- [ ] **Scope Violations:** Flag access to file shares outside the user's normal department scope (EID 5140 / 5145).
- [ ] **Bulk Access:** Flag bulk object access events if auditing enabled (EID 4663) — sensitive file reads in volume.
- [ ] **Email Forwarding:** Flag email forwarding rule creation if Exchange logs are present.
- [ ] **Privilege Escalation:** Flag privilege escalation attempts — user trying to access resources above their clearance (EID 4625 / 4656).
- [ ] **Remote Access:** Flag VPN or remote access logons during off-hours or from unusual geographic locations.
- [ ] **Policy Overrides:** Flag removable media policy override attempts (EID 6416).
- [ ] **Audit Tampering:** Flag audit policy modification — insider may attempt to disable logging (EID 4719).

---

---

### Phase 6 — Network IOC Extraction
- [ ] **Destination Harvesting:** Extract all external destinations accessed from the host during the investigation window.
- [ ] **Cloud Sync Correlation:** Flag personal cloud storage destinations — correlate with file staging timestamps.
- [ ] **Volume Analysis:** Flag large outbound data transfers to non-corporate destinations.
- [ ] **Competitive Intel:** Flag access to competitor infrastructure or external recruitment platforms.
- [ ] **Encryption Tunnels:** Flag encrypted tunnel usage — personal VPN clients masking exfiltration destination.

---

### Phase 7 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mapping:** Identify technique per MITRE ATT&CK:
    - **T1567.002:** Exfiltration to Cloud Storage
    - **T1052.001:** Exfiltration via Removable Media
    - **T1114:** Email Collection
    - **T1114.003:** Email Forwarding Rule
    - **T1005:** Data from Local System
    - **T1074.001:** Data Staged — Local
    - **T1185:** Browser Session Hijacking
    - **T1056:** Input Capture
- [ ] **Activity Timeline:** Establish insider activity timeline — first anomalous access $\rightarrow$ staging $\rightarrow$ transfer $\rightarrow$ cleanup.
- [ ] **Scope Assessment:** Assess scope — identify what data was accessed, copied, or transmitted and to where.
- [ ] **HR Correlation:** Note any correlation with HR events — resignation date, termination notice, disciplinary action.
- [ ] **Final Output:** Score by severity — flag findings as HR-sensitive and route to appropriate stakeholder, not general queue.
