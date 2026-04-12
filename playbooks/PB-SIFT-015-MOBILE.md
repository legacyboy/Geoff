# PB-SIFT-015: Mobile Device Artifacts Playbook
## Mobile Device Artifacts — Static Image Analysis

**Objective:** Identification and analysis of mobile device artifacts discovered within a desktop forensic image, backups, or full filesystem extractions using the SIFT Workstation toolset.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.
- [ ] **Device ID:** Identify mobile device type, OS version, and acquisition method from metadata.
- [ ] **Acquisition Scope:** Document acquisition type (Logical, Full Filesystem, Physical, UFED) — adjust artifact expectations accordingly.
- [ ] **Encryption Audit:** Document backup encryption status — identify if iTunes/ADB backups require password recovery.
- [ ] **Management Audit:** Note MDM enrollment status (Managed vs Unmanaged).
- [ ] **Root/Jailbreak Check:** Flag if device was jailbroken or rooted — indicator of policy violation and expanded artifact access.

---

### Phase 2 — Host-Side Connection Artifacts
- [ ] **USB History:** Check Windows registry (`HKLM/SYSTEM/CurrentControlSet/Enum/USB` and `USBSTOR`) — flag connections during incident window.
- [ ] **Driver Events:** Check `setupapi.dev.log` for mobile device driver installation events.
- [ ] **iTunes Sync:** Check `AppData/Apple Computer/MobileSync/` — flag backup timestamps and pairing records.
- [ ] **Lockdown Audit:** Check iTunes lockdown certificates — flag trusted host pairing outside approved inventory.
- [ ] **ADB Artifacts:** Flag `adb.exe` execution in prefetch or ShimCache with device connection timestamps.
- [ ] **WPD Entries:** Check Windows Portable Device (WPD) registry entries for MTP/PTP connections.
- [ ] **MDM Host Agents:** Check for Intune, AirWatch, or MobileIron installation and compliance logs.
- [ ] **Forensic Tool Residue:** Check for Cellebrite UFED, GrayKey, or Magnet AXIOM output files on host disk.

---

### Phase 3 — Acquisition Type Assessment
- [ ] **Scope Mapping:** Determine acquisition type and adjust analysis (Logical $\rightarrow$ limited app data; Full $\rightarrow$ system files, keychain, root artifacts).
- [ ] **Gap Analysis:** Flag if acquisition type is insufficient for the investigation scope.
- [ ] **UFDR Parsing:** Parse Cellebrite UFDR report files for device metadata and flagged items.
- [ ] **AXIOM Integration:** Parse Magnet AXIOM case files for artifact categories and analyst flags.
- [ ] **Pairing Validation:** Confirm lockdown certificate on host matches the device under investigation.

---

### Phase 4 — iOS Artifact Analysis

#### 4.1 — Backup & Filesystem Artifacts
- [ ] **Backup Location:** Locate iTunes backup directory (`AppData/Apple Computer/MobileSync/Backup/`).
- [ ] **App Audit:** Parse `Manifest.db` — flag sideloaded or enterprise-signed apps outside App Store.
- [ ] **Device Metadata:** Extract IMEI, UDID, and iOS version from `Info.plist`.
- [ ] **Backup Status:** Check `Status.plist` for encryption status and completion.
- [ ] **Root Analysis:** If full filesystem is available, check `/private/var/mobile/` and `/private/var/root/`.
- [ ] **Keychain Audit:** Check `Keychain-2.db` for stored credentials, tokens, and certificates.
- [ ] **Location History:** Check `consolidated.db` or `Cache.SQLiteDb` for location artifacts.
- [ ] **Data Usage:** Check `DataUsage.sqlite` — flag high data consumption (spyware indicator).

#### 4.2 — Communication Artifacts
- [ ] **SMS/iMessage:** Parse `sms.db` — flag communications with suspicious contacts.
- [ ] **Call Logs:** Parse `CallHistory.storedata` — flag calls correlated with incident timeline.
- [ ] **Voicemail Audit:** Check voicemail databases and audio files.
- [ ] **3rd Party Apps:** Check WhatsApp, Signal, Telegram, WeChat databases in app data directories.
- [ ] **Email Audit:** Check email databases for sent/received items during incident window.
- [ ] **SIM Analysis:** Flag SIM swap indicators (new ICCID or IMSI).

#### 4.3 — Location & Sensor Artifacts
- [ ] **Significant Locations:** Check `Cloud-V2.sqlite` in `com.apple.routined`.
- [ ] **EXIF Analysis:** Check photo EXIF metadata for GPS coordinates and timestamps.
- [ ] **Map/Directions:** Check Maps search and directions history.
- [ ] **Fitness Data:** Check motion and fitness logs to confirm device activity.
- [ ] **Geofencing:** Check app-registered geofences outside expected locations.

#### 4.4 — iOS Crash Log Analysis
- [ ] **Crash Correlation:** Check logs in `/private/var/mobile/Library/Logs/CrashReporter/` correlated with initial access.
- [ ] **Daemon Stability:** Flag repeated crashes of `launchd`, `backboardd`, or `springboard`.
- [ ] **Pegasus Indicators:** Check for process names and library paths associated with NSO Group tooling.
- [ ] **Exfiltration Spikes:** Check `DataUsage.sqlite` spikes on previously low-usage apps.
- [ ] **Diagnostics:** Check `/private/var/logs/AppleSupport/` for diagnostic artifacts.

---

### Phase 5 — Android Artifact Analysis

#### 5.1 — Backup & Filesystem Artifacts
- [ ] **ADB Backup:** Locate `.ab` files on host disk and extract.
- [ ] **APK Audit:** Parse extracted APK list — flag sideloaded APKs or those with dangerous permissions.
- [ ] **Root FS Analysis:** If full filesystem is available, check `/data/data/` and `/data/system/`.
- [ ] **Package Audit:** Check `/data/system/packages.xml` for install timestamps and non-standard packages.
- [ ] **Account Audit:** Check `/data/system/users/0/accounts.db` for non-corporate accounts.
- [ ] **Memory Artifacts:** If memory image is available, check `/proc/[pid]/` for deleted binaries.

#### 5.2 — Communication Artifacts
- [ ] **SMS/MMS:** Check `mmssms.db` for communications during investigation window.
- [ ] **Call Logs:** Check `contacts2.db` for calls during investigation window.
- [ ] **3rd Party Apps:** Check WhatsApp, Telegram, Signal databases in `/data/data/`.
- [ ] **Corporate Email:** Check email client databases for corporate account access.
- [ ] **SIM Swap:** Flag multiple ICCID values in telephony database.

#### 5.3 — Android-Specific Malware Indicators
- [ ] **Root Indicators:** Check for `su` binary in `/system/xbin/`, Magisk modules, or SuperSU artifacts.
- [ ] **Developer Mode:** Flag ADB debugging enabled outside controlled environment.
- [ ] **Spyware Scan:** Check installed packages against known signatures:
    - **Stalkerware:** FlexiSpy, mSpy, Hoverwatch, iKeyMonitor, Spyic.
    - **Banking Trojans:** Anubis, Cerberus, SharkBot, Hydra, BianLian.
    - **RATs:** AhMyth, DroidJack, AndroRAT, SpyNote.
- [ ] **C2 Discovery:** Check shared preferences XML files for embedded C2 addresses or tokens.
- [ ] **Certificate Audit:** Check for APKs signed with self-signed or revoked certificates.
- [ ] **Permission Audit:** Flag apps with combined SMS + Call Log + Location + Mic + Camera permissions.

---

### Phase 6 — Spyware & Pegasus Indicators
- [ ] **Pegasus (NSO) Audit:**
    - **Process Names:** Flag `bh`, `spcl`, `msgacntd`, `aggregatenotd`.
    - **File Paths:** Check `/private/var/db/stash/` and unusual files in `/private/var/mobile/Library/Preferences/`.
    - **Network IOCs:** Check for known Pegasus C2 domains/IPs (Amnesty Tech / Citizen Lab).
    - **Data Exfil:** Check `DataUsage.sqlite` for large transfers from unexpected system processes.
    - **Power Consumption:** Check battery drain artifacts for abnormal background process activity.
- [ ] **Commercial Stalkerware (Android):**
    - **Hidden Apps:** Flag apps with generic names and no launcher icon.
    - **Admin Rights:** Flag apps with Device Administrator rights not matching corporate MDM.
    - **Accessibility Abuse:** Flag apps registered as accessibility services that are not legitimate tools.
- [ ] **MDM Rogue Profiles:** Check for iOS profiles not issued by corporate MDM.
- [ ] **MDM Tampering:** Flag MDM removal/unenrollment events correlated with investigation window.
- [ ] **Zero-Click Indicators:** Flag messages received and immediately deleted, or crashes with no user interaction.

---

### Phase 7 — Log Analysis
- [ ] **iOS Unified Logs:** Parse process execution, network, and XPC events (Full FS required).
- [ ] **iOS System Log:** Check `/var/log/system.log` for service anomalies.
- [ ] **Android Logcat:** Check for suspicious process spawning or network connections.
- [ ] **Backup Anomalies:** Flag unusually frequent backups indicating data harvesting.
- [ ] **MDM Compliance:** Check host-side logs for jailbreak/root detection or unenrollment events.
- [ ] **Sync Timing:** Check host-side event logs for mobile sync software execution at unusual times.
- [ ] **Install Patterns:** Flag app install/uninstall patterns post-incident.

---

### Phase 8 — Network IOC Extraction
- [ ] **Endpoint Harvesting:** Extract IPs, domains, and URLs from app configs and browser history.
- [ ] **Persistence C2:** Flag outbound connections from LaunchAgent-backed processes.
- [ ] **App C2:** Flag C2 addresses embedded in extracted APKs or iOS app plists.
- [ ] **VPN Audit:** Check for VPN configuration endpoints installed on device.
- [ ] **Metadata Analysis:** Check photo/document EXIF for embedded GPS coordinates.
- [ ] **Mobile Intel:** Enrich extracted IOCs against Citizen Lab, Amnesty Tech, and vendor feeds.
- [ ] **Credential Leak:** Flag corporate credentials (tokens, VPN passwords) in mobile backup artifacts.
- [ ] **Proxy Audit:** Check for proxy configuration on device.

---

### Phase 9 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mobile Mapping:**
    - **T1430:** Spyware — Mobile
    - **T1430.001:** Location Tracking
    - **T1517:** Access Notifications
    - **T1412:** Capture SMS Messages
    - **T1433:** Call Log Access
    - **T1410:** Network Traffic Capture — Mobile
    - **T1458:** Rogue MDM Profile
    - **T1475:** Deliver Malicious App
    - **T1404:** Exploit via Installed App
    - **T1052:** Exfiltration via Physical Medium
    - **T1414:** Access Sensitive Data in Device Logs
    - **T1418:** Abuse Accessibility Features
    - **T1401:** Device Administrator Abuse
- [ ] **Connection Timeline:** Establish when device was connected to corporate host and what was transferred.
- [ ] **Exposure Assessment:** Assess what corporate data was accessible via mobile apps or backups.
- [ ] **Escalation:** Flag if a physical device acquisition is warranted based on logical backup findings.
- [ ] **Policy Audit:** Note BYOD policy implications (HR/Legal routing).
- [ ] **Final Output:** Score by severity and output structured findings file for analyst handoff.

> **Analysis Note:** Mobile artifact analysis from a desktop image is limited to backup and sync artifacts. Full forensic analysis requires physical acquisition via UFED, GrayKey, or Cellebrite. Flag device acquisition recommendation in findings if warranted by hits.
