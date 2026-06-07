# Playbook Gap Analysis: Communications & Narrative Evidence

**Date:** 2025-06-05  
**Author:** Steve (Steve4) — Geoff DFIR  
**Scope:** Identify playbooks needed to collect raw evidence that PB-SIFT-060 (Communications Analysis) and the RAG system require, but that no existing playbook currently gathers.

---

## 1. Current Playbook Inventory

| Playbook ID | Name | Evidence Types Collected |
|---|---|---|
| PB-SIFT-000 | Triage & Execution Planning | Memory: process list, network scan, malware scan |
| PB-SIFT-001 | Initial Access | PCAPs (analyze, HTTP extract), EVT/EVTX logs, disk images (file listing, image verify) |
| PB-SIFT-002 | Execution | Memory (process list, malware scan), disk images (file listing) |
| PB-SIFT-003 | Persistence | Registry (autoruns, services, UserAssist, Shellbags), disk images (LNK, scheduled tasks, crontabs), memory |
| PB-SIFT-004 | Privilege Escalation | Memory (injection, creds, LSADUMP, malfind, cmdline, strings), registry (services, policies, SAM, service hijack), disk (prefetch, amcache, deleted, strings) |
| PB-SIFT-005 | Credential Theft | Memory (process, malware), disk (filesystem), registry (parse) |
| PB-SIFT-006 | Lateral Movement | PCAPs (analyze, flows), EVT/EVTX, memory (network scan) |
| PB-SIFT-007 | Exfiltration | PCAPs (analyze, HTTP), memory (network), EVT/EVTX, registry (USB, mounted devices, network shares) |
| PB-SIFT-008 | Malware Hunting | Disk (partition, filesystem, file listing, strings, bulk_extractor, signature mismatch), memory (process, malware, YARA) |
| PB-SIFT-009 | Ransomware | Disk (file listing, strings, YARA), memory (process, malware, YARA), other files (strings, YARA) |
| PB-SIFT-010 | Living-off-the-Land | EVT/EVTX, memory (process, strings), disk (deleted, strings, file listing) |
| PB-SIFT-011 | Impact/Data Destruction | Disk (VSS, prefetch, deleted, mactime), EVT/EVTX, registry (UserAssist, Shimcache) |
| PB-SIFT-012 | Anti-Forensics | EVT/EVTX, disk (file listing, filesystem, backdoors, VSS, Eraser/CCleaner/SDelete detection, UsnJrnl), memory |
| PB-SIFT-013 | Data from Cloud/Network Share | Registry (network, MountPoints2, UserAssist, USB), disk (OneDrive, Google Drive, Dropbox, iCloud, USB staging, exfiltration), memory (network, processes), PCAPs |
| PB-SIFT-014 | Linux Forensics | Syslogs, disk (partition, file listing, crontabs, backdoors) |
| PB-SIFT-015 | Data Staging | Disk (file listing, strings), PCAPs |
| PB-SIFT-016 | Cross-Image Correlation | Disk (Plaso timeline, merge, correlate) |
| PB-SIFT-017 | REMnux Malware Analysis | Other files (DiE, ExifTool, ClamAV, ssdeep, hashdeep, FLOSS, radare2, peframe, UPX, PDF, OLE, JS), memory (FLOSS, ClamAV, ssdeep), disk (DiE, ClamAV, ExifTool, hashdeep), PCAPs (INetSim, FakeDNS) |
| PB-SIFT-018 | Malware Analysis SOP | Disk (timeline, strings), PCAPs, memory (process), EVT/EVTX, registry, syslogs |
| PB-SIFT-019 | Command & Control | PCAPs (analyze, flows, Zeek, TLS fingerprints), memory (process, network), EVT/EVTX, disk (file listing, strings) |
| PB-SIFT-020 | Timeline Analysis | Disk (Plaso timeline, mactime, sort) |
| PB-SIFT-021 | Mobile Analysis | iOS backups (device info, accounts, SMS, call history, contacts, mail, WhatsApp, Telegram, Safari, location, notifications, usage, photo EXIF, keychain, health, jailbreak, iLEAP), Android data dirs (device info, accounts, SMS, call logs, contacts, email, WhatsApp, Telegram, browser, location, notifications, usage, photo EXIF, root detection, aLEAP) |
| PB-SIFT-022 | Browser Forensics | Disk (file listing, browser artifact extraction), other files (history, cookies, downloads, saved passwords) |
| PB-SIFT-023 | Email Forensics | Disk (file listing, email artifact extraction), other files — PST, DBX, MBOX, EML, phishing detection |
| PB-SIFT-024 | macOS Forensics | Disk (filesystem, file listing), syslogs, other files (plist, unified log, launch agents) |
| PB-SIFT-025 | Cloud & Enterprise IR | Other files (CloudTrail, Azure, GCP, REMnux tools, strings, PII, APK/IPA/binary) |
| PB-SIFT-026 | File Carving & Recovery | Disk (PhotoRec) |
| PB-SIFT-027 | Memory Forensics | Memory (analyze, processes, network, injected code, registry, creds, DLL list, handles, mutants, API hooks, modscan, VAD, procdump, memmap) |
| PB-SIFT-028 | Windows Modern Artifacts | Disk (prefetch, jumplists, LNK, amcache, SRUM, Timeline, Defender, BITS), registry (Shimcache) |
| PB-SIFT-029 | Encrypted Containers | Disk (BitLocker, FileVault, VeraCrypt, LUKS, key search, anti-forensics), other files (key search) |
| PB-SIFT-030 | Cloud Sync Artifacts | Other files (OneDrive, Google Drive, Dropbox, iCloud, Box, exfiltration, Google Drive scan) |
| PB-SIFT-031 | Enterprise Collaboration | Other files (Teams, Slack, Discord, Skype, Zoom) |
| PB-SIFT-032 | VM Snapshot Forensics | Memory (VM extract, snapshots), disk (VM extract, escape detect) |
| PB-SIFT-033 | Container Forensics | Other files (enumerate, filesystem, image, logs, Kubernetes, supply chain) |
| PB-SIFT-034 | Network Device Forensics | Disk (strings ×2, file listing), syslogs, other files (strings) |
| PB-SIFT-035 | Active Directory DC Forensics | Other files (SQLite), registry (users, parse) |
| PB-SIFT-036 | PCAP Network Forensics | PCAPs (analyze, HTTP, flows, DNS analysis, DNS tunneling) |
| PB-SIFT-037 | EDR Telemetry Analysis | Other files (EVTX parse), disk (file listing, strings) |
| PB-SIFT-038 | Web Shell Indicators | EVT/EVTX, syslogs (Apache/IIS), disk (file listing, deleted), memory (process, malware), other files (strings) |
| PB-SIFT-039 | Insider Threat Behavioral | Registry (UserAssist, Shellbags, SRUM, Shimcache), disk (file listing, deleted), EVT/EVTX, other files (strings) |
| PB-SIFT-040 | IoT Device Forensics | Disk (file listing, fsstat), other files (strings) |
| PB-SIFT-050 | DNS Forensics | PCAPs (DNS analysis, tunneling detection) |
| PB-SIFT-051 | YARA Scanning | Disk, memory, other files (YARA scans) |
| PB-SIFT-052 | Hash Correlation | Other files (hash_file) |
| PB-SIFT-060 | Communications Analysis | **No direct tool steps** — reads from findings produced by other playbooks (PB-SIFT-023, etc.) and runs stego/encryption scans on evidence directory |

### Pass 2 Playbooks (timeline-intelligence-driven)

| Playbook ID | Name | Trigger |
|---|---|---|
| PB-SIFT-100 | Process Chain Investigation | cross_device_process_chain |
| PB-SIFT-101 | USB Lateral Movement Investigation | usb_lateral_movement |
| PB-SIFT-102 | Temporal Anomaly Investigation | temporal_anomaly, off_hours_cluster |
| PB-SIFT-103 | IOC Cross-Reference Investigation | ioc_correlation, file_beaconing |
| PB-SIFT-104 | Dwell Window Deep-Dive | dwell_window |

---

## 2. What PB-SIFT-060 (CommunicationsAnalyzer) Needs

The `CommunicationsAnalyzer` in `geoff_communications.py` provides five analysis functions:

| Function | Input Required | Source |
|---|---|---|
| `extract_communications()` | Findings with `module == "email"` or functions containing `pst`, `mbox`, `eml`, `msg`, `dbx`, or output containing `From:`/`Subject:`/`Received:` headers | PB-SIFT-023 (Email Forensics) |
| `build_communication_graph()` | Messages from `extract_communications()` | Derived from email findings |
| `detect_steganography()` | Image and audio files on the evidence directory (`.jpg`, `.png`, `.gif`, `.bmp`, `.tiff`, `.webp`, `.mp3`, `.wav`, `.flac`, `.ogg`, `.aac`, `.wma`, `.m4a`) | Direct filesystem walk of evidence dir |
| `detect_encrypted_files()` | Encrypted containers (`.tc`, `.vc`, `.luks`, `.dmg`, `.aes`), password-protected ZIPs, high-entropy 7z/RAR archives | Direct filesystem walk of evidence dir |
| `identify_relationships()` | Messages from `extract_communications()` | Derived from email findings |
| `generate_narrative()` | Messages, graph, relationships + LLM | Derived from all above |

### Critical Observation

PB-SIFT-060's `extract_communications()` **only processes email-type findings**. It filters on `module == "email"` or function names containing `pst`, `mbox`, `eml`, `msg`, `dbx`, or output containing `From:`/`Subject:`/`Received:` headers. 

**It does NOT process:**
- Chat/messaging databases (WhatsApp, Telegram, Signal, iMessage)
- SMS databases
- Social media messages
- Browser-based communications (webmail, in-browser chats)
- Collaboration tool messages (Teams, Slack, Discord) in a structured way

The stego and encrypted file scanners walk the raw evidence directory directly, so they work regardless of playbook coverage. But the communication graph and relationship analysis are **email-only**.

---

## 3. Gaps Identified

### GAP-01: No Steganography Collection Playbook

**What's missing:** Geoff has no playbook that proactively collects and catalogs steganography suspects. PB-SIFT-060's `detect_steganography()` walks the evidence directory at runtime, but:
- It only checks entropy on image/audio files >1KB
- It doesn't use dedicated stego detection tools (stegdetect, stegsolve, zsteg, etc.)
- It doesn't extract hidden payloads — just flags high-entropy files
- No YARA rules specifically for stego tool artifacts

**Scenarios affected:** National Gallery DC 2012 (explicitly involves steganography)

**Priority: HIGH**

### GAP-02: No Keylogger/Spyware Detection Playbook

**What's missing:** No playbook specifically targets keylogger or spyware detection. PB-SIFT-008 (Malware Hunting) and PB-SIFT-027 (Memory Forensics) do general malware scanning, but:
- No dedicated keylogger detection (scan for known keylogger binaries, hooks, accessibility services, keyboard intercept drivers)
- No overlay attack detection (Android accessibility service abuse)
- MOBILE_MALWARE_Specialist has regex for keyloggers in APK manifests, but it's only triggered by `.apk` files in PB-SIFT-025 (Cloud & Enterprise IR), not by any dedicated workflow
- No playbook extracts keylogger artifacts from Windows (hook DLLs, SetWindowsHookEx, keyboard filter drivers)

**Scenarios affected:** National Gallery DC 2012 (keylogger spyware), 2019 Narcos (surveillance malware)

**Priority: HIGH**

### GAP-03: No Chat/Messaging Aggregation Playbook

**What's missing:** PB-SIFT-060's `extract_communications()` only processes email. While PB-SIFT-021 (Mobile Analysis) extracts WhatsApp and Telegram messages individually, and PB-SIFT-031 (Enterprise Collaboration) processes Teams/Slack/Discord, there's **no playbook that aggregates all chat/messaging into a unified format** that PB-SIFT-060 can consume. The specialist functions exist but:
- They produce findings under different module names (`mobile`, `collaboration`)
- PB-SIFT-060's filter explicitly only matches `module == "email"` or email-related function names
- SMS/iMessage from mobile playbooks never feed into the communication graph

**Scenarios affected:** All three scenarios (2019 Owl = chat messages, 2019 Narcos = relationship analysis, National Gallery = email conversations)

**Priority: HIGH**

### GAP-04: No Social Media Artifact Collection Playbook

**What's missing:** No playbook collects social media artifacts (Facebook, Twitter/X, Instagram, LinkedIn, Reddit posts/DMs). While browser forensics (PB-SIFT-022) captures web history, it doesn't extract structured social media data:
- No extraction of social media API caches, local databases, or exported archives
- No parsing of Facebook Messenger, Twitter DMs, Instagram messages from browser storage or app data
- PB-SIFT-060 can't graph social media communications

**Scenarios affected:** 2019 Narcos (suspect relationship mapping), National Gallery DC 2012 (covert communications)

**Priority: MEDIUM**

### GAP-05: No Mobile Device Integration with Communications Pipeline

**What's missing:** PB-SIFT-021 (Mobile Analysis) extracts SMS, call logs, contacts, WhatsApp, and Telegram data, but these findings flow through the `mobile` module. PB-SIFT-060 only reads from the `email` module. The mobile data is siloed:
- iOS `extract_ios_sms()` and Android `extract_android_sms()` produce structured message data (sender, text, timestamp, service type) but it never enters the communication graph
- Call logs (iOS/Android) are extracted but not linked to the relationship analysis
- Contacts from mobile are extracted but not correlated with email contacts
- No cross-referencing between mobile contacts and email address books

**Scenarios affected:** National Gallery DC 2012 (phone + tablet), 2019 Narcos (multiple devices), 2019 Owl (mobile chat messages)

**Priority: HIGH**

### GAP-06: No Dedicated Signal/Secure Messenger Extraction

**What's missing:** PB-SIFT-021 lists WhatsApp and Telegram extraction but has **no Signal extraction function**. The `_CHAT_DB_MAP` in the EMAIL_Specialist's `detect_sms_phishing` includes WhatsApp and Telegram databases but not Signal's encrypted SQLite database. Signal stores messages in an encrypted SQLCipher database that requires the device key to decrypt. There's:
- No Signal database decryption capability
- No playbook step to locate Signal data directories
- No integration of Signal findings into the communication graph

**Scenarios affected:** All scenarios where suspects may use encrypted messaging

**Priority: MEDIUM**

### GAP-07: No Steganography Tool Artifact Detection

**What's missing:** Complementary to GAP-01, no playbook detects **steganography tool usage artifacts**:
- No detection of stego tool installation (OpenStego, Steghide, SilentEye, etc.) in prefetch, registry, or file system
- No detection of stego tool execution artifacts (command history, batch scripts)
- No extraction of LSB or palette anomalies in image files beyond entropy checks
- PB-SIFT-012 (Anti-Forensics) detects Eraser, CCleaner, SDelete but not stego tools

**Scenarios affected:** National Gallery DC 2012 (explicitly uses steganography)

**Priority: HIGH**

### GAP-08: No Encrypted File Password Recovery Playbook

**What's missing:** PB-SIFT-029 (Encrypted Containers) detects encrypted volumes and PB-SIFT-060's `detect_encrypted_files()` flags password-protected ZIPs, but neither playbook attempts **password recovery or cracking**:
- No dictionary/brute-force attack on encrypted files (John the Ripper, hashcat)
- No extraction of password hints from memory dumps, registry, or browser saved passwords
- No correlation between browser saved passwords (PB-SIFT-022) and encrypted containers
- CRYPTO_Specialist's `search_keys()` just does a naive text search for "password=" strings

**Scenarios affected:** National Gallery DC 2012 (encrypted files), 2019 Narcos (encrypted laptop)

**Priority: MEDIUM**

### GAP-09: No Webmail/In-Browser Email Extraction

**What's missing:** PB-SIFT-022 (Browser Forensics) extracts history, cookies, downloads, and saved passwords but not **webmail content**. Gmail, Outlook.com, Yahoo Mail caches are stored in browser IndexedDB/LocalStorage/Cache Storage. No playbook:
- Extracts webmail cached content from browser databases
- Parses Gmail offline cache or Outlook.com IndexedDB
- Correlates browser-saved credentials with email accounts for account identification

**Scenarios affected:** National Gallery DC 2012, 2019 Narcos (suspects likely used webmail)

**Priority: MEDIUM**

### GAP-10: No PCAP Message Extraction Playbook

**What's missing:** PB-SIFT-036 (PCAP Network Forensics) analyzes network flows and DNS but doesn't extract **application-layer communications**:
- No SMTP/IMAP/POP3 message extraction from PCAPs
- No XMPP/IRC/ICQ message reconstruction
- No HTTP webmail session extraction
- No extraction of file transfers via email attachments from network captures

**Scenarios affected:** National Gallery DC 2012 (PCAPs with email conversations), 2019 Narcos (network-based communications)

**Priority: MEDIUM**

### GAP-11: No Cross-Device Contact/Relationship Correlation Playbook

**What's missing:** While PB-SIFT-016 (Cross-Image Correlation) creates timelines across devices, there's no playbook that:
- Merges contact lists from multiple sources (email address books, mobile contacts, browser autofill, social media connections)
- Builds a unified person graph linking email addresses, phone numbers, social media handles, and device identifiers to real identities
- Correlates phone numbers found in emails with contacts in mobile backups
- Maps the same person appearing across different devices (e.g., Tracy on laptop vs. phone)

**Scenarios affected:** All three scenarios require relationship mapping between suspects across devices

**Priority: HIGH**

---

## 4. Recommended New Playbooks

### PB-SIFT-061: Steganography Detection & Extraction

**Priority:** HIGH  
**Scenarios:** National Gallery DC 2012

| Step | Tool | Function | Evidence Type |
|---|---|---|---|
| 1 | sleuthkit | list_files (with image/media filter) | disk_images |
| 2 | stego | detect_steghide | disk_images, other_files |
| 3 | stego | detect_openstego | disk_images, other_files |
| 4 | stego | detect_zsteg (PNG) | other_files |
| 5 | stego | detect_jsteg (JPEG) | other_files |
| 6 | stego | entropy_analysis | other_files |
| 7 | stego | extract_lsb_payload | other_files |
| 8 | stego | detect_palette_anomaly | other_files |
| 9 | registry | extract_stego_tool_artifacts | registry_hives |
| 10 | windows | analyze_prefetch (stego tool names) | disk_images |
| 11 | strings | extract_strings (stego keywords) | disk_images, other_files |

**Note:** Requires new `STEGO_Specialist` class in `sift_specialists_extended.py`.

---

### PB-SIFT-062: Keylogger & Spyware Detection

**Priority:** HIGH  
**Scenarios:** National Gallery DC 2012, 2019 Narcos

| Step | Tool | Function | Evidence Type |
|---|---|---|---|
| 1 | registry | extract_autoruns (filter for keylogger hooks) | registry_hives |
| 2 | registry | extract_keyboard_filter_drivers | registry_hives |
| 3 | windows | analyze_prefetch (keylogger process names) | disk_images |
| 4 | memory | find_injected_code | memory_dumps |
| 5 | volatility | dll_list (check for hook DLLs) | memory_dumps |
| 6 | volatility | apihooks (detect SetWindowsHookEx) | memory_dumps |
| 7 | strings | extract_strings (keylogger config/log paths) | disk_images, other_files |
| 8 | yara | scan_disk_image (keylogger YARA rules) | disk_images |
| 9 | yara | scan_memory_dump (keylogger YARA rules) | memory_dumps |
| 10 | mobile_malware | analyze_apk (Android keylogger/spyware detection) | other_files |

**Note:** Requires new specialist functions for keylogger-specific registry analysis and YARA rulesets.

---

### PB-SIFT-063: Chat & Messaging Aggregation

**Priority:** HIGH  
**Scenarios:** All three

| Step | Tool | Function | Evidence Type |
|---|---|---|---|
| 1 | mobile | extract_ios_sms | mobile_backups |
| 2 | mobile | extract_android_sms | mobile_backups |
| 3 | mobile | extract_whatsapp (iOS + Android) | mobile_backups |
| 4 | mobile | extract_telegram (iOS + Android) | mobile_backups |
| 5 | messaging | extract_signal | mobile_backups, other_files |
| 6 | messaging | extract_facebook_messenger | other_files, disk_images |
| 7 | messaging | extract_instagram_messages | other_files, disk_images |
| 8 | messaging | extract_twitter_messages | other_files, disk_images |
| 9 | messaging | extract_discord_messages | other_files |
| 10 | messaging | extract_slack_messages | other_files |
| 11 | messaging | extract_teams_messages | other_files |
| 12 | messaging | extract_skype_messages | other_files |
| 13 | email | detect_sms_phishing | other_files |
| 14 | messaging | normalize_messages | all |

**Note:** This playbook aggregates all chat/messaging sources and normalizes them into a unified message format that PB-SIFT-060 can consume. Requires extending `extract_communications()` to accept `module == "messaging"` alongside `module == "email"`.

---

### PB-SIFT-064: Mobile-Desktop Communication Bridge

**Priority:** HIGH  
**Scenarios:** National Gallery DC 2012, 2019 Narcos, 2019 Owl

| Step | Tool | Function | Evidence Type |
|---|---|---|---|
| 1 | mobile | extract_ios_contacts | mobile_backups |
| 2 | mobile | extract_android_contacts | mobile_backups |
| 3 | mobile | extract_ios_sms | mobile_backups |
| 4 | mobile | extract_android_sms | mobile_backups |
| 5 | mobile | extract_ios_call_history | mobile_backups |
| 6 | mobile | extract_android_call_logs | mobile_backups |
| 7 | mobile | extract_ios_mail | mobile_backups |
| 8 | mobile | extract_android_email | mobile_backups |
| 9 | browser | extract_history (mobile sync data) | other_files |
| 10 | communications | correlate_contacts | N/A (cross-source) |
| 11 | communications | build_person_graph | N/A (cross-source) |

**Note:** This playbook specifically bridges mobile findings into the PB-SIFT-060 communication pipeline. It requires extending `extract_communications()` to also match `module == "mobile"` and function names like `extract_ios_sms`, `extract_android_sms`, etc.

---

### PB-SIFT-065: Social Media Forensics

**Priority:** MEDIUM  
**Scenarios:** 2019 Narcos, National Gallery DC 2012

| Step | Tool | Function | Evidence Type |
|---|---|---|---|
| 1 | social | extract_facebook_cache | disk_images, other_files |
| 2 | social | extract_twitter_cache | disk_images, other_files |
| 3 | social | extract_instagram_cache | disk_images, other_files |
| 4 | social | extract_linkedin_cache | disk_images, other_files |
| 5 | social | extract_reddit_cache | disk_images, other_files |
| 6 | browser | extract_history (social media URLs) | other_files |
| 7 | browser | extract_cookies (social media sessions) | other_files |
| 8 | browser | extract_saved_passwords (social media accounts) | other_files |
| 9 | social | extract_direct_messages | other_files |
| 10 | messaging | normalize_messages | all |

**Note:** Requires new `SOCIAL_Specialist` class for platform-specific cache/database parsing.

---

### PB-SIFT-066: Steganography Tool Artifact Detection

**Priority:** HIGH  
**Scenarios:** National Gallery DC 2012

| Step | Tool | Function | Evidence Type |
|---|---|---|---|
| 1 | anti_forensics | detect_stego_tools | disk_images |
| 2 | registry | extract_stego_registry_artifacts | registry_hives |
| 3 | windows | analyze_prefetch (stego tool names) | disk_images |
| 4 | windows | analyze_amcache (stego tool executions) | disk_images |
| 5 | windows | analyze_shimcache | registry_hives |
| 6 | sleuthkit | list_deleted (stego tool binaries) | disk_images |
| 7 | strings | extract_strings (stego keywords) | disk_images |
| 8 | yara | scan_disk_image (stego tool YARA rules) | disk_images |

**Note:** Could be merged with PB-SIFT-061 if desired. Separate recommendation because PB-SIFT-061 focuses on detecting hidden data in images, while this focuses on detecting the tools that created them. Can be combined into a single "Steganography Investigation" playbook.

---

### PB-SIFT-067: Encrypted File Recovery & Password Correlation

**Priority:** MEDIUM  
**Scenarios:** National Gallery DC 2012, 2019 Narcos

| Step | Tool | Function | Evidence Type |
|---|---|---|---|
| 1 | crypto | detect_encrypted_containers | disk_images |
| 2 | crypto | detect_encrypted_archives | disk_images, other_files |
| 3 | browser | extract_saved_passwords | other_files |
| 4 | memory | extract_credentials | memory_dumps |
| 5 | registry | parse_hive (password hints) | registry_hives |
| 6 | crypto | correlate_passwords | N/A (cross-source) |
| 7 | crypto | attempt_container_unlock | disk_images, other_files |
| 8 | strings | extract_strings (password patterns) | disk_images |

**Note:** Requires new `correlate_passwords()` function that cross-references browser saved passwords, memory credential dumps, and registry hints against encrypted container metadata.

---

### PB-SIFT-068: Webmail & In-Browser Email Extraction

**Priority:** MEDIUM  
**Scenarios:** National Gallery DC 2012, 2019 Narcos

| Step | Tool | Function | Evidence Type |
|---|---|---|---|
| 1 | browser | extract_history (webmail URLs) | other_files |
| 2 | browser | extract_cookies (webmail sessions) | other_files |
| 3 | browser | extract_saved_passwords (email accounts) | other_files |
| 4 | email | extract_webmail_cache | disk_images, other_files |
| 5 | email | extract_gmail_offline | other_files |
| 6 | email | extract_outlook_web_cache | other_files |
| 7 | email | normalize_messages | all |

**Note:** Requires new email specialist functions for parsing browser IndexedDB/LocalStorage/Cache Storage for webmail content.

---

### PB-SIFT-069: PCAP Message Extraction

**Priority:** MEDIUM  
**Scenarios:** National Gallery DC 2012, 2019 Narcos

| Step | Tool | Function | Evidence Type |
|---|---|---|---|
| 1 | network | extract_smtp_from_pcap | pcaps |
| 2 | network | extract_imap_from_pcap | pcaps |
| 3 | network | extract_pop3_from_pcap | pcaps |
| 4 | network | extract_http_webmail_from_pcap | pcaps |
| 5 | network | extract_xmpp_from_pcap | pcaps |
| 6 | network | extract_irc_from_pcap | pcaps |
| 7 | network | extract_dns_from_pcap (message server resolution) | pcaps |
| 8 | email | normalize_messages | all |

**Note:** Requires new `NETWORK_Specialist` functions for application-layer message extraction from PCAPs. Currently PCAP analysis stops at flow/DNS/HTTP level.

---

### PB-SIFT-070: Cross-Device Person Correlation

**Priority:** HIGH  
**Scenarios:** All three

| Step | Tool | Function | Evidence Type |
|---|---|---|---|
| 1 | host_correlator | correlate_cross_image | disk_images (multiple) |
| 2 | communications | merge_contact_lists | N/A (cross-source) |
| 3 | communications | deduplicate_persons | N/A (cross-source) |
| 4 | communications | build_unified_person_graph | N/A (cross-source) |
| 5 | communications | correlate_phone_email | N/A (cross-source) |
| 6 | communications | correlate_social_profiles | N/A (cross-source) |
| 7 | communications | map_device_usage | N/A (cross-source) |

**Note:** This is the most architecturally significant gap. PB-SIFT-016 does timeline correlation across devices, but there's no person/entity correlation. The `identify_relationships()` function in PB-SIFT-060 only works on email messages. A full person graph requires merging contacts from email, mobile, browser, and social sources, then deduplicating across devices.

---

## 5. Priority Summary

| Priority | Gap ID | Description | Scenarios |
|---|---|---|---|
| **HIGH** | GAP-01 / PB-SIFT-061 | Steganography detection & extraction | National Gallery DC 2012 |
| **HIGH** | GAP-02 / PB-SIFT-062 | Keylogger & spyware detection | National Gallery DC 2012, 2019 Narcos |
| **HIGH** | GAP-03 / PB-SIFT-063 | Chat/messaging aggregation into PB-SIFT-060 pipeline | All three |
| **HIGH** | GAP-05 / PB-SIFT-064 | Mobile-desktop communication bridge | All three |
| **HIGH** | GAP-07 / PB-SIFT-066 | Steganography tool artifact detection | National Gallery DC 2012 |
| **HIGH** | GAP-11 / PB-SIFT-070 | Cross-device person correlation | All three |
| **MEDIUM** | GAP-04 / PB-SIFT-065 | Social media artifact collection | 2019 Narcos, National Gallery |
| **MEDIUM** | GAP-06 | Signal/secure messenger extraction | All scenarios |
| **MEDIUM** | GAP-08 / PB-SIFT-067 | Encrypted file password recovery | National Gallery, 2019 Narcos |
| **MEDIUM** | GAP-09 / PB-SIFT-068 | Webmail/in-browser email extraction | National Gallery, 2019 Narcos |
| **MEDIUM** | GAP-10 / PB-SIFT-069 | PCAP message extraction | National Gallery, 2019 Narcos |

---

## 6. Immediate Code Fix Required

The most impactful single fix is extending `CommunicationsAnalyzer.extract_communications()` in `geoff_communications.py` to also match findings from the `mobile` and `collaboration` modules. Currently the filter at line ~175 only matches:

```python
is_email = (
    module == "email"
    or "email" in playbook.lower()
    or any(kw in function for kw in ("pst", "mbox", "eml", "msg", "dbx"))
    or any(kw in output[:200].lower() for kw in ("from:", "subject:", "received:"))
)
```

This should be extended to:

```python
is_communication = (
    module == "email"
    or module == "mobile"
    or module == "collaboration"
    or module == "messaging"
    or "email" in playbook.lower()
    or any(kw in function for kw in (
        "pst", "mbox", "eml", "msg", "dbx",
        "sms", "whatsapp", "telegram", "signal", "imessage",
        "teams", "slack", "discord", "skype", "zoom",
        "facebook", "instagram", "twitter",
    ))
    or any(kw in output[:200].lower() for kw in (
        "from:", "subject:", "received:", "to:",
        "message:", "chat:", "sent:", "received:",
    ))
)
```

This one change would allow PB-SIFT-060 to consume chat and mobile messaging findings that are already being collected, without needing new specialists. The new playbooks (063, 064) would then feed into this expanded filter.

---

## 7. New Specialist Classes Required

| Specialist | For Playbooks | Key Functions |
|---|---|---|
| `STEGO_Specialist` | PB-SIFT-061, PB-SIFT-066 | `detect_steghide`, `detect_zsteg`, `detect_jsteg`, `detect_openstego`, `entropy_analysis`, `extract_lsb_payload`, `detect_palette_anomaly`, `extract_stego_registry_artifacts` |
| `KEYLOGGER_Specialist` | PB-SIFT-062 | `detect_hook_dlls`, `detect_keyboard_filters`, `detect_setwindowshookex`, `detect_accessibility_abuse`, `scan_keylogger_yara` |
| `MESSAGING_Specialist` | PB-SIFT-063 | `extract_signal`, `extract_facebook_messenger`, `extract_instagram_messages`, `extract_twitter_messages`, `normalize_messages` |
| `SOCIAL_Specialist` | PB-SIFT-065 | `extract_facebook_cache`, `extract_twitter_cache`, `extract_instagram_cache`, `extract_linkedin_cache`, `extract_reddit_cache`, `extract_direct_messages` |

---

## 8. Architectural Recommendations

1. **Unify message format:** All messaging specialists (mobile, email, collaboration, social, messaging) should output findings in a common `message` schema: `{from, to, date, subject, body_snippet, service, platform}`. This makes PB-SIFT-060's job trivial.

2. **Register `mobile_backups` evidence type properly:** Mobile backups are currently only processed by PB-SIFT-021. The discovery system should auto-detect iOS backup directories and Android data directories and route them to both PB-SIFT-021 and PB-SIFT-064.

3. **Add `messaging` module name:** The specialist registry should support `module == "messaging"` for the new chat/messaging aggregation playbook, distinct from `email`, `mobile`, and `collaboration`.

4. **Expand PB-SIFT-060's analysis to chat data:** The `extract_communications()` method should have a parallel `extract_chat_messages()` that parses mobile/chat findings into the same format, or better yet, a unified `extract_all_communications()` that handles all module types.

5. **Cross-device person resolution:** The `HostCorrelator` class should be extended to merge person entities (not just timelines) across devices, creating a unified person graph that feeds into PB-SIFT-060's `identify_relationships()`.