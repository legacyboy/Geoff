# Playbook Gap Analysis — Narrative/Communications Evidence Collection

## Current Playbook Inventory

| Playbook | Focus | Collects Communications? |
|----------|-------|------------------------|
| PB-SIFT-000 | Triage & Execution Planning | No |
| PB-SIFT-001 | Initial Access | No |
| PB-SIFT-002 | Execution | No |
| PB-SIFT-003 | Persistence | No |
| PB-SIFT-004 | Privilege Escalation | No |
| PB-SIFT-005 | Credential Theft | No |
| PB-SIFT-006 | Lateral Movement | No |
| PB-SIFT-007 | Exfiltration | No |
| PB-SIFT-008 | Malware Hunting | No |
| PB-SIFT-009 | Ransomware | No |
| PB-SIFT-010 | Living-off-the-Land | No |
| PB-SIFT-011 | Impact/Data Destruction | No |
| PB-SIFT-012 | Anti-Forensics | No |
| PB-SIFT-013 | Cloud/Network Share | No |
| PB-SIFT-014 | Linux Forensics | No |
| PB-SIFT-015 | Data Staging | No |
| PB-SIFT-016 | Cross-Image Correlation | No |
| PB-SIFT-017 | REMnux Malware Analysis | No |
| PB-SIFT-018 | Malware Analysis | No |
| PB-SIFT-019 | Command & Control | No |
| PB-SIFT-020 | Timeline Analysis | No |
| PB-SIFT-021 | **Mobile Analysis** | ✅ SMS, WhatsApp, Telegram, iOS Mail, Android Email, call logs, contacts |
| PB-SIFT-022 | **Browser Forensics** | ✅ History, cookies, downloads, saved passwords |
| PB-SIFT-023 | **Email Forensics** | ✅ PST/OST, MBOX, EML, DBX, phishing detection |
| PB-SIFT-024 | macOS Forensics | No |
| PB-SIFT-025 | Cloud & Enterprise IR | No |
| PB-SIFT-026 | File Carving & Recovery | No |
| PB-SIFT-027 | Memory Forensics | No |
| PB-SIFT-028 | Windows Modern Artifacts | No |
| PB-SIFT-029 | **Encrypted Containers** | ✅ BitLocker, FileVault, VeraCrypt, LUKS, key search |
| PB-SIFT-030 | Cloud Sync Artifacts | No |
| PB-SIFT-031 | Enterprise Collaboration | No |
| PB-SIFT-032 | VM Snapshot Forensics | No |
| PB-SIFT-033 | Container Forensics | No |
| PB-SIFT-034 | Network Device Forensics | No |
| PB-SIFT-035 | Active Directory DC Forensics | No |
| PB-SIFT-036 | **PCAP Network Forensics** | ✅ HTTP extraction, flow analysis, DNS analysis, tunneling detection |
| PB-SIFT-037 | EDR Telemetry Analysis | No |
| PB-SIFT-038 | Web Shell Indicators | No |
| PB-SIFT-039 | Insider Threat Behavioral | No |
| PB-SIFT-040 | IoT Device Forensics | No |
| PB-SIFT-050 | DNS Forensics | No |
| PB-SIFT-051 | YARA Scanning | No |
| PB-SIFT-052 | Hash Correlation & NSRL | No |
| **PB-SIFT-060** | **Communications Analysis** | ✅ Reads from existing findings (no collection) |

## What PB-SIFT-060 Needs

The `CommunicationsAnalyzer.extract_communications()` method looks for findings where:
- `module == "email"` or playbook contains "email"
- Function name contains "pst", "mbox", "eml", "msg", "dbx"
- Output text contains "From:", "Subject:", "Received:"

It parses message blocks with `From:`, `To:`, `Subject:`, `Date:` fields.

**It does NOT currently look for:**
- Chat/messaging findings (WhatsApp, Telegram, SMS)
- Mobile SMS/call log findings
- Social media artifacts
- Forum/chat website content from browser history

## Gaps Identified

### GAP 1: Chat/Messaging Not Fed to CommunicationsAnalyzer
**Severity: HIGH**

PB-SIFT-021 (Mobile) already extracts WhatsApp, Telegram, SMS, and call logs. But `extract_communications()` only looks for email-format findings. Chat messages have different schemas (sender, receiver, timestamp, message body) and aren't being picked up.

**Affects:** All three scenarios (NGDC has phone/tablet chats, Narcos has messaging, Owl has chat about owl trade)

**Fix needed:** Update `extract_communications()` to also parse chat-format findings from mobile playbooks.

### GAP 2: No Social Media / Forum Extraction
**Severity: MEDIUM**

Browser history is extracted (PB-SIFT-022) but there's no playbook that specifically looks for social media content, forum posts, or webmail content from browser cache/history. The NGDC scenario involves suspects communicating via webmail and potentially forums.

**Affects:** NGDC scenario (web-based communications)

**Fix needed:** New playbook or extend PB-SIFT-022 to extract webmail/forum content from browser cache.

### GAP 3: No Keylogger/Spyware Artifact Extraction
**Severity: HIGH (for NGDC)**

The NGDC scenario specifically mentions a keylogger installed by Tracy's ex-husband that emails captured keystrokes. Geoff has no playbook that:
- Detects keylogger software from running processes/memory
- Extracts keylogger output files
- Correlates keylogger findings with email artifacts

**Affects:** NGDC scenario (keylogger is central to the plot)

**Fix needed:** New playbook PB-SIFT-061 — Keylogger/Spyware Analysis

### GAP 4: Steganography Detection Not Integrated into Pipeline
**Severity: HIGH (for NGDC)**

The `CommunicationsAnalyzer.detect_steganography()` method exists but is only called from `analyze()`, which runs as part of PB-SIFT-060. The steganography detection walks image/audio files and checks entropy. However:
- It needs the evidence directory path passed in
- It's not integrated into the main evidence scanning pipeline
- The NGDC scenario specifically mentions steganography tools

**Affects:** NGDC scenario (steganography is a key plot point)

**Fix needed:** Ensure PB-SIFT-060 receives the evidence path and steganography detection runs properly.

### GAP 5: No Encrypted File Content Extraction
**Severity: MEDIUM**

PB-SIFT-029 detects encrypted containers (BitLocker, VeraCrypt, etc.) but there's no playbook that:
- Attempts to extract/crack password-protected ZIP/RAR files
- Identifies encrypted email attachments
- Correlates encrypted files with communications

**Affects:** NGDC scenario (encrypted files mentioned), Narcos (potential encrypted evidence)

**Fix needed:** Extend PB-SIFT-029 or create a new playbook for password-protected file analysis.

### GAP 6: No Relationship/Network Graph from Communications
**Severity: MEDIUM**

The `CommunicationsAnalyzer.build_communication_graph()` and `identify_relationships()` methods exist but only process email-format findings. They don't incorporate:
- Phone call logs (who called who, when, duration)
- SMS/chat contact networks
- Cross-platform identity correlation (same person on email + WhatsApp + phone)

**Affects:** All three scenarios (understanding who's involved is key)

**Fix needed:** Extend graph building to include call logs, SMS, and chat contacts.

### GAP 7: No PCAP Content Extraction for Communications
**Severity: MEDIUM**

PB-SIFT-036 extracts HTTP and flows from PCAPs, but there's no playbook that:
- Extracts email content from captured network traffic (SMTP/POP3/IMAP)
- Extracts chat messages from network traffic
- Reconstructs webmail sessions from PCAPs

The NGDC scenario has both interior and exterior PCAPs that could contain actual communications.

**Affects:** NGDC scenario (PCAPs may contain unencrypted communications)

**Fix needed:** New playbook or extend PB-SIFT-036 for communications extraction from PCAPs.

### GAP 8: No macOS-Specific Communications Artifacts
**Severity: MEDIUM**

PB-SIFT-024 (macOS Forensics) exists but doesn't specifically extract:
- macOS Mail app data
- iMessage/SMS from macOS (continuity)
- macOS Notes (can contain plaintext communications)
- Keychain passwords for email/chat accounts

The NGDC scenario involves a MacBook Air with spyware.

**Affects:** NGDC scenario (Tracy's MacBook Air)

**Fix needed:** Extend PB-SIFT-024 or create macOS communications extraction.

## Recommended New Playbooks

| Priority | Playbook | Name | What It Collects |
|----------|----------|------|------------------|
| **HIGH** | PB-SIFT-061 | Keylogger/Spyware Analysis | Detect keyloggers from process/memory, extract keylogger output files, correlate with email findings |
| **HIGH** | PB-SIFT-062 | Chat & Messaging Analysis | Extract WhatsApp, Telegram, SMS, iMessage content into structured format for CommunicationsAnalyzer |
| **MEDIUM** | PB-SIFT-063 | PCAP Communications Extraction | Extract emails (SMTP/POP3/IMAP) and chat messages from network captures |
| **MEDIUM** | PB-SIFT-064 | macOS Communications | Extract Mail.app, iMessage, Notes, Keychain from macOS images |
| **LOW** | PB-SIFT-065 | Social Media & Webmail | Extract webmail/forum/social media content from browser cache |

## Priority Summary

**For NGDC (most complex scenario):**
1. ✅ PB-SIFT-021 (Mobile) — already covers phone/tablet SMS, WhatsApp, Telegram
2. ✅ PB-SIFT-023 (Email) — already covers PST/OST/MBOX
3. ✅ PB-SIFT-036 (PCAP) — already covers network traffic
4. ❌ **PB-SIFT-061 (Keylogger)** — NEEDED for the spyware plot
5. ❌ **PB-SIFT-062 (Chat)** — NEEDED to feed chat data into CommunicationsAnalyzer
6. ⚠️ PB-SIFT-060 (Communications) — exists but needs chat input support

**For Narcos (simpler, fewer devices):**
1. ✅ PB-SIFT-023 (Email) — laptop/desktop email
2. ✅ PB-SIFT-021 (Mobile) — if mobile evidence exists
3. ⚠️ PB-SIFT-060 — needs chat input support

**For Owl (simplest, chat-focused):**
1. ❌ **PB-SIFT-062 (Chat)** — NEEDED for the chat-based scenario
2. ✅ PB-SIFT-021 (Mobile) — if mobile evidence exists

## Immediate Fixes (No New Playbooks Needed)

1. **Update `extract_communications()`** to also parse chat-format findings (WhatsApp, Telegram, SMS) — this is a code change to `geoff_communications.py`, not a new playbook
2. **Ensure PB-SIFT-060 receives evidence path** for steganography detection
3. **Add chat findings to communication graph** — extend `build_communication_graph()` to include chat contacts
