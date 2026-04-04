# Forensic Threat Taxonomy

A reference guide for classifying evidence patterns during digital forensics investigations.

## Data Exfiltration
**Definition:** Unauthorized transfer of data from an organization to an external destination

**Evidence Patterns:**
- Files found in unusual locations (USB drives, cloud storage, personal devices)
- Large data transfers during off-hours
- Access to sensitive files outside job scope
- Email attachments to personal accounts
- Compressed archives of sensitive data
- Recent documents showing company files

**Key Artifacts:**
- MFT timestamps showing file copies
- USB device connection logs (setupapi.log, SYSTEM\CurrentControlSet\Enum\USBSTOR)
- Email headers showing attachments
- Browser download history
- Cloud storage sync logs
- Shellbags showing access to external drives

---

## Malware Infection
**Definition:** Presence of malicious software designed to damage, disrupt, or gain unauthorized access

**Evidence Patterns:**
- Suspicious processes in memory
- Unknown files in system directories
- Modified system files
- Unusual network connections
- Scheduled tasks running malicious payloads
- Registry persistence mechanisms

**Key Artifacts:**
- Prefetch files showing execution history
- Event logs (Security, System)
- Browser cache showing malware downloads
- Temporary files in unusual locations
- Modified hosts file
- Startup folder entries

---

## Ransomware
**Definition:** Malware that encrypts files and demands payment for decryption

**Evidence Patterns:**
- Encrypted files with changed extensions (.encrypted, .locked, etc.)
- Ransom notes (README files, desktop backgrounds)
- Mass file modification timestamps
- Shadow copy deletion (vssadmin delete shadows)
- Disabled recovery options

**Key Artifacts:**
- Ransom note files
- Event logs showing service stops
- File extension changes
- Bitcoin wallet addresses in files
- Process creation logs for encryption tools

---

## Insider Threat
**Definition:** Malicious activity by someone with authorized access (employee, contractor)

**Evidence Patterns:**
- Accessing data outside normal job function
- Downloads before resignation
- Privilege escalation attempts
- Covering tracks (log deletion, timestamp manipulation)
- Communication with competitors

**Key Artifacts:**
- NTUSER.DAT showing recent documents
- Browser history showing job searches
- File access patterns
- Email to external competitors
- VPN logs showing unusual access times

---

## Financial Fraud
**Definition:** Manipulation of financial records or systems for personal gain

**Evidence Patterns:**
- Modified spreadsheets or databases
- Unauthorized transactions
- Ghost employees in payroll
- Invoice manipulation
- Embezzlement evidence

**Key Artifacts:**
- Document metadata showing modifications
- Database transaction logs
- Spreadsheet revision history
- Email communications about finances
- Access to financial systems

---

## Corporate Espionage
**Definition:** Theft of trade secrets or proprietary information for competitive advantage

**Evidence Patterns:**
- Access to R&D documents
- Communication with competitors
- Patent filings by competitors shortly after access
- Unusual printing of sensitive documents
- Photography of screens

**Key Artifacts:**
- Document access logs
- Email to external competitors
- USB device connections
- Print spooler logs
- Cloud storage uploads of confidential data

---

## Sabotage
**Definition:** Deliberate destruction or damage to systems or data

**Evidence Patterns:**
- Deleted critical files
- Configuration changes causing outages
- Data corruption
- System downtime during critical periods
- Logic bombs (time-delayed malicious code)

**Key Artifacts:**
- File deletion logs
- Configuration change records
- Event logs showing service failures
- Recycle Bin contents
- Volume Shadow Copy deletion

---

## Credential Theft
**Definition:** Stealing authentication credentials for unauthorized access

**Evidence Patterns:**
- Keyloggers or credential harvesting tools
- Unauthorized logins from unusual locations
- Password spraying attempts
- Stolen session cookies
- Credential dumping (LSASS, SAM)

**Key Artifacts:**
- Memory dumps showing credential harvesting
- Browser stored passwords
- Event logs showing failed then successful logins
- Presence of credential dumping tools
- Network traffic showing credential transmission

---

## Privilege Escalation
**Definition:** Exploiting vulnerabilities to gain higher-level permissions

**Evidence Patterns:**
- Exploitation of known vulnerabilities
- Token impersonation
- Bypassing User Account Control (UAC)
- Kernel exploits
- Service account compromise

**Key Artifacts:**
- Event logs showing privilege changes
- Process tokens
- Exploit tool presence
- Modified system binaries
- Scheduled tasks with SYSTEM privileges

---

## Anti-Forensics
**Definition:** Techniques used to hide, destroy, or manipulate evidence

**Evidence Patterns:**
- Log file deletion or clearing
- Timestamp manipulation
- File wiping (secure deletion)
- Encrypted communications
- Virtual machine usage for isolation

**Key Artifacts:**
- Event log gaps
- MFT timestamp anomalies
- Presence of wiping tools
- VPN/proxy usage
- Encrypted container files

---

## Network Intrusion
**Definition:** Unauthorized access to network resources from external sources

**Evidence Patterns:**
- Unusual network traffic
- Port scanning activity
- Exploitation of public-facing services
- Lateral movement
- Persistence mechanisms

**Key Artifacts:**
- Firewall logs
- Network traffic captures
- Authentication logs
- Registry entries for remote access tools
- Process connections to external IPs

---

## Usage Guide

When analyzing evidence, ask:
1. **What pattern does this evidence match?**
2. **What artifacts should I expect to find?**
3. **What timeline makes sense for this threat?**
4. **What gaps in evidence need explanation?**

Always correlate multiple artifacts before concluding threat type.
