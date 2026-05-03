# PB-SIFT-023 — Email Forensics

**Phase:** Collection
**Auto-triggered when:** `.pst`, `.ost`, `.mbox`, `.eml`, `.msg`, `.dbx` files present in evidence
**Specialist:** `email`

## Objective

Extract email artefacts from PST/OST archives, mbox files, EML/MSG messages, and mobile mail databases to surface phishing campaigns, data exfiltration via email, business email compromise (BEC), auto-forwarding rules, and attacker communications.

## Steps

### PST/OST Analysis (`analyze_pst`)

- Convert PST/OST to mbox using `readpst` (libpff)
- Enumerate all folders and message counts
- Extract sender, recipient, subject, date, and attachment names for each message
- Flag messages with executable or macro-enabled attachments
- Flag auto-forwarding rules (Inbox rules that forward externally)
- Identify bulk-delete activity (mass deletion of sent items or inbox)
- Surface emails from/to external domains during the incident window

### Mbox Analysis (`analyze_mbox`)

- Parse mbox using Python stdlib `mailbox`
- Extract all message headers: From, To, Cc, Subject, Date, X-headers
- Identify spoofed senders (From ≠ Return-Path)
- Extract and list attachment filenames and MIME types
- Flag base64-encoded payloads in message bodies

### EML Analysis (`analyze_eml`)

- Parse individual .eml files using Python stdlib `email`
- Extract full Received chain for hop-by-hop IP analysis
- Extract DKIM, SPF, DMARC authentication results from headers
- Identify obfuscated links in HTML body (href ≠ display text)
- Extract attachment filenames and hashes where available

### Deep Attachment Extraction (`extract_attachments`)

- Extract all attachments from PST/OST/EML/MSG with full MIME type identification
- Calculate SHA-256 hash for each extracted attachment
- Flag executable attachments (`.exe`, `.dll`, `.scr`, `.bat`, `.ps1`)
- Flag macro-enabled Office documents (`.docm`, `.xlsm`, `.pptm`)
- Flag archive attachments (`.zip`, `.rar`, `.7z`) that may contain nested malware
- Extract OLE objects and embedded scripts from Office documents
- Scan attachments with ClamAV / YARA for known malware signatures
- Cross-reference attachment hashes with VirusTotal or MISP

### iOS Mail.app Analysis (`extract_ios_envelope`)

- Parse `Mail Envelope Index` SQLite database from iOS backup (`AppDomain-com.apple.mobilemail`)
- Deep parse all tables: `messages`, `mailboxes`, `subjects`, `addresses`, `attachments`
- Extract subject, sender, date received/sent, read/flagged status, and mailbox folder
- Cross-reference senders and recipients against findings from SMS, WhatsApp, and call history
- Flag messages in the incident window that are unread, flagged, or in the Trash mailbox
- Extract attachment metadata from iOS Mail (filename, MIME type, local path)

### Android Gmail Analysis (`extract_android_gmail`)

- Search for `mailstore.*.db` (Gmail app database) within Android data directory
- Parse `conversations`, `messages`, `attachments`, `labels` tables
- Extract sender, recipients, subject, snippet, timestamp, and label (Inbox, Sent, Trash, Spam)
- Flag emails with suspicious snippets (credential references, wire transfers, bulk attachments)
- Cross-reference email addresses against contacts and messaging app handles
- Detect Gmail app configuration (account email, sync settings)

### Android EmailProvider Analysis (`extract_email_provider`)

- Parse `EmailProvider.db` / `EmailProviderBody.db` (Samsung Mail, AOSP Email, third-party mail)
- Extract account configuration, folders, messages, and attachments
- Flag POP3/IMAP accounts configured to auto-forward or leave copies on server
- Detect emails deleted locally but still on server (IMAP sync gap)
- Cross-reference with Gmail app for same email account (dual app usage)

### Auto-Forward Detection (`detect_auto_forward`)

- Parse Exchange auto-forward rules from OST/PST (hidden `IPM.Rule.Message` objects)
- Detect server-side forwarding rules (`.forward`, `.procmailrc` on IMAP servers)
- Check for Journaling rules that silently BCC external addresses
- Flag auto-forwarding to free webmail (Gmail, ProtonMail, Yahoo)
- Detect forwarding rules created during incident window
- Cross-reference forwarded emails with cloud sync artifacts

### Received Header Chain Analysis (`analyze_received_chain`)

- Parse full `Received:` chain from EML/MSG headers
- Extract hop-by-hop IP addresses and timestamps
- Identify spoofed headers (inconsistent timestamps, forged IPs)
- Check each hop IP against threat intelligence feeds (MISP, AbuseIPDB)
- Detect email routed through unexpected geographies
- Flag Tor exit nodes, VPN exit IPs, or bulletproof hosters in chain
- Calculate total transit time — suspiciously fast or slow routing

## Indicators of Interest

- Phishing lures with malicious attachments or links
- Auto-forward rules to external Gmail/ProtonMail accounts
- BEC patterns: urgency language, wire transfer requests, impersonation
- Bulk deletion of outbox/sent items during incident window
- Emails originating from internal accounts to competitor domains
- Received chain IPs matching known attacker infrastructure
- **Executable attachments from unexpected senders**
- **OLE objects or embedded macros in "invoice" or "payment" emails**
- **iOS Mail messages in Trash with unread status during incident window**
- **Android Gmail snippets containing "password", "transfer", "confidential"**
- **Auto-forward rules created by compromised account to attacker inbox**
- **Received chain with hop through Tor exit node or bulletproof hoster**
- **Emails to competitor domains with attachments during incident window**
- **Dual email apps (Gmail + Samsung Mail) with different sync states**

## Output

```json
{
  "sources": ["archive.pst", "backup.mbox", "inbox/"],
  "total_messages": 8432,
  "folders": 12,
  "attachments_total": 456,
  "attachments_extracted": 456,
  "attachments_flagged": 12,
  "forwarding_rules": ["Forward all to attacker@gmail.com"],
  "external_recipients_during_window": ["exfil@proton.me"],
  "ios_mail_messages": 234,
  "ios_mail_flagged": 3,
  "android_gmail_messages": 189,
  "android_gmail_flagged": 2,
  "auto_forwards_detected": 1,
  "received_chain_flagged": 2,
  "received_chain_ips": ["185.220.101.42", "192.168.1.100"],
  "bec_indicators": [
    "Urgency language in email requesting wire transfer"
  ],
  "credential_harvesting": [
    "Fake Microsoft login link in email body"
  ],
  "mass_deletion_detected": true,
  "findings": []
}
```

## Tools Required

- `readpst` (libpff) — PST/OST conversion
- `libyal` / `pff-tools` — PST forensic parsing
- `mailbox` (Python stdlib) — mbox parsing
- `email` (Python stdlib) — EML/MSG parsing
- `libemail-utils` — attachment extraction and MIME analysis
- `olefile` / `oletools` — Office document macro extraction
- `exiftool` — attachment metadata extraction
- `SQLite3` — iOS Mail Envelope Index, Android mailstore.db

## Notes

- Attachments may be nested inside archives — recursively extract
- OST files require `readpst` or `libpff` — are not standard PST format
- iOS Mail Envelope Index is SQLite but schema varies by iOS version
- Android Gmail `mailstore.db` is encrypted in newer versions — may need device key
- Auto-forward rules may be server-side only (not visible in local PST)
- Received header chain can be forged — look for inconsistencies in timestamps and IP formatting
