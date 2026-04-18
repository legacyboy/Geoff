# PB-SIFT-023 — Email Forensics

**Phase:** Collection  
**Auto-triggered when:** `.pst`, `.ost`, `.mbox`, or `.eml` files present in evidence  
**Specialist:** `email`

## Objective

Extract email artefacts from PST/OST archives, mbox files, and individual EML messages to surface phishing campaigns, data exfiltration via email, business email compromise (BEC), and attacker communications.

## Steps

### PST/OST Analysis (`analyze_pst`)

- Convert PST/OST to mbox using `readpst`
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

## Indicators of Interest

- Phishing lures with malicious attachments or links
- Auto-forward rules to external Gmail/ProtonMail accounts
- BEC patterns: urgency language, wire transfer requests, impersonation
- Bulk deletion of outbox/sent items during incident window
- Emails originating from internal accounts to competitor domains
- Received chain IPs matching known attacker infrastructure

## Output

```json
{
  "source": "archive.pst",
  "folders": 12,
  "total_messages": 8432,
  "attachments_flagged": ["invoice.xlsm", "payment.exe"],
  "forwarding_rules": ["Forward all to attacker@gmail.com"],
  "external_recipients_during_window": ["exfil@proton.me"],
  "findings": []
}
```
