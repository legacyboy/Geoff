# PB-SIFT-022 — Browser Forensics

**Phase:** Collection  
**Auto-triggered when:** Always (browser databases analysed if found in evidence)  
**Specialist:** `browser`

## Objective

Recover user browsing activity, downloaded files, saved credentials origins, and web-based attack artefacts from Chrome and Firefox SQLite databases found in the evidence.

## Steps

### History Extraction (`extract_history`)

- Locate `History` (Chrome) and `places.sqlite` (Firefox) databases
- Extract URL, visit count, last visit time, and page title for each entry
- Flag visits to paste sites (pastebin, hastebin), file-sharing services, and known malicious domains
- Flag bulk browsing activity outside normal hours

### Cookie Extraction (`extract_cookies`)

- Parse `Cookies` (Chrome) and `cookies.sqlite` (Firefox)
- Identify session cookies for cloud storage, webmail, and SaaS applications
- Flag long-lived authentication cookies that may indicate session hijacking
- Flag cookies for domains not in browsing history (injected cookies)

### Download History (`extract_downloads`)

- Parse `History` downloads table (Chrome) and `downloads.sqlite` (Firefox)
- Extract filename, source URL, referrer URL, MIME type, and download time
- Flag executables, scripts, and archives downloaded from external sources
- Cross-reference downloaded filenames with known malware names

### Saved Password Origins (`extract_saved_passwords`)

- Extract origin URLs from `Login Data` (Chrome) and `logins.json` (Firefox)
- Note: passwords are not decrypted — only the origin URLs are recorded
- Flag corporate credential origins stored in personal browser profiles
- Flag unusual or unknown domains with saved credentials

## Indicators of Interest

- Downloads of dual-use tools (ngrok, chisel, mimikatz, etc.)
- Browsing to attacker infrastructure shortly before or during incident window
- Web-based exfiltration via file upload forms (Google Drive, Dropbox, WeTransfer)
- Credential harvesting page visits
- Browser extensions installed from outside official stores
- Searches for "how to" instructions related to lateral movement or persistence

## Output

```json
{
  "browser": "Chrome",
  "profile": "Default",
  "history_entries": 4821,
  "downloads": 38,
  "suspicious_downloads": ["mimikatz.exe", "ngrok.exe"],
  "suspicious_domains": ["192.168.1.200", "evilsite.onion"],
  "findings": []
}
```
