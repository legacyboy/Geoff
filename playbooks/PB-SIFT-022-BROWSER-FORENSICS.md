# PB-SIFT-022 — Browser Forensics

**Phase:** Collection
**Auto-triggered when:** Always (browser databases analysed if found in evidence)
**Specialist:** `browser`

## Objective

Recover user browsing activity, downloaded files, saved credentials origins, autofill data, session state, extension storage, and web-based attack artefacts from Chrome, Firefox, Edge, and Safari databases found in the evidence.

## Steps

### History Extraction (`extract_history`)

- Locate `History` (Chrome/Edge) and `places.sqlite` (Firefox) databases
- Extract URL, visit count, last visit time, and page title for each entry
- Flag visits to paste sites (pastebin, hastebin), file-sharing services, and known malicious domains
- Flag bulk browsing activity outside normal hours

### Cookie Extraction (`extract_cookies`)

- Parse `Cookies` (Chrome/Edge) and `cookies.sqlite` (Firefox)
- Identify session cookies for cloud storage, webmail, and SaaS applications
- Flag long-lived authentication cookies that may indicate session hijacking
- Flag cookies for domains not in browsing history (injected cookies)

### Download History (`extract_downloads`)

- Parse `History` downloads table (Chrome/Edge) and `downloads.sqlite` (Firefox)
- Extract filename, source URL, referrer URL, MIME type, and download time
- Flag executables, scripts, and archives downloaded from external sources
- Cross-reference downloaded filenames with known malware names

### Saved Password Origins (`extract_saved_passwords`)

- Extract origin URLs from `Login Data` (Chrome/Edge) and `logins.json` (Firefox)
- Note: passwords are not decrypted — only the origin URLs are recorded
- Flag corporate credential origins stored in personal browser profiles
- Flag unusual or unknown domains with saved credentials

### Login Data Deep Extraction (`extract_login_data`)

- Parse Chrome/Edge `Login Data` SQLite database (`logins` table)
- Extract origin URL, username element, username value (if unencrypted), password element
- Check for password values stored without encryption (older Chrome versions)
- Flag saved credentials for banking, cloud admin panels, and VPN portals
- Detect duplicate entries with different passwords (credential stuffing indicator)
- Cross-reference login origins with phishing domain lists

### Web Data / Autofill Extraction (`extract_web_data`)

- Parse Chrome/Edge `Web Data` SQLite database
- Extract autofill profiles (name, address, phone, email) from `autofill_profiles`
- Extract credit card metadata from `credit_cards` (name on card, last 4 digits, expiration)
- Note: full card numbers are encrypted — only metadata is extracted
- Flag autofill data for corporate addresses in personal profiles
- Detect autofill entries created during incident window

### Session & Tab Restore (`extract_session_restore`)

- Parse Chrome/Edge Session files (`Sessions/` directory): `Session_*`, `Tabs_*`
- Extract open tabs, window state, and recently closed tabs
- Identify websites the user was actively viewing at time of imaging
- Parse Firefox `sessionstore.jsonlz4` or `recovery.jsonlz4`
- Detect session hijacking: tabs pointing to credential phishing pages
- Flag tabs opened to file sharing or cloud upload pages during incident

### Firefox Key4 & Logins (`extract_firefox_key4`)

- Parse Firefox `key4.db` (SQLite key database) for password storage metadata
- Extract `logins.json` entries: hostname, username, password field metadata
- Check for master password protection status
- Flag Firefox saved logins for admin panels, SSH gateways, or cloud consoles
- Detect password age and modification patterns

### Firefox Form History (`extract_firefox_formhistory`)

- Parse Firefox `formhistory.sqlite` (legacy) or `places.sqlite` (modern)
- Extract search terms and form submissions
- Flag searches for anti-forensics tools ("secure delete", "wipe disk", "hide files")
- Detect searches for attacker tools during incident window
- Cross-reference search terms with downloaded files

### LevelDB & IndexedDB Analysis (`analyze_leveldb`)

- Parse Chrome/Edge LevelDB databases in `IndexedDB/` and `Local Storage/leveldb/`
- Extract extension storage data (settings, cache, tokens)
- Parse IndexedDB object stores for web app data
- Detect extension IDs from non-Chrome-Web-Store sources
- Flag suspicious IndexedDB contents (exfiltrated data, encoded payloads)
- Check for service worker caches with cached malicious content

## Indicators of Interest

- Downloads of dual-use tools (ngrok, chisel, mimikatz, etc.)
- Browsing to attacker infrastructure shortly before or during incident window
- Web-based exfiltration via file upload forms (Google Drive, Dropbox, WeTransfer)
- Credential harvesting page visits
- Browser extensions installed from outside official stores
- Searches for "how to" instructions related to lateral movement or persistence
- **Chrome extensions from non-store sources** (loaded unpacked or from CRX sideload)
- **Suspicious IndexedDB contents** — large binary blobs, encoded strings, exfil data
- **Session hijacking artifacts** — tabs to credential phishing pages opened without user action
- **Autofill credit cards** added during incident window
- **Login Data** entries for attacker-controlled domains
- **Firefox Form History** searches for anti-forensics techniques
- **Saved passwords** for corporate VPN, cloud admin, or domain controller

## Output

```json
{
  "browser": "Chrome",
  "profile": "Default",
  "history_entries": 4821,
  "downloads": 38,
  "suspicious_downloads": ["mimikatz.exe", "ngrok.exe"],
  "suspicious_domains": ["192.168.1.200", "evilsite.onion"],
  "saved_passwords": 23,
  "password_origins_flagged": 3,
  "autofill_profiles": 2,
  "credit_cards": 1,
  "session_tabs": 12,
  "tabs_flagged": 1,
  "extensions": 8,
  "extensions_non_store": 1,
  "indexeddb_stores": 34,
  "indexeddb_suspicious": 2,
  "firefox_form_history": 0,
  "findings": []
}
```

## Tools Required

- `SQLite3` — Chrome/Edge `History`, `Cookies`, `Login Data`, `Web Data`
- `SQLite3` — Firefox `places.sqlite`, `cookies.sqlite`, `formhistory.sqlite`
- `LevelDB` parser — Chrome IndexedDB/Local Storage
- `strings` — raw LevelDB content extraction
- `sqlite_parser.py` or `chrome_historian` — specialized Chrome forensics tools

## Notes

- Chrome/Edge profiles may be encrypted with DPAPI (Windows) — requires user password or master key
- Firefox `logins.json` encryption key is in `key4.db` — requires master password if set
- Session files show what the user was actively doing at time of imaging
- LevelDB databases may contain deleted data — parse raw for recovery
- Extension storage can contain authentication tokens for web apps
- Autofill data reveals real-world identity even in anonymous browsing profiles
