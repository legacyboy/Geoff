# Geoff v2.1: Email Evidence Blind Spots Audit

## CRITICAL BLIND SPOTS

### 1. OST Files (Exchange Cache) ⚠️
- **Status:** NOT IMPLEMENTED
- **Impact:** HIGH - Exchange users (most enterprises) use OST, not PST
- **Problem:** OST is encrypted and requires MAPI profile/server connection
- **Evidence Found:** None in current cases, but common in enterprise

### 2. Browser History/Cache - PARTIAL
- **Status:** PARTIALLY COVERED
- **Evidence Found:** `steve_chrome_history.db` (Narcos case)
- **Gap:** No dedicated agent for browser forensics
- **Contains:** URLs, searches, form data, webmail access

### 3. Webmail Evidence - NOT COVERED
- **Status:** NOT IMPLEMENTED
- **Evidence:** GMail, Outlook.com, Yahoo accessed via browser
- **Locations:**
  - `chrome_history.db` - URLs and searches
  - `Cookies` - Session tokens
  - `Login Data` - Saved credentials

### 4. Cloud Storage Sync - PARTIAL
- **Status:** Dropbox logs found, but no extraction agent
- **Evidence Found:**
  - `DropboxUpdate_*.log` (Lone Wolf case)
  - `global.db` (Google Drive, Lone Wolf)
- **Gap:** No cloud storage analysis

### 5. Chat/IM Applications - LIMITED
- **Status:** Basic coverage only
- **Evidence Found:**
  - AIM chat (M57-Jean) - basic parsing
  - Discord (Narcos) - manual extraction only
- **Gap:** No dedicated agent for modern chat (Discord, WhatsApp, Signal)

### 6. SQLite Databases - NOT SYSTEMATIC
- **Status:** Manual extraction only
- **Evidence Found:** Multiple .db files across cases
- **Gap:** No systematic SQLite parsing

## PRIORITY FIXES

1. **BrowserAgent** - Extract and analyze browser history, webmail, searches
2. **CloudAgent** - Parse Dropbox, OneDrive, Google Drive sync logs
3. **ChatAgent** - Modern IM/Chat (Discord, WhatsApp, Signal)
4. **SQLiteAgent** - Systematic SQLite database parsing

## CASE-SPECIFIC FINDINGS

### Narcos Case
- Chrome history: Drug searches, steganography searches, gang research
- Discord: Need extraction agent

### Lone Wolf Case  
- Dropbox: Cloud storage evidence
- Google Drive: `global.db` not parsed
- Browser: Not extracted from memory

### M57-Jean Case
- Webmail: Primary attack vector, but browser history not analyzed
- Could have found phishing URL access

## RECOMMENDATION

Create **BrowserAgent** as next priority - covers webmail, web searches, and cloud access patterns.
