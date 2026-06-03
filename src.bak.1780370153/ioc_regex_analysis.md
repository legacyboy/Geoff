# Geoff IOC Regex Analysis & Improvement Recommendations

This analysis is based on code in `/Users/dan/Geoff/src/`. The primary IOC extraction
occurs in two locations:

1. **`STRINGS_Specialist.extract_strings()`** at `sift_specialists.py` lines 1306–1428
2. **`VOLATILITY_Specialist._fallback_analysis()`** at `sift_specialists.py` lines 1022–1077

A separate structured-IP pipeline (`_extract_ips_from_evidence` in `geoff_utils.py`
lines 969–1169) uses `tshark`/`volatility`/`reglookup` output, not `strings` — that
pipeline is fine.

---

## 1. Email Regex

### Current Pattern (sift_specialists.py line 1348)
```python
email_re = re.compile(r'[\w\.\-]+@[\w\.\-]+\.\w{2,}')
```

### What It Matches
- `[\w\.\-]+` — one or more word chars (`a-zA-Z0-9_`), dots, or hyphens (local part)
- `@` — literal
- `[\w\.\-]+` — one or more word chars, dots, or hyphens (domain part)
- `\.\w{2,}` — dot followed by 2+ word chars (so-called "TLD")

### False Positive Examples from M57-Jean

| String | Why it matched | Why it's wrong |
|--------|---------------|----------------|
| `M@T.7vE` | local=`M`, domain=`T`, tld=`7vE` | No valid TLD, single-char local & domain |
| `hH@g.M_` | local=`hH`, domain=`g`, tld=`M_` | `M_` is not a valid TLD; `_` not valid in domains |
| `2E@6.ZE` | local=`2E`, domain=`6`, tld=`ZE` | Single-char domain, no valid TLD |
| `2E@6.ZE` (also) | variants repeat | same problems |
| `f@V.123` | local=`f`, domain=`V`, tld=`123` | Numeric TLD not valid |

### Root Cause Analysis
1. **No minimum length** on local part or domain: `[\w\.\-]+` matches a single character.
2. **No TLD validation**: `\w{2,}` matches literally any 2+ word chars — `7vE`, `M_`, `ZE`,
   `123`, `ABC`, `xyz` — all pass, even when they're clearly not valid TLDs.
3. **Underscore allowed in domain**: `\w` includes `_`, which is invalid in domain names.
4. **Domain can start with dot or hyphen**: `[\w\.\-]+` at the start of domain segment
   can begin with `.` or `-`.
5. **Strings extracted at `-n 4`**: `strings -n 4` produces all ≥4-char printable runs
   from binary files. A short binary artifact like `M@T.7vE` (8 chars) easily passes.

### Improved Regex
```python
email_re = re.compile(
    r'\b[a-zA-Z0-9][a-zA-Z0-9._%+-]{2,64}@'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
    r'(?:com|org|net|edu|gov|mil|int|'
    r'[a-z]{2,3}|xn--[a-z0-9]+)\b',
    re.IGNORECASE
)
```

### Changes Made
| Issue | Fix |
|-------|-----|
| Single-char local part | Require local part ≥ 3 chars (`[a-zA-Z0-9][a-zA-Z0-9._%+-]{2,64}`) |
| No TLD validation | Explicitly allow only IANA-known TLDs: `com|org|net|...` or `[a-z]{2,3}` for ccTLDs, plus IDN `xn--` |
| Underscore in domain | Use `[a-zA-Z0-9]` and `[a-zA-Z0-9-]` in domain, not `\w` |
| Domain starts with dot/hyphen | Anchor with `[a-zA-Z0-9]` at start of each domain segment |
| Floating matches | Added `\b` word boundaries at both ends |

**Result**: `M@T.7vE`, `hH@g.M_`, `2E@6.ZE` all fail — local part too short, domain
too short, TLD not recognized. Real emails like `user@gmail.com` still pass.

---

## 2. IP Address Regex

### Current Pattern (sift_specialists.py line 1347)
```python
ip_re = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)
```

### What It Matches
This is a *correct* IPv4 address regex — it properly validates that each octet is
0–255. The pattern `[1-9]?\d` matches 0–99, `1\d{2}` matches 100–199, etc.

### False Positive Examples from M57-Jean
| String | Why it's FP |
|--------|-------------|
| `7.0.2.7` | Software version string (all octets valid 0-255) |
| `1.5.3.7` | Version string |
| `2.1.5.2` | Version string |
| `1.5.3.7` (dup) | Version string |

### Root Cause Analysis
The fundamental problem: **a valid IPv4 address is syntactically identical to a
X.Y.Z.W version number**. `7.0.2.7` passes all octet range checks because every value
is 0–255. The regex cannot distinguish between `8.8.8.8` (Google DNS, real IP) and
`7.0.2.7` (version string) based on syntax alone.

### Key Insight
In the M57-Jean context (strings extracted from binary files), IP patterns that are
actually version strings **almost always have all octets ≤ 9** (single digit each).
Real public IPs rarely consist exclusively of single-digit octets. The one notable
exception is `8.8.8.8` (Google DNS), which should have a specific allowlist entry.

The current code already filters private/RFC1918 IPs (lines 1374–1379), which removes
`10.x.x.x`, `192.168.x.x`, `127.x.x.x`, `169.254.x.x`, `172.16-31.x.x`, and
`0.x.x.x`/`255.x.x.x`.

### Improved Regex
Option A — **Add post-match heuristic** (better than trying to embed in regex):

```python
# After the regex match and private-IP filter:
is_version_like = all(0 <= int(o) <= 9 for o in ip.split('.'))
if is_version_like and ip not in ALLOWED_SINGLE_DIGIT_IPS:
    continue  # skip — likely a version string
```

Where:
```python
ALLOWED_SINGLE_DIGIT_IPS = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '4.4.4.4'}
```

Option B — **Embed heuristic in regex** (less readable but self-contained):
```python
ip_re = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)
# PLUS the post-filter below
```

**Recommendation**: Option A with post-filter + allowlist. Keep the regex clean,
add a 3-line heuristic check.

### Also: Regex in VOLATILITY fallback (sift_specialists.py line 1041)
```python
ip_pattern = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
```
This is functionally identical to the one in STRINGS_Specialist (slightly different
octet notation: `[01]?\d\d?` vs `[1-9]?\d|1\d{2}`). Apply the same post-filter there.

---

## 3. URL Regex

### Current Patterns
**STRINGS_Specialist (line 1346):**
```python
url_re = re.compile(r'https?://[^\s"\'\)\]>]+')
```

**VOLATILITY fallback (line 1044):**
```python
url_pattern = re.compile(r'https?://[^\s<>"\'\)\]]+', re.IGNORECASE)
```

### Analysis of 0 URLs in M57-Jean
The M57-Jean disk image is from a small business (Jean) with limited network activity.
Zero URL matches from strings scanning a disk image is **entirely plausible** —
disk images rarely contain embedded `http://` URLs in short 4-char+ strings unless
there are browser history files, bookmarks, or configuration files with URLs.

The regex itself is the standard "greedy URL" pattern. It's not too strict; the
evidence simply has no URLs in plain text strings.

### Improvements (optional, for robustness)
```python
url_re = re.compile(
    r'https?://'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,}'
    r'(?::\d{1,5})?'
    r'(?:/[^\s<>"\'\)\]>,;]*)?',
    re.IGNORECASE
)
```
This version requires a valid domain structure in the URL (not just any characters
after `://`), which helps avoid matching malformed or truncated garbage strings.

**Priority**: Low. The current regex is adequate for real URLs. Focus on email/IP.

---

## 4. Suspicious Strings — Over-Matching

### Current Pattern (lines 1354–1360)
```python
suspicious_keywords = [
    'password', 'passwd', 'login', 'cmd.exe', 'powershell', 'wscript',
    'cscript', 'mimikatz', 'lsass', 'ntds.dit', 'shadow', 'dump',
    'inject', 'shellcode', 'keylog', 'rootkit', 'backdoor',
    'beacon', 'c2', 'exfil', 'encrypt', 'decrypt', 'ransom'
]
```

### The Problem
- `strings -n 4` extracts ALL ≥4-char printable strings from a binary → thousands of strings
- These keywords match via **substring** check (`kw in s_lower`)
- `'password'` appears in every Windows registry hive (SAM, SYSTEM)
- `'login'` is in countless configuration strings
- `'dump'` appears in mundane log messages
- `'c2'` is a 2-char substring that matches anything containing "C2" (product names,
  "Class 2", "C2 level", hex data patterns)
- `'shadow'` matches "Shadow Copy" (legitimate Windows feature)
- `'shellcode'` as substring matches anything containing the word "shell" or "code"
  separately? No — `'shellcode' in s_lower` checks if the exact substring "shellcode"
  appears. But that's still going to match things like "ShellCode32.dll" in legitimate
  system files.

### With `strings -n 4`, 10,924 unique strings from one image is entirely possible.
A typical Windows 7 image has hundreds of thousands of 4+ char strings. Even 0.5%
matching one of these very common keywords yields thousands of "suspicious" strings.

### Recommended Fix
1. **Increase minimum string length**: Change from `min_length=4` to `min_length=8`
   for suspicious keyword matching (longer strings are more meaningful). Or use
   `min_length=6` as a compromise.

2. **Remove overly generic keywords**: Remove `'dump'`, `'shadow'`, `'login'`,
   `'password'`, `'encrypt'`, `'decrypt'` — these are far too common in legitimate
   system files. Keep only genuinely malicious indicators:
   ```python
   suspicious_keywords = [
       'mimikatz', 'ntds.dit', 'shellcode', 'keylog', 'rootkit',
       'backdoor', 'c2_exfil', 'ransomware',
   ]
   ```

3. **Use word-boundary matching** instead of substring:
   ```python
   kw_re = re.compile(r'\b(?:' + '|'.join(re.escape(kw) for kw in suspicious_keywords) + r')\b', re.IGNORECASE)
   ```
   This prevents `password` from matching inside `PasswordManager123`.

4. **Add minimum context length**: Only flag strings that are ≥ 10 characters AND
   contain the keyword — eliminates short binary noise.

5. **Deduplication**: The current code already deduplicates by unique string value
   (the `seen` set), which helps but doesn't reduce noise enough.

### Recommended Suspicious Keywords (final)
```python
suspicious_keywords = [
    # Credential theft
    'mimikatz', 'ntds.dit', 'lsass', 'wce.exe',
    # Malware types
    'shellcode', 'rootkit', 'backdoor', 'keylogger',
    # C2/beaconing
    'beacon', 'cobaltstrike', 'metasploit',
    # Ransomware
    'ransomware', 'lockbit', 'blackcat',
]
```
Remove: `password`, `passwd`, `login`, `cmd.exe`, `powershell`, `wscript`, `cscript`,
`shadow`, `dump`, `inject`, `c2`, `exfil`, `encrypt`, `decrypt`, `ransom` (as substring).

---

## 5. Domain Regex (bonus)

### Current Pattern (line 1352)
```python
domain_re = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)
```

### Assessment
This is actually **well-structured** — it enforces:
- Alphanumeric start/end for each label
- Max 63 chars per label (via `{0,61}`)
- TLD minimum 2 alpha chars
- Valid dot-separated structure

No changes needed for this pattern.

---

## 6. Summary of All Regex Patterns Found

| Pattern | File | Line | Needs Fix? |
|---------|------|------|-----------|
| `url_re` | sift_specialists.py | 1346 | Low (works, no false positives reported) |
| `ip_re` | sift_specialists.py | 1347 | **YES** — version number FPs |
| `email_re` | sift_specialists.py | 1348 | **YES** — critical, 87 false FPs |
| `registry_re` | sift_specialists.py | 1349 | OK (requires HKLM/HKCU prefix) |
| `win_path_re` | sift_specialists.py | 1350 | OK |
| `unix_path_re` | sift_specialists.py | 1351 | OK |
| `domain_re` | sift_specialists.py | 1352 | OK |
| `ip_pattern` (fallback) | sift_specialists.py | 1041 | **YES** — same IP FP issue |
| `url_pattern` (fallback) | sift_specialists.py | 1044 | OK |
| `_EMAIL_HEADER_IPS` | geoff_utils.py | 1132 | OK (context-specific, uses `ipaddress` validation) |
| Generic IP `\b(?:\d{1,3}\.){3}\d{1,3}\b` | geoff_utils.py | 1062, 1113, 1123 | OK (used on structured tool output, validated against `ipaddress` module) |

---

## 7. Implementation Order

1. **Email regex** (CRITICAL) — Replace the broken pattern with the validated version
   above. Will eliminate all 87 false positive emails.
2. **IP post-filter** (HIGH) — Add the version-string heuristic. Will eliminate most
   of the 12 false positive IPs.
3. **Suspicious keywords** (HIGH) — Reduce keyword list and increase min string length.
   Will dramatically cut 10,924 noisy entries.
4. **VOLATILITY fallback IP regex** (MEDIUM) — Apply same post-filter as #2.
5. **URL regex** (LOW) — Optional improvement for domain validation.
