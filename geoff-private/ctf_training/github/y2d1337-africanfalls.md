# CyberDefenders: AfricanFalls Challenge Write-up

## Overview
Investigation of a laptop disk image belonging to John Doe, accused of illegal activities.
- Image Format: .ad1 (672 MB)
- Tags: FTK Imager, Windows, DFIR, Autopsy

## Tools Used
- FTK Imager: Disk image preview and extraction.
- ChromeCacheView: Analysis of Google Chrome cache.
- PECmd: Prefetch parser for execution evidence.
- BrowsingHistoryView: Multi-browser history analysis.
- Hashcat: Password recovery and cracking.
- ShellBags Explorer: Analyzing folder access history via registry.
- samdump2: Extracting password hashes from the SAM hive.

## Analysis & Findings

### 1. Internet Activity & Software
- Search History: Suspect searched for "password cracking lists".
- FTP Usage: Evidence of FileZilla installation and use. A recently used server was identified at 192.168.1.20.
- Anonymity Tools: Investigated Tor Browser execution using Prefetch files. Found that while the installer was executed, the browser itself may not have been.
- Email: Identified a ProtonMail account: dreammaker82@protonmail.com.

### 2. Command Line & System Activity
- PowerShell History: Found ConsoleHost_history.txt revealing the execution of nmap dfir.science.
- File Recovery: Recovered a deleted password list (10-million-password-list-top-100.txt) from the Recycle Bin.

### 3. Media & Location Forensics
- EXIF Analysis: Extracted GPS coordinates from a photo, placing the location in Zambia.
- Device Identification: The photo was taken with an LG Electronics LM-Q725K.
- Folder Access: Used ShellBags to locate photos in My Computer\LGQ7\Internal storage\DCIM\Camera.

### 4. Credential Recovery
- Hash Cracking: 
  - Used Hashcat with the OneRuleToRuleThemAll ruleset to crack a hash -> AFR1CA!.
  - Used samdump2 to extract the SAM hash for John Doe and cracked it -> ctf2021.

## Flags Summary
- Image MD5: 9471e69c95d8909ae60ddff30d50ffa1
- Search Query: password cracking lists
- FTP Server IP: 192.168.1.20
- Deleted File Date: 2021-04-29 18:22:17 UTC
- Tor Execution Count: 0
- Email Address: dreammaker82@protonmail.com
- Nmap Target: dfir.science
- Location: Zambia
- Photo Folder: Camera
- Sourced Password: AFR1CA!
- User Password: ctf2021
