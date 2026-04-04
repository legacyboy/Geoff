# M57-JEAN FORENSIC INVESTIGATION REPORT

**Case:** M57-Jean Investigation  
**Analyst:** Steve (Digital Forensics)  
**Date:** April 3, 2026  
**Image Analyzed:** `nps-2008-jean.E01`

---

## 1. EXECUTIVE SUMMARY

This investigation examined a Windows XP hard drive image belonging to "Jean," an employee at M57 (a fictional company). The analysis uncovered significant evidence of workplace misconduct and potential corporate data exfiltration via AOL Instant Messenger (AIM).

**Key Finding:** Jean accidentally accused her boss (alisonm57) of embezzlement during an IM conversation, not realizing she was speaking to the boss.

---

## 2. IMAGE METADATA

| Attribute | Value |
|-----------|-------|
| **File Format** | E01 (Expert Witness Format) |
| **File System** | NTFS |
| **Operating System** | Windows XP |
| **Volume Serial** | 7E745008744FC21F |
| **Partition Offset** | Sector 63 |
| **Sector Size** | 512 bytes |
| **Cluster Size** | 4096 bytes |

**Source:** `mmls` and `fsstat` analysis of nps-2008-jean.E01

---

## 3. USER IDENTITY

### Primary User
- **Windows Username:** Jean
- **User Account Picture:** Jean.bmp (inode 10775)
- **Security ID:** S-1-5-21-484763869-796845957-839522115-1004

### AIM Identity
- **Screen Name:** **m57jean**
- **Evidence Location:** Browser cache files containing `sn=m57jean` parameter
- **AIM Version:** AIM 6

### Associated Email Addresses
Evidence found in browser cache:
- jean@who
- jean@adbrite
- jean@bidvertiser
- jean@quantserve

**Source:** `fls -r` output showing browser cache entries

---

## 4. INSTANT MESSENGER EVIDENCE

### Critical Conversation Log
**File:** `alisonm57.html` (inode 32194)  
**Location:** `/Documents and Settings/Jean/Application Data/AIM/AIMLogger/m57jean/IM Logs/`  
**Date:** Friday, July 18, 2008  
**Participants:** m57jean (Jean) ↔ alisonm57

| Time | Speaker | Message |
|------|---------|---------|
| 06:05:38 | alisonm57 | "You know, We really should spend more time working and less time chatting about current events." |
| 06:05:58 | alisonm57 | "How many times have we changed what we are doing with this company?" |
| 06:06:35 | alisonm57 | "Why aren't these people working for us?" |
| 06:07:03 | m57jean | "um...I wasn't paying attention. bad case of PMS today. sorry." |
| 06:07:50 | m57jean | "I'm really busy looking for a new laptop bag. Do you how much those cost?" |
| 06:08:01 | alisonm57 | "Are you gonna charge it to the company?" |
| 06:08:16 | m57jean | "They've been complaining about 2Q issues." |
| 06:08:21 | m57jean | "might not be a good time." |
| 06:09:24 | alisonm57 | "How much cash is left in the account?" |
| **06:09:43** | **m57jean** | **"mmm.... I think we have about $5K discretionary."** |
| **06:10:11** | **m57jean** | **"I think the boss has been dipping."** |
| **06:10:28** | **m57jean** | **"but he dips his everything in everything, yk?"** |
| **06:10:41** | **alisonm57** | **"Uh, Jean, I am the boss. Remember?"** |
| **06:10:51** | **alisonm57** | **"You work for me."** |
| 06:10:54 | m57jean | "sorry. told you the hormones were bad." |

### Analysis
This conversation reveals:
1. **Financial Information:** $5,000 discretionary funds disclosed
2. **Embezzlement Accusation:** Jean accused "the boss" of stealing company money
3. **Identity Reveal:** alisonm57 IS the boss Jean was accusing
4. **Awkward Recovery:** Jean blames "hormones/PMS" after realizing her mistake

**Source:** `/tmp/m57_evidence/im_logs/alisonm57.html`

---

## 5. SOFTWARE INSTALLATIONS

| Application | Evidence | Significance |
|-------------|----------|--------------|
| **AIM 6** | `AIM 6.lnk`, AIM directory (inode 29259) | Primary communication platform |
| **AIMTunes** | `AIMTunes.exe`, `AIM Tunes.url` | AOL music player |
| **MSN Messenger** | `MSN.lnk` | Secondary IM client |
| **QQ** | `QQSetup65.exe` | Chinese messaging app |
| **Firefox 3.0 Beta 5** | Download cache | Web browser |

**Source:** File system enumeration via `fls -r`

---

## 6. BROWSER ACTIVITY

### Internet History
- **Browser:** Internet Explorer 6
- **History Files:** Multiple `History.IE5` folders found
- **Cache Location:** `/Documents and Settings/*/Local Settings/Temporary Internet Files/`

### Notable URLs
- `http://www.aim.com/redirects/inclient/AIM_UAC_v2` - AIM user access control
- `http://buddies.aim.com/buddies/invitations` - AIM buddy requests (July 19-20, 2008)
- AOL News articles (entertainment/celebrity gossip)

**Source:** `index.dat` files extracted from user profiles

---

## 7. DOCUMENT EVIDENCE

### Word Documents
| File | User | Size |
|------|------|------|
| winword.doc | Jean (inode 16193) | 4,608 bytes |
| winword2.doc | Jean (inode 16189) | 1,769 bytes |

**Note:** These appear to be Microsoft Word templates rather than user-created content.

**Source:** `/tmp/m57_evidence/jean_winword.doc`

---

## 8. EMAIL EVIDENCE

### Outlook PST Files
| File | Inode | Created | Modified | Size |
|------|-------|---------|----------|------|
| outlook.pst | 24012 | 2008-07-10 | 2008-07-19 | 98,304 bytes |
| outlook_1.pst | 17358 | - | - | 65,536 bytes |

**Analysis:** Two Outlook data files found. The primary PST shows activity from July 10-19, 2008.

**Source:** `/tmp/m57_evidence/outlook.pst`

---

## 9. TIMELINE OF EVENTS

| Date | Time | Event |
|------|------|-------|
| 2008-07-10 | 02:47 | outlook.pst created |
| 2008-07-17 | 23:33 | Stic.log (AIM software) created |
| **2008-07-18** | **06:05** | **CRITICAL: IM conversation with alisonm57** |
| 2008-07-18 | ~05:33 | AIM software update activity |
| 2008-07-19 | 06:49 | AIM buddy request notification |
| 2008-07-19 | 19:00 | outlook.pst last modified |
| 2008-07-20 | 01:01 | AIM buddy request notification |

**Source:** File metadata from `istat` analysis

---

## 10. CONCLUSIONS

### What Happened
Jean (m57jean) was an employee at M57 who used AIM for workplace communications. During a conversation with her contact "alisonm57," Jean:

1. Disclosed confidential financial information ($5K discretionary funds)
2. Accused "the boss" of embezzlement ("dipping")
3. Did not realize alisonm57 WAS the boss until explicitly told
4. Attempted to cover by blaming "hormones/PMS"

### Evidence Quality
- **High:** Direct IM conversation logs with timestamps
- **High:** User identity confirmed via multiple sources
- **Medium:** Email data available but not fully analyzed
- **Low:** Word documents appear to be templates, not evidence

### Recommendations
1. Review Jean's access to financial systems
2. Analyze outlook.pst for additional evidence
3. Examine QQ usage for external communications
4. Interview alisonm57 (the boss) for context

---

## 11. EVIDENCE INVENTORY

All evidence extracted to: `/tmp/m57_evidence/`

| File | Description | Size |
|------|-------------|------|
| alisonm57.html | IM conversation with boss | 13,076 bytes |
| aim.html | AIM system messages | 1,574 bytes |
| outlook.pst | Email data file | 98,304 bytes |
| outlook_1.pst | Secondary email file | 65,536 bytes |
| NTUSER.DAT | User registry hive | 131,379 bytes |
| jean_winword.doc | Word document | 4,608 bytes |
| full_file_list.txt | Complete file listing | 703,725 bytes |

---

**Report Completed:** April 3, 2026  
**Analyst:** Steve  
**Tools Used:** SleuthKit (mmls, fsstat, fls, icat, istat)
