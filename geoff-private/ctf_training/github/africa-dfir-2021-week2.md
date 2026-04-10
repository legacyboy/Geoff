# Africa DFIR CTF 2021 — Week 2 Write-up

## Overview
Focus on RAM/Memory Forensics using Volatility 3 and basic forensic techniques.

## Challenges & Techniques

### 1. Process Identification (Be Brave)
- Objective: Find the Process ID (PID) for the Brave browser.
- Tool: Volatility 3 plugin windows.pslist.PsList.
- Finding: PID 4856.

### 2. Image Verification
- Objective: Obtain the SHA256 hash of a file.
- Tool: PowerShell utility Get-FileHash.
- Finding: Hash value provided in the write-up.

### 3. Network Connection Analysis (Let's Connect)
- Objective: Determine the number of established network connections at the time of acquisition.
- Tool: 
  - windows.info.Info to find the acquisition time (2021-04-30 17:52:19).
  - windows.netscan.NetScan to list established connections.
- Finding: 10 established connections.

### 4. Domain Identification (Chrome Connection)
- Objective: Find the domain name associated with a specific IP address (185.70.41.130) used by Chrome.
- Tool: Online IP lookup (whatismyip.com).
- Finding: Domain: protonmail.

### 5. Process Memory Hashing (Hash Hash Baby)
- Objective: Calculate the MD5 hash of the memory of a specific process (PID 6988).
- Tool: Volatility 3 windows.pslist.PsList (with dump argument) to extract process memory, then MD5 hashing.
- Finding: Hash value extracted.

### 6. Memory Offset Analysis (Offset Select)
- Objective: Find the word starting at memory offset 0x45BE876.
- Tool: Hex editor (Bless).
- Finding: "hacker".

### 7. Parent Process Analysis (Process Parents Please)
- Objective: Find the creation date and time of the parent process of powershell.exe.
- Method:
  - Use windows.pslist.PsList to find powershell.exe (PID 5096).
  - Identify its Parent Process ID (PPID 4352).
  - Search for the process with PID 4352 to get its creation timestamp.
- Finding: 2021-04-30 17:39:48.

### 8. File Activity (Finding Filenames)
- Objective: Find the full path and name of the last file opened in Notepad.
- Tool: Volatility 3 windows.cmdline.CmdLine (analyzing conhost.exe memory).
- Finding: C:\Users\JOHNDO~1\AppData\Local\Temp\7zO4FB31F24\accountNum.

### 9. Execution Tracking (Hocus Focus)
- Objective: Find when the suspect last used the Brave browser.
- Tool: Volatility 3 windows.registry.userassist.UserAssist.
- Finding: Time 4:01:54.

### 10. Metadata Analysis (Meetings)
- Objective: Find a location based on coordinates in a PDF.
- Tool: Autopsy (metadata analysis).
- Finding: File almanac-start-a-garden.pdf contained coordinates leading to Victoria Falls.
