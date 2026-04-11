## Source: https://0xsh3rl0ck.github.io/ctf-writeup/Africa-DFIR-2021-CTF-Week-2/
### Key Techniques
- **Process Analysis**: Using `windows.pslist` to identify active processes and their Process IDs (PIDs).
- **Network Connection Analysis**: Using `windows.netscan` to identify established network connections and their timestamps at the time of memory acquisition.
- **Memory Acquisition Metadata**: Using `windows.info` to retrieve OS, kernel details, and the exact time the memory dump was captured.
- **Process Dumping and Hashing**: Using `windows.pslist` with dump arguments to extract a specific process from memory (via PID) and calculating its MD5 hash for verification.
- **Memory Offset Analysis**: Using hex editors (e.g., Bless) to navigate to a specific logical memory offset (distance from the start of a memory segment) to retrieve raw data/strings.
- **Process Tree Analysis**: Using `windows.pstree` or `windows.pslist` to identify the relationship between Parent Processes (PPID) and Child Processes (PID) to determine the lineage of an execution (e.g., finding what launched `powershell.exe`).
- **Command Line Recovery**: Using `windows.cmdline` to recover command-line arguments from `conhost.exe` memory, allowing the recovery of file paths opened in applications like Notepad even after the process has ended.
- **UserAssist Analysis**: Using `windows.registry.userassist` to track program execution counts and last execution timestamps.
- **PDF Metadata Analysis**: Using forensic tools (e.g., Autopsy) to extract GPS coordinates or location data from PDF metadata.

### Tools Used
- **Volatility 3**: The primary framework for memory forensics.
    - `windows.pslist`: Lists processes and dumps process memory.
    - `windows.netscan`: Scans for network connections.
    - `windows.info`: Provides system and acquisition info.
    - `windows.pstree`: Shows process hierarchy.
    - `windows.cmdline`: Extracts command line history.
    - `windows.registry.userassist`: Parses UserAssist registry keys.
- **Bless Hex Editor**: Used for navigating memory dumps via offsets.
- **Autopsy**: Used for file system analysis and PDF metadata extraction.
- **PowerShell (`Get-FileHash`)**: Used to verify file integrity via SHA256.
- **WhatIsMyIP**: Used for reverse DNS lookups of IPs found in memory.

### Lessons Learned
- **C2 and Domain Mapping**: IPs found in `netscan` (e.g., `185.70.41.130`) can be mapped to domains (e.g., `protonmail`) to understand the nature of the connection.
- **Process Lineage**: Tracking the PPID is essential for understanding how a malicious process was spawned.
- **Persistence of Command Lines**: Commands executed in `cmd.exe` often persist in the memory of `conhost.exe`, providing a critical trail of activity.
- **UserAssist as Evidence**: UserAssist is a powerful artifact for proving that a specific application was run and when.

### Commands/Examples
**Calculating file hash via PowerShell:**
```powershell
Get-FileHash -Algorithm SHA256 <file_path>
```

**Volatility 3 Plugin Usage (Conceptual):**
- `vol -f mem.dump windows.pslist` $\rightarrow$ Find PID
- `vol -f mem.dump windows.netscan` $\rightarrow$ Find connections
- `vol -f mem.dump windows.info` $\rightarrow$ Find acquisition time
- `vol -f mem.dump windows.cmdline` $\rightarrow$ Find file paths

### Geoff Application
- **Memory Triage Workflow**: Always start with `windows.info` to establish a timeline, then `windows.pslist` and `windows.netscan` to identify suspicious processes and connections.
- **Artifact Pivot**: If a suspicious process is found, pivot to `windows.cmdline` to see how it was started and `windows.registry.userassist` to see how often it has been run.
- **Data Recovery**: Use hex editors for specific offset-based data retrieval when the structure of the memory segment is known.
- **Metadata Hunting**: In file-based challenges, always check PDF/Image metadata for coordinates or hidden strings using Autopsy.
