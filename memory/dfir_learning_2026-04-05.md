
## Source: https://github.com/Haalloobim/Cyber-Defender-Labs-WriteUp/blob/main/BRabbit-CyberDefender-WU/README.md
### Key Techniques
- **Phishing Analysis**: Analysis of `.eml` files to identify sender addresses and social engineering indicators.
- **Malware Family Identification**: Using VirusTotal to identify malware families based on file hashes.
- **Dynamic Analysis**: Using Any.Run to monitor malware execution and identify dropped files (e.g., files starting with 'i').
- **Static Analysis**: Reviewing strings and security reports (Securelist, Talos) to identify hardcoded credentials, usernames, and brute-force capabilities.
- **TTP Mapping**: Mapping malware behavior to MITRE ATT&CK sub-techniques (e.g., Web Protocols for C2, Scheduled Tasks for Persistence).
- **MBR Analysis**: Identifying drivers used for Master Boot Record corruption and hard drive encryption.
- **Attribution**: Utilizing Malpedia to link malware families (e.g., BAdRabbit) to specific threat actors.

### Tools Used
- **Eml Analyzer**: Parsing `.eml` files to extract headers and attachments.
- **VirusTotal**: Hash-based malware identification and family detection.
- **Any.Run**: Interactive sandbox for dynamic analysis and behavioral monitoring.
- **Malpedia**: Threat actor attribution and malware family research.
- **MITRE ATT&CK**: Framework for identifying and labeling attacker techniques.

### Lessons Learned
- **Social Engineering**: Attackers often spoof company logos and familiar addresses to deceive employees.
- **Persistence**: Ransomware may use Scheduled Tasks to maintain a presence on the system.
- **Anti-Defense**: Some binaries (e.g., `dispci.exe`) may explicitly prompt users to disable security software.
- **MBR Corruption**: High-impact ransomware often targets the MBR to render systems unbootable.

### Commands/Examples
- No specific CLI commands provided, primarily GUI-based tool usage.

### Geoff Application
- Implement a workflow for `.eml` analysis starting with header extraction $\rightarrow$ hash submission to VT $\rightarrow$ sandbox execution in Any.Run $\rightarrow$ TTP mapping.

---

## Source: https://github.com/Haalloobim/Cyber-Defender-Labs-WriteUp/blob/main/KrakenKeylogger-CyberDefender-WU/README.md
### Key Techniques
- **LNK File Analysis**: Analyzing Windows shortcut files to find malicious paths and arguments (e.g., scripts passed to `powershell.exe`).
- **Persistence Detection**: Identifying obfuscated scripts used for persistence through LNK and LOLApps.
- **Deobfuscation**: Using Python to reverse obfuscated strings (e.g., string slicing and reversal).
- **Notification Database Analysis**: Parsing `wpndatabase.db` (Windows Push Notification database) to recover communication logs and passwords.
- **LOLBins/LOLApps Analysis**: Identifying the use of legitimate software (e.g., Greenshot) to execute malicious commands.
- **Log Analysis**: Examining `.trace` files within application directories to find attacker IP addresses.

### Tools Used
- **LECmd**: Parsing `.lnk` files to extract target paths and arguments.
- **Timeline Explorer**: Analyzing CSV dumps of forensic artifacts to identify anomalies.
- **DB Browser for SQLite**: Querying `.db` files (like `wpndatabase.db`).
- **Python**: Custom scripts for string deobfuscation.
- **LOLApps Project**: Reference for identifying Living-off-the-Land Applications.

### Lessons Learned
- **Windows Notifications**: The `wpndatabase.db` file is a goldmine for recovering messages and passwords sent via notifications.
- **LNK Arguments**: Attackers often use the "Arguments" field in LNK files to hide PowerShell scripts.
- **LOLApps Persistence**: Legitimate apps like Greenshot can be leveraged to maintain persistence or execute commands.

### Commands/Examples
- **Listing Artifacts**:
```sh
tree | grep -E '\\.db|\\.lnk'
```
- **LECmd Execution**:
```sh
./LECmd.exe -d "challenge/" --all --csv "csvDump" --pretty
```
- **DB Browser**:
```sh
sqlitebrowser -R wpndatabase.db
```
- **Python Deobfuscation Script**:
```python
url = 'aht1.sen/hi/coucys.erstmaofershma//s:tpht'
url = url[::-1]
for i in range(0, len(url), 2):
    if i == len(url) - 1:
        print(url[i])
        break
    else:
        print(url[i+1] + url[i], end='')
```

### Geoff Application
- Add `wpndatabase.db` and `.lnk` file analysis to the standard Windows host forensics checklist. Focus on the "Arguments" field in LNKs.

---

## Source: https://github.com/Haalloobim/Cyber-Defender-Labs-WriteUp/blob/main/PsExec-CyberDefender-Wu/README.md
### Key Techniques
- **Network Traffic Analysis**: Analyzing PCAP files to identify lateral movement.
- **SMB Protocol Analysis**: Tracking SMB session requests and responses to identify target hostnames and usernames.
- **PsExec Behavioral Analysis**: Identifying the service executables and network shares (`ADMIN$`, `C$`) used by PsExec for service installation and communication.
- **Pivot Detection**: Identifying new session requests at the end of a capture to detect further lateral movement attempts.

### Tools Used
- **Wireshark**: Deep packet inspection of SMB and TCP traffic.

### Lessons Learned
- **PsExec Indicators**: PsExec typically creates a service on the target machine; identifying the executable name is key to confirming its use.
- **SMB Shares**: PsExec relies on administrative shares for the initial installation of its service.
- **Lateral Movement**: Tracking the source IP of the first SMB packet often reveals the initial compromise point.

### Commands/Examples
- Analysis performed via Wireshark GUI (filtering for `smb` or `smb2`).

### Geoff Application
- When analyzing PCAPs for lateral movement, filter for SMB traffic and look specifically for service installation patterns associated with PsExec.

---

## Source: https://github.com/Haalloobim/Cyber-Defender-Labs-WriteUp/blob/main/TheCrime-CyberDefender-WU/README.md
### Key Techniques
- **Android Forensics**: Parsing Android device artifacts to recover app lists, messages, and location data.
- **App Inventory Analysis**: Identifying installed trading apps to establish a user's financial activities.
- **SMS and Contact Recovery**: Correlating phone numbers from SMS messages to contact lists to identify individuals.
- **Location Tracking**: Analyzing "Recent Activity" and map data to determine a victim's movements.
- **Communication Analysis**: Parsing Discord chat logs to find meeting locations and coordination details.

### Tools Used
- **ALEAPP**: Android Logs and Events Analysis Tool for parsing Android artifacts.
- **DB Browser for SQLite**: Manual analysis of Android database files.

### Lessons Learned
- **Android Artifacts**: `index.html` output from ALEAPP provides a comprehensive overview of installed apps, SMS, and activity logs.
- **Cross-Referencing**: Combining SMS logs $\rightarrow$ Contacts $\rightarrow$ Discord chats $\rightarrow$ Google Maps results allows for a full timeline reconstruction.

### Commands/Examples
- **ALEAPP GUI Launch**:
```sh
python3 aleappGUI.py
```

### Geoff Application
- For mobile forensics, use ALEAPP as the primary parser and follow the lead from SMS/Chat $\rightarrow$ Contacts $\rightarrow$ Location History.
