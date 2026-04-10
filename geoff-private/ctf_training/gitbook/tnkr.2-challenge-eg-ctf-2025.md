# TNKR.2 Challenge — EG-CTF 2025 Forensics Write-up

## Objective
Analyze system artifacts to determine the Command and Control (C2) server and the domain used for data exfiltration.

## Analysis Approach
- Artifacts: Windows Event Logs (.evtx files).
- Tool Used: Hayabusa (specifically json-timeline mode).
- Methodology: 
  - Triage of workstations (dc-1, desktop6) and the file server.
  - Used pivot-keywords-list in Hayabusa to find high-signal events (suspicious process execution, network connections, PowerShell activity).
  - Focused on the file server where C2 and exfiltration activity were centralized.

## Key Findings
- C2 Infrastructure:
  - A Python script (testc.py) executed via pythonw.exe in silent mode.
  - C2 Domain: agegamepay.com
  - C2 IP (Redirector): 104.21.76.201 (Cloudflare).
  - C2 Port: TCP 8443.
  - Strategy: Used C2 Redirection via Cloudflare to mask the true backend server IP.

- Data Exfiltration:
  - Occurred exclusively from the file server.
  - Tools Used: rclone.exe, rclone+config.zip, and python.zip.
  - Exfiltration Destination: Mega cloud storage (mega:V1A).

## Summary of Indicators
- C2 Domain: agegamepay.com
- C2 IP: 104.21.76.201 (Cloudflare reverse proxy)
- Exfiltration Tool: Rclone
- Exfiltration Target: Mega.nz
