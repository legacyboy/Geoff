# CyberDefenders: Injector Challenge Write-up

## Overview
Investigation of a breached web server. The goal is to determine the compromise vector and attacker actions using memory and disk forensics.
- Image Size: 2.9 GB (.mem & disk image)
- Tags: Volatility, Autopsy, Web Server, DFIR, Memory analysis, FTK Imager

## Tools Used
- FTK Imager: Disk image preview.
- Volatility: Memory analysis.
- Regripper: Registry hive parsing.
- CyberChef: Decoding and analysis.

## Analysis & Findings

### 1. System Configuration (Registry Analysis)
- Computer Name: Extracted from SOFTWARE hive -> WIN-L0ZZQ76PMUF.
- Time Zone: Extracted from SYSTEM hive -> UTC-7 (Pacific Standard Time).
- OS Version: Extracted from SOFTWARE hive -> Build 6001.
- User Accounts: Analyzed SAM hive -> Found 4 user accounts.

### 2. Web Server Compromise (Log Analysis)
- Software: The server was running XAMPP with the DVWA (Damn Vulnerable Web Application) installed.
- Attack Vectors identified in access.log:
  - XSS (Cross-Site Scripting): Found <script>eval(window.name)</script> in requests to security.php.
  - SQL Injection (SQLi): Found payloads like a'+or+1=1. Attacker used sqlmap/1.0-dev-nongit-20150902.
  - LFI (Local File Inclusion): Found attempts to read /windows/system32/drivers/etc/hosts.
- Web Shell: Identified a PHP web shell using the cmd GET parameter.

### 3. Attacker Actions (Memory Analysis)
- Persistence/Access: Used Volatility cmdscan to find netsh commands used to enable remotedesktop (RDP) through the firewall.
- Credential Theft: Used hashdump to extract NTLM hashes for users.
- Malicious File Upload: The attacker used sqlmap's INTO OUTFILE capability to upload a PHP file uploader. The uploader checks for PHP version 4.1.0.

### 4. Indicators of Compromise (IoC)
- Attacker IP: 192.168.56.102
- Malicious File Hash: 5594112b531660654429f8639322218b
- MITRE Technique: T1136.001 (Local Account Creation).

## Flags Summary
- Computer Name: WIN-L0ZZQ76PMUF
- Time Zone: UTC-7
- Web Vulnerability 1: XSS
- OS Build: 6001
- User Count: 4
- Web Server: xampp
- Web App: dvwa
- Tool Used: sqlmap/1.0-dev-nongit-20150902
- LFI File: hosts
- RDP Service: remotedesktop
- User Account Count (Hashdump): 2
- User Creation Date: 2015-09-02 09:05:06 UTC
- NT Hash: 817875ce4794a9262159186413772644
- MITRE Tech: T1136.001
- Web Shell Param: cmd
- File Hash: 5594112b531660654429f8639322218b
- Attacker IP: 192.168.56.102
- PHP Version: 4.1.0
