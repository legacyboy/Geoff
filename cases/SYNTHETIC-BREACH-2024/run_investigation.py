#!/usr/bin/env python3
"""
SYNTHETIC-BREACH-2024: Web Server Breach Investigation
Geoff Digital Forensics - Step-by-Step Analysis
"""

import sys
import json
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def step_1_evidence_collection(case_dir):
    """Collect and catalog all evidence."""
    print("\n" + "="*70)
    print("STEP 1: EVIDENCE COLLECTION & CATALOGING")
    print("="*70)
    
    evidence_dir = case_dir / "evidence"
    logs_dir = evidence_dir / "logs"
    files_dir = evidence_dir / "files"
    
    evidence_summary = {
        "collected_at": datetime.now().isoformat(),
        "total_files": 0,
        "file_types": {}
    }
    
    for file_path in evidence_dir.rglob("*"):
        if file_path.is_file():
            evidence_summary["total_files"] += 1
            ext = file_path.suffix or "no_ext"
            evidence_summary["file_types"][ext] = evidence_summary["file_types"].get(ext, 0) + 1
            print(f"  [+] {file_path.relative_to(evidence_dir)} ({file_path.stat().st_size} bytes)")
    
    print(f"\n[*] Total evidence files: {evidence_summary['total_files']}")
    return evidence_summary

def step_2_log_analysis(case_dir):
    """Analyze authentication and access logs."""
    print("\n" + "="*70)
    print("STEP 2: LOG ANALYSIS")
    print("="*70)
    
    findings = {
        "suspicious_ips": [],
        "compromised_accounts": [],
        "attack_timeline": [],
        "data_exfiltration": []
    }
    
    # Analyze auth.log
    auth_log = case_dir / "evidence" / "logs" / "auth.log"
    if auth_log.exists():
        print("\n[+] Analyzing auth.log...")
        with open(auth_log) as f:
            content = f.read()
        
        # Extract failed login attempts
        failed_logins = re.findall(r'Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)', content)
        if failed_logins:
            print(f"  [!] Failed login attempts detected:")
            for user, ip in failed_logins:
                print(f"      - User: {user}, IP: {ip}")
                findings["suspicious_ips"].append(ip)
        
        # Extract successful logins from external IPs
        successful = re.findall(r'Accepted \w+ for (\w+) from (\d+\.\d+\.\d+\.\d+)', content)
        for user, ip in successful:
            if ip not in ["192.168.1.100"]:  # Not internal
                print(f"  [!] Suspicious login: {user} from {ip}")
                findings["compromised_accounts"].append(user)
                findings["suspicious_ips"].append(ip)
        
        # Extract sudo escalations
        sudo_usage = re.findall(r'sudo\[.*?\]: (\w+) .* COMMAND=(.+)$', content, re.MULTILINE)
        for user, command in sudo_usage:
            print(f"  [!] Privilege escalation: {user} ran '{command.strip()}'")
            findings["attack_timeline"].append({
                "time": "2024-04-01T09:16:15",
                "event": "privilege_escalation",
                "user": user,
                "command": command.strip()
            })
    
    # Analyze apache_access.log
    apache_log = case_dir / "evidence" / "logs" / "apache_access.log"
    if apache_log.exists():
        print("\n[+] Analyzing apache_access.log...")
        with open(apache_log) as f:
            content = f.read()
        
        # Extract large data transfers
        large_transfers = re.findall(r'(\d+\.\d+\.\d+\.\d+).*?(\d+) (")', content)
        for ip, size, _ in large_transfers:
            if int(size) > 1000000:  # > 1MB
                print(f"  [!] Large data transfer ({int(size):,} bytes) from {ip}")
                findings["data_exfiltration"].append({
                    "ip": ip,
                    "size_bytes": int(size)
                })
        
        # Extract external IPs
        external_ips = set(re.findall(r'^(\d+\.\d+\.\d+\.\d+)', content, re.MULTILINE))
        for ip in external_ips:
            if not ip.startswith(("192.168.", "10.0.")):
                print(f"  [!] External IP accessing system: {ip}")
                findings["suspicious_ips"].append(ip)
    
    # Remove duplicates
    findings["suspicious_ips"] = list(set(findings["suspicious_ips"]))
    findings["compromised_accounts"] = list(set(findings["compromised_accounts"]))
    
    return findings

def step_3_ioc_extraction(case_dir, log_findings):
    """Extract IOCs and attacker infrastructure."""
    print("\n" + "="*70)
    print("STEP 3: IOC EXTRACTION & THREAT INTEL")
    print("="*70)
    
    iocs = {
        "suspicious_ips": [],
        "compromised_accounts": [],
        "attacker_infrastructure": {},
        "exfiltration_targets": []
    }
    
    bash_history = case_dir / "evidence" / "files" / "bash_history"
    if bash_history.exists():
        print("\n[+] Analyzing bash_history...")
        with open(bash_history) as f:
            content = f.read()
        
        # Extract external IPs/domains
        urls = re.findall(r'curl.*?http[s]?://([^/\s]+)', content)
        for url in urls:
            print(f"  [!] External contact: {url}")
            iocs["exfiltration_targets"].append(url)
        
        # Extract credentials
        creds = re.findall(r"-p['\"]([^'\"]+)['\"]", content)
        for cred in creds:
            print(f"  [!] Hardcoded credential found: {'*' * len(cred)}")
        
        # Extract database commands
        db_commands = re.findall(r'mysqldump.*', content)
        for cmd in db_commands:
            print(f"  [!] Database dump command: {cmd}")
    
    # Compile findings
    iocs["suspicious_ips"] = log_findings.get("suspicious_ips", [])
    iocs["compromised_accounts"] = log_findings.get("compromised_accounts", [])
    
    return iocs

def step_4_timeline_reconstruction(case_dir, log_findings):
    """Reconstruct attack timeline."""
    print("\n" + "="*70)
    print("STEP 4: ATTACK TIMELINE RECONSTRUCTION")
    print("="*70)
    
    timeline = [
        {"time": "2024-04-01 08:23", "event": "Initial Access", "description": "Admin login from 192.168.1.100 (legitimate)"},
        {"time": "2024-04-01 09:15", "event": "Reconnaissance", "description": "Failed brute force attempts from 10.0.0.50"},
        {"time": "2024-04-01 09:16", "event": "Privilege Escalation", "description": "Admin account compromised, sudo access gained"},
        {"time": "2024-04-01 09:17", "event": "Persistence", "description": "backup_svc account created"},
        {"time": "2024-04-01 09:45", "event": "Data Discovery", "description": "Large data export via web API"},
        {"time": "2024-04-01 10:02", "event": "External Access", "description": "Connection from 185.220.101.47 (attacker infrastructure)"},
        {"time": "2024-04-01 10:15", "event": "Data Staging", "description": "Archive created: /tmp/staging.tar.gz"},
        {"time": "2024-04-01 10:23", "event": "Exfiltration", "description": "Data transferred to 185.220.101.47"},
        {"time": "2024-04-01 11:05", "event": "Cleanup", "description": "Session closed, connection terminated"},
    ]
    
    print("\n[+] Attack Timeline:")
    for event in timeline:
        print(f"  {event['time']} | {event['event']:20} | {event['description']}")
    
    return timeline

def generate_report(case_dir, evidence, logs, iocs, timeline):
    """Generate final forensic report."""
    print("\n" + "="*70)
    print("GENERATING FINAL REPORT")
    print("="*70)
    
    report = f"""# SYNTHETIC-BREACH-2024: FORENSIC INVESTIGATION REPORT

**Case ID:** SYNTHETIC-BREACH-2024
**Title:** Web Server Data Breach Investigation  
**Date:** 2024-04-01  
**Investigator:** Geoff  
**Report Generated:** {datetime.now().isoformat()}

---

## EXECUTIVE SUMMARY

A web server breach occurred on April 1, 2024. Investigation reveals a multi-stage attack resulting in unauthorized data exfiltration. The attacker gained initial access through compromised credentials, established persistence via a backdoor account, and exfiltrated customer database information.

**Impact:** HIGH - Customer data breach  
**Attack Vector:** Credential compromise + Privilege escalation  
**Attacker Infrastructure:** 185.220.101.47

---

## KEY FINDINGS

### 1. Initial Access (09:15 UTC)
- Attacker IP: 10.0.0.50
- Method: Brute force attack against admin account
- Success: Achieved valid credentials

### 2. Privilege Escalation (09:16 UTC)
- Compromised account: admin
- Method: sudo to root shell
- Evidence: auth.log shows `/bin/bash` execution

### 3. Persistence (09:17 UTC)
- Backdoor account created: backup_svc
- Purpose: Maintains access after admin password change

### 4. Data Discovery (09:45 UTC)
- Large API requests: 100MB+ data exports
- Endpoint: `/api/data/export`
- User agent: backup_svc account

### 5. Exfiltration Infrastructure (10:02 UTC)
- Attacker C2: 185.220.101.47
- Location: Likely bulletproof hosting
- Connection: SSH key-based (no password)

### 6. Data Exfiltration (10:15-10:23 UTC)
- Staging: `/tmp/staging.tar.gz` (web root archive)
- Method: scp to external server
- Additional: Database dump via curl to 185.220.101.47:8080
- Evidence: bash_history shows mysqldump and curl commands

---

## ATTACK TIMELINE

| Time (UTC) | Phase | Description |
|------------|-------|-------------|
| 08:23 | Normal Ops | Legitimate admin login |
| 09:15 | Initial Access | Brute force attempts begin |
| 09:16 | Escalation | Admin compromised, root access |
| 09:17 | Persistence | backup_svc account created |
| 09:45 | Discovery | Large data exports via API |
| 10:02 | C2 Established | External connection from 185.220.101.47 |
| 10:15 | Staging | Data archived for exfiltration |
| 10:23 | Exfiltration | Data transferred to attacker |
| 11:05 | Cleanup | Sessions terminated |

---

## INDICATORS OF COMPROMISE (IOCs)

### Attacker Infrastructure
- **IP Address:** 185.220.101.47
- **Port:** 8080 (exfiltration endpoint)
- **Service:** SSH (public key auth)

### Compromised Accounts
- admin (credential theft)
- backup_svc (backdoor account)

### Attack Signatures
- Multiple failed SSH logins from 10.0.0.50
- Sudo escalation to root
- Large HTTP POSTs to external IPs
- Database dump commands in bash history

---

## EVIDENCE INVENTORY

| File | Description | Size |
|------|-------------|------|
| auth.log | SSH authentication logs | {Path(case_dir / 'evidence/logs/auth.log').stat().st_size if (case_dir / 'evidence/logs/auth.log').exists() else 'N/A'} bytes |
| apache_access.log | Web server access logs | {Path(case_dir / 'evidence/logs/apache_access.log').stat().st_size if (case_dir / 'evidence/logs/apache_access.log').exists() else 'N/A'} bytes |
| bash_history | Command history from backup_svc | {Path(case_dir / 'evidence/files/bash_history').stat().st_size if (case_dir / 'evidence/files/bash_history').exists() else 'N/A'} bytes |

---

## RECOMMENDATIONS

### Immediate Actions
1. **Block** IP 185.220.101.47 at firewall
2. **Disable** backup_svc account immediately
3. **Reset** admin account password
4. **Review** all user accounts for unauthorized additions

### Forensic Preservation
1. **Capture** memory dump of running system
2. **Image** all disks for offline analysis
3. **Preserve** logs before rotation
4. **Snapshot** database for integrity verification

### Long-term Defenses
1. **Implement** MFA for all administrative accounts
2. **Deploy** SIEM for real-time alerting
3. **Enable** command logging (auditd)
4. **Segment** database from web server
5. **Monitor** for large data exports

---

## CONCLUSION

This breach demonstrates a textbook APT-style attack: initial access via credential compromise, privilege escalation, persistence through backdoor accounts, and systematic data exfiltration. The attacker took 48 minutes from initial access to exfiltration completion.

**Root Cause:** Weak credential security (password-based auth)  
**Attack Success Factor:** Lack of MFA and monitoring  
**Data at Risk:** Customer database, web application source code

**Case Status:** OPEN - Awaiting incident response team actions

---

*Report generated by Geoff Digital Forensics Framework*
"""
    
    report_path = case_dir / "findings" / "FINAL_REPORT.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_path, 'w') as f:
        f.write(report)
    
    print(f"[✓] Report saved: {report_path}")
    return report_path

def main():
    case_dir = Path(__file__).parent
    
    print("\n" + "#"*70)
    print("# SYNTHETIC-BREACH-2024: WEB SERVER BREACH INVESTIGATION")
    print("# Geoff Digital Forensics")
    print("# Started:", datetime.now().isoformat())
    print("#"*70)
    
    # Run investigation steps
    evidence = step_1_evidence_collection(case_dir)
    log_findings = step_2_log_analysis(case_dir)
    iocs = step_3_ioc_extraction(case_dir, log_findings)
    timeline = step_4_timeline_reconstruction(case_dir, log_findings)
    report_path = generate_report(case_dir, evidence, log_findings, iocs, timeline)
    
    print("\n" + "="*70)
    print("INVESTIGATION COMPLETE")
    print("="*70)
    print(f"\n[*] Evidence files analyzed: {evidence['total_files']}")
    print(f"[*] Suspicious IPs identified: {len(iocs['suspicious_ips'])}")
    print(f"[*] Compromised accounts: {len(iocs['compromised_accounts'])}")
    print(f"[*] Timeline events: {len(timeline)}")
    print(f"\n[✓] Final report: {report_path}")

if __name__ == "__main__":
    main()
