# Security Agent Team Configuration

Specialized sub-agents for Kali Linux security research and CTF automation.

## Agent Roster

### 🔍 kali-recon (Reconnaissance Agent)
**Purpose:** Network reconnaissance, host discovery, enumeration

**Tools:**
- nmap (discovery, port scan, version, OS, scripts)
- masscan (fast large-scale scanning)
- dnsrecon, dnsenum, fierce (DNS enum)
- snmpwalk, onesixtyone (SNMP)
- arp-scan, netdiscover (host discovery)

**Usage:**
```bash
# Spawn for recon task
openclaw subagent spawn kali-recon "Scan 192.168.1.0/24 for web servers"
```

---

### 🌐 kali-websec (Web Application Security Agent)
**Purpose:** Web app testing, directory brute-forcing, vulnerability scanning

**Tools:**
- gobuster, dirb, ffuf, feroxbuster (directory brute)
- nikto, nmap http scripts (web vuln scan)
- sublist3r, amass, subfinder (subdomain enum)
- whatweb, wappalyzer (tech fingerprinting)
- sslscan, sslyze, testssl.sh (SSL/TLS)
- sqlmap (SQL injection)

**Usage:**
```bash
# Spawn for web testing
openclaw subagent spawn kali-websec "Test https://target.com - find directories and tech stack"
```

---

### 💥 kali-exploit (Exploitation Agent)
**Purpose:** Exploit research, credential testing, privilege escalation

**Tools:**
- searchsploit (exploit DB search)
- msfconsole (Metasploit when needed)
- hydra, medusa, crackmapexec (credential brute)
- john, hashcat (password cracking)
- enum4linux, crackmapexec (SMB)
- sqlmap (automated SQLi)
- linpeas, winpeas (privesc enum)

**Usage:**
```bash
# Spawn for exploitation assistance
openclaw subagent spawn kali-exploit "Search exploits for Apache 2.4.41"
```

---

### 📝 kali-report (Documentation Agent)
**Purpose:** Report generation, CTF notes, engagement tracking

**Tools:**
- Markdown/HTML report generation
- Tool output parsing and formatting
- Progress tracking
- Loot/credential management
- Methodology checklists

**Usage:**
```bash
# Spawn for documentation
openclaw subagent spawn kali-report "Create CTF report for hackthebox machine 'Doctor'"
```

---

## Quick Commands

```bash
# Check agent status
openclaw subagent list

# Send task to running agent
openclaw subagent send kali-recon "Run nmap -sV -sC on 10.10.10.10"

# Terminate agent
openclaw subagent kill kali-recon
```

## Directory Structure

```
workspace/
├── ctf/
│   ├── active/           # Current CTF challenges
│   ├── completed/        # Finished challenges
│   └── loot/             # Credentials, flags
├── engagements/
│   └── [target]/         # Client/personal testing notes
└── scans/
    └── [date]/           # Raw scan outputs
```

## Safety Rules

1. **Recon Agent:** Always ask before scanning non-owned networks
2. **WebSec Agent:** Only test targets with explicit permission
3. **Exploit Agent:** Never exploit without authorization; PoC preferred
4. **Report Agent:** Maintain confidentiality of all target data
