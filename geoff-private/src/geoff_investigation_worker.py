#!/usr/bin/env python3
"""
G.E.O.F.F. Investigation Worker
Background process for long-running forensic investigations
Updates status file and ACTUALLY RUNS TOOLS, saves outputs
"""

import os
import sys
import json
import time
import subprocess
import re
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, '/home/claw/.openclaw/workspace/geoff-private/src')

# Configuration from environment
CASES_WORK_DIR = os.environ.get('GEOFF_CASES_PATH', "/home/sansforensics/evidence-storage/cases")
EVIDENCE_BASE_DIR = os.environ.get('GEOFF_EVIDENCE_PATH', "/home/sansforensics/evidence-storage/evidence")

class InvestigationWorker:
    """Background worker for running full investigations"""
    
    def __init__(self, case_name: str, work_dir: str = None, evidence_path: str = None):
        self.case_name = case_name
        self.evidence_path = evidence_path
        self.start_time = datetime.now()
        
        # Use provided work directory or create timestamped one
        if work_dir:
            self.case_dir = Path(work_dir)
            self.case_dir.mkdir(parents=True, exist_ok=True)
        else:
            # Fallback: use cases/<case>_<timestamp>/
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.case_dir = Path(CASES_WORK_DIR) / f"{case_name}_{timestamp}"
            self.case_dir.mkdir(parents=True, exist_ok=True)
        
        self.status_file = self.case_dir / "investigation_status.json"
        self.log_file = self.case_dir / "investigation_log.jsonl"
        
        # Ensure output subdirectories exist
        (self.case_dir / "output").mkdir(exist_ok=True)
        (self.case_dir / "reports").mkdir(exist_ok=True)
        (self.case_dir / "timeline").mkdir(exist_ok=True)
        
    def update_status(self, phase: str, tool: str, status: str, progress: int, details: dict = None):
        """Update investigation status file"""
        status_data = {
            "timestamp": datetime.now().isoformat(),
            "case": self.case_name,
            "phase": phase,
            "current_tool": tool,
            "status": status,
            "progress_percent": progress,
            "elapsed_seconds": (datetime.now() - self.start_time).total_seconds(),
            "details": details or {}
        }
        
        with open(self.status_file, 'w') as f:
            json.dump(status_data, f, indent=2)
        
        # Also append to log
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(status_data) + '\n')
        
        print(f"[{self.case_name}] {phase}/{tool}: {status} ({progress}%)")
    
    def run_tool_and_save(self, tool_name: str, command: list, output_file: str) -> dict:
        """Run a forensic tool and save output to file"""
        output_path = self.case_dir / "output" / output_file
        
        try:
            # Run the command and capture output
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Save stdout to file
            with open(output_path, 'w') as f:
                f.write(result.stdout)
                if result.stderr:
                    f.write("\n\nSTDERR:\n")
                    f.write(result.stderr)
            
            return {
                "success": result.returncode == 0,
                "output_file": str(output_path),
                "lines": len(result.stdout.splitlines()),
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout", "output_file": str(output_path)}
        except Exception as e:
            return {"success": False, "error": str(e), "output_file": str(output_path)}
    
    def run_investigation(self):
        """Run full investigation through all playbooks - ACTUALLY RUNS TOOLS"""
        try:
            self.update_status("INIT", "startup", "running", 0, 
                             {"message": "Investigation started", "work_dir": str(self.case_dir)})
            
            # Find evidence files
            evidence_files = []
            if self.evidence_path and os.path.exists(self.evidence_path):
                evidence_files = [self.evidence_path]
            else:
                # Search in evidence base dir for case
                case_evidence_dir = Path(EVIDENCE_BASE_DIR) / self.case_name
                if case_evidence_dir.exists():
                    for ext in ['.E01', '.dd', '.raw', '.mem', '.img', '.vmdk', '.aff']:
                        evidence_files.extend(case_evidence_dir.rglob(f'*{ext}'))
            
            evidence_file = str(evidence_files[0]) if evidence_files else None
            
            results_summary = []
            
            # Phase 1: DISK FORENSICS
            self.update_status("DISK_FORENSICS", "mmls", "running", 5,
                             {"evidence": evidence_file})
            
            if evidence_file and os.path.exists(evidence_file):
                # Run mmls
                result = self.run_tool_and_save(
                    "mmls",
                    ["mmls", evidence_file],
                    "mmls_partition_table.txt"
                )
                results_summary.append({"tool": "mmls", "result": result})
                self.git_commit(f"Added mmls output for {self.case_name}")
                
                # Run fsstat
                self.update_status("DISK_FORENSICS", "fsstat", "running", 10)
                result = self.run_tool_and_save(
                    "fsstat",
                    ["fsstat", evidence_file],
                    "fsstat_filesystem.txt"
                )
                results_summary.append({"tool": "fsstat", "result": result})
                
                # Run fls (list files)
                self.update_status("DISK_FORENSICS", "fls", "running", 15)
                result = self.run_tool_and_save(
                    "fls",
                    ["fls", "-r", "-p", evidence_file],
                    "fls_file_listing.txt"
                )
                results_summary.append({"tool": "fls", "result": result})
            
            # Phase 2: STRING EXTRACTION (always works)
            self.update_status("IOC_EXTRACTION", "strings", "running", 30)
            if evidence_file:
                result = self.run_tool_and_save(
                    "strings",
                    ["strings", "-a", "-n", "8", evidence_file],
                    "strings_output.txt"
                )
                results_summary.append({"tool": "strings", "result": result})
                
                # Extract IOCs from strings
                self.extract_iocs_from_strings()
            
            # Phase 3: MEMORY FORENSICS (if memory dump)
            self.update_status("MEMORY_FORENSICS", "volatility", "running", 50)
            if evidence_file and ('.mem' in evidence_file or '.raw' in evidence_file):
                # Run volatility pslist
                result = self.run_tool_and_save(
                    "volatility",
                    ["vol.py", "-f", evidence_file, "windows.pslist.PsList"],
                    "volatility_pslist.txt"
                )
                results_summary.append({"tool": "volatility_pslist", "result": result})
            
            # Phase 4: YARA SCAN (if rules available)
            self.update_status("MALWARE_DETECTION", "yara", "running", 70)
            if evidence_file:
                result = self.run_tool_and_save(
                    "yara",
                    ["yara", "/usr/share/yara/rules/index.yar", evidence_file],
                    "yara_scan.txt"
                )
                results_summary.append({"tool": "yara", "result": result})
            
            # Phase 5: Generate summary report
            self.update_status("REPORT_GENERATION", "summary", "running", 90)
            self.generate_summary_report(results_summary)
            self.git_commit(f"Investigation complete for {self.case_name}")
            
            # Final status
            self.update_status("COMPLETE", "investigation", "complete", 100,
                             {"message": "Full investigation complete",
                              "total_tools": len(results_summary),
                              "evidence_file": evidence_file,
                              "output_dir": str(self.case_dir / "output"),
                              "elapsed_minutes": (datetime.now() - self.start_time).total_seconds() / 60})
            
        except Exception as e:
            self.update_status("ERROR", "investigation", "error", 0,
                             {"error": str(e)})
            raise
    
    def extract_iocs_from_strings(self):
        """Extract IOCs from strings output"""
        strings_file = self.case_dir / "output" / "strings_output.txt"
        iocs_file = self.case_dir / "output" / "extracted_iocs.txt"
        
        if not strings_file.exists():
            return
        
        iocs = {
            "urls": [],
            "ips": [],
            "emails": [],
            "registry": []
        }
        
        with open(strings_file, 'r', errors='ignore') as f:
            content = f.read()
            
            # Extract URLs
            urls = re.findall(r'https?://[^\s<>"{}|\^`\[\]]+', content)
            iocs["urls"] = list(set(urls))[:100]  # Limit to 100 unique
            
            # Extract IPs
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
            iocs["ips"] = list(set(ips))[:100]
            
            # Extract emails
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
            iocs["emails"] = list(set(emails))[:50]
            
            # Extract registry paths
            registry = re.findall(r'HKLM\\[A-Za-z0-9_\\]+|HKCU\\[A-Za-z0-9_\\]+', content)
            iocs["registry"] = list(set(registry))[:50]
        
        with open(iocs_file, 'w') as f:
            json.dump(iocs, f, indent=2)
    
    def generate_summary_report(self, results_summary: list):
        """Generate final summary report"""
        report_file = self.case_dir / "reports" / "investigation_summary.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"G.E.O.F.F. INVESTIGATION REPORT\n")
            f.write(f"=" * 60 + "\n\n")
            f.write(f"Case: {self.case_name}\n")
            f.write(f"Started: {self.start_time.isoformat()}\n")
            f.write(f"Completed: {datetime.now().isoformat()}\n")
            f.write(f"Duration: {(datetime.now() - self.start_time).total_seconds() / 60:.1f} minutes\n\n")
            
            f.write(f"TOOLS EXECUTED:\n")
            f.write(f"-" * 40 + "\n")
            for item in results_summary:
                tool = item["tool"]
                result = item["result"]
                status = "✓" if result.get("success") else "✗"
                f.write(f"{status} {tool}: {result.get('lines', 0)} lines\n")
                if "output_file" in result:
                    f.write(f"   Output: {result['output_file']}\n")
            
            f.write(f"\nOUTPUT LOCATION: {self.case_dir / 'output'}\n")
            f.write(f"REPORTS LOCATION: {self.case_dir / 'reports'}\n")
    
    def git_commit(self, message: str):
        """Commit changes to git with error handling"""
        try:
            # Configure git to trust this directory
            subprocess.run(
                ['git', 'config', '--local', 'safe.directory', str(self.case_dir)],
                cwd=self.case_dir,
                capture_output=True
            )
            
            # Add all files
            result = subprocess.run(
                ['git', 'add', '.'],
                cwd=self.case_dir,
                capture_output=True,
                text=True
            )
            
            # Check if there are changes to commit
            status = subprocess.run(
                ['git', 'diff', '--cached', '--quiet'],
                cwd=self.case_dir,
                capture_output=True
            )
            
            # Only commit if there are staged changes
            if status.returncode != 0:  # Changes exist
                result = subprocess.run(
                    ['git', 'commit', '-m', message],
                    cwd=self.case_dir,
                    capture_output=True,
                    text=True
                )
                print(f"[GIT] Committed: {message}")
            else:
                print(f"[GIT] Nothing to commit for: {message}")
                
        except Exception as e:
            print(f"[GIT ERROR] {e}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: geoff_investigation_worker.py <case_name> [work_directory] [evidence_path]")
        sys.exit(1)
    
    case_name = sys.argv[1]
    work_dir = sys.argv[2] if len(sys.argv) > 2 else None
    evidence_path = sys.argv[3] if len(sys.argv) > 3 else None
    
    worker = InvestigationWorker(case_name, work_dir, evidence_path)
    worker.run_investigation()
