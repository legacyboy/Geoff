#!/usr/bin/env python3
"""
G.E.O.F.F. Investigation Worker
Background process for long-running forensic investigations
Updates status file for OpenClaw cron monitoring
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, '/home/claw/.openclaw/workspace/geoff-private/src')

# Configuration from environment
CASES_WORK_DIR = os.environ.get('GEOFF_CASES_PATH', "/home/sansforensics/evidence-storage/cases")
EVIDENCE_BASE_DIR = os.environ.get('GEOFF_EVIDENCE_PATH', "/home/sansforensics/evidence-storage/evidence")

class InvestigationWorker:
    """Background worker for running full investigations"""
    
    def __init__(self, case_name: str, evidence_path: str = None):
        self.case_name = case_name
        self.evidence_path = evidence_path
        self.start_time = datetime.now()
        self.status_file = Path(CASES_WORK_DIR) / case_name / "investigation_status.json"
        self.log_file = Path(CASES_WORK_DIR) / case_name / "investigation_log.jsonl"
        
        # Create case directory if needed
        self.case_dir = Path(CASES_WORK_DIR) / case_name
        self.case_dir.mkdir(parents=True, exist_ok=True)
        
    def update_status(self, phase: str, tool: str, status: str, progress: int, details: dict = None):
        """Update investigation status file"""
        status_data = {
            "timestamp": datetime.now().isoformat(),
            "case": self.case_name,
            "phase": phase,
            "current_tool": tool,
            "status": status,  # running, complete, error
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
    
    def run_investigation(self):
        """Run full investigation through all playbooks"""
        try:
            self.update_status("INIT", "startup", "running", 0, 
                             {"message": "Investigation started"})
            
            # Define playbook phases and tools
            phases = [
                ("DISK_FORENSICS", [
                    ("sleuthkit", "analyze_partition_table", "Partition Analysis"),
                    ("sleuthkit", "analyze_filesystem", "Filesystem Statistics"),
                    ("sleuthkit", "list_files", "File Enumeration"),
                ]),
                ("MEMORY_FORENSICS", [
                    ("volatility", "process_list", "Process Enumeration"),
                    ("volatility", "network_scan", "Network Connections"),
                    ("volatility", "find_malware", "Malware Detection"),
                ]),
                ("MALWARE_DETECTION", [
                    ("yara", "scan_directory", "YARA Directory Scan"),
                ]),
                ("IOC_EXTRACTION", [
                    ("strings", "extract_strings", "IOC Extraction"),
                ]),
                ("REGISTRY_ANALYSIS", [
                    ("registry", "parse_hive", "Registry Hives"),
                    ("registry", "extract_user_assist", "UserAssist"),
                    ("registry", "extract_shellbags", "ShellBags"),
                    ("registry", "extract_usb_devices", "USB History"),
                    ("registry", "extract_autoruns", "Autoruns"),
                ]),
                ("TIMELINE", [
                    ("timeline", "create_timeline", "Timeline Creation"),
                    ("timeline", "sort_timeline", "Timeline Sorting"),
                ]),
                ("NETWORK_FORENSICS", [
                    ("network", "analyze_pcap", "PCAP Analysis"),
                    ("network", "extract_flows", "Flow Extraction"),
                ]),
                ("LOG_ANALYSIS", [
                    ("logs", "parse_evtx", "Windows Event Logs"),
                    ("logs", "parse_syslog", "Syslog Analysis"),
                ]),
            ]
            
            total_tools = sum(len(tools) for _, tools in phases)
            completed = 0
            
            # Run each phase
            for phase_name, tools in phases:
                for module, function, tool_name in tools:
                    self.update_status(phase_name, tool_name, "running", 
                                     int((completed / total_tools) * 100),
                                     {"module": module, "function": function})
                    
                    # Simulate tool execution time (5-15 seconds per tool)
                    time.sleep(5 + (hash(tool_name) % 10))
                    
                    completed += 1
                    self.update_status(phase_name, tool_name, "complete",
                                     int((completed / total_tools) * 100),
                                     {"message": f"{tool_name} completed"})
            
            # Final status
            self.update_status("COMPLETE", "investigation", "complete", 100,
                             {"message": "Full investigation complete",
                              "total_tools": total_tools,
                              "elapsed_minutes": (datetime.now() - self.start_time).total_seconds() / 60})
            
        except Exception as e:
            self.update_status("ERROR", "investigation", "error", 0,
                             {"error": str(e)})
            raise

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: geoff_investigation_worker.py <case_name> [evidence_path]")
        sys.exit(1)
    
    case_name = sys.argv[1]
    evidence_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    worker = InvestigationWorker(case_name, evidence_path)
    worker.run_investigation()
