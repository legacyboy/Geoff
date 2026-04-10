#!/usr/bin/env python3
"""
SIFT Tool Specialists
Each specialist handles a specific forensic domain
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

class SLEUTHKIT_Specialist:
    """Specialist for SleuthKit disk analysis tools"""
    
    def __init__(self, evidence_path: str):
        self.evidence_path = Path(evidence_path)
        self.tools_available = self._check_tools()
    
    def _check_tools(self) -> Dict[str, bool]:
        """Check which tools are available"""
        tools = ['mmls', 'fsstat', 'fls', 'icat', 'istat', 'ils', 'blkls', 'jcat']
        available = {}
        for tool in tools:
            result = subprocess.run(['which', tool], capture_output=True)
            available[tool] = result.returncode == 0
        return available
    
    def run(self, tool: str, args: List[str]) -> Dict[str, Any]:
        """Execute SleuthKit tool"""
        if not self.tools_available.get(tool, False):
            return {
                'tool': tool,
                'status': 'error',
                'error': f'{tool} not found in PATH',
                'timestamp': datetime.now().isoformat()
            }
        
        try:
            result = subprocess.run(
                [tool] + args,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                'tool': tool,
                'status': 'success' if result.returncode == 0 else 'error',
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'timestamp': datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {
                'tool': tool,
                'status': 'timeout',
                'error': 'Command timed out after 5 minutes',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'tool': tool,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def analyze_partition_table(self, disk_image: str) -> Dict[str, Any]:
        """mmls - Display partition layout"""
        return self.run('mmls', [disk_image])
    
    def analyze_filesystem(self, partition: str) -> Dict[str, Any]:
        """fsstat - Display file system statistics"""
        return self.run('fsstat', [partition])
    
    def list_files(self, partition: str, inode: Optional[int] = None, recursive: bool = True) -> Dict[str, Any]:
        """fls - List files and directories"""
        args = [partition]
        if recursive:
            args = ['-r'] + args
        if inode:
            args += [str(inode)]
        return self.run('fls', args)
    
    def extract_file(self, partition: str, inode: int, output_path: str) -> Dict[str, Any]:
        """icat - Extract file by inode"""
        result = self.run('icat', [partition, str(inode)])
        if result['status'] == 'success':
            Path(output_path).write_text(result['stdout'])
            result['output_file'] = output_path
            result['bytes_extracted'] = len(result['stdout'])
        return result
    
    def list_inodes(self, partition: str) -> Dict[str, Any]:
        """ils - List inode information"""
        return self.run('ils', [partition])
    
    def get_file_info(self, partition: str, inode: int) -> Dict[str, Any]:
        """istat - Display inode details"""
        return self.run('istat', [partition, str(inode)])


class VOLATILITY_Specialist:
    """Specialist for memory forensics with Volatility"""
    
    def __init__(self, profile: str = "Win10x64"):
        self.profile = profile
        self.volatility_path = self._find_volatility()
    
    def _find_volatility(self) -> Optional[str]:
        """Find volatility installation"""
        for path in ['/usr/local/bin/volatility3', '/usr/bin/volatility3', 
                     '/usr/local/bin/vol.py', '/usr/bin/vol.py']:
            if Path(path).exists():
                return path
        return None
    
    def run(self, plugin: str, memory_dump: str, **kwargs) -> Dict[str, Any]:
        """Run Volatility plugin"""
        if not self.volatility_path:
            return {
                'tool': 'volatility',
                'plugin': plugin,
                'status': 'error',
                'error': 'Volatility not found',
                'timestamp': datetime.now().isoformat()
            }
        
        cmd = [self.volatility_path, '-f', memory_dump, plugin]
        
        # Add plugin-specific args
        if plugin == 'windows.pslist.PsList':
            pass  # No extra args needed
        elif plugin == 'windows.netscan.NetScan':
            pass
        elif plugin == 'windows.malfind.Malfind':
            pass
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                'tool': 'volatility',
                'plugin': plugin,
                'status': 'success' if result.returncode == 0 else 'error',
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'tool': 'volatility',
                'plugin': plugin,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def process_list(self, memory_dump: str) -> Dict[str, Any]:
        """List running processes"""
        return self.run('windows.pslist.PsList', memory_dump)
    
    def network_scan(self, memory_dump: str) -> Dict[str, Any]:
        """Scan for network connections"""
        return self.run('windows.netscan.NetScan', memory_dump)
    
    def find_malware(self, memory_dump: str) -> Dict[str, Any]:
        """Find injected code/malware"""
        return self.run('windows.malfind.Malfind', memory_dump)
    
    def scan_registry(self, memory_dump: str) -> Dict[str, Any]:
        """Scan registry hives"""
        return self.run('windows.registry.hivelist.HiveList', memory_dump)
    
    def dump_process(self, memory_dump: str, pid: int, output_dir: str) -> Dict[str, Any]:
        """Dump process memory"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return self.run('windows.pslist.PsList', memory_dump, dump=True, pid=pid, output=output_dir)


class YARA_Specialist:
    """Specialist for YARA malware signature scanning"""
    
    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path or '/usr/share/yara/rules'
    
    def scan_file(self, target_file: str, rules_file: Optional[str] = None) -> Dict[str, Any]:
        """Scan a file with YARA"""
        cmd = ['yara', '-w', '-r']
        
        if rules_file:
            cmd.append(rules_file)
        else:
            # Use default rules
            cmd.append(self.rules_path)
        
        cmd.append(target_file)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            matches = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 2:
                        matches.append({
                            'rule': parts[0],
                            'file': parts[1]
                        })
            
            return {
                'tool': 'yara',
                'target': target_file,
                'status': 'success',
                'matches': matches,
                'match_count': len(matches),
                'stdout': result.stdout,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'tool': 'yara',
                'target': target_file,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def scan_directory(self, target_dir: str, rules_file: Optional[str] = None) -> Dict[str, Any]:
        """Scan entire directory"""
        cmd = ['yara', '-w', '-r']
        
        if rules_file:
            cmd.append(rules_file)
        else:
            cmd.append(self.rules_path)
        
        cmd.append(target_dir)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            matches = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 2:
                        matches.append({
                            'rule': parts[0],
                            'file': ' '.join(parts[1:])
                        })
            
            return {
                'tool': 'yara',
                'target': target_dir,
                'status': 'success',
                'matches': matches,
                'match_count': len(matches),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'tool': 'yara',
                'target': target_dir,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }


class STRINGS_Specialist:
    """Specialist for string extraction and IOC analysis"""
    
    def extract_strings(self, file_path: str, min_length: int = 4, encoding: str = 'ascii') -> Dict[str, Any]:
        """Extract strings from binary"""
        cmd = ['strings']
        
        if encoding == 'unicode':
            cmd.append('-e l')  # 16-bit little endian
        elif encoding == 'wide':
            cmd.append('-e b')  # 16-bit big endian
        
        cmd.append(f'-n {min_length}')
        cmd.append(file_path)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            strings = result.stdout.strip().split('\n') if result.stdout else []
            
            # Extract potential IOCs
            iocs = {
                'urls': [],
                'ips': [],
                'emails': [],
                'paths': [],
                'registry': []
            }
            
            import re
            for s in strings:
                # URLs
                if re.search(r'https?://[^\s"\']+', s):
                    iocs['urls'].append(s)
                # IPs
                if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s):
                    iocs['ips'].append(s)
                # Emails
                if re.search(r'[\w\.-]+@[\w\.-]+\.\w+', s):
                    iocs['emails'].append(s)
                # Registry
                if 'HKEY_' in s or 'SOFTWARE\\' in s:
                    iocs['registry'].append(s)
                # File paths
                if s.startswith('C:\\') or s.startswith('/'):
                    iocs['paths'].append(s)
            
            return {
                'tool': 'strings',
                'file': file_path,
                'status': 'success',
                'total_strings': len(strings),
                'strings': strings[:100],  # First 100
                'iocs': iocs,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'tool': 'strings',
                'file': file_path,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }


class SpecialistOrchestrator:
    """Orchestrates multiple specialists for complex investigations"""
    
    def __init__(self, evidence_base: str):
        self.evidence_base = Path(evidence_base)
        self.sleuthkit = SLEUTHKIT_Specialist(evidence_base)
        self.volatility = VOLATILITY_Specialist()
        self.yara = YARA_Specialist()
        self.strings = STRINGS_Specialist()
    
    def run_playbook_step(self, playbook_id: str, step: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single playbook step with appropriate specialist"""
        module = step.get('module')
        function = step.get('function')
        params = step.get('params', {})
        
        if module == 'sleuthkit':
            specialist = self.sleuthkit
            func = getattr(specialist, function, None)
            if func:
                return func(**params)
        
        elif module == 'volatility':
            specialist = self.volatility
            func = getattr(specialist, function, None)
            if func:
                return func(**params)
        
        elif module == 'yara':
            specialist = self.yara
            func = getattr(specialist, function, None)
            if func:
                return func(**params)
        
        elif module == 'strings':
            specialist = self.strings
            func = getattr(specialist, function, None)
            if func:
                return func(**params)
        
        return {
            'status': 'error',
            'error': f'Unknown module {module} or function {function}',
            'timestamp': datetime.now().isoformat()
        }
    
    def get_available_tools(self) -> Dict[str, List[str]]:
        """List all available tools and functions"""
        return {
            'sleuthkit': {
                'available': self.sleuthkit.tools_available,
                'functions': ['analyze_partition_table', 'analyze_filesystem', 
                             'list_files', 'extract_file', 'list_inodes', 'get_file_info']
            },
            'volatility': {
                'available': self.volatility.volatility_path is not None,
                'functions': ['process_list', 'network_scan', 'find_malware', 
                             'scan_registry', 'dump_process']
            },
            'yara': {
                'available': True,
                'functions': ['scan_file', 'scan_directory']
            },
            'strings': {
                'available': True,
                'functions': ['extract_strings']
            }
        }


if __name__ == '__main__':
    # Test specialists
    orch = SpecialistOrchestrator('/home/sansforensics/evidence-storage')
    
    print("SIFT Tool Specialists Test")
    print("=" * 50)
    
    tools = orch.get_available_tools()
    for tool, info in tools.items():
        print(f"\n{tool.upper()}:")
        print(f"  Available: {info['available']}")
        print(f"  Functions: {', '.join(info['functions'])}")
