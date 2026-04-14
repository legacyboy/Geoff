#!/usr/bin/env python3
"""
REMnux Tool Specialists
Wrappers for REMnux malware analysis tools
Installed on top of SIFT workstation for advanced static/dynamic analysis
"""

import json
import subprocess
import re
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


def _run_tool(tool: str, args: List[str], timeout: int = 300) -> Dict[str, Any]:
    """Execute a tool command with error handling"""
    try:
        result = subprocess.run(
            [tool] + args,
            capture_output=True,
            text=True,
            timeout=timeout
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
            'error': f'Command timed out after {timeout}s',
            'timestamp': datetime.now().isoformat()
        }
    except FileNotFoundError:
        return {
            'tool': tool,
            'status': 'error',
            'error': f'{tool} not found in PATH (install REMnux)',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'tool': tool,
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


def _check_tool_available(tool_name: str) -> bool:
    """Check if a tool is available on PATH"""
    result = subprocess.run(['which', tool_name], capture_output=True)
    return result.returncode == 0


class BINARY_IDENT_Specialist:
    """Static analysis: file identification, metadata, PE structure"""

    def die_scan(self, target_file: str) -> Dict[str, Any]:
        """Detect packers, compilers, and signatures with die (Detect It Easy)"""
        result = _run_tool('die', [target_file])
        if result['status'] != 'success':
            return result

        # Parse DIE output into structured findings
        packers = []
        compilers = []
        signatures = []

        for line in result['stdout'].splitlines():
            line = line.strip()
            if not line:
                continue
            lower = line.lower()
            if 'packer' in lower or 'packed' in lower:
                packers.append(line)
            elif 'compiler' in lower or 'linker' in lower:
                compilers.append(line)
            else:
                signatures.append(line)

        return {
            'tool': 'die',
            'target': target_file,
            'status': 'success',
            'packers_detected': packers,
            'compilers_detected': compilers,
            'signatures': signatures,
            'is_packed': len(packers) > 0,
            'raw_output': result['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def exiftool_scan(self, target_file: str) -> Dict[str, Any]:
        """Extract metadata with exiftool"""
        result = _run_tool('exiftool', [target_file])
        if result['status'] != 'success':
            return result

        # Parse key-value pairs
        metadata = {}
        for line in result['stdout'].splitlines():
            if ':' in line:
                key, _, value = line.partition(':')
                metadata[key.strip()] = value.strip()

        # Flag suspicious metadata
        suspicious = []
        suspicious_authors = ['admin', 'system', 'test', 'malware', 'user']
        suspicious_timestamps = []

        author = metadata.get('Author', '')
        if author.lower() in suspicious_authors:
            suspicious.append(f'Suspicious author: {author}')

        create_date = metadata.get('Create-Date', metadata.get('File Access Date/Time', ''))
        mod_date = metadata.get('Modify-Date', metadata.get('File Modification Date/Time', ''))
        if create_date and mod_date and create_date == mod_date:
            suspicious.append('Create and modify dates match (possible timestomping)')

        return {
            'tool': 'exiftool',
            'target': target_file,
            'status': 'success',
            'metadata': metadata,
            'suspicious_indicators': suspicious,
            'raw_output': result['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def peframe_scan(self, target_file: str) -> Dict[str, Any]:
        """PE structure analysis with peframe"""
        result = _run_tool('peframe', [target_file], timeout=120)
        if result['status'] != 'success':
            return result

        # Parse peframe output for key sections
        suspicious_apis = []
        sections = []
        imports = []

        for line in result['stdout'].splitlines():
            line_stripped = line.strip()
            lower = line_stripped.lower()
            # Detect suspicious API calls
            for api in ['CreateRemoteThread', 'VirtualAlloc', 'WriteProcessMemory',
                        'NtCreateThreadEx', 'QueueUserAPC', 'SetWindowsHookEx',
                        'RegSetValueEx', 'CreateService', 'WinExec', 'ShellExecute']:
                if api.lower() in lower:
                    suspicious_apis.append(api)
            # Detect section names
            if line_stripped.startswith('.'):
                sections.append(line_stripped)

        return {
            'tool': 'peframe',
            'target': target_file,
            'status': 'success',
            'suspicious_apis': list(set(suspicious_apis)),
            'sections': sections,
            'raw_output': result['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def ssdeep_hash(self, target_file: str) -> Dict[str, Any]:
        """Generate fuzzy hash with ssdeep"""
        result = _run_tool('ssdeep', ['-b', target_file])
        if result['status'] != 'success':
            return result

        # Parse ssdeep output: hash,filename
        fuzzy_hash = ''
        for line in result['stdout'].splitlines():
            if target_file in line or (line.strip() and not line.startswith(',')):
                parts = line.strip().split(',')
                if len(parts) >= 1:
                    fuzzy_hash = parts[0].strip()
                break

        return {
            'tool': 'ssdeep',
            'target': target_file,
            'status': 'success',
            'fuzzy_hash': fuzzy_hash,
            'raw_output': result['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def hashdeep_audit(self, target_dir: str) -> Dict[str, Any]:
        """Generate multi-hash audit with hashdeep"""
        result = _run_tool('hashdeep', ['-r', '-l', '-c', 'md5,sha256,sha1', target_dir], timeout=600)
        if result['status'] != 'success':
            return result

        # Parse hashdeep output
        file_hashes = []
        for line in result['stdout'].splitlines():
            if line.startswith('#') or line.startswith('%') or not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) >= 3:
                file_hashes.append({
                    'md5': parts[0] if len(parts) > 0 else '',
                    'sha256': parts[1] if len(parts) > 1 else '',
                    'sha1': parts[2] if len(parts) > 2 else '',
                    'size': parts[3] if len(parts) > 3 else '',
                    'path': parts[4] if len(parts) > 4 else ''
                })

        return {
            'tool': 'hashdeep',
            'target_dir': target_dir,
            'status': 'success',
            'files_hashed': len(file_hashes),
            'file_hashes': file_hashes,
            'raw_output': result['stdout'][:10000],
            'timestamp': datetime.now().isoformat()
        }


class UNPACKING_Specialist:
    """Unpacking and deobfuscation tools"""

    def upx_unpack(self, target_file: str, output_file: str = None) -> Dict[str, Any]:
        """Unpack UPX-compressed executable"""
        out = output_file or target_file + '.unpacked'
        result = _run_tool('upx', ['-d', '-o', out, target_file])
        if result['status'] != 'success':
            return result

        return {
            'tool': 'upx',
            'target': target_file,
            'status': 'success',
            'unpacked_file': out,
            'raw_output': result['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def pdfid_scan(self, pdf_file: str) -> Dict[str, Any]:
        """Identify PDF suspicious elements with pdfid"""
        result = _run_tool('pdfid', [pdf_file])
        if result['status'] != 'success':
            return result

        # Parse pdfid output for suspicious indicators
        suspicious = []
        for line in result['stdout'].splitlines():
            lower = line.lower()
            if '/javascript' in lower:
                suspicious.append('JavaScript in PDF')
            if '/js' in lower:
                suspicious.append('JS action in PDF')
            if '/launch' in lower:
                suspicious.append('Launch action in PDF')
            if '/openaction' in lower:
                suspicious.append('OpenAction in PDF')
            if '/embeddedfile' in lower:
                suspicious.append('Embedded file in PDF')

        return {
            'tool': 'pdfid',
            'target': pdf_file,
            'status': 'success',
            'suspicious_indicators': suspicious,
            'raw_output': result['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def pdf_parser(self, pdf_file: str) -> Dict[str, Any]:
        """Extract streams and objects from PDF with pdf-parser"""
        result = _run_tool('pdf-parser', [pdf_file], timeout=120)
        if result['status'] != 'success':
            return result

        # Count objects and streams
        objects = []
        streams = []
        for line in result['stdout'].splitlines():
            if line.startswith('obj'):
                objects.append(line.strip())
            if 'stream' in line.lower():
                streams.append(line.strip())

        return {
            'tool': 'pdf-parser',
            'target': pdf_file,
            'status': 'success',
            'object_count': len(objects),
            'stream_count': len(streams),
            'raw_output': result['stdout'][:10000],
            'timestamp': datetime.now().isoformat()
        }

    def oledump_scan(self, office_file: str) -> Dict[str, Any]:
        """Extract macros and embedded content from Office docs with oledump"""
        result = _run_tool('oledump.py', [office_file], timeout=120)
        if result['status'] != 'success':
            # Try without .py extension
            result = _run_tool('oledump', [office_file], timeout=120)
            if result['status'] != 'success':
                return result

        # Parse oledump output for macro indicators
        macros_found = []
        streams = []
        for line in result['stdout'].splitlines():
            if line.strip():
                streams.append(line.strip())
                if 'M' in line and '|' in line:
                    macros_found.append(line.strip())
                if 'm' in line.split('|')[0] if '|' in line else '':
                    macros_found.append(line.strip())

        return {
            'tool': 'oledump',
            'target': office_file,
            'status': 'success',
            'streams': streams,
            'macros_found': macros_found,
            'has_macros': len(macros_found) > 0,
            'raw_output': result['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def js_beautify(self, js_file: str, output_file: str = None) -> Dict[str, Any]:
        """Deobfuscate JavaScript with js-beautify"""
        out = output_file or js_file + '.beautified.js'
        result = _run_tool('js-beautify', ['-o', out, js_file])
        if result['status'] != 'success':
            return result

        return {
            'tool': 'js-beautify',
            'target': js_file,
            'status': 'success',
            'output_file': out,
            'timestamp': datetime.now().isoformat()
        }


class DISASSEMBLY_Specialist:
    """Disassembly and debugging tools"""

    def radare2_analyze(self, target_file: str) -> Dict[str, Any]:
        """Analyze binary with radare2 (static analysis only)"""
        # Run radare2 in batch mode: auto-analyze, list imports, list strings
        cmd_args = ['-q', '-e', 'scr.color=0', '-c', 'aaa; ii; izz', target_file]
        result = _run_tool('radare2', cmd_args, timeout=300)
        if result['status'] != 'success':
            return result

        # Parse imports
        imports = []
        strings = []
        in_imports = False
        in_strings = False

        for line in result['stdout'].splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue
            # Imports section
            if '[Imports]' in line or 'ordinal' in line.lower():
                in_imports = True
                in_strings = False
                continue
            # Strings section
            if '[Strings]' in line or 'izz' in line.lower():
                in_strings = True
                in_imports = False
                continue

            # Look for suspicious API imports
            suspicious_apis = [
                'CreateRemoteThread', 'VirtualAlloc', 'VirtualAllocEx',
                'WriteProcessMemory', 'NtCreateThreadEx', 'QueueUserAPC',
                'SetWindowsHookEx', 'RegSetValueEx', 'CreateService',
                'WinExec', 'ShellExecute', 'URLDownloadToFile',
                'InternetOpen', 'HttpOpenRequest', 'Socket', 'connect'
            ]

            if in_imports:
                for api in suspicious_apis:
                    if api.lower() in line_stripped.lower():
                        imports.append(line_stripped)
                        break

            if in_strings:
                # Extract interesting strings (URLs, IPs, paths)
                if re.search(r'https?://', line_stripped):
                    strings.append(line_stripped)
                elif re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line_stripped):
                    strings.append(line_stripped)
                elif re.search(r'[A-Z]:\\\\', line_stripped):
                    strings.append(line_stripped)

        return {
            'tool': 'radare2',
            'target': target_file,
            'status': 'success',
            'suspicious_imports': imports,
            'interesting_strings': strings,
            'raw_output': result['stdout'][:10000],
            'timestamp': datetime.now().isoformat()
        }

    def floss_strings(self, target_file: str) -> Dict[str, Any]:
        """Extract obfuscated strings with FLARE FLOSS"""
        result = _run_tool('floss', [target_file], timeout=300)
        if result['status'] != 'success':
            return result

        # Parse FLOSS output sections
        decoded_strings = []
        stack_strings = []
        tight_strings = []

        current_section = None
        for line in result['stdout'].splitlines():
            lower = line.lower().strip()
            if 'decoded strings' in lower:
                current_section = 'decoded'
                continue
            elif 'stack strings' in lower:
                current_section = 'stack'
                continue
            elif 'tight strings' in lower:
                current_section = 'tight'
                continue
            elif line.strip() and not line.startswith('=') and not line.startswith('-'):
                if current_section == 'decoded':
                    decoded_strings.append(line.strip())
                elif current_section == 'stack':
                    stack_strings.append(line.strip())
                elif current_section == 'tight':
                    tight_strings.append(line.strip())

        return {
            'tool': 'floss',
            'target': target_file,
            'status': 'success',
            'decoded_strings': decoded_strings[:200],
            'stack_strings': stack_strings[:200],
            'tight_strings': tight_strings[:200],
            'raw_output': result['stdout'][:10000],
            'timestamp': datetime.now().isoformat()
        }


class ANTIVIRUS_Specialist:
    """Signature-based detection tools"""

    def clamav_scan(self, target_path: str) -> Dict[str, Any]:
        """Scan with ClamAV signatures"""
        result = _run_tool('clamscan', ['-r', '--no-summary', target_path], timeout=600)
        if result['status'] != 'success':
            return result

        # Parse ClamAV output
        detections = []
        for line in result['stdout'].splitlines():
            if 'FOUND' in line:
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    detections.append({
                        'file': parts[0].strip(),
                        'signature': parts[1].strip().replace('FOUND', '').strip()
                    })

        return {
            'tool': 'clamav',
            'target': target_path,
            'status': 'success',
            'detections': detections,
            'detection_count': len(detections),
            'raw_output': result['stdout'][:10000],
            'timestamp': datetime.now().isoformat()
        }


class NETWORK_SIM_Specialist:
    """Network simulation tools for dynamic analysis"""

    def inetsim_check(self) -> Dict[str, Any]:
        """Check if INetSim is available and configured"""
        available = _check_tool_available('inetsim')
        if not available:
            return {
                'tool': 'inetsim',
                'status': 'unavailable',
                'error': 'INetSim not found (install REMnux)',
                'timestamp': datetime.now().isoformat()
            }

        result = _run_tool('inetsim', ['--help'], timeout=10)
        return {
            'tool': 'inetsim',
            'status': 'available',
            'raw_output': result.get('stdout', '')[:500],
            'timestamp': datetime.now().isoformat()
        }

    def fakedns_check(self) -> Dict[str, Any]:
        """Check if fakedns is available"""
        available = _check_tool_available('fakedns')
        if not available:
            # Try alternate name
            available = _check_tool_available('fakedns-dns')
        return {
            'tool': 'fakedns',
            'status': 'available' if available else 'unavailable',
            'error': None if available else 'fakedns not found (install REMnux)',
            'timestamp': datetime.now().isoformat()
        }


class REMNUX_Orchestrator:
    """Orchestrator for all REMnux specialists"""

    def __init__(self):
        self.binary_ident = BINARY_IDENT_Specialist()
        self.unpacking = UNPACKING_Specialist()
        self.disassembly = DISASSEMBLY_Specialist()
        self.antivirus = ANTIVIRUS_Specialist()
        self.network_sim = NETWORK_SIM_Specialist()

        self.specialist_map = {
            'remnux_die': self.binary_ident,
            'die_scan': self.binary_ident,
            'remnux_exiftool': self.binary_ident,
            'exiftool_scan': self.binary_ident,
            'remnux_peframe': self.binary_ident,
            'peframe_scan': self.binary_ident,
            'remnux_ssdeep': self.binary_ident,
            'ssdeep_hash': self.binary_ident,
            'remnux_hashdeep': self.binary_ident,
            'hashdeep_audit': self.binary_ident,
            'remnux_upx': self.unpacking,
            'upx_unpack': self.unpacking,
            'remnux_pdfid': self.unpacking,
            'pdfid_scan': self.unpacking,
            'remnux_pdf_parser': self.unpacking,
            'pdf_parser': self.unpacking,
            'remnux_oledump': self.unpacking,
            'oledump_scan': self.unpacking,
            'remnux_js_beautify': self.unpacking,
            'js_beautify': self.unpacking,
            'remnux_radare2': self.disassembly,
            'radare2_analyze': self.disassembly,
            'remnux_floss': self.disassembly,
            'floss_strings': self.disassembly,
            'remnux_clamav': self.antivirus,
            'clamav_scan': self.antivirus,
            'remnux_inetsim': self.network_sim,
            'inetsim_check': self.network_sim,
            'remnux_fakedns': self.network_sim,
            'fakedns_check': self.network_sim,
        }

        self.function_map = {
            'remnux_die': 'die_scan',
            'die_scan': 'die_scan',
            'remnux_exiftool': 'exiftool_scan',
            'exiftool_scan': 'exiftool_scan',
            'remnux_peframe': 'peframe_scan',
            'peframe_scan': 'peframe_scan',
            'remnux_ssdeep': 'ssdeep_hash',
            'ssdeep_hash': 'ssdeep_hash',
            'remnux_hashdeep': 'hashdeep_audit',
            'hashdeep_audit': 'hashdeep_audit',
            'remnux_upx': 'upx_unpack',
            'upx_unpack': 'upx_unpack',
            'remnux_pdfid': 'pdfid_scan',
            'pdfid_scan': 'pdfid_scan',
            'remnux_pdf_parser': 'pdf_parser',
            'pdf_parser': 'pdf_parser',
            'remnux_oledump': 'oledump_scan',
            'oledump_scan': 'oledump_scan',
            'remnux_js_beautify': 'js_beautify',
            'js_beautify': 'js_beautify',
            'remnux_radare2': 'radare2_analyze',
            'radare2_analyze': 'radare2_analyze',
            'remnux_floss': 'floss_strings',
            'floss_strings': 'floss_strings',
            'remnux_clamav': 'clamav_scan',
            'clamav_scan': 'clamav_scan',
            'remnux_inetsim': 'inetsim_check',
            'inetsim_check': 'inetsim_check',
            'remnux_fakedns': 'fakedns_check',
            'fakedns_check': 'fakedns_check',
        }

    def run_playbook_step(self, investigation_id: str, step: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a REMnux playbook step"""
        function = step.get('function', '')
        params = step.get('params', {})

        if function in self.function_map:
            specialist = self.specialist_map[function]
            method_name = self.function_map[function]
            method = getattr(specialist, method_name, None)
            if method:
                return method(**params)

        return {
            'status': 'error',
            'error': f'Unknown REMnux function: {function}',
            'timestamp': datetime.now().isoformat()
        }

    def get_available_tools(self) -> Dict[str, Any]:
        """List all REMnux tools and their availability"""
        tools = {
            'die': _check_tool_available('die'),
            'exiftool': _check_tool_available('exiftool'),
            'peframe': _check_tool_available('peframe'),
            'ssdeep': _check_tool_available('ssdeep'),
            'hashdeep': _check_tool_available('hashdeep'),
            'upx': _check_tool_available('upx'),
            'pdfid': _check_tool_available('pdfid'),
            'pdf-parser': _check_tool_available('pdf-parser'),
            'oledump': _check_tool_available('oledump') or _check_tool_available('oledump.py'),
            'js-beautify': _check_tool_available('js-beautify'),
            'radare2': _check_tool_available('radare2'),
            'floss': _check_tool_available('floss'),
            'clamscan': _check_tool_available('clamscan'),
            'inetsim': _check_tool_available('inetsim'),
            'fakedns': _check_tool_available('fakedns') or _check_tool_available('fakedns-dns'),
        }

        return {
            'remnux': {
                'category': 'REMnux Malware Analysis',
                'tools_available': tools,
                'functions': list(self.function_map.keys()),
                'available_count': sum(1 for v in tools.values() if v),
                'total_count': len(tools)
            }
        }


if __name__ == '__main__':
    orch = REMNUX_Orchestrator()
    print("REMnux Tool Specialists")
    print("=" * 50)
    tools = orch.get_available_tools()
    info = tools['remnux']
    print(f"Available: {info['available_count']}/{info['total_count']} tools")
    for tool, available in info['tools_available'].items():
        status = '✅' if available else '❌'
        print(f"  {status} {tool}")