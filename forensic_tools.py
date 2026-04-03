#!/usr/bin/env python3
"""
Real Forensic Tools Integration
Calls actual SleuthKit, TestDisk, and other forensic tools
"""

import subprocess
import json
import hashlib
from datetime import datetime
from pathlib import Path

def run_sleuthkit(cmd, args):
    """Run SleuthKit command and return output"""
    try:
        result = subprocess.run(
            [cmd] + args,
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
    except Exception as e:
        return f"Error: {e}"

def mmls(disk_image):
    """Display partition layout"""
    print(f"  [mmls] Analyzing partition table: {disk_image}")
    output = run_sleuthkit('mmls', [disk_image])
    return {
        'tool': 'mmls',
        'disk': disk_image,
        'output': output,
        'timestamp': datetime.now().isoformat()
    }

def fsstat(partition):
    """Display file system statistics"""
    print(f"  [fsstat] Analyzing file system: {partition}")
    output = run_sleuthkit('fsstat', [partition])
    return {
        'tool': 'fsstat',
        'partition': partition,
        'output': output,
        'timestamp': datetime.now().isoformat()
    }

def fls(partition, inode=None):
    """List files and directories"""
    print(f"  [fls] Listing files: {partition}")
    args = ['-r', '-m', '/'] if inode is None else ['-r', '-m', '/', str(inode)]
    args.append(partition)
    output = run_sleuthkit('fls', args)
    
    # Parse output
    files = []
    for line in output.strip().split('\n'):
        if line and not line.startswith('Error'):
            parts = line.split('|')
            if len(parts) >= 2:
                files.append({
                    'type': parts[0][0] if parts[0] else '?',
                    'inode': parts[1] if len(parts) > 1 else '0',
                    'name': parts[-1] if len(parts) > 2 else 'unknown'
                })
    
    return {
        'tool': 'fls',
        'partition': partition,
        'files': files,
        'raw_output': output,
        'count': len(files),
        'timestamp': datetime.now().isoformat()
    }

def icat(partition, inode, output_file):
    """Extract file by inode"""
    print(f"  [icat] Extracting inode {inode} to {output_file}")
    output = run_sleuthkit('icat', [partition, str(inode)])
    
    with open(output_file, 'wb') as f:
        f.write(output.encode() if isinstance(output, str) else output)
    
    return {
        'tool': 'icat',
        'partition': partition,
        'inode': inode,
        'output_file': output_file,
        'size': len(output),
        'timestamp': datetime.now().isoformat()
    }

def calculate_hash(file_path, algorithm='sha256'):
    """Calculate file hash"""
    print(f"  [hash] Calculating {algorithm}: {file_path}")
    
    if algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha1':
        hasher = hashlib.sha1()
    else:
        hasher = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        
        return {
            'file': file_path,
            'algorithm': algorithm,
            'hash': hasher.hexdigest(),
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'file': file_path,
            'algorithm': algorithm,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def timeline(partition, output_file=None):
    """Generate MAC timeline from file system"""
    print(f"  [timeline] Generating MAC timeline: {partition}")
    output = run_sleuthkit('fls', ['-m', '-r', partition])
    
    timeline_data = []
    for line in output.strip().split('\n'):
        if line and not line.startswith('Error'):
            parts = line.split('|')
            if len(parts) >= 4:
                timeline_data.append({
                    'date': parts[0] if parts[0] else 'unknown',
                    'time': parts[1] if len(parts) > 1 else '',
                    'size': parts[2] if len(parts) > 2 else '0',
                    'type': parts[3] if len(parts) > 3 else 'unknown',
                    'name': parts[-1] if len(parts) > 4 else 'unknown'
                })
    
    return {
        'tool': 'fls-timeline',
        'partition': partition,
        'entries': len(timeline_data),
        'timeline': timeline_data[:100],  # First 100 entries
        'timestamp': datetime.now().isoformat()
    }

def photorec(disk_image, output_dir):
    """Carve deleted files using PhotoRec"""
    print(f"  [photorec] Carving files from: {disk_image}")
    print(f"  [photorec] Output: {output_dir}")
    
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # PhotoRec command (non-interactive mode)
    cmd = [
        'photorec',
        '/d', output_dir,
        '/cmd', disk_image,
        'search', 'options', 'paranoid', 'enable',
        'fileopt', 'enable', 'everything'
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        # Count recovered files
        recovered = list(Path(output_dir).rglob('*'))
        files = [f for f in recovered if f.is_file()]
        
        return {
            'tool': 'photorec',
            'disk': disk_image,
            'output_dir': output_dir,
            'files_recovered': len(files),
            'files': [str(f.relative_to(output_dir)) for f in files[:10]],
            'returncode': result.returncode,
            'timestamp': datetime.now().isoformat()
        }
    except subprocess.TimeoutExpired:
        return {
            'tool': 'photorec',
            'disk': disk_image,
            'error': 'Timeout after 5 minutes',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'tool': 'photorec',
            'disk': disk_image,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def analyze_disk_image(disk_image, output_dir):
    """Full analysis workflow"""
    print(f"[ANALYSIS] Starting full analysis of: {disk_image}")
    
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    results = {
        'disk_image': disk_image,
        'started': datetime.now().isoformat(),
        'steps': []
    }
    
    # Step 1: Partition table
    results['steps'].append(mmls(disk_image))
    
    # Step 2: Calculate hash
    results['steps'].append(calculate_hash(disk_image))
    
    # Step 3: Try to analyze first partition (if DOS/MBR)
    # Note: In real use, would parse mmls output to find valid partitions
    
    return results

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: forensic_tools.py <disk_image> [output_dir]")
        print("Available commands: mmls, fls, fsstat, hash, photorec")
        sys.exit(1)
    
    disk = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else './forensic_output'
    
    # Run analysis
    results = analyze_disk_image(disk, out_dir)
    
    # Save results
    report_file = Path(out_dir) / 'analysis_report.json'
    with open(report_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[COMPLETE] Analysis saved to: {report_file}")
    print(f"[SUMMARY] Steps completed: {len(results['steps'])}")
