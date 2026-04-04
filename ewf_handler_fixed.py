#!/usr/bin/env python3
"""
Fixed EWF Handler - Robust extraction using libewf2
"""

import ctypes
import os
import logging
from pathlib import Path
from typing import List, Optional, Callable

logger = logging.getLogger(__name__)

# Load libewf library
libewf = None
for path in ['libewf.so.2', '/usr/lib/x86_64-linux-gnu/libewf.so.2', '/usr/lib/libewf.so.2']:
    try:
        libewf = ctypes.CDLL(path)
        break
    except:
        continue

class EWFError(Exception):
    pass

def extract_ewf_image(ewf_files: List[Path], output_dir: Path,
                      progress_callback: Optional[Callable] = None) -> Optional[Path]:
    """Extract EWF files to raw image using libewf2."""
    
    if libewf is None:
        logger.error("libewf not available")
        return None
    
    if not ewf_files:
        logger.error("No EWF files")
        return None
    
    ewf_files = sorted([str(p) for p in ewf_files])
    
    try:
        # Initialize handle
        handle = ctypes.c_void_p()
        result = libewf.libewf_handle_initialize(ctypes.byref(handle), None)
        if result != 1:
            raise EWFError(f"Init failed: {result}")
        
        # Open files
        file_array = (ctypes.c_char_p * len(ewf_files))()
        for i, f in enumerate(ewf_files):
            file_array[i] = f.encode('utf-8')
        
        result = libewf.libewf_handle_open(handle, file_array, len(ewf_files), 1)
        if result != 1:
            libewf.libewf_handle_free(ctypes.byref(handle), None)
            raise EWFError(f"Open failed: {result}")
        
        # Get media size
        media_size = ctypes.c_uint64(0)
        result = libewf.libewf_handle_get_media_size(handle, ctypes.byref(media_size))
        if result != 1:
            libewf.libewf_handle_close(handle, None)
            libewf.libewf_handle_free(ctypes.byref(handle), None)
            raise EWFError(f"Size failed: {result}")
        
        total_size = media_size.value
        logger.info(f"Extracting {total_size/(1024**3):.2f} GB")
        
        # Create output
        base_name = Path(ewf_files[0]).stem
        output_path = Path(output_dir) / f"{base_name}.raw"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Extract
        chunk_size = 1024 * 1024 * 10  # 10MB
        buffer = ctypes.create_string_buffer(chunk_size)
        bytes_written = 0
        
        with open(output_path, 'wb') as out:
            while bytes_written < total_size:
                to_read = min(chunk_size, total_size - bytes_written)
                result = libewf.libewf_handle_read_buffer(handle, buffer, to_read, None)
                
                if result < 0:
                    raise EWFError(f"Read error: {result}")
                if result == 0:
                    break
                
                out.write(buffer[:result])
                bytes_written += result
                
                if bytes_written % (1024**3) == 0:
                    pct = (bytes_written / total_size) * 100
                    logger.info(f"  {bytes_written/(1024**3):.1f} GB ({pct:.1f}%)")
        
        # Cleanup
        libewf.libewf_handle_close(handle, None)
        libewf.libewf_handle_free(ctypes.byref(handle), None)
        
        logger.info(f"Extracted: {output_path}")
        return output_path
        
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        return None

def find_ewf_files(directory: Path) -> List[Path]:
    """Find EWF files in directory."""
    if not directory.exists():
        return []
    files = []
    for pattern in ['*.E01', '*.E02', '*.E03', '*.E04', '*.E05']:
        files.extend(directory.glob(pattern))
    return sorted(files)

if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
    
    evidence_path = Path('/mnt/evidence-storage/cases/tuck/evidence')
    output_dir = Path('/mnt/evidence-storage/sift_extract_Tuck-Office-Investigation')
    
    files = find_ewf_files(evidence_path)
    print(f"Found {len(files)} EWF files")
    
    if files:
        result = extract_ewf_image(files, output_dir)
        if result:
            print(f"✓ SUCCESS: {result}")
        else:
            print("✗ FAILED")
    else:
        print("No files found")
