#!/usr/bin/env python3
"""
MMIO Vulnerability Scanner
Detects vulnerable MmMapIoSpace patterns lacking input validation in Windows kernel drivers.

Usage:
    python mmio_scanner.py <path> [-e extensions] [-o output] [-j json] [-v]
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from datetime import datetime


class MMIOScanner:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings = []
        
        self.mmio_calls = [
            'MmMapIoSpace',
            'MmMapIoSpaceEx', 
            'MmMapLockedPages',
            'MmMapViewInSystemSpace',
        ]
        
        self.validation_funcs = [
            r'CheckPhysicalAddress',
            r'ValidatePhysicalAddress',
            r'ValidateIoSpace',
            r'ResourceCheck',
            r'CheckDeviceRange',
            r'VerifyAddress',
            r'CheckRange',
            r'RtlCompareMemory',
            r'MmQueryPhysicalAddress',
            r'CheckValidAddress',
            r'ValidateAddress',
        ]
        
        self.user_mode_sources = [
            r'irp->IoStatus',
            r'irpSp->Parameters',
            r'IoStackLocation->Parameters',
            r'Request->Parameters',
            r'UserBuffer',
            r'UserPtr',
            r'InputBuffer',
            r'OutputBuffer',
            r'Irp->AssociatedIrp',
            r'IoAllocateMdl',
        ]
        
    def is_kernel_constant(self, expr: str) -> bool:
        num_patterns = [
            r'^0x[0-9A-Fa-f]+$',
            r'^[0-9]+$',
        ]
        for p in num_patterns:
            if re.match(p, expr.strip()):
                return True
        return False

    def trace_variable(self, lines: List[str], var_name: str, start_idx: int) -> Optional[str]:
        search_end = max(0, start_idx - 50)
        
        for i in range(start_idx - 1, search_end, -1):
            line = lines[i]
            assign_match = re.search(rf'(\w+)\s*=\s*([^;]+)', line)
            if assign_match and assign_match.group(1) == var_name:
                rhs = assign_match.group(2).strip()
                if any(src in rhs for src in self.user_mode_sources):
                    return 'userControlled'
                if self.is_kernel_constant(rhs):
                    return 'constant'
                return 'unknown'
                
            if re.search(rf'\b{var_name}\b.*=', line):
                break
                
        return None

    def has_validation_block(self, lines: List[str], call_idx: int) -> Tuple[bool, str]:
        search_start = max(0, call_idx - 30)
        search_region = ''.join(lines[search_start:call_idx])
        
        for vfunc in self.validation_funcs:
            if re.search(vfunc, search_region, re.IGNORECASE):
                return True, f"Found validation: {vfunc}"
        
        for pattern in [
            r'if\s*\([^)]*(?:Address|Addr|Param)[^)]*(?:<=|>=|<|>)',
            r'if\s*\([^)]*<=.*\b(phys|Phys)',
            r'if\s*\([^)]*(?:#define|MAX_|MIN_)',
            r'if\s*\([^)]*(?:\bvalidates?\b)',
            r'if\s*\([^)]*param_\w+[^)]*(?:>|<|>=|<=)',
            r'if\s*\(\s*\w+\s*(?:>|<|>=|<=)\s*(?:0x[0-9A-Fa-f]+|[0-9]+)',
            r'if\s*\(\s*\(.*\)\s*\w+\s*(?:>|<|>=|<=)',
        ]:
            if re.search(pattern, search_region):
                return True, "Found range check"
        
        return False, ""

    def extract_mmio_args(self, line: str) -> List[str]:
        match = re.search(r'MmMapIoSpace\s*\(([^)]+)\)', line)
        if not match:
            return []
        
        args_str = match.group(1)
        args = [a.strip() for a in args_str.split(',')]
        return args

    def analyze_call(self, lines: List[str], call_idx: int, line_content: str) -> Optional[Tuple[int, str, str]]:
        args = self.extract_mmio_args(line_content)
        if not args:
            return None
            
        addr_arg = args[0]
        
        has_val, val_reason = self.has_validation_block(lines, call_idx)
        
        if has_val:
            return None
        
        if re.match(r'^param_\d+$', addr_arg) or re.match(r'^[a-z]\w+$', addr_arg):
            return (call_idx + 1, "VULN", 
                   f"Vulnerable: function parameter '{addr_arg}' passed to MmMapIoSpace without validation")
        
        trace = self.trace_variable(lines, addr_arg, call_idx)
        if trace == 'userControlled':
            return (call_idx + 1, "VULN",
                   f"Vulnerable: user-controlled address '{addr_arg}' passed to MmMapIoSpace - {val_reason}")
        elif trace == 'constant':
            return None
        elif trace == 'unknown':
            return (call_idx + 1, "LIKELY_VULN",
                   f"Possibly vulnerable: address '{addr_arg}' origin unknown - {val_reason}")
        else:
            return (call_idx + 1, "CHECK",
                   f"Manual review needed: {addr_arg} - {val_reason}")

    def scan_file(self, filepath: Path) -> List[Tuple[int, str, str]]:
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return []
        
        for i, line in enumerate(lines):
            for mmio in self.mmio_calls:
                if mmio in line:
                    result = self.analyze_call(lines, i, line)
                    if result:
                        findings.append(result)
                    break
                    
        return findings

    def scan_directory(self, directory: str, extensions: List[str]) -> Dict[str, List]:
        results = {}
        dir_path = Path(directory)
        
        if not dir_path.exists():
            print(f"[ERROR] Directory not found: {directory}")
            return results
            
        for ext in extensions:
            for filepath in dir_path.rglob(f'*{ext}'):
                findings = self.scan_file(filepath)
                if findings:
                    results[str(filepath)] = findings
                    
        return results


def print_results(results: dict, verbose: bool = False):
    if not results:
        print("[OK] No vulnerable patterns detected.")
        return
        
    print("=== MMIO Vulnerability Scan Results ===\n")
    
    severity_counts = {'VULN': 0, 'LIKELY_VULN': 0, 'CHECK': 0}
    
    for filepath, findings in results.items():
        print(f"[FILE] {filepath}")
        for line_num, severity, message in findings:
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            print(f"  [{severity}] {message}")
        print()

    print(f"Summary: {severity_counts['VULN']} VULN | {severity_counts['LIKELY_VULN']} LIKELY_VULN | {severity_counts['CHECK']} CHECK")


def main():
    parser = argparse.ArgumentParser(
        description='MMIO Vulnerability Scanner - Detect vulnerable MmMapIoSpace patterns',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python mmio_scanner.py driver.c
  python mmio_scanner.py /path/to/drivers/ -e .c .h
  python mmio_scanner.py /path/to/drivers/ -j results.json -v
        """
    )
    parser.add_argument('path', help='File or directory to scan')
    parser.add_argument('-e', '--extensions', nargs='+',
                       default=['.c', '.cpp', '.h', '.hpp'],
                       help='File extensions to scan')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('-o', '--output',
                       help='Output file for results')
    parser.add_argument('-j', '--json',
                       help='JSON output file')

    args = parser.parse_args()

    scanner = MMIOScanner(verbose=args.verbose)
    path = Path(args.path)

    if path.is_file():
        results = {str(path): scanner.scan_file(path)}
    elif path.is_dir():
        results = scanner.scan_directory(str(path), args.extensions)
    else:
        print(f"[ERROR] Invalid path: {args.path}")
        sys.exit(1)

    print_results(results, args.verbose)

    if args.json:
        output_data = {
            'scan_date': datetime.now().isoformat(),
            'path': str(path),
            'results': {
                f: [{'line': l, 'severity': s, 'message': m} for l, s, m in findings]
                for f, findings in results.items()
            }
        }
        with open(args.json, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"[+] Results saved to {args.json}")

    if args.output:
        with open(args.output, 'w') as f:
            for filepath, findings in results.items():
                f.write(f"[FILE] {filepath}\n")
                for line_num, severity, message in findings:
                    f.write(f"  [{severity}] {message}\n")
        print(f"[+] Results saved to {args.output}")

    total_vuln = sum(1 for f in results.values() for _, s, _ in f if s == 'VULN')
    sys.exit(1 if total_vuln > 0 else 0)


if __name__ == '__main__':
    main()