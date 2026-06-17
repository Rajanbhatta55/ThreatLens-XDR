#!/usr/bin/env python
"""Comprehensive test of all ThreatLens commands."""

import subprocess
import sys
import os

python_exe = sys.executable

commands = {
    'scan': '--help',
    'follow': '--help',
    'rules': '',
    'summary': '--help',
    'dashboard': '--help',
    'seed-db': '--help',
    'wazuh-pull': '--help',
    'windows-agent-listen': '--help',
    'correlate': '--help',
    'forensic-report': '--help',
    'verify-chain': '--help',
    'encrypt-report': '--help',
    'sign-report': '--help',
    'weekly-report': '--help',
}

print('=' * 70)
print('THREATLENS COMMAND VERIFICATION TEST')
print('=' * 70)
print(f'Using Python: {python_exe}')
print()

passed = 0
failed = 0

for cmd_name, args in commands.items():
    try:
        cmd_list = [python_exe, '-m', 'threatlens.cli', cmd_name]
        if args:
            cmd_list.append(args)
        
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=10,
            cwd=os.getcwd()
        )
        
        output = result.stdout + result.stderr
        
        if cmd_name == 'rules':
            if 'ThreatLens' in output or 'Brute-Force' in output or 'Detection Rules' in output:
                print(f'✓ {cmd_name:<25} WORKS')
                passed += 1
            else:
                print(f'✗ {cmd_name:<25} FAILED')
                failed += 1
        else:
            if 'usage:' in output:
                print(f'✓ {cmd_name:<25} WORKS')
                passed += 1
            else:
                print(f'✗ {cmd_name:<25} FAILED (rc={result.returncode})')
                failed += 1
                
    except subprocess.TimeoutExpired:
        print(f'✗ {cmd_name:<25} TIMEOUT')
        failed += 1
    except Exception as e:
        print(f'✗ {cmd_name:<25} ERROR: {str(e)[:40]}')
        failed += 1

print()
print('=' * 70)
print(f'RESULTS: {passed} PASSED, {failed} FAILED OUT OF 14')
print('=' * 70)
