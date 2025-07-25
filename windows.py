#!/usr/bin/env python3
"""
Windows Privilege Escalation Detection Script
Educational tool for authorized security testing only
Based on techniques from the cybersecurity research document
"""

import os
import sys
import subprocess
import winreg
import ctypes
import getpass
import re
from pathlib import Path

class WindowsPrivEscDetector:
    def __init__(self):
        self.vulnerabilities = []
        self.current_user = getpass.getuser()
        self.is_admin = self.check_admin_privileges()
        
    def check_admin_privileges(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                   Windows Privilege Escalation Detector                     ║
║                         Educational Purpose Only                             ║
║                    Use only on authorized systems                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
        print(f"[*] Running as: {self.current_user}")
        print(f"[*] Administrator privileges: {'Yes' if self.is_admin else 'No'}")
        print("=" * 80)

    def run_command(self, command, suppress_errors=True):
        """Execute system command and return output"""
        try:
            # Use subprocess with explicit encoding handling
            result = subprocess.run(command, shell=True, capture_output=True, text=False)
            if result.returncode == 0:
                # Try to decode with utf-8 first, fallback to cp1252 with error handling
                try:
                    return result.stdout.decode('utf-8').strip()
                except UnicodeDecodeError:
                    return result.stdout.decode('cp1252', errors='replace').strip()
            return ""
        except Exception as e:
            if not suppress_errors:
                print(f"[!] Error executing command '{command}': {e}")
            return ""

    def check_token_privileges(self):
        """Check for dangerous token privileges"""
        print("\n[+] Analyzing Token Privileges...")
        
        # Get current process privileges
        whoami_priv = self.run_command("whoami /priv")
        if whoami_priv:
            print("[*] Current process privileges:")
            print(whoami_priv)
            
            # Check for dangerous privileges
            dangerous_privileges = [
                'SeImpersonatePrivilege',
                'SeAssignPrimaryTokenPrivilege',
                'SeDebugPrivilege',
                'SeTakeOwnershipPrivilege',
                'SeRestorePrivilege',
                'SeBackupPrivilege'
            ]
            
            for priv in dangerous_privileges:
                if priv in whoami_priv and 'Enabled' in whoami_priv:
                    print(f"[!] DANGEROUS PRIVILEGE DETECTED: {priv}")
                    self.vulnerabilities.append(f"Dangerous privilege: {priv}")
                    
                    if priv == 'SeImpersonatePrivilege':
                        print("    [>] Possible exploitation with PrintSpoofer, JuicyPotato, or RoguePotato")
                    elif priv == 'SeDebugPrivilege':
                        print("    [>] Possible process injection into higher privileged processes")

    def check_services_vulnerabilities(self):
        """Check for vulnerable Windows services"""
        print("\n[+] Checking Windows Services...")
        
        # Get all services with their paths
        services_output = self.run_command(
            'wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\\\"'
        )
        
        if services_output:
            print("[*] Non-Windows services running automatically:")
            services = services_output.split('\n')
            
            for service in services:
                if service.strip():
                    print(f"[*] Service: {service}")
                    
                    # Check for unquoted service paths
                    if '"' not in service and ' ' in service:
                        print(f"[!] UNQUOTED SERVICE PATH DETECTED: {service}")
                        self.vulnerabilities.append(f"Unquoted service path: {service}")

        # Check service permissions using PowerShell
        print("\n[+] Checking service permissions...")
        ps_command = '''powershell "Get-WmiObject win32_service | select Name,DisplayName,PathName,StartMode | Where {$_.StartMode -eq 'Auto' -and $_.PathName -notlike 'C:\\Windows\\*'}"'''
        services_ps = self.run_command(ps_command)
        if services_ps:
            print("[*] Services found via PowerShell enumeration")

    def check_scheduled_tasks(self):
        """Check for vulnerable scheduled tasks"""
        print("\n[+] Checking Scheduled Tasks...")
        
        # Get scheduled tasks
        tasks_output = self.run_command('schtasks /query /fo LIST /v | findstr /B /C:"TaskName" /C:"Run As User"')
        
        if tasks_output:
            print("[*] Scheduled tasks found:")
            tasks = tasks_output.split('\n')
            
            for task in tasks:
                if task.strip():
                    print(f"[*] Task: {task}")
                    
                    # Look for tasks running as SYSTEM or Administrator
                    if 'SYSTEM' in task or 'Administrator' in task:
                        print(f"[!] HIGH PRIVILEGE TASK: {task}")

    
                        pass
                    
            

    def check_dll_hijacking(self):
        """Check for DLL hijacking opportunities"""
        print("\n[+] Checking for DLL Hijacking Opportunities...")
        
        # Check for missing DLLs that could be hijacked
        system_paths = [
            os.environ.get('SYSTEMROOT', 'C:\\Windows'),
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'),
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64')
        ]
        
        # Check current directory for potential DLL hijacking
        current_dir = os.getcwd()
        print(f"[*] Current directory: {current_dir}")
        
        # Look for executable files in current directory
        for file in os.listdir(current_dir):
            if file.endswith('.exe'):
                print(f"[*] Executable in current directory: {file}")
                print("    [>] Check if this application loads DLLs from current directory")

    def check_unattended_installs(self):
        """Check for unattended install files with credentials"""
        print("\n[+] Checking for Unattended Install Files...")
        
        unattend_paths = [
            "C:\\Windows\\Panther\\Unattend.xml",
            "C:\\Windows\\Panther\\Unattended.xml",
            "C:\\Windows\\System32\\Sysprep\\Unattend.xml",
            "C:\\Windows\\System32\\Sysprep\\Panther\\Unattend.xml"
        ]
        
        for path in unattend_paths:
            if os.path.exists(path):
                print(f"[!] UNATTENDED INSTALL FILE FOUND: {path}")
                self.vulnerabilities.append(f"Unattended install file: {path}")
                print("    [>] Check file for stored credentials")

    def check_always_install_elevated(self):
        """Check AlwaysInstallElevated registry setting"""
        print("\n[+] Checking AlwaysInstallElevated...")
        
        try:
            # Check HKLM
            hklm_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SOFTWARE\Policies\Microsoft\Windows\Installer")
            try:
                value, _ = winreg.QueryValueEx(hklm_key, "AlwaysInstallElevated")
                if value == 1:
                    print("[!] AlwaysInstallElevated is enabled in HKLM")
                    hklm_enabled = True
                else:
                    hklm_enabled = False
            except FileNotFoundError:
                hklm_enabled = False
            winreg.CloseKey(hklm_key)
            
            # Check HKCU
            hkcu_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                    r"SOFTWARE\Policies\Microsoft\Windows\Installer")
            try:
                value, _ = winreg.QueryValueEx(hkcu_key, "AlwaysInstallElevated")
                if value == 1:
                    print("[!] AlwaysInstallElevated is enabled in HKCU")
                    hkcu_enabled = True
                else:
                    hkcu_enabled = False
            except FileNotFoundError:
                hkcu_enabled = False
            winreg.CloseKey(hkcu_key)
            
            if hklm_enabled and hkcu_enabled:
                print("[!] VULNERABILITY: AlwaysInstallElevated is fully enabled")
                self.vulnerabilities.append("AlwaysInstallElevated enabled")
                print("    [>] Exploit: msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi")
                print("    [>] Then: msiexec /quiet /qn /i evil.msi")
                
        except Exception as e:
            print(f"[*] AlwaysInstallElevated check completed (registry keys may not exist)")

    def check_stored_credentials(self):
        """Check for stored credentials"""
        print("\n[+] Checking for Stored Credentials...")
        
        # Check cmdkey for stored credentials
        cmdkey_output = self.run_command("cmdkey /list")
        if cmdkey_output and "Target:" in cmdkey_output:
            print("[!] STORED CREDENTIALS FOUND:")
            print(cmdkey_output)
            self.vulnerabilities.append("Stored credentials found")
            print("    [>] Use: runas /savecred /user:DOMAIN\\Administrator cmd.exe")

        # Check for common credential files
        credential_files = [
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\*",
            "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Credentials\\*"
        ]
        
        for pattern in credential_files:
            files = self.run_command(f'dir "{pattern}" /s /b 2>nul')
            if files:
                print(f"[!] CREDENTIAL FILES FOUND: {pattern}")

    def check_weak_service_permissions(self):
        """Check for services with weak permissions using PowerShell"""
        print("\n[+] Checking Service Permissions with PowerShell...")
        
        ps_script = '''
        Get-WmiObject win32_service | ForEach-Object {
            $service = $_
            try {
                $acl = Get-Acl -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$($service.Name)" -ErrorAction Stop
                $permissions = $acl.Access | Where-Object {$_.IdentityReference -match "Users|Everyone|Authenticated Users"}
                if ($permissions) {
                    Write-Output "Service: $($service.Name) - $($service.DisplayName)"
                    $permissions | ForEach-Object {
                        Write-Output "  Permission: $($_.IdentityReference) - $($_.RegistryRights)"
                    }
                }
            } catch {}
        }
        '''
        
        result = self.run_command(f'powershell -Command "{ps_script}"')
        if result:
            print("[!] Services with weak permissions found:")
            print(result)

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
        
        print("\n[+] RECOMMENDED TOOLS FOR FURTHER TESTING:")
        print("    - WinPEAS: Comprehensive Windows privilege escalation checker")
        print("    - PowerUp: PowerShell privilege escalation framework")
        print("    - Sherlock: PowerShell script for finding missing patches")
        print("    - Watson: .NET enumeration tool for missing patches")
        
        print("\n[+] COMMON EXPLOITATION TOOLS:")
        print("    - PrintSpoofer: Token impersonation exploit")
        print("    - JuicyPotato: CLSID-based token impersonation")
        print("    - RoguePotato: Updated potato family exploit")
        
        print("\n[+] RECOMMENDED ACTIONS:")
        print("    1. Apply latest Windows security updates")
        print("    2. Review and fix service permissions")
        print("    3. Disable unnecessary services and scheduled tasks")
        print("    4. Follow principle of least privilege")
        print("    5. Regular security audits and penetration testing")

    def run_all_checks(self):
        """Run all privilege escalation checks"""
        self.print_banner()
        
        try:
            self.check_token_privileges()
            self.check_services_vulnerabilities()
            self.check_scheduled_tasks()
            self.check_dll_hijacking()
            self.check_unattended_installs()
            self.check_always_install_elevated()
            self.check_stored_credentials()
            self.check_weak_service_permissions()
            self.generate_report()
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        except Exception as e:
            print(f"[!] Error during scan: {e}")

def main():
    if os.name != 'nt':
        print("[!] This script is designed for Windows systems only.")
        sys.exit(1)
    
    detector = WindowsPrivEscDetector()
    detector.run_all_checks()

if __name__ == "__main__":
    main()