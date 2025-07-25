# Privilege Escalation Checker

A comprehensive tool for detecting potential privilege escalation vulnerabilities on Windows and Linux systems. This tool is designed for educational purposes and authorized security testing only.

## Description

This project consists of two scripts:
- `windows.py`: For detecting privilege escalation vulnerabilities on Windows systems
- `linux.py`: For detecting privilege escalation vulnerabilities on Linux systems

The scripts perform various checks to identify common privilege escalation vectors, including:

### Windows Checks:
- Token privileges analysis
- Service vulnerabilities (unquoted paths, weak permissions)
- Scheduled tasks with elevated privileges
- DLL hijacking opportunities
- Unattended installation files
- AlwaysInstallElevated registry settings
- Stored credentials
- Weak service permissions

### Linux Checks:
- SUID/SGID binaries
- Sudo privileges and misconfigurations
- Writable cron jobs
- Dangerous Linux capabilities
- Kernel exploits
- Writable sensitive files
- Dangerous environment variables

## Installation

No installation is required. Simply clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/priv_checker.git
cd priv_checker
```

## Usage

### Windows Systems

```bash
python windows.py
```

### Linux Systems

```bash
python3 linux.py
```

## Requirements

### Windows
- Python 3.x
- Windows operating system
- Administrator privileges (for some checks)

### Linux
- Python 3.x
- Linux operating system
- Root privileges (for some checks)

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Use only on systems you own or have explicit permission to test. Unauthorized use of this tool against systems without proper authorization may be illegal and is strictly prohibited.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- This tool is inspired by various privilege escalation techniques documented in cybersecurity research.
- Special thanks to the security community for documenting these techniques.

## Note on Character Encoding

If you encounter a UnicodeDecodeError when running the Windows script, you may need to modify the `run_command` method in `windows.py` to handle different character encodings:

```python
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
```