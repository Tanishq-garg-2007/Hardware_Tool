import re
from pathlib import Path
from typing import Dict, Any, List, Optional

# Coreutils / busybox applets to deprioritize from credentials
COREUTILS_APPLETS = {
    'cat', 'catv', 'chgrp', 'chmod', 'chown', 'cp', 'cpio', 'date', 'dd', 'df',
    'dmesg', 'echo', 'false', 'fgrep', 'free', 'fsync', 'getopt', 'grep', 'gunzip',
    'gzip', 'hostname', 'iostat', 'kill', 'killall', 'killall5', 'ln', 'ls', 'lsattr',
    'mkdir', 'mknod', 'more', 'mount', 'mountpoint', 'mpstat', 'mt', 'mv', 'nice',
    'pidof', 'ping', 'powertop', 'printenv', 'ps', 'pwd', 'rm', 'rmdir', 'sed',
    'sleep', 'stat', 'stty', 'sync', 'tar', 'touch', 'true', 'umount', 'uname',
    'uncompress', 'usleep', 'vi', 'watch', 'zcat', 'ash', 'sh', 'egrep', 'mktemp',
    'fdflush', 'dumpkmap', 'loadkmap', 'setarch', 'linux32', 'linux64', 'cttyhack',
    'base64', 'scriptreplay', 'ipcalc', 'ionice', 'dnsdomainname', 'chattr'
}


def parse_firmaudit_report(report_text: str) -> Dict[str, Any]:
    """
    Parses raw FirmAudit output text into structured security findings:
    - vulnerabilities: Command injections, dangerous memory symbols, SSH keys
    - weak_crypto: Outdated/broken algorithms (DES, MD5, SHA1), predictable keys
    - credentials: Real password/shadow files, config credentials, daemon binaries
    - configs_and_dbs: System configurations, databases, service binaries
    - network_endpoints: Discovered IPv4 addresses, URLs, developer emails
    - shared_libraries: ELF binaries and their linked DT_NEEDED dependencies
    """
    lines = report_text.splitlines() if report_text else []

    vulnerabilities = []
    weak_crypto = []
    credentials = []
    configs_and_dbs = []
    network_endpoints = []
    shared_libraries = []

    current_section = None
    lib_file = None

    seen_vulns = set()
    seen_crypto = set()
    seen_creds = set()
    seen_files = set()
    seen_endpoints = set()

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        if 'Searching in ' in line_clean and 'directory' in line_clean:
            continue
        elif 'Searching for IP addresses' in line_clean:
            current_section = 'ip'
            continue
        elif 'Searching for important binaries' in line_clean:
            current_section = 'binaries'
            continue
        elif 'Searching for Database file' in line_clean:
            current_section = 'database'
            continue
        elif 'Searching for system configuration files' in line_clean:
            current_section = 'configs'
            continue
        elif 'Searching for passwords' in line_clean:
            current_section = 'passwords'
            continue
        elif 'Searching for files' in line_clean:
            current_section = 'files'
            continue
        elif 'Searching for ssh files' in line_clean:
            current_section = 'ssh_files'
            continue
        elif 'Searching for ssl files' in line_clean:
            current_section = 'ssl_files'
            continue
        elif 'Searching for webserveres' in line_clean:
            current_section = 'webservers'
            continue
        elif 'Searching for shell scripts' in line_clean:
            current_section = 'scripts'
            continue
        elif 'Searching for .bin files' in line_clean:
            current_section = 'bin_files'
            continue
        elif 'Searching for email addresses' in line_clean:
            current_section = 'emails'
            continue
        elif 'Searching for urls' in line_clean:
            current_section = 'urls'
            continue
        elif 'Searching for default credentials' in line_clean:
            current_section = 'default_creds_files'
            continue
        elif 'Searching for hardcoded sensitive information' in line_clean:
            current_section = 'sensitive_info'
            continue
        elif 'Searching for insecure services' in line_clean:
            current_section = 'insecure_services'
            continue
        elif 'Searching for misconfigurations' in line_clean:
            current_section = 'misconfigs'
            continue
        elif 'Identifying file signatures' in line_clean:
            current_section = 'signatures'
            continue
        elif 'Identifying third-party libraries in ELF files' in line_clean:
            current_section = 'third_party_libs'
            continue
        elif 'Identifying dangerous functions in ELF files' in line_clean:
            current_section = 'dangerous_functions'
            continue
        elif 'Searching for hardcoded SSH keys' in line_clean:
            current_section = 'ssh_keys'
            continue
        elif 'Searching for command injection vulnerabilities' in line_clean:
            current_section = 'command_injection'
            continue
        elif 'Searching for outdated or weak cryptographic algorithms' in line_clean:
            current_section = 'weak_crypto'
            continue
        elif 'Checking for weak or predictable encryption keys' in line_clean:
            current_section = 'weak_keys'
            continue
        elif 'Searching for Default Credentials in System Binaries' in line_clean:
            current_section = 'default_credentials_binaries'
            continue

        if line_clean.startswith('########################'):
            continue

        # 1. Potential command injection
        m_ci = re.match(r'^File:\s*(.*?)\s*-\s*Potential command injection vulnerability', line_clean, re.I)
        if m_ci:
            fpath = m_ci.group(1).strip()
            if fpath not in seen_vulns:
                seen_vulns.add(fpath)
                vulnerabilities.append({
                    'file': fpath,
                    'type': 'Command Injection',
                    'severity': 'CRITICAL',
                    'detail': 'Potential shell execution or command injection vector detected in web interface or script.'
                })
            continue

        # 2. Dangerous function in ELF
        m_df = re.match(r'^File:\s*(.*?)\s*-\s*Dangerous Function:\s*(.*)', line_clean, re.I)
        if m_df:
            fpath = m_df.group(1).strip()
            func = m_df.group(2).strip()
            key = f'{fpath}:{func}'
            if key not in seen_vulns:
                seen_vulns.add(key)
                vulnerabilities.append({
                    'file': fpath,
                    'type': f'Dangerous Function ({func})',
                    'severity': 'HIGH',
                    'detail': f'Deprecated or dangerous memory API symbol \'{func}\' found in ELF symbol table.'
                })
            continue

        # 3. Hardcoded SSH private key
        m_ssh = re.match(r'^File:\s*(.*?)\s*-\s*Contains hardcoded SSH key', line_clean, re.I)
        if m_ssh:
            fpath = m_ssh.group(1).strip()
            if fpath not in seen_vulns:
                seen_vulns.add(fpath)
                vulnerabilities.append({
                    'file': fpath,
                    'type': 'Hardcoded SSH Private Key',
                    'severity': 'CRITICAL',
                    'detail': 'Embedded private key banner (RSA/DSA/EC) found inside binary or file.'
                })
            continue

        # 4. Weak cryptographic algorithms
        m_wc = re.match(r'^File:\s*(.*?)\s*-\s*(MD5|SHA1|DES|RC4)\b', line_clean, re.I)
        if m_wc:
            fpath = m_wc.group(1).strip()
            algo = m_wc.group(2).strip().upper()
            key = f'{fpath}:{algo}'
            if key not in seen_crypto:
                seen_crypto.add(key)
                weak_crypto.append({
                    'file': fpath,
                    'algorithm': algo,
                    'severity': 'HIGH' if algo in ['DES', 'RC4'] else 'MEDIUM',
                    'detail': f'Outdated, broken, or collision-prone cryptographic algorithm \'{algo}\' used.'
                })
            continue

        # 5. Weak or predictable encryption keys
        m_wk = re.match(r'^File:\s*(.*?)\s*-\s*Contains weak or predictable encryption key:\s*(.*)', line_clean, re.I)
        if m_wk:
            fpath = m_wk.group(1).strip()
            kdetail = m_wk.group(2).strip()
            key = f'{fpath}:{kdetail}'
            if key not in seen_crypto:
                seen_crypto.add(key)
                weak_crypto.append({
                    'file': fpath,
                    'algorithm': 'Predictable Key Pattern',
                    'severity': 'HIGH',
                    'detail': f'Predictable static key or password pattern: {kdetail}'
                })
            continue

        # 6. Default credentials in system binaries / files
        m_dc = re.match(r'^File:\s*(.*?)\s*-\s*Contains default credentials', line_clean, re.I)
        if m_dc:
            fpath = m_dc.group(1).strip()
            fname = fpath.split('/')[-1].lower()
            is_config_or_script = any(x in fpath.lower() for x in ['/etc/', '.conf', '.cfg', '.sh', '.json', '.xml', 'init', 'rc.'])
            is_daemon = any(x in fname for x in ['login', 'telnet', 'ftp', 'ssh', 'dropbear', 'updater', 'sysctl', 'admin', 'auth'])

            if fname in COREUTILS_APPLETS and not is_config_or_script:
                continue

            if fpath not in seen_creds:
                seen_creds.add(fpath)
                if is_config_or_script:
                    ctype = 'Default Credentials in Config/Script'
                    csev = 'CRITICAL'
                elif is_daemon:
                    ctype = 'Default Credentials in Daemon Binary'
                    csev = 'HIGH'
                else:
                    ctype = 'Default Credentials in Binary'
                    csev = 'MEDIUM'

                credentials.append({
                    'file': fpath,
                    'type': ctype,
                    'severity': csev,
                    'detail': 'Default credential pair (admin/admin, root/root, etc.) detected.'
                })
            continue

        # 7. Password / Shadow / PSK Files
        if current_section == 'passwords':
            if line_clean not in seen_creds:
                seen_creds.add(line_clean)
                fname = line_clean.split('/')[-1]
                credentials.append({
                    'file': line_clean,
                    'type': 'Password / Shadow Hash File' if ('shadow' in fname or 'passwd' in fname) else 'Pre-Shared Key / Secret File',
                    'severity': 'CRITICAL',
                    'detail': f'Sensitive user credential or hash storage file: {fname}'
                })
            continue

        # 8. Third-party dynamic libraries
        if current_section == 'third_party_libs':
            if line_clean.startswith('File:'):
                lib_file = line_clean.replace('File:', '').strip()
            elif lib_file and ('.so' in line_clean or 'libc' in line_clean):
                libs = [l.strip() for l in line_clean.split(',') if l.strip()]
                shared_libraries.append({
                    'binary': lib_file,
                    'libraries': libs
                })
                lib_file = None
            continue

        # 9. Configs, Databases, and Sensitive Files
        if current_section in ['configs', 'database', 'binaries', 'ssl_files', 'ssh_files', 'webservers']:
            cat_map = {
                'configs': 'System Configuration',
                'database': 'Database File',
                'binaries': 'Critical Service Binary',
                'ssl_files': 'SSL Certificate / Key',
                'ssh_files': 'SSH Configuration / Key',
                'webservers': 'Web Server Executable'
            }
            if line_clean not in seen_files and not line_clean.startswith('File:'):
                seen_files.add(line_clean)
                configs_and_dbs.append({
                    'file': line_clean,
                    'category': cat_map.get(current_section, 'System File'),
                    'detail': f'{cat_map.get(current_section)} discovered during deep audit'
                })
            continue

        # 10. Network Endpoints (IPs, URLs, Emails)
        if current_section == 'ip':
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line_clean):
                if line_clean not in seen_endpoints:
                    seen_endpoints.add(line_clean)
                    network_endpoints.append({
                        'type': 'IP Address',
                        'value': line_clean,
                        'detail': 'Hardcoded IPv4 address'
                    })
            continue
        elif current_section == 'urls':
            if line_clean.startswith('http://') or line_clean.startswith('https://'):
                clean_url = re.sub(r'[\'\";\)\>\.]+$', '', line_clean)
                if clean_url not in seen_endpoints:
                    seen_endpoints.add(clean_url)
                    network_endpoints.append({
                        'type': 'URL Endpoint',
                        'value': clean_url,
                        'detail': 'Discovered remote HTTP/HTTPS resource URL'
                    })
            continue
        elif current_section == 'emails':
            if '@' in line_clean and line_clean not in seen_endpoints:
                seen_endpoints.add(line_clean)
                network_endpoints.append({
                    'type': 'Email Contact',
                    'value': line_clean,
                    'detail': 'Developer / vendor contact email address'
                })
            continue

    return {
        'summary': {
            'vulnerabilities': len(vulnerabilities),
            'weak_crypto': len(weak_crypto),
            'credentials': len(credentials),
            'configs_and_dbs': len(configs_and_dbs),
            'network_endpoints': len(network_endpoints),
            'shared_libraries': len(shared_libraries)
        },
        'vulnerabilities': vulnerabilities,
        'weak_crypto': weak_crypto,
        'credentials': credentials,
        'configs_and_dbs': configs_and_dbs,
        'network_endpoints': network_endpoints,
        'shared_libraries': shared_libraries
    }


def get_firmaudit_report_data(base_name: str, candidate_dirs: Optional[List[Path]] = None) -> Dict[str, Any]:
    """
    Finds and parses an existing FirmAudit report by base name across provided or default directories.
    """
    clean_name = base_name.replace(".txt", "")

    if not candidate_dirs:
        backend_dir = Path(__file__).resolve().parent
        project_root = backend_dir.parent
        candidate_dirs = [
            project_root / "FirmAudit",
            project_root / "extracted_files",
            project_root,
            backend_dir
        ]

    for cand_dir in candidate_dirs:
        candidates = [
            cand_dir / f"{clean_name}.txt",
            cand_dir / f"{clean_name}_testout.txt"
        ]
        for cand in candidates:
            if cand.exists() and cand.is_file():
                try:
                    with open(cand, "r", encoding="utf-8", errors="replace") as f:
                        txt_content = f.read()
                    parsed = parse_firmaudit_report(txt_content)
                    return {
                        "found": True,
                        "base_name": clean_name,
                        "file_path": str(cand),
                        "txt_output": txt_content,
                        "audit_results": parsed,
                        "txt_url": f"/FirmAudit/{clean_name}.txt" if (cand_dir / f"{clean_name}.txt").exists() else None
                    }
                except Exception as e:
                    return {"found": False, "error": str(e)}

    return {"found": False, "message": f"Report for '{base_name}' not found."}
