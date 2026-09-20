import re
import os
import pathlib
import sys
import subprocess
from urllib.parse import urlparse
import signal
# pyrefly: ignore [missing-import]
from elftools.elf.elffile import ELFFile
from collections import defaultdict

glo = set()
seen_entries = set()  # Set to track seen entries

# patterns
bins = ['ssh', 'sshd', 'scp', 'sftp', 'tftp', 'dropbear', 'busybox', 'telnet', 'telnetd', 'openssl']
dbs = ['*.db', '*.sqlite', '*.sqlite3']
confs = ['*.conf', '*.cfg', '*.ini']
passwords = ['passwd', 'shadow', '*.psk']
others = ['upgrade', 'admin', 'root', 'password', 'passwd', 'pwd', 'dropbear', 'ssl', 'private key', 'telnet', 'secret', 'pgp', 'gpg', 'token', 'api key', 'oauth']
sshFiles = ['authorized_keys', '*authorized_keys*', 'host_key', '*host_key*', 'id_rsa', '*id_rsa*', 'id_dsa', '*id_dsa*', '*.pub']
sslFiles = ['*.crt', '*.pem', '*.cer', '*.p7b', '*.p12', '*.key']
webServers = ['apache', 'lighttpd', 'alphapd', 'httpd']

# New patterns for additional checks
default_creds = ['default_user', 'default_password', 'default_credentials', 'user:password']
sensitive_info = ['api_key', 'secret_key', 'access_token', 'private_key']
insecure_services = ['telnet', 'ftp', 'http']
misconfigurations = ['insecure', 'misconfigured', 'unsafe']

# Weak cryptography patterns
# weak_algorithms = ['MD5', 'SHA1', 'DES']
# Weak cryptography patterns specifically for implementation
weak_algorithm_patterns = {
    re.compile(r'\bMD5\b(?!sum)'): 'MD5',
    re.compile(r'\bSHA1\b(?!sum)'): 'SHA1',
    re.compile(r'\bDES\b(?!sum)'): 'DES'
}

# weak_algorithm_patterns = [
#     re.compile(r'\bMD5\b(?!sum)'),
#     re.compile(r'\bSHA1\b(?!sum)'),
#     re.compile(r'\bDES\b(?!sum)')
# ]


# Default credentials to check
default_credentials = [
    ('admin', 'admin'),
    ('root', 'root'),
    ('admin', 'password'),
    ('user', 'user'),
    ('guest', 'guest')
]

weak_keys = [re.compile(r'key\s*=\s*[\'"]?[a-zA-Z0-9]{8,16}[\'"]?'), re.compile(r'password\s*=\s*[\'"]?[a-zA-Z0-9]{8,16}[\'"]?')]
hardcoded_creds = ['hardcoded_key', 'hardcoded_password', 'hardcoded_secret']

# Dangerous functions and deprecated APIs to check for
dangerous_functions = ['strcpy', 'gets', 'sprintf', 'strcat', 'scanf']

# Web command injection patterns
command_injection_patterns = [re.compile(r'system\s*\('), re.compile(r'exec\s*\('), re.compile(r'popen\s*\('), re.compile(r'passthru\s*\('), re.compile(r'shell_exec\s*\(')]

# File signatures for identification
file_signatures = {
    b'\x1F\x8B\x08': 'gzip compressed file',
    b'\x50\x4B\x03\x04': 'zip archive',
    b'\x42\x5A\x68': 'bzip2 compressed file',
    b'\x37\x7A\xBC\xAF\x27\x1C': '7-zip archive',
    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'PNG image',
    b'\xFF\xD8\xFF': 'JPEG image',
    b'\x7F\x45\x4C\x46': 'ELF executable',
    b'\x4D\x5A': 'PE executable',
    # Add more signatures as needed
}

# Patterns for hardcoded backdoors
ssh_private_key_patterns = [re.compile(r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----')]
telnet_credential_patterns = [re.compile(r'telnet_username\s*=\s*["\'](\w+)["\']'), re.compile(r'telnet_password\s*=\s*["\'](\w+)["\']')]

# ip encoded in single quotes
ip = re.compile(r'\'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\'')
# in double quotes
ip1 = re.compile(r'\"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\"')

# email
email = re.compile(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+")

# urls         
urlpat = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
urls = re.compile(urlpat)

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException

# Set the signal handler for alarm (cross-platform compatible)
if hasattr(signal, "SIGALRM"):
    signal.signal(signal.SIGALRM, timeout_handler)
else:
    signal.alarm = lambda s: None

# Search functions
def pattern_search(dirc, pattern): 
    path = pathlib.Path(dirc)
    for f in path.rglob("*"):
        if not os.path.isdir(f):
            if 'dev' in f.parts:
                continue
            if os.path.exists(f):  # Check if file exists
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, errors='ignore') as _file:
                        for i, line in enumerate(_file.readlines()):
                            line = line.rstrip()
                            match = pattern.findall(line)
                            for item in match:
                                if item not in seen_entries:
                                    print(item)
                                    seen_entries.add(item)
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                finally:
                    signal.alarm(0)  # Disable the alarm

def url_search(dirc): 
    print("Searching for urls... \n")
    res = set()
    path = pathlib.Path(dirc)
    for f in path.rglob("*"):
        if not os.path.isdir(f):
            if 'dev' in f.parts:
                continue
            if os.path.exists(f):  # Check if file exists
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, errors='ignore') as _file:
                        for i, line in enumerate(_file.readlines()):
                            line = line.rstrip()
                            arr = ["".join(x) for x in urls.findall(line)]
                            for item in arr:
                                if item not in seen_entries:
                                    print(item)
                                    seen_entries.add(item)
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                finally:
                    signal.alarm(0)  # Disable the alarm

# pattern with file name:
def search_wfileName(dirc, pattern1, pattern2): 
    path = pathlib.Path(dirc)
    for f in path.rglob("*"):
        if not os.path.isdir(f):
            if 'dev' in f.parts:
                continue
            res = set()
            if os.path.exists(f):  # Check if file exists
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, errors='ignore') as _file:
                        for i, line in enumerate(_file.readlines()):
                            line = line.rstrip()
                            res.update(pattern1.findall(line))
                            res.update(pattern2.findall(line))
                        if len(res) > 0:
                            for item in res:
                                if item not in seen_entries:
                                    print(f)
                                    print(item)
                                    seen_entries.add(item)
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                finally:
                    signal.alarm(0)  # Disable the alarm

# calls for both 'ip' & "ip"
def ip_Search(dirc):
    print("Searching for IP addresses...\n")
    pattern_search(dirc, ip)
    pattern_search(dirc, ip1)

def ipWithFileName(dirc):
    print("Searching for IP addresses...\n")
    search_wfileName(dirc, ip1, ip)

def call_Search(dirc, pat, txt):
    print("\n", txt)
    pattern_search(dirc, pat)

# Signature-based identification
def identify_file_signatures(dirc):
    print("\nIdentifying file signatures... \n")
    path = pathlib.Path(dirc)
    for f in path.rglob("*"):
        if not os.path.isdir(f):
            if 'dev' in f.parts:
                continue
            if os.path.exists(f):
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, 'rb') as _file:
                        file_start = _file.read(64)  # Read the first 64 bytes
                        for signature, file_type in file_signatures.items():
                            if file_start.startswith(signature):
                                entry = f"File: {f} - Type: {file_type}"
                                if entry not in seen_entries:
                                    print(entry)
                                    seen_entries.add(entry)
                                break
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                finally:
                    signal.alarm(0)  # Disable the alarm

def identify_third_party_libraries(dirc):
    print("\nIdentifying third-party libraries in ELF files...\n")
    path = pathlib.Path(dirc)
    library_map = defaultdict(list)

    for f in path.rglob("*"):
        if not os.path.isdir(f):
            if 'dev' in f.parts:
                continue
            if os.path.exists(f):
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, 'rb') as _file:
                        elffile = ELFFile(_file)
                        if elffile.has_dwarf_info():
                            for segment in elffile.iter_segments():
                                if segment['p_type'] == 'PT_DYNAMIC':
                                    for tag in segment.iter_tags():
                                        if tag.entry.d_tag == 'DT_NEEDED':
                                            library_map[f].append(tag.needed)
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                except Exception as e:
                    # Catch other exceptions (e.g., not an ELF file)
                    continue
                finally:
                    signal.alarm(0)  # Disable the alarm

    # Print the collected library information
    for file, libraries in library_map.items():
        libraries_str = ', '.join(libraries)
        print(f"File: {file}\n{libraries_str}")

# Identify dangerous functions
def identify_dangerous_functions(dirc):
    print("\nIdentifying dangerous functions in ELF files...\n")
    path = pathlib.Path(dirc)
    for f in path.rglob("*"):
        if not os.path.isdir(f):
            if 'dev' in f.parts:
                continue
            if os.path.exists(f):
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, 'rb') as _file:
                        elffile = ELFFile(_file)
                        symtab = elffile.get_section_by_name('.symtab')
                        if symtab:
                            for symbol in symtab.iter_symbols():
                                if symbol.name in dangerous_functions:
                                    entry = f"File: {f} - Dangerous Function: {symbol.name}"
                                    if entry not in seen_entries:
                                        print(entry)
                                        seen_entries.add(entry)
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                except Exception as e:
                    # Catch other exceptions (e.g., not an ELF file)
                    continue
                finally:
                    signal.alarm(0)  # Disable the alarm

# Search for hardcoded SSH keys
def search_hardcoded_ssh_keys(dirc):
    print("\nSearching for hardcoded SSH keys...\n")
    path = pathlib.Path(dirc)
    for f in path.rglob("*"):
        if not os.path.isdir(f):
            if 'dev' in f.parts:
                continue
            if os.path.exists(f):
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, 'r', errors='ignore') as _file:
                        content = _file.read()
                        for pattern in ssh_private_key_patterns:
                            if pattern.search(content):
                                entry = f"File: {f} - Contains hardcoded SSH key"
                                if entry not in seen_entries:
                                    print(entry)
                                    seen_entries.add(entry)
                                break
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                except Exception as e:
                    # Catch other exceptions (e.g., binary files)
                    continue
                finally:
                    signal.alarm(0)  # Disable the alarm

# Search for hardcoded Telnet credentials
def search_hardcoded_telnet_credentials(dirc):
    print("\nSearching for hardcoded Telnet credentials...\n")
    path = pathlib.Path(dirc)
    for f in path.rglob("*"):
        if not os.path.isdir(f):
            if 'dev' in f.parts:
                continue
            if os.path.exists(f):
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, 'r', errors='ignore') as _file:
                        content = _file.read()
                        for pattern in telnet_credential_patterns:
                            matches = pattern.findall(content)
                            if matches:
                                entry = f"File: {f} - Contains hardcoded Telnet credentials: {matches}"
                                if entry not in seen_entries:
                                    print(entry)
                                    seen_entries.add(entry)
                                break
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                except Exception as e:
                    # Catch other exceptions (e.g., binary files)
                    continue
                finally:
                    signal.alarm(0)  # Disable the alarm

# Search for command injection vulnerabilities in web interfaces
def search_command_injection(dirc):
    print("\nSearching for command injection vulnerabilities in web interfaces...\n")
    path = pathlib.Path(dirc)
    for f in path.rglob("*"):
        if not os.path.isdir(f):
            if 'dev' in f.parts:
                continue
            if os.path.exists(f):
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, 'r', errors='ignore') as _file:
                        content = _file.read()
                        for pattern in command_injection_patterns:
                            if pattern.search(content):
                                entry = f"File: {f} - Potential command injection vulnerability"
                                if entry not in seen_entries:
                                    print(entry)
                                    seen_entries.add(entry)
                                break
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                except Exception as e:
                    # Catch other exceptions (e.g., binary files)
                    continue
                finally:
                    signal.alarm(0)  # Disable the alarm

# Searching for sensitive files
def file_search(dirc, arr, text):
    print("\n", text)
    for i in arr:
        print("########################", i)
        path = pathlib.Path(dirc)
        if (i[0] == '*' or i[-1] == '*'):
            for f in path.rglob(i):
                if not os.path.isdir(f):
                    if 'dev' in f.parts:
                        continue
                    entry = f"{f}"
                    if entry not in seen_entries:
                        print(entry)
                        seen_entries.add(entry)
        else:
            for f in path.rglob('*'):
                if not os.path.isdir(f):
                    if 'dev' in f.parts:
                        continue
                    if i in f.parts:
                        entry = f"{f}"
                        if entry not in seen_entries:
                            print(entry)
                            seen_entries.add(entry)

def extension_search(dirc, ext, text):
    print("\n", text)
    path = pathlib.Path(dirc)
    for f in path.rglob(ext):
        entry = f"{f}"
        if entry not in seen_entries:
            print(entry)
            seen_entries.add(entry)

def run_extractor(action, firmware_file):
    """
    Runs the extractor.py script with the specified action and firmware file.
    """
    try:
        extractor_script = os.path.join(os.path.dirname(__file__) or ".", "extractor.py")
        result = subprocess.run([sys.executable, extractor_script, action, firmware_file], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(result.stdout.decode())
        print(result.stderr.decode())
    except subprocess.CalledProcessError as e:
        print(f"Error running extractor.py: {e.stderr.decode()}", file=sys.stderr)
        sys.exit(1)

# Search for weak cryptographic algorithms
def search_weak_cryptographic_algorithms(dirc):
    print("\nSearching for outdated or weak cryptographic algorithms...\n")
    path = pathlib.Path(dirc)
    for f in path.rglob("*"):
        if not os.path.isdir(f):
            if 'dev' in f.parts:
                continue
            if os.path.exists(f):  # Check if file exists
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, errors='ignore') as _file:
                        for i, line in enumerate(_file.readlines()):
                            for pattern, algo_name in weak_algorithm_patterns.items():
                                if pattern.search(line):
                                    #entry = f"File: {f} - Contains weak cryptographic algorithm implementation: {algo_name}"
                                    entry = f"File: {f} -  {algo_name}"
                                    if entry not in seen_entries:
                                        print(entry)
                                        seen_entries.add(entry)
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                finally:
                    signal.alarm(0)  # Disable the alarm
                    
# Check for weak or predictable encryption keys
def search_weak_keys(dirc):
    print("\nChecking for weak or predictable encryption keys...\n")
    path = pathlib.Path(dirc)
    for f in path.rglob("*"):
        if not os.path.isdir(f):
            # if 'dev' in f.parts:
            #     continue
            if os.path.exists(f):  # Check if file exists
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, errors='ignore') as _file:
                        for i, line in enumerate(_file.readlines()):
                            for pattern in weak_keys:
                                matches = pattern.findall(line)
                                for item in matches:
                                    entry = f"File: {f} - Contains weak or predictable encryption key: {item}"
                                    if entry not in seen_entries:
                                        print(entry)
                                        seen_entries.add(entry)
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                finally:
                    signal.alarm(0)  # Disable the alarm

# Look for hardcoded cryptographic keys or passwords
# def search_hardcoded_creds(dirc):
#     print("\nLooking for hardcoded cryptographic keys or passwords...\n")
#     path = pathlib.Path(dirc)
#     for f in path.rglob("*"):
#         if not os.path.isdir(f):
#             if 'dev' in f.parts:
#                 continue
#             if os.path.exists(f):  # Check if file exists
#                 try:
#                     signal.alarm(10)  # Set alarm for 10 seconds
#                     with open(f, errors='ignore') as _file:
#                         for i, line in enumerate(_file.readlines()):
#                             for cred in hardcoded_creds:
#                                 if cred in line:
#                                     entry = f"File: {f} - Contains hardcoded cryptographic key or password: {cred}"
#                                     if entry not in seen_entries:
#                                         print(entry)
#                                         seen_entries.add(entry)
#                 except TimeoutException:
#                     print(f"Skipping file {f} due to timeout.")
#                 finally:
#                     signal.alarm(0)  # Disable the alarm
                    
# Search for default credentials
def search_default_credentials(dirc):
    print("\nSearching for Default Credentials in System Binaries\n")
    path = pathlib.Path(dirc)
    for f in path.rglob("*"):
        if not os.path.isdir(f):
            if 'dev' in f.parts:
                continue
            if os.path.exists(f):  # Check if file exists
                try:
                    signal.alarm(10)  # Set alarm for 10 seconds
                    with open(f, errors='ignore') as _file:
                        for i, line in enumerate(_file.readlines()):
                            for username, password in default_credentials:
                                if username in line and password in line:
                                    # entry = f"File: {f} - Contains default credentials: {username}/{password}"
                                    entry = f"File: {f} - Contains default credentials"
                                    if entry not in seen_entries:
                                        print(entry)
                                        seen_entries.add(entry)
                except TimeoutException:
                    print(f"Skipping file {f} due to timeout.")
                finally:
                    signal.alarm(0)  # Disable the alarm
                    
def run_entropy_script(firmware_file, block_size=None, output_dir=None):
    """
    Runs the entropy.py script with the specified firmware file and optional block size.
    """
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__)) or "."
        entropy_script = os.path.join(current_dir, "entropy.py")
        cmd = [sys.executable, entropy_script, firmware_file]
        if output_dir:
            cmd.extend(['--output_dir', str(output_dir)])
        if block_size is not None:
            cmd.extend(['--chunk_size', str(block_size)])
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(result.stdout.decode())
        print(result.stderr.decode())
    except subprocess.CalledProcessError as e:
        print(f"Error running entropy.py: {e.stderr.decode()}", file=sys.stderr)
        sys.exit(1)
                
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: FirmAudit.py <firmware_file> [-info | -E | -B <block_size>] [--output_dir <dir>]")
        sys.exit(1)

    filepath = sys.argv[1]
    tempname = os.path.basename(filepath)
    output = os.path.splitext(tempname)[0]

    output_dir = None
    if '--output_dir' in sys.argv:
        idx_o = sys.argv.index('--output_dir')
        if idx_o + 1 < len(sys.argv):
            output_dir = sys.argv[idx_o + 1]

    if len(sys.argv) >= 3 and sys.argv[2] == '-info':
        # Display info only
        run_extractor('-i', filepath)
        sys.exit(0)
    elif len(sys.argv) >= 3 and sys.argv[2] == '-E':
        # Run the entropy.py script
        run_entropy_script(filepath, output_dir=output_dir)
        sys.exit(0)
    elif len(sys.argv) >= 4 and sys.argv[2] == '-B':
        try:
            block_size = int(sys.argv[3])
            # Run the entropy.py script with block size
            run_entropy_script(filepath, block_size=block_size, output_dir=output_dir)
        except ValueError:
            print("Block size must be an integer.")
            sys.exit(1)
        sys.exit(0)
    
    
    dirc = output+"_extracted"
    print("The extracted files can be found in", dirc, "directory\nThe analysis report can be found in", output+"_testout.txt", "file")

    # Extraction using extractor.py instead of Binwalk
    run_extractor('-u', filepath)

    # Update the directory path to the actual extraction path
    dirc = os.path.join(dirc, 'squashfs_out')

    orig_stdout = sys.stdout
    f = open(output+"_testout.txt", 'w')
    sys.stdout = f

    print("Searching in", dirc, "directory.\n")
    
    if len(sys.argv) > 2:
        if sys.argv[2] == "-wf":
            ipWithFileName(dirc)
    else:
        ip_Search(dirc)

    file_search(dirc, bins, "Searching for important binaries... \n")
    file_search(dirc, dbs, "Searching for Database file... \n")
    file_search(dirc, confs, "Searching for system configuration files... \n")
    file_search(dirc, passwords, "Searching for passwords... \n")
    file_search(dirc, others, "Searching for files... \n")
    file_search(dirc, sshFiles, "Searching for ssh files... \n")
    file_search(dirc, sslFiles, "Searching for ssl files... \n")
    file_search(dirc, webServers, "Searching for webserveres... \n")
    extension_search(dirc, '*.sh', "Searching for shell scripts... \n")
    extension_search(dirc, '*.bin', "Searching for .bin files... \n")

    call_Search(dirc, email, "Searching for email addresses... \n")
    url_search(dirc)

    # Additional checks
    file_search(dirc, default_creds, "Searching for default credentials... \n")
    file_search(dirc, sensitive_info, "Searching for hardcoded sensitive information... \n")
    file_search(dirc, insecure_services, "Searching for insecure services... \n")
    call_Search(dirc, re.compile('|'.join(misconfigurations)), "Searching for misconfigurations... \n")

    # Signature-based identification
    identify_file_signatures(dirc)

    # Identify third-party libraries in ELF files
    identify_third_party_libraries(dirc)

    # Identify dangerous functions in ELF files
    identify_dangerous_functions(dirc)

    # Search for hardcoded SSH keys
    search_hardcoded_ssh_keys(dirc)

    # Search for hardcoded Telnet credentials
    # search_hardcoded_telnet_credentials(dirc)

    # Search for command injection vulnerabilities in web interfaces
    search_command_injection(dirc)

    # Search for weak cryptographic algorithms
    search_weak_cryptographic_algorithms(dirc)

    # Check for weak or predictable encryption keys
    search_weak_keys(dirc)
 
    # Search for weak access controls
    search_default_credentials(dirc)
 
    f.close()
    sys.stdout = orig_stdout
    
    
